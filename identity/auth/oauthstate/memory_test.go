package oauthstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestMemoryStore(t *testing.T, cleanupInterval time.Duration, maxEntries int) *MemoryStore {
	t.Helper()
	s := NewMemoryStore(cleanupInterval, maxEntries)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (s *MemoryStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func TestMemoryStorePutIfAbsent(t *testing.T) {
	tests := []struct {
		name string
		// seed runs before the operation under test.
		seed            func(t *testing.T, s *MemoryStore)
		key             string
		ttl             time.Duration
		wantErr         error
		wantErrContains string
	}{
		{
			name: "new key is stored",
			key:  "state:abc",
			ttl:  time.Minute,
		},
		{
			name: "live key is not overwritten",
			seed: func(t *testing.T, s *MemoryStore) {
				if err := s.PutIfAbsent(context.Background(), "state:abc", []byte("first"), time.Minute); err != nil {
					t.Fatalf("seed PutIfAbsent: %v", err)
				}
			},
			key:     "state:abc",
			ttl:     time.Minute,
			wantErr: ErrAlreadyExists,
		},
		{
			name: "expired key may be reused",
			seed: func(t *testing.T, s *MemoryStore) {
				if err := s.PutIfAbsent(context.Background(), "state:abc", []byte("first"), time.Nanosecond); err != nil {
					t.Fatalf("seed PutIfAbsent: %v", err)
				}
				time.Sleep(5 * time.Millisecond)
			},
			key: "state:abc",
			ttl: time.Minute,
		},
		{
			name:            "empty key is rejected",
			key:             "",
			ttl:             time.Minute,
			wantErrContains: "oauthstate: memory store: key is required",
		},
		{
			name:            "non-positive ttl is rejected",
			key:             "state:abc",
			ttl:             0,
			wantErrContains: "oauthstate: memory store: entry ttl must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestMemoryStore(t, time.Hour, 0)
			if tt.seed != nil {
				tt.seed(t, s)
			}

			err := s.PutIfAbsent(context.Background(), tt.key, []byte("second"), tt.ttl)

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("PutIfAbsent error = %v; want %v", err, tt.wantErr)
				}
				// The original entry must survive an ErrAlreadyExists.
				got, takeErr := s.Take(context.Background(), tt.key)
				if takeErr != nil {
					t.Fatalf("Take after a refused overwrite: %v", takeErr)
				}
				if !bytes.Equal(got, []byte("first")) {
					t.Errorf("stored entry = %q; want the original %q", got, "first")
				}
			case tt.wantErrContains != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("PutIfAbsent error = %v; want it to contain %q", err, tt.wantErrContains)
				}
			default:
				if err != nil {
					t.Fatalf("PutIfAbsent: %v", err)
				}
				got, takeErr := s.Take(context.Background(), tt.key)
				if takeErr != nil {
					t.Fatalf("Take: %v", takeErr)
				}
				if !bytes.Equal(got, []byte("second")) {
					t.Errorf("stored entry = %q; want %q", got, "second")
				}
			}
		})
	}
}

func TestMemoryStoreTake(t *testing.T) {
	tests := []struct {
		name        string
		seed        func(t *testing.T, s *MemoryStore)
		key         string
		wantEntry   []byte
		wantErr     error
		wantMissing bool
	}{
		{
			name:        "missing key",
			key:         "state:missing",
			wantErr:     ErrNotFound,
			wantMissing: true,
		},
		{
			name: "live entry is returned",
			seed: func(t *testing.T, s *MemoryStore) {
				if err := s.PutIfAbsent(context.Background(), "state:abc", []byte("payload"), time.Minute); err != nil {
					t.Fatalf("seed PutIfAbsent: %v", err)
				}
			},
			key:       "state:abc",
			wantEntry: []byte("payload"),
		},
		{
			name: "expired entry is rejected",
			seed: func(t *testing.T, s *MemoryStore) {
				if err := s.PutIfAbsent(context.Background(), "state:abc", []byte("payload"), time.Nanosecond); err != nil {
					t.Fatalf("seed PutIfAbsent: %v", err)
				}
				time.Sleep(5 * time.Millisecond)
			},
			key:         "state:abc",
			wantErr:     ErrNotFound,
			wantMissing: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A one-hour sweep never fires here: expiry under test is the
			// read-path guard in Take, not the background janitor.
			s := newTestMemoryStore(t, time.Hour, 0)
			if tt.seed != nil {
				tt.seed(t, s)
			}

			entry, err := s.Take(context.Background(), tt.key)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Take error = %v; want %v", err, tt.wantErr)
				}
				if entry != nil {
					t.Errorf("Take returned entry %q alongside %v", entry, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("Take: %v", err)
				}
				if !bytes.Equal(entry, tt.wantEntry) {
					t.Errorf("Take entry = %q; want %q", entry, tt.wantEntry)
				}
			}

			// Single use, and expired entries reclaimed: nothing may remain.
			if got := s.size(); got != 0 {
				t.Errorf("store holds %d entries after Take; want 0", got)
			}
			if _, err := s.Take(context.Background(), tt.key); !errors.Is(err, ErrNotFound) {
				t.Errorf("second Take error = %v; want ErrNotFound", err)
			}
		})
	}
}

func TestMemoryStoreTakeCopiesNothingBack(t *testing.T) {
	s := newTestMemoryStore(t, time.Hour, 0)

	entry := []byte("payload")
	if err := s.PutIfAbsent(context.Background(), "state:abc", entry, time.Minute); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	// The caller reuses its buffer after the call returns.
	copy(entry, "MUTATED")

	got, err := s.Take(context.Background(), "state:abc")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Errorf("Take entry = %q; want %q — the store retained the caller's slice", got, "payload")
	}
}

func TestMemoryStoreEvictsNearestExpiryAtCap(t *testing.T) {
	const maxEntries = 4
	s := newTestMemoryStore(t, time.Hour, maxEntries)

	// Ascending TTLs: state:0 is nearest expiry and must be the victim.
	for i := 0; i < maxEntries; i++ {
		key := fmt.Sprintf("state:%d", i)
		if err := s.PutIfAbsent(context.Background(), key, []byte(key), time.Duration(i+1)*time.Minute); err != nil {
			t.Fatalf("PutIfAbsent(%s): %v", key, err)
		}
	}

	if err := s.PutIfAbsent(context.Background(), "state:new", []byte("state:new"), time.Hour); err != nil {
		t.Fatalf("PutIfAbsent(state:new): %v", err)
	}

	if got := s.size(); got != maxEntries {
		t.Errorf("store holds %d entries; want the cap of %d", got, maxEntries)
	}
	if _, err := s.Take(context.Background(), "state:0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Take(state:0) error = %v; want ErrNotFound — the nearest-expiry entry should have been evicted", err)
	}
	// The longer-lived entries (a Reserve marker outlives a login state) and
	// the newcomer must survive.
	for _, key := range []string{"state:1", "state:2", "state:3", "state:new"} {
		if _, err := s.Take(context.Background(), key); err != nil {
			t.Errorf("Take(%s) error = %v; want it to have survived eviction", key, err)
		}
	}
}

func TestMemoryStoreJanitorReclaimsAbandonedEntries(t *testing.T) {
	s := newTestMemoryStore(t, 5*time.Millisecond, 0)

	if err := s.PutIfAbsent(context.Background(), "state:abandoned", []byte("payload"), time.Millisecond); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}

	// An abandoned login is never read back, so only the sweep can reclaim it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.size() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("expired entry still present after 2s; the janitor did not reclaim it")
}

func TestMemoryStoreCloseIsIdempotentAndClears(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0)

	if err := s.PutIfAbsent(context.Background(), "state:abc", []byte("payload"), time.Minute); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.size(); got != 0 {
		t.Errorf("store holds %d entries after Close; want 0", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	const goroutines = 16

	s := newTestMemoryStore(t, time.Millisecond, 0)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("state:%d-%d", i, j)
				if err := s.PutIfAbsent(context.Background(), key, []byte(key), time.Minute); err != nil {
					t.Errorf("PutIfAbsent(%s): %v", key, err)
					return
				}
				if _, err := s.Take(context.Background(), key); err != nil {
					t.Errorf("Take(%s): %v", key, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
