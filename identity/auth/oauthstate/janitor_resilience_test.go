// janitor_resilience_test.go covers the "background job crash" class for the
// OAuth-state janitor. Unlike the other two loops in this module, THIS one runs
// in a goroutine the package starts itself (NewMemoryStore), inside the host
// application's process — so an unrecovered panic in a sweep is not a failed
// library call, it is the host terminating.
package oauthstate

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureSlog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func TestJanitor_PanickingSweepIsContainedAndLogged(t *testing.T) {
	logs := captureSlog(t)

	s := NewMemoryStore(time.Hour, 0) // the real janitor must not interfere
	t.Cleanup(func() { _ = s.Close() })

	var sweeps int
	var mu sync.Mutex
	swept := make(chan struct{}, 4)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		s.janitor(time.Millisecond, func() {
			mu.Lock()
			sweeps++
			mu.Unlock()
			select {
			case swept <- struct{}{}:
			default:
			}
			panic("simulated fault while sweeping expired entries")
		})
	}()

	// The loop must survive at least two faulting sweeps: one recovery could
	// be an accident of timing, two proves the loop kept ticking.
	for i := 0; i < 2; i++ {
		select {
		case <-swept:
		case <-time.After(3 * time.Second):
			t.Fatalf("the janitor stopped after %d faulting sweep(s)", i)
		}
	}

	_ = s.Close()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the janitor did not stop on Close after recovering a panic")
	}

	logged := logs.String()
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("a recovered panic must be logged at error level, got %q", logged)
	}
	if !strings.Contains(logged, "job=oauthstate-janitor") {
		t.Errorf("the recovery log must name the job, got %q", logged)
	}
	if !strings.Contains(logged, "simulated fault while sweeping expired entries") {
		t.Errorf("the recovery log must carry the panic value, got %q", logged)
	}
	if !strings.Contains(logged, "stack=") {
		t.Errorf("the recovery log must carry a stack trace, got %q", logged)
	}
}

// The store must stay usable after the janitor recovers a panic raised while
// the map lock was held: recovering past a trailing (non-deferred) Unlock would
// turn a crash into a permanent deadlock of every login, which is worse than
// the fault being recovered.
//
// This pins the contract the janitor imposes on any sweep body — fault while
// holding s.mu and the lock must still be released. It cannot detect a
// regression in the shipped MemoryStore.sweep specifically: nothing inside that
// critical section (a map walk and a time comparison) can fault, so its
// deferred unlock has no reachable trigger and is prophylactic. That is why the
// contract is asserted here at the boundary instead.
func TestJanitor_RecoveredSweepDoesNotHoldTheMapLock(t *testing.T) {
	captureSlog(t)

	s := NewMemoryStore(time.Hour, 0)
	t.Cleanup(func() { _ = s.Close() })

	swept := make(chan struct{}, 1)
	go s.janitor(time.Millisecond, func() {
		// Take the same lock the real sweep takes, then fault while holding it.
		s.mu.Lock()
		defer s.mu.Unlock()
		select {
		case swept <- struct{}{}:
		default:
		}
		panic("simulated fault while holding the map lock")
	})

	select {
	case <-swept:
	case <-time.After(3 * time.Second):
		t.Fatal("the injected sweep never ran")
	}

	done := make(chan error, 1)
	go func() {
		done <- s.PutIfAbsent(context.Background(), "k", []byte("v"), time.Minute)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("PutIfAbsent after a recovered sweep: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the store deadlocked after a recovered sweep — the map lock was left held")
	}
}

// The real sweep must still do its job: recovery is a boundary, not a
// replacement for the behaviour behind it.
func TestSweep_PurgesExpiredEntries(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0)
	t.Cleanup(func() { _ = s.Close() })

	if err := s.PutIfAbsent(context.Background(), "live", []byte("v"), time.Minute); err != nil {
		t.Fatalf("PutIfAbsent(live): %v", err)
	}
	if err := s.PutIfAbsent(context.Background(), "dead", []byte("v"), time.Millisecond); err != nil {
		t.Fatalf("PutIfAbsent(dead): %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	s.sweep()

	s.mu.Lock()
	_, deadStillThere := s.entries["dead"]
	_, liveStillThere := s.entries["live"]
	s.mu.Unlock()

	if deadStillThere {
		t.Error("sweep left an expired entry in the map")
	}
	if !liveStillThere {
		t.Error("sweep dropped a live entry")
	}
}

// MemoryStore.Close is the sibling shutdown of APIKeyExpiryNotifier.Stop;
// assert the same idempotency and concurrency contract for it, so the two
// cannot drift apart again.
func TestMemoryStore_Close_IsIdempotent(t *testing.T) {
	tests := []struct {
		name  string
		close func(s *MemoryStore)
	}{
		{
			name: "twice in sequence",
			close: func(s *MemoryStore) {
				_ = s.Close()
				_ = s.Close()
			},
		},
		{
			name: "concurrently from many goroutines",
			close: func(s *MemoryStore) {
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						_ = s.Close()
					}()
				}
				close(start)
				wg.Wait()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemoryStore(time.Hour, 0)
			tc.close(s) // must not panic
			if err := s.Close(); err != nil {
				t.Errorf("Close returned %v, want nil", err)
			}
			// Documented contract: the store stays usable, minus the sweep.
			if err := s.PutIfAbsent(context.Background(), "k", []byte("v"), time.Minute); err != nil {
				t.Errorf("the store should remain usable after Close: %v", err)
			}
		})
	}
}
