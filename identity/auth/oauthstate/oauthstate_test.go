package oauthstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// laxStore is a Store that never expires anything: PutIfAbsent records the
// bytes and ignores ttl entirely. It stands in for a backend whose TTL is
// coarse, lagging, or misconfigured, and exists so that Manager's own expiry
// check can be exercised independently of any store-level expiry.
type laxStore struct {
	mu      sync.Mutex
	entries map[string][]byte
	closed  bool
}

func newLaxStore() *laxStore { return &laxStore{entries: map[string][]byte{}} }

func (s *laxStore) PutIfAbsent(_ context.Context, key string, entry []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[key]; ok {
		return ErrAlreadyExists
	}
	s.entries[key] = append([]byte(nil), entry...)
	return nil
}

func (s *laxStore) Take(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.entries, key)
	return entry, nil
}

func (s *laxStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// brokenStore fails every operation with errBroken, or (when takeEntry is set)
// returns bytes that are not a valid envelope.
type brokenStore struct {
	takeEntry []byte
}

var errBroken = errors.New("backend unavailable")

func (s *brokenStore) PutIfAbsent(context.Context, string, []byte, time.Duration) error {
	return errBroken
}

func (s *brokenStore) Take(context.Context, string) ([]byte, error) {
	if s.takeEntry != nil {
		return s.takeEntry, nil
	}
	return nil, errBroken
}

func (s *brokenStore) Close() error { return errBroken }

func newTestManager(t *testing.T, store Store) *Manager {
	t.Helper()
	m, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// newMemoryManager returns a Manager over a MemoryStore whose janitor is
// effectively disabled (a one-hour sweep never fires during a test), so expiry
// behaviour under test is the read-path guard rather than a background sweep.
func newMemoryManager(t *testing.T) *Manager {
	t.Helper()
	return newTestManager(t, NewMemoryStore(time.Hour, 0))
}

func mustIssue(t *testing.T, m *Manager, purpose string, payload []byte, ttl time.Duration) string {
	t.Helper()
	state, err := m.Issue(context.Background(), purpose, payload, ttl)
	if err != nil {
		t.Fatalf("Issue(%q): %v", purpose, err)
	}
	return state
}

func TestManagerConsumeRejections(t *testing.T) {
	tests := []struct {
		name string
		// prepare returns the manager plus the (purpose, state) pair to
		// redeem. Every case must be rejected.
		prepare func(t *testing.T) (m *Manager, purpose, state string)
		wantErr error
	}{
		{
			name: "state that was never issued",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				// Well-formed shape, simply never minted by this Manager.
				return m, "oidc-login", strings.Repeat("A", 43)
			},
			wantErr: ErrNotFound,
		},
		{
			name: "state consumed a second time",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				state := mustIssue(t, m, "oidc-login", []byte("first"), time.Minute)
				if _, err := m.Consume(context.Background(), "oidc-login", state); err != nil {
					t.Fatalf("first Consume: %v", err)
				}
				return m, "oidc-login", state
			},
			wantErr: ErrNotFound,
		},
		{
			name: "expired state, store enforces expiry",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				state := mustIssue(t, m, "oidc-login", []byte("stale"), time.Nanosecond)
				time.Sleep(5 * time.Millisecond)
				return m, "oidc-login", state
			},
			wantErr: ErrNotFound,
		},
		{
			name: "expired state, store does not enforce expiry",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newTestManager(t, newLaxStore())
				state := mustIssue(t, m, "oidc-login", []byte("stale"), time.Nanosecond)
				time.Sleep(5 * time.Millisecond)
				return m, "oidc-login", state
			},
			wantErr: ErrExpired,
		},
		{
			name: "state redeemed under a different purpose",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				state := mustIssue(t, m, "scm:provider-a", []byte("token-owner"), time.Minute)
				return m, "scm:provider-b", state
			},
			wantErr: ErrPurposeMismatch,
		},
		{
			name: "state redeemed under a purpose that is a prefix of the issued one",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				state := mustIssue(t, m, "scm:provider-a", []byte("token-owner"), time.Minute)
				return m, "scm:provider", state
			},
			wantErr: ErrPurposeMismatch,
		},
		{
			name: "empty state",
			prepare: func(t *testing.T) (*Manager, string, string) {
				return newMemoryManager(t), "oidc-login", ""
			},
			wantErr: ErrNotFound,
		},
		{
			name: "reserve marker cannot be redeemed as a state",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m := newMemoryManager(t)
				reserved, err := m.Reserve(context.Background(), "assertion-1", time.Minute)
				if err != nil || !reserved {
					t.Fatalf("Reserve = %v, %v; want true, nil", reserved, err)
				}
				return m, "saml-acs", "assertion-1"
			},
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, purpose, state := tt.prepare(t)

			payload, err := m.Consume(context.Background(), purpose, state)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Consume error = %v; want %v", err, tt.wantErr)
			}
			// A rejected redemption must hand back nothing: the payload is the
			// principal/resource the callback would go on to trust.
			if payload != nil {
				t.Errorf("Consume returned payload %q on a rejected redemption; want nil", payload)
			}
		})
	}
}

func TestManagerIssueConsumeRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		purpose string
		payload []byte
	}{
		{name: "nil payload", purpose: "oidc-login", payload: nil},
		{name: "empty payload", purpose: "oidc-login", payload: []byte{}},
		{name: "json payload", purpose: "scm:9f1c", payload: []byte(`{"user_id":"u-1","provider_id":"9f1c"}`)},
		{name: "binary payload", purpose: "oidc-login", payload: []byte{0x00, 0xff, 0x10, 0x00, 0x7f}},
		{name: "large payload", purpose: "oidc-login", payload: bytes.Repeat([]byte("x"), 64*1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMemoryManager(t)
			state := mustIssue(t, m, tt.purpose, tt.payload, time.Minute)

			got, err := m.Consume(context.Background(), tt.purpose, state)
			if err != nil {
				t.Fatalf("Consume: %v", err)
			}
			if !bytes.Equal(got, tt.payload) {
				t.Errorf("payload round trip = %q (len %d); want %q (len %d)", got, len(got), tt.payload, len(tt.payload))
			}
		})
	}
}

// TestIssueStateIsUnguessableAndOpaque is the direct regression test for the
// defect this package exists to prevent: a state that describes the login it
// belongs to (e.g. "userID:providerID"). The state must be freshly random
// every time and must carry none of the caller's payload or purpose.
func TestIssueStateIsUnguessableAndOpaque(t *testing.T) {
	const (
		iterations = 500
		purpose    = "scm:provider-9f1c"
		secret     = "user-1234-5678"
	)
	payload := []byte(`{"user_id":"` + secret + `","provider_id":"provider-9f1c"}`)

	m := newMemoryManager(t)
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		state := mustIssue(t, m, purpose, payload, time.Minute)

		if _, dup := seen[state]; dup {
			t.Fatalf("Issue returned a repeated state after %d iterations: %q", i, state)
		}
		seen[state] = struct{}{}

		// 32 random bytes, base64url (unpadded) => 43 characters.
		raw, err := base64.RawURLEncoding.DecodeString(state)
		if err != nil {
			t.Fatalf("state %q is not base64url: %v", state, err)
		}
		if len(raw) != stateEntropyBytes {
			t.Fatalf("state decodes to %d bytes; want %d", len(raw), stateEntropyBytes)
		}

		// Nothing the caller supplied may be recoverable from the state,
		// encoded or otherwise.
		for _, needle := range []string{secret, purpose, "provider-9f1c", "user_id"} {
			if strings.Contains(state, needle) {
				t.Fatalf("state %q contains caller data %q", state, needle)
			}
			if bytes.Contains(raw, []byte(needle)) {
				t.Fatalf("decoded state contains caller data %q", needle)
			}
		}
		if bytes.Contains(raw, payload) {
			t.Fatalf("decoded state embeds the caller payload")
		}
	}
}

func TestIssueValidation(t *testing.T) {
	tests := []struct {
		name    string
		purpose string
		ttl     time.Duration
		// wantErrContains pins the specific guard, not merely "an error":
		// these messages are unique to Manager.Issue, so if the guard is
		// removed and some other layer errors instead, this test still fails.
		wantErrContains string
	}{
		{name: "empty purpose", purpose: "", ttl: time.Minute, wantErrContains: "oauthstate: purpose is required"},
		{name: "zero ttl", purpose: "oidc-login", ttl: 0, wantErrContains: "oauthstate: ttl must be positive"},
		{name: "negative ttl", purpose: "oidc-login", ttl: -time.Second, wantErrContains: "oauthstate: ttl must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMemoryManager(t)

			state, err := m.Issue(context.Background(), tt.purpose, []byte("payload"), tt.ttl)
			if err == nil {
				t.Fatalf("Issue succeeded with state %q; want error %q", state, tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("Issue error = %q; want it to contain %q", err, tt.wantErrContains)
			}
			if state != "" {
				t.Errorf("Issue returned state %q alongside an error; want empty", state)
			}
		})
	}
}

func TestConsumeRequiresPurpose(t *testing.T) {
	m := newMemoryManager(t)
	state := mustIssue(t, m, "oidc-login", []byte("payload"), time.Minute)

	payload, err := m.Consume(context.Background(), "", state)
	if err == nil || !strings.Contains(err.Error(), "oauthstate: purpose is required") {
		t.Fatalf("Consume with empty purpose error = %v; want %q", err, "oauthstate: purpose is required")
	}
	if payload != nil {
		t.Errorf("Consume returned payload %q; want nil", payload)
	}
}

// TestConsumeBurnsStateOnPurposeMismatch pins that the state is consumed
// before the purpose is checked. A "peek, validate, then delete" ordering
// would leave the state redeemable after a failed probe.
func TestConsumeBurnsStateOnPurposeMismatch(t *testing.T) {
	m := newMemoryManager(t)
	state := mustIssue(t, m, "scm:provider-a", []byte("payload"), time.Minute)

	if _, err := m.Consume(context.Background(), "scm:provider-b", state); !errors.Is(err, ErrPurposeMismatch) {
		t.Fatalf("mismatched Consume error = %v; want ErrPurposeMismatch", err)
	}

	payload, err := m.Consume(context.Background(), "scm:provider-a", state)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume after a mismatched probe error = %v; want ErrNotFound", err)
	}
	if payload != nil {
		t.Errorf("Consume returned payload %q after a mismatched probe; want nil", payload)
	}
}

func TestConcurrentConsumeHasExactlyOneWinner(t *testing.T) {
	const goroutines = 32
	want := []byte("only-one-caller-may-see-this")

	m := newMemoryManager(t)
	state := mustIssue(t, m, "oidc-login", want, time.Minute)

	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		mu        sync.Mutex
		winners   int
		notFounds int
		others    []error
	)
	start.Add(1)
	done.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer done.Done()
			start.Wait()

			payload, err := m.Consume(context.Background(), "oidc-login", state)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
				if !bytes.Equal(payload, want) {
					others = append(others, errors.New("winner got the wrong payload"))
				}
			case errors.Is(err, ErrNotFound):
				notFounds++
				if payload != nil {
					others = append(others, errors.New("loser received a payload"))
				}
			default:
				others = append(others, err)
			}
		}()
	}

	start.Done()
	done.Wait()

	if winners != 1 {
		t.Errorf("winners = %d; want exactly 1", winners)
	}
	if notFounds != goroutines-1 {
		t.Errorf("ErrNotFound results = %d; want %d", notFounds, goroutines-1)
	}
	if len(others) != 0 {
		t.Errorf("unexpected results: %v", others)
	}
}

func TestReserve(t *testing.T) {
	tests := []struct {
		name string
		// run performs the scenario and returns the reservation result under
		// test.
		run  func(t *testing.T, m *Manager) bool
		want bool
	}{
		{
			name: "first use of a key is reserved",
			run: func(t *testing.T, m *Manager) bool {
				ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute)
				if err != nil {
					t.Fatalf("Reserve: %v", err)
				}
				return ok
			},
			want: true,
		},
		{
			name: "replay of the same key is refused",
			run: func(t *testing.T, m *Manager) bool {
				if ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute); err != nil || !ok {
					t.Fatalf("first Reserve = %v, %v; want true, nil", ok, err)
				}
				ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute)
				if err != nil {
					t.Fatalf("second Reserve: %v", err)
				}
				return ok
			},
			want: false,
		},
		{
			name: "a different key is unaffected",
			run: func(t *testing.T, m *Manager) bool {
				if ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute); err != nil || !ok {
					t.Fatalf("first Reserve = %v, %v; want true, nil", ok, err)
				}
				ok, err := m.Reserve(context.Background(), "assertion-2", time.Minute)
				if err != nil {
					t.Fatalf("Reserve: %v", err)
				}
				return ok
			},
			want: true,
		},
		{
			name: "an expired marker no longer blocks",
			run: func(t *testing.T, m *Manager) bool {
				if ok, err := m.Reserve(context.Background(), "assertion-1", time.Nanosecond); err != nil || !ok {
					t.Fatalf("first Reserve = %v, %v; want true, nil", ok, err)
				}
				time.Sleep(5 * time.Millisecond)
				ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute)
				if err != nil {
					t.Fatalf("Reserve: %v", err)
				}
				return ok
			},
			want: true,
		},
		{
			name: "an issued state does not collide with a marker of the same name",
			run: func(t *testing.T, m *Manager) bool {
				state := mustIssue(t, m, "oidc-login", []byte("payload"), time.Minute)
				ok, err := m.Reserve(context.Background(), state, time.Minute)
				if err != nil {
					t.Fatalf("Reserve: %v", err)
				}
				return ok
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMemoryManager(t)
			if got := tt.run(t, m); got != tt.want {
				t.Errorf("reserved = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestReserveValidation(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		ttl             time.Duration
		wantErrContains string
	}{
		{name: "empty key", key: "", ttl: time.Minute, wantErrContains: "oauthstate: key is required"},
		{name: "zero ttl", key: "assertion-1", ttl: 0, wantErrContains: "oauthstate: ttl must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMemoryManager(t)

			ok, err := m.Reserve(context.Background(), tt.key, tt.ttl)
			if err == nil {
				t.Fatalf("Reserve succeeded (reserved=%v); want error %q", ok, tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("Reserve error = %q; want it to contain %q", err, tt.wantErrContains)
			}
			if ok {
				t.Errorf("Reserve returned reserved=true alongside an error")
			}
		})
	}
}

func TestConcurrentReserveHasExactlyOneWinner(t *testing.T) {
	const goroutines = 32

	m := newMemoryManager(t)

	var (
		start   sync.WaitGroup
		done    sync.WaitGroup
		mu      sync.Mutex
		winners int
		errs    []error
	)
	start.Add(1)
	done.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer done.Done()
			start.Wait()

			ok, err := m.Reserve(context.Background(), "assertion-1", time.Minute)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if ok {
				winners++
			}
		}()
	}

	start.Done()
	done.Wait()

	if winners != 1 {
		t.Errorf("winners = %d; want exactly 1", winners)
	}
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestNewManagerRejectsNilStore(t *testing.T) {
	m, err := NewManager(nil)
	if err == nil {
		t.Fatalf("NewManager(nil) succeeded; want an error")
	}
	if m != nil {
		t.Errorf("NewManager(nil) returned a Manager alongside an error")
	}
}

func TestManagerCloseClosesStore(t *testing.T) {
	store := newLaxStore()
	m, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.closed {
		t.Errorf("Manager.Close did not close the underlying store")
	}
}

func TestManagerSurfacesStoreFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("issue", func(t *testing.T) {
		m := newTestManager(t, &brokenStore{})
		if _, err := m.Issue(ctx, "oidc-login", nil, time.Minute); !errors.Is(err, errBroken) {
			t.Fatalf("Issue error = %v; want it to wrap errBroken", err)
		}
	})

	t.Run("consume", func(t *testing.T) {
		m := newTestManager(t, &brokenStore{})
		payload, err := m.Consume(ctx, "oidc-login", "some-state")
		if !errors.Is(err, errBroken) {
			t.Fatalf("Consume error = %v; want it to wrap errBroken", err)
		}
		// A backend failure must never be mistaken for "no such state" — and
		// must certainly not yield a payload.
		if errors.Is(err, ErrNotFound) {
			t.Errorf("a backend failure was reported as ErrNotFound")
		}
		if payload != nil {
			t.Errorf("Consume returned payload %q on a backend failure", payload)
		}
	})

	t.Run("consume with an undecodable entry", func(t *testing.T) {
		m := newTestManager(t, &brokenStore{takeEntry: []byte("not-json")})
		payload, err := m.Consume(ctx, "oidc-login", "some-state")
		if err == nil {
			t.Fatalf("Consume succeeded on an undecodable entry")
		}
		if !strings.Contains(err.Error(), "failed to decode state entry") {
			t.Fatalf("Consume error = %q; want a decode failure", err)
		}
		if payload != nil {
			t.Errorf("Consume returned payload %q on an undecodable entry", payload)
		}
	})

	t.Run("reserve", func(t *testing.T) {
		m := newTestManager(t, &brokenStore{})
		ok, err := m.Reserve(ctx, "assertion-1", time.Minute)
		if !errors.Is(err, errBroken) {
			t.Fatalf("Reserve error = %v; want it to wrap errBroken", err)
		}
		// Fail closed: a backend failure is not evidence of first use.
		if ok {
			t.Errorf("Reserve reported reserved=true on a backend failure")
		}
	})
}
