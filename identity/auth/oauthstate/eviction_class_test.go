// eviction_class_test.go pins what a capacity-bounded store is allowed to
// forget.
//
// MemoryStore holds two kinds of entry whose absence means opposite things. A
// login state's absence fails CLOSED — the login is refused and the user
// retries. A Reserve marker's absence fails OPEN — the identifier it guards
// becomes acceptable again, which for a SAML assertion ID is precisely the
// replay it was recorded to prevent.
//
// Ranking the two by nearest expiry cannot see that difference. At equal TTLs
// an existing marker is by construction nearer to expiring than a state minted
// moments ago, so an unauthenticated flood of Issue calls sheds exactly the
// entry that must never be shed. These tests assert both directions: markers
// survive (and keep denying) under pressure, and ordinary logins still work.
package oauthstate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

const markerTTL = 10 * time.Minute

// newCappedManager returns a Manager over a MemoryStore with an explicit
// per-namespace capacity and a janitor that never fires during a test, so what
// the tables exercise is the capacity path rather than a background sweep.
func newCappedManager(t *testing.T, maxEntries int) *Manager {
	t.Helper()
	return newTestManager(t, NewMemoryStore(time.Hour, maxEntries))
}

// TestEvictionClass_ReserveMarkerSurvivesStateFlood is the regression test for
// the eviction asymmetry, driven entirely through the public API at the TTL
// relationship a real deployment has: both sides passing the same value.
func TestEvictionClass_ReserveMarkerSurvivesStateFlood(t *testing.T) {
	tests := []struct {
		name     string
		stateTTL time.Duration
	}{
		// The natural configuration, and the one the old policy got wrong: the
		// marker is older, therefore nearer expiry, therefore the victim.
		{"equal TTLs", markerTTL},
		// A state outliving the marker makes the marker nearer still.
		{"state TTL longer than the marker", 30 * time.Minute},
		// And the case the old comment assumed was the only one.
		{"state TTL shorter than the marker", time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const maxEntries = 8
			ctx := context.Background()
			m := newCappedManager(t, maxEntries)

			const assertionID = "saml-assertion-id-1"
			reserved, err := m.Reserve(ctx, assertionID, markerTTL)
			if err != nil {
				t.Fatalf("first Reserve: %v", err)
			}
			if !reserved {
				t.Fatal("first Reserve = false; want true for an unseen identifier")
			}

			// Drive far past the cap from the unauthenticated login endpoint.
			for i := 0; i < maxEntries*4; i++ {
				if _, err := m.Issue(ctx, "oidc-login", []byte("payload"), tt.stateTTL); err != nil {
					t.Fatalf("Issue #%d: %v", i, err)
				}
			}

			// DENY direction: the same identifier must still be refused.
			replayed, err := m.Reserve(ctx, assertionID, markerTTL)
			if err != nil {
				t.Fatalf("Reserve after flood: %v", err)
			}
			if replayed {
				t.Error("Reserve of an already-seen identifier = true after a login flood; the replay marker was evicted")
			}

			// ALLOW direction: a genuinely new identifier is still accepted, so
			// the store is not simply refusing everything.
			fresh, err := m.Reserve(ctx, "saml-assertion-id-2", markerTTL)
			if err != nil {
				t.Fatalf("Reserve of a new identifier: %v", err)
			}
			if !fresh {
				t.Error("Reserve of an unseen identifier = false; want true")
			}
		})
	}
}

// TestEvictionClass_MarkersAreNeverTheVictim asserts the store-level property
// directly: with the login-state namespace at capacity, eviction takes a state
// and leaves every marker in place.
func TestEvictionClass_MarkersAreNeverTheVictim(t *testing.T) {
	const maxEntries = 3
	ctx := context.Background()
	s := NewMemoryStore(time.Hour, maxEntries)
	t.Cleanup(func() { _ = s.Close() })

	// Markers first, so they are the oldest and nearest-expiry entries present.
	markers := []string{reservePrefix + "a", reservePrefix + "b"}
	for _, k := range markers {
		if err := s.PutIfAbsent(ctx, k, nil, time.Minute); err != nil {
			t.Fatalf("PutIfAbsent(%s): %v", k, err)
		}
	}

	// Fill and then overflow the state namespace at the same TTL.
	for i := 0; i < maxEntries+5; i++ {
		key := fmt.Sprintf("%s%d", statePrefix, i)
		if err := s.PutIfAbsent(ctx, key, []byte(key), time.Minute); err != nil {
			t.Fatalf("PutIfAbsent(%s): %v", key, err)
		}
	}

	for _, k := range markers {
		if _, err := s.Take(ctx, k); err != nil {
			t.Errorf("Take(%s) = %v; want the marker to have survived the flood", k, err)
		}
	}
}

// TestEvictionClass_MarkerCapacityFailsClosed pins what happens when the marker
// namespace itself is full: the write is refused rather than satisfied by
// forgetting an earlier reservation. Both channels Reserve returns say deny.
func TestEvictionClass_MarkerCapacityFailsClosed(t *testing.T) {
	const maxEntries = 2
	ctx := context.Background()
	m := newCappedManager(t, maxEntries)

	for i := 0; i < maxEntries; i++ {
		reserved, err := m.Reserve(ctx, fmt.Sprintf("assertion-%d", i), markerTTL)
		if err != nil || !reserved {
			t.Fatalf("Reserve(assertion-%d) = %v, %v; want true, nil", i, reserved, err)
		}
	}

	reserved, err := m.Reserve(ctx, "assertion-overflow", markerTTL)
	if reserved {
		t.Error("Reserve = true with the marker namespace full; want false")
	}
	if !errors.Is(err, ErrCapacityExhausted) {
		t.Errorf("Reserve error = %v; want ErrCapacityExhausted", err)
	}

	// The reservations already held must still deny — the refusal above must
	// not have been paid for by dropping one of them.
	for i := 0; i < maxEntries; i++ {
		replayed, err := m.Reserve(ctx, fmt.Sprintf("assertion-%d", i), markerTTL)
		if err != nil {
			t.Fatalf("replay Reserve(assertion-%d): %v", i, err)
		}
		if replayed {
			t.Errorf("Reserve(assertion-%d) = true; the existing marker was dropped to make room", i)
		}
	}
}

// TestEvictionClass_MarkerFloodDoesNotStarveLogins is the other half of the
// budget: markers get their own capacity, so a store saturated with them still
// issues logins. Without separate budgets, making markers un-evictable would
// convert a marker flood into a total login outage.
func TestEvictionClass_MarkerFloodDoesNotStarveLogins(t *testing.T) {
	const maxEntries = 4
	ctx := context.Background()
	m := newCappedManager(t, maxEntries)

	for i := 0; i < maxEntries; i++ {
		if _, err := m.Reserve(ctx, fmt.Sprintf("assertion-%d", i), markerTTL); err != nil {
			t.Fatalf("Reserve(assertion-%d): %v", i, err)
		}
	}

	for i := 0; i < maxEntries*3; i++ {
		state, err := m.Issue(ctx, "oidc-login", []byte("payload"), markerTTL)
		if err != nil {
			t.Fatalf("Issue #%d with the marker namespace full: %v", i, err)
		}
		if state == "" {
			t.Fatalf("Issue #%d returned an empty state", i)
		}
	}
}

// TestEvictionClass_LoginStatesStillDegradeGracefully keeps the original
// nearest-expiry behaviour honest: a state flood must shed the state closest to
// expiring rather than failing the write, so ordinary logins degrade instead of
// erroring out.
func TestEvictionClass_LoginStatesStillDegradeGracefully(t *testing.T) {
	const maxEntries = 4
	ctx := context.Background()
	s := NewMemoryStore(time.Hour, maxEntries)
	t.Cleanup(func() { _ = s.Close() })

	// Ascending TTLs: state:0 is nearest expiry and must be the victim.
	for i := 0; i < maxEntries; i++ {
		key := fmt.Sprintf("%s%d", statePrefix, i)
		if err := s.PutIfAbsent(ctx, key, []byte(key), time.Duration(i+1)*time.Minute); err != nil {
			t.Fatalf("PutIfAbsent(%s): %v", key, err)
		}
	}

	if err := s.PutIfAbsent(ctx, statePrefix+"new", []byte("new"), time.Hour); err != nil {
		t.Fatalf("PutIfAbsent at capacity: %v; want the newcomer admitted", err)
	}

	if _, err := s.Take(ctx, statePrefix+"0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Take(state:0) error = %v; want ErrNotFound — the nearest-expiry state should have been evicted", err)
	}
	for _, suffix := range []string{"1", "2", "3", "new"} {
		if _, err := s.Take(ctx, statePrefix+suffix); err != nil {
			t.Errorf("Take(state:%s) = %v; want it to have survived eviction", suffix, err)
		}
	}
}

// TestEvictionClass_ExpiredMarkersDoNotHoldCapacity guards the flip side of
// making markers un-evictable: they must still be reclaimed once they expire,
// or the namespace fills permanently and every later reservation fails closed
// forever.
func TestEvictionClass_ExpiredMarkersDoNotHoldCapacity(t *testing.T) {
	const maxEntries = 2
	ctx := context.Background()
	m := newCappedManager(t, maxEntries)

	for i := 0; i < maxEntries; i++ {
		if _, err := m.Reserve(ctx, fmt.Sprintf("short-%d", i), time.Millisecond); err != nil {
			t.Fatalf("Reserve(short-%d): %v", i, err)
		}
	}
	time.Sleep(10 * time.Millisecond)

	reserved, err := m.Reserve(ctx, "after-expiry", markerTTL)
	if err != nil {
		t.Fatalf("Reserve after the earlier markers expired: %v", err)
	}
	if !reserved {
		t.Error("Reserve = false; expired markers must not hold capacity forever")
	}
}
