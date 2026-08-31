//go:build integration

package notify

// notifier_dedup_integration_test.go proves claimDedup's atomicity against a
// real server, not just that its SQL text parses under sqlmock. The whole
// point of the mechanism is to survive N genuinely concurrent callers -- the
// failure mode it exists to prevent is exactly what a mock, which returns
// whatever a test scripted regardless of real contention, cannot exercise.

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity"
)

// dedupTestDB runs the real identity schema migrations (the actual
// 000008_notify_dedup_claims.up.sql this package ships, not a hand-copy of
// its DDL) against a fresh database and returns a connection plus a
// Notifier built over it.
func dedupTestDB(t *testing.T) (*sql.DB, *Notifier) {
	t.Helper()
	base := notifyTestDSN(t)
	// search_path "identity": claimDedup's SQL names notify_dedup_claims
	// unqualified, by design (see schema_routing.go), so this connection
	// must route unqualified names into the identity schema the same way a
	// consumer would -- an empty search_path here would look for the table
	// in "$user", public and never find what RunMigrations just created.
	db := notifyConn(t, base, "identity")
	if err := identity.RunMigrations(db, "up"); err != nil {
		t.Fatalf("failed to run identity migrations: %v", err)
	}
	t.Cleanup(func() { notifyExec(t, db, `TRUNCATE identity.notify_dedup_claims`) })
	return db, NewNotifier(NewChannelRepository(db), nil, nil, nil, Options{})
}

// TestIntegrationClaimDedup_OnlyOneOfManyConcurrentCallersWins is the
// decisive test: N goroutines race the identical key at genuinely the same
// time, against a real server enforcing the row lock the UPSERT depends on.
// Exactly one must win. This is precisely the terraform-registry-backend
// ScannerUpdateJob shape -- replicas that boot together and poll on the same
// tick -- reproduced directly rather than inferred from the SQL.
func TestIntegrationClaimDedup_OnlyOneOfManyConcurrentCallersWins(t *testing.T) {
	_, n := dedupTestDB(t)

	const racers = 25
	var wins atomic.Int32
	var ready, start, done sync.WaitGroup
	ready.Add(racers)
	start.Add(1)
	done.Add(racers)

	for i := 0; i < racers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			start.Wait() // every goroutine is parked here before any of them calls claimDedup
			if n.claimDedup(context.Background(), Event{Type: "x", DedupKey: "race-key"}) {
				wins.Add(1)
			}
		}()
	}
	ready.Wait()
	start.Done() // release all racers at once
	done.Wait()

	if got := wins.Load(); got != 1 {
		t.Fatalf("%d of %d concurrent callers won the same dedup key, want exactly 1", got, racers)
	}
}

// TestIntegrationClaimDedup_DifferentKeysAreIndependent guards against the
// opposite defect: a claim implementation that accidentally serializes on
// something coarser than dedup_key (a table-level lock, a fixed advisory
// lock id) would make unrelated events block each other too.
func TestIntegrationClaimDedup_DifferentKeysAreIndependent(t *testing.T) {
	_, n := dedupTestDB(t)
	ctx := context.Background()

	if !n.claimDedup(ctx, Event{Type: "x", DedupKey: "key-a"}) {
		t.Error("first claim of key-a lost, want won")
	}
	if !n.claimDedup(ctx, Event{Type: "x", DedupKey: "key-b"}) {
		t.Error("first claim of key-b lost, want won -- a distinct key must not be blocked by key-a's live claim")
	}
}

// TestIntegrationClaimDedup_ExpiredClaimCanBeReclaimed proves the mechanism
// is a reservation, not a permanent tombstone: the same key claimed again
// after its TTL elapses must win, not lose forever. Backdates claimed_at
// directly rather than sleeping the test past a real TTL.
func TestIntegrationClaimDedup_ExpiredClaimCanBeReclaimed(t *testing.T) {
	db, n := dedupTestDB(t)
	ctx := context.Background()
	ttl := 10 * time.Minute

	if !n.claimDedup(ctx, Event{Type: "x", DedupKey: "stale-key", DedupTTL: ttl}) {
		t.Fatal("first claim lost, want won")
	}
	if n.claimDedup(ctx, Event{Type: "x", DedupKey: "stale-key", DedupTTL: ttl}) {
		t.Fatal("immediate re-claim within the TTL won, want lost")
	}

	notifyExec(t, db, fmt.Sprintf(
		`UPDATE identity.notify_dedup_claims SET claimed_at = NOW() - INTERVAL '%d seconds' WHERE dedup_key = 'stale-key'`,
		int(ttl.Seconds())+60))

	if !n.claimDedup(ctx, Event{Type: "x", DedupKey: "stale-key", DedupTTL: ttl}) {
		t.Fatal("re-claim after the TTL elapsed lost, want won -- an expired claim must be reclaimable")
	}
}
