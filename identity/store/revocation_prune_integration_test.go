//go:build integration

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// TestIntegrationRevocationSelfPruneHorizon asserts the retention horizon in
// BOTH directions against a real PostgreSQL: rows past it are removed, rows
// inside it are not.
//
// One direction alone is not evidence. A prune that deletes everything passes a
// "the old row is gone" assertion while destroying the denylist, and a prune
// that deletes nothing passes a "the fresh row survived" assertion while leaving
// the table unbounded — which is the exact defect issue #154 reported.
func TestIntegrationRevocationSelfPruneHorizon(t *testing.T) {
	db := identityTestDB(t)
	userID := seedRevocationUser(t, db)
	repo := NewTokenRepository(db)

	// Three rows straddling the horizon (revocationRetentionGrace = 1h):
	//   past-horizon  expired well beyond the grace  -> must be pruned
	//   inside-grace  expired but still inside it    -> must survive
	//   unexpired     not expired at all             -> must survive
	pastHorizon := insertRevocation(t, db, userID, -3*time.Hour)
	insideGrace := insertRevocation(t, db, userID, -30*time.Minute)
	unexpired := insertRevocation(t, db, userID, time.Hour)

	fresh := newJTI(t, db)
	if err := repo.RevokeToken(context.Background(), fresh, userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	if revocationExists(t, db, pastHorizon) {
		t.Errorf("a revocation whose token expired %v ago (past the %v retention grace) must be pruned",
			3*time.Hour, revocationRetentionGrace)
	}
	if !revocationExists(t, db, insideGrace) {
		t.Errorf("a revocation whose token expired only %v ago is INSIDE the %v retention grace "+
			"and must survive: the clock that prunes is not the clock that verifies, and "+
			"dropping it early re-opens the token to a verifier running behind",
			30*time.Minute, revocationRetentionGrace)
	}
	if !revocationExists(t, db, unexpired) {
		t.Error("a revocation for a token that has not expired must never be pruned — that is the " +
			"denylist doing its job")
	}
	if !revocationExists(t, db, fresh) {
		t.Error("the revocation just written must not be pruned by its own call")
	}
}

// TestIntegrationRevocationSelfPruneIsBounded asserts one prune deletes at most
// pruneBatch rows, so the first revocation issued against a large, never-pruned
// backlog does a bounded amount of work — and that successive prunes drain the
// rest rather than stalling.
func TestIntegrationRevocationSelfPruneIsBounded(t *testing.T) {
	db := identityTestDB(t)
	userID := seedRevocationUser(t, db)

	repo := NewTokenRepository(db)
	repo.pruneBatch = 2
	repo.pruneInterval = time.Nanosecond // drain across calls without waiting

	for i := 0; i < 5; i++ {
		insertRevocation(t, db, userID, -3*time.Hour)
	}

	revoke := func(n int) {
		t.Helper()
		jti := newJTI(t, db)
		if err := repo.RevokeToken(context.Background(), jti, userID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("RevokeToken %d failed: %v", n, err)
		}
	}

	revoke(1)
	if got := countExpiredBeyondGrace(t, db); got != 3 {
		t.Errorf("one prune must delete at most pruneBatch(=2) rows, leaving 3 of 5; got %d remaining", got)
	}
	revoke(2)
	if got := countExpiredBeyondGrace(t, db); got != 1 {
		t.Errorf("the second prune must drain another batch, leaving 1 of 5; got %d remaining", got)
	}
	revoke(3)
	if got := countExpiredBeyondGrace(t, db); got != 0 {
		t.Errorf("successive prunes must drain the backlog completely; got %d remaining", got)
	}
}

// TestIntegrationRevocationSelfPruneIsThrottled asserts a burst of revocations
// costs ONE prune, not one per revocation, against a real database.
func TestIntegrationRevocationSelfPruneIsThrottled(t *testing.T) {
	db := identityTestDB(t)
	userID := seedRevocationUser(t, db)

	repo := NewTokenRepository(db)
	repo.pruneBatch = 1

	for i := 0; i < 4; i++ {
		insertRevocation(t, db, userID, -3*time.Hour)
	}

	for i := 0; i < 4; i++ {
		jti := newJTI(t, db)
		if err := repo.RevokeToken(context.Background(), jti, userID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("RevokeToken %d failed: %v", i, err)
		}
	}

	if got := countExpiredBeyondGrace(t, db); got != 3 {
		t.Errorf("four revocations inside one %v prune interval must issue exactly one bounded "+
			"prune (1 of 4 stale rows removed, 3 left); got %d remaining",
			revocationPruneInterval, got)
	}
}

// TestIntegrationCleanupExpiredRevocationsStillSweepsImmediately pins the
// documented difference between the two mechanisms: the host-callable sweep
// applies no grace, so a host that already schedules it keeps its current
// behaviour.
func TestIntegrationCleanupExpiredRevocationsStillSweepsImmediately(t *testing.T) {
	db := identityTestDB(t)
	userID := seedRevocationUser(t, db)
	repo := NewTokenRepository(db)

	justExpired := insertRevocation(t, db, userID, -time.Minute)
	unexpired := insertRevocation(t, db, userID, time.Hour)

	if err := repo.CleanupExpiredRevocations(context.Background()); err != nil {
		t.Fatalf("CleanupExpiredRevocations failed: %v", err)
	}
	if revocationExists(t, db, justExpired) {
		t.Error("CleanupExpiredRevocations sweeps every already-expired row, with no grace")
	}
	if !revocationExists(t, db, unexpired) {
		t.Error("CleanupExpiredRevocations must never remove a live revocation")
	}
}

// --- helpers ---------------------------------------------------------------

func seedRevocationUser(t *testing.T, db *sql.DB) string {
	t.Helper()
	return scanUUID(t, db,
		`INSERT INTO identity.users (email, name) VALUES ('revoker@example.test', 'revoker') RETURNING id`)
}

// insertRevocation writes a revocation row whose token expires at now+offset
// (a negative offset means it has already expired) and returns its jti.
func insertRevocation(t *testing.T, db *sql.DB, userID string, offset time.Duration) string {
	t.Helper()

	var jti string
	if err := db.QueryRow(
		`INSERT INTO identity.revoked_tokens (jti, user_id, expires_at)
		 VALUES (gen_random_uuid(), $1, NOW() + make_interval(secs => $2)) RETURNING jti`,
		userID, offset.Seconds(),
	).Scan(&jti); err != nil {
		t.Fatalf("failed to seed a revocation at offset %v: %v", offset, err)
	}
	return jti
}

// newJTI mints a fresh uuid for a revocation the test is about to write through
// the repository.
func newJTI(t *testing.T, db *sql.DB) string {
	t.Helper()

	return scanUUID(t, db, `SELECT gen_random_uuid()`)
}

func revocationExists(t *testing.T, db *sql.DB, jti string) bool {
	t.Helper()

	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM identity.revoked_tokens WHERE jti = $1)`, jti,
	).Scan(&exists); err != nil {
		t.Fatalf("failed to look up revocation %s: %v", jti, err)
	}
	return exists
}

// countExpiredBeyondGrace counts the rows a prune is entitled to delete.
func countExpiredBeyondGrace(t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM identity.revoked_tokens
		 WHERE expires_at < NOW() - make_interval(secs => $1)`,
		revocationRetentionGrace.Seconds(),
	).Scan(&n); err != nil {
		t.Fatalf("failed to count prunable revocations: %v", err)
	}
	return n
}
