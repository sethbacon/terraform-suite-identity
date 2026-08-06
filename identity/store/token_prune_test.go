package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// timeWithin matches a time.Time argument that lands inside [want-tol, want+tol].
// The prune's cutoff is computed from time.Now() at call time, so it can only be
// asserted against a tolerance — but the tolerance is small enough that a wrong
// SIGN or a missing grace (the two ways the horizon goes wrong) cannot slip
// through it.
type timeWithin struct {
	want time.Time
	tol  time.Duration
}

func (m timeWithin) Match(v driver.Value) bool {
	got, ok := v.(time.Time)
	if !ok {
		return false
	}
	delta := got.Sub(m.want)
	if delta < 0 {
		delta = -delta
	}
	return delta <= m.tol
}

func (m timeWithin) String() string {
	return fmt.Sprintf("time within %v of %v", m.tol, m.want)
}

// TestRevokeToken_SelfPruneHorizonAndBatch pins the two values the prune sends:
// the retention horizon (now MINUS the grace, not now, and not now plus it) and
// the batch bound.
func TestRevokeToken_SelfPruneHorizonAndBatch(t *testing.T) {
	repo, mock := newTokenRepo(t)
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM revoked_tokens").
		WithArgs(
			timeWithin{want: time.Now().Add(-revocationRetentionGrace), tol: time.Minute},
			revocationPruneBatch,
		).
		WillReturnResult(sqlmock.NewResult(0, 7))

	if err := repo.RevokeToken(context.Background(), "jti-1", "user-1", exp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestRevokeToken_SelfPruneIsThrottled asserts the second revocation inside the
// interval does NOT issue a second DELETE. Without this the prune would run on
// every revocation, which is how a bounded table turns into a hot-path cost.
func TestRevokeToken_SelfPruneIsThrottled(t *testing.T) {
	repo, mock := newTokenRepo(t)
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnResult(sqlmock.NewResult(0, 0))
	// Second revocation: insert only.
	mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))

	for i, jti := range []string{"jti-a", "jti-b"} {
		if err := repo.RevokeToken(context.Background(), jti, "user-1", exp); err != nil {
			t.Fatalf("revocation %d failed: %v", i, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestRevokeToken_SelfPruneResumesAfterInterval is the other half of the
// throttle: once the interval has elapsed the next revocation prunes again, so
// the throttle bounds the rate rather than disabling the mechanism after one
// run.
func TestRevokeToken_SelfPruneResumesAfterInterval(t *testing.T) {
	repo, mock := newTokenRepo(t)
	repo.pruneInterval = time.Millisecond
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.RevokeToken(context.Background(), "jti-a", "user-1", exp); err != nil {
		t.Fatalf("first revocation failed: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := repo.RevokeToken(context.Background(), "jti-b", "user-1", exp); err != nil {
		t.Fatalf("second revocation failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestRevokeToken_PruneFailureDoesNotFailRevocation: housekeeping must never be
// able to refuse a revocation. A revoked credential that reports failure to the
// host is worse than a table that stays large for another interval.
func TestRevokeToken_PruneFailureDoesNotFailRevocation(t *testing.T) {
	repo, mock := newTokenRepo(t)
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnError(errDB)

	if err := repo.RevokeToken(context.Background(), "jti-1", "user-1", exp); err != nil {
		t.Errorf("prune failure must not fail the revocation, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestPrune_SurvivesACancelledCallerContext: the caller's context is typically a
// request context that is cancelled the moment the handler returns. The prune
// runs on a context derived with context.WithoutCancel precisely so that does
// not abort it — with a plain derived context this DELETE would never reach the
// driver.
func TestPrune_SurvivesACancelledCallerContext(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnResult(sqlmock.NewResult(0, 3))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo.maybePruneExpiredRevocations(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the prune must not inherit the caller's cancellation: %v", err)
	}
}

// TestRevokeToken_EmptyJTIDoesNotPrune: the empty-jti refusal happens before any
// database work, so it must not consume the throttle slot either — otherwise a
// caller looping on a misconfigured field would suppress pruning for an hour.
func TestRevokeToken_EmptyJTIDoesNotPrune(t *testing.T) {
	repo, _ := newTokenRepo(t)

	if err := repo.RevokeToken(context.Background(), "", "user-1", time.Now()); err != ErrEmptyTokenID {
		t.Fatalf("expected ErrEmptyTokenID, got %v", err)
	}
	if got := repo.nextPruneAtUnixNano.Load(); got != 0 {
		t.Errorf("a refused revocation must not claim a prune slot, got nextPruneAt=%d", got)
	}
}

// TestClaimPruneSlot_ExactlyOneConcurrentWinner asserts the throttle is a
// compare-and-swap and not a read-then-write. A burst of concurrent revocations
// — a password change revoking every session a user holds, a fleet of replicas
// sharing one repository per process — must yield exactly ONE prune, not one per
// goroutine. A load/store throttle passes every sequential test in this file and
// fails only here.
func TestClaimPruneSlot_ExactlyOneConcurrentWinner(t *testing.T) {
	repo, _ := newTokenRepo(t)

	// The window a load-then-store throttle loses updates in is only open until
	// the first store lands, so one race is not evidence: the racers have to
	// enter the function together, and the round has to be repeated. Releasing
	// them from a spin on an atomic (rather than a channel, whose wakeups the
	// scheduler serialises) is what gets them in together; resetting the slot
	// between rounds is what re-opens the window.
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs at least 2 CPUs to make concurrent claims genuinely overlap")
	}

	const (
		rounds     = 500
		goroutines = 8
	)

	var winners atomic.Int64
	for round := 0; round < rounds; round++ {
		repo.nextPruneAtUnixNano.Store(0)
		now := time.Now()

		var gate atomic.Bool
		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !gate.Load() {
					runtime.Gosched()
				}
				if repo.claimPruneSlot(now) {
					winners.Add(1)
				}
			}()
		}
		gate.Store(true)
		wg.Wait()
	}

	if got := winners.Load(); got != rounds {
		t.Errorf("exactly one caller per round may claim the prune slot: expected %d claims "+
			"across %d rounds of %d concurrent callers, got %d.\n"+
			"A load-then-store throttle lets every caller that read the same stale deadline "+
			"decide to prune, so a burst of revocations issues a burst of DELETEs.",
			rounds, rounds, goroutines, got)
	}
}

// TestRevokeToken_ConcurrentRevocationsAreRaceFree drives the real write path
// from many goroutines at once so -race covers the shared throttle state.
func TestRevokeToken_ConcurrentRevocationsAreRaceFree(t *testing.T) {
	const goroutines = 16

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.MatchExpectationsInOrder(false)
	repo := NewTokenRepository(db)

	for i := 0; i < goroutines; i++ {
		mock.ExpectExec("INSERT INTO revoked_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	}
	mock.ExpectExec("DELETE FROM revoked_tokens").WillReturnResult(sqlmock.NewResult(0, 0))

	var wg sync.WaitGroup
	exp := time.Now().Add(time.Hour)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := repo.RevokeToken(context.Background(), fmt.Sprintf("jti-%d", i), "user-1", exp); err != nil {
				t.Errorf("revocation %d failed: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the single prune did not run): %v", err)
	}
}
