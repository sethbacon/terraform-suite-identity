//go:build integration

// The half of this package that only a real database can establish.
//
// sqlmock can show that the locking read is ISSUED with FOR UPDATE — the unit
// tests do, by matching on it. It cannot show that the lock WORKS: that a second
// revoker waits for the first, and then sees the world the first one left
// behind. Nor can it show that ON CONFLICT (user_id) needs an arbiter, that
// TableDDL produces a table these statements can actually run against, or that
// an audit intent refused inside the transaction takes the mutation with it.
// Those are properties of Postgres, so they are asserted against Postgres.
//
// AND THE INTERLEAVING IS FORCED, NOT RACED. Registry recorded the lesson
// directly: its two-goroutine test passed with AND without the FOR UPDATE,
// because the window between "read the remaining grants" and "delete the row" is
// a few hundred microseconds and two goroutines started together do not reliably
// land inside it. A test that cannot fail without the fix is not evidence of the
// fix.
//
// So this does not race. It pins the schedule, using the fact that Revoke calls
// the caller's own Predicate INSIDE the transaction, after the FOR UPDATE read
// and before the DELETE — the predicate IS the parking spot, no test hook
// required:
//
//  1. revoker A enters Revoke, takes FOR UPDATE over the carrier, and BLOCKS
//     inside its predicate
//  2. revoker B enters Revoke and blocks on A's row locks
//  3. the test WAITS UNTIL POSTGRES ITSELF REPORTS B AS WAITING
//     (pg_stat_activity.wait_event_type = 'Lock'), so the blocking is observed
//     rather than assumed
//  4. A is released; it sees two administrators, removes one, commits
//  5. B wakes, reads ONE administrator, and refuses
//
// TestIntegrationUnserialisedRevokesReachZero is the falsification, kept
// permanently rather than run once and described in a commit message: the same
// two revocations, the same predicate, WITHOUT the row lock, reaching zero
// administrators.
package platformadmin

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// carrierTable is schema-qualified deliberately: it exercises the parameterised
// two-part name against a real catalogue, which is the routing an application
// that keeps its authorization state in its own schema actually uses.
const (
	testSchema   = "pa_test"
	carrierTable = testSchema + ".platform_admins"
	usersTable   = testSchema + ".users"
	intentTable  = testSchema + ".audit_intents"
)

// carrierTestDB returns a connection to this package's own test database with a
// freshly created carrier table, or skips when no database is configured.
//
// Its OWN database, derived from TEST_DATABASE_URL by suffixing the name, for
// the reason identity/store/integration_db_test.go gives: `go test ./...` runs
// package binaries concurrently and each suite drops and re-creates its schema,
// so sharing one database would make each suite's result depend on the other's
// timing.
func carrierTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	parsed, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL must be a postgres:// URL, got %q (parse error: %v)", dsn, err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	if base == "" {
		t.Fatalf("TEST_DATABASE_URL %q names no database", dsn)
	}
	name := base + "_platformadmin"

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to open the administrative connection: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.Ping(); err != nil {
		t.Skipf("Postgres not reachable at TEST_DATABASE_URL: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE ` + pgquote.Identifier(name)); err != nil {
		// 42P04 duplicate_database: a previous run already created it.
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" {
			t.Fatalf("failed to create the %q test database (the role needs CREATEDB): %v", name, err)
		}
	}

	target := *parsed
	target.Path = "/" + name
	db, err := sql.Open("pgx", target.String())
	if err != nil {
		t.Fatalf("failed to open %q: %v", name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach %q: %v", name, err)
	}

	// A clean slate per test, so one test's carrier rows cannot satisfy
	// another's floor.
	mustExec(t, db, `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`)
	mustExec(t, db, `CREATE SCHEMA `+testSchema)

	// The carrier itself comes from the SHIPPED DDL, never from a hand-written
	// statement here. A test fixture that diverged from what applications are
	// told to apply would assert the wrong table.
	ddl, err := TableDDL(carrierTable)
	if err != nil {
		t.Fatalf("TableDDL(%q): %v", carrierTable, err)
	}
	mustExec(t, db, ddl)

	// The application's own tables, standing in for whatever it really has: the
	// principals a Resolver resolves against, and an audit destination an
	// AuditIntentWriter writes into.
	mustExec(t, db, `CREATE TABLE `+usersTable+` (id UUID PRIMARY KEY, email TEXT NOT NULL)`)
	mustExec(t, db, `CREATE TABLE `+intentTable+` (
		id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, target UUID NOT NULL)`)

	return db
}

func mustExec(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.Exec(statement); err != nil {
		t.Fatalf("statement failed: %v\n%s", err, statement)
	}
}

func newCarrier(t *testing.T, db *sql.DB) *Carrier {
	t.Helper()
	c, err := New(db, carrierTable)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// seedUser inserts a principal a Resolver will resolve.
func seedUser(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO `+usersTable+` (id, email) VALUES ($1, $2)`, id, id+"@example.com"); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

// liveUsers is the Resolver an application would supply: a real lookup against
// its own principals, distinguishing "no such user" from "could not find out".
func liveUsers(db *sql.DB) Resolver {
	return ResolverFunc(func(ctx context.Context, userID string) (bool, error) {
		var exists bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM `+usersTable+` WHERE id = $1)`, userID).Scan(&exists)
		return exists, err
	})
}

// recordingIntent is the AuditIntentWriter an application would supply: a write
// on the mutation's own transaction.
func recordingIntent(action, target string) AuditIntentWriter {
	return func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO `+intentTable+` (action, target) VALUES ($1, $2)`, action, target)
		return err
	}
}

func carrierCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ` + carrierTable).Scan(&n); err != nil {
		t.Fatalf("count carrier rows: %v", err)
	}
	return n
}

func intentCount(t *testing.T, db *sql.DB, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM `+intentTable+` WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatalf("count audit intents: %v", err)
	}
	return n
}

// waitForALockWaiter blocks until Postgres reports a session in THIS database
// waiting on a lock.
//
// This is the step that makes the interleaving forced rather than hoped for:
// without it the test would release the first revoker on a timer and could not
// tell a serialised run from a lucky one.
func waitForALockWaiter(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		err := db.QueryRow(`
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND wait_event_type = 'Lock'`).Scan(&waiting)
		if err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no session ever blocked — the second caller was never serialised behind the first, " +
		"so this test is not exercising the lock at all and would pass with it removed")
}

// ---------------------------------------------------------------------------
// The shipped DDL, against a real catalogue
// ---------------------------------------------------------------------------

// TestIntegrationTableDDLProducesATableTheStatementsRunAgainst closes the loop
// between what applications are told to create and what this package actually
// executes. VerifyTable's answer and a real grant have to agree.
func TestIntegrationTableDDLProducesATableTheStatementsRunAgainst(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)

	resolved, err := c.VerifyTable(context.Background())
	if err != nil {
		t.Fatalf("VerifyTable on a table created from the shipped TableDDL: %v", err)
	}
	if resolved != carrierTable {
		t.Errorf("VerifyTable resolved to %q, want %q — the reported name is how an operator "+
			"learns where grants are actually kept", resolved, carrierTable)
	}

	note := "bootstrap administrator"
	grantor := adminA
	got, err := c.Grant(context.Background(), adminB, &grantor, &note, recordingIntent(AuditActionGranted, adminB))
	if err != nil {
		t.Fatalf("Grant against the shipped DDL: %v", err)
	}
	if got.GrantedBy == nil || *got.GrantedBy != adminA || got.Note == nil || *got.Note != note {
		t.Errorf("grant = %+v, want the provenance round-tripped", got)
	}
	if got.GrantedAt.IsZero() {
		t.Error("granted_at was not defaulted by the DDL")
	}
}

// GUARD on-conflict-needs-an-arbiter, proven rather than described. Without the
// unique index the column checks all pass and every grant fails at write time,
// which is why VerifyTable checks for the index and not merely the columns.
func TestIntegrationVerifyTableCatchesTheMissingOnConflictArbiter(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)

	// The same table, minus only the primary key.
	mustExec(t, db, `ALTER TABLE `+carrierTable+` DROP CONSTRAINT platform_admins_pkey`)

	if _, err := c.VerifyTable(context.Background()); !errors.Is(err, ErrTableShape) {
		t.Fatalf("VerifyTable = %v, want ErrTableShape for a carrier with no unique index on user_id", err)
	}

	// And this is what VerifyTable spared the operator from finding out at
	// runtime.
	_, err := c.Grant(context.Background(), adminB, nil, nil, recordingIntent(AuditActionGranted, adminB))
	if err == nil {
		t.Fatal("Grant succeeded without an ON CONFLICT arbiter, so this guard is protecting nothing")
	}
	if !strings.Contains(err.Error(), "ON CONFLICT") {
		t.Errorf("Grant failed with %v; expected Postgres to reject the ON CONFLICT specification", err)
	}
}

// ---------------------------------------------------------------------------
// Provenance and the audit intent, transactionally
// ---------------------------------------------------------------------------

// A re-grant leaves the ORIGINAL row alone. The provenance is the reason this is
// a table and not a boolean, and a re-grant that overwrote it would erase who
// first conferred the privilege.
func TestIntegrationRegrantPreservesTheOriginalProvenance(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	ctx := context.Background()

	first := adminA
	firstNote := "granted at onboarding"
	original, err := c.Grant(ctx, adminB, &first, &firstNote, recordingIntent(AuditActionGranted, adminB))
	if err != nil {
		t.Fatalf("first Grant: %v", err)
	}

	second := adminC
	secondNote := "granted again by somebody else"
	got, err := c.Grant(ctx, adminB, &second, &secondNote, recordingIntent(AuditActionGranted, adminB))
	if !errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Fatalf("second Grant = %v, want ErrAlreadyPlatformAdmin", err)
	}
	if got != nil {
		t.Errorf("second Grant returned %+v, want nil", got)
	}

	grants, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("carrier holds %d rows after a re-grant, want 1", len(grants))
	}
	if grants[0].GrantedBy == nil || *grants[0].GrantedBy != first {
		t.Errorf("granted_by = %v, want the ORIGINAL grantor %q — a re-grant must not rewrite "+
			"who conferred the highest privilege in the product", grants[0].GrantedBy, first)
	}
	if grants[0].Note == nil || *grants[0].Note != firstNote {
		t.Errorf("note = %v, want the original %q", grants[0].Note, firstNote)
	}
	if !grants[0].GrantedAt.Equal(original.GrantedAt) {
		t.Errorf("granted_at = %v, want the original %v", grants[0].GrantedAt, original.GrantedAt)
	}
	// One grant happened, so exactly one record of a grant exists.
	if n := intentCount(t, db, AuditActionGranted); n != 1 {
		t.Errorf("%d grant records written, want 1 — the conflicting re-grant changed nothing "+
			"and must not appear in the trail as though it had", n)
	}
}

// GUARD durable-audit-atomic, against a real transaction. The audit destination
// refuses; neither the grant nor its record may survive.
func TestIntegrationARefusedAuditIntentRollsTheGrantBack(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	ctx := context.Background()

	outboxDown := errors.New("audit destination unreachable")
	refusing := func(innerCtx context.Context, tx *sql.Tx) error {
		// Write first, THEN refuse: this is the shape that proves the rollback
		// carries the record away too, rather than there never having been one.
		if _, err := tx.ExecContext(innerCtx,
			`INSERT INTO `+intentTable+` (action, target) VALUES ($1, $2)`, AuditActionGranted, adminB); err != nil {
			return err
		}
		return outboxDown
	}

	got, err := c.Grant(ctx, adminB, nil, nil, refusing)
	if !errors.Is(err, outboxDown) {
		t.Fatalf("Grant = %v, want the audit writer's own error", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v, want nil", got)
	}
	if n := carrierCount(t, db); n != 0 {
		t.Errorf("%d carrier rows survived an unauditable grant, want 0 — this deployment would "+
			"have a platform administrator nobody can account for", n)
	}
	if n := intentCount(t, db, AuditActionGranted); n != 0 {
		t.Errorf("%d audit records survived the rollback, want 0", n)
	}
}

func TestIntegrationRevokeRemovesTheRowAndItsRecordTogether(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	ctx := context.Background()
	seedUser(t, db, adminA)
	seedUser(t, db, adminB)

	for _, id := range []string{adminA, adminB} {
		if _, err := c.Grant(ctx, id, nil, nil, recordingIntent(AuditActionGranted, id)); err != nil {
			t.Fatalf("Grant %s: %v", id, err)
		}
	}

	got, err := c.Revoke(ctx, adminB, RequireAnotherExercisableAdmin(liveUsers(db)),
		recordingIntent(AuditActionRevoked, adminB))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got == nil || got.UserID != adminB {
		t.Fatalf("Revoke = %+v, want the removed grant", got)
	}
	if n := carrierCount(t, db); n != 1 {
		t.Errorf("%d carrier rows remain, want 1", n)
	}
	if n := intentCount(t, db, AuditActionRevoked); n != 1 {
		t.Errorf("%d revocation records written, want 1", n)
	}
}

// GUARD orphan-grant-is-not-an-administrator, end to end. The carrier holds two
// rows; the other names a principal the application's users table no longer has.
// A floor that counted rows would let this revocation through.
func TestIntegrationRevokeRefusesWhenTheOnlyOtherGrantIsOrphaned(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	ctx := context.Background()
	seedUser(t, db, adminA) // orphanD is deliberately NOT seeded

	for _, id := range []string{adminA, orphanD} {
		if _, err := c.Grant(ctx, id, nil, nil, recordingIntent(AuditActionGranted, id)); err != nil {
			t.Fatalf("Grant %s: %v", id, err)
		}
	}

	_, err := c.Revoke(ctx, adminA, RequireAnotherExercisableAdmin(liveUsers(db)),
		recordingIntent(AuditActionRevoked, adminA))
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("Revoke = %v, want ErrLastPlatformAdmin — the carrier had two rows but only one "+
			"administrator", err)
	}
	if n := carrierCount(t, db); n != 2 {
		t.Errorf("%d carrier rows after a refused revocation, want 2", n)
	}
	if n := intentCount(t, db, AuditActionRevoked); n != 0 {
		t.Errorf("%d revocation records written for a revocation that was refused, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// The concurrency proof
// ---------------------------------------------------------------------------

// seedTwoAdministrators lays out the state the concurrency tests start from: two
// grants, both naming principals that resolve.
func seedTwoAdministrators(t *testing.T, db *sql.DB, c *Carrier) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{adminA, adminB} {
		seedUser(t, db, id)
		if _, err := c.Grant(ctx, id, nil, nil, recordingIntent(AuditActionGranted, id)); err != nil {
			t.Fatalf("seed grant %s: %v", id, err)
		}
	}
}

// TestIntegrationConcurrentRevocationsCannotBothPass is the headline assertion:
// two well-formed requests, each revoking a different one of the application's
// two administrators, must not both succeed.
func TestIntegrationConcurrentRevocationsCannotBothPass(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	seedTwoAdministrators(t, db, c)

	floor := RequireAnotherExercisableAdmin(liveUsers(db))

	entered := make(chan struct{})
	release := make(chan struct{})
	// Released through a sync.Once registered as a cleanup, not with a bare
	// close(). A t.Fatal below returns from THIS goroutine while the first
	// revoker is still parked holding an open transaction, and the pool's own
	// cleanup would then block forever waiting for that connection: the test
	// would hang instead of failing.
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)

	// The predicate is the parking spot. It runs inside the revoking
	// transaction, after the FOR UPDATE read and before the DELETE — exactly the
	// window a naive race is too fast to land in.
	parking := func(ctx context.Context, remaining []Grant) error {
		close(entered)
		<-release
		return floor(ctx, remaining)
	}

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)

	go func() {
		_, err := c.Revoke(context.Background(), adminA, parking, recordingIntent(AuditActionRevoked, adminA))
		firstDone <- err
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first revoker never reached its predicate")
	}

	go func() {
		_, err := c.Revoke(context.Background(), adminB, floor, recordingIntent(AuditActionRevoked, adminB))
		secondDone <- err
	}()

	// Observed, not assumed: the second revoker is blocked on the first's row
	// locks.
	waitForALockWaiter(t, db)

	releaseAll()

	var firstErr, secondErr error
	select {
	case firstErr = <-firstDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the first revoker never finished")
	}
	select {
	case secondErr = <-secondDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the second revoker never finished — the row lock was not released")
	}

	if firstErr != nil {
		t.Fatalf("the first revocation failed: %v — it ran against two administrators and must succeed", firstErr)
	}
	if !errors.Is(secondErr, ErrLastPlatformAdmin) {
		t.Fatalf("the second revocation returned %v, want ErrLastPlatformAdmin — it ran AFTER the "+
			"first committed and must see only one administrator left", secondErr)
	}
	if n := carrierCount(t, db); n != 1 {
		t.Fatalf("%d administrator(s) remain, want exactly 1 — two concurrent revocations took the "+
			"application below the floor", n)
	}
	if n := intentCount(t, db, AuditActionRevoked); n != 1 {
		t.Errorf("%d revocation records written, want 1 — the refused revocation must not appear "+
			"in the trail", n)
	}
}

// TestIntegrationUnserialisedRevocationsReachZero is the falsification, kept
// permanently rather than run once and described in a commit message.
//
// It performs the SAME two revocations with the same predicate — "does another
// administrator remain?" — but reads WITHOUT the row lock, and asserts that the
// application reaches ZERO administrators. If this ever stops reaching zero, the
// scenario has drifted and the test above is no longer exercising the hazard it
// claims to.
//
// No goroutines: the interleaving is written out by hand, which is the whole
// point — this is the schedule the FOR UPDATE forbids.
func TestIntegrationUnserialisedRevocationsReachZero(t *testing.T) {
	db := carrierTestDB(t)
	c := newCarrier(t, db)
	seedTwoAdministrators(t, db, c)
	ctx := context.Background()

	floor := RequireAnotherExercisableAdmin(liveUsers(db))

	// unlockedRevoke is Carrier.Revoke with ONE thing removed: the FOR UPDATE.
	unlockedRevoke := func(userID string) (*sql.Tx, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+grantColumns+` FROM `+carrierTable)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		var remaining []Grant
		for rows.Next() {
			g, err := scanGrant(rows)
			if err != nil {
				_ = rows.Close()
				_ = tx.Rollback()
				return nil, err
			}
			if g.UserID != userID {
				remaining = append(remaining, *g)
			}
		}
		_ = rows.Close()
		if err := floor(ctx, remaining); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+carrierTable+` WHERE user_id = $1`, userID); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		return tx, nil
	}

	// Both readers run BEFORE either writer commits: the interleaving forced by
	// hand, and the one the row lock exists to make impossible.
	txA, err := unlockedRevoke(adminA)
	if err != nil {
		t.Fatalf("unserialised revoke of A: %v", err)
	}
	txB, err := unlockedRevoke(adminB)
	if err != nil {
		_ = txA.Rollback()
		t.Fatalf("unserialised revoke of B: %v — both revocations read a carrier holding two "+
			"administrators, so both must have passed the floor", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	if err := txB.Commit(); err != nil {
		t.Fatalf("commit B: %v", err)
	}

	if n := carrierCount(t, db); n != 0 {
		t.Fatalf("%d administrator(s) remain, want 0 — without the row lock two concurrent "+
			"revocations must be able to empty the carrier. If this no longer reproduces, the "+
			"scenario has drifted and TestIntegrationConcurrentRevocationsCannotBothPass is no "+
			"longer exercising the hazard it claims to", n)
	}
}

// Serialize's advisory lock, which is what orders a carrier revoke against the
// application's OTHER authority-reducing writes — the ones the row lock cannot
// reach because they are on different tables, possibly a different connection.
//
// Forced the same way, through the test-only insideLock hook, and observed the
// same way through pg_stat_activity.
func TestIntegrationSerializeBlocksASecondCallerUntilTheFirstFinishes(t *testing.T) {
	db := carrierTestDB(t)
	first := newCarrier(t, db)
	second := newCarrier(t, db)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	first.insideLock = func(context.Context) {
		close(entered)
		<-release
	}

	var order []string
	var mu sync.Mutex
	record := func(who string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, who)
	}

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)

	go func() {
		firstDone <- first.Serialize(context.Background(), func(context.Context) error {
			record("first")
			return nil
		})
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first caller never took the lock")
	}

	go func() {
		secondDone <- second.Serialize(context.Background(), func(context.Context) error {
			record("second")
			return nil
		})
	}()

	waitForALockWaiter(t, db)
	releaseAll()

	for i, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("caller %d: %v", i+1, err)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("caller %d never finished — the advisory lock was not released", i+1)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("writes ran in order %v, want [first second] — the second caller entered the "+
			"critical section before the first had left it", order)
	}
}

// Two applications sharing one database must not block each other. Same
// database, same lock mechanism, different carrier table: the second caller
// must NOT wait.
func TestIntegrationTwoApplicationsCarriersDoNotBlockEachOther(t *testing.T) {
	db := carrierTestDB(t)
	mustExec(t, db, `CREATE TABLE `+testSchema+`.other_platform_admins (
		user_id UUID PRIMARY KEY, granted_by UUID, granted_at TIMESTAMPTZ NOT NULL DEFAULT now(), note TEXT)`)

	mine := newCarrier(t, db)
	theirs, err := New(db, testSchema+".other_platform_admins")
	if err != nil {
		t.Fatalf("New for the second application's carrier: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	mine.insideLock = func(context.Context) {
		close(entered)
		<-release
	}

	held := make(chan error, 1)
	go func() {
		held <- mine.Serialize(context.Background(), func(context.Context) error { return nil })
	}()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first application never took its lock")
	}

	// The other application's carrier, while the first one's lock is held.
	done := make(chan error, 1)
	go func() {
		done <- theirs.Serialize(context.Background(), func(context.Context) error { return nil })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the second application's Serialize failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second application's carrier blocked on the first application's floor lock — " +
			"two applications sharing a database would serialise every administrator change against " +
			"each other, which is what deriving the lock key from the table name exists to prevent")
	}

	releaseOnce.Do(func() { close(release) })
	if err := <-held; err != nil {
		t.Fatalf("the first application's Serialize failed: %v", err)
	}
}
