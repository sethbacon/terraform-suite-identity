//go:build integration

package auditoutbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// The evidence, against a real PostgreSQL rather than a mock.
//
// Four of this package's claims cannot be proved anywhere else:
//
//   - "a privileged mutation cannot commit without its audit record" is
//     enforced by a DEFERRABLE constraint trigger, and only a real commit can be
//     refused by one;
//   - "redelivery does not duplicate" is enforced by the destination's primary
//     key;
//   - "a crash mid-flight loses nothing" needs a transaction that really dies —
//     forced here by terminating the relay's backend while it is parked inside
//     its transaction, not by racing goroutines and hoping;
//   - "the rendered DDL is valid SQL" is only true if PostgreSQL parses it.
//
// EVERY OBJECT HERE IS DELIBERATELY OFF-DEFAULT: schema `app`, outbox
// `audit_intents`, destination `activity_log`. A hardcoded `audit_outbox` or
// `audit_logs` anywhere in the package would fail this suite rather than pass it
// by coincidence.
const (
	testSchema      = "app"
	testOutbox      = "app.audit_intents"
	testDestination = "app.activity_log"
	testGuarded     = "app.platform_admins"

	actionGranted = "platform_admin.granted"
	actionRevoked = "platform_admin.revoked"
	resourceAdmin = "platform_admin"
)

// wideDestination carries actor_email — identity.audit_logs after identity
// migration 000007.
const wideDestination = `CREATE TABLE app.activity_log (
	id              UUID         PRIMARY KEY,
	user_id         UUID,
	organization_id UUID,
	action          VARCHAR(500) NOT NULL,
	resource_type   VARCHAR(100),
	resource_id     VARCHAR(255),
	metadata        JSONB,
	ip_address      VARCHAR(45),
	created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
	actor_email     VARCHAR(255))`

// narrowDestination is the pre-000007 shape, with the narrower resource_id and
// INET ip_address a registry-style public.audit_logs actually has. This is the
// destination registry #864 is about: every write through the shared audit
// writer fails against it with 42703.
const narrowDestination = `CREATE TABLE app.activity_log (
	id              UUID         PRIMARY KEY,
	user_id         UUID,
	organization_id UUID,
	action          VARCHAR(255) NOT NULL,
	resource_type   VARCHAR(50),
	resource_id     UUID,
	metadata        JSONB,
	ip_address      INET,
	created_at      TIMESTAMP    NOT NULL DEFAULT now())`

const guardedTable = `CREATE TABLE app.platform_admins (
	user_id    UUID PRIMARY KEY,
	granted_by UUID,
	granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	note       TEXT)`

func carrierTrigger() TriggerSpec {
	return TriggerSpec{
		Outbox:        testOutbox,
		Table:         testGuarded,
		SubjectColumn: "user_id",
		ResourceType:  resourceAdmin,
		OnInsert:      actionGranted,
		OnDelete:      actionRevoked,
	}
}

// outboxTestDB returns a connection to this package's own test database with
// the `app` schema freshly built from the RENDERED DDL, plus the DSN so a test
// can open a second pool of its own.
//
// Its own database, derived from TEST_DATABASE_URL by suffixing the name,
// because `go test ./...` runs package binaries concurrently and every DB-backed
// suite in this module resets its own schema.
func outboxTestDB(t *testing.T, destinationDDL string) (*sql.DB, string) {
	t.Helper()

	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL must be a postgres:// URL, got %q (parse error: %v)", raw, err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	if base == "" {
		t.Fatalf("TEST_DATABASE_URL %q names no database", raw)
	}
	name := base + "_auditoutbox"

	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatalf("failed to open the administrative connection: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.Ping(); err != nil {
		t.Fatalf("failed to reach the database at TEST_DATABASE_URL: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE ` + pgquote.Identifier(name)); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" { // duplicate_database
			t.Fatalf("failed to create the %q test database (the role needs CREATEDB): %v", name, err)
		}
	}

	target := *parsed
	target.Path = "/" + name
	dsn := target.String()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to open %q: %v", name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach %q: %v", name, err)
	}

	// A clean slate per run.
	mustExec(t, db, `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`)
	mustExec(t, db, `CREATE SCHEMA `+testSchema)
	mustExec(t, db, destinationDDL)
	mustExec(t, db, guardedTable)

	// THE RENDERED DDL, EXECUTED. If OutboxDDL or TriggerSpec.DDL emits
	// anything PostgreSQL will not parse, every test in this file fails here.
	outboxDDL, err := OutboxDDL(testOutbox)
	if err != nil {
		t.Fatalf("OutboxDDL: %v", err)
	}
	mustExec(t, db, outboxDDL)
	triggerDDL, err := carrierTrigger().DDL()
	if err != nil {
		t.Fatalf("TriggerSpec.DDL: %v", err)
	}
	mustExec(t, db, triggerDDL)

	return db, dsn
}

func mustExec(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.Exec(statement); err != nil {
		t.Fatalf("statement failed: %v\n%s", err, statement)
	}
}

func countRows(t *testing.T, db *sql.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

func newUUID(t *testing.T) string {
	t.Helper()
	return uuid.New().String()
}

func grantIntent(actor, target string) *Intent {
	resource := resourceAdmin
	email := "actor@example.test"
	ip := "203.0.113.7"
	return &Intent{
		Action:       actionGranted,
		ActorUserID:  &actor,
		ActorEmail:   &email,
		ResourceType: &resource,
		ResourceID:   &target,
		IPAddress:    &ip,
		Metadata:     map[string]interface{}{"target_user_id": target},
	}
}

// grantWithIntent performs the mutation and its audit intent in one
// transaction, exactly as a repository taking an IntentWriter would.
func grantWithIntent(t *testing.T, db *sql.DB, o *Outbox, actor, target string) *Intent {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`INSERT INTO app.platform_admins (user_id, granted_by) VALUES ($1, $2)`, target, actor); err != nil {
		t.Fatalf("granting: %v", err)
	}
	intent := grantIntent(actor, target)
	if err := RequireIntentWriter(o.Writer(intent)); err != nil {
		t.Fatalf("RequireIntentWriter: %v", err)
	}
	if err := o.Writer(intent)(context.Background(), tx); err != nil {
		t.Fatalf("writing the intent: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return intent
}

func newTestRelay(t *testing.T, db *sql.DB, o *Outbox) *Relay {
	t.Helper()
	sink, err := NewTableSink(db, testDestination)
	if err != nil {
		t.Fatalf("NewTableSink: %v", err)
	}
	return NewRelay(o, sink, nil, RelayConfig{BatchSize: 10, RetainDelivered: -1, BacklogWarn: -1})
}

func newTestOutbox(t *testing.T, db *sql.DB) *Outbox {
	t.Helper()
	o, err := New(db, testOutbox)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o
}

// ---------------------------------------------------------------------------
// The constraint trigger: the database refuses the unaudited commit
// ---------------------------------------------------------------------------

// THE PROPERTY, ENFORCED RATHER THAN INTENDED. This is the case the Go layer
// cannot cover: hand-written SQL, a migration, a future handler that forgets.
// The trigger is DEFERRABLE INITIALLY DEFERRED, so the INSERT itself succeeds
// and the COMMIT is what fails — and the carrier is unchanged afterwards.
func TestIntegrationUnauditedMutationCannotCommit(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	target := newUUID(t)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO app.platform_admins (user_id) VALUES ($1)`, target); err != nil {
		t.Fatalf("the INSERT itself should succeed; the deferred check happens at COMMIT: %v", err)
	}
	err = tx.Commit()
	if err == nil {
		t.Fatal("an unaudited privileged mutation COMMITTED; the constraint trigger is not enforcing")
	}
	if !strings.Contains(err.Error(), "no audit intent in this transaction") {
		t.Fatalf("commit failed with %v, want the audit-intent refusal", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Errorf("refusal carried SQLSTATE %v, want 23514 (check_violation)", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.platform_admins`); n != 0 {
		t.Errorf("app.platform_admins has %d row(s) after the refused commit, want 0", n)
	}
}

// The same mutation WITH its intent commits. Without this the test above would
// pass against a trigger that refuses everything.
func TestIntegrationAuditedMutationCommits(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	actor, target := newUUID(t), newUUID(t)

	intent := grantWithIntent(t, db, o, actor, target)

	if n := countRows(t, db, `SELECT count(*) FROM app.platform_admins WHERE user_id = $1`, target); n != 1 {
		t.Errorf("app.platform_admins has %d row(s) for the target, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE event_id = $1`, intent.EventID); n != 1 {
		t.Errorf("app.audit_intents has %d row(s) for the intent, want 1", n)
	}
}

// The check is "an intent from THIS transaction naming THIS subject with THIS
// action". Each half of that is load-bearing, and each is refused separately.
func TestIntegrationTriggerRejectsAMismatchedOrStaleIntent(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	actor, target, other := newUUID(t), newUUID(t), newUUID(t)
	ctx := context.Background()

	t.Run("intent names another subject", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`INSERT INTO app.platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := o.Enqueue(ctx, tx, grantIntent(actor, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("a grant committed against an audit record naming somebody else")
		}
	})

	t.Run("intent from an earlier transaction", func(t *testing.T) {
		// This is why the trigger matches pg_current_xact_id() and not a
		// foreign key: an FK would be satisfied by an intent written days ago.
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Enqueue(ctx, tx, grantIntent(actor, target)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("committing the intent alone: %v", err)
		}

		tx2, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx2.Rollback() }()
		if _, err := tx2.Exec(`INSERT INTO app.platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := tx2.Commit(); err == nil {
			t.Fatal(`a grant committed against an audit record written by an EARLIER transaction; ` +
				`"same transaction" is the property, and a foreign key would not have expressed it`)
		}
	})

	t.Run("revocation under a grant's record", func(t *testing.T) {
		grantWithIntent(t, db, o, actor, other)

		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`DELETE FROM app.platform_admins WHERE user_id = $1`, other); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := o.Enqueue(ctx, tx, grantIntent(actor, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal(`a REVOCATION committed under a record that says "granted"`)
		}
		if n := countRows(t, db, `SELECT count(*) FROM app.platform_admins WHERE user_id = $1`, other); n != 1 {
			t.Errorf("the grant is gone despite the refused commit (%d rows)", n)
		}
	})

	t.Run("a correctly named revocation commits", func(t *testing.T) {
		grantWithIntent(t, db, o, actor, newUUID(t))
		var subject string
		if err := db.QueryRow(`SELECT user_id::text FROM app.platform_admins LIMIT 1`).Scan(&subject); err != nil {
			t.Fatal(err)
		}

		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`DELETE FROM app.platform_admins WHERE user_id = $1`, subject); err != nil {
			t.Fatalf("delete: %v", err)
		}
		revoke := grantIntent(actor, subject)
		revoke.Action = actionRevoked
		if err := o.Enqueue(ctx, tx, revoke); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("a correctly audited revocation was refused: %v", err)
		}
	})
}

// The trigger guards only the operations the spec named. UPDATE was left out of
// carrierTrigger, so it must NOT be refused — a guard that fires on operations
// it never claimed is as wrong as one that misses the ones it did.
func TestIntegrationTriggerLeavesUnnamedOperationsAlone(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	actor, target := newUUID(t), newUUID(t)
	grantWithIntent(t, db, o, actor, target)

	if _, err := db.Exec(`UPDATE app.platform_admins SET note = 'promoted' WHERE user_id = $1`, target); err != nil {
		t.Fatalf("an UPDATE the spec did not guard was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delivery, end to end
// ---------------------------------------------------------------------------

func TestIntegrationRelayDeliversTheIntent(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	actor, target := newUUID(t), newUUID(t)
	intent := grantWithIntent(t, db, o, actor, target)

	relay := newTestRelay(t, db, o)
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch = (%d, %v), want (1, nil)", delivered, err)
	}

	var action, resourceID, actorEmail string
	var occurred time.Time
	err := db.QueryRow(`SELECT action, resource_id, actor_email, created_at FROM app.activity_log WHERE id = $1`,
		intent.EventID).Scan(&action, &resourceID, &actorEmail, &occurred)
	if err != nil {
		t.Fatalf("the delivered row is missing or unreadable: %v", err)
	}
	if action != actionGranted || resourceID != target {
		t.Errorf("delivered row = (%q, %q), want (%s, %s)", action, resourceID, actionGranted, target)
	}
	// The address the intent carried, not one resolved by a join across the
	// identity boundary.
	if actorEmail != "actor@example.test" {
		t.Errorf("actor_email = %q, want the address captured at intent time", actorEmail)
	}
	// The audit trail must say when the event HAPPENED, not when it was
	// delivered. TIMESTAMPTZ stores microseconds and PostgreSQL ROUNDS to them,
	// so the comparison has to round too: truncating fails roughly half the
	// time, whenever the sub-microsecond digits round up. It did exactly that
	// on main after v0.28.0 -- stored 689835us against a truncated 689834us --
	// having passed on the PR only because that run's nanoseconds rounded down.
	wantOccurred := intent.OccurredAt.UTC().Round(time.Microsecond)
	if !occurred.UTC().Equal(wantOccurred) {
		t.Errorf("created_at = %v, want the intent's OccurredAt rounded to microseconds %v (raw %v)",
			occurred.UTC(), wantOccurred, intent.OccurredAt.UTC())
	}
	if delay := time.Since(occurred); delay < 0 {
		t.Errorf("created_at %v is in the future; the delivery time leaked into the record", occurred)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE delivered_at IS NULL`); n != 0 {
		t.Errorf("%d intent(s) still pending after a successful delivery", n)
	}
}

// At-least-once transport, applied three times, must leave exactly one row.
// Redelivery is forced by resetting delivered_at — precisely the state a crashed
// relay leaves behind.
func TestIntegrationRedeliveryDoesNotDuplicate(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	intent := grantWithIntent(t, db, o, newUUID(t), newUUID(t))
	relay := newTestRelay(t, db, o)

	for i := 0; i < 3; i++ {
		// Each pass must SUCCEED, not merely fail harmlessly. A destination
		// that rejected the redelivery outright would also leave one row
		// behind, while leaving the intent stuck in the backlog forever.
		if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 1 {
			t.Fatalf("delivery %d = (%d, %v), want (1, nil) — redelivery must be absorbed, not rejected",
				i+1, delivered, err)
		}
		mustExec(t, db, `UPDATE app.audit_intents SET delivered_at = NULL`)
	}

	if n := countRows(t, db, `SELECT count(*) FROM app.activity_log WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("the destination holds %d copies of one event after three deliveries, want exactly 1", n)
	}
}

// parkingSink delivers for real, then blocks so the test can kill the relay's
// backend at a moment of its choosing.
type parkingSink struct {
	inner   Sink
	parked  chan struct{}
	release chan struct{}
	once    bool
}

func (s *parkingSink) Deliver(ctx context.Context, intent Intent) error {
	if err := s.inner.Deliver(ctx, intent); err != nil {
		return err
	}
	if !s.once {
		s.once = true
		close(s.parked)
		<-s.release
	}
	return nil
}

// THE CRASH TEST, with a FORCED SCHEDULE rather than a race: the relay is parked
// inside its transaction immediately after the destination write, its backend is
// terminated from another connection, and only then is it allowed to continue.
//
// What must be true afterwards: the destination row exists (the sink got
// there), the outbox intent is STILL PENDING (nothing was marked under a
// transaction that never committed), and a fresh relay delivers it again to a
// total of exactly one row.
func TestIntegrationRelayCrashMidFlightLosesNothingAndDuplicatesNothing(t *testing.T) {
	db, dsn := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)
	intent := grantWithIntent(t, db, o, newUUID(t), newUUID(t))

	// A single-connection pool for the relay, so the backend to terminate is
	// known exactly rather than guessed at from pg_stat_activity.
	relayPool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open(relay pool): %v", err)
	}
	defer func() { _ = relayPool.Close() }()
	relayPool.SetMaxOpenConns(1)
	relayPool.SetMaxIdleConns(1)
	var relayPID int
	if err := relayPool.QueryRow(`SELECT pg_backend_pid()`).Scan(&relayPID); err != nil {
		t.Fatalf("reading the relay's backend pid: %v", err)
	}

	innerSink, err := NewTableSink(db, testDestination)
	if err != nil {
		t.Fatal(err)
	}
	parked := make(chan struct{})
	release := make(chan struct{})
	crashing := &parkingSink{inner: innerSink, parked: parked, release: release}

	relayOutbox, err := New(relayPool, testOutbox)
	if err != nil {
		t.Fatal(err)
	}
	relay := NewRelay(relayOutbox, crashing, nil, RelayConfig{BatchSize: 10, RetainDelivered: -1, BacklogWarn: -1})
	done := make(chan error, 1)
	go func() {
		_, _, err := relay.DeliverBatch(context.Background())
		done <- err
	}()

	select {
	case <-parked:
	case <-time.After(30 * time.Second):
		t.Fatal("the relay never reached the sink")
	}

	// The destination write has happened; the outbox transaction has not
	// committed. Kill it.
	if n := countRows(t, db, `SELECT count(*) FROM app.activity_log WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("the destination holds %d row(s) at the parked moment, want 1 — the schedule is not what the test assumes", n)
	}
	if _, err := db.Exec(`SELECT pg_terminate_backend($1)`, relayPID); err != nil {
		t.Fatalf("terminating the relay backend: %v", err)
	}
	close(release)

	if err := <-done; err == nil {
		t.Fatal("the relay reported a successful batch after its backend was killed")
	}

	// NOTHING WAS MARKED. This is the crash contract.
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE event_id = $1 AND delivered_at IS NULL`, intent.EventID); n != 1 {
		t.Fatalf("the intent is no longer pending after the crash (%d pending rows); "+
			"a marked-but-uncommitted delivery would mean records can be lost", n)
	}

	// A fresh relay picks it up, and the destination absorbs the redelivery.
	recovered := newTestRelay(t, db, o)
	if _, delivered, err := recovered.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("recovery DeliverBatch = (%d, %v), want (1, nil)", delivered, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.activity_log WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("the destination holds %d copies after the crash and recovery, want exactly 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE delivered_at IS NULL`); n != 0 {
		t.Errorf("%d intent(s) still pending after recovery", n)
	}
}

// The mutation has already committed with its record, so the record must survive
// a destination outage and land when the destination returns. Never a silent
// drop, and never a silently unbounded queue.
func TestIntegrationBrokenDestinationRetainsEveryRecordAndDrainsOnRepair(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)

	const n = 4
	var intents []*Intent
	for i := 0; i < n; i++ {
		intents = append(intents, grantWithIntent(t, db, o, newUUID(t), newUUID(t)))
	}

	mustExec(t, db, `ALTER TABLE app.activity_log RENAME TO activity_log_broken`)

	relay := newTestRelay(t, db, o)
	for cycle := 1; cycle <= 3; cycle++ {
		claimed, delivered, err := relay.DeliverBatch(context.Background())
		if err != nil {
			t.Fatalf("cycle %d: DeliverBatch returned %v; a broken destination must not break the relay", cycle, err)
		}
		if claimed != n || delivered != 0 {
			t.Fatalf("cycle %d: claimed=%d delivered=%d, want %d and 0", cycle, claimed, delivered, n)
		}

		backlog, err := o.Backlog(context.Background())
		if err != nil {
			t.Fatalf("cycle %d: Backlog: %v", cycle, err)
		}
		if backlog.Pending != n || backlog.Failed != n {
			t.Fatalf("cycle %d: backlog = %+v, want %d pending and %d failed — an operator must be able to see this",
				cycle, backlog, n, n)
		}
		if backlog.OldestPending.IsZero() {
			t.Fatalf("cycle %d: the backlog reports no oldest event, so its age cannot be alarmed on", cycle)
		}
	}

	// Attempts accumulate on every row, so an operator can see it is stuck
	// rather than merely busy — and every record is still there, with a reason.
	var minAttempts int
	if err := db.QueryRow(`SELECT min(attempts) FROM app.audit_intents WHERE delivered_at IS NULL`).Scan(&minAttempts); err != nil {
		t.Fatalf("reading attempts: %v", err)
	}
	if minAttempts != 3 {
		t.Errorf("min(attempts) = %d after three cycles, want 3", minAttempts)
	}
	var lastErr sql.NullString
	if err := db.QueryRow(`SELECT last_error FROM app.audit_intents LIMIT 1`).Scan(&lastErr); err != nil {
		t.Fatalf("reading last_error: %v", err)
	}
	if !lastErr.Valid || lastErr.String == "" {
		t.Error("the retained intent carries no reason for its failure")
	}
	if got := countRows(t, db, `SELECT count(*) FROM app.audit_intents`); got != n {
		t.Fatalf("the outbox holds %d row(s), want %d — nothing may be dropped for failing to deliver", got, n)
	}

	// Repair it. Everything that accumulated lands, exactly once each.
	mustExec(t, db, `ALTER TABLE app.activity_log_broken RENAME TO activity_log`)
	// A relay whose plan was cached before the outage must recover too.
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != n {
		t.Fatalf("after repair: DeliverBatch = (%d, %v), want (%d, nil)", delivered, err, n)
	}
	for _, intent := range intents {
		if got := countRows(t, db, `SELECT count(*) FROM app.activity_log WHERE id = $1`, intent.EventID); got != 1 {
			t.Errorf("the destination holds %d row(s) for %s, want exactly 1", got, intent.EventID)
		}
	}
}

// Pruning bounds the table's growth, and must never be able to reach a record
// that has not arrived.
func TestIntegrationPruneRemovesDeliveredHistoryAndNeverTheBacklog(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)

	for i := 0; i < 2; i++ {
		grantWithIntent(t, db, o, newUUID(t), newUUID(t))
	}
	relay := newTestRelay(t, db, o)
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 2 {
		t.Fatalf("DeliverBatch = (%d, %v), want (2, nil)", delivered, err)
	}
	mustExec(t, db, `UPDATE app.audit_intents SET delivered_at = now() - interval '30 days'`)

	// One intent that never got delivered, aged well past the retention window.
	stuck := grantWithIntent(t, db, o, newUUID(t), newUUID(t))
	mustExec(t, db, `UPDATE app.audit_intents SET occurred_at = now() - interval '30 days' WHERE delivered_at IS NULL`)

	pruned, err := o.PruneDelivered(context.Background(), time.Now().Add(-7*24*time.Hour), 100)
	if err != nil {
		t.Fatalf("PruneDelivered: %v", err)
	}
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE event_id = $1`, stuck.EventID); n != 1 {
		t.Fatal("the pruner deleted an UNDELIVERED intent; that is a destroyed audit record, " +
			"which is worse than the unbounded table it was trying to prevent")
	}
}

// The relay drains a backlog larger than one batch, oldest first.
func TestIntegrationRelayDrainsABacklogAcrossBatches(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	o := newTestOutbox(t, db)

	const n = 7
	for i := 0; i < n; i++ {
		grantWithIntent(t, db, o, newUUID(t), newUUID(t))
	}

	sink, err := NewTableSink(db, testDestination)
	if err != nil {
		t.Fatal(err)
	}
	relay := NewRelay(o, sink, nil, RelayConfig{BatchSize: 2, RetainDelivered: -1, BacklogWarn: -1})
	relay.RunCycle(context.Background())

	if got := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE delivered_at IS NULL`); got != 0 {
		t.Errorf("%d intent(s) still pending after a full cycle", got)
	}
	if got := countRows(t, db, `SELECT count(*) FROM app.activity_log`); got != n {
		t.Errorf("the destination holds %d rows, want %d", got, n)
	}
}

// ---------------------------------------------------------------------------
// The destination probe (registry #864)
// ---------------------------------------------------------------------------

// THE DELIVERY TARGET IS BROKEN BY DEFAULT, AND THIS PATH IS NOT.
//
// identity/store's CreateAuditLog writes actor_email unconditionally, but that
// column exists only after identity migration 000007. Against the destination
// below — the shape registry's default topology actually resolves to — every
// write through the shared writer fails with 42703. The sink asks the connection
// which columns the table has instead of assuming, so the audit trail is
// delivered anyway, with the narrower resource_id and INET ip_address that
// destination really carries.
func TestIntegrationSinkDeliversAgainstAPre000007Destination(t *testing.T) {
	db, _ := outboxTestDB(t, narrowDestination)
	o := newTestOutbox(t, db)

	// The premise, asserted rather than assumed.
	var hasActorEmail bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_attribute
		WHERE attrelid = to_regclass('app.activity_log') AND attname = 'actor_email' AND NOT attisdropped)`).
		Scan(&hasActorEmail); err != nil {
		t.Fatalf("probing the destination: %v", err)
	}
	if hasActorEmail {
		t.Fatal("the destination in this test has actor_email, so it is not the shape issue #864 describes")
	}

	// The premise's other half: the unconditional write really does fail here.
	_, err := db.Exec(`INSERT INTO app.activity_log (id, action, actor_email) VALUES ($1, 'x', 'y')`, newUUID(t))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42703" {
		t.Fatalf("writing actor_email to this destination returned %v, want 42703 undefined_column — "+
			"without that this test is not covering the failure it claims to", err)
	}

	target := newUUID(t)
	intent := grantWithIntent(t, db, o, newUUID(t), target)

	relay := newTestRelay(t, db, o)
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch against the pre-000007 destination = (%d, %v), want (1, nil) — "+
			"the outbox must not be blocked by the schema gap", delivered, err)
	}

	var action, resourceID string
	if err := db.QueryRow(`SELECT action, resource_id::text FROM app.activity_log WHERE id = $1`, intent.EventID).
		Scan(&action, &resourceID); err != nil {
		t.Fatalf("the delivered row is missing from the narrow destination: %v", err)
	}
	if action != actionGranted || resourceID != target {
		t.Errorf("delivered row = (%q, %q), want (%s, %s)", action, resourceID, actionGranted, target)
	}
	if n := countRows(t, db, `SELECT count(*) FROM app.audit_intents WHERE delivered_at IS NULL`); n != 0 {
		t.Errorf("%d intent(s) still pending", n)
	}
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

// Verify reports the schema an UNQUALIFIED name resolved to on the connection in
// use. That is the whole point of reporting it: the tables are app-owned, and
// search_path is what decides which physical one a bare name reaches.
func TestIntegrationVerifyReportsWhereUnqualifiedNamesResolve(t *testing.T) {
	_, dsn := outboxTestDB(t, wideDestination)

	routed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := routed.Query()
	query.Set("search_path", testSchema)
	routed.RawQuery = query.Encode()

	db, err := sql.Open("pgx", routed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	o, err := New(db, "audit_intents")
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.Verify(context.Background())
	if err != nil {
		t.Fatalf("Outbox.Verify: %v", err)
	}
	if got != "app.audit_intents" {
		t.Errorf("Outbox.Verify = %q, want app.audit_intents", got)
	}

	sink, err := NewTableSink(db, "activity_log")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sink.Verify(context.Background()); err != nil || got != "app.activity_log" {
		t.Errorf("TableSink.Verify = (%q, %v), want (app.activity_log, nil)", got, err)
	}

	// And a name that resolves to nothing says so, rather than failing later at
	// the first privileged mutation.
	absent, err := New(db, "not_an_outbox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := absent.Verify(context.Background()); !errors.Is(err, ErrOutboxShape) {
		t.Errorf("Verify of an absent table = %v, want ErrOutboxShape", err)
	}
}

// The rendered down-migration removes exactly what the up-migration added, in an
// order that leaves no trigger reading a dropped table.
func TestIntegrationRenderedDropDDLIsClean(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)

	triggerDrop, err := carrierTrigger().DropDDL()
	if err != nil {
		t.Fatal(err)
	}
	outboxDrop, err := OutboxDropDDL(testOutbox)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, triggerDrop)
	mustExec(t, db, outboxDrop)

	// Rolling back reopens the hole, which is the documented consequence: the
	// unaudited mutation now commits.
	if _, err := db.Exec(`INSERT INTO app.platform_admins (user_id) VALUES ($1)`, newUUID(t)); err != nil {
		t.Fatalf("after the down migration the carrier is unusable rather than merely unguarded: %v", err)
	}

	for _, object := range []string{"app.audit_intents", "app.audit_intents_assert_intent"} {
		var present bool
		if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, object).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present {
			t.Errorf("%s survived the down migration", object)
		}
	}
	var triggers int
	if err := db.QueryRow(`SELECT count(*) FROM pg_trigger
		WHERE tgrelid = to_regclass('app.platform_admins') AND NOT tgisinternal`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 0 {
		t.Errorf("%d trigger(s) survived the down migration", triggers)
	}
}

// A sanity check that the suite is talking to the database it thinks it is.
func TestIntegrationOutboxTableIsWhereTheDDLPutIt(t *testing.T) {
	db, _ := outboxTestDB(t, wideDestination)
	var schema string
	if err := db.QueryRow(`SELECT n.nspname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.oid = to_regclass($1)`, testOutbox).Scan(&schema); err != nil {
		t.Fatalf("locating %s: %v", testOutbox, err)
	}
	if schema != testSchema {
		t.Errorf("%s lives in %q, want %q", testOutbox, schema, testSchema)
	}
	if _, err := db.Exec(fmt.Sprintf(`SELECT 1 FROM %s LIMIT 1`, testOutbox)); err != nil {
		t.Fatalf("the rendered outbox is not queryable: %v", err)
	}
}
