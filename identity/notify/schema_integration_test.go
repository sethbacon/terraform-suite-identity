//go:build integration

package notify

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// This suite runs against its OWN database (TEST_DATABASE_URL's name plus a
// suffix), like identity/store's: package test binaries run concurrently, and
// this one creates and drops notification_channels in more than one schema.

const notifyTestSuffix = "_notify"

func notifyTestDSN(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL must be a postgres:// URL for this suite, got %q (parse error: %v)", dsn, err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	if base == "" {
		t.Fatalf("TEST_DATABASE_URL %q names no database", dsn)
	}
	name := base + notifyTestSuffix

	admin, err := sql.Open("pgx", dsn)
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
	return target.String()
}

// notifyConn opens a pool on the suite's database with the given search_path
// ("" leaves the server default of `"$user", public`).
func notifyConn(t *testing.T, baseDSN, searchPath string) *sql.DB {
	t.Helper()

	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse %q: %v", baseDSN, err)
	}
	if searchPath != "" {
		q := parsed.Query()
		q.Set("search_path", searchPath)
		parsed.RawQuery = q.Encode()
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatalf("failed to open the test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach the test database: %v", err)
	}
	return db
}

func notifyExec(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	for _, s := range statements {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("statement failed: %v\n%s", err, s)
		}
	}
}

// TestIntegrationChannelTableDDLSatisfiesTheRepository runs the DDL this package
// ships and then drives every ChannelRepository statement against the table it
// created.
//
// This is what replaces the prose contract. A doc comment cannot be executed, so
// a consuming app's hand-written migration was only ever checked by a delivery
// attempt in production; this proves the shipped definition and the shipped
// statements agree, on a real server, before either is released.
func TestIntegrationChannelTableDDLSatisfiesTheRepository(t *testing.T) {
	ctx := context.Background()
	baseDSN := notifyTestDSN(t)
	db := notifyConn(t, baseDSN, "")

	notifyExec(t, db, `DROP TABLE IF EXISTS public.`+ChannelTable)
	notifyExec(t, db, ChannelTableDDL)

	qualified, err := VerifyChannelTable(ctx, db)
	if err != nil {
		t.Fatalf("VerifyChannelTable rejected the table its own shipped DDL created: %v", err)
	}
	if qualified != "public."+ChannelTable {
		t.Fatalf("resolved name = %q, want %q", qualified, "public."+ChannelTable)
	}

	repo := NewChannelRepository(db)

	saved, err := repo.Create(ctx, &NotificationChannel{
		Name: "ops-webhook", Type: "webhook", EncryptedTarget: "SEALED",
		Events: []string{"drift_detected"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("Create against the shipped DDL: %v", err)
	}
	if saved.EncryptedTarget != "" {
		t.Error("Create returned the sealed target to its caller")
	}

	got, err := repo.GetByID(ctx, saved.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.EncryptedTarget != "SEALED" || !got.Enabled || len(got.Events) != 1 {
		t.Errorf("round-tripped channel = %+v, want the sealed target, enabled, one event", got)
	}

	list, err := repo.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v (%d rows), want exactly the one created channel", err, len(list))
	}

	matched, err := repo.ListEnabledForEvent(ctx, "drift_detected")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	if len(matched) != 1 {
		t.Fatalf("ListEnabledForEvent matched %d channels, want 1 — the jsonb containment "+
			"predicate is the statement that pins events to JSONB", len(matched))
	}
	unmatched, err := repo.ListEnabledForEvent(ctx, "some_other_event")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	if len(unmatched) != 0 {
		t.Errorf("ListEnabledForEvent matched %d channels for an unsubscribed event, want 0", len(unmatched))
	}

	if _, err := repo.Update(ctx, saved.ID, "ops-webhook", "slack", []string{}, false, ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := repo.RecordDelivery(ctx, saved.ID, "sent", "", time.Now()); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
	if err := repo.Delete(ctx, saved.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, saved.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second Delete = %v, want the not-found sentinel", err)
	}
}

// TestIntegrationVerifyChannelTableRejectsRealDrift replays the shape one
// consuming application actually shipped — encrypted_target BYTEA, events
// TEXT[] — which this DAO cannot scan or query, and which was only discovered by
// running it.
func TestIntegrationVerifyChannelTableRejectsRealDrift(t *testing.T) {
	ctx := context.Background()
	baseDSN := notifyTestDSN(t)
	db := notifyConn(t, baseDSN, "")

	notifyExec(t, db,
		`DROP TABLE IF EXISTS public.`+ChannelTable,
		`CREATE TABLE public.`+ChannelTable+` (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name             TEXT NOT NULL,
			type             TEXT NOT NULL,
			encrypted_target BYTEA NOT NULL,
			events           TEXT[] NOT NULL DEFAULT '{}',
			enabled          BOOLEAN NOT NULL DEFAULT true,
			last_status      TEXT,
			last_error       TEXT,
			last_sent_at     TIMESTAMP,
			created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at       TIMESTAMPTZ NOT NULL DEFAULT now())`,
	)
	t.Cleanup(func() { notifyExec(t, db, `DROP TABLE IF EXISTS public.`+ChannelTable) })

	qualified, err := VerifyChannelTable(ctx, db)
	if err == nil {
		t.Fatal("VerifyChannelTable accepted a table this package's statements cannot use; " +
			"that shape fails inside notification delivery instead")
	}
	if qualified != "public."+ChannelTable {
		t.Errorf("resolved name = %q on failure, want %q", qualified, "public."+ChannelTable)
	}
	for _, want := range []string{"encrypted_target is bytea", "events is text[]", "last_sent_at is timestamp without time zone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q:\n%v", want, err)
		}
	}

	// And the drift really is fatal at use time, which is what makes catching
	// it at startup worth doing. ListEnabledForEvent is the fan-out query the
	// notifier runs for every event: on a text[] events column its jsonb
	// predicate does not even plan.
	if _, lerr := NewChannelRepository(db).ListEnabledForEvent(ctx, "drift_detected"); lerr == nil {
		t.Error("the notifier's fan-out query succeeded against the drifted table, so this " +
			"assertion would be guarding against nothing")
	}
}

// TestIntegrationVerifyChannelTableReportsWhereTheTableResolves is the trap this
// batch was warned about, encoded as a test.
//
// Both consuming applications hold their notification_channels rows in public.
// If a migration in this module created identity.notification_channels, every
// connection whose search_path puts identity first would read the new EMPTY
// table instead — same statement, no error, no rows. The module therefore ships
// no such migration; what it ships is an assertion that says out loud which
// physical table the repository is about to use, so a re-point is a startup log
// line rather than a silently empty channel list.
func TestIntegrationVerifyChannelTableReportsWhereTheTableResolves(t *testing.T) {
	ctx := context.Background()
	baseDSN := notifyTestDSN(t)

	app := notifyConn(t, baseDSN, "")
	notifyExec(t, app, `DROP TABLE IF EXISTS public.`+ChannelTable)
	notifyExec(t, app, ChannelTableDDL)
	if _, err := NewChannelRepository(app).Create(ctx, &NotificationChannel{
		Name: "live-channel", Type: "slack", EncryptedTarget: "SEALED", Enabled: true,
	}); err != nil {
		t.Fatalf("seeding the app-owned table: %v", err)
	}

	// A second, empty table of the same name in another schema: exactly what a
	// migration shipped from this module would have created.
	notifyExec(t, app, `CREATE SCHEMA IF NOT EXISTS identity`)
	shadow := notifyConn(t, baseDSN, "identity")
	notifyExec(t, shadow, `DROP TABLE IF EXISTS identity.`+ChannelTable)
	notifyExec(t, shadow, ChannelTableDDL)
	t.Cleanup(func() {
		notifyExec(t, app, `DROP TABLE IF EXISTS identity.`+ChannelTable, `DROP TABLE IF EXISTS public.`+ChannelTable)
	})

	// The pool a consumer would move this repository onto once the module
	// claimed the table.
	identityFirst := notifyConn(t, baseDSN, "identity,public")

	rows, err := NewChannelRepository(identityFirst).List(ctx)
	if err != nil {
		t.Fatalf("List on the identity-first connection: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("List returned %d rows; the fixture is not reproducing the re-point", len(rows))
	}
	// That is the whole failure: a working query, no error, and every live
	// channel invisible.

	qualified, err := VerifyChannelTable(ctx, identityFirst)
	if err != nil {
		t.Fatalf("VerifyChannelTable: %v", err)
	}
	if qualified != "identity."+ChannelTable {
		t.Fatalf("VerifyChannelTable reported %q; it must report the table the repository "+
			"will actually read (identity.%s), because reporting the one the operator "+
			"expected is how the re-point stays invisible", qualified, ChannelTable)
	}

	// The app-owned connection still reaches the populated table, unchanged.
	appQualified, err := VerifyChannelTable(ctx, app)
	if err != nil {
		t.Fatalf("VerifyChannelTable on the app connection: %v", err)
	}
	if appQualified != "public."+ChannelTable {
		t.Errorf("app connection resolved %q, want public.%s", appQualified, ChannelTable)
	}
	live, err := NewChannelRepository(app).List(ctx)
	if err != nil || len(live) != 1 {
		t.Errorf("List on the app connection = %v (%d rows), want the one live channel", err, len(live))
	}
}

// TestIntegrationVerifyChannelTableReportsAnAbsentTable covers the consumer that
// wires identity/notify without applying ChannelTableDDL at all.
func TestIntegrationVerifyChannelTableReportsAnAbsentTable(t *testing.T) {
	ctx := context.Background()
	baseDSN := notifyTestDSN(t)
	db := notifyConn(t, baseDSN, "")

	notifyExec(t, db, `DROP TABLE IF EXISTS public.`+ChannelTable)

	qualified, err := VerifyChannelTable(ctx, db)
	if err == nil {
		t.Fatal("VerifyChannelTable accepted a database with no notification_channels at all")
	}
	if qualified != "" {
		t.Errorf("resolved name = %q, want empty when nothing resolved", qualified)
	}
	if !strings.Contains(err.Error(), "ChannelTableDDL") {
		t.Errorf("error does not point at the canonical DDL, which is the whole remedy:\n%v", err)
	}
}
