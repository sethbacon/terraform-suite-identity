package identity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrationFilePattern matches golang-migrate's file naming convention:
// <version>_<description>.(up|down).sql, e.g.
// "000005_oidc_config_single_active.up.sql".
var migrationFilePattern = regexp.MustCompile(`^(\d+)_.+\.(up|down)\.sql$`)

// embeddedMigrationVersions reads the embedded migrations directory and returns
// the sorted set of migration versions it contains, requiring every version to
// have BOTH an .up.sql and a .down.sql file.
//
// Deriving the version set from the embed.FS — rather than restating it as a
// literal in a test — is deliberate: a hardcoded "latest version" constant is a
// control that silently goes stale the moment a migration is added without
// touching the test, which is exactly how migrations 000004 and 000005 came to
// be tracked in the repository while the integration test still asserted
// version 3 (issue #140). Anything derived from this function tracks the
// migrations directory automatically and cannot drift from it.
func embeddedMigrationVersions() ([]uint, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations dir: %w", err)
	}

	hasUp := map[uint]bool{}
	hasDown := map[uint]bool{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationFilePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("embedded migration %q does not match the "+
				"<version>_<description>.(up|down).sql naming convention", entry.Name())
		}
		parsed, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("embedded migration %q has an unparseable version: %w", entry.Name(), err)
		}
		version := uint(parsed)
		if match[2] == "up" {
			hasUp[version] = true
		} else {
			hasDown[version] = true
		}
	}

	if len(hasUp) == 0 {
		return nil, fmt.Errorf("no embedded migrations found")
	}

	versions := make([]uint, 0, len(hasUp))
	for version := range hasUp {
		if !hasDown[version] {
			return nil, fmt.Errorf("embedded migration version %d has an .up.sql with no matching .down.sql", version)
		}
		versions = append(versions, version)
	}
	for version := range hasDown {
		if !hasUp[version] {
			return nil, fmt.Errorf("embedded migration version %d has a .down.sql with no matching .up.sql", version)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	return versions, nil
}

// latestEmbeddedMigrationVersion returns the highest embedded migration
// version, failing the test if the embedded set is malformed.
func latestEmbeddedMigrationVersion(t *testing.T) uint {
	t.Helper()

	versions, err := embeddedMigrationVersions()
	if err != nil {
		t.Fatalf("failed to enumerate embedded identity migrations: %v", err)
	}
	return versions[len(versions)-1]
}

// TestEmbeddedMigrationsLoad guards against a broken or empty migrations embed:
// the iofs source must load and expose migration version 1. (Actually
// applying the migrations requires a live PostgreSQL and is covered by the
// "integration"-build-tagged TestIntegrationRunMigrations in
// db_integration_test.go, run via `go test -tags=integration ./...`.)
func TestEmbeddedMigrationsLoad(t *testing.T) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("failed to load embedded identity migrations: %v", err)
	}
	defer func() { _ = src.Close() }()

	first, err := src.First()
	if err != nil {
		t.Fatalf("no embedded identity migrations found: %v", err)
	}
	if first != 1 {
		t.Errorf("expected first identity migration to be version 1, got %d", first)
	}
}

// TestEmbeddedMigrationsAreContiguousAndPaired asserts the structural
// invariants of the embedded migration set: versions start at 1, increase by
// exactly 1 with no gaps, and every version has both an up and a down file.
//
// This runs in the ordinary (untagged) unit-test job, not just the
// PostgreSQL-backed integration job, so a malformed or gapped migration set
// fails in the fast, always-required job rather than only in a DB-backed one.
// golang-migrate refuses to apply a set with a gap, so a gap would otherwise
// surface for the first time as a failed deploy against a live database:
// both consuming applications call RunMigrations at startup.
func TestEmbeddedMigrationsAreContiguousAndPaired(t *testing.T) {
	versions, err := embeddedMigrationVersions()
	if err != nil {
		t.Fatalf("embedded identity migrations are malformed: %v", err)
	}

	for i, version := range versions {
		if want := uint(i + 1); version != want {
			t.Fatalf("embedded migration versions must be contiguous starting at 1: "+
				"got %v, expected version %d at index %d", versions, want, i)
		}
	}

	// Cross-check the derived set against golang-migrate's own view of the
	// embedded source, so the two can never disagree about the latest version.
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("failed to load embedded identity migrations: %v", err)
	}
	defer func() { _ = src.Close() }()

	latest := versions[len(versions)-1]
	if up, _, err := src.ReadUp(latest); err != nil {
		t.Errorf("iofs source cannot read up-migration for derived latest version %d: %v", latest, err)
	} else {
		_ = up.Close()
	}
	if down, _, err := src.ReadDown(latest); err != nil {
		t.Errorf("iofs source cannot read down-migration for derived latest version %d: %v", latest, err)
	} else {
		_ = down.Close()
	}
	if next, err := src.Next(latest); err == nil {
		t.Errorf("derived latest version %d is not actually the latest: iofs reports a later version %d",
			latest, next)
	}
}

// TestDownMigrationDoesNotDropSchema is a regression guard for issue #64: the
// 000001 down-migration must never re-introduce "DROP SCHEMA IF EXISTS
// identity". golang-migrate stores its own version-tracking table
// (identity.identity_schema_migrations) inside the "identity" schema, so a
// full down-unwind always leaves that bookkeeping table behind — meaning a
// DROP SCHEMA at the end of the down-migration would always fail with
// "schema not empty" and, per golang-migrate's dirty-flag semantics, brick
// the migration state with no in-library recovery. Dropping the schema
// itself is unnecessary: it is left empty of domain tables and is
// re-created idempotently (CREATE SCHEMA IF NOT EXISTS) the next time
// migrations run.
func TestDownMigrationDoesNotDropSchema(t *testing.T) {
	const downMigrationPath = "migrations/000001_identity_schema.down.sql"

	contents, err := migrationsFS.ReadFile(downMigrationPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", downMigrationPath, err)
	}

	if strings.Contains(strings.ToUpper(string(contents)), "DROP SCHEMA") {
		t.Errorf("%s must not contain a DROP SCHEMA statement: golang-migrate's own "+
			"version-tracking table still lives in the schema at that point in a full "+
			"down-unwind, so the statement always fails and leaves migration state dirty",
			downMigrationPath)
	}
}

// ---------------------------------------------------------------------------
// Pooled-connection release (issue #139)
// ---------------------------------------------------------------------------

// TestNewMigratorReleasesTheBorrowedConnectionOnErrorPaths asserts that a
// newMigrator call that fails hands its borrowed connection back to the pool
// before returning.
//
// newMigrator checks a connection out of the caller's *sql.DB and the migrator
// holds it until closeMigrator runs — but if construction fails there is no
// migrator to close, so the release has to happen inside newMigrator. A
// connection dropped on one of those paths is gone for the life of the
// process: it counts against the consuming application's MaxOpenConns forever,
// and enough of them wedge every other query in the app.
//
// The pool here is deliberately sized at exactly one connection, which turns
// "the connection was not returned" from an accounting curiosity into an
// observable failure: the follow-up checkout has nothing to wait for and
// blocks until its context deadline. The db.Stats().InUse assertion is the
// complementary direct reading of the same fact.
//
// The happy path (a migrator that is built, used, and closed) needs a real
// PostgreSQL and is covered by TestIntegrationRunMigrationsReleasesPooledConnections.
func TestNewMigratorReleasesTheBorrowedConnectionOnErrorPaths(t *testing.T) {
	tests := []struct {
		name   string
		expect func(sqlmock.Sqlmock)
	}{
		{
			// Fails inside ensureSchema, after the connection is borrowed.
			name: "schema creation fails",
			expect: func(m sqlmock.Sqlmock) {
				m.ExpectExec("CREATE SCHEMA IF NOT EXISTS identity").
					WillReturnError(errors.New("permission denied for database"))
			},
		},
		{
			// Fails inside postgres.WithConnection, which probes the database
			// name before it can build the driver.
			name: "migration driver construction fails",
			expect: func(m sqlmock.Sqlmock) {
				m.ExpectExec("CREATE SCHEMA IF NOT EXISTS identity").
					WillReturnResult(sqlmock.NewResult(0, 0))
				m.ExpectQuery("SELECT CURRENT_DATABASE").
					WillReturnError(errors.New("connection reset by peer"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			db.SetMaxOpenConns(1)
			tc.expect(mock)

			if m, err := newMigrator(context.Background(), db); err == nil {
				closeMigrator(m)
				t.Fatal("expected newMigrator to fail, got a working migrator")
			}

			if inUse := db.Stats().InUse; inUse != 0 {
				t.Errorf("db.Stats().InUse = %d after a failed newMigrator, want 0: "+
					"the borrowed connection was not returned to the pool", inUse)
			}

			// The decisive check: the one-connection pool must be able to hand
			// its connection out again. If newMigrator kept it, this blocks
			// until the deadline instead of hanging the test forever.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatalf("the pool could not serve a connection after a failed newMigrator "+
					"(the borrowed connection was never released): %v", err)
			}
			_ = conn.Close()

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}
