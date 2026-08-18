//go:build integration

package store

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sethbacon/terraform-suite-identity/identity"
	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// Shared setup for this package's PostgreSQL-backed tests.
//
// These tests run against their OWN database, derived from TEST_DATABASE_URL by
// suffixing the database name, rather than the one identity/db_integration_test.go
// uses. `go test ./...` runs package binaries concurrently, and both suites
// begin by dropping and re-creating the identity schema; sharing one database
// would make each suite's result depend on the other's timing. A separate
// database removes that coupling instead of papering over it with -p 1.

// identityTestDB returns a connection to a freshly migrated identity schema in
// this package's own test database, or skips when no database is configured.
func identityTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	target := storeTestDSN(t, dsn)

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to open the administrative connection: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.Ping(); err != nil {
		t.Fatalf("failed to reach the database at TEST_DATABASE_URL: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE ` + pgquote.Identifier(target.name)); err != nil {
		// 42P04 duplicate_database: a previous run already created it.
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" {
			t.Fatalf("failed to create the %q test database (the role needs CREATEDB): %v",
				target.name, err)
		}
	}

	db, err := sql.Open("pgx", target.dsn)
	if err != nil {
		t.Fatalf("failed to open %q: %v", target.name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach %q: %v", target.name, err)
	}

	// A clean slate per run, so a re-run locally exercises the migrations
	// rather than tripping over a schema a previous run left behind.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset the identity schema: %v", err)
	}
	if err := identity.RunMigrations(db, "up"); err != nil {
		t.Fatalf("RunMigrations(up) failed: %v", err)
	}

	return db
}

type testDSN struct {
	name string
	dsn  string
}

// storeTestDSN derives this package's dedicated database name and DSN from the
// configured one, carrying search_path=identity so the repositories' unqualified
// table names resolve exactly as they do in a consuming application.
func storeTestDSN(t *testing.T, dsn string) testDSN {
	t.Helper()

	parsed, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL must be a postgres:// URL for this suite, got %q (parse error: %v)", dsn, err)
	}

	base := strings.TrimPrefix(parsed.Path, "/")
	if base == "" {
		t.Fatalf("TEST_DATABASE_URL %q names no database", dsn)
	}
	name := base + "_store"

	target := *parsed
	target.Path = "/" + name
	query := target.Query()
	query.Set("search_path", "identity")
	target.RawQuery = query.Encode()

	return testDSN{name: name, dsn: target.String()}
}

// explain returns the query plan for query as a single string.
func explain(t *testing.T, db *sql.DB, query string, args ...interface{}) string {
	t.Helper()

	rows, err := db.Query("EXPLAIN "+query, args...) // #nosec G202 -- test helper; query is built by this package's own builders or is a fixed literal in the test
	if err != nil {
		t.Fatalf("EXPLAIN failed for query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()

	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("failed to scan EXPLAIN output: %v", err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("failed to read EXPLAIN output: %v", err)
	}
	return plan.String()
}

// assertPlanUsesIndex fails with the whole plan when index does not appear in it.
func assertPlanUsesIndex(t *testing.T, what, index, plan string) {
	t.Helper()

	if strings.Contains(plan, index) {
		return
	}
	t.Errorf("%s does not use %s.\n"+
		"An index the planner will not choose is not a hot-path index — this is the "+
		"assertion that separates 'the migration ran' from 'the query got faster'.\n"+
		"Plan was:\n%s", what, index, plan)
}

func mustExec(t *testing.T, db *sql.DB, statement string, args ...interface{}) {
	t.Helper()

	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatalf("statement failed: %v\n%s", err, statement)
	}
}

func scanUUID(t *testing.T, db *sql.DB, query string, args ...interface{}) string {
	t.Helper()

	var id string
	if err := db.QueryRow(query, args...).Scan(&id); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}
	return id
}
