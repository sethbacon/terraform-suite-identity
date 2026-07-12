//go:build integration

package identity

import (
	"database/sql"
	"os"
	"testing"

	// Registers the "postgres" driver used by sql.Open below.
	_ "github.com/lib/pq"
)

// expectedLatestMigrationVersion is the version number of the highest-numbered
// migration under identity/migrations. Update this alongside adding a new
// migration file so TestIntegrationRunMigrations keeps asserting against the
// real latest version instead of silently passing on a stale one.
const expectedLatestMigrationVersion uint = 3

// TestIntegrationRunMigrations exercises RunMigrations and GetMigrationVersion
// against a real PostgreSQL database. It is the end-to-end proof that issue
// #64's fix to the identity schema's down-migration (which used to end with a
// "DROP SCHEMA" that always failed because golang-migrate's own
// version-tracking table still lived inside that schema, permanently
// "dirty"-ing migration state with no in-library way to recover) actually
// works: it runs the migrations up, confirms a clean version, runs them back
// down, and confirms that also completes without error and without leaving
// dirty state behind.
//
// It requires a live database reachable via the TEST_DATABASE_URL environment
// variable (a libpq connection string, e.g.
// "postgres://postgres:postgres@localhost:5432/identity_test?sslmode=disable")
// and is skipped otherwise, so `go test ./...` without a database configured
// -- including everyone's default local run -- is unaffected. The
// "integration" build tag additionally keeps it out of ordinary `go test
// ./...` and `go vet ./...` invocations entirely; run it explicitly with:
//
//	go test -tags=integration ./... -run TestIntegrationRunMigrations
func TestIntegrationRunMigrations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach database at TEST_DATABASE_URL: %v", err)
	}

	// Start from a clean slate so re-running this test locally against a
	// persistent database exercises a real up/down cycle rather than
	// tripping over a schema left behind by a previous run.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema before test: %v", err)
	}

	// --- up: apply every migration ---
	if err := RunMigrations(db, "up"); err != nil {
		t.Fatalf("RunMigrations(up) failed: %v", err)
	}

	version, dirty, err := GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after up failed: %v", err)
	}
	if dirty {
		t.Fatalf("expected clean migration state after up, got dirty=true at version %d", version)
	}
	if version != expectedLatestMigrationVersion {
		t.Fatalf("expected migration version %d after up, got %d", expectedLatestMigrationVersion, version)
	}

	// --- up again: golang-migrate's ErrNoChange must be swallowed, so a
	// second "up" against an already-migrated database is a no-op, not an
	// error. ---
	if err := RunMigrations(db, "up"); err != nil {
		t.Fatalf("second RunMigrations(up) should be a no-op, got error: %v", err)
	}

	version, dirty, err = GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after second up failed: %v", err)
	}
	if dirty || version != expectedLatestMigrationVersion {
		t.Fatalf("expected unchanged clean state at version %d after idempotent up, got version=%d dirty=%v",
			expectedLatestMigrationVersion, version, dirty)
	}

	// --- down: fully unwind. Before issue #64's fix this failed with
	// "schema not empty" because migration 000001's down step tried to DROP
	// SCHEMA identity while golang-migrate's own bookkeeping table was still
	// in it, leaving migration state permanently dirty. ---
	if err := RunMigrations(db, "down"); err != nil {
		t.Fatalf("RunMigrations(down) failed (regression of issue #64): %v", err)
	}

	version, dirty, err = GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after down failed: %v", err)
	}
	if dirty {
		t.Fatalf("expected clean migration state after down, got dirty=true at version %d", version)
	}
	if version != 0 {
		t.Fatalf("expected migration version 0 after a full down-unwind, got %d", version)
	}
}
