package identity

import (
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

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
