package identity

import (
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
