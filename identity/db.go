// Package identity manages shared identity schema migrations.
package identity

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

const (
	identitySchemaName      = "identity"
	identityMigrationsTable = "identity_schema_migrations"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func ensureSchema(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS identity`); err != nil {
		return fmt.Errorf("failed to ensure identity schema: %w", err)
	}
	return nil
}

// newMigrator builds a migrator over a single connection borrowed from db.
//
// The connection is the migrator's to hold and the caller's to release:
// every migrator returned here MUST be handed to closeMigrator (see the
// deferred calls in RunMigrations, RunMigrationSteps and GetMigrationVersion),
// which returns the borrowed connection to db's pool. Callers keep ownership
// of db itself, which is never closed by this package.
//
// The borrowing is explicit for a reason. postgres.WithInstance(db, ...) also
// checks out a dedicated connection and holds it for the driver's lifetime,
// but it additionally records db on the driver, so the driver's Close() closes
// the caller's shared *sql.DB — unusable for a pool this package does not own.
// postgres.WithConnection takes a connection this package obtained itself and
// leaves the pool alone, so Close() releases exactly what was borrowed and
// nothing more. Without that release, each call to any of the three exported
// entry points would permanently consume one slot of the caller's
// MaxOpenConns; GetMigrationVersion in particular is shaped like a readiness
// probe, so a handful of probe intervals could exhaust the pool and block
// every other query in the consuming application.
func newMigrator(ctx context.Context, db *sql.DB) (*migrate.Migrate, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire a connection for identity migrations: %w", err)
	}

	if err := ensureSchema(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{
		SchemaName:      identitySchemaName,
		MigrationsTable: identityMigrationsTable,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to create identity migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		// driver.Close() releases the borrowed connection back to db's pool
		// (and only that: WithConnection leaves the driver's db field nil).
		_ = driver.Close()
		return nil, fmt.Errorf("failed to create identity migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		_ = driver.Close()
		_ = sourceDriver.Close()
		return nil, fmt.Errorf("failed to create identity migration instance: %w", err)
	}

	return m, nil
}

// closeMigrator releases the migrator's source driver and returns its borrowed
// connection to the pool it came from. It is deliberately best-effort: a close
// failure must not mask (or manufacture) an error from the migration itself,
// and the connection is released either way — a *sql.Conn whose Close fails is
// still removed from the pool's in-use set rather than being held forever.
func closeMigrator(m *migrate.Migrate) {
	if m == nil {
		return
	}
	_, _ = m.Close()
}

// RunMigrations applies identity schema migrations in the requested
// direction. direction must be "up" (apply all pending migrations) or
// "down" (fully unwind all applied migrations). A full "down" unwind
// completes cleanly: it drops every identity table but leaves the
// (now-empty) "identity" schema and golang-migrate's own version-tracking
// table (identity.identity_schema_migrations) in place, since
// golang-migrate manages that bookkeeping table itself and a subsequent
// "up" re-creates the schema idempotently. To roll back (or re-apply)
// only a bounded number of migrations instead of the whole schema, use
// RunMigrationSteps.
func RunMigrations(db *sql.DB, direction string) error {
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		return err
	}
	defer closeMigrator(m)

	switch direction {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to run identity migrations: %w", err)
		}
	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to rollback identity migrations: %w", err)
		}
	default:
		return fmt.Errorf("invalid migration direction: %s (must be 'up' or 'down')", direction)
	}

	return nil
}

// RunMigrationSteps applies n identity schema migration steps: a positive n
// moves forward that many migrations, a negative n rolls back that many
// migrations, and n == 0 is a no-op. Unlike RunMigrations(db, "down"), which
// unwinds the entire schema, this lets a caller undo (or apply) just a
// bounded number of migrations — for example, rolling back only the most
// recently applied migration with RunMigrationSteps(db, -1) — without
// dropping every identity table.
func RunMigrationSteps(db *sql.DB, n int) error {
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		return err
	}
	defer closeMigrator(m)

	if err := m.Steps(n); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to step identity migrations: %w", err)
	}

	return nil
}

// GetMigrationVersion returns the current version for identity schema migrations.
//
// It borrows one connection from db for the duration of the call and returns
// it before returning, so it is safe to call repeatedly — for example from a
// readiness probe — without draining the caller's pool.
func GetMigrationVersion(db *sql.DB) (version uint, dirty bool, err error) {
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		return 0, false, err
	}
	defer closeMigrator(m)

	version, dirty, err = m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return 0, false, fmt.Errorf("failed to get identity migration version: %w", err)
	}

	return version, dirty, nil
}
