// Package identity manages shared identity schema migrations.
package identity

import (
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

func ensureSchema(db *sql.DB) error {
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS identity`); err != nil {
		return fmt.Errorf("failed to ensure identity schema: %w", err)
	}
	return nil
}

func newMigrator(db *sql.DB) (*migrate.Migrate, error) {
	if err := ensureSchema(db); err != nil {
		return nil, err
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{
		SchemaName:      identitySchemaName,
		MigrationsTable: identityMigrationsTable,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create identity migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to create identity migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity migration instance: %w", err)
	}

	return m, nil
}

// RunMigrations applies identity schema migrations in the requested direction.
func RunMigrations(db *sql.DB, direction string) error {
	m, err := newMigrator(db)
	if err != nil {
		return err
	}

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

// GetMigrationVersion returns the current version for identity schema migrations.
func GetMigrationVersion(db *sql.DB) (version uint, dirty bool, err error) {
	m, err := newMigrator(db)
	if err != nil {
		return 0, false, err
	}

	version, dirty, err = m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return 0, false, fmt.Errorf("failed to get identity migration version: %w", err)
	}

	return version, dirty, nil
}
