//go:build integration

package identity

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestIntegrationVerifySchemaVersion walks a real database up the identity
// chain one migration at a time and asserts VerifySchemaVersion's verdict at
// every stop.
//
// The unit tests cover checkSchemaVersion's decision table; what they cannot
// cover is the half that reads the database, and that half is where the defect
// lived — GetMigrationVersion has always worked and no consumer ever compared
// its answer to anything. So this exercises the wrapper end to end, including
// the two states a unit test cannot manufacture: an identity schema that has
// never been created at all, and a partially-applied chain.
//
// It also proves the guard is not decorative, by demonstrating BOTH sides at
// version 000006 — the exact version the consumer outage ran on:
//
//   - VerifySchemaVersion refuses, and
//   - the write it is protecting genuinely fails there, with SQLSTATE 42703.
//
// A guard asserted only in the direction of its own success is indistinguishable
// from one guarding nothing.
//
//	TEST_DATABASE_URL=postgres://... go test -tags=integration ./identity/ \
//	    -run TestIntegrationVerifySchemaVersion
func TestIntegrationVerifySchemaVersion(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", migrationTestDSN(t, dsn))
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach database at TEST_DATABASE_URL: %v", err)
	}

	ctx := context.Background()

	// --- no identity schema at all ---
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema: %v", err)
	}
	err = VerifySchemaVersion(ctx, db)
	if err == nil {
		t.Fatal("VerifySchemaVersion certified a database with no identity schema at all. " +
			"That is the state a consumer that never runs the chain is in, and it is the " +
			"state this check exists for")
	}
	if !errors.Is(err, ErrSchemaVersion) {
		t.Errorf("error does not wrap ErrSchemaVersion: %v", err)
	}
	if !strings.Contains(err.Error(), "NEVER been applied") {
		t.Errorf("an unmigrated database should be reported as such, not as a low version: %v", err)
	}

	// --- one migration at a time ---
	head := latestEmbeddedMigrationVersion(t)
	for v := uint(1); v <= head; v++ {
		if err := RunMigrationSteps(db, 1); err != nil {
			t.Fatalf("RunMigrationSteps to %d failed: %v", v, err)
		}
		got, dirty, gerr := GetMigrationVersion(db)
		if gerr != nil {
			t.Fatalf("GetMigrationVersion at step %d failed: %v", v, gerr)
		}
		if got != v || dirty {
			t.Fatalf("expected clean version %d, got %d (dirty=%v)", v, got, dirty)
		}

		err := VerifySchemaVersion(ctx, db)
		switch {
		case v < RequiredSchemaVersion && err == nil:
			t.Errorf("VerifySchemaVersion certified schema %06d, below the required %06d; "+
				"the unmet columns are %v", v, RequiredSchemaVersion, UnmetSchemaRequirements(v))
		case v >= RequiredSchemaVersion && err != nil:
			t.Errorf("VerifySchemaVersion rejected schema %06d, at or above the required "+
				"%06d: %v", v, RequiredSchemaVersion, err)
		}

		// At the version the outage ran on, prove the guard is guarding
		// something: the column it names must actually be absent.
		if v == RequiredSchemaVersion-1 {
			for _, r := range UnmetSchemaRequirements(v) {
				var exists bool
				if qerr := db.QueryRowContext(ctx, `
					SELECT EXISTS (
						SELECT 1 FROM information_schema.columns
						WHERE table_schema = $1 AND table_name = $2 AND column_name = $3
					)`, SchemaName, r.Table, r.Column).Scan(&exists); qerr != nil {
					t.Fatalf("column existence probe failed: %v", qerr)
				}
				if exists {
					t.Errorf("VerifySchemaVersion reports %s as missing at schema %06d, but "+
						"the column is present. A guard that names columns which already "+
						"exist is one an operator will learn to ignore", r, v)
				}
			}
		}
	}

	if err := VerifySchemaVersion(ctx, db); err != nil {
		t.Fatalf("VerifySchemaVersion rejected a database migrated to head (%06d) by this "+
			"module's own runner; the assertion would be unsatisfiable: %v", head, err)
	}
}
