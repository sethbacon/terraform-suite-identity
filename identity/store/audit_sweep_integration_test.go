//go:build integration

package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// This is the assertion terraform-registry-backend#872 says is the only one
// that proves the feature works: a held entry SURVIVES a retention run.
//
// It cannot be written with a mock. sqlmock returns whatever the fixture
// declares, so it can show the statement was built but not that Postgres
// honoured it — and every interesting property here is the database's:
// whether NOT EXISTS against a real table excludes the right rows, whether the
// range comparison includes its boundaries, whether an inactive hold stops
// protecting, and whether the batch loop makes progress rather than wedging
// behind rows it will never delete.
//
// ONE DATABASE SETUP, THREE SUBTESTS, IN THIS ORDER. identityTestDB drops,
// recreates and re-migrates the identity schema on every call, and this
// package's suite already makes twenty of them; three more measurably
// perturbed the concurrently-running auditoutbox package's tests in CI, which
// a control run without this file confirmed. The order is load-bearing too:
// the unexempted case has to run BEFORE the holds table exists, because its
// whole point is that the statement must not reference a table this consumer
// does not have.
//
// The name must begin with TestIntegration: CI runs
// `go test -tags=integration ./... -run 'TestIntegration'`, so a differently
// named test here compiles, passes locally, and silently never runs.
func TestIntegrationLegalHoldExemption(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	repo := NewAuditRepository(db)
	base := time.Now().UTC().Truncate(24 * time.Hour)
	cutoff := base.AddDate(0, 0, 1)

	clearAuditLogs := func(t *testing.T) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `DELETE FROM identity.audit_logs`); err != nil {
			t.Fatalf("clearing audit_logs: %v", err)
		}
	}
	insertAt := func(t *testing.T, action string, when time.Time) {
		t.Helper()
		_, err := db.ExecContext(ctx,
			`INSERT INTO identity.audit_logs (action, resource_type, created_at) VALUES ($1, 'test', $2)`,
			action, when)
		if err != nil {
			t.Fatalf("inserting %s: %v", action, err)
		}
	}

	// FIRST, while no legal_holds table exists in this database. Without the
	// option the sweep must not reference one — a NOT EXISTS against a missing
	// relation is a parse-time 42P01, not a degrade to "nothing is held", and
	// that is the whole reason the exemption is an option.
	t.Run("an unexempted sweep never references a holds table", func(t *testing.T) {
		clearAuditLogs(t)
		insertAt(t, "old", base.AddDate(0, 0, -5))

		n, err := repo.DeleteAuditLogsBefore(ctx, cutoff, 10)
		if err != nil {
			t.Fatalf("an unexempted sweep must not reference a holds table: %v", err)
		}
		if n != 1 {
			t.Errorf("deleted %d rows, want 1", n)
		}
	})

	// Now the table exists for the rest.
	ddl, err := LegalHoldTableDDL("identity.legal_holds")
	if err != nil {
		t.Fatalf("LegalHoldTableDDL: %v", err)
	}
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		t.Fatalf("creating the holds table from the rendered DDL: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS identity.legal_holds`) })

	if err := VerifyLegalHoldTable(ctx, db, "identity.legal_holds"); err != nil {
		t.Fatalf("the table this package just rendered does not satisfy its own verifier: %v", err)
	}

	t.Run("held rows survive a batched retention sweep", func(t *testing.T) {
		clearAuditLogs(t)
		if _, err := db.ExecContext(ctx, `DELETE FROM identity.legal_holds`); err != nil {
			t.Fatalf("clearing holds: %v", err)
		}
		for day := 1; day <= 10; day++ {
			insertAt(t, fmt.Sprintf("day-%d", day), base.AddDate(0, 0, -day))
		}
		// Days 4..6 inclusive. Boundaries matter: the exemption uses >= and <=,
		// so days 4 and 6 are held, not just day 5.
		if _, err := db.ExecContext(ctx,
			`INSERT INTO identity.legal_holds (id, name, start_date, end_date, active)
			 VALUES (gen_random_uuid(), 'investigation', $1, $2, TRUE)`,
			base.AddDate(0, 0, -6), base.AddDate(0, 0, -4)); err != nil {
			t.Fatalf("placing the hold: %v", err)
		}

		// Batched, exactly as AuditCleanupJob sweeps.
		total := int64(0)
		for i := 0; i < 20; i++ {
			n, err := repo.DeleteAuditLogsBefore(ctx, cutoff, 3, WithLegalHolds("identity.legal_holds"))
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}
			total += n
			if n == 0 {
				break
			}
		}
		if total != 7 {
			t.Errorf("deleted %d rows, want 7 (ten inserted, three held)", total)
		}

		survivors := auditActions(t, ctx, db)
		want := map[string]bool{"day-4": true, "day-5": true, "day-6": true}
		if len(survivors) != len(want) {
			t.Fatalf("survivors = %v, want exactly the three held days", survivors)
		}
		for _, s := range survivors {
			if !want[s] {
				t.Errorf("%s survived but was not held", s)
			}
		}
	})

	t.Run("a released hold stops protecting", func(t *testing.T) {
		clearAuditLogs(t)
		if _, err := db.ExecContext(ctx, `DELETE FROM identity.legal_holds`); err != nil {
			t.Fatalf("clearing holds: %v", err)
		}
		insertAt(t, "held", base.AddDate(0, 0, -5))
		if _, err := db.ExecContext(ctx,
			`INSERT INTO identity.legal_holds (id, name, start_date, end_date, active)
			 VALUES (gen_random_uuid(), 'investigation', $1, $2, TRUE)`,
			base.AddDate(0, 0, -6), base.AddDate(0, 0, -4)); err != nil {
			t.Fatalf("placing the hold: %v", err)
		}

		n, err := repo.DeleteAuditLogsBefore(ctx, cutoff, 10, WithLegalHolds("identity.legal_holds"))
		if err != nil {
			t.Fatalf("sweep under hold: %v", err)
		}
		if n != 0 {
			t.Fatalf("deleted %d rows while a hold covered them", n)
		}

		// The evidence was preserved for as long as the hold stood; releasing
		// it makes the row deletable again on the next sweep.
		if _, err := db.ExecContext(ctx,
			`UPDATE identity.legal_holds SET active = FALSE, released_at = now()`); err != nil {
			t.Fatalf("releasing: %v", err)
		}
		n, err = repo.DeleteAuditLogsBefore(ctx, cutoff, 10, WithLegalHolds("identity.legal_holds"))
		if err != nil {
			t.Fatalf("sweep after release: %v", err)
		}
		if n != 1 {
			t.Errorf("deleted %d rows after the hold was released, want 1", n)
		}
	})
}

func auditActions(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT action FROM identity.audit_logs ORDER BY created_at`)
	if err != nil {
		t.Fatalf("reading survivors: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}
