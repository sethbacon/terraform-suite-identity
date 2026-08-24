//go:build integration

package store

import (
	"context"
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
// The name must begin with TestIntegration: CI runs
// `go test -tags=integration ./... -run 'TestIntegration'`, so a differently
// named test in this file compiles, passes locally, and silently never runs.

func TestIntegrationHeldAuditRowsSurviveTheRetentionSweep(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	repo := NewAuditRepository(db)

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

	// Ten rows, one per day, days 1..10 in the past. All older than the cutoff.
	base := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := db.ExecContext(ctx, `DELETE FROM identity.audit_logs`); err != nil {
		t.Fatalf("clearing audit_logs: %v", err)
	}
	for day := 1; day <= 10; day++ {
		when := base.AddDate(0, 0, -day)
		_, err := db.ExecContext(ctx,
			`INSERT INTO identity.audit_logs (action, resource_type, created_at) VALUES ($1, 'test', $2)`,
			fmt.Sprintf("day-%d", day), when)
		if err != nil {
			t.Fatalf("inserting day-%d: %v", day, err)
		}
	}

	// A hold covering days 4..6 inclusive. Boundaries matter: the exemption uses
	// >= and <=, so days 4 and 6 are held, not just day 5.
	_, err = db.ExecContext(ctx,
		`INSERT INTO identity.legal_holds (id, name, start_date, end_date, active)
		 VALUES (gen_random_uuid(), 'investigation', $1, $2, TRUE)`,
		base.AddDate(0, 0, -6), base.AddDate(0, 0, -4))
	if err != nil {
		t.Fatalf("placing the hold: %v", err)
	}

	// Sweep everything older than "now" — which is all ten rows — in batches,
	// exactly as AuditCleanupJob does.
	cutoff := base.AddDate(0, 0, 1)
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

	var survivors []string
	rows, err := db.QueryContext(ctx, `SELECT action FROM identity.audit_logs ORDER BY created_at`)
	if err != nil {
		t.Fatalf("reading survivors: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		survivors = append(survivors, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := map[string]bool{"day-4": true, "day-5": true, "day-6": true}
	if len(survivors) != len(want) {
		t.Fatalf("survivors = %v, want exactly the three held days", survivors)
	}
	for _, s := range survivors {
		if !want[s] {
			t.Errorf("%s survived but was not held", s)
		}
	}
}

// Releasing a hold makes its rows deletable again — the evidence was preserved
// for as long as the hold stood, which is the whole contract.
func TestIntegrationReleasedHoldsStopProtecting(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	repo := NewAuditRepository(db)

	ddl, _ := LegalHoldTableDDL("identity.legal_holds")
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		t.Fatalf("creating the holds table: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS identity.legal_holds`) })

	base := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := db.ExecContext(ctx, `DELETE FROM identity.audit_logs`); err != nil {
		t.Fatalf("clearing audit_logs: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity.audit_logs (action, resource_type, created_at) VALUES ('held', 'test', $1)`,
		base.AddDate(0, 0, -5)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity.legal_holds (id, name, start_date, end_date, active)
		 VALUES (gen_random_uuid(), 'investigation', $1, $2, TRUE)`,
		base.AddDate(0, 0, -6), base.AddDate(0, 0, -4)); err != nil {
		t.Fatalf("placing the hold: %v", err)
	}

	cutoff := base.AddDate(0, 0, 1)
	n, err := repo.DeleteAuditLogsBefore(ctx, cutoff, 10, WithLegalHolds("identity.legal_holds"))
	if err != nil {
		t.Fatalf("sweep under hold: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted %d rows while a hold covered them", n)
	}

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
}

// Without the option the sweep must not reference the holds table at all — this
// is the consumer that has no such table, and a statement naming it would fail
// with 42P01 rather than degrading to "nothing is held".
func TestIntegrationSweepWithoutTheOptionIgnoresHoldsEntirely(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	repo := NewAuditRepository(db)

	base := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := db.ExecContext(ctx, `DELETE FROM identity.audit_logs`); err != nil {
		t.Fatalf("clearing audit_logs: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity.audit_logs (action, resource_type, created_at) VALUES ('old', 'test', $1)`,
		base.AddDate(0, 0, -5)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// No legal_holds table exists in this database at this point.
	n, err := repo.DeleteAuditLogsBefore(ctx, base.AddDate(0, 0, 1), 10)
	if err != nil {
		t.Fatalf("an unexempted sweep must not reference a holds table: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}
}
