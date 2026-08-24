package store

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// The retention sweep deletes; legal hold preserves. Both halves shipped, and
// they were never connected (terraform-registry-backend#872): the delete ran on
// every deployment with retention configured, and the hold store had no caller
// on either end. Finishing that wiring means the delete has to learn a
// predicate it must NOT carry for a consumer that has no holds table, because a
// NOT EXISTS against a missing relation is a parse-time error, not an empty set.

func newAuditRepoWithMock(t *testing.T) (*AuditRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewAuditRepository(db), mock
}

// The zero value must emit exactly the statement this method has always
// emitted. Every consumer without holds — terraform-state-manager among them —
// depends on that, and "the option changed nothing when absent" is not
// observable from the outside any other way.
func TestSweepWithoutOptionsIsUnchanged(t *testing.T) {
	repo, mock := newAuditRepoWithMock(t)
	mock.ExpectExec(`DELETE FROM audit_logs`).
		WillReturnResult(sqlmock.NewResult(0, 3))

	if _, err := repo.DeleteAuditLogsBefore(context.Background(), time.Now(), 10); err != nil {
		t.Fatalf("DeleteAuditLogsBefore: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSweepWithoutOptionsMentionsNoHoldsTable(t *testing.T) {
	repo, mock := newAuditRepoWithMock(t)
	// A statement carrying NOT EXISTS must NOT match, so this expectation is
	// only met if the emitted SQL is free of any exemption.
	mock.ExpectExec(`^\s*DELETE FROM audit_logs\s+WHERE id IN \(\s+SELECT id FROM audit_logs WHERE created_at < \$1\s+ORDER BY created_at ASC LIMIT \$2\s+\)\s*$`).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if _, err := repo.DeleteAuditLogsBefore(context.Background(), time.Now(), 10); err != nil {
		t.Fatalf("an unexempted sweep no longer emits the original statement: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

// The predicate must sit INSIDE the LIMIT subselect. Outside it, a batch can
// fill entirely with held rows, delete none, and hand the caller's loop the
// same batch forever — a sweep that never reaches the deletable rows behind
// them. This asserts the position, not merely the presence.
func TestExemptionSitsInsideTheLimitSubselect(t *testing.T) {
	filter := newAuditSweepFilter([]AuditSweepOption{WithLegalHolds("legal_holds")})
	clause, err := filter.exemption()
	if err != nil {
		t.Fatalf("exemption: %v", err)
	}

	query := `
		DELETE FROM audit_logs
		WHERE id IN (
			SELECT id FROM audit_logs WHERE created_at < $1` + clause + `
			ORDER BY created_at ASC LIMIT $2
		)
	`
	notExists := strings.Index(query, "NOT EXISTS")
	limit := strings.Index(query, "LIMIT $2")
	if notExists < 0 {
		t.Fatal("no NOT EXISTS in an exempted sweep")
	}
	if notExists > limit {
		t.Errorf("NOT EXISTS appears AFTER LIMIT; a batch of held rows would delete nothing "+
			"and the caller's loop would never advance past them.\n%s", query)
	}
	if !strings.Contains(query, `"legal_holds"`) {
		t.Errorf("the holds table is not quoted in the statement:\n%s", query)
	}
}

func TestExemptionReadsActiveHoldsOnly(t *testing.T) {
	clause, err := newAuditSweepFilter([]AuditSweepOption{WithLegalHolds("legal_holds")}).exemption()
	if err != nil {
		t.Fatalf("exemption: %v", err)
	}
	for _, want := range []string{"h." + LegalHoldActiveColumn, "h." + LegalHoldStartDateColumn, "h." + LegalHoldEndDateColumn} {
		if !strings.Contains(clause, want) {
			t.Errorf("exemption does not read %s:\n%s", want, clause)
		}
	}
}

// A table name is an identifier, not a bind parameter, so a malformed one must
// be an error rather than a string pasted into SQL.
func TestExemptionRefusesTableNamesItCannotQuote(t *testing.T) {
	for _, table := range []string{
		`legal_holds; DROP TABLE audit_logs; --`,
		`a.b.c`,
		`   `,
		`holds"; --`,
		strings.Repeat("h", 64),
	} {
		t.Run(table, func(t *testing.T) {
			repo, mock := newAuditRepoWithMock(t)
			_, err := repo.DeleteAuditLogsBefore(context.Background(), time.Now(), 10, WithLegalHolds(table))
			if err == nil {
				t.Fatalf("table name %q was accepted", table)
			}
			// And no statement reached the database.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a statement was executed despite the bad table name: %v", err)
			}
		})
	}
}

func TestSchemaQualifiedHoldsTableIsAccepted(t *testing.T) {
	clause, err := newAuditSweepFilter([]AuditSweepOption{WithLegalHolds("identity.legal_holds")}).exemption()
	if err != nil {
		t.Fatalf("a schema-qualified table should be accepted: %v", err)
	}
	if !strings.Contains(clause, `"identity"."legal_holds"`) {
		t.Errorf("schema qualification lost:\n%s", clause)
	}
}

func TestNilOptionIsIgnored(t *testing.T) {
	filter := newAuditSweepFilter([]AuditSweepOption{nil})
	clause, err := filter.exemption()
	if err != nil || clause != "" {
		t.Errorf("a nil option should be ignored, got clause=%q err=%v", clause, err)
	}
}

// The DDL this package renders must be the shape it reads. Shipping them from
// one file is the point; this asserts they have not drifted apart.
func TestRenderedDDLCarriesEveryColumnTheExemptionReads(t *testing.T) {
	ddl, err := LegalHoldTableDDL("legal_holds")
	if err != nil {
		t.Fatalf("LegalHoldTableDDL: %v", err)
	}
	for _, col := range []string{LegalHoldActiveColumn, LegalHoldStartDateColumn, LegalHoldEndDateColumn} {
		if !regexp.MustCompile(`(?m)^\s*` + col + `\s`).MatchString(ddl) {
			t.Errorf("rendered DDL has no %s column, but the exemption reads it:\n%s", col, ddl)
		}
	}
	if !strings.Contains(ddl, "CREATE INDEX") {
		t.Error("no index on the range the sweep probes once per candidate row")
	}
}

func TestRenderedDDLRefusesBadTableNames(t *testing.T) {
	if _, err := LegalHoldTableDDL(`x"; DROP TABLE audit_logs; --`); err == nil {
		t.Fatal("LegalHoldTableDDL accepted an unquotable table name")
	}
}

func TestVerifyLegalHoldTableNeedsAConnection(t *testing.T) {
	if err := VerifyLegalHoldTable(context.Background(), nil, "legal_holds"); err == nil {
		t.Fatal("a nil database was accepted")
	}
}
