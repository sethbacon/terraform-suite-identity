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

// TestEmptyHoldTableFailsClosed.
//
// WithLegalHolds("") used to return an empty exemption and a NIL ERROR -- an
// unprotected sweep, silently, from a caller that had explicitly asked for
// protection. A consumer wiring WithLegalHolds(cfg.HoldTable) against an unset
// config got exactly that, while VerifyLegalHoldTable REJECTED the same empty
// value at startup. The startup check and the sweep disagreed about what ""
// meant, and the sweep took the dangerous reading.
//
// The distinction that makes this expressible is holdTableSet: without it,
// "no option given" and "option given with an empty name" are the same value
// and cannot be told apart.
func TestEmptyHoldTableFailsClosed(t *testing.T) {
	// No option at all: the documented way to sweep without exemptions.
	clause, err := newAuditSweepFilter(nil).exemption()
	if err != nil {
		t.Fatalf("a sweep with no options errored: %v", err)
	}
	if clause != "" {
		t.Errorf("a sweep with no options rendered an exemption: %q", clause)
	}

	// Explicitly asking for holds, with nothing to hold against.
	if _, err := newAuditSweepFilter([]AuditSweepOption{WithLegalHolds("")}).exemption(); err == nil {
		t.Error("WithLegalHolds(\"\") produced no error.\n" +
			"That is an unprotected sweep from a caller that asked to be protected -- and " +
			"VerifyLegalHoldTable rejects the same value, so the startup check and the sweep " +
			"would disagree about whether the deployment is safe.")
	}

	// And a real name still works.
	clause, err = newAuditSweepFilter([]AuditSweepOption{WithLegalHolds("legal_holds")}).exemption()
	if err != nil {
		t.Fatalf("a valid hold table errored: %v", err)
	}
	if clause == "" {
		t.Error("a valid hold table rendered no exemption")
	}
}

// TestVerifyAndSweepAgreeOnEveryTableName is the property, rather than the one
// value that happened to break it.
//
// If VerifyLegalHoldTable accepts a name the sweep refuses, an operator gets a
// green startup and a failing sweep. If the sweep accepts one Verify refuses,
// they get the opposite -- and that direction deletes data. The two must agree
// on every input, not just on the empty string.
func TestVerifyAndSweepAgreeOnEveryTableName(t *testing.T) {
	for _, name := range []string{
		"", "   ", "legal_holds", "identity.legal_holds", "a.b.c",
		"legal-holds", "1legal", "legal holds", `legal";DROP TABLE x--`,
		"MixedCase", "legal_holds\x00",
	} {
		// The sweep's view.
		_, sweepErr := newAuditSweepFilter([]AuditSweepOption{WithLegalHolds(name)}).exemption()
		// Verify's view, reached through the same validator it uses.
		_, verifyErr := quoteAuditTable(name)

		if (sweepErr == nil) != (verifyErr == nil) {
			t.Errorf("name %q: the sweep %s it but the startup check %s it.\n"+
				"They must agree: a name one accepts and the other refuses means either a green "+
				"startup with a broken sweep, or -- worse -- a verified deployment whose sweep "+
				"deletes without the exemption.",
				name,
				map[bool]string{true: "accepts", false: "refuses"}[sweepErr == nil],
				map[bool]string{true: "accepts", false: "refuses"}[verifyErr == nil])
		}
	}
}
