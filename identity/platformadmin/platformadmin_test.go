package platformadmin

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// Three principals, as UUIDs, because the carrier's user_id column is one.
const (
	adminA  = "cccccccc-0000-0000-0000-00000000000a"
	adminB  = "cccccccc-0000-0000-0000-00000000000b"
	adminC  = "cccccccc-0000-0000-0000-00000000000c"
	orphanD = "cccccccc-0000-0000-0000-00000000000d"
)

// grantCols is the projection the carrier's reads scan.
var grantCols = []string{"user_id", "granted_by", "granted_at", "note"}

// intentSQL is what the test doubles below write. It stands in for whatever the
// application's audit writer does and exists so the assertions can be about
// ORDER and TRANSACTION MEMBERSHIP — sqlmock matches in sequence, so a writer
// that ran outside the mutation's transaction, or after the commit, fails.
const intentSQL = "INSERT INTO audit_outbox"

// writingIntent returns an AuditIntentWriter that writes on the transaction it
// is handed, and records that it ran.
func writingIntent(ran *bool) AuditIntentWriter {
	return func(ctx context.Context, tx *sql.Tx) error {
		*ran = true
		_, err := tx.ExecContext(ctx, intentSQL+" (event_id) VALUES ($1)", "event-1")
		return err
	}
}

func expectIntentWrite(mock sqlmock.Sqlmock) {
	mock.ExpectExec(intentSQL).WillReturnResult(sqlmock.NewResult(0, 1))
}

// refusingIntent stands in for an audit destination that cannot accept the
// record.
func refusingIntent(cause error) AuditIntentWriter {
	return func(context.Context, *sql.Tx) error { return cause }
}

// alwaysKeepsAnAdmin is the permissive predicate, for tests whose subject is
// not the floor.
func alwaysKeepsAnAdmin() Predicate {
	return func(context.Context, []Grant) error { return nil }
}

func newTestCarrier(t *testing.T) (*Carrier, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c, err := New(db, "platform_admins")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, mock
}

// ---------------------------------------------------------------------------
// Construction and table parameterisation
// ---------------------------------------------------------------------------

// GUARD carrier-table-is-a-bare-identifier. The table name is the one element of
// these statements that cannot be a bind parameter, so it is admitted only in a
// shape with no interpretation beyond itself. Every rejected case below is a
// name that, quoted and interpolated, would change what the statement does.
func TestNewRefusesATableNameThatIsNotABareIdentifier(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rejected := map[string]string{
		"empty":                    "",
		"whitespace only":          "   ",
		"three parts":              "db.registry.platform_admins",
		"a statement terminator":   "platform_admins; DROP TABLE users",
		"an embedded double quote": `platform_admins" ; DROP TABLE users --`,
		"a subquery":               "(SELECT 1)",
		"a space":                  "platform admins",
		"a leading digit":          "1platform_admins",
		"a hyphen":                 "platform-admins",
		"an empty schema part":     ".platform_admins",
		"an empty table part":      "registry.",
		"over 63 bytes":            strings.Repeat("a", 64),
		// REVERSED IN #213, and this entry used to be an ACCEPTED case
		// asserting that "MixedCase.MixedTable" survived as
		// `"MixedCase"."MixedTable"` -- on the reasoning that refusing it makes
		// this package unusable against a table an operator genuinely created
		// with quoted DDL.
		//
		// That reasoning was sound and lost to a better one. PostgreSQL folds
		// an unquoted CREATE TABLE MixedCase to mixedcase, while a quoted
		// "MixedCase" is a different, case-sensitive table -- so a package
		// accepting mixed case must GUESS which the operator meant, and
		// addresses the wrong one when it guesses wrong. Usually that is loud;
		// where both tables exist it is silent, on a privileged mutation
		// surface.
		//
		// identity/auditoutbox had refused it all along for exactly that
		// reason, and any application wiring a carrier and an outbox against
		// one database already had to satisfy both -- so the strict grammar was
		// the effective one by intersection and this branch was unreachable for
		// every consumer that exists.
		"mixed case, which is ambiguous about which table was created": "MixedCase.MixedTable",
		"mixed case, unqualified":                                      "MixedTable",
	}
	for name, table := range rejected {
		t.Run(name, func(t *testing.T) {
			c, err := New(db, table)
			if !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("New(%q) err = %v, want ErrNotConfigured — an unvalidated table name "+
					"is interpolated straight into every statement this package runs", table, err)
			}
			if c != nil {
				t.Errorf("New(%q) returned a usable carrier alongside its error", table)
			}
		})
	}
}

func TestNewAcceptsQualifiedAndUnqualifiedTableNames(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	accepted := []struct {
		name  string
		table string
		want  string
	}{
		{"unqualified, resolved through search_path", "platform_admins", `"platform_admins"`},
		{"schema-qualified", "registry.tsm_admins", `"registry"."tsm_admins"`},
		{"surrounding whitespace is trimmed", "  platform_admins  ", `"platform_admins"`},
		{"a leading underscore", "_leading_underscore", `"_leading_underscore"`},
		{"digits after the first character", "tsm.platform_admins_v2", `"tsm"."platform_admins_v2"`},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(db, tc.table)
			if err != nil {
				t.Fatalf("New(%q): %v", tc.table, err)
			}
			if c.table != tc.want {
				t.Errorf("table = %q, want %q — every part must be double-quoted so a "+
					"case-sensitive or reserved-word name addresses what the operator meant",
					c.table, tc.want)
			}
		})
	}
}

func TestNewRefusesANilConnection(t *testing.T) {
	c, err := New(nil, "platform_admins")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if c != nil {
		t.Error("New returned a carrier over a nil connection")
	}
}

// GUARD per-carrier-floor-lock. Two applications sharing one database must not
// serialise against each other's administrator changes — the identity model
// this package serves puts registry's and state-manager's carriers side by side.
// A fixed lock constant (which is what registry's own adminfloor uses, because
// it only ever had one carrier) would make every grant in one app wait on the
// other.
func TestAdvisoryLockKeyIsPerTableAndDeterministic(t *testing.T) {
	registry := advisoryLockKey(`"registry"."platform_admins"`)
	tsm := advisoryLockKey(`"tsm"."platform_admins"`)
	if registry == tsm {
		t.Fatalf("two applications' carriers share lock key %d — one app's administrator "+
			"changes would block on the other's", registry)
	}
	if again := advisoryLockKey(`"registry"."platform_admins"`); again != registry {
		t.Fatalf("lock key for one table is not stable: %d then %d — every process in a "+
			"deployment must take the same lock", registry, again)
	}
	if registry == 0 {
		t.Error("lock key is 0, which is also the key any caller who forgot to derive one would use")
	}
}

// ---------------------------------------------------------------------------
// IsPlatformAdmin
// ---------------------------------------------------------------------------

func TestIsPlatformAdminReportsTheCarrierRow(t *testing.T) {
	for _, granted := range []bool{true, false} {
		t.Run(map[bool]string{true: "granted", false: "not granted"}[granted], func(t *testing.T) {
			c, mock := newTestCarrier(t)
			mock.ExpectQuery(`SELECT EXISTS.*FROM "platform_admins" WHERE user_id`).
				WithArgs(adminA).
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(granted))

			got, err := c.IsPlatformAdmin(context.Background(), adminA)
			if err != nil {
				t.Fatalf("IsPlatformAdmin: %v", err)
			}
			if got != granted {
				t.Errorf("IsPlatformAdmin = %v, want %v", got, granted)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

// A failure is returned, never swallowed into a false. The caller decides what
// an unresolved authority question means; this function must not decide it by
// returning the same value as a completed "no".
func TestIsPlatformAdminReturnsTheDriversError(t *testing.T) {
	c, mock := newTestCarrier(t)
	sentinel := errors.New("connection reset")
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(sentinel)

	got, err := c.IsPlatformAdmin(context.Background(), adminA)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if got {
		t.Error("IsPlatformAdmin = true on a failed lookup")
	}
}

// An empty principal is a clean no and must not reach Postgres, where a UUID
// column would turn it into an invalid-input ERROR — indistinguishable, to an
// authorization path, from the database being down. The mock is primed with no
// expectations, so any query fails ExpectationsWereMet.
func TestIsPlatformAdminAnswersAnEmptyPrincipalWithoutQuerying(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.IsPlatformAdmin(context.Background(), "")
	if err != nil {
		t.Fatalf("IsPlatformAdmin(\"\") = %v, want a clean false", err)
	}
	if got {
		t.Error("IsPlatformAdmin(\"\") = true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the empty principal reached the database: %v", err)
	}
}

func TestUnconstructedCarrierRefusesEveryOperation(t *testing.T) {
	var c *Carrier
	ctx := context.Background()

	if _, err := c.IsPlatformAdmin(ctx, adminA); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("IsPlatformAdmin err = %v, want ErrNotConfigured", err)
	}
	if _, err := c.List(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("List err = %v, want ErrNotConfigured", err)
	}
	if _, err := c.Grant(ctx, adminA, nil, nil, writingIntent(new(bool))); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Grant err = %v, want ErrNotConfigured", err)
	}
	if _, err := c.Revoke(ctx, adminA, alwaysKeepsAnAdmin(), writingIntent(new(bool))); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Revoke err = %v, want ErrNotConfigured", err)
	}
	if err := c.Serialize(ctx, func(context.Context) error { return nil }); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Serialize err = %v, want ErrNotConfigured", err)
	}
	if _, err := c.VerifyTable(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("VerifyTable err = %v, want ErrNotConfigured", err)
	}
	// Not a permission denial dressed up as one: an unwired carrier answers
	// the authority question with a fault, never with "no admin, carry on".
	scopes, err := c.SessionScopes(ctx, adminA, []string{"admin", "modules:read"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("SessionScopes err = %v, want ErrNotConfigured", err)
	}
	if hasAdmin(scopes) {
		t.Error("an unwired carrier left `admin` in the effective scopes")
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// UNFILTERED, INCLUDING ORPHANS. The management surface is the only place a
// grant whose user is gone can be removed from; hiding it here would make a live
// row invisible to the one thing that can clean it up.
func TestListReturnsEveryGrantOldestFirstIncludingOrphans(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	note := "bootstrap"
	mock.ExpectQuery(`FROM "platform_admins" ORDER BY granted_at ASC, user_id ASC`).
		WillReturnRows(sqlmock.NewRows(grantCols).
			AddRow(adminA, nil, t0, note).
			AddRow(orphanD, adminA, t0.Add(time.Hour), nil))

	got, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d grants, want 2", len(got))
	}
	if got[0].UserID != adminA || got[1].UserID != orphanD {
		t.Errorf("List order = %q, %q; want %q then %q (oldest grant first)",
			got[0].UserID, got[1].UserID, adminA, orphanD)
	}
	if got[0].Note == nil || *got[0].Note != note {
		t.Errorf("Note = %v, want %q — the note is provenance and must survive the round trip", got[0].Note, note)
	}
	if got[1].GrantedBy == nil || *got[1].GrantedBy != adminA {
		t.Errorf("GrantedBy = %v, want %q", got[1].GrantedBy, adminA)
	}
}

func TestListReturnsAnEmptySliceNotNil(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectQuery(`FROM "platform_admins"`).WillReturnRows(sqlmock.NewRows(grantCols))

	got, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil for an empty carrier; callers range and marshal this")
	}
	if len(got) != 0 {
		t.Errorf("List returned %d grants for an empty carrier", len(got))
	}
}

func TestListReturnsTheDriversError(t *testing.T) {
	c, mock := newTestCarrier(t)
	sentinel := errors.New("relation does not exist")
	mock.ExpectQuery(`FROM "platform_admins"`).WillReturnError(sentinel)

	got, err := c.List(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if got != nil {
		t.Errorf("List = %v on failure, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

func TestGrantRecordsProvenanceAndAuditsInTheSameTransaction(t *testing.T) {
	c, mock := newTestCarrier(t)
	granted := time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC)
	note := "promoted by ops"

	// ORDERED: begin, insert, write the audit intent on the SAME transaction,
	// commit. sqlmock matches in sequence, so an intent written after the commit
	// — the shape this design replaces — is an unexpected call.
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WithArgs(adminB, adminA, note).
		WillReturnRows(sqlmock.NewRows(grantCols).AddRow(adminB, adminA, granted, note))
	expectIntentWrite(mock)
	mock.ExpectCommit()

	grantor := adminA
	var audited bool
	got, err := c.Grant(context.Background(), adminB, &grantor, &note, writingIntent(&audited))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !audited {
		t.Error("the grant committed without the audit intent writer being run")
	}
	if got.UserID != adminB {
		t.Errorf("UserID = %q, want %q", got.UserID, adminB)
	}
	if got.GrantedBy == nil || *got.GrantedBy != adminA {
		t.Errorf("GrantedBy = %v, want %q — the provenance is why this is a table and not a boolean", got.GrantedBy, adminA)
	}
	if !got.GrantedAt.Equal(granted) {
		t.Errorf("GrantedAt = %v, want %v", got.GrantedAt, granted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ON CONFLICT DO NOTHING returns no row. That must surface as the sentinel, not
// as a nil grant with a nil error, and the EXISTING row must be left alone —
// overwriting it would erase who originally conferred the privilege.
func TestGrantOnAnExistingGrantReportsTheSentinelAndAuditsNothing(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WithArgs(adminB, nil, nil).
		WillReturnRows(sqlmock.NewRows(grantCols)) // conflict: nothing returned
	mock.ExpectRollback()

	var audited bool
	got, err := c.Grant(context.Background(), adminB, nil, nil, writingIntent(&audited))
	if !errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Fatalf("err = %v, want ErrAlreadyPlatformAdmin", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v on a conflict, want nil", got)
	}
	// Nothing changed hands, so there is nothing to audit. Writing an intent
	// here would put a "granted" record in the trail for a grant that did not
	// happen.
	if audited {
		t.Error("an audit intent was written for a grant that conflicted and changed nothing")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (did it commit?): %v", err)
	}
}

func TestGrantReturnsTheDriversErrorWithoutAuditing(t *testing.T) {
	c, mock := newTestCarrier(t)
	sentinel := errors.New("insert failed")
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).WillReturnError(sentinel)
	mock.ExpectRollback()

	var audited bool
	got, err := c.Grant(context.Background(), adminB, nil, nil, writingIntent(&audited))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Error("a driver failure was reported as ErrAlreadyPlatformAdmin")
	}
	if got != nil {
		t.Errorf("Grant = %+v on failure, want nil", got)
	}
	if audited {
		t.Error("an audit intent was written for a grant that failed")
	}
}

// GUARD durable-audit-mandatory-writer (Grant). A privileged mutation with
// nowhere to record itself does not happen — and does not even open a
// transaction. The mock is primed with NO expectations, so a BEGIN would fail
// ExpectationsWereMet: this asserts the refusal came before the database, not
// merely that an error came back.
func TestGrantWithNoAuditWriterRefusesWithoutTouchingTheDatabase(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.Grant(context.Background(), adminB, nil, nil, nil)
	if !errors.Is(err, ErrAuditIntentRequired) {
		t.Fatalf("err = %v, want ErrAuditIntentRequired", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v with no audit writer, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the unauditable grant reached the database: %v", err)
	}
}

// GUARD durable-audit-atomic (Grant). The audit destination refuses, and the
// grant must not commit.
//
// Asserted on the writer's OWN sentinel and on ExpectationsWereMet, because a
// bare "err != nil" is also satisfied by sqlmock's unexpected-call error — which
// is how a guard in this estate once passed while protecting nothing.
func TestGrantDoesNotCommitWhenTheAuditIntentIsRefused(t *testing.T) {
	c, mock := newTestCarrier(t)
	granted := time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WithArgs(adminB, nil, nil).
		WillReturnRows(sqlmock.NewRows(grantCols).AddRow(adminB, nil, granted, nil))
	// No ExpectCommit: a commit here is an unexpected call and fails the test.
	mock.ExpectRollback()

	outboxDown := errors.New("audit outbox unreachable")
	got, err := c.Grant(context.Background(), adminB, nil, nil, refusingIntent(outboxDown))
	if !errors.Is(err, outboxDown) {
		t.Fatalf("err = %v, want the audit writer's own error %v", err, outboxDown)
	}
	if got != nil {
		t.Errorf("Grant = %+v when the audit record could not be written, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the unaudited grant committed: %v", err)
	}
}

func TestGrantRefusesAnEmptyPrincipalWithoutTouchingTheDatabase(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.Grant(context.Background(), "   ", nil, nil, writingIntent(new(bool)))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v for an empty principal, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the empty principal reached the database: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

// expectLockingRead primes the FOR UPDATE read Revoke performs. The regexp
// includes FOR UPDATE deliberately: a Revoke that read the carrier WITHOUT the
// row lock would not match this expectation, so the lock is asserted rather than
// assumed.
func expectLockingRead(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT user_id, granted_by, granted_at, note FROM "platform_admins" .*FOR UPDATE`).
		WillReturnRows(rows)
}

func TestRevokeDeletesUnderTheRowLockAndAuditsInTheSameTransaction(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	expectLockingRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, t0, nil).
		AddRow(adminB, adminA, t0.Add(time.Hour), nil))
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectIntentWrite(mock)
	mock.ExpectCommit()

	var sawRemaining []Grant
	var audited bool
	got, err := c.Revoke(context.Background(), adminB, func(_ context.Context, remaining []Grant) error {
		sawRemaining = remaining
		return nil
	}, writingIntent(&audited))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got == nil || got.UserID != adminB {
		t.Fatalf("Revoke = %+v, want the removed grant for %q", got, adminB)
	}
	if !audited {
		t.Error("the revocation committed without the audit intent writer being run")
	}
	// The predicate is handed what WOULD REMAIN — never the target itself.
	// Including the target would let the last administrator's own row satisfy
	// "somebody else is still here".
	if len(sawRemaining) != 1 || sawRemaining[0].UserID != adminA {
		t.Errorf("predicate saw %+v, want exactly the grant for %q", sawRemaining, adminA)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD platform-admin-last-standing. The predicate refuses, and nothing is
// deleted. No ExpectExec for the DELETE is primed, so a delete is an unexpected
// call; the sentinel is asserted rather than "an error came back".
func TestRevokeDeletesNothingWhenThePredicateRefuses(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	expectLockingRead(mock, sqlmock.NewRows(grantCols).AddRow(adminA, nil, t0, nil))
	mock.ExpectRollback()

	var audited bool
	got, err := c.Revoke(context.Background(), adminA,
		func(context.Context, []Grant) error { return ErrLastPlatformAdmin },
		writingIntent(&audited))
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin — the predicate's own sentinel must "+
			"reach the caller so a handler can tell a floor refusal from a fault", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v on a refusal, want nil", got)
	}
	if audited {
		t.Error("a revocation that did not happen was written to the audit trail")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the refused revocation reached the DELETE: %v", err)
	}
}

func TestRevokeOfANonAdminReportsNotFound(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	expectLockingRead(mock, sqlmock.NewRows(grantCols).AddRow(adminA, nil, t0, nil))
	mock.ExpectRollback()

	var predicateRan bool
	got, err := c.Revoke(context.Background(), adminC,
		func(context.Context, []Grant) error { predicateRan = true; return nil },
		writingIntent(new(bool)))
	if !errors.Is(err, ErrNotPlatformAdmin) {
		t.Fatalf("err = %v, want ErrNotPlatformAdmin", err)
	}
	// The module's single not-found sentinel answers too, so a caller with one
	// generic miss handler is not surprised.
	if !errors.Is(err, store.ErrNotFound) {
		t.Error("ErrNotPlatformAdmin does not wrap store.ErrNotFound, the module's only not-found sentinel")
	}
	if got != nil {
		t.Errorf("Revoke = %+v, want nil", got)
	}
	// There is no reduction to evaluate, so the floor must not be consulted —
	// and must not be able to refuse a no-op with ErrLastPlatformAdmin.
	if predicateRan {
		t.Error("the floor predicate ran for a principal that holds no grant")
	}
}

// GUARD floor-cannot-be-silently-absent. Registry's original made the predicate
// optional and skipped the check when nil, which is the one way the floor can
// vanish without anybody noticing. An application that genuinely wants no floor
// passes a predicate that says so, in a line a reviewer can see.
func TestRevokeWithNoPredicateRefusesWithoutTouchingTheDatabase(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.Revoke(context.Background(), adminA, nil, writingIntent(new(bool)))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v with no floor predicate, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the unguarded revocation reached the database: %v", err)
	}
}

// GUARD durable-audit-mandatory-writer (Revoke).
func TestRevokeWithNoAuditWriterRefusesWithoutTouchingTheDatabase(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.Revoke(context.Background(), adminA, alwaysKeepsAnAdmin(), nil)
	if !errors.Is(err, ErrAuditIntentRequired) {
		t.Fatalf("err = %v, want ErrAuditIntentRequired", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v with no audit writer, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the unauditable revocation reached the database: %v", err)
	}
}

// GUARD durable-audit-atomic (Revoke). The DELETE ran; the audit write refuses;
// the transaction must roll back rather than leave an unrecorded loss of
// privilege.
func TestRevokeDoesNotCommitWhenTheAuditIntentIsRefused(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	expectLockingRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, t0, nil).
		AddRow(adminB, nil, t0.Add(time.Hour), nil))
	mock.ExpectExec(`DELETE FROM "platform_admins"`).WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// No ExpectCommit: a commit is an unexpected call and fails the test.
	mock.ExpectRollback()

	outboxDown := errors.New("audit outbox unreachable")
	got, err := c.Revoke(context.Background(), adminB, alwaysKeepsAnAdmin(), refusingIntent(outboxDown))
	if !errors.Is(err, outboxDown) {
		t.Fatalf("err = %v, want the audit writer's own error %v", err, outboxDown)
	}
	if got != nil {
		t.Errorf("Revoke = %+v when the record could not be written, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the unaudited revocation committed: %v", err)
	}
}

// The row was present under FOR UPDATE moments ago, so zero rows deleted means
// the lock did not hold what it is supposed to hold. Reporting a revocation
// that did not happen would leave an administrator the operator believes is
// gone.
func TestRevokeRefusesToCommitWhenTheDeleteMatchedNothing(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	expectLockingRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, t0, nil).
		AddRow(adminB, nil, t0.Add(time.Hour), nil))
	mock.ExpectExec(`DELETE FROM "platform_admins"`).WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	got, err := c.Revoke(context.Background(), adminB, alwaysKeepsAnAdmin(), writingIntent(new(bool)))
	if err == nil {
		t.Fatal("Revoke reported success for a DELETE that matched no row")
	}
	if !strings.Contains(err.Error(), "removed 0 rows, want 1") {
		t.Errorf("err = %v, want it to name the row count so the operator can see the lock did not hold", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the phantom revocation committed: %v", err)
	}
}

func TestRevokeReturnsTheDriversReadError(t *testing.T) {
	c, mock := newTestCarrier(t)
	sentinel := errors.New("lock timeout")
	mock.ExpectBegin()
	mock.ExpectQuery(`FOR UPDATE`).WillReturnError(sentinel)
	mock.ExpectRollback()

	got, err := c.Revoke(context.Background(), adminB, alwaysKeepsAnAdmin(), writingIntent(new(bool)))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if errors.Is(err, ErrNotPlatformAdmin) {
		t.Error("a failed locking read was reported as 'user does not hold platform-admin' — " +
			"a fault must not read as a completed answer about a principal")
	}
	if got != nil {
		t.Errorf("Revoke = %+v on failure, want nil", got)
	}
}

func TestRevokeRefusesAnEmptyPrincipalWithoutTouchingTheDatabase(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.Revoke(context.Background(), "", alwaysKeepsAnAdmin(), writingIntent(new(bool)))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the empty principal reached the database: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Serialize
// ---------------------------------------------------------------------------

// The lock is taken BEFORE fn runs, on this carrier's own key, and released by
// the rollback of the write-free transaction that scopes it.
func TestSerializeTakesTheLockBeforeRunningAnythingAndReleasesIt(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WithArgs(c.lockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// fn's own work, primed AFTER the lock: sqlmock matches in sequence, so a
	// Serialize that ran fn first would not match.
	mock.ExpectExec("DELETE FROM something").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	var ran bool
	err := c.Serialize(context.Background(), func(ctx context.Context) error {
		ran = true
		_, err := c.db.ExecContext(ctx, "DELETE FROM something")
		return err
	})
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !ran {
		t.Error("Serialize did not run fn")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (was the lock taken first, and released?): %v", err)
	}
}

// A lock that could not be taken is NOT permission to proceed unserialised.
// fn must not run, and the caller must be able to tell this apart from fn's own
// failure.
func TestSerializeDoesNotRunTheWriteWhenTheLockCannotBeTaken(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WillReturnError(errors.New("deadlock detected"))
	mock.ExpectRollback()

	var ran bool
	err := c.Serialize(context.Background(), func(context.Context) error {
		ran = true
		return nil
	})
	if !errors.Is(err, ErrNotSerialized) {
		t.Fatalf("err = %v, want ErrNotSerialized", err)
	}
	if ran {
		t.Error("fn ran without the floor lock — an unserialised change is not a safe fallback for a serialised one")
	}
}

func TestSerializeReturnsTheWritesOwnErrorUnwrapped(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectBegin()
	mock.ExpectExec(`pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := c.Serialize(context.Background(), func(context.Context) error { return ErrLastPlatformAdmin })
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin to survive Serialize", err)
	}
	if errors.Is(err, ErrNotSerialized) {
		t.Error("a policy refusal from fn was reported as a failure to take the lock")
	}
}

func TestSerializeRefusesWhenGivenNothingToRun(t *testing.T) {
	c, mock := newTestCarrier(t)
	if err := c.Serialize(context.Background(), nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a no-op Serialize opened a transaction: %v", err)
	}
}

func TestSerializeReportsAFailureToBegin(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectBegin().WillReturnError(errors.New("pool exhausted"))

	var ran bool
	err := c.Serialize(context.Background(), func(context.Context) error { ran = true; return nil })
	if !errors.Is(err, ErrNotSerialized) {
		t.Fatalf("err = %v, want ErrNotSerialized", err)
	}
	if ran {
		t.Error("fn ran although no transaction could be opened to hold the lock")
	}
}
