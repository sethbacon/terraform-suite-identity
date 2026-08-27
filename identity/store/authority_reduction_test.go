package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// Behavioural guards for the transactional authority reduction (issue #129).
//
// Every one of these is a MUTATION GATE, not a coverage exercise: each names the
// edit that must make it fail. sqlmock's expectations are ordered and its query
// matcher is a regexp over the whitespace-normalised statement, so moving a
// statement out of the transaction, dropping the scope predicate, or swallowing
// a sweep error all change something the mock is asserting on.

// testRWPairs is the read/write grammar the reductions below are judged under.
var testRWPairs = auth.ReadWritePairs{"modules:read": "modules:write"}

// recordingApp is an AppCredentials that records the transaction it was handed
// and can be told to fail.
type recordingApp struct {
	calls int
	tx    *sql.Tx
	red   Reduced
	fail  error
}

func (a *recordingApp) sweep(_ context.Context, tx *sql.Tx, red Reduced) error {
	a.calls++
	a.tx = tx
	a.red = red
	return a.fail
}

// retainedRows is the reply to Reducer.retainedScopes.
func retainedRows(pairs ...string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"organization_id", "scopes"})
	for i := 0; i+1 < len(pairs); i += 2 {
		rows.AddRow(pairs[i], []byte(pairs[i+1]))
	}
	return rows
}

// keyRows is the reply to the FOR UPDATE read over api_keys.
func keyRows(triples ...string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"id", "organization_id", "scopes"})
	for i := 0; i+2 < len(triples); i += 3 {
		rows.AddRow(triples[i], triples[i+1], []byte(triples[i+2]))
	}
	return rows
}

const (
	membershipDeleteRe = `DELETE FROM organization_members WHERE organization_id = \$1 AND user_id = \$2`
	membershipUpdateRe = `UPDATE organization_members SET role_template_id = \$3`
	retainedRe         = `SELECT om\.organization_id, COALESCE\(rt\.scopes.*FROM organization_members om.*LEFT JOIN role_templates rt`
	keyReadRe          = `SELECT id, organization_id, scopes FROM api_keys WHERE user_id = \$1 AND organization_id = ANY\(\$2\).*FOR UPDATE`
	keyDeleteRe        = `DELETE FROM api_keys WHERE id = ANY\(\$1\)`
	orgPredicateSQL    = `.*organization_id = ANY\(\$\d+\)`
)

// GUARD reduction-and-sweep-in-one-transaction. The membership DELETE, the
// retained-authority lookup, the locked key read, the key DELETE and the
// application's own sweep all happen between BEGIN and COMMIT.
//
// MUTATION: move any of them onto the pool (r.db instead of tx), or commit
// before the sweep, and the ordered expectations below stop matching.
func TestReducerRemoveMemberSweepsInsideTheTransaction(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe + orgPredicateSQL).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).
		WillReturnRows(keyRows("key-1", "org-1", `["modules:write"]`))
	mock.ExpectExec(keyDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	app := &recordingApp{}
	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeOrganizations("org-1"), app.sweep)
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
	if red.KeysRevoked != 1 || red.KeysRetained != 0 {
		t.Errorf("Reduced = %+v, want 1 revoked and 0 retained", red)
	}
	if len(red.Organizations) != 1 || red.Organizations[0] != "org-1" {
		t.Errorf("Reduced.Organizations = %v, want [org-1]", red.Organizations)
	}
	if app.calls != 1 {
		t.Fatalf("AppCredentials called %d times, want 1", app.calls)
	}
	if app.tx == nil {
		t.Error("AppCredentials was handed a nil transaction, so an app-owned credential " +
			"family could only be swept on another connection — the best-effort shape this " +
			"primitive exists to replace")
	}
	if app.red.KeysRevoked != 1 {
		t.Errorf("AppCredentials saw %+v, want the api-key sweep's result", app.red)
	}
}

// GUARD sweep-failure-rolls-back-the-reduction. A credential sweep that fails
// must not leave the reduction committed.
//
// MUTATION: log the sweep error and fall through to Commit — the shape both
// consumers use today, where Outcome.Incomplete reports it after the fact — and
// this fails on the missing ROLLBACK and on the nil error.
func TestReducerRollsBackWhenTheKeySweepFails(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	boom := errors.New("api_keys unavailable")
	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows("key-1", "org-1", `["modules:write"]`))
	mock.ExpectExec(keyDeleteRe).WillReturnError(boom)
	mock.ExpectRollback()

	app := &recordingApp{}
	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), app.sweep)
	if err == nil {
		t.Fatal("RemoveMember reported success after the key sweep failed; the membership " +
			"would be gone and the credentials alive, which is the whole defect")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap the sweep failure", err)
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v on a rolled-back reduction, want the zero value so a caller "+
			"that ignores the error cannot read a summary of work that did not happen", red)
	}
	if app.calls != 0 {
		t.Error("AppCredentials ran after the api-key sweep had already failed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD app-sweep-failure-rolls-back-the-reduction. Same rule for the family
// this module does not own.
//
// MUTATION: swallow the AppCredentials error, or call it after Commit.
func TestReducerRollsBackWhenAppCredentialsFail(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	boom := errors.New("watermark write failed")
	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows())
	mock.ExpectRollback()

	app := &recordingApp{fail: boom}
	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), app.sweep)
	if err == nil {
		t.Fatal("RemoveMember reported success after the application's credential sweep failed")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap the application's failure", err)
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v on a rolled-back reduction, want the zero value", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD nil-app-credentials-refuses. A nil AppCredentials is a caller that did
// not decide, and an optional guard is how a guard goes silently absent.
//
// MUTATION: treat nil as a no-op sweep. The database must not be touched at
// all, so the mock's unmet ExpectBegin is what catches a version that opens a
// transaction first and then discovers the problem.
func TestReducerRefusesNilAppCredentials(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), nil)
	if !errors.Is(err, ErrNoCredentialDecision) {
		t.Fatalf("err = %v, want ErrNoCredentialDecision; nil must not be able to mean "+
			"\"no sweep needed\" — NoAppCredentials is how a caller says that. "+
			"Asserting merely that SOME error came back passes when the reduction ran and "+
			"failed for an unrelated reason, which is how this guard goes inert", err)
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v on a refused reduction, want the zero value", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the refusal touched the database: %v", err)
	}
}

// NoAppCredentials is the deliberate opt-out the IdP group-mapping deprovision
// path needs: sweep the API-key family, do NOT move the JWT watermark. The
// reduction and the key sweep still run and still commit.
func TestNoAppCredentialsStillSweepsTheKeyFamily(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows("key-1", "org-1", `["modules:write"]`))
	mock.ExpectExec(keyDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveMember with NoAppCredentials: %v", err)
	}
	if red.KeysRevoked != 1 {
		t.Errorf("Reduced = %+v, want the api-key family swept even though the application "+
			"opted out of its own", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD retained-authority-survives. A key whose frozen scopes the principal
// still holds is not destroyed. Deleting one is irreversible, so sweeping on an
// authority CHANGE rather than a REDUCTION is pure damage.
//
// MUTATION: delete every key in the affected organizations unconditionally —
// the unmet ExpectCommit-without-a-DELETE is what catches it.
func TestReducerRetainsKeysStillCoveredByTheRemainingRole(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipUpdateRe).WillReturnResult(sqlmock.NewResult(0, 1))
	// The membership survived the UPDATE, so the new template's scopes are the
	// retained set.
	mock.ExpectQuery(retainedRe).
		WillReturnRows(retainedRows("org-1", `["modules:write","providers:read"]`))
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows(
		"still-covered", "org-1", `["modules:read"]`, // write-implies-read
		"now-excessive", "org-1", `["users:write"]`,
	))
	mock.ExpectExec(keyDeleteRe).
		WithArgs([]string{"now-excessive"}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tmpl := "template-2"
	red, err := NewReducer(db, testRWPairs).
		UpdateMemberRoleTemplate(context.Background(), "org-1", "user-1", &tmpl, OrgScopeAllOrganizations(), NoAppCredentials)
	if err != nil {
		t.Fatalf("UpdateMemberRoleTemplate: %v", err)
	}
	if red.KeysRevoked != 1 || red.KeysRetained != 1 {
		t.Errorf("Reduced = %+v, want 1 revoked and 1 retained", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD partial-delete-aborts. The keys were selected FOR UPDATE inside this
// transaction, so the DELETE must match every one of them. A short delete means
// the statement is not deleting what the decision was made about.
//
// MUTATION: drop the count comparison and return the affected rows as the
// result — the reduction then commits having destroyed one of the two keys it
// decided to destroy, and reports success.
func TestReducerAbortsWhenTheKeyDeleteIsShort(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows(
		"key-1", "org-1", `["modules:write"]`,
		"key-2", "org-1", `["users:write"]`,
	))
	mock.ExpectExec(keyDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if err == nil {
		t.Fatal("a sweep that deleted 1 of the 2 keys it selected reported success")
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v, want the zero value", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD notfound-sweeps-nothing. A by-identifier reduction that matched no row
// changed no authority, so it must roll back before any sweep runs — reporting
// ErrNotFound exactly as the repository method does.
//
// MUTATION: drop requireRow and let a zero-row DELETE fall through. The sweep
// would then run for a membership that was never there, and (through
// AppCredentials) move a platform-wide watermark for a no-op.
func TestReducerNotFoundRollsBackBeforeSweeping(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	app := &recordingApp{}
	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), app.sweep)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound so a removal that removed nothing cannot be "+
			"recorded as one that did", err)
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v, want the zero value", red)
	}
	if app.calls != 0 {
		t.Error("AppCredentials ran for a membership that did not exist")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD nothing-reduced-sweeps-nothing. The bulk reduction is allowed to remove
// no memberships, and when it does nothing is swept and AppCredentials is not
// called — moving a per-user watermark for a reduction that did not happen ends
// every session that principal holds, everywhere, for no benefit (the same
// no-op hazard approles encodes as authorityChanged).
//
// MUTATION: call the sweeps unconditionally.
func TestReducerRemoveAllMembershipsSweepsNothingWhenNothingWasRemoved(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(`DELETE FROM organization_members WHERE user_id = \$1.*RETURNING organization_id`).
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
	mock.ExpectCommit()

	app := &recordingApp{}
	red, err := NewReducer(db, testRWPairs).
		RemoveAllMembershipsForUser(context.Background(), "user-1", OrgScopeAllOrganizations(), app.sweep)
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if len(red.Organizations) != 0 || red.KeysRevoked != 0 {
		t.Errorf("Reduced = %+v, want nothing reduced", red)
	}
	if app.calls != 0 {
		t.Error("AppCredentials ran for a deprovisioning that removed no membership")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// The bulk reduction sweeps every organization it actually emptied, and only
// those: the affected set is what the DELETE returned, not what the caller
// asked about.
func TestReducerRemoveAllMembershipsSweepsTheOrganizationsItEmptied(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(`DELETE FROM organization_members WHERE user_id = \$1.*RETURNING organization_id`).
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1").AddRow("org-2"))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).
		WithArgs("user-1", []string{"org-1", "org-2"}).
		WillReturnRows(keyRows("k1", "org-1", `["modules:write"]`, "k2", "org-2", `["users:read"]`))
	mock.ExpectExec(keyDeleteRe).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	red, err := NewReducer(db, testRWPairs).
		RemoveAllMembershipsForUser(context.Background(), "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if red.KeysRevoked != 2 {
		t.Errorf("Reduced = %+v, want both organizations' keys revoked", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD reduction-carries-the-tenant-predicate. Every reduction issues the same
// scoped statement its repository twin does, so the transactional variant is
// not a way around the tenancy guards (#138, #160, #162).
//
// MUTATION: drop the andScope call from any reduction below and its row's
// statement no longer matches the pattern.
func TestReducerReductionsKeepTheirTenantPredicate(t *testing.T) {
	cases := []struct {
		name  string
		stmt  string
		exec  bool
		call  func(*Reducer, OrgScope) error
		zero  error
		lines int
	}{
		{
			name: "RemoveMember",
			stmt: membershipDeleteRe + orgPredicateSQL,
			exec: true,
			call: func(r *Reducer, s OrgScope) error {
				_, err := r.RemoveMember(context.Background(), "org-1", "user-1", s, NoAppCredentials)
				return err
			},
			zero: ErrNotFound,
		},
		{
			name: "UpdateMemberRoleTemplate",
			stmt: membershipUpdateRe + orgPredicateSQL,
			exec: true,
			call: func(r *Reducer, s OrgScope) error {
				tmpl := "t"
				_, err := r.UpdateMemberRoleTemplate(context.Background(), "org-1", "user-1", &tmpl, s, NoAppCredentials)
				return err
			},
			zero: ErrNotFound,
		},
		{
			name: "RemoveAllMembershipsForUser",
			stmt: `DELETE FROM organization_members WHERE user_id = \$1` + orgPredicateSQL + `.*RETURNING organization_id`,
			call: func(r *Reducer, s OrgScope) error {
				_, err := r.RemoveAllMembershipsForUser(context.Background(), "user-1", s, NoAppCredentials)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/scoped", func(t *testing.T) {
			db, mock, err := newSQLMock()
			if err != nil {
				t.Fatalf("new mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			mock.ExpectBegin()
			if tc.exec {
				mock.ExpectExec(tc.stmt).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
				mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows())
			} else {
				mock.ExpectQuery(tc.stmt).
					WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
			}
			mock.ExpectCommit()

			if err := tc.call(NewReducer(db, testRWPairs), OrgScopeOrganizations("org-1")); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the statement did not carry the tenant predicate: %v", err)
			}
		})

		t.Run(tc.name+"/zero-scope", func(t *testing.T) {
			db, mock, err := newSQLMock()
			if err != nil {
				t.Fatalf("new mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			err = tc.call(NewReducer(db, testRWPairs), OrgScope{})
			if tc.zero != nil && !errors.Is(err, tc.zero) {
				t.Errorf("zero scope: err = %v, want %v", err, tc.zero)
			}
			if tc.zero == nil && err != nil {
				t.Errorf("zero scope: err = %v, want nil for a bulk reduction", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a zero scope reached the database: %v", err)
			}
		})
	}
}

// UpdateMemberRole resolves the template name INSIDE the transaction, so a
// template deleted between the lookup and the update cannot leave the
// membership pointing at a row that no longer exists.
//
// MUTATION: resolve it on the pool (r.db) before BEGIN and the ordered
// expectations below fail on the out-of-transaction query.
func TestReducerUpdateMemberRoleResolvesTheTemplateInTheTransaction(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM role_templates WHERE name = \$1`).
		WithArgs("viewer").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("tmpl-viewer"))
	mock.ExpectExec(membershipUpdateRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows("org-1", `["modules:read"]`))
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows())
	mock.ExpectCommit()

	if _, err := NewReducer(db, testRWPairs).
		UpdateMemberRole(context.Background(), "org-1", "user-1", "viewer", OrgScopeAllOrganizations(), NoAppCredentials); err != nil {
		t.Fatalf("UpdateMemberRole: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// An unresolvable template name aborts the whole reduction rather than setting
// a silent NULL role.
func TestReducerUpdateMemberRoleRefusesAnUnknownTemplate(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM role_templates WHERE name = \$1`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = NewReducer(db, testRWPairs).
		UpdateMemberRole(context.Background(), "org-1", "user-1", "nope", OrgScopeAllOrganizations(), NoAppCredentials)
	if err == nil || !strings.Contains(err.Error(), "role template \"nope\" not found") {
		t.Fatalf("err = %v, want the unresolved-template refusal rather than a silent NULL role", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// A zero-scope bulk reduction reduces nothing and reports nothing, without a
// round trip — matching OrganizationRepository.RemoveAllMembershipsForUser.
func TestReducerZeroScopeBulkReductionIsANoOp(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	red, err := NewReducer(db, testRWPairs).
		RemoveAllMembershipsForUser(context.Background(), "user-1", OrgScope{}, NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if len(red.Organizations) != 0 {
		t.Errorf("Reduced = %+v, want nothing reduced", red)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a zero scope reached the database: %v", err)
	}
}

// A Reducer with no database handle refuses. A nil-receiver no-op would reduce
// nothing and sweep nothing while reporting success.
func TestReducerWithoutADatabaseRefuses(t *testing.T) {
	for _, r := range []*Reducer{nil, {}} {
		if _, err := r.RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials); !errors.Is(err, ErrNoReducer) {
			t.Errorf("err = %v, want ErrNoReducer", err)
		}
	}
}

// A failure of the retained-authority lookup aborts rather than defaulting to
// "nothing retained" (which would over-revoke) or "everything retained" (which
// would strand credentials).
func TestReducerRollsBackWhenRetainedAuthorityCannotBeRead(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	boom := errors.New("retained read failed")
	mock.ExpectQuery(retainedRe).WillReturnError(boom)
	mock.ExpectRollback()

	_, err = NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the retained-authority read failure. Treating an "+
			"unreadable retained set as \"nothing retained\" destroys every key in the "+
			"organization; treating it as \"everything retained\" strands them all", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// A key read that fails also aborts.
func TestReducerRollsBackWhenTheKeyReadFails(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	boom := errors.New("locked out")
	mock.ExpectQuery(keyReadRe).WillReturnError(boom)
	mock.ExpectRollback()

	_, err = NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the key-read failure", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// A commit that fails is reported, and reports nothing done.
func TestReducerReportsACommitFailure(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows())
	boom := errors.New("commit failed")
	mock.ExpectCommit().WillReturnError(boom)

	red, err := NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the commit failure", err)
	}
	if !reflect.DeepEqual(red, Reduced{}) {
		t.Errorf("Reduced = %+v, want the zero value", red)
	}
}

// A failure to begin is reported rather than silently skipping the reduction.
func TestReducerReportsABeginFailure(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	boom := errors.New("no connection")
	mock.ExpectBegin().WillReturnError(boom)

	_, err = NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the begin failure", err)
	}
}

// Malformed scopes JSONB aborts rather than being read as "no scopes", which
// would silently retain every key.
func TestReducerRollsBackOnUnreadableKeyScopes(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows())
	mock.ExpectQuery(keyReadRe).WillReturnRows(keyRows("k1", "org-1", `not json`))
	mock.ExpectRollback()

	_, err = NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if err == nil || !strings.Contains(err.Error(), "unmarshal api key scopes") {
		t.Fatalf("err = %v, want the api-key scope decode failure; a key whose scopes cannot "+
			"be read must not be treated as retained", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// Malformed retained-scope JSONB aborts for the same reason, in the opposite
// direction: read as "no scopes" it would destroy every key in the
// organization.
func TestReducerRollsBackOnUnreadableRetainedScopes(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(membershipDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(retainedRe).WillReturnRows(retainedRows("org-1", `not json`))
	mock.ExpectRollback()

	_, err = NewReducer(db, testRWPairs).
		RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations(), NoAppCredentials)
	if err == nil || !strings.Contains(err.Error(), "unmarshal retained authority") {
		t.Fatalf("err = %v, want the retained-authority decode failure; unreadable retained "+
			"authority must not be read as an empty scope set, which destroys every key", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestAuthorityRetained(t *testing.T) {
	rw := auth.ReadWritePairs{"modules:read": "modules:write"}
	cases := []struct {
		name     string
		have     []string
		retained []string
		want     bool
	}{
		{"nothing frozen is vacuously retained", nil, nil, true},
		{"empty retained grants nothing", []string{"modules:read"}, nil, false},
		{"exact match", []string{"modules:read"}, []string{"modules:read"}, true},
		{"write implies read", []string{"modules:read"}, []string{"modules:write"}, true},
		{"read does not imply write", []string{"modules:write"}, []string{"modules:read"}, false},
		{"admin retains everything", []string{"users:write", "audit:read"}, []string{"admin"}, true},
		{"reordering is not a reduction",
			[]string{"a", "b"}, []string{"b", "a"}, true},
		{"one uncovered scope is enough",
			[]string{"modules:read", "users:write"}, []string{"modules:write"}, false},
		{"an empty scope string is never granted", []string{""}, []string{"admin"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuthorityRetained(tc.have, tc.retained, rw); got != tc.want {
				t.Errorf("AuthorityRetained(%v, %v) = %v, want %v", tc.have, tc.retained, got, tc.want)
			}
		})
	}

	// With no read/write grammar the predicate is STRICTER, not looser: a key
	// frozen with the read scope is no longer covered by the write scope, so it
	// is destroyed. That over-revokes and never under-revokes, which is the
	// direction a missing configuration has to fail in.
	if AuthorityRetained([]string{"modules:read"}, []string{"modules:write"}, nil) {
		t.Error("with no ReadWritePairs the predicate inferred an implication it was never given")
	}
}
