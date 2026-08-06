package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// These tests pin the observable behaviour of the five membership accessors that
// were collapsed onto the shared query constants and scan helpers in
// membership.go. They exist so the de-duplication is VERIFIED rather than
// assumed: each call site's error wording, its no-rows convention and the SQL it
// issues are asserted independently, so a future edit to a shared constant or
// helper that changes any one of them fails here instead of silently altering a
// caller that used to own its own copy.

// userMembershipCols is declared in organization_repository_test.go; the bulk
// form selects the same columns plus a leading om.user_id.
var userMembershipBulkCols = append([]string{"user_id"}, userMembershipCols...)

// userCols mirrors the users projection the repositories select.
var membershipTestUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

// badScopesJSON is not valid JSON, so it forces the role_template_scopes
// unmarshal to fail on whichever path is under test.
var badScopesJSON = []byte(`{not json`)

func whitespace(s string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(s), " ")
}

// ---------------------------------------------------------------------------
// The shared query constants
// ---------------------------------------------------------------------------

// TestUserMembershipQueriesShareOneProjection is the structural half of the
// de-duplication guarantee: the single-user and bulk forms must select the same
// projection off the same JOIN chain, differing only in the bulk form's extra
// leading om.user_id column and its predicate/ordering. If someone adds a column
// to one and not the other, the two scan paths diverge and this fails.
func TestUserMembershipQueriesShareOneProjection(t *testing.T) {
	single := whitespace(userMembershipByUserQuery)
	bulk := whitespace(userMembershipByUserIDsQuery)

	if !strings.Contains(single, whitespace(userMembershipColumns)) {
		t.Errorf("single-user query does not contain the shared projection:\n%s", single)
	}
	if !strings.Contains(bulk, whitespace(userMembershipColumns)) {
		t.Errorf("bulk query does not contain the shared projection:\n%s", bulk)
	}
	if !strings.Contains(single, whitespace(userMembershipFrom)) ||
		!strings.Contains(bulk, whitespace(userMembershipFrom)) {
		t.Error("both user-membership queries must use the shared FROM/JOIN chain")
	}
	if !strings.HasPrefix(bulk, "SELECT om.user_id, ") {
		t.Errorf("bulk query must select om.user_id first so rows can be attributed: %s", bulk)
	}
	// The query constants END at the WHERE clause and the ORDER BY is a separate
	// constant appended by each caller. That split is load-bearing since v0.25.0:
	// a tenant predicate is spliced onto the WHERE clause (andScope), so a
	// constant that already ended in ORDER BY would receive it as
	// `ORDER BY om.created_at DESC AND <predicate>`. Assert both halves, and
	// assert the ordering is NOT baked into the query — otherwise a well-meaning
	// re-merge silently reintroduces the syntax error on the scoped path only.
	if !strings.HasSuffix(single, "WHERE om.user_id = $1") {
		t.Errorf("single-user predicate changed: %s", single)
	}
	if !strings.HasSuffix(bulk, "WHERE om.user_id = ANY($1)") {
		t.Errorf("bulk predicate changed: %s", bulk)
	}
	if strings.Contains(single, "ORDER BY") || strings.Contains(bulk, "ORDER BY") {
		t.Error("the membership query constants must end at the WHERE clause; " +
			"the ORDER BY belongs in userMembershipOrderBy/userMembershipBulkOrderBy " +
			"so a tenant predicate can be appended to the predicate, not to the sort")
	}
	if whitespace(userMembershipOrderBy) != "ORDER BY om.created_at DESC" {
		t.Errorf("single-user ordering changed: %s", userMembershipOrderBy)
	}
	if whitespace(userMembershipBulkOrderBy) != "ORDER BY om.user_id, om.created_at DESC" {
		t.Errorf("bulk ordering changed: %s", userMembershipBulkOrderBy)
	}
}

// TestOrgMemberQueriesShareOneProjection is the same structural guarantee for
// the org-member-with-user shape.
func TestOrgMemberQueriesShareOneProjection(t *testing.T) {
	one := whitespace(orgMemberByOrgAndUserQuery)
	list := whitespace(orgMembersByOrgQuery)

	for name, q := range map[string]string{"single": one, "list": list} {
		if !strings.Contains(q, whitespace(orgMemberWithUserColumns)) {
			t.Errorf("%s query does not contain the shared projection:\n%s", name, q)
		}
		if !strings.Contains(q, whitespace(orgMemberWithUserFrom)) {
			t.Errorf("%s query does not use the shared FROM/JOIN chain:\n%s", name, q)
		}
	}
	if !strings.HasSuffix(one, "WHERE om.organization_id = $1 AND om.user_id = $2") {
		t.Errorf("single-member predicate changed: %s", one)
	}
	if !strings.HasSuffix(list, "WHERE om.organization_id = $1") {
		t.Errorf("list predicate changed: %s", list)
	}
	if strings.Contains(list, "ORDER BY") {
		t.Error("orgMembersByOrgQuery must end at the WHERE clause so the tenant " +
			"predicate lands on the predicate; the sort lives in orgMembersByOrgOrderBy")
	}
	if whitespace(orgMembersByOrgOrderBy) != "ORDER BY om.created_at DESC" {
		t.Errorf("list ordering changed: %s", orgMembersByOrgOrderBy)
	}
}

// TestGetUserWithOrgRolesAndGetUserMembershipsIssueIdenticalSQL pins the fact
// the audit called out: UserRepository.GetUserWithOrgRoles and
// OrganizationRepository.GetUserMemberships are the same read on two different
// repository types. They now share one constant; this asserts they still issue
// the same SQL, so the two can never drift apart again.
func TestGetUserWithOrgRolesAndGetUserMembershipsIssueIdenticalSQL(t *testing.T) {
	// Each method must issue exactly userMembershipByUserQuery: the expectation
	// below is the whitespace-normalized constant, quoted so sqlmock's regexp
	// matcher compares it literally rather than as a loose pattern.
	db1, mock1, _ := sqlmock.New()
	defer db1.Close()
	mock1.ExpectQuery(`SELECT id, email, name, oidc_sub`).
		WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
			AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()))
	mock1.ExpectQuery(regexp.QuoteMeta(whitespace(userMembershipByUserQuery))).
		WithArgs("u1").
		WillReturnRows(sqlmock.NewRows(userMembershipCols))
	if _, err := NewUserRepository(db1).GetUserWithOrgRoles(context.Background(), "u1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("GetUserWithOrgRoles: %v", err)
	}
	if err := mock1.ExpectationsWereMet(); err != nil {
		t.Errorf("GetUserWithOrgRoles did not issue userMembershipByUserQuery: %v", err)
	}

	db2, mock2, _ := sqlmock.New()
	defer db2.Close()
	mock2.ExpectQuery(regexp.QuoteMeta(whitespace(userMembershipByUserQuery))).
		WithArgs("u1").
		WillReturnRows(sqlmock.NewRows(userMembershipCols))
	if _, err := NewOrganizationRepository(db2).GetUserMemberships(context.Background(), "u1"); err != nil {
		t.Fatalf("GetUserMemberships: %v", err)
	}
	if err := mock2.ExpectationsWereMet(); err != nil {
		t.Errorf("GetUserMemberships did not issue userMembershipByUserQuery: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error-wording regression guards (the "zero behaviour change" contract)
// ---------------------------------------------------------------------------

// TestMembershipScanErrorWording pins the exact scan-failure message each of the
// five collapsed call sites produces. The two org-member call sites deliberately
// disagree ("failed to get member" vs "failed to scan member"); that difference
// predates the refactor and is preserved on purpose, which is why
// scanOrgMemberWithUser returns its Scan error unwrapped.
func TestMembershipScanErrorWording(t *testing.T) {
	// A row whose created_at column holds a non-time value forces rows.Scan to
	// fail on every one of these projections.
	tests := []struct {
		name string
		want string
		run  func(t *testing.T) error
	}{
		{
			name: "UserRepository.GetUserWithOrgRoles",
			want: "failed to scan membership: ",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`SELECT id, email, name, oidc_sub`).
					WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
						AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()))
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipCols).
						AddRow("org-1", "Org", nil, "not-a-time", nil, nil, []byte(`[]`)))
				_, err := NewUserRepository(db).GetUserWithOrgRoles(context.Background(), "u1", OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "UserRepository.loadMembershipsForUsers (via ListUsersWithMemberships)",
			want: "failed to scan membership: ",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT id, email, name, oidc_sub`).
					WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
						AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()))
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipBulkCols).
						AddRow("u1", "org-1", "Org", nil, "not-a-time", nil, nil, []byte(`[]`)))
				_, _, err := NewUserRepository(db).ListUsersWithMemberships(context.Background(), 10, 0, OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "OrganizationRepository.GetUserMemberships",
			want: "failed to scan membership: ",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipCols).
						AddRow("org-1", "Org", nil, "not-a-time", nil, nil, []byte(`[]`)))
				_, err := NewOrganizationRepository(db).GetUserMemberships(context.Background(), "u1")
				return err
			},
		},
		{
			name: "OrganizationRepository.GetMemberWithRole",
			want: "failed to get member: ",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).
						AddRow("org-1", "u1", nil, "not-a-time", "A", "a@b.c", nil, nil, []byte(`[]`)))
				_, err := NewOrganizationRepository(db).GetMemberWithRole(context.Background(), "org-1", "u1", OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "OrganizationRepository.ListMembersWithUsers",
			want: "failed to scan member: ",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).
						AddRow("org-1", "u1", nil, "not-a-time", "A", "a@b.c", nil, nil, []byte(`[]`)))
				_, err := NewOrganizationRepository(db).ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil {
				t.Fatal("expected a scan error, got nil")
			}
			if !strings.HasPrefix(err.Error(), tc.want) {
				t.Errorf("error = %q, want prefix %q", err.Error(), tc.want)
			}
		})
	}
}

// TestMembershipScopesParseErrorWording pins the role_template_scopes decode
// failure message for every call site.
//
// GetMemberWithRole is the load-bearing case: its body wraps a Scan failure with
// "failed to get member", so folding the scopes decode into
// scanOrgMemberWithUser would have double-wrapped a parse failure into
// "failed to get member: failed to parse scopes: …". This test fails if that
// regression is ever introduced.
func TestMembershipScopesParseErrorWording(t *testing.T) {
	const want = "failed to parse scopes: "

	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "UserRepository.GetUserWithOrgRoles",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`SELECT id, email, name, oidc_sub`).
					WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
						AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()))
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipCols).
						AddRow("org-1", "Org", nil, time.Now(), nil, nil, badScopesJSON))
				_, err := NewUserRepository(db).GetUserWithOrgRoles(context.Background(), "u1", OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "UserRepository.loadMembershipsForUsers (via SearchWithMemberships)",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM users`).
					WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
						AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()))
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipBulkCols).
						AddRow("u1", "org-1", "Org", nil, time.Now(), nil, nil, badScopesJSON))
				_, err := NewUserRepository(db).SearchWithMemberships(context.Background(), "a", 10, 0, OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "OrganizationRepository.GetUserMemberships",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(userMembershipCols).
						AddRow("org-1", "Org", nil, time.Now(), nil, nil, badScopesJSON))
				_, err := NewOrganizationRepository(db).GetUserMemberships(context.Background(), "u1")
				return err
			},
		},
		{
			name: "OrganizationRepository.GetMemberWithRole (must NOT double-wrap)",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).
						AddRow("org-1", "u1", nil, time.Now(), "A", "a@b.c", nil, nil, badScopesJSON))
				_, err := NewOrganizationRepository(db).GetMemberWithRole(context.Background(), "org-1", "u1", OrgScopeAllOrganizations())
				return err
			},
		},
		{
			name: "OrganizationRepository.ListMembersWithUsers",
			run: func(t *testing.T) error {
				db, mock, _ := sqlmock.New()
				defer db.Close()
				mock.ExpectQuery(`FROM organization_members`).
					WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).
						AddRow("org-1", "u1", nil, time.Now(), "A", "a@b.c", nil, nil, badScopesJSON))
				_, err := NewOrganizationRepository(db).ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil {
				t.Fatal("expected a scopes parse error, got nil")
			}
			if !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error = %q, want prefix %q (no other wrapper may be prepended)", err.Error(), want)
			}
		})
	}
}

// TestGetMemberWithRoleNoRowsConvention pins that a missing membership is
// reported as ErrNotFound and NOT as a raw sql.ErrNoRows: the driver sentinel
// must stay inside this package. This is the reason scanOrgMemberWithUser
// returns its Scan error unwrapped, so it is asserted directly rather than left
// to the helper's doc comment.
func TestGetMemberWithRoleNoRowsConvention(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`FROM organization_members`).
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols))

	member, err := NewOrganizationRepository(db).GetMemberWithRole(context.Background(), "org-1", "u1", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing membership, got %v", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Errorf("sql.ErrNoRows escaped the repository boundary: %v", err)
	}
	if member != nil {
		t.Errorf("expected nil member for a missing membership, got %+v", member)
	}
}

// TestScanOrgMemberWithUserReturnsErrNoRowsUnwrapped is the unit-level statement
// of the same contract, so a change to the helper is caught even if no caller
// happens to exercise it.
func TestScanOrgMemberWithUserReturnsErrNoRowsUnwrapped(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols))

	row := db.QueryRowContext(context.Background(), "SELECT 1")
	_, _, err := scanOrgMemberWithUser(row)
	if err != sql.ErrNoRows { //nolint:errorlint // the point is that it is NOT wrapped
		t.Fatalf("scanOrgMemberWithUser must return sql.ErrNoRows unwrapped, got %v", err)
	}
}

// TestUnmarshalRoleTemplateScopesEmptyIsNotAnError pins the shared decoder's
// treatment of an absent value, which every call site relied on before the
// collapse.
func TestUnmarshalRoleTemplateScopesEmptyIsNotAnError(t *testing.T) {
	var dest []string
	if err := unmarshalRoleTemplateScopes(nil, &dest); err != nil {
		t.Errorf("nil scopes must not error, got %v", err)
	}
	if dest != nil {
		t.Errorf("nil scopes must leave dest nil, got %v", dest)
	}
	if err := unmarshalRoleTemplateScopes([]byte(`["a","b"]`), &dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dest) != 2 || dest[0] != "a" || dest[1] != "b" {
		t.Errorf("dest = %v, want [a b]", dest)
	}
}

// TestLoadMembershipsForUsersAttributesRowsToTheRightUser covers the one call
// site the audit noted had the thinnest coverage: the bulk path's extra leading
// om.user_id column is what attaches each row to its user, and it is the only
// use of scanUserMembership's variadic leading-destination parameter.
func TestLoadMembershipsForUsersAttributesRowsToTheRightUser(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(`SELECT id, email, name, oidc_sub`).
		WillReturnRows(sqlmock.NewRows(membershipTestUserCols).
			AddRow("u1", "a@b.c", "A", nil, time.Now(), time.Now()).
			AddRow("u2", "d@e.f", "D", nil, time.Now(), time.Now()))
	mock.ExpectQuery(`FROM organization_members`).
		WillReturnRows(sqlmock.NewRows(userMembershipBulkCols).
			AddRow("u1", "org-1", "One", nil, time.Now(), nil, nil, []byte(`["a"]`)).
			AddRow("u2", "org-2", "Two", nil, time.Now(), nil, nil, []byte(`["b"]`)).
			AddRow("u2", "org-3", "Three", nil, time.Now(), nil, nil, []byte(`["c"]`)).
			// A row for a user that is not in the page is dropped, not misfiled.
			AddRow("u9", "org-9", "Nine", nil, time.Now(), nil, nil, []byte(`["z"]`)))

	got, total, err := NewUserRepository(db).ListUsersWithMemberships(context.Background(), 10, 0, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(got) != 2 {
		t.Fatalf("len(users) = %d, want 2", len(got))
	}
	if len(got[0].Memberships) != 1 || got[0].Memberships[0].OrganizationName != "One" {
		t.Errorf("u1 memberships = %+v, want exactly org One", got[0].Memberships)
	}
	if len(got[1].Memberships) != 2 {
		t.Fatalf("u2 memberships = %d, want 2", len(got[1].Memberships))
	}
	if got[1].Memberships[0].OrganizationName != "Two" || got[1].Memberships[1].OrganizationName != "Three" {
		t.Errorf("u2 memberships out of order: %+v", got[1].Memberships)
	}
	if len(got[0].Memberships[0].RoleTemplateScopes) != 1 || got[0].Memberships[0].RoleTemplateScopes[0] != "a" {
		t.Errorf("u1 scopes = %v, want [a]", got[0].Memberships[0].RoleTemplateScopes)
	}
}
