package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// CLASS TEST for the missing-tenant-scope class on ORGANIZATION-OWNED accessors
// (issues #138, #160, #161, #162; terraform-registry #718/#719 upstream).
//
// The class is (organization-owned resource) x (access axis). v0.21.0 closed it
// for audit_logs only — those three axes are the table in org_scope_class_test.go
// — and the fix did not fan out to api_keys, organizations,
// organization_members or users even though audit_scope.go's own package doc
// argued at length that the defect was a class rather than one query.
//
// This table is the remainder: one row per (accessor, axis), driven through
// FOUR scope cases each.
//
//	in-scope        a caller scoped to the owning organization SUCCEEDS
//	out-of-scope    a caller scoped elsewhere is DENIED
//	zero value      a caller that stated no tenancy is DENIED
//	all-orgs        the deliberate platform-wide reach still works
//
// Both directions are asserted on purpose. A denial-only table passes when a
// resolver returns the empty scope and denies EVERYONE, which is itself a bug
// and has shipped in this suite before; and a success-only table passes when the
// predicate was never applied at all.
//
// # Mechanism
//
// sqlmock's default matcher is regexp-based and runs against the
// whitespace-normalised SQL the repository actually issued. The in-scope and
// out-of-scope cases splice orgPredicateRe (or membershipPredicateRe, for the
// users table) into every expected statement, so the expectation only matches
// if the tenant predicate really reached the database. DELETE the scope
// application from any accessor below and its rows go red — that is the
// property the mutation gate needs.
//
// The out-of-scope case additionally primes the statement to return NOTHING,
// which is what PostgreSQL does when the predicate excludes the row, and then
// asserts the accessor reports that as a denial rather than as success. It is
// the pairing of the two that has teeth: the regex proves the filter was sent,
// and the empty result proves the accessor handles being filtered.
//
// Real cross-tenant data — rows that actually exist in another organization,
// filtered by a real PostgreSQL — is covered by TestIntegrationOrgScope* in
// org_scope_integration_test.go. A mock cannot prove a WHERE clause excludes a
// row; it can only prove the WHERE clause was sent. Both halves are required.

// orgOwnerIDPredicateRe matches the predicate a CREATE axis emits: the INSERT
// sources from a scoped SELECT over organizations, so the constrained column is
// the aliased organizations key.
const orgOwnerIDPredicateRe = `.*o\.id = ANY\(\$\d+\).*`

// orgSelfIDPredicateRe matches the predicate the organizations table itself
// emits. There the row IS the tenant, so the predicate constrains the primary
// key rather than a foreign key.
const orgSelfIDPredicateRe = `.*\bid = ANY\(\$\d+\).*`

// membershipSubqueryPredicateRe matches the predicate the membership-bearing
// half of a users accessor emits: it selects organization_members directly, so
// it filters on om.organization_id rather than through an EXISTS.
const membershipSubqueryPredicateRe = `.*om\.organization_id = ANY\(\$\d+\).*`

// membershipPredicateRe matches the tenant predicate a scoped USERS-table
// accessor must emit. users carries no organization_id, so its predicate is an
// EXISTS over organization_members (see OrgScope.membershipSQL).
const membershipPredicateRe = `.*EXISTS \(SELECT 1 FROM organization_members osm WHERE osm\.user_id = .*osm\.organization_id = ANY\(\$\d+\)\).*`

// orgScopedAxis names one (accessor, access axis) cell of the matrix and how to
// drive it.
type orgScopedAxis struct {
	// name is the STABLE SITE IDENTITY (Receiver.Method) and is what the
	// completeness guard below matches against the package's exported surface.
	name string
	// table and axis place the cell in the matrix; they exist so a gap is
	// visible as a missing (table, axis) pair rather than as an absent test.
	table string
	axis  string
	// guard is the named GUARD comment whose removal must make this row fail.
	guard string
	// predicateRe is the tenant predicate this accessor must emit;
	// orgPredicateRe for an organization-owned table, membershipPredicateRe for
	// users.
	predicateRe string
	// prime installs expectations for one call, splicing extra into every
	// statement pattern. hit selects whether the primed statement yields a
	// matching row (the in-scope case) or none (the out-of-scope case).
	prime func(m sqlmock.Sqlmock, extra string, hit bool)
	// call drives the accessor.
	call func(r *classRepos, scope OrgScope) error
	// denied is the error a filtered-out target must produce. nil means the
	// accessor reports emptiness IN BAND — an empty slice or a zero count —
	// which is the correct shape for a list axis and never for a by-id one.
	denied error
	// zeroScopeSQL is the statement pattern expected under the fail-closed zero
	// scope, or "" when the accessor must not touch the database at all.
	zeroScopeSQL string
}

func orgScopedAxes() []orgScopedAxis {
	ctx := context.Background()

	// Row/result builders shared by several cells.
	execHit := func(m sqlmock.Sqlmock, pattern string, hit bool) {
		n := int64(0)
		if hit {
			n = 1
		}
		m.ExpectExec(pattern).WillReturnResult(sqlmock.NewResult(0, n))
	}
	rowsOrEmpty := func(hit bool, cols []string, add func(*sqlmock.Rows) *sqlmock.Rows) *sqlmock.Rows {
		r := sqlmock.NewRows(cols)
		if hit {
			r = add(r)
		}
		return r
	}

	return []orgScopedAxis{
		// -------------------------------------------------------------- api_keys
		{
			name: "APIKeyRepository.CreateAPIKey", table: "api_keys", axis: "create",
			guard: "org-scope-apikey-create", predicateRe: orgOwnerIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `INSERT INTO api_keys.*FROM organizations o.*WHERE o\.id = \$3`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.keys.CreateAPIKey(ctx, sampleAPIKeyModel(), s)
			},
			denied: ErrNotFound,
		},
		{
			name: "APIKeyRepository.GetAPIKeyByID", table: "api_keys", axis: "by-id",
			guard: "org-scope-apikey-byid", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM api_keys.*WHERE id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, apiKeyCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleAPIKeyRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.GetAPIKeyByID(ctx, "key-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "APIKeyRepository.Update", table: "api_keys", axis: "update",
			guard: "org-scope-apikey-update", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `UPDATE api_keys SET.*WHERE id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.keys.Update(ctx, sampleAPIKeyModel(), s)
			},
			denied: ErrNotFound,
		},
		{
			name: "APIKeyRepository.RevokeAPIKey", table: "api_keys", axis: "delete",
			guard: "org-scope-apikey-delete", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `DELETE FROM api_keys WHERE id = \$1`+extra, hit)
			},
			call:   func(r *classRepos, s OrgScope) error { return r.keys.RevokeAPIKey(ctx, "key-1", s) },
			denied: ErrNotFound,
		},
		{
			name: "APIKeyRepository.RevokeAPIKeysForUser", table: "api_keys", axis: "delete",
			guard: "org-scope-apikey-sweep", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `DELETE FROM api_keys WHERE user_id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.RevokeAPIKeysForUser(ctx, "user-1", s)
				return err
			},
		},
		{
			name: "APIKeyRepository.ListAPIKeys", table: "api_keys", axis: "list",
			guard: "org-scope-apikey-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT ak\.id.*FROM api_keys ak` + extra).
					WillReturnRows(rowsOrEmpty(hit, apiKeyListCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleAPIKeyListRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.ListAPIKeys(ctx, s)
				return err
			},
		},
		{
			name: "APIKeyRepository.ListAPIKeysByUser", table: "api_keys", axis: "list",
			guard: "org-scope-apikey-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT ak\.id.*FROM api_keys ak.*WHERE ak\.user_id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, apiKeyListCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleAPIKeyListRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.ListAPIKeysByUser(ctx, "user-1", s)
				return err
			},
		},
		{
			name: "APIKeyRepository.ListAPIKeysByOrganization", table: "api_keys", axis: "list",
			guard: "org-scope-apikey-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT ak\.id.*FROM api_keys ak.*WHERE ak\.organization_id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, apiKeyListCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleAPIKeyListRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.ListAPIKeysByOrganization(ctx, "org-1", s)
				return err
			},
		},
		{
			name: "APIKeyRepository.ListByUserAndOrganization", table: "api_keys", axis: "list",
			guard: "org-scope-apikey-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT ak\.id.*FROM api_keys ak.*WHERE ak\.user_id = \$1 AND ak\.organization_id = \$2` + extra).
					WillReturnRows(rowsOrEmpty(hit, apiKeyListCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleAPIKeyListRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.keys.ListByUserAndOrganization(ctx, "user-1", "org-1", s)
				return err
			},
		},

		// --------------------------------------------------------- organizations
		{
			name: "OrganizationRepository.GetByID", table: "organizations", axis: "by-id",
			guard: "org-scope-organization-byid", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM organizations.*WHERE id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.GetByID(ctx, "org-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.GetByName", table: "organizations", axis: "by-id",
			guard: "org-scope-organization-byid", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM organizations.*WHERE name = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.GetByName(ctx, "default", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.Update", table: "organizations", axis: "update",
			guard: "org-scope-organization-update", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `UPDATE organizations SET.*WHERE id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.Update(ctx, &models.Organization{ID: "org-1"}, s)
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.Rename", table: "organizations", axis: "update",
			guard: "org-scope-organization-update", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `UPDATE organizations SET name = \$1.*WHERE id = \$2`+extra, hit)
			},
			call:   func(r *classRepos, s OrgScope) error { return r.orgs.Rename(ctx, "org-1", "new", s) },
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.Delete", table: "organizations", axis: "delete",
			guard: "org-scope-organization-delete", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `DELETE FROM organizations WHERE id = \$1`+extra, hit)
			},
			call:   func(r *classRepos, s OrgScope) error { return r.orgs.Delete(ctx, "org-1", s) },
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.List", table: "organizations", axis: "list",
			guard: "org-scope-organization-list", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM organizations` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.List(ctx, 10, 0, s)
				return err
			},
		},
		{
			name: "OrganizationRepository.Search", table: "organizations", axis: "list",
			guard: "org-scope-organization-list", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM organizations.*WHERE \(name ILIKE \$1 OR display_name ILIKE \$1\)` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.Search(ctx, "q", 10, 0, s)
				return err
			},
		},
		{
			name: "OrganizationRepository.Count", table: "organizations", axis: "list",
			guard: "org-scope-organization-list", predicateRe: orgSelfIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				n := 0
				if hit {
					n = 1
				}
				m.ExpectQuery(`SELECT COUNT\(\*\) FROM organizations` + extra).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(n))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.Count(ctx, s)
				return err
			},
		},

		// -------------------------------------------------- organization_members
		{
			name: "OrganizationRepository.AddMemberWithRoleTemplate", table: "organization_members", axis: "create",
			guard: "org-scope-membership-create", predicateRe: orgOwnerIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `INSERT INTO organization_members.*FROM organizations o.*WHERE o\.id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.AddMemberWithRoleTemplate(ctx, "org-1", "user-1", nil, s)
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.UpdateMemberRoleTemplate", table: "organization_members", axis: "update",
			guard: "org-scope-membership-update", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `UPDATE organization_members SET.*WHERE organization_id = \$1 AND user_id = \$2`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.UpdateMemberRoleTemplate(ctx, "org-1", "user-1", nil, s)
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.RemoveMember", table: "organization_members", axis: "delete",
			guard: "org-scope-membership-delete", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `DELETE FROM organization_members WHERE organization_id = \$1 AND user_id = \$2`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.RemoveMember(ctx, "org-1", "user-1", s)
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.RemoveAllMembershipsForUser", table: "organization_members", axis: "delete",
			guard: "org-scope-membership-sweep", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`DELETE FROM organization_members WHERE user_id = \$1` + extra + `.*RETURNING organization_id`).
					WillReturnRows(rowsOrEmpty(hit, []string{"organization_id"}, func(r *sqlmock.Rows) *sqlmock.Rows { return r.AddRow("org-1") }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.RemoveAllMembershipsForUser(ctx, "user-1", s)
				return err
			},
		},
		{
			name: "OrganizationRepository.GetMember", table: "organization_members", axis: "by-id",
			guard: "org-scope-membership-byid", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT organization_id.*FROM organization_members.*WHERE organization_id = \$1 AND user_id = \$2` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgMemberCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgMemberRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.GetMember(ctx, "org-1", "user-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.GetMemberWithRole", table: "organization_members", axis: "by-id",
			guard: "org-scope-membership-byid", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT om\.organization_id.*FROM organization_members om.*WHERE om\.organization_id = \$1 AND om\.user_id = \$2` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgMembersWithUserCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("org-1", "user-1", nil, nowValue(), "n", "e", nil, nil, []byte(`[]`))
					}))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.GetMemberWithRole(ctx, "org-1", "user-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "OrganizationRepository.CheckMembership", table: "organization_members", axis: "by-id",
			guard: "org-scope-membership-byid", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT organization_id.*FROM organization_members.*WHERE organization_id = \$1 AND user_id = \$2` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgMemberCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgMemberRow() }))
			},
			// CheckMembership absorbs ErrNotFound into its boolean by design (see
			// its doc), so the denial it must produce is `false`, checked by
			// TestOrgScopedAxes_CheckMembershipDeniesOutOfScope below rather than
			// by this table's error comparison.
			call: func(r *classRepos, s OrgScope) error {
				_, _, err := r.orgs.CheckMembership(ctx, "org-1", "user-1", s)
				return err
			},
		},
		{
			name: "OrganizationRepository.ListMembers", table: "organization_members", axis: "list",
			guard: "org-scope-membership-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT organization_id.*FROM organization_members.*WHERE organization_id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgMemberCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgMemberRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.ListMembers(ctx, "org-1", s)
				return err
			},
		},
		{
			name: "OrganizationRepository.ListMembersWithUsers", table: "organization_members", axis: "list",
			guard: "org-scope-membership-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT om\.organization_id.*FROM organization_members om.*WHERE om\.organization_id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgMembersWithUserCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("org-1", "user-1", nil, nowValue(), "n", "e", nil, nil, []byte(`[]`))
					}))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.ListMembersWithUsers(ctx, "org-1", s)
				return err
			},
		},
		{
			name: "OrganizationRepository.GetUserOrganizations", table: "organization_members", axis: "list",
			guard: "org-scope-membership-list", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT o\.id.*FROM organizations o.*JOIN organization_members om.*WHERE om\.user_id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, orgCols, func(*sqlmock.Rows) *sqlmock.Rows { return sampleOrgRow() }))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.orgs.GetUserOrganizations(ctx, "user-1", s)
				return err
			},
		},

		{
			name: "OrganizationRepository.AddMemberWithParams", table: "organization_members", axis: "create",
			guard: "org-scope-membership-create", predicateRe: orgOwnerIDPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id FROM role_templates WHERE name = \$1`).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))
				execHit(m, `INSERT INTO organization_members.*FROM organizations o.*WHERE o\.id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.AddMemberWithParams(ctx, "org-1", "user-1", "viewer", s)
			},
			denied: ErrNotFound,
			// The by-name wrappers resolve the role template BEFORE delegating, so
			// under the zero scope they still issue that one lookup. The delegate
			// then short-circuits; no organization_members statement is emitted.
			zeroScopeSQL: `SELECT id FROM role_templates WHERE name = \$1`,
		},
		{
			name: "OrganizationRepository.UpdateMemberRole", table: "organization_members", axis: "update",
			guard: "org-scope-membership-update", predicateRe: orgPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id FROM role_templates WHERE name = \$1`).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))
				execHit(m, `UPDATE organization_members SET.*WHERE organization_id = \$1 AND user_id = \$2`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.orgs.UpdateMemberRole(ctx, "org-1", "user-1", "viewer", s)
			},
			denied:       ErrNotFound,
			zeroScopeSQL: `SELECT id FROM role_templates WHERE name = \$1`,
		},

		// ----------------------------------------------------------------- users
		{
			name: "UserRepository.GetUserByID", table: "users", axis: "by-id",
			guard: "org-scope-user-byid", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM users.*WHERE id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.users.GetUserByID(ctx, "user-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "UserRepository.UpdateUser", table: "users", axis: "update",
			guard: "org-scope-user-update", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `UPDATE users SET.*WHERE id = \$1`+extra, hit)
			},
			call: func(r *classRepos, s OrgScope) error {
				return r.users.UpdateUser(ctx, &models.User{ID: "user-1"}, s)
			},
			denied: ErrNotFound,
		},
		{
			name: "UserRepository.DeleteUser", table: "users", axis: "delete",
			guard: "org-scope-user-delete", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				execHit(m, `DELETE FROM users WHERE id = \$1`+extra, hit)
			},
			call:   func(r *classRepos, s OrgScope) error { return r.users.DeleteUser(ctx, "user-1", s) },
			denied: ErrNotFound,
		},
		{
			name: "UserRepository.ListUsers", table: "users", axis: "list",
			guard: "org-scope-user-list", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				n := 0
				if hit {
					n = 1
				}
				m.ExpectQuery(`SELECT COUNT\(\*\) FROM users` + extra).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(n))
				m.ExpectQuery(`SELECT id.*FROM users` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, _, err := r.users.ListUsers(ctx, 10, 0, s)
				return err
			},
		},
		{
			name: "UserRepository.Count", table: "users", axis: "list",
			guard: "org-scope-user-list", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				n := 0
				if hit {
					n = 1
				}
				m.ExpectQuery(`SELECT COUNT\(\*\) FROM users` + extra).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(n))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.users.Count(ctx, s)
				return err
			},
		},
		{
			name: "UserRepository.Search", table: "users", axis: "list",
			guard: "org-scope-user-list", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM users.*WHERE \(email ILIKE \$1 OR name ILIKE \$1\)` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.users.Search(ctx, "q", 10, 0, s)
				return err
			},
		},
		{
			name: "UserRepository.GetUserWithOrgRoles", table: "users", axis: "by-id",
			guard: "org-scope-user-byid", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM users.*WHERE id = \$1` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
				if hit {
					// The membership half carries the ORG predicate, not the
					// membership-EXISTS one: it selects organization_members
					// directly, so it filters on om.organization_id.
					m.ExpectQuery(`SELECT om\.organization_id.*WHERE om\.user_id = \$1` + membershipHalf(extra)).
						WillReturnRows(sqlmock.NewRows(userMembershipCols))
				}
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.users.GetUserWithOrgRoles(ctx, "user-1", s)
				return err
			},
			denied: ErrNotFound,
		},
		{
			name: "UserRepository.ListUsersWithMemberships", table: "users", axis: "list",
			guard: "org-scope-user-list", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				n := 0
				if hit {
					n = 1
				}
				m.ExpectQuery(`SELECT COUNT\(\*\) FROM users` + extra).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(n))
				m.ExpectQuery(`SELECT id.*FROM users` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
				if hit {
					m.ExpectQuery(`SELECT om\.user_id.*WHERE om\.user_id = ANY\(\$1\)` + membershipHalf(extra)).
						WillReturnRows(sqlmock.NewRows(userMembershipBulkCols))
				}
			},
			call: func(r *classRepos, s OrgScope) error {
				_, _, err := r.users.ListUsersWithMemberships(ctx, 10, 0, s)
				return err
			},
		},
		{
			name: "UserRepository.SearchWithMemberships", table: "users", axis: "list",
			guard: "org-scope-user-list", predicateRe: membershipPredicateRe,
			prime: func(m sqlmock.Sqlmock, extra string, hit bool) {
				m.ExpectQuery(`SELECT id.*FROM users.*WHERE \(email ILIKE \$1 OR name ILIKE \$1\)` + extra).
					WillReturnRows(rowsOrEmpty(hit, userCols, func(r *sqlmock.Rows) *sqlmock.Rows {
						return r.AddRow("user-1", "u@example.com", "U", nil, nowValue(), nowValue())
					}))
				if hit {
					m.ExpectQuery(`SELECT om\.user_id.*WHERE om\.user_id = ANY\(\$1\)` + membershipHalf(extra)).
						WillReturnRows(sqlmock.NewRows(userMembershipBulkCols))
				}
			},
			call: func(r *classRepos, s OrgScope) error {
				_, err := r.users.SearchWithMemberships(ctx, "q", 10, 0, s)
				return err
			},
		},
	}
}

// TestOrgScopedAxes_InScopeSucceeds is the POSITIVE direction. A caller scoped
// to the owning organization must reach the row, and the statement it issued
// must carry the tenant predicate.
//
// This half exists because a denial-only table is satisfied by an accessor that
// denies everyone — the failure mode a fail-closed default makes easy to ship
// and impossible to notice, since nothing errors, things merely disappear.
func TestOrgScopedAxes_InScopeSucceeds(t *testing.T) {
	for _, axis := range orgScopedAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.prime(mock, axis.predicateRe, true)

			if err := axis.call(repos, OrgScopeOrganizations("org-1")); err != nil {
				t.Fatalf("%s [%s/%s]: a caller scoped to the OWNING organization was "+
					"refused, or the statement did not carry the tenant predicate "+
					"(guard %q removed?): %v", axis.name, axis.table, axis.axis, axis.guard, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestOrgScopedAxes_OutOfScopeIsDenied is the NEGATIVE direction. A caller
// scoped to a DIFFERENT organization issues the same statement — still carrying
// the tenant predicate — and the database returns nothing, which the accessor
// must report as a miss rather than as a success.
//
// The two assertions are inseparable. The regex proves the filter was sent (an
// accessor that dropped the predicate fails to match the expectation); the empty
// result proves the accessor does not report a filtered-out mutation as done,
// which is the fail-open half that store.ErrNotFound and requireRow closed in
// v0.24.0 and that this predicate depends on.
func TestOrgScopedAxes_OutOfScopeIsDenied(t *testing.T) {
	for _, axis := range orgScopedAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.prime(mock, axis.predicateRe, false)

			err := axis.call(repos, OrgScopeOrganizations("org-other"))
			if axis.denied != nil {
				if !errors.Is(err, axis.denied) {
					t.Fatalf("%s [%s/%s]: a caller scoped to another organization got "+
						"err=%v, want %v — a by-identifier accessor whose predicate "+
						"excluded the row must say so (guard %q removed?)",
						axis.name, axis.table, axis.axis, err, axis.denied, axis.guard)
				}
			} else if err != nil {
				t.Fatalf("%s [%s/%s]: a caller scoped to another organization got "+
					"err=%v, want an empty in-band result (guard %q removed?)",
					axis.name, axis.table, axis.axis, err, axis.guard)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestOrgScopedAxes_ZeroScopeFailsClosed pins the fail-closed default: an
// accessor called without a tenancy decision reaches nothing, never everything.
//
// Nothing is primed beyond zeroScopeSQL, so an accessor that issued an
// unconstrained statement surfaces it as an unexpected query.
func TestOrgScopedAxes_ZeroScopeFailsClosed(t *testing.T) {
	for _, axis := range orgScopedAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			if axis.zeroScopeSQL != "" {
				mock.ExpectQuery(axis.zeroScopeSQL).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))
			}

			err := axis.call(repos, OrgScope{})
			if axis.denied != nil {
				if !errors.Is(err, axis.denied) {
					t.Fatalf("%s [%s/%s]: the ZERO-VALUE scope returned err=%v, want %v — "+
						"a caller that stated no tenancy must reach nothing",
						axis.name, axis.table, axis.axis, err, axis.denied)
				}
			} else if err != nil {
				t.Fatalf("%s [%s/%s]: the ZERO-VALUE scope issued an unconstrained "+
					"statement: %v", axis.name, axis.table, axis.axis, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestOrgScopedAxes_AllOrganizationsIsExplicit documents the single legitimate
// cross-tenant reach: it must be spelled out, and it is the only way to get a
// statement whose tenant predicate constrains nothing.
func TestOrgScopedAxes_AllOrganizationsIsExplicit(t *testing.T) {
	for _, axis := range orgScopedAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.prime(mock, ".*TRUE.*", true)
			if err := axis.call(repos, OrgScopeAllOrganizations()); err != nil {
				t.Fatalf("%s: platform-wide scope: %v", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestOrgScopedAxes_CheckMembershipDeniesOutOfScope covers the one cell whose
// denial is not an error. CheckMembership absorbs ErrNotFound into its boolean
// by design, so "outside your scope" has to arrive as false — the same answer as
// "not a member" — or the predicate becomes a cross-tenant membership oracle.
func TestOrgScopedAxes_CheckMembershipDeniesOutOfScope(t *testing.T) {
	repos, mock := newClassRepos(t)
	mock.ExpectQuery(`SELECT organization_id.*FROM organization_members.*WHERE organization_id = \$1 AND user_id = \$2` + orgPredicateRe).
		WillReturnRows(sqlmock.NewRows(orgMemberCols))

	ok, role, err := repos.orgs.CheckMembership(context.Background(), "org-1", "user-1", OrgScopeOrganizations("org-other"))
	if err != nil {
		t.Fatalf("CheckMembership: %v", err)
	}
	if ok || role != nil {
		t.Errorf("CheckMembership out of scope = (%v, %v), want (false, nil)", ok, role)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("%v", err)
	}
}

// ---------------------------------------------------------------------------
// Completeness: the matrix must cover every scoped accessor in the package
// ---------------------------------------------------------------------------

// TestOrgScopeMatrixIsComplete is the structural guard. It enumerates, by
// reflection, every exported method on the four repositories that TAKES an
// OrgScope, and requires each one to appear in a class table.
//
// This is what stops the class from reopening the way it did after v0.21.0. A
// new access axis over an organization-owned table cannot be added silently:
// either it takes an OrgScope and must appear here, or it does not take one and
// the reviewer has to justify that in the accessor's doc — which is a visible,
// greppable decision rather than an omission.
func TestOrgScopeMatrixIsComplete(t *testing.T) {
	covered := map[string]bool{}
	for _, a := range orgScopedAxes() {
		covered[a.name] = true
	}
	// The audit_logs rows of the same matrix live in org_scope_class_test.go;
	// they are the cells v0.21.0 already closed.
	for _, a := range auditReadAxes() {
		covered[strings.TrimPrefix(a.name, "store.")] = true
	}

	scopeType := reflect.TypeOf(OrgScope{})
	var missing []string
	for _, repo := range []interface{}{
		&APIKeyRepository{}, &OrganizationRepository{}, &UserRepository{}, &AuditRepository{},
	} {
		rt := reflect.TypeOf(repo)
		recv := strings.TrimPrefix(rt.String(), "*store.")
		for i := 0; i < rt.NumMethod(); i++ {
			m := rt.Method(i)
			takesScope := false
			for j := 1; j < m.Type.NumIn(); j++ {
				if m.Type.In(j) == scopeType {
					takesScope = true
					break
				}
			}
			// OrgScopeForUser PRODUCES a scope rather than consuming one; it is
			// the resolver, covered by TestOrgScopeForUser* below.
			if !takesScope || m.Name == "OrgScopeForUser" {
				continue
			}
			if !covered[recv+"."+m.Name] {
				missing = append(missing, recv+"."+m.Name)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these accessors take an OrgScope but have no row in the class "+
			"matrix, so nothing proves their predicate reaches the SQL: %v\n"+
			"Add a row to orgScopedAxes() (or auditReadAxes()) for each.", missing)
	}
}

// nowValue is a stable timestamp for mock rows.
func nowValue() time.Time { return time.Unix(1700000000, 0).UTC() }

// sampleAPIKeyModel is the struct the create/update axes pass in.
func sampleAPIKeyModel() *models.APIKey {
	return &models.APIKey{ID: "key-1", OrganizationID: "org-1", Name: "CI Key", Scopes: []string{"modules:read"}}
}

// membershipHalf returns the predicate the membership-bearing statement of a
// users accessor must carry, given the predicate spliced into its users
// statement. The two halves filter DIFFERENT columns — the users half through an
// EXISTS, the membership half on om.organization_id directly — so a single regex
// cannot serve both, and asserting only one of them is how half a fix ships.
func membershipHalf(extra string) string {
	if extra == membershipPredicateRe {
		return membershipSubqueryPredicateRe
	}
	return extra
}
