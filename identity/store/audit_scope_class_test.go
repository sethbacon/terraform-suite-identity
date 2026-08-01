package store

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// CLASS TEST for the cross-tenant audit-log read class (terraform-registry
// #718/#719).
//
// The class is (organization-owned resource) x (access axis). audit_logs has
// THREE read axes in this package -- list, by-id, export-stream -- and the
// defect was that only the list axis ever learned about tenancy. So the table
// below has one row PER AXIS and each axis is driven through the same three
// scope cases. Adding a fourth read axis without adding it here shows up as a
// missing row rather than as a silently absent test.
//
// Mechanism: sqlmock's default query matcher is regexp-based and runs against
// the whitespace-normalised SQL the repository actually issued. Expectations in
// the scoped case therefore REQUIRE the organization predicate to be present in
// the statement -- delete the guard in audit_repository.go and the statement no
// longer matches, so the row fails. That is the property a mutation gate needs.
//
// Contrast with a test that only calls ListAuditLogs: it passes forever while
// GetAuditLog and StreamAuditLogs return every tenant's rows. That is exactly
// what happened when #719 was closed the first time.

// orgPredicateRe matches the tenant predicate every scoped audit read must emit.
const orgPredicateRe = `.*organization_id = ANY\(\$\d+\).*`

// auditReadAxis names one audit-log READ access axis and how to drive it.
// name is the STABLE SITE IDENTITY (package.Symbol); guard is the named guard
// whose removal must make the scoped row fail.
type auditReadAxis struct {
	name  string
	guard string
	// prime installs the mock expectations for one successful call, splicing
	// `extra` into every statement pattern the axis is expected to issue.
	prime func(mock sqlmock.Sqlmock, extra string)
	// zeroScopeSQL is the statement pattern expected under the fail-closed zero
	// scope, or "" when the axis must not touch the database at all.
	zeroScopeSQL string
	call         func(repo *AuditRepository, scope AuditScope) error
}

func auditReadAxes() []auditReadAxis {
	return []auditReadAxis{
		{
			name:  "store.AuditRepository.ListAuditLogs",
			guard: "audit-scope-list",
			prime: func(mock sqlmock.Sqlmock, extra string) {
				mock.ExpectQuery(`SELECT COUNT.*FROM audit_logs` + extra).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery(`SELECT al\.id.*FROM audit_logs` + extra).
					WillReturnRows(sampleAuditRow())
			},
			zeroScopeSQL: "",
			call: func(repo *AuditRepository, scope AuditScope) error {
				_, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, scope, 10, 0)
				return err
			},
		},
		{
			name:  "store.AuditRepository.GetAuditLog",
			guard: "audit-scope-byid",
			prime: func(mock sqlmock.Sqlmock, extra string) {
				mock.ExpectQuery(`SELECT id.*FROM audit_logs.*WHERE id = \$1` + extra).
					WillReturnRows(sampleAuditGetRow())
			},
			zeroScopeSQL: "",
			call: func(repo *AuditRepository, scope AuditScope) error {
				_, err := repo.GetAuditLog(context.Background(), "log-1", scope)
				return err
			},
		},
		{
			name:  "store.AuditRepository.StreamAuditLogs",
			guard: "audit-scope-export",
			prime: func(mock sqlmock.Sqlmock, extra string) {
				mock.ExpectQuery(`SELECT al\.id.*FROM audit_logs.*created_at >= \$1` + extra).
					WillReturnRows(sampleAuditRow())
			},
			// The export axis streams rows, so it cannot short-circuit into an
			// empty result set the way the other two do; it emits an unsatisfiable
			// predicate instead. Either way no tenant's rows come back.
			zeroScopeSQL: `SELECT al\.id.*FROM audit_logs.*AND FALSE`,
			call: func(repo *AuditRepository, scope AuditScope) error {
				rows, err := repo.StreamAuditLogs(context.Background(),
					time.Now().Add(-time.Hour), time.Now(), scope)
				if rows != nil {
					_ = rows.Close()
				}
				return err
			},
		},
	}
}

// TestAuditReadAxes_ScopedReadCarriesTenantPredicate is the class test proper:
// EVERY audit-log read axis, given a single-organization scope, must put the
// organization predicate into the SQL it issues.
func TestAuditReadAxes_ScopedReadCarriesTenantPredicate(t *testing.T) {
	for _, axis := range auditReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newAuditRepo(t)
			axis.prime(mock, orgPredicateRe)

			if err := axis.call(repo, AuditScopeOrganizations("org-1")); err != nil {
				t.Fatalf("%s: statement did not carry the organization predicate "+
					"(guard %q removed?): %v", axis.name, axis.guard, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestAuditReadAxes_ZeroScopeFailsClosed pins the fail-closed default: an
// accessor called without a tenancy decision returns nothing, never everything.
func TestAuditReadAxes_ZeroScopeFailsClosed(t *testing.T) {
	for _, axis := range auditReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newAuditRepo(t)
			if axis.zeroScopeSQL != "" {
				mock.ExpectQuery(axis.zeroScopeSQL).WillReturnRows(sqlmock.NewRows(auditCols))
			}
			// Nothing else is primed. An unconstrained statement is therefore an
			// unexpected query and surfaces as an error.
			if err := axis.call(repo, AuditScope{}); err != nil {
				t.Fatalf("%s: zero-value scope issued an unconstrained statement "+
					"(guard %q removed?): %v", axis.name, axis.guard, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestAuditReadAxes_AllOrganizationsIsExplicit documents the single legitimate
// cross-tenant read: it has to be spelled out, and it is the only way to get an
// unfiltered statement.
func TestAuditReadAxes_AllOrganizationsIsExplicit(t *testing.T) {
	for _, axis := range auditReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newAuditRepo(t)
			axis.prime(mock, "")
			if err := axis.call(repo, AuditScopeAllOrganizations()); err != nil {
				t.Fatalf("%s: unexpected error: %v", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

func TestAuditScope_PermitsOrganization(t *testing.T) {
	cases := []struct {
		name  string
		scope AuditScope
		orgID string
		want  bool
	}{
		{"zero value denies everything", AuditScope{}, "org-1", false},
		{"zero value denies org-less rows", AuditScope{}, "", false},
		{"allowlist permits a listed org", AuditScopeOrganizations("org-1", "org-2"), "org-2", true},
		{"allowlist denies an unlisted org", AuditScopeOrganizations("org-1"), "org-9", false},
		{"allowlist denies org-less rows", AuditScopeOrganizations("org-1"), "", false},
		{"empty allowlist denies everything", AuditScopeOrganizations(), "org-1", false},
		{"platform-wide permits any org", AuditScopeAllOrganizations(), "org-9", true},
		{"platform-wide permits org-less rows", AuditScopeAllOrganizations(), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.PermitsOrganization(tc.orgID); got != tc.want {
				t.Errorf("PermitsOrganization(%q) = %v, want %v", tc.orgID, got, tc.want)
			}
		})
	}
}

func TestAuditScope_MatchesNothing(t *testing.T) {
	cases := []struct {
		name  string
		scope AuditScope
		want  bool
	}{
		{"zero value", AuditScope{}, true},
		{"empty allowlist", AuditScopeOrganizations(), true},
		{"blank ids are dropped", AuditScopeOrganizations("", ""), true},
		{"one org", AuditScopeOrganizations("org-1"), false},
		{"platform-wide", AuditScopeAllOrganizations(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.MatchesNothing(); got != tc.want {
				t.Errorf("MatchesNothing() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuditScope_DeduplicatesOrganizations(t *testing.T) {
	s := AuditScopeOrganizations("org-1", "org-1", "", "org-2")
	if got := s.OrganizationIDs(); len(got) != 2 {
		t.Errorf("OrganizationIDs() = %v, want 2 unique non-empty ids", got)
	}
}
