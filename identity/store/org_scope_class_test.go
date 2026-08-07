package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
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
	// zeroScopeErr is the sentinel the axis must report under the fail-closed
	// zero scope, or nil when the axis reports emptiness in band (an empty
	// result set / an empty row stream). A by-id read has no empty value to
	// return, so since v0.24.0 it reports ErrNotFound — the SAME error a
	// genuinely absent entry produces, which is what keeps the by-id axis from
	// becoming a cross-tenant existence oracle.
	zeroScopeErr error
	call         func(repo *AuditRepository, scope OrgScope) error
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
			call: func(repo *AuditRepository, scope OrgScope) error {
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
			zeroScopeErr: ErrNotFound,
			call: func(repo *AuditRepository, scope OrgScope) error {
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
			call: func(repo *AuditRepository, scope OrgScope) error {
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

			if err := axis.call(repo, OrgScopeOrganizations("org-1")); err != nil {
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
			err := axis.call(repo, OrgScope{})
			if axis.zeroScopeErr != nil {
				if !errors.Is(err, axis.zeroScopeErr) {
					t.Fatalf("%s: zero-value scope returned %v, want %v — a fail-closed "+
						"read must be reported, not indistinguishable from a hit",
						axis.name, err, axis.zeroScopeErr)
				}
			} else if err != nil {
				t.Fatalf("%s: zero-value scope issued an unconstrained statement "+
					"(guard %q removed?): %v", axis.name, axis.guard, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestAuditReadAxes_OrgsAndUnownedCarriesBothHalves runs the whole axis table
// through the OrgScopeOrganizationsAndUnowned variant. Both halves of the
// predicate must reach the SQL on EVERY axis: the allowlist (so other tenants
// stay out) and the IS NULL branch (so the consumer's platform-level events
// come back). A variant that only widened the list axis would put the consumer
// straight back into the split this class is about.
func TestAuditReadAxes_OrgsAndUnownedCarriesBothHalves(t *testing.T) {
	const bothHalvesRe = `.*organization_id = ANY\(\$\d+\) OR .*organization_id IS NULL.*`
	for _, axis := range auditReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newAuditRepo(t)
			axis.prime(mock, bothHalvesRe)

			if err := axis.call(repo, OrgScopeOrganizationsAndUnowned("org-1")); err != nil {
				t.Fatalf("%s: statement did not carry both halves of the orgs+unowned "+
					"predicate (guard %q removed?): %v", axis.name, axis.guard, err)
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
			if err := axis.call(repo, OrgScopeAllOrganizations()); err != nil {
				t.Fatalf("%s: unexpected error: %v", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

func TestOrgScope_PermitsOrganization(t *testing.T) {
	cases := []struct {
		name  string
		scope OrgScope
		orgID string
		want  bool
	}{
		{"zero value denies everything", OrgScope{}, "org-1", false},
		{"zero value denies org-less rows", OrgScope{}, "", false},
		{"allowlist permits a listed org", OrgScopeOrganizations("org-1", "org-2"), "org-2", true},
		{"allowlist denies an unlisted org", OrgScopeOrganizations("org-1"), "org-9", false},
		{"allowlist denies org-less rows", OrgScopeOrganizations("org-1"), "", false},
		{"empty allowlist denies everything", OrgScopeOrganizations(), "org-1", false},
		{"platform-wide permits any org", OrgScopeAllOrganizations(), "org-9", true},
		{"platform-wide permits org-less rows", OrgScopeAllOrganizations(), "", true},
		// The TSM variant: my organizations, plus the platform's own org-less
		// events. It must widen to unowned rows WITHOUT widening to other
		// tenants — that combination is the whole reason it exists.
		{"orgs+unowned permits a listed org", OrgScopeOrganizationsAndUnowned("org-1"), "org-1", true},
		{"orgs+unowned permits org-less rows", OrgScopeOrganizationsAndUnowned("org-1"), "", true},
		{"orgs+unowned still denies a foreign org", OrgScopeOrganizationsAndUnowned("org-1"), "org-9", false},
		{"orgs+unowned with no orgs is unowned-only", OrgScopeOrganizationsAndUnowned(), "", true},
		{"orgs+unowned with no orgs denies owned rows", OrgScopeOrganizationsAndUnowned(), "org-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.PermitsOrganization(tc.orgID); got != tc.want {
				t.Errorf("PermitsOrganization(%q) = %v, want %v", tc.orgID, got, tc.want)
			}
		})
	}
}

func TestOrgScope_MatchesNothing(t *testing.T) {
	cases := []struct {
		name  string
		scope OrgScope
		want  bool
	}{
		{"zero value", OrgScope{}, true},
		{"empty allowlist", OrgScopeOrganizations(), true},
		{"blank ids are dropped", OrgScopeOrganizations("", ""), true},
		{"one org", OrgScopeOrganizations("org-1"), false},
		{"platform-wide", OrgScopeAllOrganizations(), false},
		{"orgs+unowned with no orgs still matches unowned rows", OrgScopeOrganizationsAndUnowned(), false},
		{"orgs+unowned with orgs", OrgScopeOrganizationsAndUnowned("org-1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.MatchesNothing(); got != tc.want {
				t.Errorf("MatchesNothing() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrgScope_DeduplicatesOrganizations(t *testing.T) {
	s := OrgScopeOrganizations("org-1", "org-1", "", "org-2")
	if got := s.OrganizationIDs(); len(got) != 2 {
		t.Errorf("OrganizationIDs() = %v, want 2 unique non-empty ids", got)
	}
}

// ---------------------------------------------------------------------------
// The exported predicate builder (the leverage this batch ships to consumers)
// ---------------------------------------------------------------------------

// TestOrgScope_SQLContract pins the contract OrgScope.SQL publishes, because a
// consumer scoping ITS OWN organization-owned tables now depends on it:
// terraform-registry's modules/providers/SCM providers, terraform-state-manager's
// states/sources. Until v0.25.0 this builder was unexported, which is the
// mechanical reason those consumers hand-rolled a filter per table instead of
// applying this one.
//
// Two properties are load-bearing and neither is obvious from the signature:
//
//  1. the clause is NEVER EMPTY. The unexported form returned "" for the
//     platform-wide scope, so a caller appending it produced an UNFILTERED
//     statement for one scope value and a filtered one for the others — the
//     fail-open shape the type exists to prevent.
//  2. len(args) is 0 or 1 and paramIndex is where the FIRST one lands, so
//     `args = append(args, scopeArgs...)` composes whether or not a placeholder
//     was consumed.
func TestOrgScope_SQLContract(t *testing.T) {
	cases := []struct {
		name       string
		scope      OrgScope
		wantClause string
		wantArgs   int
	}{
		{"zero value is an unsatisfiable predicate, not an absent one",
			OrgScope{}, "FALSE", 0},
		{"empty allowlist is unsatisfiable",
			OrgScopeOrganizations(), "FALSE", 0},
		{"platform-wide is an explicit TRUE, never an empty string",
			OrgScopeAllOrganizations(), "TRUE", 0},
		{"allowlist binds one array argument",
			OrgScopeOrganizations("org-1", "org-2"), "t.org_id = ANY($3)", 1},
		{"orgs+unowned parenthesises the alternation so it cannot be swallowed by AND",
			OrgScopeOrganizationsAndUnowned("org-1"), "(t.org_id = ANY($3) OR t.org_id IS NULL)", 1},
		{"unowned-only needs no placeholder",
			OrgScopeOrganizationsAndUnowned(), "t.org_id IS NULL", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clause, args := tc.scope.SQL("t.org_id", 3)
			if clause == "" {
				t.Fatal("SQL returned an empty clause; a caller appending it would " +
					"emit an unfiltered statement, which is the fail-open shape " +
					"OrgScope exists to make unrepresentable")
			}
			if clause != tc.wantClause {
				t.Errorf("clause = %q, want %q", clause, tc.wantClause)
			}
			if len(args) != tc.wantArgs {
				t.Errorf("len(args) = %d, want %d", len(args), tc.wantArgs)
			}
		})
	}
}

// TestOrgScope_SQLHonoursParamIndex is the composability half: a consumer
// splicing this into an existing WHERE clause passes len(args)+1 and the
// placeholder must follow.
func TestOrgScope_SQLHonoursParamIndex(t *testing.T) {
	for _, idx := range []int{1, 2, 7, 12} {
		clause, args := OrgScopeOrganizations("org-1").SQL("c", idx)
		want := fmt.Sprintf("c = ANY($%d)", idx)
		if clause != want {
			t.Errorf("SQL(c, %d) = %q, want %q", idx, clause, want)
		}
		if len(args) != 1 {
			t.Errorf("SQL(c, %d) bound %d args, want 1", idx, len(args))
		}
	}
}

// TestOrgScope_SortsOrganizationIDs pins the deterministic argument. A consumer
// building a scope out of a map (both of them do) otherwise binds a different
// array on every call for the same authority, which costs statement-cache hits
// and makes a failing test's expected argument irreproducible.
func TestOrgScope_SortsOrganizationIDs(t *testing.T) {
	got := OrgScopeOrganizations("org-c", "org-a", "org-b").OrganizationIDs()
	want := []string{"org-a", "org-b", "org-c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("OrganizationIDs() = %v, want %v", got, want)
	}
}

// TestOrgScope_WithUnownedIsANoOpOnPlatformWide guards the one widening that
// must not change anything: the platform-wide scope already admits every row,
// owned or not.
func TestOrgScope_WithUnownedIsANoOpOnPlatformWide(t *testing.T) {
	s := OrgScopeAllOrganizations().WithUnowned()
	if !s.IsAllOrganizations() || !s.PermitsOrganization("anything") || !s.IncludesUnowned() {
		t.Errorf("WithUnowned() narrowed the platform-wide scope: %v", s)
	}
}

// TestOrgScope_MembershipSQLContract is TestOrgScope_SQLContract for the users
// table, whose tenancy is derived through organization_members rather than
// carried on the row.
//
// It tests the builder DIRECTLY rather than only through an accessor, because
// every scoped users accessor short-circuits on MatchesNothing() before issuing
// a statement — so the builder's own fail-closed branch is defence in depth that
// no accessor-level test can reach. Defence in depth that nothing tests is
// decoration: a later refactor that drops a short-circuit would silently promote
// this branch to the only guard, and it has to already be correct when that
// happens.
func TestOrgScope_MembershipSQLContract(t *testing.T) {
	const exists = "EXISTS (SELECT 1 FROM organization_members osm WHERE osm.user_id = u.id AND osm.organization_id = ANY($2))"
	const notMember = "NOT EXISTS (SELECT 1 FROM organization_members osm WHERE osm.user_id = u.id)"

	cases := []struct {
		name       string
		scope      OrgScope
		wantClause string
		wantArgs   int
	}{
		{"zero value is unsatisfiable", OrgScope{}, "FALSE", 0},
		{"empty allowlist is unsatisfiable", OrgScopeOrganizations(), "FALSE", 0},
		{"platform-wide imposes no membership requirement at all",
			OrgScopeAllOrganizations(), "TRUE", 0},
		{"an allowlist requires a shared organization",
			OrgScopeOrganizations("org-1"), exists, 1},
		{"unowned-only means a user with no membership row",
			OrgScopeOrganizationsAndUnowned(), notMember, 0},
		{"orgs+unowned admits both, parenthesised",
			OrgScopeOrganizationsAndUnowned("org-1"), "(" + exists + " OR " + notMember + ")", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clause, args := tc.scope.membershipSQL("u.id", 2)
			if clause == "" {
				t.Fatal("membershipSQL returned an empty clause")
			}
			if clause != tc.wantClause {
				t.Errorf("clause =\n%q\nwant\n%q", clause, tc.wantClause)
			}
			if len(args) != tc.wantArgs {
				t.Errorf("len(args) = %d, want %d", len(args), tc.wantArgs)
			}
		})
	}
	// The platform-wide case must NOT become an EXISTS: that would silently
	// require every user to hold at least one membership, hiding pre-provisioned
	// and orphaned accounts from the one scope that is supposed to see everything.
	if clause, _ := OrgScopeAllOrganizations().membershipSQL("u.id", 1); strings.Contains(clause, "EXISTS") {
		t.Errorf("the platform-wide scope emitted %q; it must impose no membership "+
			"requirement, or a user with no memberships becomes invisible to every scope", clause)
	}
}

// ---------------------------------------------------------------------------
// The resolver (the second thing this batch ships to consumers)
// ---------------------------------------------------------------------------

// membershipRows builds the GetUserMemberships projection OrgScopeForUser reads.
func membershipRows(rows ...[2]string) *sqlmock.Rows {
	r := sqlmock.NewRows(userMembershipCols)
	for _, m := range rows {
		r = r.AddRow(m[0], "org", nil, time.Unix(0, 0), nil, nil, []byte(m[1]))
	}
	return r
}

// TestOrgScopeForUser is the unit cover for the resolver both consumers were
// hand-rolling (terraform-registry's tenantscope.Resolve, terraform-state-manager's
// adminOrgSet). Every case here is a behaviour one of those two depends on.
func TestOrgScopeForUser(t *testing.T) {
	const q = `SELECT om\.organization_id.*FROM organization_members om.*WHERE om\.user_id = \$1`

	t.Run("keeps only the organizations whose ROLE TEMPLATE grants the scope", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnRows(membershipRows(
			[2]string{"org-granted", `["mirrors:manage"]`},
			[2]string{"org-member-only", `["modules:read"]`},
		))
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "mirrors:manage", nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.PermitsOrganization("org-granted") {
			t.Error("the organization whose role template grants the scope was dropped; " +
				"a resolver that denies everyone passes every leak test ever written")
		}
		if got.PermitsOrganization("org-member-only") {
			t.Error("bare MEMBERSHIP was treated as authority — that is the defect " +
				"terraform-registry #719 closed for its per-resource guards and this " +
				"resolver exists to keep closed for the list and create axes")
		}
	})

	t.Run("honours the admin wildcard", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnRows(membershipRows([2]string{"org-1", `["admin"]`}))
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "anything:at:all", nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.PermitsOrganization("org-1") {
			t.Error("auth.ScopeAdmin in a role template must satisfy every required scope")
		}
	})

	t.Run("honours the caller's read-implies-write pairs", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnRows(membershipRows([2]string{"org-1", `["users:write"]`}))
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "users:read",
			auth.ReadWritePairs{"users:read": "users:write"})
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.PermitsOrganization("org-1") {
			t.Error("rwPairs was ignored; both consumers pass their own table and a " +
				"resolver that drops it silently narrows their authority model")
		}
	})

	t.Run("never returns the platform-wide scope", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnRows(membershipRows([2]string{"org-1", `["admin"]`}))
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "admin", nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if got.IsAllOrganizations() {
			t.Error("a membership-derived scope must never widen to every organization: " +
				"the store layer cannot see the token or an API key's organization " +
				"binding, so 'this caller is platform-wide' is the consumer's decision " +
				"and OrgScopeAllOrganizations() at the call site is how it is spelled")
		}
		if got.IncludesUnowned() {
			t.Error("the resolver must not decide what a consumer's NULL owners mean; " +
				"WithUnowned() is the call-site spelling for that")
		}
	})

	t.Run("a user with no qualifying membership resolves to the fail-closed scope", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnRows(membershipRows())
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "admin", nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.MatchesNothing() {
			t.Errorf("got %v, want a scope that matches nothing", got)
		}
	})

	t.Run("an empty user id denies without a query", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		// Nothing is primed: a lookup here would surface as an unexpected query.
		got, err := repo.OrgScopeForUser(context.Background(), "", "admin", nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.MatchesNothing() {
			t.Errorf("got %v, want a scope that matches nothing", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("%v", err)
		}
	})

	t.Run("a failed lookup returns the zero scope alongside the error", func(t *testing.T) {
		repo, mock := newOrgRepo(t)
		mock.ExpectQuery(q).WillReturnError(errors.New("db down"))
		got, err := repo.OrgScopeForUser(context.Background(), "user-1", "admin", nil)
		if err == nil {
			t.Fatal("a membership lookup failure must be reported, not silently widened")
		}
		if !got.MatchesNothing() {
			t.Errorf("got %v on the error path, want a scope that matches nothing — a "+
				"caller that drops the error must still reach nothing", got)
		}
	})
}
