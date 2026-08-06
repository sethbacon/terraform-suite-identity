//go:build integration

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// The REAL half of the tenant-scope class test.
//
// org_scope_matrix_test.go proves, over sqlmock, that every scoped accessor
// SENDS a tenant predicate. A mock cannot prove that predicate EXCLUDES
// anything — it returns whatever the test primed. These tests put genuine rows
// in two organizations and let PostgreSQL do the filtering, so "a caller scoped
// elsewhere is denied" is measured rather than asserted.
//
// Both directions, on every table:
//
//	the owner's scope reaches the owner's row       (nothing is over-denied)
//	the other tenant's scope reaches nothing        (nothing leaks)
//	the zero scope reaches nothing anywhere         (fail-closed default)
//
// The first line is not decoration. A predicate that denies everyone passes
// every leak assertion ever written, and shipping one is a real outage rather
// than a theoretical one.

// twoTenants is the fixture: two organizations, a user in each, an API key in
// each, plus a membership-less user that exercises the unowned axis.
type twoTenants struct {
	orgA, orgB     string
	userA, userB   string
	keyA, keyB     string
	orphanUser     string
	adminRoleTmpl  string
	viewerRoleTmpl string
}

func seedTwoTenants(t *testing.T, db *sql.DB) twoTenants {
	t.Helper()
	ctx := context.Background()
	f := twoTenants{}

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	newID := func() string { return uuid.New().String() }

	f.adminRoleTmpl, f.viewerRoleTmpl = newID(), newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.adminRoleTmpl, "orgscope-admin-"+f.adminRoleTmpl[:8], "Admin", []byte(`["admin"]`))
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.viewerRoleTmpl, "orgscope-viewer-"+f.viewerRoleTmpl[:8], "Viewer", []byte(`["users:read"]`))

	f.orgA, f.orgB = newID(), newID()
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, f.orgA, "orgscope-a-"+f.orgA[:8], "A")
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, f.orgB, "orgscope-b-"+f.orgB[:8], "B")

	f.userA, f.userB, f.orphanUser = newID(), newID(), newID()
	for _, u := range []struct{ id, email string }{
		{f.userA, "a-" + f.userA[:8] + "@example.test"},
		{f.userB, "b-" + f.userB[:8] + "@example.test"},
		{f.orphanUser, "orphan-" + f.orphanUser[:8] + "@example.test"},
	} {
		mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, u.id, u.email, "u")
	}
	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		f.orgA, f.userA, f.adminRoleTmpl)
	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		f.orgB, f.userB, f.viewerRoleTmpl)

	f.keyA, f.keyB = newID(), newID()
	mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
	          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		f.keyA, f.userA, f.orgA, "key-a", "h", "p"+f.keyA[:6], []byte(`["modules:read"]`))
	mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
	          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		f.keyB, f.userB, f.orgB, "key-b", "h", "p"+f.keyB[:6], []byte(`["modules:read"]`))

	return f
}

// TestIntegrationOrgScopeDeniesCrossTenantReads runs every scoped READ axis
// against real data owned by organization A, from A's scope and from B's.
func TestIntegrationOrgScopeDeniesCrossTenantReads(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()

	keys := NewAPIKeyRepository(db)
	orgs := NewOrganizationRepository(db)
	users := NewUserRepository(db)

	scopeA := OrgScopeOrganizations(f.orgA)
	scopeB := OrgScopeOrganizations(f.orgB)

	// --- by-id reads: in scope returns the row, out of scope is ErrNotFound ---
	byID := []struct {
		name string
		call func(OrgScope) error
	}{
		{"APIKeyRepository.GetAPIKeyByID", func(s OrgScope) error {
			_, err := keys.GetAPIKeyByID(ctx, f.keyA, s)
			return err
		}},
		{"OrganizationRepository.GetByID", func(s OrgScope) error {
			_, err := orgs.GetByID(ctx, f.orgA, s)
			return err
		}},
		{"OrganizationRepository.GetMember", func(s OrgScope) error {
			_, err := orgs.GetMember(ctx, f.orgA, f.userA, s)
			return err
		}},
		{"OrganizationRepository.GetMemberWithRole", func(s OrgScope) error {
			_, err := orgs.GetMemberWithRole(ctx, f.orgA, f.userA, s)
			return err
		}},
		{"UserRepository.GetUserByID", func(s OrgScope) error {
			_, err := users.GetUserByID(ctx, f.userA, s)
			return err
		}},
		{"UserRepository.GetUserWithOrgRoles", func(s OrgScope) error {
			_, err := users.GetUserWithOrgRoles(ctx, f.userA, s)
			return err
		}},
	}
	for _, tc := range byID {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(scopeA); err != nil {
				t.Errorf("the OWNING organization's scope was refused: %v — a tenant "+
					"predicate that denies its own tenant is an outage, not a fix", err)
			}
			if err := tc.call(scopeB); !errors.Is(err, ErrNotFound) {
				t.Errorf("another organization's scope got err=%v, want ErrNotFound", err)
			}
			if err := tc.call(OrgScope{}); !errors.Is(err, ErrNotFound) {
				t.Errorf("the zero-value scope got err=%v, want ErrNotFound", err)
			}
		})
	}

	// --- list reads: in scope yields rows, out of scope yields none ---
	lists := []struct {
		name string
		call func(OrgScope) (int, error)
	}{
		{"APIKeyRepository.ListAPIKeysByUser", func(s OrgScope) (int, error) {
			got, err := keys.ListAPIKeysByUser(ctx, f.userA, s)
			return len(got), err
		}},
		{"APIKeyRepository.ListAPIKeysByOrganization", func(s OrgScope) (int, error) {
			got, err := keys.ListAPIKeysByOrganization(ctx, f.orgA, s)
			return len(got), err
		}},
		{"APIKeyRepository.ListByUserAndOrganization", func(s OrgScope) (int, error) {
			got, err := keys.ListByUserAndOrganization(ctx, f.userA, f.orgA, s)
			return len(got), err
		}},
		{"OrganizationRepository.ListMembers", func(s OrgScope) (int, error) {
			got, err := orgs.ListMembers(ctx, f.orgA, s)
			return len(got), err
		}},
		{"OrganizationRepository.ListMembersWithUsers", func(s OrgScope) (int, error) {
			got, err := orgs.ListMembersWithUsers(ctx, f.orgA, s)
			return len(got), err
		}},
		{"OrganizationRepository.GetUserOrganizations", func(s OrgScope) (int, error) {
			got, err := orgs.GetUserOrganizations(ctx, f.userA, s)
			return len(got), err
		}},
	}
	for _, tc := range lists {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tc.call(scopeA)
			if err != nil {
				t.Fatalf("owning scope: %v", err)
			}
			if n == 0 {
				t.Errorf("the OWNING organization's scope returned nothing; a list " +
					"predicate that hides its own tenant's rows passes every leak " +
					"assertion while breaking the product")
			}
			if n, err := tc.call(scopeB); err != nil || n != 0 {
				t.Errorf("another organization's scope returned %d rows (err=%v), want 0", n, err)
			}
			if n, err := tc.call(OrgScope{}); err != nil || n != 0 {
				t.Errorf("the zero-value scope returned %d rows (err=%v), want 0", n, err)
			}
		})
	}
}

// TestIntegrationOrgScopeEstateEnumerationsSeeOnlyTheirOwnTenant covers the
// accessors that enumerate the ESTATE rather than a named target — the admin
// list and count axes both consumers filter in memory today.
//
// "Out of scope returns nothing" is the wrong assertion for these: a caller
// scoped to organization B SHOULD see B's own rows. The invariant is mutual
// exclusivity — each scope sees its own tenant's rows and none of the other's —
// and it is the assertion that actually distinguishes a working predicate from
// both failure modes at once.
func TestIntegrationOrgScopeEstateEnumerationsSeeOnlyTheirOwnTenant(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()

	keys := NewAPIKeyRepository(db)
	orgs := NewOrganizationRepository(db)
	users := NewUserRepository(db)

	scopeA := OrgScopeOrganizations(f.orgA)
	scopeB := OrgScopeOrganizations(f.orgB)

	t.Run("APIKeyRepository.ListAPIKeys", func(t *testing.T) {
		ids := func(s OrgScope) map[string]bool {
			t.Helper()
			got, err := keys.ListAPIKeys(ctx, s)
			if err != nil {
				t.Fatalf("ListAPIKeys: %v", err)
			}
			out := map[string]bool{}
			for _, k := range got {
				out[k.ID] = true
			}
			return out
		}
		a, b := ids(scopeA), ids(scopeB)
		if !a[f.keyA] || a[f.keyB] {
			t.Errorf("organization A's scope saw keyA=%v keyB=%v, want true/false", a[f.keyA], a[f.keyB])
		}
		if !b[f.keyB] || b[f.keyA] {
			t.Errorf("organization B's scope saw keyB=%v keyA=%v, want true/false", b[f.keyB], b[f.keyA])
		}
		if n := len(ids(OrgScope{})); n != 0 {
			t.Errorf("the zero-value scope listed %d keys, want 0", n)
		}
	})

	t.Run("OrganizationRepository.List and Count agree and are scoped", func(t *testing.T) {
		listed, err := orgs.List(ctx, 100, 0, scopeA)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(listed) != 1 || listed[0].ID != f.orgA {
			t.Errorf("organization A's scope listed %d organizations, want exactly org A", len(listed))
		}
		n, err := orgs.Count(ctx, scopeA)
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n != len(listed) {
			t.Errorf("Count() = %d but List() returned %d — a total that counts rows "+
				"the caller cannot page to is both a disclosure and a broken pager", n, len(listed))
		}
		if n, err := orgs.Count(ctx, OrgScope{}); err != nil || n != 0 {
			t.Errorf("the zero-value scope counted %d organizations (err=%v), want 0", n, err)
		}
	})

	t.Run("UserRepository.ListUsers and Count agree and are scoped", func(t *testing.T) {
		listed, total, err := users.ListUsers(ctx, 100, 0, scopeA)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if total != len(listed) {
			t.Errorf("total = %d but the page held %d users; the count must carry the "+
				"same predicate as the page", total, len(listed))
		}
		seen := map[string]bool{}
		for _, u := range listed {
			seen[u.ID] = true
		}
		if !seen[f.userA] {
			t.Error("organization A's scope did not list its own member")
		}
		if seen[f.userB] {
			t.Error("organization A's scope listed another tenant's user")
		}
		if seen[f.orphanUser] {
			t.Error("a plain organization scope listed a membership-less user; that " +
				"case is the unowned axis and must be asked for")
		}
		if _, total, err := users.ListUsers(ctx, 100, 0, OrgScope{}); err != nil || total != 0 {
			t.Errorf("the zero-value scope counted %d users (err=%v), want 0", total, err)
		}
	})

	t.Run("UserRepository.SearchWithMemberships hides another tenant's memberships", func(t *testing.T) {
		// userB belongs to org B only. Searching from org A's scope must not
		// surface the user, and must never surface the membership rows — the
		// disclosure #161 reports.
		got, err := users.SearchWithMemberships(ctx, "b-"+f.userB[:8], 100, 0, scopeA)
		if err != nil {
			t.Fatalf("SearchWithMemberships: %v", err)
		}
		for _, u := range got {
			if u.User.ID == f.userB {
				t.Errorf("organization A's scope reached another tenant's user with %d "+
					"memberships attached", len(u.Memberships))
			}
		}
		got, err = users.SearchWithMemberships(ctx, "b-"+f.userB[:8], 100, 0, scopeB)
		if err != nil {
			t.Fatalf("SearchWithMemberships: %v", err)
		}
		if len(got) != 1 || got[0].User.ID != f.userB {
			t.Fatalf("organization B's own scope did not reach its own user (got %d)", len(got))
		}
		if len(got[0].Memberships) != 1 || got[0].Memberships[0].OrganizationID != f.orgB {
			t.Errorf("memberships = %v, want exactly the in-scope one", got[0].Memberships)
		}
	})
}

// TestIntegrationOrgScopeDeniesCrossTenantMutations runs the write axes. Each
// asserts, against the real row, that an out-of-scope mutation BOTH reports
// ErrNotFound and leaves the row untouched — the second half is what a
// requireRow-only test cannot see.
func TestIntegrationOrgScopeDeniesCrossTenantMutations(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()

	keys := NewAPIKeyRepository(db)
	orgs := NewOrganizationRepository(db)
	users := NewUserRepository(db)

	scopeA := OrgScopeOrganizations(f.orgA)
	scopeB := OrgScopeOrganizations(f.orgB)

	t.Run("APIKeyRepository.Update", func(t *testing.T) {
		key, err := keys.GetAPIKeyByID(ctx, f.keyA, scopeA)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		key.Scopes = []string{"admin"}
		if err := keys.Update(ctx, key, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant scope escalation reported err=%v, want ErrNotFound", err)
		}
		after, err := keys.GetAPIKeyByID(ctx, f.keyA, scopeA)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if len(after.Scopes) != 1 || after.Scopes[0] != "modules:read" {
			t.Errorf("the key's scopes are now %v — a refused cross-tenant update still wrote", after.Scopes)
		}
		key.Scopes = []string{"modules:write"}
		if err := keys.Update(ctx, key, scopeA); err != nil {
			t.Errorf("the owning scope was refused: %v", err)
		}
	})

	t.Run("APIKeyRepository.RevokeAPIKey", func(t *testing.T) {
		if err := keys.RevokeAPIKey(ctx, f.keyA, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant revoke reported err=%v, want ErrNotFound", err)
		}
		if _, err := keys.GetAPIKeyByID(ctx, f.keyA, scopeA); err != nil {
			t.Errorf("the key is gone after a REFUSED cross-tenant revoke: %v", err)
		}
		if err := keys.RevokeAPIKey(ctx, f.keyA, scopeA); err != nil {
			t.Errorf("the owning scope was refused: %v", err)
		}
	})

	t.Run("OrganizationRepository.Rename", func(t *testing.T) {
		if err := orgs.Rename(ctx, f.orgA, "hijacked", scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant rename reported err=%v, want ErrNotFound", err)
		}
		org, err := orgs.GetByID(ctx, f.orgA, scopeA)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if org.Name == "hijacked" {
			t.Error("a refused cross-tenant rename still renamed")
		}
	})

	t.Run("OrganizationRepository.UpdateMemberRoleTemplate", func(t *testing.T) {
		if err := orgs.UpdateMemberRoleTemplate(ctx, f.orgA, f.userA, &f.viewerRoleTmpl, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant role change reported err=%v, want ErrNotFound", err)
		}
		m, err := orgs.GetMember(ctx, f.orgA, f.userA, scopeA)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if m.RoleTemplateID == nil || *m.RoleTemplateID != f.adminRoleTmpl {
			t.Error("a refused cross-tenant role change still changed the role")
		}
	})

	t.Run("OrganizationRepository.AddMemberWithRoleTemplate", func(t *testing.T) {
		if err := orgs.AddMemberWithRoleTemplate(ctx, f.orgA, f.userB, &f.adminRoleTmpl, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant privilege GRANT reported err=%v, want ErrNotFound", err)
		}
		if _, _, err := func() (bool, *string, error) {
			return orgs.CheckMembership(ctx, f.orgA, f.userB, OrgScopeAllOrganizations())
		}(); err != nil {
			t.Fatalf("check: %v", err)
		}
		ok, _, _ := orgs.CheckMembership(ctx, f.orgA, f.userB, OrgScopeAllOrganizations())
		if ok {
			t.Error("a refused cross-tenant grant still created the membership")
		}
		if err := orgs.AddMemberWithRoleTemplate(ctx, f.orgA, f.userB, &f.viewerRoleTmpl, scopeA); err != nil {
			t.Errorf("the owning scope was refused: %v", err)
		}
	})

	t.Run("UserRepository.DeleteUser", func(t *testing.T) {
		if err := users.DeleteUser(ctx, f.userA, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant user delete reported err=%v, want ErrNotFound", err)
		}
		if _, err := users.GetUserByID(ctx, f.userA, scopeA); err != nil {
			t.Errorf("the user is gone after a REFUSED cross-tenant delete: %v", err)
		}
	})

	t.Run("CreateAPIKey refuses an out-of-scope organization", func(t *testing.T) {
		k := &models.APIKey{OrganizationID: f.orgA, UserID: &f.userA, Name: "x", KeyHash: "h", KeyPrefix: "px", Scopes: []string{"modules:read"}}
		if err := keys.CreateAPIKey(ctx, k, scopeB); !errors.Is(err, ErrNotFound) {
			t.Errorf("creating a key in another tenant's organization reported err=%v, want ErrNotFound", err)
		}
		k2 := &models.APIKey{OrganizationID: f.orgA, UserID: &f.userA, Name: "y", KeyHash: "h", KeyPrefix: "py", Scopes: []string{"modules:read"}}
		if err := keys.CreateAPIKey(ctx, k2, scopeA); err != nil {
			t.Errorf("the owning scope was refused: %v", err)
		}
	})
}

// TestIntegrationOrgScopeUsersUnownedAxis pins what the unowned axis means on
// the users table: a user belonging to no organization at all.
//
// terraform-state-manager's requireSharedOrgAdminWithTargetUser lets that case
// through today ("no organization ties for this user at all — nothing
// cross-tenant to protect against"). Expressing it as the SAME unowned axis the
// audit reads already use is what lets a consumer keep that behaviour by saying
// so, rather than by having the module choose for it.
func TestIntegrationOrgScopeUsersUnownedAxis(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()
	users := NewUserRepository(db)

	if _, err := users.GetUserByID(ctx, f.orphanUser, OrgScopeOrganizations(f.orgA)); !errors.Is(err, ErrNotFound) {
		t.Errorf("a membership-less user reached by a plain org scope: err=%v, want ErrNotFound", err)
	}
	if _, err := users.GetUserByID(ctx, f.orphanUser, OrgScopeOrganizationsAndUnowned(f.orgA)); err != nil {
		t.Errorf("the unowned axis did not reach a membership-less user: %v", err)
	}
	// The widening must not also widen to the OTHER tenant's users.
	if _, err := users.GetUserByID(ctx, f.userB, OrgScopeOrganizationsAndUnowned(f.orgA)); !errors.Is(err, ErrNotFound) {
		t.Errorf("orgs+unowned reached another tenant's user: err=%v, want ErrNotFound", err)
	}
	if _, err := users.GetUserByID(ctx, f.orphanUser, OrgScopeAllOrganizations()); err != nil {
		t.Errorf("the platform-wide scope did not reach a membership-less user: %v", err)
	}
}

// TestIntegrationOrgScopeForUserResolvesRoleTemplateScopes covers the resolver
// both consumers were hand-rolling: it must return the organizations where the
// user's ROLE TEMPLATE grants the required scope, and only those.
func TestIntegrationOrgScopeForUserResolvesRoleTemplateScopes(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()
	orgs := NewOrganizationRepository(db)

	// userA is admin in orgA; userB is a viewer (users:read only) in orgB.
	// Give userB a second membership in orgA so "membership is not authority" is
	// actually exercised rather than merely stated.
	if err := orgs.AddMemberWithRoleTemplate(ctx, f.orgA, f.userB, &f.viewerRoleTmpl, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("seed second membership: %v", err)
	}

	t.Run("admin wildcard resolves the administered organization", func(t *testing.T) {
		got, err := orgs.OrgScopeForUser(ctx, f.userA, auth.ScopeAdmin, nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.PermitsOrganization(f.orgA) {
			t.Errorf("scope %v does not permit the organization the user administers", got)
		}
		if got.PermitsOrganization(f.orgB) {
			t.Errorf("scope %v permits an organization the user does not belong to", got)
		}
		if got.IsAllOrganizations() {
			t.Error("a membership-derived scope must never be the platform-wide scope; " +
				"that decision belongs to the consumer, at the call site")
		}
	})

	t.Run("membership alone is not authority", func(t *testing.T) {
		// userB belongs to BOTH organizations but holds only users:read in each.
		got, err := orgs.OrgScopeForUser(ctx, f.userB, auth.ScopeOrganizationsWrite, nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.MatchesNothing() {
			t.Errorf("scope %v (orgs %v) was resolved for a user who holds the required "+
				"scope nowhere — resolving on bare membership is the defect this "+
				"resolver exists to avoid", got, got.OrganizationIDs())
		}
		// ...and the scope they DO hold resolves both memberships.
		got, err = orgs.OrgScopeForUser(ctx, f.userB, auth.ScopeUsersRead, nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.PermitsOrganization(f.orgA) || !got.PermitsOrganization(f.orgB) {
			t.Errorf("scope %v (orgs %v) is missing an organization the user holds "+
				"users:read in — a resolver that denies everyone passes every leak "+
				"test ever written", got, got.OrganizationIDs())
		}
	})

	t.Run("a user with no memberships resolves to the fail-closed scope", func(t *testing.T) {
		got, err := orgs.OrgScopeForUser(ctx, f.orphanUser, auth.ScopeAdmin, nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.MatchesNothing() {
			t.Errorf("got %v, want a scope that matches nothing", got)
		}
	})

	t.Run("an empty user id resolves to the fail-closed scope without a query", func(t *testing.T) {
		got, err := orgs.OrgScopeForUser(ctx, "", auth.ScopeAdmin, nil)
		if err != nil {
			t.Fatalf("OrgScopeForUser: %v", err)
		}
		if !got.MatchesNothing() {
			t.Errorf("got %v, want a scope that matches nothing", got)
		}
	})
}

// TestIntegrationDeprovisionSweepMatchesTheMembershipStrip is the #160/#162
// co-design, end to end: the credential sweep covers exactly the organizations
// whose membership was actually removed.
//
// Two failure modes are checked, because narrowing the sweep and keeping it
// correct are in tension:
//
//	too wide   keys in organizations the caller may not touch get deleted (#160)
//	too narrow a membership is stripped and its key survives — the stranded
//	           credential of #732/#736, which is why the sweep exists at all
func TestIntegrationDeprovisionSweepMatchesTheMembershipStrip(t *testing.T) {
	db := identityTestDB(t)
	f := seedTwoTenants(t, db)
	ctx := context.Background()
	orgs := NewOrganizationRepository(db)
	keys := NewAPIKeyRepository(db)

	// The leaver belongs to both organizations and holds a key in each.
	if err := orgs.AddMemberWithRoleTemplate(ctx, f.orgB, f.userA, &f.viewerRoleTmpl, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	crossKey := &models.APIKey{OrganizationID: f.orgB, UserID: &f.userA, Name: "leaver-b", KeyHash: "h", KeyPrefix: "pz", Scopes: []string{"modules:read"}}
	if err := keys.CreateAPIKey(ctx, crossKey, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A SCIM caller whose authority covers organization A only.
	removed, err := orgs.RemoveAllMembershipsForUser(ctx, f.userA, OrgScopeOrganizations(f.orgA))
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if ids := removed.OrganizationIDs(); len(ids) != 1 || ids[0] != f.orgA {
		t.Fatalf("the strip reported %v removed, want exactly [%s] — the sweep's scope "+
			"is derived from this value, so a wrong answer here is a wrong sweep", ids, f.orgA)
	}
	// Organization B's membership must survive: the caller had no authority there.
	if ok, _, _ := orgs.CheckMembership(ctx, f.orgB, f.userA, OrgScopeAllOrganizations()); !ok {
		t.Error("the strip removed a membership in an organization outside its scope (#162)")
	}

	n, err := keys.RevokeAPIKeysForUser(ctx, f.userA, removed)
	if err != nil {
		t.Fatalf("RevokeAPIKeysForUser: %v", err)
	}
	if n != 1 {
		t.Errorf("the sweep deleted %d keys, want 1", n)
	}
	// TOO WIDE: organization B's key must survive — the caller never had
	// authority there and never reduced it (#160).
	if _, err := keys.GetAPIKeyByID(ctx, crossKey.ID, OrgScopeAllOrganizations()); err != nil {
		t.Errorf("the sweep deleted a key in an organization whose membership it did "+
			"not touch: %v (#160)", err)
	}
	// TOO NARROW: organization A's key must be gone — its membership WAS
	// stripped, so leaving the credential live strands it (#732/#736).
	if _, err := keys.GetAPIKeyByID(ctx, f.keyA, OrgScopeAllOrganizations()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a key survived in an organization whose membership was just "+
			"removed: err=%v — that is the stranded credential the sweep exists to "+
			"prevent (#732/#736)", err)
	}

	// And the empty removed-scope denies the sweep entirely: no authority was
	// withdrawn, so nothing may be revoked.
	n, err = keys.RevokeAPIKeysForUser(ctx, f.userA, OrgScope{})
	if err != nil || n != 0 {
		t.Errorf("the fail-closed scope revoked %d keys (err=%v), want 0", n, err)
	}
}
