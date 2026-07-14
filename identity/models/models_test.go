package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

func TestParseRoleTemplateID(t *testing.T) {
	validID := uuid.New()
	validIDStr := validID.String()
	invalidIDStr := "not-a-uuid"

	cases := []struct {
		name      string
		id        *string
		wantUUID  uuid.UUID
		wantOK    bool
		wantErr   bool
		errSubstr string
	}{
		{"nil id", nil, uuid.Nil, false, false, ""},
		{"valid id", &validIDStr, validID, true, false, ""},
		{"invalid id", &invalidIDStr, uuid.Nil, false, true, invalidIDStr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := ParseRoleTemplateID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not mention %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.wantUUID {
				t.Errorf("uuid = %v, want %v", got, tc.wantUUID)
			}
		})
	}
}

func TestOIDCConfig_GetScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes string
		want   []string
	}{
		{"empty defaults", "", []string{"openid", "email", "profile"}},
		{"json array", `["openid","email","groups"]`, []string{"openid", "email", "groups"}},
		{"single", `["openid"]`, []string{"openid"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &OIDCConfig{}
			if tc.scopes != "" {
				c.Scopes = json.RawMessage(tc.scopes)
			}
			got := c.GetScopes()
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("scope[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestOIDCConfig_GroupMappingRoundTrip(t *testing.T) {
	c := &OIDCConfig{}
	mappings := []OIDCGroupMapping{{Group: "admins", Organization: "acme", Role: "admin"}}
	if err := c.SetGroupMappingConfig("groups", mappings, "viewer"); err != nil {
		t.Fatalf("SetGroupMappingConfig: %v", err)
	}
	claim, got, def := c.GetGroupMappingConfig()
	if claim != "groups" || def != "viewer" {
		t.Errorf("claim=%q default=%q, want groups/viewer", claim, def)
	}
	if len(got) != 1 || got[0].Group != "admins" || got[0].Organization != "acme" || got[0].Role != "admin" {
		t.Errorf("mappings = %+v, want one admins/acme/admin", got)
	}
}

func TestUserWithOrgRoles_ScopesAcrossMemberships(t *testing.T) {
	u := &UserWithOrgRoles{
		Memberships: []UserMembership{
			{OrganizationID: "o1", RoleTemplateScopes: []string{"analysis:read", "admin"}},
			{OrganizationID: "o2", RoleTemplateScopes: []string{"analysis:read", "sources:write"}},
		},
	}
	if !u.HasAdminScope() {
		t.Error("expected HasAdminScope true when any membership has admin")
	}
	got := u.GetAllowedScopes()
	want := map[string]bool{"analysis:read": true, "admin": true, "sources:write": true}
	if len(got) != len(want) {
		t.Fatalf("GetAllowedScopes = %v, want keys %v", got, want)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected scope %q", s)
		}
	}

	plain := &UserWithOrgRoles{Memberships: []UserMembership{{RoleTemplateScopes: []string{"analysis:read"}}}}
	if plain.HasAdminScope() {
		t.Error("expected HasAdminScope false without admin scope")
	}
}

func TestUserWithOrgRoles_GetScopesForOrg(t *testing.T) {
	// Regression test for issue #54: GetAllowedScopes unions scopes across ALL org
	// memberships into one flat, org-less set. GetScopesForOrg must resolve scopes for
	// exactly one target organization, excluding scopes granted by the user's OTHER
	// memberships (e.g. admin in org-1 must not leak into an org-2-scoped lookup).
	u := &UserWithOrgRoles{
		Memberships: []UserMembership{
			{OrganizationID: "o1", RoleTemplateScopes: []string{"admin", "shared:read"}},
			{OrganizationID: "o2", RoleTemplateScopes: []string{"sources:write", "shared:read"}},
		},
	}

	cases := []struct {
		name  string
		orgID string
		want  map[string]bool
	}{
		{"org with membership (o1)", "o1", map[string]bool{"admin": true, "shared:read": true}},
		{"org with membership (o2)", "o2", map[string]bool{"sources:write": true, "shared:read": true}},
		{"org with no membership", "o3", map[string]bool{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := u.GetScopesForOrg(tc.orgID)
			if got == nil {
				t.Fatal("expected non-nil slice")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("GetScopesForOrg(%q) = %v, want keys %v", tc.orgID, got, tc.want)
			}
			for _, s := range got {
				if !tc.want[s] {
					t.Errorf("unexpected scope %q for org %q", s, tc.orgID)
				}
			}
		})
	}

	// Explicit cross-org isolation assertion: org-1's admin scope must never appear in a
	// lookup scoped to org-2, and vice versa for org-2's distinct scope.
	org1Scopes := u.GetScopesForOrg("o1")
	for _, s := range org1Scopes {
		if s == "sources:write" {
			t.Fatalf("org-1 scopes leaked org-2's scope: %v", org1Scopes)
		}
	}
	org2Scopes := u.GetScopesForOrg("o2")
	for _, s := range org2Scopes {
		if s == "admin" {
			t.Fatalf("org-2 scopes leaked org-1's scope: %v", org2Scopes)
		}
	}
}

// TestUserWithOrgRoles_GetScopesForOrg_EndToEndWithJWT is the full-chain regression test for
// issue #54: it exercises the entire recommended safe path — GetScopesForOrg (this package)
// feeding auth.TokenManager.GenerateForOrg, verified by auth.Validate + auth.HasScopeInOrg —
// for a user who is admin in org-1 and only a viewer in org-2, and proves the org-1 admin
// token cannot authorize an org-2 action, while it can authorize the equivalent org-1 action.
func TestUserWithOrgRoles_GetScopesForOrg_EndToEndWithJWT(t *testing.T) {
	u := &UserWithOrgRoles{
		Memberships: []UserMembership{
			{OrganizationID: "org-1", RoleTemplateScopes: []string{"admin"}},
			{OrganizationID: "org-2", RoleTemplateScopes: []string{"viewer:read"}},
		},
	}

	tm := auth.NewTokenManager("test-secret-key-that-is-long-enough-32+", "test-issuer")
	tok, err := tm.GenerateForOrg("user-1", "alice@example.com", "org-1", u.GetScopesForOrg("org-1"), time.Hour)
	if err != nil {
		t.Fatalf("GenerateForOrg: %v", err)
	}
	claims, err := tm.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if !auth.HasScopeInOrg(claims, "org-1", auth.ScopeUsersRead, nil) {
		t.Fatal("expected org-1 admin token to authorize an org-1 action")
	}
	if auth.HasScopeInOrg(claims, "org-2", auth.ScopeUsersRead, nil) {
		t.Fatal("org-1 admin token must not authorize an org-2 action")
	}
}
