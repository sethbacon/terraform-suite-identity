package models

import (
	"encoding/json"
	"testing"
)

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
