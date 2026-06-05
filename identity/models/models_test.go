package models

import "testing"

func TestOIDCConfig_GetScopes(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []string
	}{
		{"empty defaults", "", []string{"openid", "email", "profile"}},
		{"comma separated", "openid,email,groups", []string{"openid", "email", "groups"}},
		{"trims whitespace", " openid , email ", []string{"openid", "email"}},
		{"ignores empty entries", "openid,,email,", []string{"openid", "email"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &OIDCConfig{ScopesJSON: tc.json}
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

func TestUserWithOrgRoles_HasAdminScope(t *testing.T) {
	admin := &UserWithOrgRoles{Scopes: []string{"analysis:read", "admin"}}
	if !admin.HasAdminScope() {
		t.Error("expected HasAdminScope true when admin scope present")
	}
	if !equalStrings(admin.GetAllowedScopes(), admin.Scopes) {
		t.Error("GetAllowedScopes should return the user's scopes")
	}

	plain := &UserWithOrgRoles{Scopes: []string{"analysis:read"}}
	if plain.HasAdminScope() {
		t.Error("expected HasAdminScope false without admin scope")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
