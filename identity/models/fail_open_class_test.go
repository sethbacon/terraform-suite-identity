// fail_open_class_test.go pins the direction the scope accessors on
// UserWithOrgRoles fail in when asked about no organization in particular.
//
// GetScopesForOrg resolves the scopes a caller then hands to
// TokenManager.GenerateForOrg, so whatever it returns for an unspecified
// organization becomes a token's authority. Matching an empty orgID by equality
// would let a membership row with an unset OrganizationID — corrupt data, but
// exactly the shape an upstream bug produces — answer that question with real
// scopes.
package models_test

import (
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

func TestFailOpenClass_GetScopesForOrg(t *testing.T) {
	user := &models.UserWithOrgRoles{
		Memberships: []models.UserMembership{
			{OrganizationID: "org-1", RoleTemplateScopes: []string{"foo:read", "foo:write"}},
			// The corrupt row: a membership that names no organization.
			{OrganizationID: "", RoleTemplateScopes: []string{"admin"}},
		},
	}

	tests := []struct {
		name  string
		orgID string
		want  int
	}{
		{
			name:  "a named organization resolves its own scopes",
			orgID: "org-1",
			want:  2,
		},
		{
			name:  "an unspecified organization grants nothing",
			orgID: "",
			want:  0,
		},
		{
			name:  "an organization the user does not belong to grants nothing",
			orgID: "org-unknown",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := user.GetScopesForOrg(tt.orgID)
			if got == nil {
				t.Fatal("GetScopesForOrg returned nil; want a non-nil slice")
			}
			if len(got) != tt.want {
				t.Errorf("GetScopesForOrg(%q) = %v (%d scopes); want %d", tt.orgID, got, len(got), tt.want)
			}
		})
	}
}
