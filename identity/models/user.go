// Package models defines the shared identity data types (users, organizations,
// API keys, OIDC config, audit logs, role templates) used by the suite apps.
// The canonical shapes follow the registry's identity model; per-app variance is
// limited to role→scope mapping, which each app seeds onto role_templates.
package models

import "time"

// User represents an identity user account.
//
// There is intentionally no soft-active flag: a user's access derives entirely
// from their organization memberships and the scopes those role templates grant.
// "Disabling" a user means removing their memberships (or deleting the user).
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	OIDCSub   *string   `json:"oidc_sub"` // OIDC subject identifier (unique per provider)
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserWithOrgRoles represents a user with their per-organization role template
// information across all memberships (multi-org).
type UserWithOrgRoles struct {
	User
	Memberships []UserMembership `json:"memberships"` // Per-organization role templates
}

// GetAllowedScopes returns all unique scopes across all organization memberships.
func (u *UserWithOrgRoles) GetAllowedScopes() []string {
	scopeSet := make(map[string]bool)
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			scopeSet[scope] = true
		}
	}
	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	return scopes
}

// HasAdminScope returns true if any organization membership has the admin scope.
func (u *UserWithOrgRoles) HasAdminScope() bool {
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			if scope == "admin" {
				return true
			}
		}
	}
	return false
}
