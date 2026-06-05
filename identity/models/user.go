// Package models defines the shared identity data types (users, organizations,
// API keys, OIDC config, audit logs, role templates) used by the suite apps.
package models

import "time"

// User is an identity user record.
type User struct {
	ID        string    `db:"id" json:"id"`
	Email     string    `db:"email" json:"email"`
	Name      string    `db:"name" json:"name"`
	OIDCSub   *string   `db:"oidc_sub" json:"oidc_sub,omitempty"`
	IsActive  bool      `db:"is_active" json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// UserWithOrgRoles is a user joined with a single organization membership and
// the aggregated scopes granted by that membership's role template.
type UserWithOrgRoles struct {
	User
	OrganizationID   *string  `db:"organization_id" json:"organization_id,omitempty"`
	OrganizationName *string  `db:"organization_name" json:"organization_name,omitempty"`
	RoleTemplateName *string  `db:"role_template_name" json:"role_template_name,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
}

// GetAllowedScopes returns the scopes granted to the user.
func (u *UserWithOrgRoles) GetAllowedScopes() []string {
	return u.Scopes
}

// HasAdminScope reports whether the user holds the wildcard admin scope.
func (u *UserWithOrgRoles) HasAdminScope() bool {
	for _, s := range u.Scopes {
		if s == "admin" {
			return true
		}
	}
	return false
}
