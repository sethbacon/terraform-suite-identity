// Package models defines the shared identity data types (users, organizations,
// API keys, OIDC config, audit logs, role templates) used by the suite apps.
// The canonical shapes follow the registry's identity model; per-app variance is
// limited to role→scope mapping, which each app seeds onto role_templates.
package models

import (
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// User represents an identity user account.
//
// There is intentionally no soft-active flag: a user's access derives entirely
// from their organization memberships and the scopes those role templates grant.
// "Disabling" a user means removing their memberships (or deleting the user).
// (The users.is_active column has been removed — see migration 000004 — after
// an audit found it was never read or written.)
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
//
// WARNING: This returns a GLOBAL set unioned across every organization membership — it is
// suite-wide by design and carries NO per-organization qualifier. Do not use this alone to
// authorize an org-scoped action: a caller must independently verify the user's
// membership/role in the SPECIFIC target organization before trusting these scopes for that
// organization, or use GetScopesForOrg instead, which resolves scopes for exactly one target
// organization. Pair GetScopesForOrg with auth.TokenManager.GenerateForOrg (to mint the
// token) and auth.HasScopeInOrg / auth.HasAnyScopeInOrg / auth.HasAllScopesInOrg (to check
// it) so the org binding is enforceable from the token itself rather than trusted from a
// flat scope list.
//
// The return type is auth.GlobalScopes rather than []string so that this
// cross-organization union cannot reach auth.TokenManager.GenerateForOrg — which
// takes auth.OrgScopes — without an explicit, greppable conversion at the call
// site. See the doc on auth.GlobalScopes. This method is NOT marked deprecated:
// it is the only accessor for the suite-wide union, and a deprecation marker on
// a method with no replacement is a warning rather than a remedy.
func (u *UserWithOrgRoles) GetAllowedScopes() auth.GlobalScopes {
	scopeSet := make(map[string]bool)
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			scopeSet[scope] = true
		}
	}
	scopes := make(auth.GlobalScopes, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	return scopes
}

// GetScopesForOrg returns the scopes granted to the user by their role template within a
// SINGLE target organization (orgID), rather than unioning across every organization
// membership the user has (see the warning on GetAllowedScopes). Memberships holds at most
// one entry per organization, so at most one membership's RoleTemplateScopes is returned,
// deduplicated. If the user has no membership matching orgID, an empty (non-nil) slice is
// returned, matching GetAllowedScopes' convention of returning make([]string, 0, ...) rather
// than nil.
//
// An empty orgID names no organization and therefore grants nothing: it returns an empty
// slice without consulting the memberships at all. Matching it by equality instead would make
// a membership row with an unset OrganizationID — corrupt data, but the shape a bug upstream
// produces — hand its scopes to a caller that asked about no organization in particular.
//
// The return type is auth.OrgScopes, the type auth.TokenManager.GenerateForOrg
// accepts, so the org-scoped path type-checks end to end while the
// cross-organization union (auth.GlobalScopes) does not.
func (u *UserWithOrgRoles) GetScopesForOrg(orgID string) auth.OrgScopes {
	if orgID == "" {
		return auth.OrgScopes{}
	}
	scopeSet := make(map[string]bool)
	for _, m := range u.Memberships {
		if m.OrganizationID != orgID {
			continue
		}
		for _, scope := range m.RoleTemplateScopes {
			scopeSet[scope] = true
		}
	}
	scopes := make(auth.OrgScopes, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	return scopes
}

// HasAdminScope returns true if any organization membership has the admin scope.
func (u *UserWithOrgRoles) HasAdminScope() bool {
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			if scope == auth.ScopeAdmin {
				return true
			}
		}
	}
	return false
}
