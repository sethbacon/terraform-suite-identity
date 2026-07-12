// Package auth provides scope-checking helpers and identity-core scope constants
// shared across all apps in the Terraform suite.
package auth

import "fmt"

// Identity-core scope constants owned by the suite identity layer.
// Apps re-export these as their own typed constants and add app-specific scopes.
const (
	ScopeUsersRead          = "users:read"
	ScopeUsersWrite         = "users:write"
	ScopeOrganizationsRead  = "organizations:read"
	ScopeOrganizationsWrite = "organizations:write"
	ScopeAPIKeysManage      = "api_keys:manage"
	ScopeAuditRead          = "audit:read"
	ScopeSettingsRead       = "settings:read"
	ScopeSettingsWrite      = "settings:write"

	// ScopeAdmin is the wildcard scope that grants all permissions.
	//
	// ScopeAdmin MUST only ever originate from a trusted, admin-seeded
	// role_template — never from an external claim, IdP group mapping, or any
	// other lower-trust source, since HasScope treats its literal presence in a
	// scope list as a grant-all wildcard with no further checks. A consuming
	// backend that maps externally-sourced data (e.g. an OIDC IdP group claim)
	// onto a scope list before persisting or trusting it should call
	// ValidateProvisionableScopes to reject the literal "admin" string from
	// that lower-trust path.
	ScopeAdmin = "admin"
)

// ReadWritePairs maps a read scope to its corresponding write scope.
// A user holding the write scope is implicitly granted the read scope.
type ReadWritePairs map[string]string

// HasScope returns true if userScopes contains required.
//
// Two special rules apply:
//   - The ScopeAdmin wildcard grants every scope.
//   - If rwPairs[required] is present and userScopes contains that write scope,
//     the read scope is implicitly satisfied (write-implies-read).
//
// An empty required scope always returns false, even if userScopes contains an
// accidental empty-string element (e.g. from a naive strings.Split on a
// trailing/double comma upstream in a consumer) — empty string is never a
// valid scope to require or to grant.
func HasScope(userScopes []string, required string, rwPairs ReadWritePairs) bool {
	if required == "" {
		return false
	}
	for _, s := range userScopes {
		if s == required {
			return true
		}
		if s == ScopeAdmin {
			return true
		}
		if writeScope, ok := rwPairs[required]; ok && s == writeScope {
			return true
		}
	}
	return false
}

// HasAnyScope returns true if userScopes satisfies at least one of required.
func HasAnyScope(userScopes []string, required []string, rwPairs ReadWritePairs) bool {
	for _, r := range required {
		if HasScope(userScopes, r, rwPairs) {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if userScopes satisfies every scope in required.
// An empty required list returns false (fail-closed: unspecified scopes deny access).
func HasAllScopes(userScopes []string, required []string, rwPairs ReadWritePairs) bool {
	if len(required) == 0 {
		return false
	}
	for _, r := range required {
		if !HasScope(userScopes, r, rwPairs) {
			return false
		}
	}
	return true
}

// ValidateProvisionableScopes returns an error if scopes contains ScopeAdmin,
// naming it specifically, and nil otherwise.
//
// It is intended for a consuming backend to call when mapping
// externally-sourced data (e.g. an OIDC IdP group claim, a SCIM attribute, or
// any other value an external actor influences) onto a scope list, BEFORE
// persisting or trusting that list. Because HasScope treats the literal
// string "admin" anywhere in a scope list as a grant-all wildcard with no
// further checks, allowing it to flow in unchecked from a lower-trust source
// would let an external actor smuggle in full privilege.
//
// Do NOT call ValidateProvisionableScopes on scopes read back from an
// already-trusted, admin-seeded role_template — legitimate admin grants are
// expected to carry ScopeAdmin, and rejecting them there would break the
// intended feature.
//
// This module has no HTTP layer of its own, so it cannot wire this guard into
// a request path itself — that has to happen in each consuming backend, at
// the point where it resolves an externally-influenced group/role mapping.
// As of this writing no caller does so yet (verified: this function has zero
// callers outside its own test file, suite-wide). Adoption is tracked, not
// left to be silently rediscovered later:
//   - sethbacon/terraform-registry-backend#604
//   - sethbacon/terraform-state-manager-backend#173
//
// Both issues also record why this is not an active exploit path in either
// backend today: their group/role-mapping config writes already require
// ScopeAdmin, so an external actor cannot currently plant a Role that
// resolves to ScopeAdmin without already holding it. The guard remains
// defense-in-depth for if/when that gate changes (e.g. a lower-privileged,
// org-scoped mapping API) or for any future consumer that maps external data
// onto a scope list more directly.
func ValidateProvisionableScopes(scopes []string) error {
	for _, s := range scopes {
		if s == ScopeAdmin {
			return fmt.Errorf("scope %q is not permitted from this source: %s is a grant-all wildcard reserved for trusted, admin-seeded role_template assignment", ScopeAdmin, ScopeAdmin)
		}
	}
	return nil
}
