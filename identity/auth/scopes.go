// Package auth provides scope-checking helpers and identity-core scope constants
// shared across all apps in the Terraform suite.
package auth

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
func HasScope(userScopes []string, required string, rwPairs ReadWritePairs) bool {
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
