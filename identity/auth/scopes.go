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

// orgBound reports whether claims is bound to orgID: both must be non-empty and
// equal. A GLOBAL (org-less) token — one minted by TokenManager.Generate rather
// than GenerateForOrg, so Claims.OrgID is empty — never matches any orgID here,
// deliberately: an org-scoped check must never fall back to trusting a flat,
// org-less scope set.
func orgBound(claims *Claims, orgID string) bool {
	return claims != nil && orgID != "" && claims.OrgID != "" && claims.OrgID == orgID
}

// HasScopeInOrg is the org-aware counterpart to HasScope: it returns true only
// if claims is bound to orgID (see orgBound) AND claims.Scopes satisfies
// required. Use this instead of calling HasScope on claims.Scopes directly
// whenever the authorization decision is scoped to a specific organization —
// the common case for any multi-tenant, per-resource check — so that a token
// carrying a different organization's scopes, or no organization at all,
// cannot authorize the action. See the warning on
// store.OrganizationRepository.GetUserCombinedScopes for the cross-org
// escalation this guards against.
func HasScopeInOrg(claims *Claims, orgID string, required string, rwPairs ReadWritePairs) bool {
	if !orgBound(claims, orgID) {
		return false
	}
	return HasScope(claims.Scopes, required, rwPairs)
}

// HasAnyScopeInOrg is the org-aware counterpart to HasAnyScope. See HasScopeInOrg.
func HasAnyScopeInOrg(claims *Claims, orgID string, required []string, rwPairs ReadWritePairs) bool {
	if !orgBound(claims, orgID) {
		return false
	}
	return HasAnyScope(claims.Scopes, required, rwPairs)
}

// HasAllScopesInOrg is the org-aware counterpart to HasAllScopes. See HasScopeInOrg.
func HasAllScopesInOrg(claims *Claims, orgID string, required []string, rwPairs ReadWritePairs) bool {
	if !orgBound(claims, orgID) {
		return false
	}
	return HasAllScopes(claims.Scopes, required, rwPairs)
}
