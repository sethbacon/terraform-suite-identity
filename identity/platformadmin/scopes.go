// scopes.go is the elevation half of the carrier: it turns "holds a carrier
// row" into "carries auth.ScopeAdmin on this request", and — just as
// importantly — it is where the two principal kinds are kept apart.
//
// A SESSION is elevated per request. AN API KEY IS NEVER ELEVATED. Those are
// two functions, not one function with a flag, because a flag is something a
// call site can get wrong and a missing parameter is not.
package platformadmin

import (
	"context"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// SessionScopes returns the effective scopes for a USER SESSION: the scopes the
// token or session carried, with auth.ScopeAdmin removed, and re-added if and
// only if userID holds a carrier row RIGHT NOW.
//
// STRIPPED FIRST, ON EVERY RETURN PATH. `admin` present in a token is a claim
// about the past — it was true when the token was minted. The carrier is the
// only thing that makes it true now. A path that returned the caller's scopes
// unchanged on any branch (an unwired carrier, a failed lookup, an empty user
// id) would answer the authority question from the source this mechanism exists
// to stop trusting.
//
// PER REQUEST, NOT CACHED, NOT MEMOISED ACROSS CALLS. This is one indexed read
// on a table with a handful of rows, and it is what buys immediate revocation:
// a cache with any TTL at all reintroduces exactly the window a long-lived
// session would have had. TestSessionScopesResolvesOnEveryCall holds that shut.
//
// ON ERROR the STRIPPED scopes are returned alongside it, so a caller that
// chooses to continue anyway continues UNELEVATED rather than with whatever the
// token claimed. An error here should normally abort the request with a server
// error rather than a denial: an authority question that did not resolve is not
// a completed "no", and serving it as one silently downgrades a platform
// administrator to a permission denial during exactly the incident in which
// they need the admin surface.
//
// The elevation copies rather than appending to the caller's slice. `scopes` is
// typically claims.Scopes, which the caller may also have published elsewhere,
// so appending in place would write through a shared backing array whenever it
// has spare capacity.
func (c *Carrier) SessionScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	base := withoutAdmin(scopes)

	isAdmin, err := c.IsPlatformAdmin(ctx, userID)
	if err != nil {
		return base, err
	}
	if !isAdmin {
		return base, nil
	}
	elevated := make([]string, len(base), len(base)+1)
	copy(elevated, base)
	return append(elevated, auth.ScopeAdmin), nil
}

// KeyScopes returns the effective scopes for an API KEY: its own scopes with
// auth.ScopeAdmin removed, always.
//
// A FREE FUNCTION WITH NO CONTEXT, NO CONNECTION AND NO PRINCIPAL — deliberately,
// and this is the whole design. "API keys must not inherit their owner's
// platform-admin" cannot be enforced by remembering not to call something; it is
// enforced by there being nothing to call. This function is structurally
// incapable of consulting the carrier, so the API-key path cannot be elevated
// even by a caller who wants to.
//
// Why it matters: a key is a long-lived, often unattended credential, frequently
// held by CI. Its owner's authority can change many times during its life. An
// elevation that rode along would hand every pipeline token the highest
// privilege in the product, revocable only by deleting the key.
//
// It strips rather than merely declining to add, because `admin` can be present
// in a key's stored scope set — seeded there by an older role model, or by an
// operator — and a key's stored scopes are not a live authority statement about
// anybody.
//
// An application that wants a key to reach an admin-gated surface must give that
// surface a scope of its own and grant the key that scope explicitly.
func KeyScopes(scopes []string) []string {
	return withoutAdmin(scopes)
}

// withoutAdmin returns scopes with every occurrence of auth.ScopeAdmin removed.
//
// Always a new slice when anything is dropped, and the input untouched: callers
// pass slices they have published elsewhere.
func withoutAdmin(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == auth.ScopeAdmin {
			continue
		}
		out = append(out, s)
	}
	return out
}
