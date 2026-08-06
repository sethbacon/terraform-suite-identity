package auth_test

// This file is the compile-checked mirror of the Auth section's usage examples in
// README.md. Every snippet the README shows for this package appears here as a
// real, compiled Example function.
//
// It exists because a README snippet is not verified by anything: the README's
// NewTokenManager example passed []byte(secret) to a string parameter for
// several releases and did not compile, while the NewCoupledTokenManager example
// a few lines below it — which genuinely does take []byte — was correct. A
// reader copying the simpler of the two got an immediate type error.
//
// The rule: if a snippet in README.md's Auth section changes, change it here too.
// A future signature change then breaks `go build ./...` and `go test ./...`
// instead of silently drifting away from the documentation again.
//
// These are deliberately package `auth_test` (the external test package) so they
// exercise the exported API exactly as a consumer would, and deliberately have no
// "// Output:" comment — they are compile-and-run assertions, not golden output.

import (
	"fmt"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// ExampleHasScope mirrors README.md's scope-check snippet.
func ExampleHasScope() {
	userScopes := []string{"users:write"}

	// Scope checks — the module ships identity-core scope constants
	// (auth.ScopeUsersRead, auth.ScopeOrganizationsWrite, …); apps add their own
	// scopes (e.g. "modules:write") and supply the write→read pairs.
	ok := auth.HasScope(userScopes, auth.ScopeUsersRead,
		auth.ReadWritePairs{auth.ScopeUsersRead: auth.ScopeUsersWrite})

	fmt.Println(ok) // write implies read
	// Output: true
}

// ExampleNewTokenManager mirrors README.md's plain-constructor snippet.
//
// The first parameter is a string. If it is ever changed to []byte (or the
// parameter order changes), this stops compiling — which is the whole point.
func ExampleNewTokenManager() {
	secret := "a-32-byte-or-longer-signing-secret!!"
	userID, email := "user-1", "u@example.com"
	scopes := []string{"users:read"}

	// JWT — secret + issuer injected (never read from the environment by the module).
	tm := auth.NewTokenManager(secret, "terraform-registry")

	// GLOBAL (org-less) token.
	token, err := tm.Generate(userID, email, scopes, 24*time.Hour)
	if err != nil {
		panic(err)
	}
	claims, err := tm.Validate(token) // tries current then previous secret (rotation)
	if err != nil {
		panic(err)
	}

	// Audience — OFF by default (Validate skips the aud check unless set).
	tm.SetAudience("terraform-registry")

	fmt.Println(claims.UserID)
	// Output: user-1
}

// ExampleTokenManager_GenerateForOrg mirrors README.md's org-scoped snippet,
// including the auth.HasScopeInOrg check that pairs with it.
func ExampleTokenManager_GenerateForOrg() {
	tm := auth.NewTokenManager("a-32-byte-or-longer-signing-secret!!", "terraform-registry")
	userID, email, orgID := "user-1", "u@example.com", "org-1"

	// In a real app these come from orgRepo.GetUserScopesForOrg(ctx, userID, orgID).
	orgScopes := []string{auth.ScopeUsersWrite}

	orgToken, err := tm.GenerateForOrg(userID, email, orgID, orgScopes, 24*time.Hour)
	if err != nil {
		panic(err)
	}
	orgClaims, err := tm.Validate(orgToken)
	if err != nil {
		panic(err)
	}

	// Check it with the org-aware counterpart to HasScope, passing the SAME
	// orgID as the resource being accessed.
	ok := auth.HasScopeInOrg(orgClaims, orgID, auth.ScopeUsersRead,
		auth.ReadWritePairs{auth.ScopeUsersRead: auth.ScopeUsersWrite})

	fmt.Println(ok)
	// Output: true
}

// ExampleNewCoupledTokenManager mirrors README.md's recommended constructor for
// an app that shares a signing secret with a sibling. Note the []byte here is
// correct — this constructor really does take []byte, unlike NewTokenManager.
func ExampleNewCoupledTokenManager() {
	secret := "a-32-byte-or-longer-signing-secret!!"
	userID, email := "user-1", "u@example.com"
	scopes := []string{"users:read"}

	tm, err := auth.NewCoupledTokenManager(
		[]byte(secret),
		"terraform-registry", // this app's issuer
		[]string{"terraform-registry", "terraform-state-manager"}, // trusted issuers, incl. self
		"terraform-registry", // this app's audience
	)
	if err != nil {
		panic(err)
	}
	token, err := tm.Generate(userID, email, scopes, 24*time.Hour)
	if err != nil {
		panic(err)
	}
	// Rejects tokens from untrusted issuers or the wrong audience.
	claims, err := tm.Validate(token)
	if err != nil {
		panic(err)
	}

	fmt.Println(claims.Issuer)
	// Output: terraform-registry
}

// ExampleGenerateAPIKey mirrors README.md's API-key snippet and pins the return
// arity and order.
func ExampleGenerateAPIKey() {
	key, hash, prefix, err := auth.GenerateAPIKey("tfr")
	if err != nil {
		panic(err)
	}

	// ValidateAPIKey is a pure bcrypt comparison — it performs no expiry check.
	// Expiry is enforced by the SQL in store.GetAPIKeysByPrefix (the auth path's
	// lookup), not here.
	fmt.Println(auth.ValidateAPIKey(key, hash), len(prefix) > 0)
	// Output: true true
}

// ExampleDefaultExpiry pins README.md's "DefaultExpiry is 1 hour" claim so the
// sentence and the constant cannot disagree.
func ExampleDefaultExpiry() {
	fmt.Println(auth.DefaultExpiry)
	// Output: 1h0m0s
}
