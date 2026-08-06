// fail_open_class_test.go pins the direction every security primitive in this
// package fails in when its input is empty, nil or zero-valued.
//
// The class these tables guard is "a security decision that returns the
// PERMISSIVE answer when it cannot actually answer": a scope check handed no
// required scope, a token manager holding no signing secret, a token identifier
// read from a field that is structurally always empty. Each of those reads as
// working code and reviews as working code — nothing errors, nothing logs — so
// only a test that asserts the deny direction can tell a present guard from an
// absent one.
//
// Every table carries BOTH directions on purpose. A table that only asserts
// denials passes just as happily against a primitive that denies everyone,
// which is its own outage-shaped defect, so each case says whether the input is
// legitimate (and must be ALLOWED) or degenerate (and must be DENIED).
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Token identifier (jti) ------------------------------------------------

// TestFailOpenClass_TokenIdentifier pins that the token identifier is readable
// from every spelling a caller might reach for.
//
// Claims declares `jti` twice — the custom JTI field and the promoted
// RegisteredClaims.ID — and Go's field dominance means encoding/json only ever
// fills the shallower one. A denylist keyed on the idiomatic claims.ID would
// therefore look up "" and be told "not revoked" about every token ever issued,
// silently and permanently. Generate and Validate reconcile the two fields so
// that trap cannot be walked into.
func TestFailOpenClass_TokenIdentifier(t *testing.T) {
	tm := newTM()
	tok, err := tm.Generate("user-1", "u@example.com", []string{"foo:read"}, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claims, err := tm.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// ALLOWED direction: a real token yields the SAME non-empty identifier
	// through every access path.
	reads := []struct {
		name string
		got  string
	}{
		{"TokenID accessor", claims.TokenID()},
		{"custom JTI field", claims.JTI},
		{"standard RegisteredClaims.ID (promoted as claims.ID)", claims.ID},
		{"standard field spelled out", claims.RegisteredClaims.ID},
	}
	for _, r := range reads {
		t.Run("populated/"+r.name, func(t *testing.T) {
			if r.got == "" {
				t.Fatalf("%s is empty; a denylist keyed on it would report every token as not-revoked", r.name)
			}
			if r.got != claims.TokenID() {
				t.Errorf("%s = %q; want %q — the two jti fields disagree", r.name, r.got, claims.TokenID())
			}
		})
	}

	// A freshly generated (not yet round-tripped) Claims must agree too, so a
	// caller inspecting what it just minted sees the same identifier.
	t.Run("populated/generate side keeps both fields in step", func(t *testing.T) {
		var minted Claims
		if _, err := jwt.ParseWithClaims(tok, &minted, func(*jwt.Token) (interface{}, error) {
			return []byte("test-secret-key-that-is-long-enough-32+"), nil
		}); err != nil {
			t.Fatalf("ParseWithClaims: %v", err)
		}
		if minted.JTI != claims.TokenID() {
			t.Errorf("token body jti = %q; want %q", minted.JTI, claims.TokenID())
		}
	})

	// DENIED direction: no identifier present means TokenID reports nothing,
	// so a caller cannot mistake a missing id for a checked-and-clean one.
	empties := []struct {
		name   string
		claims *Claims
	}{
		{"nil claims", nil},
		{"zero-value claims", &Claims{}},
		{"claims with only an empty jti", &Claims{JTI: ""}},
	}
	for _, e := range empties {
		t.Run("absent/"+e.name, func(t *testing.T) {
			if got := e.claims.TokenID(); got != "" {
				t.Errorf("TokenID() = %q; want %q", got, "")
			}
		})
	}
}

// --- Signing secret --------------------------------------------------------

// TestFailOpenClass_EmptySigningSecret pins that a TokenManager without a
// signing secret mints nothing and accepts nothing.
//
// An empty HMAC key is not a weak key, it is a publicly known one: anybody can
// produce a token that verifies against it. A manager that quietly signs and
// validates with one turns a configuration mistake into universal forgery, and
// nothing in the token or the error channel would say so.
func TestFailOpenClass_EmptySigningSecret(t *testing.T) {
	const realSecret = "test-secret-key-that-is-long-enough-32+"

	// A token an attacker can produce knowing only that the secret is empty.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID: "attacker",
		JTI:    "forged",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString([]byte{})
	if err != nil {
		t.Fatalf("sign with empty key: %v", err)
	}

	genuine, err := NewTokenManager(realSecret, "test-issuer").Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate genuine token: %v", err)
	}

	tests := []struct {
		name    string
		manager func() *TokenManager
		// wantUsable is the ALLOWED direction: the manager both mints and
		// accepts. false is the DENIED direction.
		wantUsable bool
	}{
		{
			name:       "configured secret",
			manager:    func() *TokenManager { return NewTokenManager(realSecret, "test-issuer") },
			wantUsable: true,
		},
		{
			name:       "empty secret string",
			manager:    func() *TokenManager { return NewTokenManager("", "test-issuer") },
			wantUsable: false,
		},
		{
			name:       "zero-value manager",
			manager:    func() *TokenManager { return &TokenManager{} },
			wantUsable: false,
		},
		{
			name: "rotated onto an empty secret, overlap ended",
			manager: func() *TokenManager {
				m := NewTokenManager(realSecret, "test-issuer")
				m.RotateSecret(nil)
				m.ClearPreviousSecret()
				return m
			},
			wantUsable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.manager()

			tok, genErr := m.Generate("user-1", "u@example.com", nil, time.Hour)
			if tt.wantUsable {
				if genErr != nil {
					t.Fatalf("Generate: %v; want a token", genErr)
				}
				if _, valErr := m.Validate(tok); valErr != nil {
					t.Errorf("Validate(own token): %v; want it accepted", valErr)
				}
			} else {
				if !errors.Is(genErr, ErrNoSigningSecret) {
					t.Errorf("Generate error = %v; want ErrNoSigningSecret", genErr)
				}
			}

			// A token signed with the empty key must never validate, whatever
			// the manager is configured with.
			if _, err := m.Validate(forged); err == nil {
				t.Error("Validate accepted a token signed with an empty HMAC key")
			}

			// And a manager with no secret must not accept a genuine token
			// either: it has no basis on which to verify one.
			if _, err := m.Validate(genuine); tt.wantUsable != (err == nil) {
				t.Errorf("Validate(genuine token) error = %v; want accepted=%v", err, tt.wantUsable)
			}
		})
	}
}

// --- Algorithm confusion ---------------------------------------------------

// TestFailOpenClass_AlgorithmConfusion pins the keyfunc's exact-type signing
// method check against the highest-severity JWT bug class.
//
// The guard is one comparison (t.Method != jwt.SigningMethodHS256) and the
// tempting simplification — comparing the algorithm NAME instead — reopens the
// whole class. These rows exist so that refactor fails loudly. The final row
// asserts the allow direction, so a keyfunc that rejected everything would not
// pass this test either.
func TestFailOpenClass_AlgorithmConfusion(t *testing.T) {
	const secret = "test-secret-key-that-is-long-enough-32+"

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	// The PEM-encoded RSA PUBLIC key, i.e. the material a deployment that
	// confused an asymmetric verification key for a symmetric signing secret
	// would be holding. It is not secret — that is the entire point of the
	// confusion.
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	claims := func() jwt.RegisteredClaims {
		return jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
	}
	sign := func(t *testing.T, method jwt.SigningMethod, key interface{}) string {
		t.Helper()
		s, err := jwt.NewWithClaims(method, claims()).SignedString(key)
		if err != nil {
			t.Fatalf("sign %s: %v", method.Alg(), err)
		}
		return s
	}

	tests := []struct {
		name string
		// secret the verifying TokenManager is configured with.
		managerSecret string
		token         func(t *testing.T) string
		wantAccepted  bool
	}{
		{
			name:          "alg=none carries no signature at all",
			managerSecret: secret,
			token: func(t *testing.T) string {
				return sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
			},
		},
		{
			name:          "HS384 with the real secret",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodHS384, []byte(secret)) },
		},
		{
			name:          "HS512 with the real secret",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodHS512, []byte(secret)) },
		},
		{
			name:          "RS256 signed with an attacker RSA key",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodRS256, rsaKey) },
		},
		{
			name:          "ES256 signed with an attacker EC key",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodES256, ecKey) },
		},
		{
			// The CVE-2015-9235 shape: the verifier holds an RSA PUBLIC key
			// where an HMAC secret was expected, and is presented an RS256
			// token signed by the matching private key. A keyfunc that handed
			// its key material back without checking the method would verify
			// this as genuine.
			name:          "RS256 against a manager whose secret is the RSA public key",
			managerSecret: string(pubPEM),
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodRS256, rsaKey) },
		},
		{
			// The mirror image: the public key, being public, is used as an
			// HMAC secret to forge an HS256 token. The manager here is
			// configured with the real secret, so this must fail on the
			// signature even though the algorithm is the expected one.
			name:          "HS256 forged with the public key as the HMAC secret",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodHS256, pubPEM) },
		},
		{
			name:          "genuine HS256 with the real secret",
			managerSecret: secret,
			token:         func(t *testing.T) string { return sign(t, jwt.SigningMethodHS256, []byte(secret)) },
			wantAccepted:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := NewTokenManager(tt.managerSecret, "test-issuer")
			_, err := tm.Validate(tt.token(t))
			if accepted := err == nil; accepted != tt.wantAccepted {
				t.Errorf("Validate accepted = %v (err = %v); want accepted = %v", accepted, err, tt.wantAccepted)
			}
		})
	}
}

// --- Scope decisions -------------------------------------------------------

// TestFailOpenClass_ScopeDecisionsOnEmptyInput sweeps the package's
// authorization helpers with the degenerate inputs a mis-wired consumer
// actually produces — a blank scope constant, a scope list carrying an empty
// element from a naive split on a trailing comma, a nil claims pointer, an
// org-less token presented at an org-scoped check — and pins that each one
// denies while its legitimate counterpart still allows.
func TestFailOpenClass_ScopeDecisionsOnEmptyInput(t *testing.T) {
	pairs := ReadWritePairs{"foo:read": "foo:write"}
	orgClaims := &Claims{OrgID: "org-1", Scopes: []string{"foo:read"}}
	globalClaims := &Claims{Scopes: []string{"foo:read"}}

	tests := []struct {
		name      string
		decide    func() bool
		wantAllow bool
	}{
		{
			name:   "HasScope: blank required scope",
			decide: func() bool { return HasScope([]string{"foo:read", ""}, "", pairs) },
		},
		{
			name:      "HasScope: real required scope",
			decide:    func() bool { return HasScope([]string{"foo:read"}, "foo:read", pairs) },
			wantAllow: true,
		},
		{
			name:   "HasAnyScope: no required scopes named",
			decide: func() bool { return HasAnyScope([]string{"foo:read"}, nil, pairs) },
		},
		{
			name:      "HasAnyScope: one of the required scopes held",
			decide:    func() bool { return HasAnyScope([]string{"foo:read"}, []string{"bar:read", "foo:read"}, pairs) },
			wantAllow: true,
		},
		{
			name:   "HasAllScopes: no required scopes named",
			decide: func() bool { return HasAllScopes([]string{"foo:read"}, nil, pairs) },
		},
		{
			name:      "HasAllScopes: every required scope held",
			decide:    func() bool { return HasAllScopes([]string{"foo:read"}, []string{"foo:read"}, pairs) },
			wantAllow: true,
		},
		{
			name:   "HasScopeInOrg: nil claims",
			decide: func() bool { return HasScopeInOrg(nil, "org-1", "foo:read", pairs) },
		},
		{
			name:   "HasScopeInOrg: empty target org",
			decide: func() bool { return HasScopeInOrg(orgClaims, "", "foo:read", pairs) },
		},
		{
			name:   "HasScopeInOrg: org-less (global) token",
			decide: func() bool { return HasScopeInOrg(globalClaims, "org-1", "foo:read", pairs) },
		},
		{
			name:      "HasScopeInOrg: token bound to the target org",
			decide:    func() bool { return HasScopeInOrg(orgClaims, "org-1", "foo:read", pairs) },
			wantAllow: true,
		},
		{
			name:   "HasAnyScopeInOrg: org-less (global) token",
			decide: func() bool { return HasAnyScopeInOrg(globalClaims, "org-1", []string{"foo:read"}, pairs) },
		},
		{
			name:      "HasAnyScopeInOrg: token bound to the target org",
			decide:    func() bool { return HasAnyScopeInOrg(orgClaims, "org-1", []string{"foo:read"}, pairs) },
			wantAllow: true,
		},
		{
			name:   "HasAllScopesInOrg: org-less (global) token",
			decide: func() bool { return HasAllScopesInOrg(globalClaims, "org-1", []string{"foo:read"}, pairs) },
		},
		{
			name:      "HasAllScopesInOrg: token bound to the target org",
			decide:    func() bool { return HasAllScopesInOrg(orgClaims, "org-1", []string{"foo:read"}, pairs) },
			wantAllow: true,
		},
		{
			name:   "RoleScopesPermittedBy: caller holds nothing, role grants admin",
			decide: func() bool { return RoleScopesPermittedBy(nil, []string{ScopeAdmin}, pairs) },
		},
		{
			name:   "RoleScopesPermittedBy: caller holds nothing, role grants a real scope",
			decide: func() bool { return RoleScopesPermittedBy(nil, []string{"foo:read"}, pairs) },
		},
		{
			name:      "RoleScopesPermittedBy: caller already holds what it assigns",
			decide:    func() bool { return RoleScopesPermittedBy([]string{"foo:write"}, []string{"foo:read"}, pairs) },
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decide(); got != tt.wantAllow {
				t.Errorf("decision = %v; want %v", got, tt.wantAllow)
			}
		})
	}
}

// TestFailOpenClass_EmptyRoleScopesIsVacuouslyPermitted documents the one
// deliberate exception in this package: an assignment ceiling asked about a
// role that grants NOTHING permits it. That is not the fail-open direction —
// there is no privilege to escalate to — and the row is here so the behaviour
// is pinned rather than incidental.
func TestFailOpenClass_EmptyRoleScopesIsVacuouslyPermitted(t *testing.T) {
	for _, roleScopes := range [][]string{nil, {}} {
		if !RoleScopesPermittedBy(nil, roleScopes, nil) {
			t.Errorf("RoleScopesPermittedBy(nil, %v) = false; want true — a role granting nothing escalates nothing", roleScopes)
		}
	}
}
