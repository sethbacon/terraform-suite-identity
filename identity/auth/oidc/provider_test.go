package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	oidcpkg "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestNewProvider_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing issuer", Config{ClientID: "id", ClientSecret: "secret"}},
		{"missing client id", Config{IssuerURL: "https://issuer.example", ClientSecret: "secret"}},
		{"missing client secret", Config{IssuerURL: "https://issuer.example", ClientID: "id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProvider(tc.cfg); err == nil {
				t.Errorf("expected an error for %q, got nil", tc.name)
			}
		})
	}
}

// discoveryServer spins up an OIDC discovery document whose issuer matches its
// own URL (the go-oidc library requires the issuer in the document to match the
// configured issuer URL).
func discoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
			"end_session_endpoint":   srv.URL + "/logout",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv
}

func TestNewProvider_DiscoveryAndAuthURL(t *testing.T) {
	srv := discoveryServer(t)
	defer srv.Close()

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    srv.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURL:  "https://app.example/callback",
		Scopes:       []string{"openid", "email", "profile"},
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	authURL := p.GetAuthURL("state-123")
	for _, want := range []string{
		srv.URL + "/auth",
		"client_id=my-client",
		"response_type=code",
		"state=state-123",
		"redirect_uri=",
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("auth URL %q missing %q", authURL, want)
		}
	}

	if got := p.GetEndSessionEndpoint(); got != srv.URL+"/logout" {
		t.Errorf("end session endpoint = %q, want %q", got, srv.URL+"/logout")
	}
}

func TestNewProvider_DiscoveryFailure(t *testing.T) {
	// A server that 404s the discovery document should yield an error.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if _, err := NewProvider(Config{
		IssuerURL:    srv.URL,
		ClientID:     "id",
		ClientSecret: "secret",
	}); err == nil {
		t.Error("expected discovery failure to return an error")
	}
}

func TestNewProvider_RequireHTTPSRejectsHTTPIssuer(t *testing.T) {
	// RequireHTTPS must reject a plaintext issuer before any discovery attempt.
	_, err := NewProvider(Config{
		IssuerURL:    "http://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
		RequireHTTPS: true,
	})
	if err == nil {
		t.Fatal("expected an error for an http issuer when RequireHTTPS is set")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected an HTTPS error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RequireHTTPS + RedirectURL (issue #57 sub-finding 1)
// ---------------------------------------------------------------------------

func TestNewProvider_RequireHTTPSRejectsHTTPRedirectURL(t *testing.T) {
	// An https issuer is used here so the error can only come from the new
	// RedirectURL scheme check, not the pre-existing IssuerURL one.
	_, err := NewProvider(Config{
		IssuerURL:    "https://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "http://app.example/callback",
		RequireHTTPS: true,
	})
	if err == nil {
		t.Fatal("expected an error for an http redirect URL when RequireHTTPS is set")
	}
	if !strings.Contains(err.Error(), "HTTPS") || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("expected an HTTPS redirect URL error, got: %v", err)
	}
}

func TestNewProvider_RequireHTTPSAllowsEmptyRedirectURL(t *testing.T) {
	// An empty RedirectURL (e.g. a provider that only needs the OAuth2 config
	// for token exchange, not browser redirects) must not be rejected: the
	// check only fires when RedirectURL is non-empty.
	_, err := NewProvider(Config{
		IssuerURL:    "https://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
		RequireHTTPS: true,
	})
	if err != nil && strings.Contains(err.Error(), "redirect") {
		t.Errorf("expected no redirect-URL error for an empty RedirectURL, got: %v", err)
	}
}

func TestNewProvider_RequireHTTPSAcceptsHTTPSIssuerAndRedirect(t *testing.T) {
	// Full success path: RequireHTTPS is set, both IssuerURL and RedirectURL
	// are https, and discovery actually succeeds. This is the regression guard
	// that the new RedirectURL check doesn't reject valid https input.
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
		})
	})

	// The injected *http.Client (added by NewProviderWithContext for the
	// HTTP-timeout fix) uses http.DefaultTransport, which by default doesn't
	// trust httptest's self-signed certificate. Swap in a transport that
	// trusts this server's certificate for the duration of the call, then
	// restore the original so no other test is affected.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	origTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = origTransport })
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	p, err := NewProvider(Config{
		IssuerURL:    srv.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURL:  "https://app.example/callback",
		RequireHTTPS: true,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil provider")
	}
}

func TestNewProvider_RequireHTTPSFalseAllowsHTTPIssuerAndRedirect(t *testing.T) {
	// Regression guard: with RequireHTTPS left at its default (false), an http
	// issuer and http redirect URL must be accepted exactly as before this
	// change — the new RedirectURL check must not fire when RequireHTTPS is
	// false.
	srv := discoveryServer(t)
	defer srv.Close()

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    srv.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURL:  "http://app.example/callback",
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil provider")
	}
}

// ---------------------------------------------------------------------------
// HTTP timeout (issue #57 sub-finding 2)
// ---------------------------------------------------------------------------

func TestNewProviderWithContext_SlowDiscoveryFailsFast(t *testing.T) {
	// A discovery endpoint that never responds must not hang the caller
	// forever: the client injected via oidc.ClientContext bounds the request
	// to oidcHTTPTimeout.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond
	}))
	// Order matters: unblock the handler goroutine before Close(), which
	// otherwise blocks until all outstanding requests complete.
	defer srv.Close()
	defer close(block)

	start := time.Now()
	_, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    srv.URL,
		ClientID:     "id",
		ClientSecret: "secret",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a discovery endpoint that never responds")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("expected a deadline-exceeded-flavored error, got: %v", err)
	}
	// Lower bound: catches a regression where the timeout is accidentally
	// slashed to near-zero (the test would otherwise still pass the upper
	// bound check below). Upper bound: generous slack over oidcHTTPTimeout to
	// absorb CI scheduling jitter while still failing if construction hangs
	// far longer than the configured timeout (i.e. the client-level Timeout
	// isn't actually wired in).
	if elapsed < oidcHTTPTimeout/2 {
		t.Errorf("NewProviderWithContext returned after only %s, want close to oidcHTTPTimeout (%s)", elapsed, oidcHTTPTimeout)
	}
	if elapsed > oidcHTTPTimeout+10*time.Second {
		t.Errorf("NewProviderWithContext took %s to fail, want within oidcHTTPTimeout (%s) plus slack", elapsed, oidcHTTPTimeout)
	}
}

func TestNewProvider_SlowDiscoveryFailsFast(t *testing.T) {
	// Same as above, but through the context.Background() convenience
	// constructor, which must also get a construction deadline rather than
	// relying on the caller's own (nonexistent) context timeout.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond
	}))
	defer srv.Close()
	defer close(block)

	start := time.Now()
	_, err := NewProvider(Config{
		IssuerURL:    srv.URL,
		ClientID:     "id",
		ClientSecret: "secret",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a discovery endpoint that never responds")
	}
	if elapsed > oidcHTTPTimeout+10*time.Second {
		t.Errorf("NewProvider took %s to fail, want within oidcHTTPTimeout (%s) plus slack", elapsed, oidcHTTPTimeout)
	}
}

func TestNewProviderForConfig_GetAuthURL(t *testing.T) {
	// A discovery-free provider still builds authorization URLs.
	p := NewProviderForConfig(&oauth2.Config{
		ClientID:    "my-client",
		RedirectURL: "https://app.example/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://issuer.example/auth"},
		Scopes:      []string{"openid"},
	})
	authURL := p.GetAuthURL("state-xyz")
	for _, want := range []string{"https://issuer.example/auth", "client_id=my-client", "state=state-xyz"} {
		if !strings.Contains(authURL, want) {
			t.Errorf("auth URL %q missing %q", authURL, want)
		}
	}
}

func TestNewProviderForConfig_DiscoveryMethodsDoNotPanic(t *testing.T) {
	// A discovery-free provider has no verifier/provider. The discovery-dependent
	// methods must degrade gracefully instead of nil-panicking.
	p := NewProviderForConfig(&oauth2.Config{
		ClientID: "my-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth"},
	})

	if got := p.GetEndSessionEndpoint(); got != "" {
		t.Errorf("GetEndSessionEndpoint() = %q, want empty", got)
	}

	tok, err := p.VerifyIDToken(context.Background(), "any.jwt.value")
	if err == nil {
		t.Error("VerifyIDToken() error = nil, want a descriptive error")
	}
	if tok != nil {
		t.Errorf("VerifyIDToken() token = %v, want nil", tok)
	}
}

// ---------------------------------------------------------------------------
// Nonce + PKCE (BeginAuth / ExchangeCode / VerifyIDToken)
// ---------------------------------------------------------------------------

func TestBeginAuth_IncludesNonceAndPKCE(t *testing.T) {
	p := NewProviderForConfig(&oauth2.Config{
		ClientID:    "my-client",
		RedirectURL: "https://app.example/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://issuer.example/auth"},
		Scopes:      []string{"openid"},
	})

	ch, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	if ch.Nonce == "" {
		t.Error("expected a non-empty nonce")
	}
	if ch.CodeVerifier == "" {
		t.Error("expected a non-empty PKCE code verifier")
	}
	for _, want := range []string{
		"state=state-1",
		"nonce=" + ch.Nonce,
		"code_challenge=",
		"code_challenge_method=S256",
	} {
		if !strings.Contains(ch.URL, want) {
			t.Errorf("auth URL %q missing %q", ch.URL, want)
		}
	}

	// Two calls must produce distinct nonces and verifiers.
	ch2, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth (2): %v", err)
	}
	if ch.Nonce == ch2.Nonce {
		t.Error("nonce is not unique across BeginAuth calls")
	}
	if ch.CodeVerifier == ch2.CodeVerifier {
		t.Error("PKCE verifier is not unique across BeginAuth calls")
	}
}

func TestExchangeAndVerify_NonceAndPKCE(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    idp.server.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURL:  "https://app.example/callback",
		Scopes:       []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	ch, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	idp.setNonce(ch.Nonce) // the IdP echoes this nonce in the minted ID token

	tok, err := p.ExchangeCode(context.Background(), "auth-code", WithPKCEVerifier(ch.CodeVerifier))
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if got := idp.codeVerifier(); got != ch.CodeVerifier {
		t.Errorf("token endpoint received code_verifier %q, want %q", got, ch.CodeVerifier)
	}

	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		t.Fatal("token response missing id_token")
	}

	idToken, err := p.VerifyIDToken(context.Background(), rawID, WithExpectedNonce(ch.Nonce))
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if idToken.Nonce != ch.Nonce {
		t.Errorf("idToken.Nonce = %q, want %q", idToken.Nonce, ch.Nonce)
	}
}

func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    idp.server.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	idp.setNonce("server-nonce")
	tok, err := p.ExchangeCode(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	rawID, _ := tok.Extra("id_token").(string)

	// A mismatched nonce must fail verification.
	if _, err := p.VerifyIDToken(context.Background(), rawID, WithExpectedNonce("different-nonce")); err == nil {
		t.Fatal("expected an error for a nonce mismatch")
	}

	// Without a nonce expectation, verification succeeds (backward compatible).
	if _, err := p.VerifyIDToken(context.Background(), rawID); err != nil {
		t.Errorf("VerifyIDToken without nonce expectation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// mockIDP — an OIDC IdP test double that serves discovery + JWKS and mints
// signed ID tokens, used to exercise the nonce/PKCE flow end to end.
// ---------------------------------------------------------------------------

type mockIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string

	mu               sync.Mutex
	lastCodeVerifier string
	nonce            string
}

func newMockIDP(t *testing.T, clientID string) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	idp := &mockIDP{key: key, kid: "test-key", clientID: clientID}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idp.server = srv
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		pub := idp.key.PublicKey
		writeTestJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": idp.kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		idp.lastCodeVerifier = r.FormValue("code_verifier")
		nonce := idp.nonce
		idp.mu.Unlock()

		writeTestJSON(w, map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"id_token":     idp.mintIDToken(t, nonce),
		})
	})

	return idp
}

func (idp *mockIDP) setNonce(n string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.nonce = n
}

func (idp *mockIDP) codeVerifier() string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.lastCodeVerifier
}

func (idp *mockIDP) mintIDToken(t *testing.T, nonce string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   idp.server.URL,
		"sub":   "user-123",
		"aud":   idp.clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "user@example.com",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = idp.kid
	signed, err := tok.SignedString(idp.key)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// ExtractUserInfo / ExtractGroups (claim-resolution logic)
// ---------------------------------------------------------------------------

// mintIDTokenWithClaims signs an arbitrary claim set, merged over a minimal
// base (iss/sub/aud/exp/iat), for ad hoc claim-shape tests beyond the fixed
// shape mintIDToken uses for the nonce/PKCE tests. A key in extra overrides
// the base (e.g. "sub": "" to test a missing-subject token).
func (idp *mockIDP) mintIDTokenWithClaims(t *testing.T, extra jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": idp.server.URL,
		"sub": "user-123",
		"aud": idp.clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = idp.kid
	signed, err := tok.SignedString(idp.key)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}

// verifiedIDToken builds a Provider against a fresh mock IdP, mints a token
// with the given extra claims, and verifies it, returning a real
// *oidcpkg.IDToken so ExtractUserInfo/ExtractGroups can be exercised against
// claim shapes a live IdP could actually send.
func verifiedIDToken(t *testing.T, extra jwt.MapClaims) *oidcpkg.IDToken {
	t.Helper()
	idp := newMockIDP(t, "test-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:    idp.server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}
	raw := idp.mintIDTokenWithClaims(t, extra)
	idToken, err := p.VerifyIDToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	return idToken
}

func TestExtractUserInfo_EmailFallbackOrder(t *testing.T) {
	// email present alongside every fallback claim: email wins, and only the
	// standard email claim carries the verified signal.
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"email":              "primary@example.com",
		"email_verified":     true,
		"preferred_username": "upn-style@example.com",
		"upn":                "upn@example.com",
		"unique_name":        "uniquename@example.com",
		"name":               "Primary User",
	})
	sub, email, name, verified, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if sub != "user-123" {
		t.Errorf("sub = %q, want user-123", sub)
	}
	if email != "primary@example.com" {
		t.Errorf("email = %q, want the standard email claim to win", email)
	}
	if name != "Primary User" {
		t.Errorf("name = %q, want Primary User", name)
	}
	if !verified {
		t.Error("emailVerified = false, want true (email_verified=true on the standard email claim)")
	}
}

func TestExtractUserInfo_FallsBackToPreferredUsername(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"preferred_username": "upn-style@example.com",
		"upn":                "upn@example.com",
		"unique_name":        "uniquename@example.com",
	})
	_, email, _, verified, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if email != "upn-style@example.com" {
		t.Errorf("email = %q, want preferred_username fallback", email)
	}
	if verified {
		t.Error("emailVerified = true, want false (UPN-family fallbacks are never verified)")
	}
}

func TestExtractUserInfo_FallsBackToUPN(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"upn":         "upn@example.com",
		"unique_name": "uniquename@example.com",
	})
	_, email, _, _, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if email != "upn@example.com" {
		t.Errorf("email = %q, want upn fallback", email)
	}
}

func TestExtractUserInfo_FallsBackToUniqueName(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"unique_name": "uniquename@example.com",
	})
	_, email, _, _, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if email != "uniquename@example.com" {
		t.Errorf("email = %q, want unique_name fallback", email)
	}
}

func TestExtractUserInfo_MissingEmailIdentifier(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{})
	_, _, _, _, err := (&Provider{}).ExtractUserInfo(idToken)
	if err == nil {
		t.Fatal("expected an error when no email-shaped claim is present")
	}
	if !strings.Contains(err.Error(), "missing email identifier") {
		t.Errorf("error = %q, want it to mention the missing email identifier", err.Error())
	}
}

func TestExtractUserInfo_MissingSub(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"sub":   "",
		"email": "user@example.com",
	})
	_, _, _, _, err := (&Provider{}).ExtractUserInfo(idToken)
	if err == nil {
		t.Fatal("expected an error for a missing 'sub' claim")
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("error = %q, want it to mention the missing sub claim", err.Error())
	}
}

func TestExtractUserInfo_NameDefaultsToEmail(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"email": "user@example.com",
		// name intentionally omitted
	})
	_, email, name, _, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if name != email {
		t.Errorf("name = %q, want it to default to email %q", name, email)
	}
}

func TestExtractUserInfo_EmailVerifiedStringVariant(t *testing.T) {
	// Some IdPs emit email_verified as a string rather than a JSON boolean.
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"email":          "user@example.com",
		"email_verified": "true",
	})
	_, _, _, verified, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if !verified {
		t.Error("emailVerified = false, want true for a string \"true\" email_verified claim")
	}
}

func TestExtractUserInfo_EmailVerifiedAbsentDefaultsFalse(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"email": "user@example.com",
		// email_verified intentionally omitted
	})
	_, _, _, verified, err := (&Provider{}).ExtractUserInfo(idToken)
	if err != nil {
		t.Fatalf("ExtractUserInfo: %v", err)
	}
	if verified {
		t.Error("emailVerified = true, want false when the claim is absent")
	}
}

func TestExtractGroups_AbsentClaim(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{"email": "user@example.com"})
	if got := (&Provider{}).ExtractGroups(idToken, "groups"); got != nil {
		t.Errorf("ExtractGroups() = %v, want nil for an absent claim", got)
	}
}

func TestExtractGroups_EmptyClaimName(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{"groups": []string{"admins"}})
	if got := (&Provider{}).ExtractGroups(idToken, ""); got != nil {
		t.Errorf("ExtractGroups() = %v, want nil for an empty claim name", got)
	}
}

func TestExtractGroups_NonArrayClaim(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{"groups": "not-an-array"})
	if got := (&Provider{}).ExtractGroups(idToken, "groups"); got != nil {
		t.Errorf("ExtractGroups() = %v, want nil for a non-array claim", got)
	}
}

func TestExtractGroups_ArrayOfStrings(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{"groups": []string{"admins", "developers"}})
	got := (&Provider{}).ExtractGroups(idToken, "groups")
	if len(got) != 2 || got[0] != "admins" || got[1] != "developers" {
		t.Errorf("ExtractGroups() = %v, want [admins developers]", got)
	}
}

func TestExtractGroups_MixedTypeArrayKeepsOnlyStrings(t *testing.T) {
	idToken := verifiedIDToken(t, jwt.MapClaims{
		"groups": []any{"admins", 123, "developers", true, ""},
	})
	got := (&Provider{}).ExtractGroups(idToken, "groups")
	if len(got) != 2 || got[0] != "admins" || got[1] != "developers" {
		t.Errorf("ExtractGroups() = %v, want only the string elements [admins developers] (non-strings and empty string dropped)", got)
	}
}
