package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
