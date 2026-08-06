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

// authURLFor returns the authorization URL BeginAuth builds for state.
//
// Before v0.25.0 these assertions were made against GetAuthURL, the bare
// authorization-URL builder that requested neither a nonce nor a PKCE
// challenge. That method was deleted, so the URL-shape assertions move onto the
// only remaining builder. BeginAuth adds nonce and code_challenge parameters;
// every assertion below is a "contains", so the additions are transparent to
// them.
func authURLFor(t *testing.T, p *Provider, state string) string {
	t.Helper()
	ch, err := p.BeginAuth(state)
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	return ch.URL
}

func TestNewProvider_DiscoveryAndAuthURL(t *testing.T) {
	srv := discoveryServer(t)
	defer srv.Close()

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           srv.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		RedirectURL:         "https://app.example/callback",
		Scopes:              []string{"openid", "email", "profile"},
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	authURL := authURLFor(t, p, "state-123")
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
		IssuerURL:           srv.URL,
		ClientID:            "id",
		ClientSecret:        "secret",
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	}); err == nil {
		t.Error("expected discovery failure to return an error")
	}
}

func TestNewProvider_RejectsHTTPIssuerByDefault(t *testing.T) {
	// HTTPS is required by default — a plaintext issuer must be rejected before
	// any discovery attempt, with no explicit opt-in required.
	_, err := NewProvider(Config{
		IssuerURL:    "http://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected an error for an http issuer by default")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected an HTTPS error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// HTTPS-by-default + RedirectURL (issue #57 sub-finding 1, issue #103)
// ---------------------------------------------------------------------------

func TestNewProvider_RejectsHTTPRedirectURLByDefault(t *testing.T) {
	// An https issuer is used here so the error can only come from the
	// RedirectURL scheme check, not the IssuerURL one.
	_, err := NewProvider(Config{
		IssuerURL:    "https://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "http://app.example/callback",
	})
	if err == nil {
		t.Fatal("expected an error for an http redirect URL by default")
	}
	if !strings.Contains(err.Error(), "HTTPS") || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("expected an HTTPS redirect URL error, got: %v", err)
	}
}

func TestNewProvider_AllowsEmptyRedirectURLByDefault(t *testing.T) {
	// An empty RedirectURL (e.g. a provider that only needs the OAuth2 config
	// for token exchange, not browser redirects) must not be rejected: the
	// check only fires when RedirectURL is non-empty.
	_, err := NewProvider(Config{
		IssuerURL:    "https://issuer.example",
		ClientID:     "id",
		ClientSecret: "secret",
	})
	if err != nil && strings.Contains(err.Error(), "redirect") {
		t.Errorf("expected no redirect-URL error for an empty RedirectURL, got: %v", err)
	}
}

func TestIsHTTPSURL_CaseInsensitiveScheme(t *testing.T) {
	// The scheme check must not reject a URL solely because of casing: RFC
	// 3986 defines "scheme" as case-insensitive, so a caller-provided
	// "HTTPS://" or "HttpS://" issuer/redirect URL must be accepted exactly
	// like a lowercase "https://" one, not rejected as if it were plaintext.
	cases := []struct {
		url  string
		want bool
	}{
		{"https://issuer.example", true},
		{"HTTPS://issuer.example", true},
		{"HttpS://issuer.example", true},
		{"http://issuer.example", false},
		{"HTTP://issuer.example", false},
		{"not-a-url with spaces", false},
	}
	for _, c := range cases {
		if got := isHTTPSURL(c.url); got != c.want {
			t.Errorf("isHTTPSURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestNewProvider_AcceptsHTTPSIssuerAndRedirectByDefault(t *testing.T) {
	// Full success path: both IssuerURL and RedirectURL are https (the secure
	// default), and discovery actually succeeds. This is the regression guard
	// that the RedirectURL check doesn't reject valid https input.
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
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil provider")
	}
}

func TestNewProvider_AllowInsecureIssuerTrueAllowsHTTPIssuerAndRedirect(t *testing.T) {
	// Explicit local/dev opt-out: with AllowInsecureIssuer set true, an http
	// issuer and http redirect URL are accepted — the RedirectURL check must
	// not fire when the caller has explicitly opted out of the HTTPS default.
	srv := discoveryServer(t)
	defer srv.Close()

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           srv.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		RedirectURL:         "http://app.example/callback",
		Scopes:              []string{"openid"},
		AllowInsecureIssuer: true,
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
		IssuerURL:           srv.URL,
		ClientID:            "id",
		ClientSecret:        "secret",
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
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
		IssuerURL:           srv.URL,
		ClientID:            "id",
		ClientSecret:        "secret",
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a discovery endpoint that never responds")
	}
	if elapsed > oidcHTTPTimeout+10*time.Second {
		t.Errorf("NewProvider took %s to fail, want within oidcHTTPTimeout (%s) plus slack", elapsed, oidcHTTPTimeout)
	}
}

func TestExchangeCode_SlowTokenEndpointFailsFast(t *testing.T) {
	// A token endpoint that never responds must not hang ExchangeCode forever:
	// contextWithBoundedClient bounds the token-exchange request to
	// oidcHTTPTimeout, the same as discovery/JWKS. ExchangeCode is called with
	// a bare context.Background() (no caller-supplied deadline) so this test
	// exercises the injected client, not an incidental caller timeout.
	block := make(chan struct{})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	// Order matters: unblock the handler goroutine before Close(), which
	// otherwise blocks until all outstanding requests complete.
	defer srv.Close()
	defer close(block)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		<-block // never respond
	})

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           srv.URL,
		ClientID:            "id",
		ClientSecret:        "secret",
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	start := time.Now()
	_, _, err = p.ExchangeAndVerify(context.Background(), "auth-code",
		CallbackSession{Nonce: "n", CodeVerifier: "v"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a token endpoint that never responds")
	}
	// Lower bound mirrors the discovery slow-endpoint tests above: catches a
	// regression where the timeout is accidentally slashed to near-zero.
	//
	// Upper bound is 2x oidcHTTPTimeout, not 1x: golang.org/x/oauth2's
	// RetrieveToken auto-probes the client-auth style (Config.Endpoint.AuthStyle
	// defaults to unknown) by trying one style, and on failure retrying once
	// with the other before giving up (internal.RetrieveToken in
	// golang.org/x/oauth2/internal/token.go) — so the very first exchange
	// against a given (tokenURL, clientID) pair can perform two bounded HTTP
	// round trips, not one. This is a pre-existing property of the oauth2
	// library's auth-style negotiation, orthogonal to this timeout fix; each
	// individual round trip is still bounded to oidcHTTPTimeout by the client
	// injected via contextWithBoundedClient; what this test guards against is
	// that bound being absent (i.e. hanging far longer than two round trips).
	if elapsed < oidcHTTPTimeout/2 {
		t.Errorf("ExchangeCode returned after only %s, want close to a multiple of oidcHTTPTimeout (%s)", elapsed, oidcHTTPTimeout)
	}
	if elapsed > 2*oidcHTTPTimeout+10*time.Second {
		t.Errorf("ExchangeCode took %s to fail, want within 2x oidcHTTPTimeout (%s) plus slack", elapsed, oidcHTTPTimeout)
	}
}

// ---------------------------------------------------------------------------
// contextWithBoundedClient / boundHTTPClient
// ---------------------------------------------------------------------------

func TestContextWithBoundedClient_NoExistingClientGetsDefault(t *testing.T) {
	got := contextWithBoundedClient(context.Background())
	client, ok := got.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		t.Fatal("expected an *http.Client on the returned context")
	}
	if client.Timeout != oidcHTTPTimeout {
		t.Errorf("Timeout = %s, want %s", client.Timeout, oidcHTTPTimeout)
	}
}

func TestContextWithBoundedClient_PreservesCallerTransport(t *testing.T) {
	// A caller that already injected a custom *http.Client into ctx (e.g.
	// carrying a private-CA root pool or mTLS certs) via the same
	// oidc.ClientContext/oauth2 context convention this package uses must not
	// have that Transport silently discarded — only the Timeout is capped.
	marker := &http.Transport{}
	callerClient := &http.Client{Transport: marker, Timeout: time.Hour}

	ctx := oidcpkg.ClientContext(context.Background(), callerClient)
	got := contextWithBoundedClient(ctx)

	client, ok := got.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		t.Fatal("expected an *http.Client on the returned context")
	}
	if client.Transport != marker {
		t.Error("expected the caller-supplied Transport to be preserved")
	}
	if client.Timeout != oidcHTTPTimeout {
		t.Errorf("Timeout = %s, want capped to oidcHTTPTimeout (%s)", client.Timeout, oidcHTTPTimeout)
	}
}

func TestContextWithBoundedClient_LeavesStricterCallerTimeoutAlone(t *testing.T) {
	// A caller whose client already has a tighter deadline than
	// oidcHTTPTimeout must not have it loosened, and the client itself must
	// not be needlessly replaced.
	callerClient := &http.Client{Timeout: time.Second}
	ctx := oidcpkg.ClientContext(context.Background(), callerClient)
	got := contextWithBoundedClient(ctx)

	client, ok := got.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		t.Fatal("expected an *http.Client on the returned context")
	}
	if client != callerClient {
		t.Error("expected the caller's own (already-strict) client to be reused unchanged")
	}
}

func TestNewProviderForConfig_BeginAuth(t *testing.T) {
	// A discovery-free provider still builds authorization URLs.
	p := NewProviderForConfig(&oauth2.Config{
		ClientID:    "my-client",
		RedirectURL: "https://app.example/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://issuer.example/auth"},
		Scopes:      []string{"openid"},
	})
	authURL := authURLFor(t, p, "state-xyz")
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

	// ExchangeAndVerify must refuse BEFORE performing the token exchange. A
	// Provider with no verifier can still reach a token endpoint perfectly
	// well, so "it returned an error" does not distinguish refusing from
	// exchanging-then-failing; only the endpoint knows. Point the config at a
	// counting server and require that it was never called — otherwise a
	// working authorization code is burned on an exchange whose ID token can
	// never be verified.
	var tokenCalls int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls++
		writeTestJSON(w, map[string]any{"access_token": "a", "token_type": "Bearer"})
	}))
	defer tokenSrv.Close()

	p2 := NewProviderForConfig(&oauth2.Config{
		ClientID: "my-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth", TokenURL: tokenSrv.URL},
	})
	tok, idToken, err := p2.ExchangeAndVerify(context.Background(), "auth-code",
		CallbackSession{Nonce: "n", CodeVerifier: "v"})
	if err == nil {
		t.Error("ExchangeAndVerify() error = nil, want a descriptive error")
	}
	if tok != nil || idToken != nil {
		t.Errorf("ExchangeAndVerify() = (%v, %v), want (nil, nil)", tok, idToken)
	}
	if tokenCalls != 0 {
		t.Errorf("token endpoint called %d time(s); ExchangeAndVerify must fail before "+
			"the exchange when it has no verifier to check the result with", tokenCalls)
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
	if ch.Session.Nonce == "" {
		t.Error("expected a non-empty nonce")
	}
	if ch.Session.CodeVerifier == "" {
		t.Error("expected a non-empty PKCE code verifier")
	}
	if ch.Session.Payload != nil {
		t.Errorf("BeginAuth stored a payload it was never given: %q", ch.Session.Payload)
	}
	for _, want := range []string{
		"state=state-1",
		"nonce=" + ch.Session.Nonce,
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
	if ch.Session.Nonce == ch2.Session.Nonce {
		t.Error("nonce is not unique across BeginAuth calls")
	}
	if ch.Session.CodeVerifier == ch2.Session.CodeVerifier {
		t.Error("PKCE verifier is not unique across BeginAuth calls")
	}
}

func TestExchangeAndVerify_NonceAndPKCE(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           idp.server.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		RedirectURL:         "https://app.example/callback",
		Scopes:              []string{"openid", "email"},
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	ch, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	idp.setNonce(ch.Session.Nonce) // the IdP echoes this nonce in the minted ID token

	tok, idToken, err := p.ExchangeAndVerify(context.Background(), "auth-code", ch.Session)
	if err != nil {
		t.Fatalf("ExchangeAndVerify: %v", err)
	}
	// The PKCE binding is applied by ExchangeAndVerify itself, with no option
	// for the caller to omit — this assertion is what pins that.
	if got := idp.codeVerifier(); got != ch.Session.CodeVerifier {
		t.Errorf("token endpoint received code_verifier %q, want %q", got, ch.Session.CodeVerifier)
	}
	if rawID, _ := tok.Extra("id_token").(string); rawID == "" {
		t.Fatal("token response missing id_token")
	}
	if idToken.Nonce != ch.Session.Nonce {
		t.Errorf("idToken.Nonce = %q, want %q", idToken.Nonce, ch.Session.Nonce)
	}
}

// TestExchangeAndVerify_RejectsMissingBinding is the structural half of the
// same guarantee: with ExchangeCode/WithPKCEVerifier deleted there is no
// compiling way to omit a binding, and a caller that loses one anyway — a
// dropped struct field, a state entry written by an older version, a
// zero-value CallbackSession — is refused before any network call rather than
// completing an unbound exchange.
func TestExchangeAndVerify_RejectsMissingBinding(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           idp.server.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	for _, tc := range []struct {
		name    string
		session CallbackSession
	}{
		{"zero value", CallbackSession{}},
		{"no code verifier", CallbackSession{Nonce: "n"}},
		{"no nonce", CallbackSession{CodeVerifier: "v"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, idToken, err := p.ExchangeAndVerify(context.Background(), "auth-code", tc.session)
			if err == nil {
				t.Fatal("expected an error for an incomplete CallbackSession")
			}
			if tok != nil || idToken != nil {
				t.Errorf("got (%v, %v), want (nil, nil)", tok, idToken)
			}
			if n := idp.tokenRequestCount(); n != 0 {
				t.Errorf("the token endpoint was called %d time(s) despite the missing "+
					"binding; ExchangeAndVerify must refuse before any network call, not "+
					"send an unbound request and fail on what comes back", n)
			}
		})
	}
}

// TestExchangeAndVerify_RejectsResponseWithoutIDToken pins that a successful
// token exchange whose response carries no id_token is a failure, not a partial
// success. Returning the *oauth2.Token alone here would hand the caller an
// authenticated-looking result with nothing verified behind it.
func TestExchangeAndVerify_RejectsResponseWithoutIDToken(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	idp.setOmitIDToken()
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           idp.server.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	tok, idToken, err := p.ExchangeAndVerify(context.Background(), "auth-code",
		CallbackSession{Nonce: "n", CodeVerifier: "v"})
	if err == nil {
		t.Fatal("expected an error for a token response with no id_token")
	}
	// Without the explicit check the empty string is handed to the verifier,
	// which also fails — but with a signature/parse error that tells an operator
	// nothing about the actual fault. Pin the diagnosis, not just the refusal.
	if !strings.Contains(err.Error(), "no id_token") {
		t.Errorf("error = %v, want it to name the missing id_token", err)
	}
	if tok != nil || idToken != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", tok, idToken)
	}
}

func TestExchangeAndVerify_NonceMismatch(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           idp.server.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	idp.setNonce("server-nonce")

	// A token minted for a DIFFERENT login must not be accepted for this one.
	if _, _, err := p.ExchangeAndVerify(context.Background(), "auth-code",
		CallbackSession{Nonce: "different-nonce", CodeVerifier: "v"}); err == nil {
		t.Fatal("expected an error for a nonce mismatch")
	}
}

// TestExchangeAndVerify_RejectsIDTokenWithoutNonce pins the consequence of
// deleting the legacy no-nonce flow. GetAuthURL (which never requested a
// nonce) and the optionless VerifyIDToken (which accepted a token that carried
// none) were removed together in v0.25.0: every authorization request this
// package can now build carries a nonce, so an ID token that comes back
// WITHOUT one means the identity provider dropped the binding, and the only
// safe reading of that is failure.
//
// Under the removed API this same shape was an explicit success case
// (TestVerifyIDToken_NoNonceClaimSucceedsWithoutExpectation).
func TestExchangeAndVerify_RejectsIDTokenWithoutNonce(t *testing.T) {
	idp := newMockIDP(t, "my-client")
	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           idp.server.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	// idp.setNonce is never called, so the minted ID token carries no nonce.
	if _, _, err := p.ExchangeAndVerify(context.Background(), "auth-code",
		CallbackSession{Nonce: "expected-nonce", CodeVerifier: "v"}); err == nil {
		t.Fatal("expected an error for an ID token that carries no nonce claim")
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
	omitIDToken      bool
	tokenRequests    int
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
		idp.tokenRequests++
		idp.lastCodeVerifier = r.FormValue("code_verifier")
		nonce := idp.nonce
		omit := idp.omitIDToken
		idp.mu.Unlock()

		body := map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		}
		if !omit {
			body["id_token"] = idp.mintIDToken(t, nonce)
		}
		writeTestJSON(w, body)
	})

	return idp
}

func (idp *mockIDP) setNonce(n string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.nonce = n
}

// setOmitIDToken makes the token endpoint answer with a valid OAuth2 token
// response that carries no id_token — an OAuth2-only provider, or an OIDC one
// misconfigured to drop the claim.
func (idp *mockIDP) setOmitIDToken() {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.omitIDToken = true
}

// tokenRequestCount reports how many times the token endpoint was called. It
// is what distinguishes "refused before any network call" from "reached the
// identity provider and failed afterwards" — the two are indistinguishable by
// the returned error alone, and only the first is the guarantee
// ExchangeAndVerify makes.
func (idp *mockIDP) tokenRequestCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.tokenRequests
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
		IssuerURL:           idp.server.URL,
		ClientID:            "test-client",
		ClientSecret:        "test-secret",
		AllowInsecureIssuer: true, // idp.server is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}
	raw := idp.mintIDTokenWithClaims(t, extra)
	idToken, err := p.verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
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
