// Package oidc implements a generic OpenID Connect provider shared across the
// Terraform suite. It performs discovery, builds authorization URLs, exchanges
// authorization codes, and verifies ID tokens. Configuration is supplied by the
// caller (apps resolve it from env/DB); this package is storage- and app-neutral.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

// oidcHTTPTimeout bounds every HTTP round trip this package makes to an
// identity provider: OIDC discovery (the initial NewProvider/NewProviderWithContext
// call), the JWKS key-set fetches/refreshes performed later during ID-token
// verification (go-oidc reuses the *http.Client supplied via the discovery
// context for the lifetime of the resulting *oidc.Provider — see
// github.com/coreos/go-oidc/v3/oidc's Provider.client / remoteKeySet), and the
// authorization-code token-exchange call made by ExchangeAndVerify. Without an
// explicit client, these fall back to http.DefaultClient, which has no
// Timeout and can hang indefinitely against a slow or unresponsive issuer. 15
// seconds comfortably covers discovery + JWKS fetches + token exchange against
// a healthy IdP (including ones a few network hops away) while still failing
// fast enough that a hung issuer can't wedge a caller's startup or a request
// goroutine.
const oidcHTTPTimeout = 15 * time.Second

// newGuardedClient builds THE client this package uses for every outbound
// request, from the deployment's egress guard and the caller's TLS material.
//
// There is exactly one of these per Provider and no way to supply a different
// one. Before v0.25.0 a caller could install an arbitrary *http.Client on the
// context (the oidc.ClientContext / oauth2.HTTPClient convention) and this
// package would adopt it, capping only its Timeout — which meant the egress
// guard was, for the single most attacker-adjacent surface in the module,
// opt-out by accident. The legitimate reason to do that was always TLS
// material this package cannot know about (a private-CA root pool, mTLS client
// certificates for an internal IdP); that reason is now served by
// Config.TLSClientConfig, which reaches the transport WITHOUT displacing the
// dialer. A client found on the context is now an error, not an override.
func newGuardedClient(cfg Config) *http.Client {
	return httpsafe.NewClientWithTLS(oidcHTTPTimeout, cfg.EgressGuard, cfg.TLSClientConfig)
}

// errCallerClientOnContext is returned when the caller installed its own
// *http.Client on the context. Silently ignoring it would drop TLS material the
// caller believes is in effect; silently honouring it would drop the egress
// guard. Neither is acceptable, so this fails closed and names the replacement.
var errCallerClientOnContext = errors.New(
	"oidc: the context carries a caller-supplied *http.Client (oidc.ClientContext/oauth2.HTTPClient), " +
		"which this package no longer adopts: an arbitrary client displaces the egress guard that " +
		"protects the discovered token_endpoint and jwks_uri. Put TLS material (private-CA roots, mTLS " +
		"certificates) in Config.TLSClientConfig instead, and the deployment's allow-list in Config.EgressGuard")

// Config holds the resolved OIDC settings required to construct a Provider.
// Apps resolve these values from their own configuration (env, file or DB)
// before constructing the provider.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	// AllowInsecureIssuer opts out of the default HTTPS requirement for the
	// issuer and redirect URLs, AND for the endpoints read out of the discovery
	// document (authorization_endpoint, token_endpoint, jwks_uri,
	// end_session_endpoint). An HTTP issuer means discovery and JWKS key
	// material are fetched over plaintext, allowing a MITM to substitute
	// signing keys and forge ID tokens accepted by the verifier — so HTTPS is
	// required unless this is explicitly set. Set it true only for local/dev
	// stacks that use an http issuer; production callers must leave it false.
	//
	// It does NOT opt out of EgressGuard: the scheme rule and the destination
	// rule are separate, and a dev stack that needs a loopback or RFC 1918 IdP
	// must say so in the deployment's allow-list rather than getting it for
	// free with the plaintext opt-out.
	AllowInsecureIssuer bool

	// EgressGuard applies the deployment's egress policy (security.egress.allowlist)
	// to every outbound request this package makes: discovery, the JWKS
	// key-set fetches, and the authorization-code token exchange.
	//
	// A nil guard is the STRICT default policy — loopback, RFC 1918, link-local
	// (including the cloud metadata address), CGNAT and IPv6 ULA are all denied.
	// A deployment whose identity provider lives on an internal address (the
	// common case for a self-hosted IdP, and for every local dev stack) MUST
	// pass a guard built from its allow-list, or provider construction will
	// fail naming the denied destination. This is a deployment-configuration
	// requirement introduced in v0.25.0; see UPGRADING.md.
	//
	// The guard is applied at BOTH ends: the discovered token_endpoint and
	// jwks_uri are pre-flighted against it at construction (so a hostile
	// discovery document is refused before any credential-bearing request is
	// built), and the client's dialer re-checks every resolved IP at connect
	// time (so a name that changes its answer later still cannot reach a denied
	// address).
	EgressGuard *httpsafe.Guard

	// TLSClientConfig supplies TLS material this package cannot know about —
	// a private-CA root pool, or mTLS client certificates an internal IdP
	// requires. It is installed on the guarded transport, so it does NOT
	// displace the egress guard the way a caller-substituted *http.Client did
	// before v0.25.0. It is cloned, so the caller may keep and mutate its own
	// *tls.Config afterwards. Nil means the platform defaults.
	TLSClientConfig *tls.Config
}

// Provider wraps the generic OIDC provider, verifier and OAuth2 config.
type Provider struct {
	verifier *oidc.IDTokenVerifier
	config   *oauth2.Config
	provider *oidc.Provider

	// httpClient is the guarded client built at construction. Every outbound
	// request this Provider makes for the rest of its life uses it: go-oidc
	// captured it for the JWKS key set, and ExchangeAndVerify installs it on
	// the exchange context so a per-request context cannot substitute another.
	httpClient *http.Client

	// endSessionEndpoint is the discovery document's end_session_endpoint,
	// already scheme-validated at construction. Stored rather than re-read so
	// GetEndSessionEndpoint cannot hand back a value that skipped the check.
	endSessionEndpoint string
}

// NewProvider initializes a new OIDC provider using a background context. The
// underlying discovery request (and any subsequent JWKS refresh) is bounded by
// oidcHTTPTimeout, so this call cannot hang forever against an unresponsive
// issuer; callers that need a different deadline, or that want to cancel
// construction early, should use NewProviderWithContext instead.
func NewProvider(cfg Config) (*Provider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), oidcHTTPTimeout)
	defer cancel()
	return NewProviderWithContext(ctx, cfg)
}

// NewProviderWithContext initializes a new OIDC provider with the given context.
// It performs OIDC discovery against the issuer URL, so the context governs the
// discovery request. Discovery (and the JWKS key-set fetches/refreshes made
// later during ID-token verification) are additionally bounded by
// oidcHTTPTimeout via an injected *http.Client, regardless of the caller's own
// context deadline.
func NewProviderWithContext(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is required")
	}

	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OIDC client ID is required")
	}

	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC client secret is required")
	}

	if !cfg.AllowInsecureIssuer && !isHTTPSURL(cfg.IssuerURL) {
		return nil, fmt.Errorf("OIDC issuer URL must use HTTPS, got: %q (set AllowInsecureIssuer to allow an http issuer for local/dev)", cfg.IssuerURL)
	}

	if !cfg.AllowInsecureIssuer && cfg.RedirectURL != "" && !isHTTPSURL(cfg.RedirectURL) {
		return nil, fmt.Errorf("OIDC redirect URL must use HTTPS, got: %q (set AllowInsecureIssuer to allow an http redirect URL for local/dev)", cfg.RedirectURL)
	}

	if _, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return nil, errCallerClientOnContext
	}

	httpClient := newGuardedClient(cfg)
	discoveryCtx := oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(discoveryCtx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	endSession, err := validateDiscoveredEndpoints(ctx, cfg, provider)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		// Config arrives by value, so its string fields are already ours, but
		// the Scopes slice header still points at the caller's backing array.
		// Copy it: the provider requests these scopes on every subsequent
		// authorization URL, and a caller that keeps its Config (the normal
		// pattern) must not be able to change them after construction.
		Scopes: append([]string(nil), cfg.Scopes...),
	}

	return &Provider{
		verifier:           verifier,
		config:             oauth2Config,
		provider:           provider,
		httpClient:         httpClient,
		endSessionEndpoint: endSession,
	}, nil
}

// discoveryDocument is the subset of the OIDC discovery document this package
// acts on. Every field here is ATTACKER-INFLUENCEABLE: it is asserted by the
// issuer, not configured by the operator, so a hostile or compromised issuer —
// or one whose reverse proxy terminates TLS incorrectly — chooses these values.
// Only IssuerURL and RedirectURL come from the caller.
type discoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// validateDiscoveredEndpoints applies the module's two egress rules to the
// endpoints the issuer advertised, and returns the validated
// end_session_endpoint (empty if the issuer advertises none).
//
// The endpoints split by what this process does with them:
//
//   - token_endpoint and jwks_uri are DIALED BY THIS PACKAGE. They get both
//     rules: the scheme rule (an http token endpoint puts the client_secret and
//     the authorization code on the wire in cleartext; an http jwks_uri fetches
//     signing keys a MITM can substitute, yielding forged ID tokens that pass
//     the verifier) and the egress rule (the destination must be reachable
//     under the deployment's allow-list). Both are also required to be present:
//     OIDC Discovery makes jwks_uri mandatory, and an authorization-code flow
//     cannot complete without a token endpoint, so an absent one is a
//     misconfiguration that would otherwise surface much later as a confusing
//     exchange failure.
//
//   - authorization_endpoint and end_session_endpoint are BROWSER REDIRECT
//     TARGETS — this process never dials them, the user agent does. The egress
//     rule is therefore not ours to apply (the browser resolves the name from
//     its own network position, which is not this one), but the scheme rule
//     still is: a plaintext authorization endpoint exposes the authorization
//     request, and a plaintext end_session_endpoint exposes the id_token_hint.
//
// userinfo_endpoint is deliberately absent: this package never fetches it
// (ExtractUserInfo reads the ID token's own claims), and validating an endpoint
// nothing uses would fail deployments over a field that cannot hurt them.
func validateDiscoveredEndpoints(ctx context.Context, cfg Config, provider *oidc.Provider) (string, error) {
	var doc discoveryDocument
	if err := provider.Claims(&doc); err != nil {
		return "", fmt.Errorf("failed to read the OIDC discovery document: %w", err)
	}

	dialed := []struct{ name, raw string }{
		{"token_endpoint", doc.TokenEndpoint},
		{"jwks_uri", doc.JWKSURI},
	}
	for _, ep := range dialed {
		if ep.raw == "" {
			return "", fmt.Errorf("OIDC discovery document from issuer %q advertises no %s", cfg.IssuerURL, ep.name)
		}
		if err := checkDiscoveredScheme(cfg, ep.name, ep.raw); err != nil {
			return "", err
		}
		if err := cfg.EgressGuard.ValidateURL(ctx, ep.raw); err != nil {
			return "", fmt.Errorf("OIDC discovery document from issuer %q advertises a %s this deployment refuses to reach (%s): %w",
				cfg.IssuerURL, ep.name, ep.raw, err)
		}
	}

	redirectTargets := []struct{ name, raw string }{
		{"authorization_endpoint", doc.AuthorizationEndpoint},
		{"end_session_endpoint", doc.EndSessionEndpoint},
	}
	for _, ep := range redirectTargets {
		if ep.raw == "" {
			continue
		}
		if err := checkDiscoveredScheme(cfg, ep.name, ep.raw); err != nil {
			return "", err
		}
	}

	return doc.EndSessionEndpoint, nil
}

// checkDiscoveredScheme applies the same HTTPS rule to a discovered endpoint
// that NewProviderWithContext already applies to the caller-supplied IssuerURL,
// gated on the same AllowInsecureIssuer escape hatch.
func checkDiscoveredScheme(cfg Config, name, raw string) error {
	if cfg.AllowInsecureIssuer || isHTTPSURL(raw) {
		return nil
	}
	return fmt.Errorf("OIDC discovery document from issuer %q advertises a non-HTTPS %s: %q "+
		"(set AllowInsecureIssuer to allow plaintext discovered endpoints for local/dev)",
		cfg.IssuerURL, name, raw)
}

// isHTTPSURL reports whether rawURL parses as an absolute URL with an https
// scheme. The scheme comparison is case-insensitive per RFC 3986 (section
// 3.1: "scheme" is case-insensitive), so "HTTPS://" and "HttpS://" are
// accepted exactly like "https://" — a plain strings.HasPrefix("https://")
// check would incorrectly reject those.
func isHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// NewProviderForConfig constructs a Provider backed by the given oauth2 config
// without performing OIDC discovery. Intended for sibling packages (e.g. an
// Azure AD adapter) and tests that need the OAuth2 methods (BeginAuth, and the
// token-exchange half of ExchangeAndVerify) without a live identity provider.
// Methods that depend on the discovery document or verifier (the verification
// half of ExchangeAndVerify, GetEndSessionEndpoint) are not usable on a
// Provider built this way.
//
// The config is copied, not retained: the returned Provider shares no memory
// with cfg, so the caller may keep and reuse (or mutate) its own *oauth2.Config
// without changing the client id, secret, redirect URL, endpoint or scopes this
// Provider will use for every later BeginAuth/BeginAuthSession/ExchangeAndVerify.
func NewProviderForConfig(cfg *oauth2.Config) *Provider {
	if cfg == nil {
		return &Provider{}
	}
	// oauth2.Config's only reference-typed field is Scopes ([]string); every
	// other field, Endpoint included, is a struct of values. So the struct
	// copy plus a fresh Scopes slice is the full depth required.
	cp := *cfg
	cp.Scopes = append([]string(nil), cfg.Scopes...)
	return &Provider{config: &cp}
}

// nonceLength is the number of random bytes used for the OIDC nonce.
const nonceLength = 32

// AuthChallenge holds an authorization URL together with the per-login bindings
// the caller must persist (keyed to the state token) and supply back at the
// callback.
type AuthChallenge struct {
	// URL is the authorization endpoint URL to redirect the user agent to.
	URL string
	// Session carries this login's OIDC nonce and PKCE code verifier. Persist
	// it as ONE value keyed to the state token and hand it back to
	// ExchangeAndVerify verbatim: there is no per-binding option to apply, and
	// therefore none to forget. CallbackSession is JSON-serializable for that
	// purpose.
	Session CallbackSession
}

// BeginAuth builds an authorization URL that includes a random nonce and a PKCE
// (S256) code challenge, returning it alongside the CallbackSession that binds
// the callback to this login. The caller MUST persist that CallbackSession
// server-side (keyed to the state token) and pass it back to ExchangeAndVerify.
// The nonce binds the ID token to this specific login (defending against token
// injection/replay) and PKCE proves possession of the authorization code.
//
// # The state parameter is the caller's responsibility here
//
// state is passed straight through to the authorization request, and this
// package has no way to tell an unguessable single-use token from a value that
// describes the login it belongs to. It MUST be an unguessable random value
// that the caller stores server-side and consumes exactly once at the callback.
//
// A SELF-DESCRIBING state — one that encodes the user, tenant or resource the
// flow refers to, e.g. fmt.Sprintf("%s:%s", userID, providerID) — is a
// vulnerability, not a CSRF token. It is guessable and forgeable, it replays
// because nothing consumes it, and a callback that reads the principal or the
// target resource out of it lets an anonymous caller name whose record gets
// written. This is not hypothetical: it is the defect that made a suite
// consumer's OAuth callback critically vulnerable, and it is why
// identity/auth/oauthstate exists.
//
// Prefer BeginAuthSession + CompleteAuthSession, which take no state parameter
// at all: they mint it from crypto/rand via oauthstate.Manager, persist this
// login's nonce and PKCE verifier alongside the caller's own opaque payload,
// and consume the state exactly once at the callback. BeginAuth is NOT marked
// deprecated — it remains correct, and remains the right entry point, when the
// caller genuinely owns a store-and-consume state (for example one from
// oauthstate.Manager.Issue, or an app's existing equivalent).
func (p *Provider) BeginAuth(state string) (AuthChallenge, error) {
	nonce, err := randomNonce()
	if err != nil {
		return AuthChallenge{}, fmt.Errorf("failed to generate OIDC nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	authURL := p.config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return AuthChallenge{
		URL:     authURL,
		Session: CallbackSession{Nonce: nonce, CodeVerifier: verifier},
	}, nil
}

// randomNonce returns a URL-safe, high-entropy random string for use as an
// OIDC nonce.
func randomNonce() (string, error) {
	b := make([]byte, nonceLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GetEndSessionEndpoint returns the OIDC end_session_endpoint from the discovery
// document, or an empty string if the provider does not advertise one (or was
// built via NewProviderForConfig, which performs no discovery).
//
// The value was scheme-validated at construction — a non-HTTPS
// end_session_endpoint fails NewProviderWithContext outright — so this accessor
// cannot hand back a plaintext logout URL that would carry the id_token_hint in
// the clear. It is returned from the stored field rather than re-read from the
// document precisely so the checked and the returned value cannot diverge.
func (p *Provider) GetEndSessionEndpoint() string {
	return p.endSessionEndpoint
}

// ExchangeAndVerify completes an OIDC login: it exchanges the authorization
// code for tokens and verifies the resulting ID token, applying BOTH of this
// login's bindings itself. It is the ONLY way this package will complete an
// exchange.
//
// # Why there is no option-based alternative
//
// This method replaces ExchangeCode(WithPKCEVerifier)/VerifyIDToken(
// WithExpectedNonce), which were removed in v0.25.0. Under that shape the two
// bindings were opt-in strings the caller had to remember to carry forward, and
// omitting WithPKCEVerifier COMPILED CLEANLY and produced a token request with
// no code_verifier at all — the exchange then succeeded or failed entirely at
// the identity provider's discretion (RFC 7636 §4.6 requires a compliant token
// endpoint to reject it; a lenient one does not). A remedy a caller can omit is
// not a remedy, so the omittable path was deleted rather than left beside a
// safer sibling.
//
// session must be the CallbackSession produced for THIS login, by
// CompleteAuthSession (which reads it from server-side storage) or by BeginAuth
// (which returns it in AuthChallenge.Session for the caller to persist). Both
// bindings are REQUIRED: an empty Nonce or CodeVerifier is rejected before any
// network call, so a caller that loses one — a dropped struct field, a state
// entry written by an older version, a zero-value struct — fails closed with a
// clear error instead of silently completing an unbound exchange.
//
// Every HTTP round trip is bounded by oidcHTTPTimeout (via
// contextWithBoundedClient), the same as discovery and JWKS fetches, so a slow
// or hostile token endpoint cannot hang the calling goroutine indefinitely; a
// client the caller already installed on ctx is preserved, with only its
// Timeout capped. Note that golang.org/x/oauth2 auto-probes the client-auth
// style on the first exchange against a given token endpoint, trying one style
// and, on failure, retrying once with the other (see internal.RetrieveToken) —
// so the very first call can perform up to two bounded round trips (worst case
// ~2x oidcHTTPTimeout) rather than one.
//
// It returns the OAuth2 token (for the access/refresh tokens) alongside the
// verified ID token; pass the latter to ExtractUserInfo / ExtractGroups.
func (p *Provider) ExchangeAndVerify(ctx context.Context, code string, session CallbackSession) (*oauth2.Token, *oidc.IDToken, error) {
	// A Provider built via NewProviderForConfig has no verifier (it skipped
	// discovery). Fail before the exchange rather than performing a network
	// call whose result could not be verified — an unverifiable ID token must
	// never be handed back, and returning the token alone would invite exactly
	// that.
	if p.verifier == nil {
		return nil, nil, fmt.Errorf("ExchangeAndVerify is unavailable: this Provider was built with NewProviderForConfig (no discovery); use NewProvider or NewProviderWithContext")
	}
	// Fail closed on a missing binding. These are the two checks that make the
	// deleted option-based API unnecessary: there is no longer any way to reach
	// the token endpoint without a code_verifier, or to accept an ID token
	// without matching its nonce.
	if session.CodeVerifier == "" {
		return nil, nil, fmt.Errorf("oidc: ExchangeAndVerify requires the PKCE code verifier for this login; CallbackSession.CodeVerifier is empty")
	}
	if session.Nonce == "" {
		return nil, nil, fmt.Errorf("oidc: ExchangeAndVerify requires the nonce for this login; CallbackSession.Nonce is empty")
	}

	// Install THIS Provider's guarded client on the exchange context. This is
	// an override, not a merge: a client already on ctx (however it got there —
	// a framework, a middleware, a caller reaching for the oauth2 convention)
	// loses, because the token exchange carries the client_secret and the
	// authorization code to an endpoint the ISSUER named, and the guard that
	// vetted that endpoint at construction must be the one that dials it.
	exchangeCtx := oidc.ClientContext(ctx, p.httpClient)
	token, err := p.config.Exchange(exchangeCtx, code, oauth2.VerifierOption(session.CodeVerifier))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil, fmt.Errorf("oidc: token response contains no id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify ID token: %w", err)
	}
	if idToken.Nonce != session.Nonce {
		return nil, nil, fmt.Errorf("ID token nonce does not match the expected value")
	}
	// After the nonce, because a replayed token should be rejected as a replay
	// rather than reported as an audience problem.
	if err := checkAuthorizedParty(idToken, p.config.ClientID); err != nil {
		return nil, nil, err
	}
	return token, idToken, nil
}

// ExtractGroups reads the named claim from the ID token and returns its string
// values. Returns nil if the claim is absent or not a string array.
func (p *Provider) ExtractGroups(idToken *oidc.IDToken, claimName string) []string {
	if claimName == "" {
		return nil
	}

	var raw map[string]interface{}
	if err := idToken.Claims(&raw); err != nil {
		return nil
	}

	val, ok := raw[claimName]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	default:
		// idToken.Claims unmarshals JSON via encoding/json, which always decodes
		// a JSON array into []interface{} (never []string) and any non-array
		// value into a non-slice type — so this covers both "not an array" and
		// any other unexpected shape.
		return nil
	}
}

// ExtractUserInfo extracts the subject, email, name, and email-verified signal
// from the ID token. The email identifier is resolved from the standard `email`
// claim; only that claim carries the `email_verified` signal, so an email
// resolved from the Azure AD / Entra UPN-family fallbacks (preferred_username,
// upn, unique_name) is reported as unverified. If the name claim is empty it
// falls back to the resolved email.
//
// Callers MUST treat emailVerified as a trust signal for account linking: an
// unverified email must not be used to link or create an account keyed on email
// (see store.GetOrCreateUserFromOIDC).
func (p *Provider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, emailVerified bool, err error) {
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		UPN               string `json:"upn"`
		UniqueName        string `json:"unique_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", false, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if claims.Sub == "" {
		return "", "", "", false, fmt.Errorf("ID token missing 'sub' claim")
	}

	// Resolve email: the standard `email` claim carries the email_verified signal.
	// The UPN-family fallbacks are not verified-email claims, so an email taken
	// from them is left unverified.
	resolved := claims.Email
	if resolved != "" {
		emailVerified = boolClaim(idToken, "email_verified")
	} else {
		resolved = claims.PreferredUsername
		if resolved == "" {
			resolved = claims.UPN
		}
		if resolved == "" {
			resolved = claims.UniqueName
		}
	}
	if resolved == "" {
		// Log the available claim keys so an administrator can diagnose which
		// claims the identity provider is actually sending.
		var raw map[string]json.RawMessage
		if jsonErr := idToken.Claims(&raw); jsonErr == nil {
			keys := make([]string, 0, len(raw))
			for k := range raw {
				keys = append(keys, k)
			}
			slog.Error("oidc: no email identifier found in ID token",
				"available_claims", keys)
		}
		return "", "", "", false, fmt.Errorf("ID token missing email identifier (checked: email, preferred_username, upn, unique_name)")
	}

	if claims.Name == "" {
		claims.Name = resolved
	}

	return claims.Sub, resolved, claims.Name, emailVerified, nil
}

// boolClaim reads a claim leniently as a boolean. Per OIDC core `email_verified`
// is a JSON boolean, but some providers emit the string "true"/"false"; reading
// it from the raw claims (rather than a typed field) means a type quirk cannot
// break parsing of the surrounding claims. Absent or unrecognized values are
// treated as false.
// checkAuthorizedParty enforces the azp ("authorized party") rules of OpenID
// Connect Core section 3.1.3.7, which the underlying library deliberately does
// not.
//
// go-oidc's Verify checks only that our client_id appears in the audience, and
// says so in its own source:
//
//	// This check DOES NOT ensure that the ClientID is the party to which the
//	// ID Token was issued (i.e. Authorized party).
//
// Membership of the audience is weaker than being the party the token was
// issued TO. On an IdP serving several clients, a token minted for client B
// that merely lists our client_id among its audiences passes that check. azp
// is the claim that distinguishes the two, so without this the registry
// accepts an ID token intended for a different relying party.
//
// The rules, as the spec states them:
//
//   - If azp is present, it MUST be our client_id.
//   - If there are multiple audiences, azp SHOULD be present — a multi-audience
//     token with no azp names no single authorized party, so there is nothing
//     to bind it to us. Treated as a rejection.
//
// A single-audience token with no azp is the ordinary case and stays valid;
// tightening that would reject the majority of correct IdPs and get the check
// turned off.
func checkAuthorizedParty(idToken *oidc.IDToken, clientID string) error {
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to read ID token claims: %w", err)
	}
	return checkAuthorizedPartyClaims(claims, idToken.Audience, clientID)
}

// checkAuthorizedPartyClaims is the adjudication itself, split out from the
// token so it can be tested directly.
//
// oidc.IDToken keeps its claims in an unexported field reachable only through
// Claims(), so a test outside go-oidc cannot build a token carrying an azp at
// all. Splitting the decision from the decoding is what makes the rule
// testable, rather than reachable only through a live IdP round trip that would
// really be testing go-oidc.
func checkAuthorizedPartyClaims(claims map[string]json.RawMessage, audience []string, clientID string) error {
	raw, present := claims["azp"]
	if present {
		var azp string
		if err := json.Unmarshal(raw, &azp); err != nil {
			return fmt.Errorf("ID token azp claim is not a string")
		}
		if azp != clientID {
			// The value is not echoed: it is attacker-influenced and would land
			// in logs verbatim.
			return fmt.Errorf("ID token azp names a different client; it was not issued to this registry")
		}
		return nil
	}

	if len(audience) > 1 {
		return fmt.Errorf("ID token has %d audiences and no azp claim, so no authorized party is named", len(audience))
	}
	return nil
}

func boolClaim(idToken *oidc.IDToken, name string) bool {
	var m map[string]json.RawMessage
	if err := idToken.Claims(&m); err != nil {
		return false
	}
	raw, ok := m[name]
	if !ok {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.EqualFold(s, "true")
	}
	return false
}
