// Package oidc implements a generic OpenID Connect provider shared across the
// Terraform suite. It performs discovery, builds authorization URLs, exchanges
// authorization codes, and verifies ID tokens. Configuration is supplied by the
// caller (apps resolve it from env/DB); this package is storage- and app-neutral.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcHTTPTimeout bounds every HTTP round trip this package makes to an
// identity provider: OIDC discovery (the initial NewProvider/NewProviderWithContext
// call) and the JWKS key-set fetches/refreshes performed later during ID-token
// verification (go-oidc reuses the *http.Client supplied via the discovery
// context for the lifetime of the resulting *oidc.Provider — see
// github.com/coreos/go-oidc/v3/oidc's Provider.client / remoteKeySet). Without
// an explicit client, discovery falls back to http.DefaultClient, which has no
// Timeout and can hang indefinitely against a slow or unresponsive issuer. 15
// seconds comfortably covers discovery + JWKS fetches against a healthy IdP
// (including ones a few network hops away) while still failing fast enough
// that a hung issuer can't wedge a caller's startup or a request goroutine.
const oidcHTTPTimeout = 15 * time.Second

// Config holds the resolved OIDC settings required to construct a Provider.
// Apps resolve these values from their own configuration (env, file or DB)
// before constructing the provider.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	// RequireHTTPS rejects a non-HTTPS issuer URL. An HTTP issuer means discovery
	// and JWKS key material are fetched over plaintext, allowing a MITM to
	// substitute signing keys and forge ID tokens. Off by default so local/dev
	// stacks can use http issuers; production callers should set it true.
	RequireHTTPS bool
}

// Provider wraps the generic OIDC provider, verifier and OAuth2 config.
type Provider struct {
	verifier *oidc.IDTokenVerifier
	config   *oauth2.Config
	provider *oidc.Provider
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

	if cfg.RequireHTTPS && !strings.HasPrefix(cfg.IssuerURL, "https://") {
		return nil, fmt.Errorf("OIDC issuer URL must use HTTPS, got: %q", cfg.IssuerURL)
	}

	if cfg.RequireHTTPS && cfg.RedirectURL != "" && !strings.HasPrefix(cfg.RedirectURL, "https://") {
		return nil, fmt.Errorf("OIDC redirect URL must use HTTPS, got: %q", cfg.RedirectURL)
	}

	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: oidcHTTPTimeout})

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	return &Provider{
		verifier: verifier,
		config:   oauth2Config,
		provider: provider,
	}, nil
}

// NewProviderForConfig constructs a Provider backed by the given oauth2 config
// without performing OIDC discovery. Intended for sibling packages (e.g. an
// Azure AD adapter) and tests that need the OAuth2 methods (GetAuthURL,
// ExchangeCode) without a live identity provider. Methods that depend on the
// discovery document or verifier (VerifyIDToken, GetEndSessionEndpoint) are not
// usable on a Provider built this way.
func NewProviderForConfig(cfg *oauth2.Config) *Provider {
	return &Provider{config: cfg}
}

// GetAuthURL returns the OAuth2 authorization URL for the given state.
//
// Deprecated: GetAuthURL builds a bare OAuth2 authorization URL with no OIDC
// nonce and no PKCE challenge, so a caller using it (together with a
// no-options VerifyIDToken call) is not defended against token injection/replay
// or authorization-code interception. Use BeginAuth instead, which returns an
// AuthChallenge carrying a generated nonce and PKCE verifier alongside the URL.
func (p *Provider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// nonceLength is the number of random bytes used for the OIDC nonce.
const nonceLength = 32

// AuthChallenge holds an authorization URL together with the per-login secrets
// the caller must persist (keyed to the state token) and supply back at the
// callback: the OIDC nonce and the PKCE code verifier.
type AuthChallenge struct {
	// URL is the authorization endpoint URL to redirect the user agent to.
	URL string
	// Nonce must be persisted and passed to VerifyIDToken via WithExpectedNonce.
	Nonce string
	// CodeVerifier must be persisted and passed to ExchangeCode via
	// WithPKCEVerifier.
	CodeVerifier string
}

// BeginAuth builds an authorization URL that includes a random nonce and a PKCE
// (S256) code challenge, returning it alongside the generated nonce and code
// verifier. The caller MUST persist Nonce and CodeVerifier server-side (keyed to
// the state token) and pass them back at the callback via WithExpectedNonce (to
// VerifyIDToken) and WithPKCEVerifier (to ExchangeCode). The nonce binds the ID
// token to this specific login (defending against token injection/replay) and
// PKCE proves possession of the authorization code.
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
	return AuthChallenge{URL: authURL, Nonce: nonce, CodeVerifier: verifier}, nil
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
// document, or an empty string if the provider does not advertise one.
func (p *Provider) GetEndSessionEndpoint() string {
	// A Provider built via NewProviderForConfig has no discovery document.
	// Return empty rather than dereferencing a nil provider.
	if p.provider == nil {
		return ""
	}
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return ""
	}
	return claims.EndSessionEndpoint
}

// ExchangeOption customizes the authorization-code exchange.
type ExchangeOption func(*exchangeConfig)

type exchangeConfig struct {
	codeVerifier string
}

// WithPKCEVerifier supplies the PKCE code verifier generated by BeginAuth so the
// token endpoint can bind the authorization code to this login (proof of
// possession). Omit it only for providers that do not support PKCE.
func WithPKCEVerifier(verifier string) ExchangeOption {
	return func(c *exchangeConfig) { c.codeVerifier = verifier }
}

// ExchangeCode exchanges the authorization code for tokens. When a PKCE verifier
// is supplied via WithPKCEVerifier it is sent on the token request as the
// code_verifier parameter.
func (p *Provider) ExchangeCode(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
	var cfg exchangeConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	var authCodeOpts []oauth2.AuthCodeOption
	if cfg.codeVerifier != "" {
		authCodeOpts = append(authCodeOpts, oauth2.VerifierOption(cfg.codeVerifier))
	}

	token, err := p.config.Exchange(ctx, code, authCodeOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return token, nil
}

// VerifyOption customizes ID-token verification.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	expectedNonce string
}

// WithExpectedNonce requires the ID token's `nonce` claim to equal the nonce
// generated by BeginAuth for this login, binding the token to the session and
// defending against token injection/replay.
func WithExpectedNonce(nonce string) VerifyOption {
	return func(c *verifyConfig) { c.expectedNonce = nonce }
}

// VerifyIDToken verifies and parses the raw ID token. When an expected nonce is
// supplied via WithExpectedNonce, the token's `nonce` claim must match it.
//
// Calling VerifyIDToken without WithExpectedNonce is a discouraged, legacy
// calling convention: the token is accepted regardless of which login it was
// issued for, so it does not defend against ID-token injection/replay across
// concurrent authorization attempts. VerifyIDToken itself is not deprecated —
// it remains the correct function to call — only the no-nonce-option pattern
// is discouraged, so this is intentionally not marked with a blanket
// "Deprecated:" godoc tag (which would flag every call site, including ones
// that already pass WithExpectedNonce correctly). New call sites built against
// a flow started with BeginAuth should always pass
// WithExpectedNonce(challenge.Nonce).
func (p *Provider) VerifyIDToken(ctx context.Context, rawIDToken string, opts ...VerifyOption) (*oidc.IDToken, error) {
	// A Provider built via NewProviderForConfig has no verifier (it skipped
	// discovery). Return a descriptive error rather than panicking on a nil
	// verifier deref.
	if p.verifier == nil {
		return nil, fmt.Errorf("VerifyIDToken is unavailable: this Provider was built with NewProviderForConfig (no discovery); use NewProvider or NewProviderWithContext")
	}

	var cfg verifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	if cfg.expectedNonce != "" && idToken.Nonce != cfg.expectedNonce {
		return nil, fmt.Errorf("ID token nonce does not match the expected value")
	}
	return idToken, nil
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
