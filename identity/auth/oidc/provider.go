// Package oidc implements a generic OpenID Connect provider shared across the
// Terraform suite. It performs discovery, builds authorization URLs, exchanges
// authorization codes, and verifies ID tokens. Configuration is supplied by the
// caller (apps resolve it from env/DB); this package is storage- and app-neutral.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

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

// NewProvider initializes a new OIDC provider using a background context.
func NewProvider(cfg Config) (*Provider, error) {
	return NewProviderWithContext(context.Background(), cfg)
}

// NewProviderWithContext initializes a new OIDC provider with the given context.
// It performs OIDC discovery against the issuer URL, so the context governs the
// discovery request.
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
func (p *Provider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// GetEndSessionEndpoint returns the OIDC end_session_endpoint from the discovery
// document, or an empty string if the provider does not advertise one.
func (p *Provider) GetEndSessionEndpoint() string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return ""
	}
	return claims.EndSessionEndpoint
}

// ExchangeCode exchanges the authorization code for tokens.
func (p *Provider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return token, nil
}

// VerifyIDToken verifies and parses the raw ID token.
func (p *Provider) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
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
	case []string:
		return v
	default:
		return nil
	}
}

// ExtractUserInfo extracts the subject, email and name from the ID token.
// The email identifier is resolved from the standard `email` claim, falling
// back to the Azure AD / Entra ID variants (preferred_username, upn,
// unique_name) which carry the UPN when `email` is not configured as an
// optional claim. If the name claim is empty it falls back to the resolved
// email.
func (p *Provider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, err error) {
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		UPN               string `json:"upn"`
		UniqueName        string `json:"unique_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if claims.Sub == "" {
		return "", "", "", fmt.Errorf("ID token missing 'sub' claim")
	}

	// Resolve email: standard claim first, then Azure AD UPN variants.
	resolved := claims.Email
	if resolved == "" {
		resolved = claims.PreferredUsername
	}
	if resolved == "" {
		resolved = claims.UPN
	}
	if resolved == "" {
		resolved = claims.UniqueName
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
		return "", "", "", fmt.Errorf("ID token missing email identifier (checked: email, preferred_username, upn, unique_name)")
	}

	if claims.Name == "" {
		claims.Name = resolved
	}

	return claims.Sub, resolved, claims.Name, nil
}
