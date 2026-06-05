// Package oidc implements a generic OpenID Connect provider shared across the
// Terraform suite. It performs discovery, builds authorization URLs, exchanges
// authorization codes, and verifies ID tokens. Configuration is supplied by the
// caller (apps resolve it from env/DB); this package is storage- and app-neutral.
package oidc

import (
	"context"
	"fmt"

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
// If the name claim is empty it falls back to the email.
func (p *Provider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, err error) {
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if claims.Sub == "" {
		return "", "", "", fmt.Errorf("ID token missing 'sub' claim")
	}

	if claims.Email == "" {
		return "", "", "", fmt.Errorf("ID token missing 'email' claim")
	}

	if claims.Name == "" {
		claims.Name = claims.Email
	}

	return claims.Sub, claims.Email, claims.Name, nil
}
