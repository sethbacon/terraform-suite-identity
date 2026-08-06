// retained_config_class_test.go covers the inbound half of the aliasing class
// behind issues #139/#147: a constructor that stores the caller's pointer,
// slice or map keeps a live handle to memory the caller still owns and will
// keep using. For a Provider that memory decides which client id, redirect URL
// and scopes are sent on every subsequent authorization request, so it has to
// be the Provider's own.
package oidc

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// TestNewProviderForConfigDoesNotRetainTheCallersConfig asserts that the
// Provider copies the *oauth2.Config it is handed, deeply enough that neither
// the struct fields nor the Scopes slice can be changed from outside after
// construction.
func TestNewProviderForConfigDoesNotRetainTheCallersConfig(t *testing.T) {
	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://idp.example.com/authorize",
			TokenURL: "https://idp.example.com/token",
		},
	}

	p := NewProviderForConfig(cfg)

	if p.config == cfg {
		t.Fatal("NewProviderForConfig stored the caller's *oauth2.Config")
	}

	// Everything a caller that kept its own config could reach afterwards.
	cfg.ClientID = "attacker-client"
	cfg.RedirectURL = "https://elsewhere.example.com/callback"
	cfg.Endpoint.AuthURL = "https://elsewhere.example.com/authorize"
	cfg.Scopes[0] = "changed-scope"
	cfg.Scopes = append(cfg.Scopes, "extra-scope")

	authURL := authURLFor(t, p, "state-123")
	for _, want := range []string{
		"https://idp.example.com/authorize",
		"client_id=client-id",
		"scope=openid+email",
		"redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("auth URL %q lost %q: the Provider is still reading the caller's config",
				authURL, want)
		}
	}
	for _, unwanted := range []string{"changed-scope", "extra-scope", "attacker-client", "elsewhere.example.com"} {
		if strings.Contains(authURL, unwanted) {
			t.Errorf("auth URL %q picked up %q from a post-construction mutation of the "+
				"caller's config", authURL, unwanted)
		}
	}
}

// TestNewProviderForConfigAcceptsNil pins the behaviour of the nil argument,
// which the copy must not turn into a panic.
func TestNewProviderForConfigAcceptsNil(t *testing.T) {
	p := NewProviderForConfig(nil)
	if p == nil {
		t.Fatal("NewProviderForConfig(nil) returned nil")
	}
	if p.config != nil {
		t.Errorf("NewProviderForConfig(nil) built a config: %+v", p.config)
	}
}

// TestNewProviderWithContextDoesNotRetainTheCallersScopes asserts the same for
// the discovery-backed constructor. Config is passed by value, so its string
// fields are already safe — but the Scopes slice header is not, and those
// scopes are what every later authorization URL requests.
func TestNewProviderWithContextDoesNotRetainTheCallersScopes(t *testing.T) {
	srv := discoveryServer(t)
	defer srv.Close()

	scopes := []string{"openid", "email"}

	p, err := NewProviderWithContext(context.Background(), Config{
		IssuerURL:           srv.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		RedirectURL:         "https://app.example/callback",
		Scopes:              scopes,
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}

	// The caller still owns `scopes` and writes through it.
	scopes[0] = "changed-scope"

	authURL := authURLFor(t, p, "state-123")
	if !strings.Contains(authURL, "scope=openid+email") {
		t.Errorf("auth URL %q does not request the scopes the provider was built with: "+
			"the provider is reading the caller's slice", authURL)
	}
	if strings.Contains(authURL, "changed-scope") {
		t.Errorf("auth URL %q picked up a post-construction write to the caller's "+
			"Scopes slice", authURL)
	}
}

// TestNewProviderPreservesNilScopes keeps the copy from turning an absent
// scope list into an empty-but-present one, which would change the shape of
// the authorization request.
func TestNewProviderPreservesNilScopes(t *testing.T) {
	p := NewProviderForConfig(&oauth2.Config{ClientID: "client-id"})
	if p.config.Scopes != nil {
		t.Errorf("nil Scopes became %#v after the copy", p.config.Scopes)
	}
}
