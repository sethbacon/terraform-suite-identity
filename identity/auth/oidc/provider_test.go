package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
