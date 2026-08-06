// egress_test.go covers the endpoints this package learns from the DISCOVERY
// DOCUMENT rather than from its caller.
//
// IssuerURL and RedirectURL are configuration: an operator typed them, and the
// only question about them is whether they are HTTPS. token_endpoint and
// jwks_uri are not configuration. They arrive in a document the issuer serves,
// so whoever controls the issuer — legitimately, through a TLS-termination
// mistake, or through compromise — chooses them, and this process then sends
// the client_secret and the authorization code to one of them and fetches the
// signing keys that decide which ID tokens are valid from the other.
//
// Both directions are asserted for every case: a denied destination must be
// refused AND a permitted one must still work. A one-directional test would
// pass just as happily against a provider that refused everything.
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

// endpointServer serves a discovery document whose issuer is the server's own
// URL (go-oidc requires that match) and whose token_endpoint and jwks_uri are
// whatever the caller says. Empty means "advertise this server's own".
func endpointServer(t *testing.T, tokenEndpoint, jwksURI string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if tokenEndpoint == "" {
			tokenEndpoint = srv.URL + "/token"
		}
		if jwksURI == "" {
			jwksURI = srv.URL + "/keys"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         tokenEndpoint,
			"jwks_uri":               jwksURI,
		})
	})
	return srv
}

func newProviderAgainst(srv *httptest.Server) (*Provider, error) {
	return NewProviderWithContext(context.Background(), Config{
		EgressGuard:         loopbackGuard(),
		IssuerURL:           srv.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		RedirectURL:         "https://app.example/callback",
		AllowInsecureIssuer: true, // srv is a plain httptest.NewServer, not TLS
	})
}

// deniedDestinations are addresses the default policy refuses, one per range
// class that matters here. Each is an IP LITERAL, so the check needs no DNS and
// the test makes no network request of any kind.
var deniedDestinations = []struct {
	name string
	url  string
}{
	{"link-local metadata", "http://169.254.169.254/hijacked"},
	{"RFC 1918 private", "http://10.10.10.10/hijacked"},
	{"loopback outside the allow-list", "http://127.0.0.2:9/hijacked"},
}

func TestNewProvider_RefusesDiscoveredJWKSURIAtADeniedDestination(t *testing.T) {
	for _, d := range deniedDestinations {
		t.Run(d.name, func(t *testing.T) {
			srv := endpointServer(t, "", d.url)
			_, err := newProviderAgainst(srv)
			if err == nil {
				t.Fatalf("provider constructed against a discovery document advertising jwks_uri %s", d.url)
			}
			// The refusal must NAME the destination: an operator reading this
			// in a startup log has to be able to tell a hostile issuer from a
			// missing allow-list entry, and "egress blocked" alone cannot.
			if !strings.Contains(err.Error(), d.url) {
				t.Errorf("refusal does not name the destination %q: %v", d.url, err)
			}
			if !strings.Contains(err.Error(), "jwks_uri") {
				t.Errorf("refusal does not name which endpoint was refused: %v", err)
			}
		})
	}
}

func TestNewProvider_RefusesDiscoveredTokenEndpointAtADeniedDestination(t *testing.T) {
	for _, d := range deniedDestinations {
		t.Run(d.name, func(t *testing.T) {
			srv := endpointServer(t, d.url, "")
			_, err := newProviderAgainst(srv)
			if err == nil {
				t.Fatalf("provider constructed against a discovery document advertising token_endpoint %s", d.url)
			}
			if !strings.Contains(err.Error(), d.url) {
				t.Errorf("refusal does not name the destination %q: %v", d.url, err)
			}
			if !strings.Contains(err.Error(), "token_endpoint") {
				t.Errorf("refusal does not name which endpoint was refused: %v", err)
			}
		})
	}
}

// TestNewProvider_AcceptsDiscoveredEndpointsAtAPermittedDestination is the other
// direction, and it is not optional: without it every assertion above would
// still pass if construction simply always failed.
func TestNewProvider_AcceptsDiscoveredEndpointsAtAPermittedDestination(t *testing.T) {
	srv := endpointServer(t, "", "")
	p, err := newProviderAgainst(srv)
	if err != nil {
		t.Fatalf("provider refused a discovery document whose endpoints are on the allow-listed issuer: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil provider")
	}
	if got := p.config.Endpoint.TokenURL; got != srv.URL+"/token" {
		t.Errorf("token endpoint = %q, want the discovered %q", got, srv.URL+"/token")
	}
}

// TestNewProvider_AllowlistIsWhatMakesAnInternalIdPWork pins the deployment
// contract this release introduces: the SAME discovery document is refused
// under the default policy and accepted once the destination is allow-listed.
// Nothing about the issuer changes between the two halves — only the operator's
// configuration does.
func TestNewProvider_AllowlistIsWhatMakesAnInternalIdPWork(t *testing.T) {
	srv := endpointServer(t, "", "")

	cfg := Config{
		IssuerURL:           srv.URL,
		ClientID:            "my-client",
		ClientSecret:        "my-secret",
		AllowInsecureIssuer: true,
	}

	// Default policy (nil guard): loopback is denied, so an IdP at this address
	// is unreachable. This is exactly what a deployment with an internal IdP
	// and an empty security.egress.allowlist sees.
	cfg.EgressGuard = nil
	if _, err := NewProviderWithContext(context.Background(), cfg); err == nil {
		t.Fatal("the strict default policy accepted an IdP on loopback")
	}

	// With the destination allow-listed, the identical document is accepted.
	cfg.EgressGuard = httpsafe.MustGuard("127.0.0.1", "::1")
	if _, err := NewProviderWithContext(context.Background(), cfg); err != nil {
		t.Fatalf("allow-listing the IdP's address did not make it reachable: %v", err)
	}
}

// tlsDiscoveryServer serves the given discovery document over TLS, so the
// caller-supplied ISSUER passes the HTTPS check and the assertion can be about
// the DISCOVERED endpoints alone. It returns the *tls.Config a Provider needs to
// trust the server's self-signed certificate — supplied through
// Config.TLSClientConfig, the supported hook, which reaches the guarded
// transport without displacing the guard.
func tlsDiscoveryServer(t *testing.T, doc func(issuer string) map[string]any) (*httptest.Server, *tls.Config) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc(srv.URL))
	})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// TestNewProvider_RefusesPlaintextDiscoveredEndpoints covers the scheme half of
// the rule, which is separate from the destination half: an HTTPS issuer that
// advertises an http token_endpoint or jwks_uri is refused. An http jwks_uri
// fetches signing keys over a channel that can be substituted; an http
// token_endpoint puts the client_secret and the authorization code on the wire.
func TestNewProvider_RefusesPlaintextDiscoveredEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, token, jwks, wantNamed string
	}{
		{"plaintext token_endpoint", "http://idp.example/token", "https://idp.example/keys", "token_endpoint"},
		{"plaintext jwks_uri", "https://idp.example/token", "http://idp.example/keys", "jwks_uri"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, tlsCfg := tlsDiscoveryServer(t, func(issuer string) map[string]any {
				return map[string]any{
					"issuer":                 issuer,
					"authorization_endpoint": "https://idp.example/auth",
					"token_endpoint":         tc.token,
					"jwks_uri":               tc.jwks,
				}
			})

			_, err := NewProviderWithContext(context.Background(), Config{
				EgressGuard:     loopbackGuard(),
				TLSClientConfig: tlsCfg,
				IssuerURL:       srv.URL,
				ClientID:        "my-client",
				ClientSecret:    "my-secret",
			})
			if err == nil {
				t.Fatalf("provider constructed against a discovery document advertising a plaintext %s", tc.wantNamed)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("refusal does not name which endpoint was refused: %v", err)
			}
			if !strings.Contains(err.Error(), "HTTPS") {
				t.Errorf("refusal does not read as a scheme refusal: %v", err)
			}
		})
	}
}

// TestNewProvider_AllowInsecureIssuerCoversDiscoveredEndpoints is the paired
// direction: a dev stack that has explicitly opted out of the HTTPS rule must
// not then be blocked by the same rule one layer down, or the opt-out would not
// let anything run.
func TestNewProvider_AllowInsecureIssuerCoversDiscoveredEndpoints(t *testing.T) {
	srv := endpointServer(t, "", "")
	if _, err := newProviderAgainst(srv); err != nil {
		t.Fatalf("AllowInsecureIssuer did not cover the discovered endpoints: %v", err)
	}
}

// TestNewProvider_RequiresTheEndpointsItWillDial keeps an absent mandatory
// endpoint from surfacing much later as a confusing exchange or verification
// failure. jwks_uri is mandatory per OIDC Discovery; an authorization-code flow
// cannot complete without a token endpoint.
func TestNewProvider_RequiresTheEndpointsItWillDial(t *testing.T) {
	for _, tc := range []struct{ name, field string }{
		{"no token_endpoint", "token_endpoint"},
		{"no jwks_uri", "jwks_uri"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				doc := map[string]any{
					"issuer":                 srv.URL,
					"authorization_endpoint": srv.URL + "/auth",
					"token_endpoint":         srv.URL + "/token",
					"jwks_uri":               srv.URL + "/keys",
				}
				delete(doc, tc.field)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
			})
			_, err := newProviderAgainst(srv)
			if err == nil {
				t.Fatalf("provider constructed against a discovery document with no %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error does not name the missing endpoint %q: %v", tc.field, err)
			}
		})
	}
}

// TestNewProvider_RefusesPlaintextEndSessionEndpoint covers the browser-redirect
// half. This process never dials end_session_endpoint — the user agent does —
// so the destination rule is not ours to apply, but the scheme rule is: a
// plaintext logout URL carries the id_token_hint in the clear.
func TestNewProvider_RefusesPlaintextEndSessionEndpoint(t *testing.T) {
	srv, tlsCfg := tlsDiscoveryServer(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
			"end_session_endpoint":   "http://idp.example/logout",
		}
	})

	_, err := NewProviderWithContext(context.Background(), Config{
		EgressGuard:     loopbackGuard(),
		TLSClientConfig: tlsCfg,
		IssuerURL:       srv.URL,
		ClientID:        "my-client",
		ClientSecret:    "my-secret",
	})
	if err == nil {
		t.Fatal("expected a refusal for a plaintext end_session_endpoint")
	}
	if !strings.Contains(err.Error(), "end_session_endpoint") {
		t.Errorf("error does not name the endpoint: %v", err)
	}
}

// TestNewProvider_DoesNotEgressCheckBrowserRedirectTargets pins the other side
// of that judgment. authorization_endpoint and end_session_endpoint are
// resolved by the USER AGENT from its own network position, not by this
// process, so applying this deployment's egress policy to them would reject
// configurations that are entirely legitimate — an IdP whose login page is
// public while its token endpoint is internal, or the reverse.
func TestNewProvider_DoesNotEgressCheckBrowserRedirectTargets(t *testing.T) {
	srv, tlsCfg := tlsDiscoveryServer(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer": issuer,
			// Both are HTTPS (the rule that DOES apply) but point at a private
			// address this deployment's guard would refuse to dial.
			"authorization_endpoint": "https://10.20.30.40/auth",
			"end_session_endpoint":   "https://10.20.30.40/logout",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		}
	})

	p, err := NewProviderWithContext(context.Background(), Config{
		EgressGuard:     loopbackGuard(),
		TLSClientConfig: tlsCfg,
		IssuerURL:       srv.URL,
		ClientID:        "my-client",
		ClientSecret:    "my-secret",
	})
	if err != nil {
		t.Fatalf("this deployment's egress policy was applied to a browser redirect target it never dials: %v", err)
	}
	if got := p.GetEndSessionEndpoint(); got != "https://10.20.30.40/logout" {
		t.Errorf("end session endpoint = %q, want the discovered value", got)
	}
}

// TestGuardedClient_RefusesDeniedDestinationsAtDialTime is the second half of
// the enforcement, and it is what still holds if a name resolves to a denied
// address only later: the pre-flight above is a fast, clear failure, the dialer
// is the guarantee.
func TestGuardedClient_RefusesDeniedDestinationsAtDialTime(t *testing.T) {
	client := newGuardedClient(Config{EgressGuard: loopbackGuard()})
	for _, d := range deniedDestinations {
		t.Run(d.name, func(t *testing.T) {
			resp, err := client.Get(d.url)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("the guarded client reached %s", d.url)
			}
			if !strings.Contains(err.Error(), "blocked") {
				t.Errorf("error does not read as an egress-policy refusal: %v", err)
			}
		})
	}
}
