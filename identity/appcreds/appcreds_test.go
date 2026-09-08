package appcreds

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

func TestNew_Defaults(t *testing.T) {
	m := New()
	if m.entraLoginBaseURL != DefaultEntraLoginBaseURL {
		t.Errorf("entra host = %q, want %q", m.entraLoginBaseURL, DefaultEntraLoginBaseURL)
	}
	if m.githubAPIBaseURL != DefaultGitHubAPIBaseURL {
		t.Errorf("github host = %q, want %q", m.githubAPIBaseURL, DefaultGitHubAPIBaseURL)
	}
	// An unbounded client would hold the caller's request open for as long as a
	// hung token endpoint cared to.
	if m.httpClient == nil || m.httpClient.Timeout == 0 {
		t.Error("the default client has no timeout")
	}
	if m.now == nil || m.credentialFactory == nil {
		t.Error("the default clock or credential factory is nil")
	}
}

// Every option ignores its zero value, so a caller can pass an unset config
// field without silently blanking a working default -- an empty login host
// would otherwise send the client secret to a relative URL.
func TestOptions_IgnoreZeroValues(t *testing.T) {
	m := New(
		WithHTTPClient(nil),
		WithEgressGuard(nil),
		WithEntraLoginBaseURL(""),
		WithGitHubAPIBaseURL(""),
		WithClock(nil),
		WithFederatedCredentialFactory(nil),
	)
	if m.httpClient == nil {
		t.Error("WithHTTPClient(nil) cleared the client")
	}
	if m.entraLoginBaseURL != DefaultEntraLoginBaseURL || m.githubAPIBaseURL != DefaultGitHubAPIBaseURL {
		t.Error("an empty host override cleared a default")
	}
	if m.now == nil {
		t.Error("WithClock(nil) cleared the clock")
	}
	if m.credentialFactory == nil {
		t.Error("WithFederatedCredentialFactory(nil) cleared the factory")
	}
}

func TestOptions_Apply(t *testing.T) {
	c := &http.Client{Timeout: time.Second}
	m := New(
		WithHTTPClient(c),
		WithEntraLoginBaseURL("https://login.microsoftonline.us"),
		WithGitHubAPIBaseURL("https://ghe.example.com/api/v3"),
		WithClock(fixedClock(testNow)),
	)
	if m.httpClient != c {
		t.Error("WithHTTPClient did not take")
	}
	if m.entraLoginBaseURL != "https://login.microsoftonline.us" {
		t.Errorf("sovereign login host not applied: %q", m.entraLoginBaseURL)
	}
	if m.githubAPIBaseURL != "https://ghe.example.com/api/v3" {
		t.Errorf("GitHub Enterprise host not applied: %q", m.githubAPIBaseURL)
	}
	if !m.now().Equal(testNow) {
		t.Error("WithClock did not take")
	}
}

// The guard is the reason a token endpoint cannot be pointed at the internal
// network. A configured host resolving to a private address must be refused
// before the request -- and the client secret -- leaves the process.
//
// This asserts the guard is WIRED, which is the part a refactor drops. That it
// classifies addresses correctly is httpsafe's own business.
func TestWithEgressGuard_RefusesAPrivateTokenEndpoint(t *testing.T) {
	m := New(WithEgressGuard(httpsafe.MustGuard()), WithEntraLoginBaseURL("http://127.0.0.1:1"))

	_, err := m.MintEntra(context.Background(), EntraCreds{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
	})
	if err == nil {
		t.Fatal("a loopback token endpoint was allowed")
	}
	// Distinguish "the guard refused it" from "nothing was listening on port 1",
	// which is the shape a vacuous version of this test would have.
	if !strings.Contains(strings.ToLower(err.Error()), "loopback") &&
		!strings.Contains(strings.ToLower(err.Error()), "denied") &&
		!strings.Contains(strings.ToLower(err.Error()), "blocked") &&
		!strings.Contains(strings.ToLower(err.Error()), "not allowed") {
		t.Errorf("the request failed but not visibly because of the egress guard: %v", err)
	}
}

// An allowlisted loopback host is reachable, which is what makes the guarded
// client usable in the callers' own tests.
func TestWithEgressGuard_AllowlistedLoopbackIsReachable(t *testing.T) {
	srv, _, _ := entraServer(t, http.StatusOK, `{"access_token":"t","expires_in":60}`)
	m := New(
		WithEgressGuard(httpsafe.MustGuard("127.0.0.1", "::1")),
		WithEntraLoginBaseURL(srv.URL),
		WithClock(fixedClock(testNow)),
	)
	if _, err := m.MintEntra(context.Background(), EntraCreds{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
	}); err != nil {
		t.Fatalf("an allowlisted loopback endpoint was refused: %v", err)
	}
}

// A cancelled context must abort the exchange rather than run it to completion.
func TestMint_HonoursContextCancellation(t *testing.T) {
	srv, _, _ := entraServer(t, http.StatusOK, `{"access_token":"t","expires_in":60}`)
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.MintEntra(ctx, EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}); err == nil {
		t.Fatal("a cancelled context still minted")
	}
}

// newTestMinter builds a Minter that can reach an httptest server.
//
// The package's default guard refuses loopback, which is the correct production
// policy and makes every test using httptest explicit about the exemption
// instead of quietly inheriting a permissive default. A test that forgets this
// fails with an egress error rather than passing for the wrong reason -- the
// shape where a "the endpoint rejected us" assertion is really "we never left
// the process".
func newTestMinter(t *testing.T, opts ...Option) *Minter {
	t.Helper()
	return New(append([]Option{
		WithEgressGuard(httpsafe.MustGuard("127.0.0.1", "::1")),
		WithClock(fixedClock(testNow)),
	}, opts...)...)
}
