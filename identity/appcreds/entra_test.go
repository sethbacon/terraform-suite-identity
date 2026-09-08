package appcreds

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fixedClock makes expiry arithmetic assertable rather than approximate.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

var testNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// entraServer returns a token endpoint that records the request it was sent.
func entraServer(t *testing.T, status int, body string) (*httptest.Server, *http.Request, *url.Values) {
	t.Helper()
	var got http.Request
	form := url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		parsed, _ := url.ParseQuery(string(raw))
		for k, v := range parsed {
			form[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &form
}

func TestMintEntra_Success(t *testing.T) {
	srv, req, form := entraServer(t, http.StatusOK, `{"access_token":"ado-token","expires_in":3600}`)
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithClock(fixedClock(testNow)))

	tok, err := m.MintEntra(context.Background(), EntraCreds{
		TenantID: "tenant-1", ClientID: "client-1", ClientSecret: "the-secret",
	})
	if err != nil {
		t.Fatalf("MintEntra: %v", err)
	}
	if tok.AccessToken != "ado-token" {
		t.Errorf("token = %q, want ado-token", tok.AccessToken)
	}
	// Absolute, computed from the injected clock -- so a stored token is usable
	// without remembering when it was minted.
	if want := testNow.Add(time.Hour); !tok.ExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want %v", tok.ExpiresAt, want)
	}

	if req.URL.Path != "/tenant-1/oauth2/v2.0/token" {
		t.Errorf("path = %q, want /tenant-1/oauth2/v2.0/token", req.URL.Path)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	// The audience is what makes the token usable against Azure DevOps at all;
	// a token minted for the wrong resource authenticates to nothing while
	// looking perfectly well-formed.
	if got := form.Get("scope"); got != AzureDevOpsResourceID+"/.default" {
		t.Errorf("scope = %q, want the Azure DevOps resource id", got)
	}
	if got := form.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q", got)
	}
	if form.Get("client_id") != "client-1" || form.Get("client_secret") != "the-secret" {
		t.Errorf("credentials not sent: %v", *form)
	}
}

// A tenant id reaches the URL from operator-supplied configuration. Unescaped,
// a slash in it would add path segments and send the client secret to an
// endpoint the operator did not name.
func TestMintEntra_EscapesTheTenantIntoOnePathSegment(t *testing.T) {
	srv, req, _ := entraServer(t, http.StatusOK, `{"access_token":"t","expires_in":60}`)
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithClock(fixedClock(testNow)))

	if _, err := m.MintEntra(context.Background(), EntraCreds{
		TenantID: "evil/../../attacker", ClientID: "c", ClientSecret: "s",
	}); err != nil {
		t.Fatalf("MintEntra: %v", err)
	}
	// EscapedPath keeps the %2F; a naive concatenation would show real slashes.
	if strings.Count(req.URL.EscapedPath(), "/") != 4 {
		t.Errorf("tenant escaped into %q -- it added path segments", req.URL.EscapedPath())
	}
	if !strings.Contains(req.URL.EscapedPath(), "%2F") {
		t.Errorf("tenant slashes were not escaped: %q", req.URL.EscapedPath())
	}
}

func TestMintEntra_TrailingSlashOnTheLoginHost(t *testing.T) {
	srv, req, _ := entraServer(t, http.StatusOK, `{"access_token":"t","expires_in":60}`)
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL+"/"), WithClock(fixedClock(testNow)))

	if _, err := m.MintEntra(context.Background(), EntraCreds{
		TenantID: "t1", ClientID: "c", ClientSecret: "s",
	}); err != nil {
		t.Fatalf("MintEntra: %v", err)
	}
	if strings.HasPrefix(req.URL.Path, "//") {
		t.Errorf("path = %q -- a configured trailing slash produced a double slash", req.URL.Path)
	}
}

func TestMintEntra_Failures(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantErrHas string
	}{
		{
			// The AADSTS code is the only thing separating "wrong secret" from
			// "app not consented" from "no such tenant", so it must survive.
			name: "AADSTS code is surfaced", status: http.StatusUnauthorized,
			body:       `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret"}`,
			wantErrHas: "AADSTS7000215",
		},
		{name: "not JSON", status: http.StatusOK, body: `<html>proxy error</html>`, wantErrHas: "not JSON"},
		{name: "no access_token", status: http.StatusOK, body: `{"expires_in":3600}`, wantErrHas: "no access_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := entraServer(t, tc.status, tc.body)
			m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithClock(fixedClock(testNow)))
			_, err := m.MintEntra(context.Background(), EntraCreds{
				TenantID: "t", ClientID: "c", ClientSecret: "s",
			})
			if err == nil {
				t.Fatal("mint succeeded")
			}
			if !strings.Contains(err.Error(), tc.wantErrHas) {
				t.Errorf("error %q does not mention %q", err, tc.wantErrHas)
			}
		})
	}
}

// An absent or nonsensical expires_in must not produce a zero expiry: a token
// with no expiry is treated as already spent by Token.Expired, so every call
// would re-mint, and a naive caller might treat it as immortal instead.
func TestMintEntra_MissingExpiresInFallsBackToAnHour(t *testing.T) {
	for _, body := range []string{`{"access_token":"t"}`, `{"access_token":"t","expires_in":0}`, `{"access_token":"t","expires_in":-5}`} {
		srv, _, _ := entraServer(t, http.StatusOK, body)
		m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithClock(fixedClock(testNow)))
		tok, err := m.MintEntra(context.Background(), EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"})
		if err != nil {
			t.Fatalf("body %s: %v", body, err)
		}
		if want := testNow.Add(time.Hour); !tok.ExpiresAt.Equal(want) {
			t.Errorf("body %s: expiry = %v, want %v", body, tok.ExpiresAt, want)
		}
	}
}

// Nothing should leave the process when the credentials cannot produce a grant:
// the caller gets ErrInvalidCreds, which is a 400, not a 502.
func TestMintEntra_InvalidCredsNeverReachTheNetwork(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ }))
	defer srv.Close()
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL))

	for _, creds := range []EntraCreds{
		{ClientID: "c", ClientSecret: "s"},
		{TenantID: "t", ClientSecret: "s"},
		{TenantID: "t", ClientID: "c"},
		{TenantID: "   ", ClientID: "c", ClientSecret: "s"},
		{},
	} {
		_, err := m.MintEntra(context.Background(), creds)
		if err == nil {
			t.Fatalf("%+v minted", creds)
		}
		if !errors.Is(err, ErrInvalidCreds) {
			t.Errorf("%+v: error %v is not ErrInvalidCreds, so a caller cannot tell it is a 400", creds, err)
		}
	}
	if called != 0 {
		t.Errorf("token endpoint was called %d times with invalid credentials, want 0", called)
	}
}

// The error names every missing field at once, so an operator fixes the
// configuration in one pass instead of discovering them one at a time.
func TestEntraCreds_ValidateNamesEveryMissingField(t *testing.T) {
	err := EntraCreds{}.Validate()
	if err == nil {
		t.Fatal("empty credentials validated")
	}
	for _, want := range []string{"tenant_id", "client_id", "client_secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}
