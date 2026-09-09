package appcreds

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, string(pemBytes)
}

func ghServer(t *testing.T, status int, body string) (*httptest.Server, *http.Request) {
	t.Helper()
	var got http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestMintGitHubApp_Success(t *testing.T) {
	key, keyPEM := testRSAKey(t)
	expiry := testNow.Add(time.Hour).UTC().Truncate(time.Second)
	srv, req := ghServer(t, http.StatusCreated,
		`{"token":"ghs_installation","expires_at":"`+expiry.Format(time.RFC3339)+`"}`)

	m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL), WithClock(fixedClock(testNow)))
	tok, err := m.MintGitHubApp(context.Background(), GitHubAppCreds{
		AppID: "12345", InstallationID: "67890", PrivateKeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatalf("MintGitHubApp: %v", err)
	}
	if tok.AccessToken != "ghs_installation" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	// GitHub reports the expiry; it must be used rather than guessed, or a
	// caller caches for the wrong window.
	if !tok.ExpiresAt.Equal(expiry) {
		t.Errorf("expiry = %v, want GitHub's %v", tok.ExpiresAt, expiry)
	}
	if req.URL.Path != "/app/installations/67890/access_tokens" {
		t.Errorf("path = %q", req.URL.Path)
	}
	if got := req.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q -- GitHub may change behaviour without a pinned version", got)
	}

	// The JWT is VERIFIED rather than merely present. A malformed or wrongly
	// signed one would be rejected by GitHub and surface as an opaque 401 far
	// from this code, so the signature and claims are checked here against the
	// key that supposedly signed them.
	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		t.Fatalf("Authorization = %q, want a Bearer app JWT", authz)
	}
	parts := strings.Split(strings.TrimPrefix(authz, "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("app JWT has %d segments, want 3", len(parts))
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("app JWT does not verify against the app's own key: %v", err)
	}

	var hdr struct{ Alg, Typ string }
	rawHdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(rawHdr, &hdr); err != nil {
		t.Fatalf("header is not JSON: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Typ != "JWT" {
		t.Errorf("header = %+v, want RS256/JWT", hdr)
	}

	var claims struct {
		Iat, Exp int64
		Iss      string
	}
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatalf("claims are not JSON: %v", err)
	}
	if claims.Iss != "12345" {
		t.Errorf("iss = %q, want the app id", claims.Iss)
	}
	// Backdated: a JWT whose iat is even slightly in GitHub's future is
	// rejected outright, and clocks do drift.
	if claims.Iat != testNow.Add(-appJWTBackdate).Unix() {
		t.Errorf("iat = %d, want it backdated by %v", claims.Iat, appJWTBackdate)
	}
	// Under GitHub's hard 10-minute cap; a longer one is refused.
	if lifetime := time.Duration(claims.Exp-claims.Iat) * time.Second; lifetime > 10*time.Minute {
		t.Errorf("JWT lifetime %v exceeds GitHub's 10-minute maximum", lifetime)
	}
}

// A key that has been through a conversion tool comes back PKCS#8. Rejecting it
// would look to an operator like "GitHub gave me a bad key".
func TestMintGitHubApp_AcceptsPKCS8(t *testing.T) {
	key, _ := testRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	srv, _ := ghServer(t, http.StatusCreated, `{"token":"t","expires_at":"2026-09-08T13:00:00Z"}`)
	m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL), WithClock(fixedClock(testNow)))
	if _, err := m.MintGitHubApp(context.Background(), GitHubAppCreds{
		AppID: "1", InstallationID: "2", PrivateKeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("a PKCS#8 RSA key was rejected: %v", err)
	}
	if !ValidRSAPrivateKey(keyPEM) {
		t.Error("ValidRSAPrivateKey rejected a PKCS#8 RSA key")
	}
}

// An Ed25519 key parses as PKCS#8 perfectly well and cannot sign an RS256 JWT.
// Without the type assertion this would panic or sign nothing.
func TestMintGitHubApp_RejectsNonRSAKeys(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	if ValidRSAPrivateKey(keyPEM) {
		t.Error("ValidRSAPrivateKey accepted an Ed25519 key")
	}
	m := newTestMinter(t, WithClock(fixedClock(testNow)))
	_, err = m.MintGitHubApp(context.Background(), GitHubAppCreds{
		AppID: "1", InstallationID: "2", PrivateKeyPEM: keyPEM,
	})
	if err == nil {
		t.Fatal("an Ed25519 key minted an RS256 JWT")
	}
	if !errors.Is(err, ErrInvalidCreds) {
		t.Errorf("error %v is not ErrInvalidCreds, so a caller cannot report it as a 400", err)
	}
}

func TestMintGitHubApp_Failures(t *testing.T) {
	_, keyPEM := testRSAKey(t)
	creds := GitHubAppCreds{AppID: "1", InstallationID: "2", PrivateKeyPEM: keyPEM}

	cases := []struct {
		name       string
		status     int
		body       string
		wantErrHas string
	}{
		// 200 is NOT success here: GitHub returns 201 Created. Accepting 200
		// would treat a proxy's cached empty response as a token.
		{"200 is not created", http.StatusOK, `{"token":"t"}`, "returned 200"},
		{"404 unknown installation", http.StatusNotFound, `{"message":"Not Found"}`, "Not Found"},
		{"not JSON", http.StatusCreated, `<html>gateway</html>`, "not JSON"},
		{"no token", http.StatusCreated, `{"expires_at":"2026-09-08T13:00:00Z"}`, "no token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := ghServer(t, tc.status, tc.body)
			m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL), WithClock(fixedClock(testNow)))
			_, err := m.MintGitHubApp(context.Background(), creds)
			if err == nil {
				t.Fatal("mint succeeded")
			}
			if !strings.Contains(err.Error(), tc.wantErrHas) {
				t.Errorf("error %q does not mention %q", err, tc.wantErrHas)
			}
		})
	}
}

// An unparseable expires_at must not yield a zero time: Token.Expired treats
// that as spent, and a caller storing it would re-mint on every call.
func TestMintGitHubApp_UnparseableExpiryFallsBackToAnHour(t *testing.T) {
	_, keyPEM := testRSAKey(t)
	srv, _ := ghServer(t, http.StatusCreated, `{"token":"t","expires_at":"not a timestamp"}`)
	m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL), WithClock(fixedClock(testNow)))

	tok, err := m.MintGitHubApp(context.Background(), GitHubAppCreds{
		AppID: "1", InstallationID: "2", PrivateKeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatalf("MintGitHubApp: %v", err)
	}
	if want := testNow.Add(time.Hour); !tok.ExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want %v", tok.ExpiresAt, want)
	}
}

// An installation id reaches the URL from stored configuration. A slash in it
// would otherwise retarget the request to a different endpoint entirely.
func TestMintGitHubApp_EscapesTheInstallationID(t *testing.T) {
	_, keyPEM := testRSAKey(t)
	srv, req := ghServer(t, http.StatusCreated, `{"token":"t","expires_at":"2026-09-08T13:00:00Z"}`)
	m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL), WithClock(fixedClock(testNow)))

	if _, err := m.MintGitHubApp(context.Background(), GitHubAppCreds{
		AppID: "1", InstallationID: "2/../../orgs", PrivateKeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("MintGitHubApp: %v", err)
	}
	if !strings.Contains(req.URL.EscapedPath(), "%2F") {
		t.Errorf("installation id was not escaped: %q", req.URL.EscapedPath())
	}
}

func TestMintGitHubApp_InvalidCredsNeverReachTheNetwork(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ }))
	defer srv.Close()
	m := newTestMinter(t, WithGitHubAPIBaseURL(srv.URL))

	for _, creds := range []GitHubAppCreds{
		{InstallationID: "2", PrivateKeyPEM: "k"},
		{AppID: "1", PrivateKeyPEM: "k"},
		{AppID: "1", InstallationID: "2"},
		{},
	} {
		if _, err := m.MintGitHubApp(context.Background(), creds); !errors.Is(err, ErrInvalidCreds) {
			t.Errorf("%+v: error %v is not ErrInvalidCreds", creds, err)
		}
	}
	if called != 0 {
		t.Errorf("the endpoint was called %d times with invalid credentials, want 0", called)
	}
}

func TestParseRSAPrivateKey_RejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"not a pem at all",
		"-----BEGIN RSA PRIVATE KEY-----\nnot base64\n-----END RSA PRIVATE KEY-----",
	} {
		if _, err := parseRSAPrivateKey(in); err == nil {
			t.Errorf("%q parsed as a private key", in)
		}
		if ValidRSAPrivateKey(in) {
			t.Errorf("ValidRSAPrivateKey accepted %q", in)
		}
	}

	// Valid PEM whose payload is not a key at all: it decodes, then fails both
	// the PKCS#1 and the PKCS#8 parse.
	notAKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	if _, err := parseRSAPrivateKey(notAKey); err == nil {
		t.Error("a PEM block containing arbitrary bytes parsed as a private key")
	}
}
