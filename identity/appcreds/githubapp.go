// githubapp.go mints GitHub installation access tokens: it signs a short-lived
// app JWT (RS256) with the app's private key, then exchanges that for an
// installation token. This is the headless, app-owned alternative to per-user
// OAuth for GitHub integrations.
//
// The JWT is hand-rolled over crypto/rsa rather than pulled from a JWT library.
// A GitHub App JWT is a plain RS256 token with three claims, so stdlib signing
// keeps the dependency surface of a SHARED module minimal -- every consumer of
// this module would otherwise inherit whatever a JWT library depends on.
package appcreds

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultGitHubAPIBaseURL is github.com's API host. GitHub Enterprise Server
// uses https://<host>/api/v3; see WithGitHubAPIBaseURL.
const DefaultGitHubAPIBaseURL = "https://api.github.com"

// appJWTLifetime is under GitHub's 10-minute maximum. The JWT is used once, to
// exchange for an installation token, so there is no reason to sit near the cap.
const appJWTLifetime = 9 * time.Minute

// appJWTBackdate absorbs clock skew between this host and GitHub. A JWT whose
// iat is even slightly in GitHub's future is rejected outright.
const appJWTBackdate = 60 * time.Second

// GitHubAppCreds is a GitHub App installation used to mint installation access
// tokens. PrivateKeyPEM is the app's RSA private key in PEM form (PKCS#1 or
// PKCS#8).
type GitHubAppCreds struct {
	AppID          string
	InstallationID string
	PrivateKeyPEM  string
}

// Validate reports whether the exchange has everything it needs. It does NOT
// parse the key -- see ValidRSAPrivateKey, which callers should run at the point
// the key is accepted from a user, not at every mint.
func (c GitHubAppCreds) Validate() error {
	var missing []string
	if strings.TrimSpace(c.AppID) == "" {
		missing = append(missing, "app_id")
	}
	if strings.TrimSpace(c.InstallationID) == "" {
		missing = append(missing, "installation_id")
	}
	if strings.TrimSpace(c.PrivateKeyPEM) == "" {
		missing = append(missing, "private_key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: github app auth requires %s",
			ErrInvalidCreds, strings.Join(missing, ", "))
	}
	return nil
}

// Fingerprint keys a cache, and folds in the private key so that rotating it
// invalidates the cached token even when the app and installation ids are
// unchanged -- which is exactly what a key rotation looks like.
func (c GitHubAppCreds) Fingerprint() string {
	sum := sha256.Sum256([]byte("github_app\x00" + c.AppID + "\x00" + c.InstallationID + "\x00" + c.PrivateKeyPEM))
	return hex.EncodeToString(sum[:])
}

// MintGitHubApp signs an app JWT and exchanges it for an installation access
// token, returning the token and its absolute expiry.
func (m *Minter) MintGitHubApp(ctx context.Context, creds GitHubAppCreds) (Token, error) {
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}
	key, err := parseRSAPrivateKey(creds.PrivateKeyPEM)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s", ErrInvalidCreds, err.Error())
	}
	appJWT, err := signAppJWT(creds.AppID, key, m.now())
	if err != nil {
		return Token{}, err
	}

	endpoint := fmt.Sprintf("%s/app/installations/%s/access_tokens",
		strings.TrimRight(m.githubAPIBaseURL, "/"), urlPathSegment(creds.InstallationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: build github installation token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: github installation token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if resp.StatusCode != http.StatusCreated {
		return Token{}, fmt.Errorf("appcreds: github installation token endpoint returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Token{}, fmt.Errorf("appcreds: github installation token response was not JSON: %w", err)
	}
	if out.Token == "" {
		return Token{}, errors.New("appcreds: github installation token response carried no token")
	}

	expiresAt, perr := time.Parse(time.RFC3339, out.ExpiresAt)
	if perr != nil {
		// GitHub installation tokens last about an hour. Erring short only costs
		// an extra mint; treating an unparseable expiry as far away serves a
		// dead token.
		expiresAt = m.now().Add(time.Hour)
	}
	return Token{AccessToken: out.Token, ExpiresAt: expiresAt}, nil
}

// ValidRSAPrivateKey reports whether pemStr parses as a supported RSA private
// key. Callers validate at the point a key is accepted from a user, so a bad
// key is a 400 on the request that supplied it rather than a mint failure days
// later.
func ValidRSAPrivateKey(pemStr string) bool {
	_, err := parseRSAPrivateKey(pemStr)
	return err == nil
}

// parseRSAPrivateKey accepts a PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE
// KEY") PEM and returns the RSA key. GitHub hands out PKCS#1; a key that has
// been through some conversion tools comes back PKCS#8, and rejecting that
// would look like "GitHub gave me a bad key".
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("private key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key is not a supported RSA key (PKCS#1 or PKCS#8): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		// An Ed25519 or ECDSA key parses as PKCS#8 perfectly well and cannot
		// sign an RS256 JWT, so this is a real path, not a defensive branch.
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

// signAppJWT builds a GitHub App JWT (RS256): header.payload signed with RSA
// PKCS#1 v1.5 over SHA-256.
func signAppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	header := `{"alg":"RS256","typ":"JWT"}`
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-appJWTBackdate).Unix(),
		"exp": now.Add(appJWTLifetime).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", fmt.Errorf("appcreds: encode app jwt claims: %w", err)
	}
	signingInput := b64url([]byte(header)) + "." + b64url(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("appcreds: sign app jwt: %w", err)
	}
	return signingInput + "." + b64url(sig), nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// urlPathSegment escapes a single path segment. Installation ids are numeric in
// practice, but this value reaches the URL from stored configuration and a
// slash in it would otherwise retarget the request to a different endpoint.
func urlPathSegment(s string) string {
	return strings.NewReplacer("/", "%2F", "?", "%3F", "#", "%23").Replace(s)
}
