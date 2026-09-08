// entra.go mints Azure DevOps access tokens from a Microsoft Entra app
// registration via the OAuth 2.0 client-credentials grant: the headless,
// app-owned alternative to per-user OAuth. There is no user and no refresh
// token -- the grant simply re-mints.
package appcreds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxTokenResponseBytes bounds what is read from a token endpoint. A token
// response is a few hundred bytes; anything larger is a misconfigured host or a
// hostile one, and neither should be able to exhaust memory.
const maxTokenResponseBytes = 8 << 10

// EntraCreds is a Microsoft Entra app registration used to mint Azure DevOps
// access tokens via the client-credentials grant.
type EntraCreds struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Validate reports whether the grant has everything it needs.
func (c EntraCreds) Validate() error {
	var missing []string
	if strings.TrimSpace(c.TenantID) == "" {
		missing = append(missing, "tenant_id")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		missing = append(missing, "client_id")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		missing = append(missing, "client_secret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: entra client-credentials requires %s",
			ErrInvalidCreds, strings.Join(missing, ", "))
	}
	return nil
}

// Fingerprint keys a cache so that rotating ANY field yields a different key and
// the old token is never served again.
//
// The "entra_client_secret" namespace and the NUL separators keep this from
// colliding with another credential type's fingerprint in a shared cache, and
// keep two different field splits ("ab"+"c" versus "a"+"bc") from hashing alike.
func (c EntraCreds) Fingerprint() string {
	sum := sha256.Sum256([]byte("entra_client_secret\x00" + c.TenantID + "\x00" + c.ClientID + "\x00" + c.ClientSecret))
	return hex.EncodeToString(sum[:])
}

// MintEntra performs the client-credentials POST against the tenant's v2.0 token
// endpoint and returns the access token with its absolute expiry.
func (m *Minter) MintEntra(ctx context.Context, creds EntraCreds) (Token, error) {
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", creds.ClientID)
	form.Set("client_secret", creds.ClientSecret)
	form.Set("scope", AzureDevOpsResourceID+"/.default")

	// PathEscape on the tenant: it reaches this from operator-supplied
	// configuration, and an unescaped one could otherwise add path segments to
	// the endpoint and send the client secret somewhere else entirely.
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token",
		strings.TrimRight(m.entraLoginBaseURL, "/"), url.PathEscape(creds.TenantID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: build entra token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: entra token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if resp.StatusCode != http.StatusOK {
		// Entra puts an AADSTS code in the body and it is the only thing that
		// distinguishes "wrong secret" from "app not consented" from "tenant
		// does not exist", so it is surfaced rather than swallowed. The body of
		// a FAILED client-credentials response carries no token; the secret was
		// in the request, and is not echoed back.
		return Token{}, fmt.Errorf("appcreds: entra token endpoint returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Token{}, fmt.Errorf("appcreds: entra token response was not JSON: %w", err)
	}
	if out.AccessToken == "" {
		return Token{}, fmt.Errorf("appcreds: entra token response carried no access_token")
	}

	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		// Absent or nonsensical expires_in. An hour is Entra's own default, and
		// erring short only costs an extra mint; erring long serves a dead token.
		ttl = time.Hour
	}
	return Token{AccessToken: out.AccessToken, ExpiresAt: m.now().Add(ttl)}, nil
}
