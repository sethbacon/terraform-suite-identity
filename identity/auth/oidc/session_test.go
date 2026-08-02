package oidc

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/sethbacon/terraform-suite-identity/identity/auth/oauthstate"
)

func sessionTestProvider() *Provider {
	return NewProviderForConfig(&oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://idp.example.com/authorize",
			TokenURL: "https://idp.example.com/token",
		},
	})
}

func sessionTestManager(t *testing.T) *oauthstate.Manager {
	t.Helper()
	// A one-hour sweep never fires during a test, so expiry behaviour comes
	// from the read path rather than a background goroutine.
	m, err := oauthstate.NewManager(oauthstate.NewMemoryStore(time.Hour, 0))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// junkStore returns a well-formed oauthstate entry whose opaque payload is not
// a session envelope, standing in for a corrupted or foreign store record.
// The base64 payload decodes to "not-an-envelope".
type junkStore struct{}

func (junkStore) PutIfAbsent(context.Context, string, []byte, time.Duration) error { return nil }
func (junkStore) Take(context.Context, string) ([]byte, error) {
	return []byte(`{"purpose":"oidc-login","expires_at":"2999-01-01T00:00:00Z","payload":"bm90LWFuLWVudmVsb3Bl"}`), nil
}
func (junkStore) Close() error { return nil }

func TestBeginAuthSession_MintsStateAndBindsNonceAndPKCE(t *testing.T) {
	p := sessionTestProvider()
	states := sessionTestManager(t)

	sess, err := p.BeginAuthSession(context.Background(), states, "oidc-login", []byte(`{"redirect":"/home"}`), time.Minute)
	if err != nil {
		t.Fatalf("BeginAuthSession: %v", err)
	}
	if sess.State == "" {
		t.Fatal("BeginAuthSession returned an empty state")
	}

	parsed, err := url.Parse(sess.URL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := parsed.Query()

	if got := q.Get("state"); got != sess.State {
		t.Errorf("state in URL = %q; want %q", got, sess.State)
	}
	if q.Get("nonce") == "" {
		t.Error("auth URL carries no nonce")
	}
	if q.Get("code_challenge") == "" {
		t.Error("auth URL carries no PKCE code_challenge")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q; want S256", got)
	}

	// The state must survive the round trip and hand back the same secrets
	// the authorization request was built with.
	cb, err := p.CompleteAuthSession(context.Background(), states, "oidc-login", sess.State)
	if err != nil {
		t.Fatalf("CompleteAuthSession: %v", err)
	}
	if cb.Nonce != q.Get("nonce") {
		t.Errorf("stored nonce = %q; want the one sent in the auth URL %q", cb.Nonce, q.Get("nonce"))
	}
	if got := oauth2.S256ChallengeFromVerifier(cb.CodeVerifier); got != q.Get("code_challenge") {
		t.Errorf("stored code verifier hashes to %q; want the challenge sent in the auth URL %q", got, q.Get("code_challenge"))
	}
}

// TestBeginAuthSession_StateCarriesNoCallerData is the regression test for the
// defect the oauthstate contract exists to prevent: the caller's payload must
// not be derivable from the state, which travels through the user agent.
func TestBeginAuthSession_StateCarriesNoCallerData(t *testing.T) {
	const (
		userID     = "user-1234-5678"
		providerID = "provider-9f1c"
	)
	payload := []byte(`{"user_id":"` + userID + `","provider_id":"` + providerID + `"}`)

	p := sessionTestProvider()
	states := sessionTestManager(t)

	first, err := p.BeginAuthSession(context.Background(), states, "scm:"+providerID, payload, time.Minute)
	if err != nil {
		t.Fatalf("BeginAuthSession: %v", err)
	}
	second, err := p.BeginAuthSession(context.Background(), states, "scm:"+providerID, payload, time.Minute)
	if err != nil {
		t.Fatalf("BeginAuthSession (second): %v", err)
	}

	if first.State == second.State {
		t.Error("two logins with identical inputs produced the same state; the state is derived, not random")
	}
	for _, needle := range []string{userID, providerID, "user_id"} {
		if strings.Contains(first.State, needle) {
			t.Errorf("state %q contains caller data %q", first.State, needle)
		}
		if strings.Contains(first.URL, needle) {
			t.Errorf("auth URL leaks caller data %q to the user agent", needle)
		}
	}
}

func TestCompleteAuthSession_RoundTripsOpaquePayload(t *testing.T) {
	// The purposes vary deliberately: both methods must forward the caller's
	// purpose verbatim, so a round trip has to work for a purpose other than
	// the obvious "oidc-login" default.
	tests := []struct {
		name    string
		purpose string
		payload []byte
	}{
		{name: "nil payload", purpose: "oidc-login", payload: nil},
		{name: "json payload", purpose: "azuread-login", payload: []byte(`{"user_id":"u-1","redirect_url":"/modules"}`)},
		{name: "binary payload", purpose: "scm:provider-9f1c", payload: []byte{0x00, 0xff, 0x7f}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sessionTestProvider()
			states := sessionTestManager(t)

			sess, err := p.BeginAuthSession(context.Background(), states, tt.purpose, tt.payload, time.Minute)
			if err != nil {
				t.Fatalf("BeginAuthSession: %v", err)
			}

			cb, err := p.CompleteAuthSession(context.Background(), states, tt.purpose, sess.State)
			if err != nil {
				t.Fatalf("CompleteAuthSession: %v", err)
			}
			if !bytes.Equal(cb.Payload, tt.payload) {
				t.Errorf("payload = %q; want %q", cb.Payload, tt.payload)
			}
			if cb.Nonce == "" {
				t.Error("CompleteAuthSession returned an empty nonce")
			}
			if cb.CodeVerifier == "" {
				t.Error("CompleteAuthSession returned an empty code verifier")
			}
		})
	}
}

func TestCompleteAuthSession_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, p *Provider, states *oauthstate.Manager) (purpose, state string)
		wantErr error
	}{
		{
			name: "state that was never issued",
			prepare: func(t *testing.T, p *Provider, states *oauthstate.Manager) (string, string) {
				return "oidc-login", strings.Repeat("A", 43)
			},
			wantErr: oauthstate.ErrNotFound,
		},
		{
			name: "state completed twice",
			prepare: func(t *testing.T, p *Provider, states *oauthstate.Manager) (string, string) {
				sess, err := p.BeginAuthSession(context.Background(), states, "oidc-login", []byte("payload"), time.Minute)
				if err != nil {
					t.Fatalf("BeginAuthSession: %v", err)
				}
				if _, err := p.CompleteAuthSession(context.Background(), states, "oidc-login", sess.State); err != nil {
					t.Fatalf("first CompleteAuthSession: %v", err)
				}
				return "oidc-login", sess.State
			},
			wantErr: oauthstate.ErrNotFound,
		},
		{
			name: "expired state",
			prepare: func(t *testing.T, p *Provider, states *oauthstate.Manager) (string, string) {
				sess, err := p.BeginAuthSession(context.Background(), states, "oidc-login", []byte("payload"), time.Nanosecond)
				if err != nil {
					t.Fatalf("BeginAuthSession: %v", err)
				}
				time.Sleep(5 * time.Millisecond)
				return "oidc-login", sess.State
			},
			wantErr: oauthstate.ErrNotFound,
		},
		{
			name: "state redeemed at a different resource's callback",
			prepare: func(t *testing.T, p *Provider, states *oauthstate.Manager) (string, string) {
				sess, err := p.BeginAuthSession(context.Background(), states, "scm:provider-a", []byte("payload"), time.Minute)
				if err != nil {
					t.Fatalf("BeginAuthSession: %v", err)
				}
				return "scm:provider-b", sess.State
			},
			wantErr: oauthstate.ErrPurposeMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sessionTestProvider()
			states := sessionTestManager(t)

			purpose, state := tt.prepare(t, p, states)

			cb, err := p.CompleteAuthSession(context.Background(), states, purpose, state)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CompleteAuthSession error = %v; want %v", err, tt.wantErr)
			}
			if cb.Payload != nil || cb.Nonce != "" || cb.CodeVerifier != "" {
				t.Errorf("CompleteAuthSession returned session material %+v on a rejected callback", cb)
			}
		})
	}
}

func TestBeginAuthSession_PropagatesIssueValidation(t *testing.T) {
	p := sessionTestProvider()
	states := sessionTestManager(t)

	sess, err := p.BeginAuthSession(context.Background(), states, "", []byte("payload"), time.Minute)
	if err == nil {
		t.Fatalf("BeginAuthSession succeeded with an empty purpose (state %q)", sess.State)
	}
	if !strings.Contains(err.Error(), "purpose is required") {
		t.Errorf("error = %q; want it to name the missing purpose", err)
	}
	if sess.URL != "" || sess.State != "" {
		t.Errorf("BeginAuthSession returned %+v alongside an error; want the zero value", sess)
	}
}

func TestAuthSession_RequiresStateManager(t *testing.T) {
	p := sessionTestProvider()

	if _, err := p.BeginAuthSession(context.Background(), nil, "oidc-login", nil, time.Minute); err == nil {
		t.Error("BeginAuthSession(nil manager) succeeded; want an error")
	}
	if _, err := p.CompleteAuthSession(context.Background(), nil, "oidc-login", "state"); err == nil {
		t.Error("CompleteAuthSession(nil manager) succeeded; want an error")
	}
}

func TestCompleteAuthSession_UndecodableEntry(t *testing.T) {
	p := sessionTestProvider()
	states, err := oauthstate.NewManager(junkStore{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	cb, err := p.CompleteAuthSession(context.Background(), states, "oidc-login", "some-state")
	if err == nil {
		t.Fatal("CompleteAuthSession succeeded on an undecodable entry")
	}
	if !strings.Contains(err.Error(), "failed to decode session payload") {
		t.Errorf("error = %q; want a session-payload decode failure", err)
	}
	if cb.Payload != nil || cb.Nonce != "" || cb.CodeVerifier != "" {
		t.Errorf("CompleteAuthSession returned session material %+v alongside an error", cb)
	}
}
