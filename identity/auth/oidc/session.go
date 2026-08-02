package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sethbacon/terraform-suite-identity/identity/auth/oauthstate"
)

// AuthSession is the result of BeginAuthSession: where to send the user agent,
// and the state that was minted for this login.
//
// There is nothing here the caller must remember to persist. The nonce and
// PKCE verifier for this login are stored server-side against State and come
// back from CompleteAuthSession — unlike BeginAuth, where forgetting to
// persist them silently drops both bindings.
type AuthSession struct {
	// URL is the authorization endpoint URL to redirect the user agent to.
	URL string
	// State is the state parameter embedded in URL. It is an unguessable,
	// single-use token minted by oauthstate.Manager and carries no meaning:
	// never parse it, and never derive the principal or the target resource
	// from it at the callback.
	State string
}

// CallbackSession is the result of CompleteAuthSession — everything the
// callback needs, all of it read from server-side storage rather than from the
// callback request.
type CallbackSession struct {
	// Payload is the opaque payload handed to BeginAuthSession, byte for byte.
	Payload []byte
	// Nonce must be passed to VerifyIDToken via WithExpectedNonce.
	Nonce string
	// CodeVerifier must be passed to ExchangeCode via WithPKCEVerifier.
	CodeVerifier string
}

// sessionEnvelope is what this package stores in the opaque oauthstate
// payload. Wrapping the caller's payload here — rather than teaching
// oauthstate about nonces — keeps that package free of OIDC concepts and keeps
// the caller's payload opaque to both.
type sessionEnvelope struct {
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Payload      []byte `json:"payload,omitempty"`
}

// BeginAuthSession starts a login without the caller ever handling a state
// value. It generates the per-login nonce and PKCE verifier exactly as
// BeginAuth does, but stores them — together with the caller's opaque payload —
// against a state minted from crypto/rand by states, and returns the
// authorization URL with that state already embedded.
//
// This is the safe counterpart to BeginAuth: because there is no state
// parameter to pass, there is no way to pass a self-describing one, and the
// callback has a matching CompleteAuthSession that consumes the state exactly
// once.
//
// purpose binds the state to this flow and to the specific resource behind it
// (e.g. "oidc-login" or "scm:"+providerID); CompleteAuthSession must be given
// the same value, reconstructed from the callback's own route or configuration
// rather than from the request. payload is opaque to this module — serialize
// whatever the callback needs (the app's own session struct) into it; it may
// be nil. ttl bounds how long the login may take (oauthstate.DefaultTTL is a
// reasonable choice).
func (p *Provider) BeginAuthSession(ctx context.Context, states *oauthstate.Manager, purpose string, payload []byte, ttl time.Duration) (AuthSession, error) {
	if states == nil {
		return AuthSession{}, fmt.Errorf("oidc: BeginAuthSession requires a non-nil *oauthstate.Manager")
	}

	nonce, err := randomNonce()
	if err != nil {
		return AuthSession{}, fmt.Errorf("failed to generate OIDC nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	entry, err := json.Marshal(sessionEnvelope{
		Nonce:        nonce,
		CodeVerifier: verifier,
		Payload:      payload,
	})
	if err != nil {
		return AuthSession{}, fmt.Errorf("oidc: failed to encode session payload: %w", err)
	}

	state, err := states.Issue(ctx, purpose, entry, ttl)
	if err != nil {
		return AuthSession{}, fmt.Errorf("oidc: failed to issue state: %w", err)
	}

	authURL := p.config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return AuthSession{URL: authURL, State: state}, nil
}

// CompleteAuthSession verifies the state returned to the callback, consuming
// it exactly once, and returns the payload plus the nonce and PKCE verifier
// stored for this login. Pass those to ExchangeCode (WithPKCEVerifier) and
// VerifyIDToken (WithExpectedNonce).
//
// purpose must be the same value BeginAuthSession was given, reconstructed
// from the callback's own context — its route parameter, its configured
// provider — and never parsed out of the state or any other part of the
// request. Errors wrap oauthstate's sentinels (oauthstate.ErrNotFound,
// ErrExpired, ErrPurposeMismatch) and match errors.Is; report a single generic
// failure to the user agent and keep the distinction for server-side logs.
func (p *Provider) CompleteAuthSession(ctx context.Context, states *oauthstate.Manager, purpose, state string) (CallbackSession, error) {
	if states == nil {
		return CallbackSession{}, fmt.Errorf("oidc: CompleteAuthSession requires a non-nil *oauthstate.Manager")
	}

	entry, err := states.Consume(ctx, purpose, state)
	if err != nil {
		return CallbackSession{}, fmt.Errorf("oidc: state verification failed: %w", err)
	}

	var env sessionEnvelope
	if err := json.Unmarshal(entry, &env); err != nil {
		return CallbackSession{}, fmt.Errorf("oidc: failed to decode session payload: %w", err)
	}

	return CallbackSession{
		Payload:      env.Payload,
		Nonce:        env.Nonce,
		CodeVerifier: env.CodeVerifier,
	}, nil
}
