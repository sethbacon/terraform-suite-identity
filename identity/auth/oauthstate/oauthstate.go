// Package oauthstate implements the missing half of the OAuth/OIDC `state`
// protocol: minting an unguessable state, persisting an opaque caller payload
// against it under a TTL, and consuming it exactly once at the callback.
//
// # Why this exists
//
// identity/auth/oidc hands the caller a `state` string to pass into
// GetAuthURL/BeginAuth but shipped no counterpart to verify one, so every
// consumer had to invent that half itself. Two apps hand-rolled near-identical
// single-use stores. A third call site — the registry's SCM connector
// authorization flow — did not, and instead built the state as
// fmt.Sprintf("%s:%s", userID, providerID) and trusted it back at an
// unauthenticated callback.
//
// A self-describing state like that is not a CSRF token at all. It is
// guessable and forgeable, it is not single-use so it replays, and because the
// callback reads the principal and the target resource out of it, an anonymous
// caller gets to name whose record the callback writes. That was a critical
// vulnerability, and it was reachable precisely because passing a
// self-describing value was the path of least resistance.
//
// The defence here is structural rather than advisory: a caller cannot supply
// a state in the first place. Manager.Issue mints one from crypto/rand and
// keeps the caller's meaning in a payload the module never interprets;
// Manager.Consume redeems that state exactly once, after checking expiry and
// the purpose binding, and only then hands the payload back. Everything the
// callback needs to trust therefore comes from server-side storage, never from
// the request.
//
// # What belongs where
//
// The module owns the security-critical protocol — entropy, TTL, single use,
// purpose binding. The application owns the meaning: it serializes its own
// session struct (the two consuming apps' structs genuinely differ) into the
// opaque payload and gets those exact bytes back at the callback. The module
// never unmarshals it.
//
// # Usage
//
//	states, err := oauthstate.NewManager(oauthstate.NewMemoryStore(0, 0))
//	// login: purpose names the flow AND the resource it is bound to
//	state, err := states.Issue(ctx, "scm:"+providerID, payload, oauthstate.DefaultTTL)
//	// callback: the same purpose must be reconstructed from the callback's own
//	// route/context — never from the state
//	payload, err := states.Consume(ctx, "scm:"+providerID, r.FormValue("state"))
//
// For an OIDC login, prefer oidc.Provider.BeginAuthSession /
// oidc.Provider.CompleteAuthSession, which drive this package for you and also
// carry the per-login nonce and PKCE verifier inside the stored payload.
package oauthstate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DefaultTTL is a reasonable lifetime for an in-flight authorization request:
// long enough for a user to complete an interactive login at the identity
// provider, short enough that an abandoned or intercepted state stops being
// redeemable quickly. Callers pass their own TTL to Issue; this is only a
// suggested value.
const DefaultTTL = 10 * time.Minute

// stateEntropyBytes is the number of crypto/rand bytes behind every issued
// state (256 bits, base64url-encoded to 43 characters). This is the property
// that makes a state unguessable, and it is the reason Issue takes no
// caller-supplied state.
const stateEntropyBytes = 32

// Store keys are namespaced by kind so that a value written by one Manager
// method can never be redeemed through another — a Reserve marker is not a
// state, and Consume must not be able to return one.
const (
	statePrefix   = "state:"
	reservePrefix = "reserve:"
)

// Sentinel errors returned by Manager. Callers should surface a single generic
// failure to the end user (distinguishing them in a response body tells an
// attacker which guard tripped); they exist so that server-side logs and tests
// can pin the specific verdict.
var (
	// ErrNotFound means the state was never issued, has already been consumed,
	// or has aged out of the store. These are deliberately indistinguishable:
	// the store cannot tell them apart, and a caller must treat all three the
	// same way.
	ErrNotFound = errors.New("oauthstate: state not found, already consumed, or expired")

	// ErrExpired means a stored entry was still present but its recorded
	// expiry had passed. Manager checks this itself rather than trusting the
	// Store's TTL, so a backend whose expiry is coarse, lagging, or
	// misconfigured cannot resurrect a stale authorization request.
	ErrExpired = errors.New("oauthstate: state expired")

	// ErrPurposeMismatch means the state was issued for a different purpose or
	// resource than the one it is being redeemed against — e.g. a state minted
	// for SCM provider A presented at provider B's callback. The state is
	// consumed regardless (see Consume).
	ErrPurposeMismatch = errors.New("oauthstate: state was issued for a different purpose")

	// ErrAlreadyExists is returned by Store.PutIfAbsent when a live entry
	// already exists for the key. Manager.Reserve turns it into reserved=false.
	ErrAlreadyExists = errors.New("oauthstate: entry already exists")
)

// Store is the persistence primitive behind Manager. It is deliberately
// narrow: it stores and retrieves opaque bytes and knows nothing about states,
// purposes, or entropy. Minting and verification stay in Manager so that
// bringing your own backend (Redis, Memcached, a database table) cannot
// weaken the protocol — an implementation gets no say in what a state looks
// like.
//
// The module ships MemoryStore as a reference implementation. It deliberately
// does not ship a Redis one: that would put a client dependency in a library
// linked into every consumer. An HA deployment implements this interface over
// its own client (SET NX EX for PutIfAbsent, GETDEL or an atomic
// GET+DEL script for Take).
//
// Implementations MUST be safe for concurrent use by multiple goroutines and
// MUST make Take atomic: a get followed by a separate delete lets two
// concurrent callbacks both observe a live entry, which is exactly how replay
// gets in.
type Store interface {
	// PutIfAbsent stores entry under key for ttl, failing with
	// ErrAlreadyExists if a live entry already exists for that key. The
	// check-and-set MUST be atomic — Manager.Reserve relies on it for
	// single-use replay detection. Implementations must not retain or mutate
	// the caller's slice.
	PutIfAbsent(ctx context.Context, key string, entry []byte, ttl time.Duration) error

	// Take atomically retrieves and removes the entry for key, returning
	// ErrNotFound when no live entry exists. It MUST remove the entry on every
	// hit, not only on the branch that returns data — a non-consuming read is
	// how a state stops being single-use.
	Take(ctx context.Context, key string) ([]byte, error)

	// Close releases resources held by the store (background goroutines,
	// connections). It must be safe to call more than once.
	Close() error
}

// Manager owns the state protocol: it mints states, wraps caller payloads in
// an envelope carrying the purpose binding and expiry, and redeems them
// exactly once. It is safe for concurrent use provided its Store is.
//
// Manager is a concrete type, and oidc.Provider's session methods take it
// concretely rather than as an interface, on purpose: an interface here would
// let an application substitute its own minting and reintroduce the
// self-describing state this package exists to prevent.
type Manager struct {
	store Store
}

// NewManager returns a Manager backed by store, which must be non-nil.
func NewManager(store Store) (*Manager, error) {
	if store == nil {
		return nil, errors.New("oauthstate: NewManager requires a non-nil Store")
	}
	return &Manager{store: store}, nil
}

// envelope is what a Manager actually stores. The caller's payload rides
// inside it untouched; Purpose and ExpiresAt are the module's, and are checked
// at Consume before the payload is handed back.
type envelope struct {
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	Payload   []byte    `json:"payload,omitempty"`
}

// Issue mints a fresh, unguessable state, stores payload against it for ttl,
// and returns the state for use as the OAuth `state` parameter.
//
// purpose binds the state to the flow AND to the specific resource it is for —
// use a value the callback can independently reconstruct from its own route or
// configuration, such as "oidc-login" or "scm:"+providerID. A state issued
// under one purpose cannot be redeemed under another, which is what stops a
// state minted for one provider from filing a token under a different one.
//
// payload is opaque: whatever the caller needs at the callback (its own
// serialized session struct), stored server-side and never exposed to the user
// agent. It may be nil. Nothing about it influences the returned state, so no
// part of it leaks to the browser or to the identity provider.
func (m *Manager) Issue(ctx context.Context, purpose string, payload []byte, ttl time.Duration) (string, error) {
	if purpose == "" {
		return "", errors.New("oauthstate: purpose is required")
	}
	if ttl <= 0 {
		return "", errors.New("oauthstate: ttl must be positive")
	}

	state, err := newState()
	if err != nil {
		return "", err
	}

	encoded, err := json.Marshal(envelope{
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(ttl),
		Payload:   payload,
	})
	if err != nil {
		return "", fmt.Errorf("oauthstate: failed to encode state entry: %w", err)
	}

	if err := m.store.PutIfAbsent(ctx, statePrefix+state, encoded, ttl); err != nil {
		// A collision on 256 bits of entropy means something is badly wrong
		// (a broken RNG, or a store returning stale keys); fail closed rather
		// than overwriting another login's state.
		return "", fmt.Errorf("oauthstate: failed to store state: %w", err)
	}
	return state, nil
}

// Consume redeems state exactly once and returns the payload Issue was given.
//
// The state is consumed before any check runs, so a state presented with the
// wrong purpose, or after it expired, is destroyed rather than left for
// another attempt: an attacker probing purposes burns the state on the first
// probe. Returns ErrNotFound (never issued, already consumed, or aged out),
// ErrExpired, or ErrPurposeMismatch.
//
// purpose must be reconstructed from the callback's own context — its route
// parameter, its configured provider — and never parsed out of the state or
// any other attacker-controlled input, or the binding checks nothing.
func (m *Manager) Consume(ctx context.Context, purpose, state string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("oauthstate: purpose is required")
	}

	// An empty state is not special-cased: it is looked up like any other and
	// the store reports ErrNotFound, because Issue never mints one.
	stored, err := m.store.Take(ctx, statePrefix+state)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("oauthstate: failed to load state: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(stored, &env); err != nil {
		return nil, fmt.Errorf("oauthstate: failed to decode state entry: %w", err)
	}

	// Checked here as well as by the Store: the Store's TTL is the backend's
	// promise, this is the module's own. A store with coarse expiry, a lagging
	// janitor, or a mis-set TTL must not be able to make a stale authorization
	// request redeemable.
	if time.Now().After(env.ExpiresAt) {
		return nil, ErrExpired
	}

	// Plain comparison: purpose is a routing label, not a secret, so there is
	// no timing signal worth defending here (the state itself was already
	// looked up by key).
	if env.Purpose != purpose {
		return nil, ErrPurposeMismatch
	}

	return env.Payload, nil
}

// Reserve atomically records a single-use marker under key for ttl. It returns
// true the first time a key is seen and false when a live marker already
// exists — that false is a replay.
//
// Unlike a state, the key here is a caller-supplied identifier that the module
// did not mint: the intended use is an identifier some external party assigned
// and that must not be honoured twice, such as a SAML assertion ID checked at
// the ACS endpoint. It is stored in a separate namespace from issued states,
// so a marker can never be redeemed by Consume.
func (m *Manager) Reserve(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, errors.New("oauthstate: key is required")
	}
	if ttl <= 0 {
		return false, errors.New("oauthstate: ttl must be positive")
	}

	err := m.store.PutIfAbsent(ctx, reservePrefix+key, nil, ttl)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrAlreadyExists):
		return false, nil
	default:
		return false, fmt.Errorf("oauthstate: failed to reserve key: %w", err)
	}
}

// Close releases the underlying Store.
func (m *Manager) Close() error {
	return m.store.Close()
}

// newState returns a base64url-encoded, 256-bit random string. It is the only
// place a state is created — there is no code path by which a caller-supplied
// value becomes a state.
func newState() (string, error) {
	b := make([]byte, stateEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauthstate: failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
