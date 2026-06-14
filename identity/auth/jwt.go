package auth

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the suite-standard JWT claims payload carried by access tokens.
// JTI is a unique token identifier that apps may use for revocation
// (e.g. a denylist keyed by JTI).
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Scopes []string `json:"scopes,omitempty"`
	JTI    string   `json:"jti,omitempty"`
	jwt.RegisteredClaims
}

// DefaultExpiry is applied when Generate is called with expiresIn == 0.
const DefaultExpiry = time.Hour

// TokenManager issues and validates HS256 JWTs using an injected signing secret
// and issuer. It holds no global or environment state, so each consuming app
// configures its own instance (e.g. from its own secret env var) — keeping this
// package app-neutral.
//
// The signing secret can be rotated at runtime via RotateSecret: the previous
// secret remains accepted for validation until ClearPreviousSecret is called,
// giving in-flight tokens an overlap window. Generate always signs with the
// current secret.
type TokenManager struct {
	issuer   string
	current  atomic.Pointer[[]byte]
	previous atomic.Pointer[[]byte]
	// allowedIssuers, when non-nil, restricts Validate to tokens whose `iss`
	// claim is in the set. nil (the default) disables the check — accepting any
	// issuer, preserving single-app behaviour.
	allowedIssuers atomic.Pointer[[]string]
}

// NewTokenManager returns a TokenManager that signs with secret and stamps the
// given issuer into generated tokens.
func NewTokenManager(secret, issuer string) *TokenManager {
	m := &TokenManager{issuer: issuer}
	b := []byte(secret)
	m.current.Store(&b)
	return m
}

// RotateSecret swaps in newSecret as the current signing secret and retains the
// outgoing secret as the previous one, so tokens signed with it still validate
// until ClearPreviousSecret. Safe for concurrent use.
func (m *TokenManager) RotateSecret(newSecret []byte) {
	if cur := m.current.Load(); cur != nil {
		m.previous.Store(cur)
	}
	b := append([]byte(nil), newSecret...)
	m.current.Store(&b)
}

// ClearPreviousSecret drops the previous signing secret, ending the rotation
// overlap window. Tokens signed with the previous secret no longer validate.
func (m *TokenManager) ClearPreviousSecret() {
	m.previous.Store(nil)
}

// SetAllowedIssuers restricts Validate to tokens whose `iss` claim is one of the
// given issuers. An empty or nil set (the default) disables the check entirely,
// accepting any issuer — so this is fully backward-compatible for single-app use.
//
// In a coupled suite sharing one signing secret, set this to {own issuer} plus
// the trusted sibling issuers so a shared secret cannot be replayed from an
// untrusted minter while still accepting legitimate sibling tokens. Safe for
// concurrent use and intended to be updated at runtime as siblings are
// discovered.
func (m *TokenManager) SetAllowedIssuers(issuers []string) {
	if len(issuers) == 0 {
		m.allowedIssuers.Store(nil)
		return
	}
	cp := append([]string(nil), issuers...)
	m.allowedIssuers.Store(&cp)
}

// issuerAllowed reports whether iss passes the configured issuer pin. With no
// pin configured (the default) every issuer is allowed.
func (m *TokenManager) issuerAllowed(iss string) bool {
	allowed := m.allowedIssuers.Load()
	if allowed == nil {
		return true
	}
	for _, a := range *allowed {
		if a == iss {
			return true
		}
	}
	return false
}

func (m *TokenManager) currentSecret() []byte {
	if p := m.current.Load(); p != nil {
		return *p
	}
	return nil
}

// Generate creates a signed JWT for the given user, scopes, and lifetime.
// A zero expiresIn uses DefaultExpiry. Each token receives a unique JTI.
func (m *TokenManager) Generate(userID, email string, scopes []string, expiresIn time.Duration) (string, error) {
	if expiresIn == 0 {
		expiresIn = DefaultExpiry
	}
	jti := uuid.NewString()
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Scopes: scopes,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    m.issuer,
			Subject:   userID,
			// Note: RegisteredClaims.ID also serializes to "jti"; the custom JTI
			// field (same tag, shallower) is the canonical one, so ID is left unset.
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.currentSecret())
}

// Validate parses and verifies a JWT (rejecting non-HMAC signing methods) and
// returns its claims. It tries the current signing secret first, then the
// previous secret (if a rotation overlap is in effect).
func (m *TokenManager) Validate(tokenString string) (*Claims, error) {
	claims, err := m.validateWith(tokenString, m.currentSecret())
	if err == nil {
		return claims, nil
	}
	if prev := m.previous.Load(); prev != nil {
		if c, e := m.validateWith(tokenString, *prev); e == nil {
			return c, nil
		}
	}
	return nil, err
}

func (m *TokenManager) validateWith(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	// Enforced here (the single choke point) so the pin applies to both the
	// current- and previous-secret validation attempts.
	if !m.issuerAllowed(claims.Issuer) {
		return nil, errors.New("token issuer not allowed")
	}
	return claims, nil
}
