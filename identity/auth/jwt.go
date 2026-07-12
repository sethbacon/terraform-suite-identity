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
//
// OrgID is empty on a token minted by Generate (a GLOBAL, org-less token — see
// the warning on Generate) and set to a single organization ID on a token
// minted by GenerateForOrg. Never authorize an org-scoped action from Scopes
// alone: check OrgID and Scopes together via HasScopeInOrg / HasAnyScopeInOrg /
// HasAllScopesInOrg rather than reading Scopes directly.
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	OrgID  string   `json:"org_id,omitempty"`
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
// TokenManager provides no revocation of its own: Validate never consults a
// denylist. Callers that need to stop a compromised or must-be-invalidated
// token before its natural expiry must check the JTI claim against their own
// store (e.g. store.TokenRepository) on every request — Claims.JTI exists
// specifically to support that pattern.
//
// The signing secret can be rotated at runtime via RotateSecret: the previous
// secret remains accepted for validation until ClearPreviousSecret is called,
// giving in-flight tokens an overlap window. A token signed with the previous
// secret validates for the ENTIRE overlap window regardless of its own
// expiry — size the window deliberately and call ClearPreviousSecret promptly
// once rotation is complete. Generate always signs with the current secret.
type TokenManager struct {
	issuer   string
	current  atomic.Pointer[[]byte]
	previous atomic.Pointer[[]byte]
	// allowedIssuers, when non-nil, restricts Validate to tokens whose `iss`
	// claim is in the set. nil (the default) disables the check — accepting any
	// issuer, preserving single-app behaviour.
	allowedIssuers atomic.Pointer[[]string]
	// audience, when non-nil, is stamped as the `aud` claim on Generate and
	// required on Validate. nil (the default) omits and does not check the
	// audience, preserving single-app behaviour.
	audience atomic.Pointer[string]
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
// given issuers.
//
// A nil set (the default) disables the check entirely, accepting any issuer — so
// this is fully backward-compatible for single-app use. A non-nil but EMPTY set
// fails closed (rejects every token): passing an accidentally-empty configured
// slice therefore denies access rather than silently disabling the pin, which
// would otherwise re-open shared-secret cross-app replay in a coupled suite.
//
// In a coupled suite sharing one signing secret, set this to {own issuer} plus
// the trusted sibling issuers so a shared secret cannot be replayed from an
// untrusted minter while still accepting legitimate sibling tokens. Safe for
// concurrent use and intended to be updated at runtime as siblings are
// discovered.
func (m *TokenManager) SetAllowedIssuers(issuers []string) {
	if issuers == nil {
		m.allowedIssuers.Store(nil)
		return
	}
	cp := append([]string(nil), issuers...)
	m.allowedIssuers.Store(&cp)
}

// SetAudience sets the audience stamped as the `aud` claim on Generate and
// required on Validate. An empty string (the default) omits the claim and skips
// the audience check, preserving single-app behaviour. In a coupled suite each
// app should set this to its own identity so a token minted for one app cannot
// be replayed against a sibling. Safe for concurrent use.
func (m *TokenManager) SetAudience(aud string) {
	if aud == "" {
		m.audience.Store(nil)
		return
	}
	cp := aud
	m.audience.Store(&cp)
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
//
// This mints a GLOBAL (org-less) token: Claims.OrgID is left empty and
// Claims.Scopes is stamped in verbatim — typically the flat set unioned across
// every organization the user belongs to (e.g.
// store.OrganizationRepository.GetUserCombinedScopes or
// models.UserWithOrgRoles.GetAllowedScopes). Such a token authorizes the union
// of scopes across ALL of the user's organizations; nothing in the token lets a
// resource server tell which organization a given scope came from, so a role in
// one organization silently authorizes an action in another unless the host
// independently re-checks per-org membership on every request.
//
// In a multi-tenant deployment, prefer GenerateForOrg: it binds the token to a
// single organization and that organization's own scopes, so the binding is
// enforceable from the token alone via HasScopeInOrg (or HasAnyScopeInOrg /
// HasAllScopesInOrg) instead of trusting a flat scope list.
func (m *TokenManager) Generate(userID, email string, scopes []string, expiresIn time.Duration) (string, error) {
	return m.generate(userID, email, "", scopes, expiresIn)
}

// GenerateForOrg creates a signed JWT scoped to a single organization: it is
// identical to Generate except Claims.OrgID is set to orgID. Pass the scopes
// that orgID SPECIFICALLY grants the user — e.g.
// store.OrganizationRepository.GetUserScopesForOrg or
// models.UserWithOrgRoles.GetScopesForOrg — not the flat, cross-organization
// union Generate expects. Pair this with HasScopeInOrg (or HasAnyScopeInOrg /
// HasAllScopesInOrg) on the verification side, checking the same orgID as the
// resource being accessed, so a token minted for one organization cannot
// authorize an action in another. See the warning on Generate for the
// cross-org escalation this closes.
func (m *TokenManager) GenerateForOrg(userID, email, orgID string, scopes []string, expiresIn time.Duration) (string, error) {
	return m.generate(userID, email, orgID, scopes, expiresIn)
}

func (m *TokenManager) generate(userID, email, orgID string, scopes []string, expiresIn time.Duration) (string, error) {
	if expiresIn == 0 {
		expiresIn = DefaultExpiry
	}
	jti := uuid.NewString()
	claims := &Claims{
		UserID: userID,
		Email:  email,
		OrgID:  orgID,
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
	if aud := m.audience.Load(); aud != nil {
		claims.Audience = jwt.ClaimStrings{*aud}
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.currentSecret())
}

// Validate parses and verifies a JWT (rejecting any signing method other than
// HS256) and returns its claims. It tries the current signing secret first, then
// the previous secret (if a rotation overlap is in effect).
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
	parserOpts := []jwt.ParserOption{}
	if aud := m.audience.Load(); aud != nil {
		parserOpts = append(parserOpts, jwt.WithAudience(*aud))
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		// Strictly require HS256 — the only method Generate ever uses. Accepting
		// other HMAC variants (HS384/HS512), let alone non-HMAC methods, widens the
		// signature-algorithm surface for no benefit.
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, parserOpts...)
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
