package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrEmptyTokenID is returned by RevokeToken and IsTokenRevoked when the token
// identifier (`jti`) is empty.
//
// An empty identifier is never a legitimate lookup key: it matches no row, so
// answering it normally would report "not revoked" for every such call and a
// denylist wired against the wrong field would appear to work while revoking
// nothing. Both methods therefore refuse it loudly instead. Read the identifier
// with auth.Claims.TokenID, which is the accessor that cannot silently yield "".
var ErrEmptyTokenID = errors.New("store: token identifier (jti) is empty")

// TokenRepository handles JWT revocation database operations
type TokenRepository struct {
	db *sql.DB
}

// NewTokenRepository creates a new TokenRepository
func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// RevokeToken adds a JTI to the revocation list.
//
// An empty jti returns ErrEmptyTokenID without touching the database: the row
// it would otherwise insert can never be matched by a lookup, so accepting it
// would report a successful revocation that revokes nothing.
func (r *TokenRepository) RevokeToken(ctx context.Context, jti, userID string, expiresAt time.Time) error {
	if jti == "" {
		return ErrEmptyTokenID
	}
	query := `
		INSERT INTO revoked_tokens (jti, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, jti, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// IsTokenRevoked reports whether a JTI has been revoked.
//
// It fails closed on BOTH return channels whenever it cannot answer the
// question — an empty jti (ErrEmptyTokenID) or a failed query — returning
// revoked=true alongside the error. The boolean is the value a caller acts on,
// and plenty of real call sites read it while discarding the error (an
// optionally-authenticated route downgrading a revoked caller to anonymous, for
// instance); returning false there would let an unanswerable revocation check
// admit the token. A caller that inspects the error still sees the failure and
// can distinguish "revoked" from "could not tell".
func (r *TokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return true, ErrEmptyTokenID
	}
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, jti).Scan(&exists)
	if err != nil {
		return true, fmt.Errorf("failed to check token revocation: %w", err)
	}
	return exists, nil
}

// CleanupExpiredRevocations removes entries whose tokens have already expired
func (r *TokenRepository) CleanupExpiredRevocations(ctx context.Context) error {
	query := `DELETE FROM revoked_tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired token revocations: %w", err)
	}
	return nil
}
