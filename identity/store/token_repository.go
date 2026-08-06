package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
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

// Self-bounding parameters for the revocation denylist. See RevokeToken.
const (
	// revocationRetentionGrace is how long a revocation row is kept AFTER the
	// token it denies has already expired.
	//
	// It is not zero because "the token is expired" is a statement about a
	// clock, and the clock that prunes is not the clock that verifies. A
	// verifier whose time is behind the database's — or one configured with
	// leeway on `exp` — would still accept a token whose denylist row a
	// prune-at-exactly-expiry had already deleted, turning a bounded table into
	// a (narrow) fail-open. An hour is far wider than any plausible skew or
	// leeway and costs one extra hour of already-dead rows.
	//
	// terraform-registry applies the same reasoning to its own per-user
	// revocation watermarks, retaining them 25h against a 24h token TTL.
	revocationRetentionGrace = time.Hour

	// revocationPruneInterval is the minimum gap between two self-prunes issued
	// by one TokenRepository. Revocation is a write a host may issue in bursts
	// (a password change revoking a user's sessions, a scripted logout loop);
	// without a throttle every one of them would pay for a DELETE.
	revocationPruneInterval = time.Hour

	// revocationPruneBatch bounds how many rows one self-prune deletes, so the
	// first revocation issued against a large, never-pruned backlog costs a
	// bounded amount of work instead of an unbounded one. Successive prunes
	// drain the remainder.
	revocationPruneBatch = 10000

	// revocationPruneTimeout bounds the self-prune's own round trip. The prune
	// is best-effort maintenance riding on a caller's revocation; it must never
	// be the reason a logout hangs.
	revocationPruneTimeout = 10 * time.Second
)

// TokenRepository handles JWT revocation database operations.
//
// The revocation denylist is SELF-BOUNDING: RevokeToken is the only statement
// in this module that grows revoked_tokens, and it is also what prunes it (see
// RevokeToken). Hold a TokenRepository by pointer — it carries the prune
// throttle.
type TokenRepository struct {
	db *sql.DB

	// nextPruneAtUnixNano is the earliest wall-clock time, as Unix
	// nanoseconds, at which RevokeToken may prune again. It is atomic because
	// concurrent revocations on different goroutines share one repository, and
	// compare-and-swap is what makes exactly one of them win the slot rather
	// than all of them issuing a DELETE at once. Zero (the value a freshly
	// constructed repository has) means "prune on the next revocation", so a
	// process starting against an existing backlog begins draining it
	// immediately rather than an interval later.
	nextPruneAtUnixNano atomic.Int64

	// pruneInterval / pruneGrace / pruneBatch shadow the constants above so a
	// test can exercise the throttle and the retention horizon without waiting
	// an hour. Zero means "use the constant"; production never sets them.
	pruneInterval time.Duration
	pruneGrace    time.Duration
	pruneBatch    int
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
//
// # Why this also prunes
//
// revoked_tokens is append-only and this INSERT is the ONLY statement in the
// module that grows it, so this is the one place a bound can be enforced that
// cannot be forgotten. A prune scheduled anywhere else — a cleanup helper with
// its own Start/Stop loop, or a documented "the host MUST call this"
// obligation — is opt-in, and opt-in maintenance is exactly what leaves the
// table growing for the life of a deployment that wired revocation but not the
// janitor. identity/auth/oauthstate.MemoryStore made the same call for the same
// reason and self-bounds inside its Store path; this is that design applied to
// the denylist's durable twin.
//
// The prune is throttled (revocationPruneInterval), bounded
// (revocationPruneBatch), given its own deadline (revocationPruneTimeout), and
// keeps rows for revocationRetentionGrace past the denied token's own expiry.
// It CANNOT fail the revocation: a failed prune is logged and the revocation
// still succeeds, because refusing to revoke a credential because housekeeping
// failed trades a bounded table for a live token.
//
// CleanupExpiredRevocations remains available for a host that wants an
// additional scheduled sweep; it is no longer the only thing standing between
// the denylist and unbounded growth.
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

	r.maybePruneExpiredRevocations(ctx)

	return nil
}

// claimPruneSlot reports whether this call won the right to prune now, and
// reserves the next slot if it did.
//
// The reservation happens on the ATTEMPT, not on success: a prune that fails (a
// dead connection, a lock timeout) must not let the very next revocation retry
// immediately, or a persistent failure becomes a DELETE — and a log line — on
// every revocation.
func (r *TokenRepository) claimPruneSlot(now time.Time) bool {
	next := r.nextPruneAtUnixNano.Load()
	if now.UnixNano() < next {
		return false
	}
	interval := r.pruneInterval
	if interval <= 0 {
		interval = revocationPruneInterval
	}
	// CompareAndSwap, not Store: concurrent revocations must not all observe
	// the same elapsed deadline and all decide to prune.
	return r.nextPruneAtUnixNano.CompareAndSwap(next, now.Add(interval).UnixNano())
}

// maybePruneExpiredRevocations deletes a bounded batch of revocation rows whose
// tokens expired more than the retention grace ago, at most once per prune
// interval. It never returns an error: see RevokeToken for why a housekeeping
// failure must not fail a revocation.
func (r *TokenRepository) maybePruneExpiredRevocations(ctx context.Context) {
	now := time.Now()
	if !r.claimPruneSlot(now) {
		return
	}

	grace := r.pruneGrace
	if grace <= 0 {
		grace = revocationRetentionGrace
	}
	batch := r.pruneBatch
	if batch <= 0 {
		batch = revocationPruneBatch
	}

	// The horizon: a row survives until the token it denies has been expired
	// for longer than the grace. Rows at or newer than the cutoff are kept.
	cutoff := now.Add(-grace)

	// context.WithoutCancel: the prune is bounded work whose slot has already
	// been burned, and the caller's context is typically a request context that
	// ends the moment the handler returns. Inheriting its cancellation would
	// abort the prune partway on exactly the deployments that revoke most
	// often. The deadline below is what bounds it instead.
	pruneCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationPruneTimeout)
	defer cancel()

	// Delete by primary key from a bounded, ordered subselect: the LIMIT keeps
	// one prune's cost bounded, and the ORDER BY makes concurrent prunes on two
	// replicas walk the backlog in the same direction rather than deadlock
	// against each other. expires_at is indexed
	// (idx_identity_revoked_tokens_expires_at, migration 000001).
	const pruneQuery = `
		DELETE FROM revoked_tokens
		WHERE jti IN (
			SELECT jti FROM revoked_tokens
			WHERE expires_at < $1
			ORDER BY expires_at
			LIMIT $2
		)
	`
	if _, err := r.db.ExecContext(pruneCtx, pruneQuery, cutoff, batch); err != nil {
		// Loud, but bounded to once per prune interval per process by the
		// throttle above. Silence here would let the denylist grow again with
		// nothing in the record to show for it.
		slog.Error("failed to prune expired token revocations; the revocation itself succeeded",
			"error", err)
	}
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

// CleanupExpiredRevocations removes entries whose tokens have already expired.
//
// This is the unbounded, immediate sweep. It is retained for hosts that already
// schedule it and for one-off maintenance; it is NOT the mechanism that bounds
// the table — RevokeToken's self-prune is, precisely so that a host which never
// calls this still cannot grow the denylist forever.
//
// Unlike the self-prune it applies no retention grace, so a host calling it
// directly also drops rows for tokens that expired a moment ago.
func (r *TokenRepository) CleanupExpiredRevocations(ctx context.Context) error {
	query := `DELETE FROM revoked_tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired token revocations: %w", err)
	}
	return nil
}
