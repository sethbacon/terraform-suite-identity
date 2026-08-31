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

// Self-bounding parameters for notify_dedup_claims. See ClaimDedup.
const (
	// dedupPruneGrace is how long a claim is kept past its own claimed_at
	// before a prune will remove it.
	//
	// It is not tied to any one caller's DedupTTL -- the repository has no
	// way to know every TTL a host will ever pass -- so it is instead a
	// fixed horizon comfortably larger than any TTL a caller should
	// reasonably use (identity/notify's Event.DedupTTL doc recommends
	// "roughly your trigger's own re-fire interval": hours, for even a
	// once-daily poller, not weeks). A prune horizon shorter than a live
	// caller's TTL would let a claim be deleted and immediately re-won
	// within what should still be its reservation window, silently
	// defeating the dedup guarantee -- this margin is what keeps that from
	// happening in practice.
	dedupPruneGrace = 7 * 24 * time.Hour

	// dedupPruneInterval is the minimum gap between two self-prunes issued
	// by one NotifyDedupRepository. ClaimDedup can be called in bursts (a
	// job whose single tick claims several distinct keys); without a
	// throttle every one of them would pay for a DELETE.
	dedupPruneInterval = time.Hour

	// dedupPruneBatch bounds how many rows one self-prune deletes, so the
	// first claim issued against a large, never-pruned backlog costs a
	// bounded amount of work instead of an unbounded one. Successive prunes
	// drain the remainder.
	dedupPruneBatch = 10000

	// dedupPruneTimeout bounds the self-prune's own round trip. The prune is
	// best-effort maintenance riding on a caller's claim; it must never be
	// the reason Notify hangs.
	dedupPruneTimeout = 10 * time.Second
)

// NotifyDedupRepository backs identity/notify's optional Event.DedupKey
// (issue #157): an atomic, TTL-bounded claim so a logical occurrence
// delivered by one caller -- a sibling replica of a horizontally-scaled
// host, or a periodic trigger that independently rediscovers the same fact
// on more than one tick -- is not redelivered to every configured
// notification channel a second (or Nth) time.
//
// It lives here, not in identity/notify, for the same reason
// ClaimExpiryNotification lives on APIKeyRepository rather than in
// identity/notify/api_key_expiry.go: every migration-owned identity-schema
// table is addressed from identity/store, so VerifySchemaRouting's inventory
// (RepositoryTables) stays complete by construction rather than by every
// package remembering to update it. identity/notify already imports this
// package for exactly that reason (see apiKeyRepo in api_key_expiry.go).
//
// notify_dedup_claims is SELF-BOUNDING, the same shape as revoked_tokens
// (see TokenRepository): ClaimDedup is the only statement in this module
// that grows the table, and it is also what prunes it. Hold a
// NotifyDedupRepository by pointer and reuse it -- identity/notify's
// Notifier constructs exactly one, at NewNotifier time, for this reason --
// because it carries the prune throttle; a fresh repository per call would
// reset that throttle to "prune now" every time.
type NotifyDedupRepository struct {
	db *sql.DB

	// nextPruneAtUnixNano mirrors TokenRepository's throttle: the earliest
	// wall-clock time, as Unix nanoseconds, at which ClaimDedup may prune
	// again. Atomic because concurrent claims on different goroutines share
	// one repository, and compare-and-swap is what makes exactly one of
	// them win the slot. Zero (a freshly constructed repository) means
	// "prune on the next claim", so a process starting against an existing
	// backlog begins draining it immediately.
	nextPruneAtUnixNano atomic.Int64

	// pruneInterval / pruneGrace / pruneBatch shadow the constants above so
	// a test can exercise the throttle and the retention horizon without
	// waiting a week. Zero means "use the constant"; production never sets
	// them.
	pruneInterval time.Duration
	pruneGrace    time.Duration
	pruneBatch    int
}

// NewNotifyDedupRepository constructs the repository over the app connection.
func NewNotifyDedupRepository(db *sql.DB) *NotifyDedupRepository {
	return &NotifyDedupRepository{db: db}
}

// ClaimDedup atomically reserves key for ttl and reports whether THIS call
// won the claim.
//
// One UPSERT, not a check-then-act pair: a SELECT followed by an INSERT
// would just move the race this exists to close down one level, from
// "two callers both deliver" to "two callers both pass the SELECT" -- the
// same defect terraform-registry-backend's ScannerUpdateJob had, and the
// same idiom CVERepository.UpsertAdvisory already uses correctly to avoid
// it. The first caller within ttl wins the INSERT (or a stale, expired
// claim's UPDATE); a caller racing a live claim has its UPDATE's WHERE
// clause exclude the row, so the statement returns no row and Scan reports
// sql.ErrNoRows -- one round trip, no separate lock or transaction.
//
// A claim is a reservation, not a permanent tombstone: once ttl elapses the
// same key can be claimed again, because "the same logical occurrence" can
// legitimately recur (a scanner version rediscovered after a data reset, a
// health check that fails again after recovering).
func (r *NotifyDedupRepository) ClaimDedup(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	var claimed string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO notify_dedup_claims (dedup_key, claimed_at)
		VALUES ($1, NOW())
		ON CONFLICT (dedup_key) DO UPDATE
			SET claimed_at = NOW()
			WHERE notify_dedup_claims.claimed_at < NOW() - make_interval(secs => $2)
		RETURNING dedup_key
	`, key, ttl.Seconds()).Scan(&claimed)

	r.maybePruneExpiredClaims(ctx)

	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, fmt.Errorf("failed to claim notify dedup key %q: %w", key, err)
}

// claimPruneSlot reports whether this call won the right to prune now, and
// reserves the next slot if it did. The reservation happens on the
// ATTEMPT, not on success, matching TokenRepository.claimPruneSlot: a prune
// that fails must not let the very next claim retry immediately.
func (r *NotifyDedupRepository) claimPruneSlot(now time.Time) bool {
	next := r.nextPruneAtUnixNano.Load()
	if now.UnixNano() < next {
		return false
	}
	interval := r.pruneInterval
	if interval <= 0 {
		interval = dedupPruneInterval
	}
	return r.nextPruneAtUnixNano.CompareAndSwap(next, now.Add(interval).UnixNano())
}

// maybePruneExpiredClaims deletes a bounded batch of claim rows older than
// dedupPruneGrace, at most once per prune interval. It never returns an
// error: a housekeeping failure must not fail ClaimDedup, which callers
// depend on for correctness (a caller that lost the dedup race must still
// see that outcome even if the janitor is unavailable).
func (r *NotifyDedupRepository) maybePruneExpiredClaims(ctx context.Context) {
	now := time.Now()
	if !r.claimPruneSlot(now) {
		return
	}

	grace := r.pruneGrace
	if grace <= 0 {
		grace = dedupPruneGrace
	}
	batch := r.pruneBatch
	if batch <= 0 {
		batch = dedupPruneBatch
	}
	cutoff := now.Add(-grace)

	// context.WithoutCancel: the prune is bounded work whose slot has
	// already been burned, and the caller's context is typically a request
	// or job-tick context that ends the moment the caller returns.
	// Inheriting its cancellation would abort the prune partway on exactly
	// the deployments claiming most often. The deadline below bounds it
	// instead.
	pruneCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dedupPruneTimeout)
	defer cancel()

	// Delete by primary key from a bounded, ordered subselect: the LIMIT
	// keeps one prune's cost bounded, and the ORDER BY makes concurrent
	// prunes on two replicas walk the backlog in the same direction rather
	// than deadlock against each other.
	const pruneQuery = `
		DELETE FROM notify_dedup_claims
		WHERE dedup_key IN (
			SELECT dedup_key FROM notify_dedup_claims
			WHERE claimed_at < $1
			ORDER BY claimed_at
			LIMIT $2
		)
	`
	if _, err := r.db.ExecContext(pruneCtx, pruneQuery, cutoff, batch); err != nil {
		// Loud, but bounded to once per prune interval per process by the
		// throttle above. Silence here would let the table grow again with
		// no operator signal.
		slog.Error("failed to prune expired notify dedup claims; the claim itself succeeded",
			"error", err)
	}
}
