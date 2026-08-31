-- Backs Notifier.Notify's optional Event.DedupKey (issue #157): an atomic,
-- TTL-bounded reservation so a logical occurrence delivered by one caller --
-- a sibling replica of a horizontally-scaled host, or a periodic trigger
-- that independently rediscovers the same fact on more than one tick -- is
-- not redelivered to every configured channel a second (or Nth) time.
--
-- A single UPSERT claims the row: the first caller within the caller's own
-- TTL wins the INSERT (or a stale, expired claim's UPDATE); a caller racing
-- a live claim has its UPDATE excluded by the WHERE clause, so the
-- statement returns no row and the caller knows it lost -- see
-- identity/store/notify_dedup_repository.go's ClaimDedup for the read side.
--
-- No expiry sweep: a caller is expected to pick a bounded-cardinality key
-- (one per logical occurrence, e.g. a tool+version or an alert condition),
-- not a per-request identifier, so this table's size tracks the number of
-- distinct occurrences ever claimed, not traffic volume. A caller that picks
-- an unbounded key defeats its own dedup and grows this table -- that is a
-- caller-side misuse this migration does not defend against.
CREATE TABLE IF NOT EXISTS identity.notify_dedup_claims (
    dedup_key   TEXT PRIMARY KEY,
    claimed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
