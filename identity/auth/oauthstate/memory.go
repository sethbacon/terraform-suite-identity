package oauthstate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/safeloop"
)

// Defaults applied by NewMemoryStore when a zero (or negative) argument is
// passed.
const (
	// DefaultCleanupInterval is how often the background janitor sweeps
	// expired entries. Expiry is enforced on read regardless of the janitor
	// (see Take) — the sweep only reclaims entries belonging to abandoned
	// logins, which are never read again.
	DefaultCleanupInterval = time.Minute

	// DefaultMaxEntries bounds the map. The endpoint that issues a state is
	// typically unauthenticated, so without a cap, abandoned or scripted
	// logins grow it without bound.
	//
	// The cap is applied PER NAMESPACE (login states and replay markers are
	// budgeted separately — see MemoryStore), so the worst-case entry count is
	// twice this value.
	DefaultMaxEntries = 4096
)

// MemoryStore is the reference Store: an in-process map with TTL expiry, safe
// for concurrent use.
//
// It holds state in one process's memory, so it is suitable for single-replica
// and development deployments only. Across multiple replicas a callback can
// land on a replica that never saw the login, and the state will not verify —
// an HA deployment implements Store over a shared backend instead.
//
// # Capacity is budgeted per namespace, and replay markers are never evicted
//
// The store holds two kinds of entry with opposite failure directions. A login
// state (Manager.Issue) is a credential: losing one fails CLOSED, costing a
// user one retry. A replay marker (Manager.Reserve) is the ABSENCE of which
// grants — dropping one lets the assertion it guards be presented a second
// time, so losing one fails OPEN.
//
// Evicting purely by nearest expiry cannot tell those apart. At equal TTLs — the
// natural configuration, with both sides passing DefaultTTL — an existing marker
// is by definition nearer to expiring than a state minted a moment ago, so the
// marker is exactly what a flood of unauthenticated Issue calls would shed
// first. This store therefore does not rank the two against each other at all:
//
//   - Each namespace gets its own budget of maxEntries, so neither can starve
//     the other.
//   - Only login states are ever evicted, and only to admit another login
//     state, nearest-expiry within that namespace.
//   - A replay marker is never evicted. When the marker budget is full,
//     PutIfAbsent returns ErrCapacityExhausted and Manager.Reserve surfaces it
//     as reserved=false plus an error — deny on both channels — rather than
//     making room by forgetting that an assertion was already used.
//
// Keys are classified by the namespace prefix Manager writes; anything that is
// not a replay marker is treated as an evictable login state.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry

	maxEntries int
	stopCh     chan struct{}
	stopOnce   sync.Once
}

type memoryEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryStore returns a store and starts a background janitor that sweeps
// expired entries every cleanupInterval. Pass 0 for cleanupInterval or
// maxEntries to take DefaultCleanupInterval / DefaultMaxEntries. Call Close to
// stop the janitor.
//
// maxEntries is the budget for EACH namespace (login states, replay markers),
// not the total — see MemoryStore for why the two are not ranked against each
// other.
func NewMemoryStore(cleanupInterval time.Duration, maxEntries int) *MemoryStore {
	if cleanupInterval <= 0 {
		cleanupInterval = DefaultCleanupInterval
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	s := &MemoryStore{
		entries:    make(map[string]memoryEntry),
		maxEntries: maxEntries,
		stopCh:     make(chan struct{}),
	}
	go s.janitor(cleanupInterval, s.sweep)
	return s
}

// PutIfAbsent stores entry under key for ttl, refusing to overwrite a live
// entry. The refusal is what makes Manager.Reserve an atomic single-use check.
//
// It returns ErrCapacityExhausted when the key's namespace is full and no room
// can be made without dropping security state — see MemoryStore.
func (s *MemoryStore) PutIfAbsent(_ context.Context, key string, entry []byte, ttl time.Duration) error {
	if key == "" {
		return errors.New("oauthstate: memory store: key is required")
	}
	if ttl <= 0 {
		return errors.New("oauthstate: memory store: entry ttl must be positive")
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.entries[key]; ok && now.Before(existing.expiresAt) {
		return ErrAlreadyExists
	}

	if err := s.makeRoomLocked(key, now); err != nil {
		return err
	}

	// Copy: the caller owns its slice and may reuse or mutate it after this
	// call returns.
	stored := make([]byte, len(entry))
	copy(stored, entry)
	s.entries[key] = memoryEntry{data: stored, expiresAt: now.Add(ttl)}
	return nil
}

// Take atomically retrieves and removes the entry for key, returning
// ErrNotFound when there is no live entry.
func (s *MemoryStore) Take(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, ErrNotFound
	}

	// Delete on every hit, not only on the branch that returns data. Holding
	// the lock across the read and the delete is what makes this single-use:
	// with a separate load and delete, two concurrent callbacks presenting the
	// same state could both see a live entry before either removed it.
	delete(s.entries, key)

	if time.Now().After(e.expiresAt) {
		return nil, ErrNotFound
	}
	return e.data, nil
}

// Close stops the janitor and drops every entry. It is safe to call more than
// once; the store remains usable afterwards, minus the background sweep.
func (s *MemoryStore) Close() error {
	s.stopOnce.Do(func() { close(s.stopCh) })

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]memoryEntry)
	return nil
}

// janitor runs in a goroutine THIS package starts (see NewMemoryStore), inside
// the host application's process. An unrecovered panic in the sweep would
// therefore terminate the host, so each sweep runs behind the module's panic
// boundary and the loop survives to try again on the next tick.
// sweep is taken as a parameter (rather than called as s.sweep directly) so a
// test can drive the loop with a body that faults on purpose and assert the
// loop survives it.
func (s *MemoryStore) janitor(interval time.Duration, sweep func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			safeloop.Guard("oauthstate-janitor", sweep)
		case <-s.stopCh:
			return
		}
	}
}

// sweep drops expired entries under the lock. The unlock is deferred, not
// trailing: recovering a panic that unwound past a plain Unlock call would
// leave s.mu held forever, converting a crash into a permanent deadlock of
// every PutIfAbsent, Take and Close — a worse failure than the one being
// recovered.
func (s *MemoryStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(time.Now())
}

// isReplayMarker reports whether key names a Manager.Reserve replay marker
// rather than a login state. Markers are the entries whose ABSENCE grants, so
// this is the predicate that decides what may never be evicted.
func isReplayMarker(key string) bool {
	return strings.HasPrefix(key, reservePrefix)
}

// purgeExpiredLocked drops every entry whose expiry has passed and reports how
// many live entries remain in each namespace. The counts are a by-product of
// the sweep the caller already pays for, so the capacity decision in
// makeRoomLocked needs no second pass over the map. Callers must hold s.mu.
func (s *MemoryStore) purgeExpiredLocked(now time.Time) (states, markers int) {
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
			continue
		}
		if isReplayMarker(k) {
			markers++
		} else {
			states++
		}
	}
	return states, markers
}

// makeRoomLocked reclaims expired entries and then ensures key's own namespace
// can accept one more entry, or fails closed. Login states may be evicted to
// admit another login state; replay markers are never evicted, by anything.
// Callers must hold s.mu.
func (s *MemoryStore) makeRoomLocked(key string, now time.Time) error {
	states, markers := s.purgeExpiredLocked(now)

	if isReplayMarker(key) {
		// Refusing the write is the fail-closed answer: Manager.Reserve reports
		// reserved=false alongside the error, so a caller reading either channel
		// rejects the assertion. Silently making room by dropping an existing
		// marker would instead let an already-used assertion through.
		if markers >= s.maxEntries {
			return ErrCapacityExhausted
		}
		return nil
	}

	for states >= s.maxEntries {
		if !s.evictNearestExpiryStateLocked() {
			// Unreachable while states >= maxEntries >= 1, but exceeding the cap
			// is not an acceptable alternative to failing the write.
			return ErrCapacityExhausted
		}
		states--
	}
	return nil
}

// evictNearestExpiryStateLocked drops the live LOGIN STATE closest to expiring
// and reports whether it found one, so a flood of new logins degrades other
// in-flight logins rather than exhausting memory. Losing a login state costs a
// user one retry; replay markers are skipped outright because losing one of
// those would let the assertion it guards be presented a second time. Callers
// must hold s.mu.
func (s *MemoryStore) evictNearestExpiryStateLocked() bool {
	var victim string
	var soonest time.Time
	for k, e := range s.entries {
		if isReplayMarker(k) {
			continue
		}
		if victim == "" || e.expiresAt.Before(soonest) {
			victim, soonest = k, e.expiresAt
		}
	}
	if victim == "" {
		return false
	}
	delete(s.entries, victim)
	return true
}
