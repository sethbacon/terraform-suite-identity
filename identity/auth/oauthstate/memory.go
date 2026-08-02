package oauthstate

import (
	"context"
	"errors"
	"sync"
	"time"
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
	DefaultMaxEntries = 4096
)

// MemoryStore is the reference Store: an in-process map with TTL expiry, safe
// for concurrent use.
//
// It holds state in one process's memory, so it is suitable for single-replica
// and development deployments only. Across multiple replicas a callback can
// land on a replica that never saw the login, and the state will not verify —
// an HA deployment implements Store over a shared backend instead.
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
	go s.janitor(cleanupInterval)
	return s
}

// PutIfAbsent stores entry under key for ttl, refusing to overwrite a live
// entry. The refusal is what makes Manager.Reserve an atomic single-use check.
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

	s.purgeExpiredLocked(now)
	if len(s.entries) >= s.maxEntries {
		s.evictNearestExpiryLocked()
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

func (s *MemoryStore) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.purgeExpiredLocked(time.Now())
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// purgeExpiredLocked drops every entry whose expiry has passed. Callers must
// hold s.mu.
func (s *MemoryStore) purgeExpiredLocked(now time.Time) {
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}

// evictNearestExpiryLocked drops the live entry closest to expiring, so a
// flood of new logins degrades other in-flight logins rather than exhausting
// memory. Nearest-expiry (rather than random or oldest-inserted) is chosen so
// that short-lived login states are shed before longer-lived Reserve markers:
// evicting a replay marker early would let the assertion it guards be
// presented a second time. Callers must hold s.mu.
func (s *MemoryStore) evictNearestExpiryLocked() {
	var victim string
	var soonest time.Time
	for k, e := range s.entries {
		if victim == "" || e.expiresAt.Before(soonest) {
			victim, soonest = k, e.expiresAt
		}
	}
	if victim != "" {
		delete(s.entries, victim)
	}
}
