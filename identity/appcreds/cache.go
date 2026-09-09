// cache.go is an OPTIONAL in-memory token cache, keyed by credential
// fingerprint. It is not wired into Minter: a caller that persists tokens (say,
// sealed and bound to a database row) wants nothing to do with a process-local
// map, and a Minter that cached silently would serve such a caller a token its
// own store had already revoked.
package appcreds

import (
	"context"
	"sync"
	"time"
)

// DefaultRefreshMargin re-mints this long before expiry so an in-flight request
// never races a hard expiry.
const DefaultRefreshMargin = 60 * time.Second

// Cache holds minted tokens keyed by credential fingerprint.
//
// Keying by fingerprint rather than by record id makes rotation
// self-invalidating: change any credential field and the new credentials hash to
// a key nothing was stored under, so the old token can never be served. Evict
// exists anyway -- see its comment.
//
// Safe for concurrent use. The zero value is ready to use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]Token
	now     func() time.Time
	margin  time.Duration
}

// NewCache builds a cache. A zero margin means DefaultRefreshMargin; pass a
// negative one to serve tokens right up to expiry.
func NewCache(margin time.Duration) *Cache {
	return &Cache{entries: map[string]Token{}, margin: margin}
}

func (c *Cache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Cache) refreshMargin() time.Duration {
	if c.margin == 0 {
		return DefaultRefreshMargin
	}
	if c.margin < 0 {
		return 0
	}
	return c.margin
}

// Get returns a cached token for creds if one is present and not within the
// refresh margin of expiry.
func (c *Cache) Get(creds Creds) (Token, bool) {
	if creds == nil {
		return Token{}, false
	}
	key := creds.Fingerprint()

	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.entries[key]
	if !ok {
		return Token{}, false
	}
	if tok.Expired(c.clock(), c.refreshMargin()) {
		// Dropped rather than left to rot: a credential that stops being used
		// would otherwise pin its last token in the map forever.
		delete(c.entries, key)
		return Token{}, false
	}
	return tok, true
}

// Put stores a token under creds' fingerprint. An empty token is not stored --
// caching one would turn a single failed mint into a run of them.
func (c *Cache) Put(creds Creds, tok Token) {
	if creds == nil || tok.AccessToken == "" {
		return
	}
	key := creds.Fingerprint()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]Token{}
	}
	c.entries[key] = tok
}

// Evict removes exactly one entry, by the fingerprint of the credentials a
// record USED TO carry.
//
// Rotating a credential to a genuinely different value already invalidates the
// old token implicitly -- the fingerprint changes with it, so the old entry is
// never looked up again. But a route whose whole job is "replace this record's
// credential" should not depend on that staying true: an explicit evict makes it
// an invariant of the route rather than a property that falls out of how the
// cache happens to be keyed today. Compute the fingerprint from the OLD values
// BEFORE overwriting them.
func (c *Cache) Evict(creds Creds) {
	if creds == nil {
		return
	}
	c.EvictKey(creds.Fingerprint())
}

// EvictKey removes one entry by a fingerprint captured earlier, for a caller
// that no longer holds the old credentials themselves.
func (c *Cache) EvictKey(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Reset empties the cache. Intended for test isolation, not for production use:
// in production, evict the one credential that changed.
func (c *Cache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]Token{}
}

// Len reports how many entries are held, including any that have expired but
// not yet been read. For tests and metrics.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// CachedMinter is the small amount of glue between a Minter and a Cache, for
// callers that want state-manager's "mint and cache in one call" shape.
//
// Callers that persist tokens should NOT use this; they should call the Minter
// directly and store the result themselves.
type CachedMinter struct {
	Minter *Minter
	Cache  *Cache
}

// Entra returns a cached token for creds, minting one if the cache has none.
func (cm CachedMinter) Entra(ctx context.Context, creds EntraCreds) (Token, error) {
	return cm.mint(ctx, creds, func() (Token, error) { return cm.Minter.MintEntra(ctx, creds) })
}

// Federated returns a cached token for creds, minting one if the cache has none.
func (cm CachedMinter) Federated(ctx context.Context, creds FederatedCreds) (Token, error) {
	return cm.mint(ctx, creds, func() (Token, error) { return cm.Minter.MintFederated(ctx, creds) })
}

// GitHubApp returns a cached token for creds, minting one if the cache has none.
func (cm CachedMinter) GitHubApp(ctx context.Context, creds GitHubAppCreds) (Token, error) {
	return cm.mint(ctx, creds, func() (Token, error) { return cm.Minter.MintGitHubApp(ctx, creds) })
}

// mint is the shared read-through path.
//
// Two callers racing on the same cold key both mint. That is deliberate: holding
// the cache lock across a network round trip would serialise every unrelated
// credential behind the slowest token endpoint, and the cost of the race is one
// redundant exchange, not a wrong answer.
func (cm CachedMinter) mint(_ context.Context, creds Creds, do func() (Token, error)) (Token, error) {
	if cm.Minter == nil {
		return Token{}, errNoMinter
	}
	// Redundant with the Mint method's own validation, which every arm performs
	// before touching the network -- so removing this survives mutation. It
	// earns its place by keeping invalid credentials away from Fingerprint and
	// the cache entirely: without it, a caller's malformed input still costs a
	// SHA-256 and a lock acquisition per call, on a path an attacker can drive.
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}
	if cm.Cache != nil {
		if tok, ok := cm.Cache.Get(creds); ok {
			return tok, nil
		}
	}
	tok, err := do()
	if err != nil {
		return Token{}, err
	}
	if cm.Cache != nil {
		cm.Cache.Put(creds, tok)
	}
	return tok, nil
}
