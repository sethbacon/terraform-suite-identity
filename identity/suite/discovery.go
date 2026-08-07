package suite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	"github.com/sethbacon/terraform-suite-identity/identity/internal/safeloop"
)

// SiblingState is the discovery client's view of the configured sibling.
type SiblingState string

const (
	StateUnknown     SiblingState = "unknown"     // not yet polled
	StateActive      SiblingState = "active"      // reachable AND compatible
	StateDegraded    SiblingState = "degraded"    // a poll failed, but within the grace window of a prior success
	StateUnreachable SiblingState = "unreachable" // unreachable beyond grace, or incompatible
)

// ManifestPath is the path each app must serve its capability Manifest at, and
// the path DiscoveryClient appends to a sibling's base URL when polling.
//
// It is exported so a publisher can register its route from this constant
// instead of hand-copying the literal: the discovery client and the publisher
// then genuinely cannot diverge, because there is one definition. Note the
// guarantee only holds for a publisher that actually references it — a route
// registered from a copied literal still has to be kept in sync by hand, and
// the failure mode is a permanently Unreachable sibling.
//
// This value is part of the wire contract between the two suite apps. Changing
// it is a breaking change for every already-deployed sibling, not a refactor.
const ManifestPath = "/api/v1/suite/manifest"

const (
	defaultPollInterval = 60 * time.Second
	defaultGraceWindow  = 5 * time.Minute
	pollTimeout         = 2 * time.Second
	// maxManifestBytes caps how much of a sibling's response is read. A manifest
	// is a few hundred bytes; the cap defends against a hostile or malfunctioning
	// sibling streaming an unbounded body.
	maxManifestBytes = 1 << 20 // 1 MiB
)

// DiscoveryClient polls a sibling app's manifest endpoint and caches the last
// good result. Safe for concurrent use. Construct ONLY when an operator
// configured a sibling URL.
type DiscoveryClient struct {
	siblingURL   string
	self         Manifest
	pollInterval time.Duration
	graceWindow  time.Duration
	httpClient   *http.Client
	guard        *httpsafe.Guard

	mu       sync.RWMutex
	state    SiblingState
	lastGood *Manifest
	lastOKAt time.Time
}

// NewDiscoveryClient builds a client for the given sibling base URL (e.g.
// "https://tfstate.example.com"). A non-positive pollInterval uses the default.
//
// The manifest fetch carries no request auth or signature — only transport
// integrity protects it from tampering. NewDiscoveryClient therefore fails
// closed: it returns a non-nil error (and a nil *DiscoveryClient) when
// siblingURL uses a plaintext "http://" scheme, rather than constructing a
// client for it. Without this, a network-position attacker on that plaintext
// path could inject an arbitrary spoofed Manifest — NegotiateCompat's only
// checks (app id, schema major) are trivially satisfiable by an attacker who
// knows the target app id, so transport security is the only real defense.
//
// For local/dev setups where the sibling is only reachable over plaintext
// HTTP (e.g. loopback), use NewInsecureDiscoveryClient instead — its name is
// the explicit, deliberate opt-out of this check. Never pass an
// operator-configured production siblingURL to it.
//
// guard applies the deployment's egress policy (security.egress.allowlist) to
// the manifest poll AND is the guard SiblingPublicURL validates against. A nil
// guard is the strict default policy, which denies loopback, RFC 1918 and
// link-local — so a sibling on an internal address (the usual case for two apps
// in one cluster, and for every local dev stack) requires a guard built from
// the deployment's allow-list. This parameter is new in v0.25.0; see
// UPGRADING.md for the configuration each deployment must add.
func NewDiscoveryClient(siblingURL string, self Manifest, pollInterval time.Duration, guard *httpsafe.Guard) (*DiscoveryClient, error) {
	normalized := strings.TrimRight(siblingURL, "/")
	if strings.HasPrefix(strings.ToLower(normalized), "http://") {
		return nil, fmt.Errorf("insecure sibling URL: %q uses plaintext HTTP; suite discovery requires HTTPS to protect the manifest fetch from tampering — use NewInsecureDiscoveryClient only if you understand and accept this risk (e.g. local development)", normalized)
	}
	return newDiscoveryClient(normalized, self, pollInterval, guard), nil
}

// NewInsecureDiscoveryClient builds a client exactly like NewDiscoveryClient,
// but explicitly opts out of the HTTPS requirement: a plaintext "http://"
// siblingURL (after the same trailing-slash normalization NewDiscoveryClient
// applies) is accepted — only a warning is logged — rather than rejected.
//
// The function's name IS the opt-out: use it only for local/dev setups where
// the sibling is reached over plaintext HTTP (e.g. loopback). Passing it an
// operator-configured production siblingURL reintroduces the spoofing risk
// documented on NewDiscoveryClient.
//
// Note what this does NOT opt out of: guard still applies in full. The scheme
// rule and the destination rule are separate, and a dev stack that needs a
// loopback or RFC 1918 sibling must say so in its allow-list rather than
// getting it for free with the plaintext opt-out.
func NewInsecureDiscoveryClient(siblingURL string, self Manifest, pollInterval time.Duration, guard *httpsafe.Guard) *DiscoveryClient {
	normalized := strings.TrimRight(siblingURL, "/")
	if strings.HasPrefix(strings.ToLower(normalized), "http://") {
		slog.Warn("suite discovery: sibling URL uses plaintext HTTP; manifest polling is exposed to interception and tampering — use HTTPS",
			"sibling_url", normalized)
	}
	return newDiscoveryClient(normalized, self, pollInterval, guard)
}

// newDiscoveryClient builds the client itself. siblingURL must already be
// normalized (trailing slash trimmed) — shared by NewDiscoveryClient and
// NewInsecureDiscoveryClient after each applies its own scheme check.
func newDiscoveryClient(siblingURL string, self Manifest, pollInterval time.Duration, guard *httpsafe.Guard) *DiscoveryClient {
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	// The manifest poll goes through the shared egress guard like every other
	// outbound request in this module: resolve-and-pin on the dial, so the
	// checked IP is the connected IP.
	httpClient := httpsafe.NewClient(pollTimeout, guard)
	// Do not follow redirects: the manifest lives at a known path on the
	// configured sibling. Following a redirect could be steered to an
	// unintended (e.g. internal) host. This REPLACES the guard's own
	// re-validating CheckRedirect with a strictly stronger rule — refuse every
	// hop rather than re-check it. ErrUseLastResponse returns the 3xx as-is,
	// which then fails the StatusOK check and is treated as unreachable.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &DiscoveryClient{
		siblingURL: siblingURL,
		// self arrives by value, so its string fields are already the
		// client's own — but a shallow copy still shares the caller's
		// Capabilities backing array and Links map. Clone so a caller that
		// keeps its Manifest (the normal pattern: build it once, hand it to
		// the client, keep using it) cannot reach into this client's identity
		// afterwards by writing to that map or slice.
		self:         *self.clone(),
		pollInterval: pollInterval,
		graceWindow:  defaultGraceWindow,
		httpClient:   httpClient,
		guard:        guard,
		state:        StateUnknown,
	}
}

// Snapshot returns the current state and a deep COPY of the last-good sibling
// manifest (nil if the sibling was never successfully reached). Returning a copy
// keeps the client's cached manifest immutable from the caller's side — a
// consumer mutating the result (e.g. its Links map or Capabilities slice) cannot
// corrupt the shared cache or race the poll loop. Cheap; safe to call per request.
func (d *DiscoveryClient) Snapshot() (SiblingState, *Manifest) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.state, d.lastGood.clone()
}

// SiblingPublicURL returns the sibling's self-advertised publicUrl, validated
// against this client's egress guard and ready to use as the base of an
// outbound request — but ONLY with a client built from the SAME guard, which
// GuardedClient returns.
//
// This is the whole correct sequence in one call, and it exists because the
// sequence is what consumers got wrong: read the field, notice it is
// sibling-asserted rather than operator-pinned, validate it, and dial it with
// a guarded client. Skipping any step compiles.
//
// It returns an error when the sibling is not currently Active, when it has
// never been reached, when it advertises no publicUrl, or when the URL it
// advertises is not reachable under the deployment's egress policy. A caller
// that just wants to render the value (a UI config payload) wants
// Snapshot().PublicURL.Display() instead — no fetch, no check, no error.
func (d *DiscoveryClient) SiblingPublicURL(ctx context.Context) (string, error) {
	state, m := d.Snapshot()
	if state != StateActive || m == nil {
		return "", fmt.Errorf("suite: sibling is not active (state %q)", state)
	}
	return m.PublicURL.Resolve(ctx, d.guard)
}

// GuardedClient returns an *http.Client bound to this deployment's egress
// policy, for a consumer making its own follow-up requests to the sibling
// (the module-freshness join, for instance). timeout is the total per-request
// budget.
//
// It is a convenience with a purpose: it removes the last reason a consumer
// had to reach for a bare &http.Client{} — not knowing where the guard
// lived — and so removes the last way to accidentally leave a sibling-named
// destination unguarded. Pair it with SiblingPublicURL; using one without the
// other leaves half the check in place.
func (d *DiscoveryClient) GuardedClient(timeout time.Duration) *http.Client {
	return httpsafe.NewClient(timeout, d.guard)
}

// Start runs the poll loop until ctx is cancelled. Run it in a goroutine.
//
// A panic inside a single poll is recovered and logged, and the loop continues
// with the next tick. The goroutine belongs to the host application, so an
// unrecovered panic here would terminate the host process rather than fail a
// library call — losing one poll (the client simply keeps its previous state
// until the next one) is strictly preferable.
func (d *DiscoveryClient) Start(ctx context.Context) {
	d.safePollOnce(ctx)
	t := time.NewTicker(d.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.safePollOnce(ctx)
		}
	}
}

// safePollOnce is the loop body's panic boundary. pollOnce releases d.mu with
// a deferred unlock, so a recovered panic cannot leave the client's state lock
// held (which would wedge every Snapshot caller instead of crashing).
func (d *DiscoveryClient) safePollOnce(ctx context.Context) {
	safeloop.Guard("suite-discovery", func() { d.pollOnce(ctx) })
}

func (d *DiscoveryClient) pollOnce(ctx context.Context) {
	m, err := d.fetch(ctx)
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		if !d.lastOKAt.IsZero() && now.Sub(d.lastOKAt) <= d.graceWindow {
			d.state = StateDegraded
		} else {
			d.state = StateUnreachable
		}
		return
	}
	if ok, _ := NegotiateCompat(d.self, *m); !ok {
		d.state = StateUnreachable
		return
	}
	d.lastGood = m
	d.lastOKAt = now
	d.state = StateActive
}

func (d *DiscoveryClient) fetch(ctx context.Context) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.siblingURL+ManifestPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{resp.StatusCode}
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestBytes)).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

type statusError struct{ code int }

func (e *statusError) Error() string {
	return "manifest endpoint returned status " + strconv.Itoa(e.code)
}
