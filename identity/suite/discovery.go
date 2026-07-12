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
)

// SiblingState is the discovery client's view of the configured sibling.
type SiblingState string

const (
	StateUnknown     SiblingState = "unknown"     // not yet polled
	StateActive      SiblingState = "active"      // reachable AND compatible
	StateDegraded    SiblingState = "degraded"    // a poll failed, but within the grace window of a prior success
	StateUnreachable SiblingState = "unreachable" // unreachable beyond grace, or incompatible
)

const (
	defaultPollInterval = 60 * time.Second
	defaultGraceWindow  = 5 * time.Minute
	pollTimeout         = 2 * time.Second
	manifestPath        = "/api/v1/suite/manifest"
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

	mu       sync.RWMutex
	state    SiblingState
	lastGood *Manifest
	lastOKAt time.Time
}

// NewDiscoveryClient builds a client for the given sibling base URL (e.g.
// "https://tfstate.example.com"). A non-positive pollInterval uses the default.
//
// The manifest fetch carries no request auth or signature — only transport
// integrity protects it from tampering. A plaintext "http://" siblingURL is
// accepted here (only a warning is logged) so this constructor remains usable
// for local/dev setups where the sibling is reached over plaintext HTTP (e.g.
// loopback). For production use, prefer NewSecureDiscoveryClient, which
// refuses to construct a client for a plaintext sibling URL.
func NewDiscoveryClient(siblingURL string, self Manifest, pollInterval time.Duration) *DiscoveryClient {
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	siblingURL = strings.TrimRight(siblingURL, "/")
	if strings.HasPrefix(strings.ToLower(siblingURL), "http://") {
		slog.Warn("suite discovery: sibling URL uses plaintext HTTP; manifest polling is exposed to interception and tampering — use HTTPS",
			"sibling_url", siblingURL)
	}
	return &DiscoveryClient{
		siblingURL:   siblingURL,
		self:         self,
		pollInterval: pollInterval,
		graceWindow:  defaultGraceWindow,
		// Do not follow redirects: the manifest lives at a known path on the
		// configured sibling. Following a redirect could be steered to an
		// unintended (e.g. internal) host. ErrUseLastResponse returns the 3xx as-is,
		// which then fails the StatusOK check and is treated as unreachable.
		httpClient: &http.Client{
			Timeout: pollTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		state: StateUnknown,
	}
}

// NewSecureDiscoveryClient builds a client exactly like NewDiscoveryClient, but
// fails closed on an insecure sibling: it returns an error instead of
// constructing a client when siblingURL (after the same trailing-slash
// normalization NewDiscoveryClient applies) uses a plaintext "http://" scheme.
//
// The manifest endpoint is unauthenticated and unsigned, so a plaintext fetch
// lets any network-position attacker inject an arbitrary spoofed Manifest;
// NegotiateCompat's checks (app id, schema major) are trivially satisfiable by
// an attacker who knows the target app id, so transport security is the only
// real defense. This is the preferred constructor for production use.
//
// NewDiscoveryClient remains available, unchanged, for local/dev use with a
// plaintext sibling — it still only warns in that case rather than rejecting.
func NewSecureDiscoveryClient(siblingURL string, self Manifest, pollInterval time.Duration) (*DiscoveryClient, error) {
	normalized := strings.TrimRight(siblingURL, "/")
	if strings.HasPrefix(strings.ToLower(normalized), "http://") {
		return nil, fmt.Errorf("insecure sibling URL: %q uses plaintext HTTP; suite discovery requires HTTPS to protect the manifest fetch from tampering — use NewDiscoveryClient directly only if you understand and accept this risk (e.g. local development)", normalized)
	}
	return NewDiscoveryClient(siblingURL, self, pollInterval), nil
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

// Start runs the poll loop until ctx is cancelled. Run it in a goroutine.
func (d *DiscoveryClient) Start(ctx context.Context) {
	d.pollOnce(ctx)
	t := time.NewTicker(d.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.pollOnce(ctx)
		}
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.siblingURL+manifestPath, nil)
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
