package suite

import (
	"context"
	"encoding/json"
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

// Snapshot returns the current state and the last-good sibling manifest (nil if
// the sibling was never successfully reached). Cheap; safe to call per request.
func (d *DiscoveryClient) Snapshot() (SiblingState, *Manifest) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.state, d.lastGood
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
