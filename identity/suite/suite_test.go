package suite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManifestJSONRoundTrip(t *testing.T) {
	in := Manifest{
		SchemaVersion: SchemaVersionV1,
		App:           "terraform-registry",
		Version:       "1.2.3",
		PublicURL:     "https://registry.example.com",
		Identity:      IdentityInfo{Issuer: "terraform-registry", SharedStore: false, Schema: "identity"},
		Capabilities:  []Capability{{ID: "modules.v1"}},
		Links:         map[string]string{"moduleDetail": "/modules/{namespace}/{name}/{system}"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Manifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.App != in.App || out.SchemaVersion != in.SchemaVersion || out.Identity.Issuer != in.Identity.Issuer {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	raw := `{"schemaVersion":"suite/v1","app":"terraform-state-manager","futureField":42,"capabilities":[{"id":"state.v1","futureCap":true}]}`
	var m Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unknown fields must be ignored, got: %v", err)
	}
	if m.App != "terraform-state-manager" {
		t.Fatalf("app = %q", m.App)
	}
}

func TestMajor(t *testing.T) {
	cases := map[string]string{"suite/v1": "v1", "suite/v2.3": "v2", "v1": "v1", "": ""}
	for in, want := range cases {
		if got := Major(in); got != want {
			t.Errorf("Major(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNegotiateCompat(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	tests := []struct {
		name   string
		sib    Manifest
		wantOK bool
	}{
		{"compatible sibling", Manifest{SchemaVersion: "suite/v1", App: "terraform-state-manager"}, true},
		{"same app (self)", Manifest{SchemaVersion: "suite/v1", App: "terraform-registry"}, false},
		{"major mismatch", Manifest{SchemaVersion: "suite/v2", App: "terraform-state-manager"}, false},
		{"empty app", Manifest{SchemaVersion: "suite/v1", App: ""}, false},
	}
	for _, tt := range tests {
		if ok, _ := NegotiateCompat(self, tt.sib); ok != tt.wantOK {
			t.Errorf("%s: got %v, want %v", tt.name, ok, tt.wantOK)
		}
	}
}

func TestDiscoveryClient_ActiveThenUnreachable(t *testing.T) {
	sibling := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-state-manager",
		Identity: IdentityInfo{Issuer: "terraform-state-manager"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != manifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(sibling)
	}))

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	// srv is a plain-HTTP httptest server (a local/dev-style loopback target),
	// so the explicit insecure opt-out is the right constructor here.
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second)

	d.pollOnce(context.Background())
	if st, m := d.Snapshot(); st != StateActive || m == nil || m.App != "terraform-state-manager" {
		t.Fatalf("after good poll: state=%v manifest=%v", st, m)
	}

	srv.Close()
	d.mu.Lock()
	d.lastOKAt = time.Now().Add(-10 * time.Minute)
	d.mu.Unlock()
	d.pollOnce(context.Background())
	if st, _ := d.Snapshot(); st != StateUnreachable {
		t.Fatalf("after sibling down beyond grace: state=%v, want unreachable", st)
	}
}

func TestDiscoveryClient_DegradedWithinGrace(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	// Deliberately unreachable (port 0); http:// here needs the insecure
	// opt-out since this test is about the degraded-transition logic, not
	// the scheme guard.
	d := NewInsecureDiscoveryClient("http://127.0.0.1:0", self, time.Second)
	d.mu.Lock()
	d.lastOKAt = time.Now()
	d.mu.Unlock()
	d.pollOnce(context.Background())
	if st, _ := d.Snapshot(); st != StateDegraded {
		t.Fatalf("failed poll within grace window: state=%v, want degraded", st)
	}
}

func TestDiscoveryClient_SnapshotReturnsIsolatedCopy(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d, err := NewDiscoveryClient("https://sibling.example", self, time.Second)
	if err != nil {
		t.Fatalf("unexpected error for an https:// siblingURL: %v", err)
	}
	d.mu.Lock()
	d.state = StateActive
	d.lastGood = &Manifest{
		SchemaVersion: SchemaVersionV1,
		App:           "terraform-state-manager",
		Capabilities:  []Capability{{ID: "state.v1"}},
		Links:         map[string]string{"ui": "https://sibling.example/ui"},
	}
	d.mu.Unlock()

	_, m := d.Snapshot()
	// Mutating the returned copy must not affect the client's cached manifest.
	m.Links["ui"] = "https://evil.example"
	m.Capabilities[0].ID = "tampered"
	m.App = "tampered"

	_, again := d.Snapshot()
	if again.Links["ui"] != "https://sibling.example/ui" {
		t.Errorf("cached Links mutated via Snapshot copy: %q", again.Links["ui"])
	}
	if again.Capabilities[0].ID != "state.v1" {
		t.Errorf("cached Capabilities mutated via Snapshot copy: %q", again.Capabilities[0].ID)
	}
	if again.App != "terraform-state-manager" {
		t.Errorf("cached App mutated via Snapshot copy: %q", again.App)
	}
}

func TestDiscoveryClient_DoesNotFollowRedirects(t *testing.T) {
	// A sibling that redirects the manifest must NOT be followed to another
	// location; the 3xx is treated as a non-OK response (unreachable). If the
	// client wrongly followed it, /elsewhere would return a valid manifest and
	// the state would become Active.
	sibling := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-state-manager",
		Identity: IdentityInfo{Issuer: "terraform-state-manager"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case manifestPath:
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/elsewhere":
			_ = json.NewEncoder(w).Encode(sibling)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second)
	d.pollOnce(context.Background())

	if st, m := d.Snapshot(); st != StateUnreachable || m != nil {
		t.Fatalf("redirect must not be followed (want unreachable/nil), got state=%v manifest=%v", st, m)
	}
}

func TestDiscoveryClient_IncompatibleManifestBecomesUnreachableButKeepsStaleLastGood(t *testing.T) {
	// Unlike a connection failure, a 200 response with a well-formed but
	// INCOMPATIBLE manifest (different app id here) fails NegotiateCompat.
	// pollOnce's incompatible branch only sets d.state — it does not clear
	// d.lastGood/d.lastOKAt (discovery.go's pollOnce, the `if ok, _ :=
	// NegotiateCompat(...); !ok` branch returns without touching either) — so
	// Snapshot() keeps returning the stale prior-good manifest indefinitely
	// once a sibling degrades to incompatible. Pinned here as a known,
	// intentionally-untouched behavior (a testing-coverage gap, not something
	// this test changes).
	var compatible atomic.Bool
	compatible.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != manifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if compatible.Load() {
			_ = json.NewEncoder(w).Encode(Manifest{
				SchemaVersion: SchemaVersionV1, App: "terraform-state-manager",
				Identity: IdentityInfo{Issuer: "terraform-state-manager"},
			})
			return
		}
		// Well-formed manifest, but incompatible (major schema mismatch).
		_ = json.NewEncoder(w).Encode(Manifest{SchemaVersion: "suite/v2", App: "terraform-state-manager"})
	}))
	defer srv.Close()

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second)

	d.pollOnce(context.Background())
	st, m := d.Snapshot()
	if st != StateActive || m == nil || m.App != "terraform-state-manager" {
		t.Fatalf("after good poll: state=%v manifest=%v", st, m)
	}

	compatible.Store(false)
	d.pollOnce(context.Background())
	st, m = d.Snapshot()
	if st != StateUnreachable {
		t.Fatalf("after incompatible manifest: state=%v, want unreachable", st)
	}
	if m == nil || m.App != "terraform-state-manager" {
		t.Fatalf("Snapshot() after incompatible transition = %v, want the STALE prior-good manifest still returned (pinned known behavior)", m)
	}
}

func TestNewDiscoveryClient_RejectsPlaintextHTTP(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d, err := NewDiscoveryClient("http://sibling.example", self, time.Second)
	if err == nil {
		t.Fatal("expected an error for a plaintext http:// siblingURL, got nil")
	}
	if d != nil {
		t.Fatalf("expected a nil client on rejection, got %+v", d)
	}
	if !strings.Contains(err.Error(), "http://sibling.example") {
		t.Errorf("error message should reference the rejected URL, got: %v", err)
	}
}

func TestNewDiscoveryClient_RejectsPlaintextHTTP_CaseInsensitiveAndTrailingSlash(t *testing.T) {
	// Mirrors NewDiscoveryClient's own TrimRight(siblingURL, "/") normalization
	// and case-insensitive scheme check, so an uppercase scheme or a trailing
	// slash cannot slip past the guard.
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d, err := NewDiscoveryClient("HTTP://sibling.example/", self, time.Second)
	if err == nil || d != nil {
		t.Fatalf("expected rejection for uppercase-scheme plaintext URL, got client=%+v err=%v", d, err)
	}
}

func TestNewDiscoveryClient_AcceptsHTTPS(t *testing.T) {
	sibling := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-state-manager",
		Identity: IdentityInfo{Issuer: "terraform-state-manager"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != manifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(sibling)
	}))
	defer srv.Close()
	// httptest.NewServer is plain HTTP; swap the scheme to https:// to exercise
	// the accept path without standing up a TLS listener — NewDiscoveryClient
	// only inspects the scheme prefix, it does not itself dial the sibling.
	httpsURL := "https://" + strings.TrimPrefix(srv.URL, "http://")

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d, err := NewDiscoveryClient(httpsURL, self, time.Second)
	if err != nil {
		t.Fatalf("unexpected error for an https:// siblingURL: %v", err)
	}
	if d == nil {
		t.Fatal("expected a non-nil client for an https:// siblingURL")
	}

	want := NewInsecureDiscoveryClient(httpsURL, self, time.Second)
	if d.siblingURL != want.siblingURL || d.pollInterval != want.pollInterval ||
		d.graceWindow != want.graceWindow || d.state != want.state ||
		d.self.App != want.self.App || d.self.SchemaVersion != want.self.SchemaVersion {
		t.Fatalf("NewDiscoveryClient result diverges from NewInsecureDiscoveryClient given the same https:// URL: got %+v, want-equivalent %+v", d, want)
	}
}

func TestNewInsecureDiscoveryClient_PlaintextHTTPStillWarnsAndConstructs(t *testing.T) {
	// NewInsecureDiscoveryClient is the explicit, named opt-out: it must still
	// only warn (never reject) on a plaintext sibling, and return a working,
	// non-nil client that a caller can Start()/poll normally.
	sibling := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-state-manager",
		Identity: IdentityInfo{Issuer: "terraform-state-manager"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != manifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(sibling)
	}))
	defer srv.Close()

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second) // srv.URL is plain http://
	if d == nil {
		t.Fatal("NewInsecureDiscoveryClient must still construct a client for a plaintext sibling URL")
	}
	d.pollOnce(context.Background())
	if st, m := d.Snapshot(); st != StateActive || m == nil || m.App != "terraform-state-manager" {
		t.Fatalf("plaintext-sibling client must still operate normally: state=%v manifest=%v", st, m)
	}
}

func TestNewInsecureDiscoveryClient_AcceptsHTTPS(t *testing.T) {
	// The insecure opt-out must not itself become "insecure-only" — an https://
	// siblingURL passed to it works exactly as it would via NewDiscoveryClient.
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient("https://sibling.example", self, time.Second)
	if d == nil || d.siblingURL != "https://sibling.example" {
		t.Fatalf("expected a working client for an https:// siblingURL, got %+v", d)
	}
}

func TestDiscoveryClient_OversizedBodyRejected(t *testing.T) {
	// maxManifestBytes (1 MiB) caps the response body read. A sibling streaming
	// more than that must be truncated/rejected (a decode failure -> fetch
	// error -> unreachable) rather than hanging or succeeding on a partial body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != manifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Emit a JSON object whose single field value exceeds 1 MiB, so the
		// object is truncated mid-value at the cap and never valid JSON.
		_, _ = w.Write([]byte(`{"schemaVersion":"suite/v1","app":"terraform-state-manager","padding":"`))
		padding := strings.Repeat("x", 2<<20) // 2 MiB, well past the 1 MiB cap
		_, _ = w.Write([]byte(padding))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second)
	d.pollOnce(context.Background())

	if st, m := d.Snapshot(); st != StateUnreachable || m != nil {
		t.Fatalf("oversized body must be rejected (want unreachable/nil), got state=%v manifest=%v", st, m)
	}
}
