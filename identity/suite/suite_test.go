package suite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	d := NewDiscoveryClient(srv.URL, self, time.Second)

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
	d := NewDiscoveryClient("http://127.0.0.1:0", self, time.Second)
	d.mu.Lock()
	d.lastOKAt = time.Now()
	d.mu.Unlock()
	d.pollOnce(context.Background())
	if st, _ := d.Snapshot(); st != StateDegraded {
		t.Fatalf("failed poll within grace window: state=%v, want degraded", st)
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
	d := NewDiscoveryClient(srv.URL, self, time.Second)
	d.pollOnce(context.Background())

	if st, m := d.Snapshot(); st != StateUnreachable || m != nil {
		t.Fatalf("redirect must not be followed (want unreachable/nil), got state=%v manifest=%v", st, m)
	}
}
