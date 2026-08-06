// egress_test.go covers the manifest field a sibling ASSERTS ABOUT ITSELF and
// consumers then reuse to build further outbound requests.
//
// The operator pins siblingURL. The sibling pins publicUrl. Those are not the
// same thing, and NegotiateCompat does not make them the same thing: it checks
// the app id and the schema major, both of which anyone who knows the target
// app id can satisfy. So a sibling that is compromised, that is tricked into
// echoing an attacker-chosen value, or that is simply misconfigured with an
// internal address decides what publicUrl says — and a consumer that
// concatenates a path onto it and fetches it is issuing that request from
// inside the deployment network.
//
// Both directions are asserted throughout: denied must be refused AND permitted
// must still work.
package suite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

// siblingServing stands up a sibling whose manifest advertises publicURL, polls
// it once, and returns the client. The sibling is otherwise well-formed and
// compatible, so nothing but publicUrl is in question.
func siblingServing(t *testing.T, publicURL string) *DiscoveryClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ManifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Manifest{
			SchemaVersion: SchemaVersionV1,
			App:           "terraform-state-manager",
			Version:       "1.0.0",
			PublicURL:     UntrustedURL(publicURL),
		})
	}))
	t.Cleanup(srv.Close)

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second, testGuard())
	d.pollOnce(context.Background())
	if state, _ := d.Snapshot(); state != StateActive {
		t.Fatalf("sibling state = %q, want active — the fixture, not the assertion, is broken", state)
	}
	return d
}

// deniedPublicURLs are addresses the deployment's policy refuses. Each is an IP
// literal, so no DNS lookup and no network request occurs.
var deniedPublicURLs = []struct{ name, url string }{
	{"link-local metadata", "http://169.254.169.254"},
	{"RFC 1918 private", "http://10.10.10.10"},
	{"loopback outside the allow-list", "http://127.0.0.2:9"},
}

func TestSiblingPublicURL_RefusesADeniedDestination(t *testing.T) {
	for _, d := range deniedPublicURLs {
		t.Run(d.name, func(t *testing.T) {
			dc := siblingServing(t, d.url)
			got, err := dc.SiblingPublicURL(context.Background())
			if err == nil {
				t.Fatalf("SiblingPublicURL returned %q for a sibling-asserted address this deployment refuses", got)
			}
			if got != "" {
				t.Errorf("SiblingPublicURL returned %q alongside its error; a caller that ignores err would fetch it", got)
			}
			// The refusal must NAME the destination so an operator can tell a
			// hostile manifest from a missing allow-list entry.
			if !strings.Contains(err.Error(), d.url) {
				t.Errorf("refusal does not name the destination %q: %v", d.url, err)
			}
		})
	}
}

func TestSiblingPublicURL_AcceptsAPermittedDestination(t *testing.T) {
	// The sibling advertises an address this deployment DOES allow. Without
	// this half, every assertion above would pass against a method that always
	// failed.
	dc := siblingServing(t, "http://127.0.0.1:9999/")
	got, err := dc.SiblingPublicURL(context.Background())
	if err != nil {
		t.Fatalf("SiblingPublicURL refused an allow-listed destination: %v", err)
	}
	if got != "http://127.0.0.1:9999" {
		t.Errorf("SiblingPublicURL = %q, want the advertised URL with the trailing slash trimmed", got)
	}
}

func TestSiblingPublicURL_RefusesWhenTheSiblingIsNotActive(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient("http://127.0.0.1:1", self, time.Second, testGuard())
	if _, err := d.SiblingPublicURL(context.Background()); err == nil {
		t.Fatal("SiblingPublicURL succeeded for a sibling that was never reached")
	}
}

func TestUntrustedURL_ResolveBothDirections(t *testing.T) {
	guard := httpsafe.MustGuard("203.0.113.10")
	for _, tc := range []struct {
		name    string
		url     UntrustedURL
		wantErr bool
	}{
		{"metadata endpoint", "http://169.254.169.254/latest/meta-data/", true},
		{"private range", "http://192.168.1.1/", true},
		{"empty", "", true},
		{"non-http scheme", "file:///etc/passwd", true},
		{"allow-listed address", "https://203.0.113.10/", false},
		{"public address", "https://198.51.100.7/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.url.Resolve(context.Background(), guard)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Resolve(%q) = %q, want an error", tc.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) = %v, want nil", tc.url, err)
			}
			if got == "" {
				t.Error("Resolve returned an empty URL with no error")
			}
		})
	}
}

// TestUntrustedURL_NilGuardIsStrictNotPermissive keeps the nil case from being
// the accidental bypass. A consumer that has not wired a guard yet must get the
// STRICT policy, not no policy.
func TestUntrustedURL_NilGuardIsStrictNotPermissive(t *testing.T) {
	if _, err := UntrustedURL("http://169.254.169.254/").Resolve(context.Background(), nil); err == nil {
		t.Fatal("a nil guard permitted the cloud metadata endpoint")
	}
	if _, err := UntrustedURL("https://198.51.100.7/").Resolve(context.Background(), nil); err != nil {
		t.Fatalf("a nil guard refused a public address: %v", err)
	}
}

// TestUntrustedURL_DisplayDoesNotValidate documents the deliberate asymmetry:
// Display exists so a UI can render what the sibling claims, and must never be
// used to build a request. Naming the two operations differently is the whole
// point of the type.
func TestUntrustedURL_DisplayDoesNotValidate(t *testing.T) {
	u := UntrustedURL("http://169.254.169.254/")
	if u.Display() != "http://169.254.169.254/" {
		t.Errorf("Display() = %q, want the raw value", u.Display())
	}
}

// TestManifestJSONShapeIsUnchangedByTheType guards the wire contract: PublicURL
// became a distinct Go type to make the trust boundary visible at the call
// site, and that must be invisible on the wire. A named string type marshals
// identically, but "must" is not "does".
func TestManifestJSONShapeIsUnchangedByTheType(t *testing.T) {
	b, err := json.Marshal(Manifest{
		SchemaVersion: SchemaVersionV1,
		App:           "terraform-registry",
		PublicURL:     "https://registry.example.com",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"publicUrl":"https://registry.example.com"`) {
		t.Errorf("publicUrl no longer marshals as a plain JSON string: %s", b)
	}

	// omitempty must still elide it.
	b, err = json.Marshal(Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "publicUrl") {
		t.Errorf("an empty publicUrl is no longer elided by omitempty: %s", b)
	}

	var back Manifest
	if err := json.Unmarshal([]byte(`{"publicUrl":"https://x.example"}`), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.PublicURL != "https://x.example" {
		t.Errorf("PublicURL round-tripped as %q", back.PublicURL)
	}
}

// TestDiscoveryClient_ManifestPollIsGuarded covers the fetch that PRODUCES the
// manifest, not just the one that follows it. A sibling on a denied address
// must not be polled at all.
func TestDiscoveryClient_ManifestPollIsGuarded(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	// A guard that allow-lists nothing: the httptest server is on loopback, so
	// the poll must be refused before any connection is made.
	d := NewInsecureDiscoveryClient(srv.URL, self, time.Second, nil)
	d.pollOnce(context.Background())

	if reached {
		t.Error("the manifest poll reached a sibling on an address the egress policy denies")
	}
	if state, _ := d.Snapshot(); state != StateUnreachable {
		t.Errorf("state = %q, want unreachable", state)
	}
}

// TestGuardedClient_UsesTheClientsOwnGuard closes the last gap: a consumer
// making its own follow-up request to the sibling gets a client bound to the
// same policy, so it has no reason left to build a bare one.
func TestGuardedClient_UsesTheClientsOwnGuard(t *testing.T) {
	self := Manifest{SchemaVersion: SchemaVersionV1, App: "terraform-registry"}
	d := NewInsecureDiscoveryClient("http://127.0.0.1:1", self, time.Second, nil)

	client := d.GuardedClient(2 * time.Second)
	if client.Timeout != 2*time.Second {
		t.Errorf("Timeout = %s, want 2s", client.Timeout)
	}
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the client returned by GuardedClient reached the cloud metadata endpoint")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error does not read as an egress-policy refusal: %v", err)
	}
}
