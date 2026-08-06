// Package suite defines the runtime coupling contract between Terraform Suite
// applications (terraform-registry and terraform-state-manager): a capability
// manifest each app publishes, version negotiation, and a discovery client that
// polls a sibling app's manifest. The package intentionally has NO application
// or web-framework dependencies, so both apps import it identically and the
// contract cannot drift between them.
package suite

import (
	"context"
	"fmt"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

// UntrustedURL is a URL a SIBLING APP ASSERTED ABOUT ITSELF in its manifest
// response. It is not the operator-pinned sibling URL the discovering app was
// configured with, and this library does not independently verify it:
// NegotiateCompat checks only the app id and the schema major, both of which
// are trivially satisfiable by anyone who knows the target app id.
//
// It is a distinct type rather than a string because the defect it exists to
// prevent is not a mistake anyone makes deliberately. One consuming app
// resolve-and-pinned this field through the egress guard and wrote a regression
// test for it; the other read the identical field, from the identical
// Snapshot() API, into a bare *http.Client with Go's default cross-host
// redirect following — turning "any authenticated user opens a panel" into
// "this backend issues a GET to whatever address the manifest names, from
// inside the deployment network". Both authors were competent and the contract
// was the same; what differed was whether the trust boundary was visible at the
// call site. A `string` field is invisible. A type that will not concatenate is
// not.
//
// There are exactly two ways to get the value out, and they are named for what
// they are for: Resolve, which validates against the egress policy and is the
// only way to obtain a URL to FETCH, and Display, which does not validate and
// must never be used to build a request.
type UntrustedURL string

// Resolve validates the sibling-asserted URL against the deployment's egress
// policy and returns it as a plain string, ready to use as the base of an
// outbound request — but ONLY together with a client built from the same guard
// (httpsafe.NewClient), because this check is a pre-flight, not the enforcement
// point. Validation here fails fast with a clear error naming the destination;
// the client's dialer is what makes the guarantee hold when the name resolves
// differently at connect time.
//
// A nil guard is the strict default policy (loopback, RFC 1918, link-local
// including the cloud metadata address, CGNAT and IPv6 ULA all denied), so
// passing nil is safe rather than permissive.
//
// An empty value returns an error rather than an empty string: a sibling that
// advertises no public URL has nothing to fetch, and returning ("", nil) would
// invite a caller to concatenate a path onto "" and request it against itself.
func (u UntrustedURL) Resolve(ctx context.Context, g *httpsafe.Guard) (string, error) {
	raw := strings.TrimRight(strings.TrimSpace(string(u)), "/")
	if raw == "" {
		return "", fmt.Errorf("suite: sibling manifest advertises no publicUrl")
	}
	if err := g.ValidateURL(ctx, raw); err != nil {
		return "", fmt.Errorf("suite: sibling-asserted publicUrl %q is not reachable under this deployment's egress policy: %w", raw, err)
	}
	return raw, nil
}

// Display returns the raw sibling-asserted value for rendering and logging
// ONLY — a UI config payload, a diagnostic line, an admin page. It performs no
// validation whatsoever.
//
// Never build an outbound request from this. Use Resolve, which is the same
// call plus the check, and which costs nothing when the value is fine.
func (u UntrustedURL) Display() string { return string(u) }

// SchemaVersionV1 is the current manifest schema version. Two siblings are
// compatible only if the MAJOR token ("suite/v1" -> "v1") matches. MINOR/patch
// may evolve freely because parsers ignore unknown JSON fields (the anti-lockstep
// rule): a newer app can advertise new capabilities to an older one harmlessly.
const SchemaVersionV1 = "suite/v1"

// Manifest is the self-description a Suite app publishes at
// GET /api/v1/suite/manifest. It MUST stay additive: never remove or repurpose a
// field. Consumers MUST ignore unknown fields (encoding/json does this by default).
//
// # Trust
//
// A Manifest plays two roles, and they have opposite trust properties.
//
// As the value an app passes to NewDiscoveryClient to describe ITSELF, every
// field comes from that app's own configuration and is trusted.
//
// As the value returned by DiscoveryClient.Snapshot — the sibling's parsed
// response — EVERY FIELD IS UNTRUSTED INPUT ASSERTED BY THE SIBLING. It is not
// the operator-pinned sibling URL, and it is not verified here: NegotiateCompat
// inspects only App and the schema MAJOR. A sibling that is compromised, that
// is itself tricked into echoing an attacker-chosen value, or that is merely
// misconfigured with an internal address, controls what these fields say.
//
//   - PublicURL carries that boundary in its TYPE (UntrustedURL) because it is
//     the field consumers reuse to build further outbound requests. Call
//     Resolve to get a fetchable URL, or DiscoveryClient.SiblingPublicURL,
//     which does the same thing with the client's own guard.
//   - Links values are sibling-asserted too. They are path TEMPLATES in the
//     documented contract ("/modules/{namespace}/{name}/{system}"), not
//     absolute URLs, so they are typed as plain strings — but a consumer that
//     renders one into a link, or that ever accepts an absolute URL there,
//     owes it the same treatment: validate before fetching, escape before
//     rendering.
//   - Version, BuildDate and Identity.Issuer are display/negotiation values a
//     sibling asserts about itself. Never grant trust on Identity.SharedStore
//     or Identity.Issuer alone.
type Manifest struct {
	SchemaVersion string       `json:"schemaVersion"`
	App           string       `json:"app"`     // stable id, e.g. "terraform-registry"
	Version       string       `json:"version"` // semver of the running build
	BuildDate     string       `json:"buildDate,omitempty"`
	PublicURL     UntrustedURL `json:"publicUrl,omitempty"`
	Identity      IdentityInfo `json:"identity"`
	Capabilities  []Capability `json:"capabilities,omitempty"`
	// Links are sibling-asserted path templates. See the Trust section above.
	Links map[string]string `json:"links,omitempty"`
}

// clone returns a deep copy of the manifest. The value fields copy directly; the
// Capabilities slice and Links map are duplicated so a caller holding the copy
// cannot mutate shared state (e.g. the discovery client's cached last-good
// manifest) through the returned pointer. Returns nil for a nil receiver.
func (m *Manifest) clone() *Manifest {
	if m == nil {
		return nil
	}
	cp := *m
	if m.Capabilities != nil {
		cp.Capabilities = append([]Capability(nil), m.Capabilities...)
	}
	if m.Links != nil {
		cp.Links = make(map[string]string, len(m.Links))
		for k, v := range m.Links {
			cp.Links[k] = v
		}
	}
	return &cp
}

// IdentityInfo advertises how the app does identity so a sibling (and the UI)
// can decide whether single-sign-on is actually in effect.
type IdentityInfo struct {
	Issuer      string `json:"issuer"`           // the app's JWT issuer claim
	SharedStore bool   `json:"sharedStore"`      // true only when both apps share one identity DB
	Schema      string `json:"schema,omitempty"` // identity schema name, e.g. "identity"
}

// Capability is one feature the app offers. Additive: new fields may be added.
type Capability struct {
	ID string `json:"id"` // e.g. "modules.v1", "state.v1"
}

// Major returns the MAJOR token of a schema version: "suite/v1" -> "v1",
// "suite/v2.3" -> "v2". Returns the input unchanged if it has no "/".
func Major(schemaVersion string) string {
	i := strings.LastIndex(schemaVersion, "/")
	if i < 0 {
		return schemaVersion
	}
	major := schemaVersion[i+1:]
	if dot := strings.IndexByte(major, '.'); dot >= 0 {
		major = major[:dot]
	}
	return major
}

// NegotiateCompat reports whether a sibling manifest is compatible with self.
// Incompatible (false) when: the sibling app id is empty, equals self (a
// pointing-at-yourself misconfiguration), either side's schema MAJOR is empty,
// or the schema MAJORs differ.
func NegotiateCompat(self, sibling Manifest) (bool, string) {
	if sibling.App == "" {
		return false, "sibling manifest has empty app id"
	}
	if sibling.App == self.App {
		return false, "sibling app equals self (pointing at self?)"
	}
	selfMajor := Major(self.SchemaVersion)
	siblingMajor := Major(sibling.SchemaVersion)
	// Major("") == "", so without this guard two manifests that both happen to
	// have an empty/unset SchemaVersion would silently pass the equality check
	// below ("" == ""). Treat that as an explicit incompatibility rather than
	// a silent pass.
	if selfMajor == "" {
		return false, "schema version missing on self"
	}
	if siblingMajor == "" {
		return false, "sibling manifest has empty schema version"
	}
	if siblingMajor != selfMajor {
		return false, "schema major mismatch: " + sibling.SchemaVersion + " vs " + self.SchemaVersion
	}
	return true, ""
}
