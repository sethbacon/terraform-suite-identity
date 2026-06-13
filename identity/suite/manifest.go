// Package suite defines the runtime coupling contract between Terraform Suite
// applications (terraform-registry and terraform-state-manager): a capability
// manifest each app publishes, version negotiation, and a discovery client that
// polls a sibling app's manifest. The package intentionally has NO application
// or web-framework dependencies, so both apps import it identically and the
// contract cannot drift between them.
package suite

import "strings"

// SchemaVersionV1 is the current manifest schema version. Two siblings are
// compatible only if the MAJOR token ("suite/v1" -> "v1") matches. MINOR/patch
// may evolve freely because parsers ignore unknown JSON fields (the anti-lockstep
// rule): a newer app can advertise new capabilities to an older one harmlessly.
const SchemaVersionV1 = "suite/v1"

// Manifest is the self-description a Suite app publishes at
// GET /api/v1/suite/manifest. It MUST stay additive: never remove or repurpose a
// field. Consumers MUST ignore unknown fields (encoding/json does this by default).
type Manifest struct {
	SchemaVersion string            `json:"schemaVersion"`
	App           string            `json:"app"`     // stable id, e.g. "terraform-registry"
	Version       string            `json:"version"` // semver of the running build
	BuildDate     string            `json:"buildDate,omitempty"`
	PublicURL     string            `json:"publicUrl,omitempty"`
	Identity      IdentityInfo      `json:"identity"`
	Capabilities  []Capability      `json:"capabilities,omitempty"`
	Links         map[string]string `json:"links,omitempty"`
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
// pointing-at-yourself misconfiguration), or its schema MAJOR differs.
func NegotiateCompat(self, sibling Manifest) (bool, string) {
	if sibling.App == "" {
		return false, "sibling manifest has empty app id"
	}
	if sibling.App == self.App {
		return false, "sibling app equals self (pointing at self?)"
	}
	if Major(sibling.SchemaVersion) != Major(self.SchemaVersion) {
		return false, "schema major mismatch: " + sibling.SchemaVersion + " vs " + self.SchemaVersion
	}
	return true, ""
}
