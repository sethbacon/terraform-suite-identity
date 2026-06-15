package suite

import (
	"strings"
	"testing"
)

func TestCanonicalHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "reg.example.com", "reg.example.com"},
		{"uppercase", "REG.Example.COM", "reg.example.com"},
		{"trailing dot", "reg.example.com.", "reg.example.com"},
		{"default https port stripped", "reg.example.com:443", "reg.example.com"},
		{"default http port stripped", "reg.example.com:80", "reg.example.com"},
		{"non-default port preserved", "reg.example.com:8443", "reg.example.com:8443"},
		{"scheme stripped", "https://reg.example.com/", "reg.example.com"},
		{"scheme + default port + path", "https://REG.Example.com.:443/v1/modules/", "reg.example.com"},
		{"scheme + non-default port", "http://reg.example.com:8080", "reg.example.com:8080"},
		{"surrounding whitespace", "  reg.example.com  ", "reg.example.com"},
		{"public registry idempotent", "registry.terraform.io", "registry.terraform.io"},
		{"ipv4", "10.0.0.5", "10.0.0.5"},
		{"ipv4 with port", "10.0.0.5:8443", "10.0.0.5:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalHost(tc.in); got != tc.want {
				t.Errorf("CanonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalHost_Idempotent guards the join invariant: applying the function
// twice equals applying it once, so re-canonicalizing a stored host never drifts.
func TestCanonicalHost_Idempotent(t *testing.T) {
	for _, in := range []string{
		"reg.example.com", "REG.Example.com:443", "https://reg.example.com:8080",
		"CAFÉ.Example.com", // IDN: punycode form must re-canonicalize stably
	} {
		once := CanonicalHost(in)
		if twice := CanonicalHost(once); twice != once {
			t.Errorf("not idempotent: CanonicalHost(%q)=%q then %q", in, once, twice)
		}
	}
}

// TestCanonicalHost_IDN: a Unicode host folds to lowercase punycode ASCII so it
// matches a punycode-encoded source address. (Exact punycode is not hardcoded —
// asserted via ASCII-ness + the xn-- prefix + stability.)
func TestCanonicalHost_IDN(t *testing.T) {
	got := CanonicalHost("CAFÉ.Example.COM")
	if !strings.HasPrefix(got, "xn--") || !strings.HasSuffix(got, ".example.com") {
		t.Fatalf("IDN host not folded to punycode: %q", got)
	}
	for _, r := range got {
		if r > 127 {
			t.Fatalf("result not ASCII: %q", got)
		}
	}
	// Non-default port is preserved alongside IDN folding.
	if withPort := CanonicalHost("CAFÉ.Example.com:8443"); !strings.HasSuffix(withPort, ":8443") {
		t.Errorf("port dropped on IDN host: %q", withPort)
	}
}
