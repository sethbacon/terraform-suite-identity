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
		// Port canonicalized numerically: a leading-zero default port folds away,
		// and a leading-zero non-default port loses the zero — so ":080" and ":80"
		// (and ":08443"/":8443") produce the same join key.
		{"leading-zero default port", "reg.example.com:080", "reg.example.com"},
		{"leading-zero non-default port", "reg.example.com:08443", "reg.example.com:8443"},
		// IPv6 brackets are unwrapped so every spelling of the same literal folds
		// to one key.
		{"ipv6 bare bracketed", "[::1]", "::1"},
		{"ipv6 default port", "[::1]:443", "::1"},
		{"ipv6 non-default port", "[::1]:8080", "[::1]:8080"},
		{"ipv6 uppercase + default port", "[2001:DB8::1]:443", "2001:db8::1"},
		// Adversarial input shapes not exploitable beyond join-key mismatch (this
		// is a normalization helper, not an auth check) but worth pinning since a
		// real consumer (parsing a user-editable module source address or a
		// config-file host string) could hand these to the function.
		//
		// No colon at all: this is the bare-hostname fast path, unaffected by
		// the userinfo/multi-colon fallback below (there's no port to recover).
		{"userinfo-prefixed host passes through unmodified", "attacker@reg.example.com", "attacker@reg.example.com"},
		{"non-numeric port re-emitted verbatim (Atoi fails silently)", "reg.example.com:notaport", "reg.example.com:notaport"},
		// A malformed double-scheme URL is NOT handled gracefully: url.Parse
		// misreads "https:" (from the second scheme) as the host, so the real
		// host "evil.com" is silently DROPPED — contradicting this function's own
		// doc comment ("never drops or mangles input"). Pinned as a known gap.
		{"double scheme drops the real host", "https://https://evil.com", "https"},
		// Userinfo combined with a port: net.SplitHostPort rejects this
		// ("too many colons"), and the url.Parse fallback recovers a non-nil
		// User, so this is now explicitly REJECTED (returns "") rather than
		// silently passed through as garbage.
		{"userinfo + port rejected outright", "user:pass@host:1234", ""},
		// Trailing junk after a valid host:port. net.SplitHostPort rejects this
		// ("too many colons"), and url.Parse's fallback also fails (invalid
		// port after host), so this is rejected outright (returns "") rather
		// than silently passing "host:443:extra" through unchanged.
		{"trailing junk after host:port rejected outright", "host:443:extra", ""},
		// Regression guard: a normal full-URL sibling address (scheme + mixed
		// case + default port + trailing slash) must still canonicalize exactly
		// as before — unaffected by the userinfo/multi-colon fallback, since
		// SplitHostPort accepts "Sibling.Example.com:443" cleanly on its own.
		{"full URL with default port unaffected", "https://Sibling.Example.com:443/", "sibling.example.com"},
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
