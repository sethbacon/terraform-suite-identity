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
		// A bare, unbracketed, non-zone-scoped IPv6 literal with no port reaches
		// splitHostPort's url.Parse fallback: net.SplitHostPort rejects it ("too
		// many colons") and bareIPv6WithZone declines it (no "%zone"), but
		// url.Parse("//::1") recovers it cleanly. This is a legitimate input
		// shape, not malformed junk, so it must round-trip unchanged — and it
		// must fold to the SAME key as its bracketed spelling "[::1]" above, or
		// the "Consumed by" join would miss.
		{"ipv6 bare unbracketed, no port", "::1", "::1"},
		{"ipv6 bare unbracketed non-loopback, no port", "2001:db8::1", "2001:db8::1"},
		{"ipv6 bare unbracketed uppercase folds to lowercase", "2001:DB8::1", "2001:db8::1"},
		{"ipv6 unspecified address", "::", "::"},
		// Adversarial input shapes not exploitable beyond join-key mismatch (this
		// is a normalization helper, not an auth check) but worth pinning since a
		// real consumer (parsing a user-editable module source address or a
		// config-file host string) could hand these to the function.
		//
		// Userinfo ("@") is never legitimate for a bare host-identity join key,
		// so it's rejected outright regardless of colon count: a bare userinfo
		// prefix with no colon at all (would otherwise take the no-port fast
		// path)...
		{"bare userinfo prefix (no colon) rejected outright", "attacker@reg.example.com", ""},
		// ...userinfo with no password, single colon (only separates host from
		// port) — net.SplitHostPort happily splits this into host="user@host",
		// port="1234" on its own, so this shape is NOT caught by any
		// colon-count-based check; only an explicit "@" scan catches it.
		{"userinfo (no password) + port rejected outright", "user@host:1234", ""},
		// ...userinfo with a password but no port — a single colon (between
		// user and pass), so net.SplitHostPort also splits this cleanly
		// (host="user", port="pass@evil.com") without ever erroring.
		{"userinfo (with password), no port, rejected outright", "user:pass@evil.com", ""},
		// ...userinfo with no password, default port present — single colon
		// again; would otherwise merely have its default port stripped and
		// pass through as "user@evil.com".
		{"userinfo (no password) + default port rejected outright", "user@evil.com:443", ""},
		// ...and userinfo with both password and port, the two-colon shape
		// net.SplitHostPort itself rejects ("too many colons").
		{"userinfo (with password) + port rejected outright", "user:pass@host:1234", ""},
		{"non-numeric port re-emitted verbatim (Atoi fails silently)", "reg.example.com:notaport", "reg.example.com:notaport"},
		// A malformed double-scheme URL is NOT handled gracefully: url.Parse
		// misreads "https:" (from the second scheme) as the host, so the real
		// host "evil.com" is silently DROPPED — contradicting this function's own
		// doc comment ("never drops or mangles input"). Pinned as a known gap.
		{"double scheme drops the real host", "https://https://evil.com", "https"},
		// Trailing junk after a valid host:port. net.SplitHostPort rejects this
		// ("too many colons"), and url.Parse's fallback also fails (invalid
		// port after host), so this is rejected outright (returns "") rather
		// than silently passing "host:443:extra" through unchanged.
		{"trailing junk after host:port rejected outright", "host:443:extra", ""},
		// Bare (unbracketed) zone-scoped IPv6 literal: net.SplitHostPort demands
		// brackets around IPv6 and errors on this ("too many colons"), and
		// net/url's authority parser can't recover it either (it misreads the
		// "%zone" suffix as an invalid port) — but this is a legitimate address
		// form, not malformed junk, so it must round-trip unchanged rather than
		// collapsing to "" like the genuinely-malformed shapes above.
		{"bare zone-scoped IPv6 literal round-trips unchanged", "2001:db8::1%eth0", "2001:db8::1%eth0"},
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

// TestCanonicalHost_IPv6SpellingsFoldTogether states the join invariant the two
// new bare-IPv6 cases exist for: bracketed and unbracketed spellings of one
// literal, with or without a default port, must all produce the same key.
func TestCanonicalHost_IPv6SpellingsFoldTogether(t *testing.T) {
	groups := [][]string{
		{"::1", "[::1]", "[::1]:443", "[::1]:80", "[::1]:080"},
		{"2001:db8::1", "2001:DB8::1", "[2001:db8::1]", "[2001:DB8::1]:443"},
	}
	for _, group := range groups {
		want := CanonicalHost(group[0])
		for _, in := range group[1:] {
			if got := CanonicalHost(in); got != want {
				t.Errorf("CanonicalHost(%q) = %q, want %q (same literal as %q)", in, got, want, group[0])
			}
		}
	}
}

// TestSplitHostPort exercises the four host/port-splitting sub-cases directly,
// which the audit noted were only reachable through the whole of CanonicalHost.
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{"no colon fast path", "reg.example.com", "reg.example.com", "", true},
		{"SplitHostPort accepts host:port", "reg.example.com:8443", "reg.example.com", "8443", true},
		{"SplitHostPort accepts [ipv6]:port", "[::1]:8443", "::1", "8443", true},
		{"bare zone-scoped IPv6", "fe80::1%eth0", "fe80::1%eth0", "", true},
		{"url.Parse fallback recovers bare IPv6", "::1", "::1", "", true},
		{"malformed multi-colon rejected", "host:443:extra", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, ok := splitHostPort(tc.in)
			if host != tc.wantHost || port != tc.wantPort || ok != tc.wantOK {
				t.Errorf("splitHostPort(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.in, host, port, ok, tc.wantHost, tc.wantPort, tc.wantOK)
			}
		})
	}
}

// TestCanonicalPort covers the port sub-case on its own, including the
// "never mangle input" branch for a non-numeric port.
func TestCanonicalPort(t *testing.T) {
	cases := map[string]string{
		"":          "",
		"80":        "",
		"443":       "",
		"080":       "",
		"0443":      "",
		"8443":      "8443",
		"08443":     "8443",
		"notaport":  "notaport",
		"65535":     "65535",
		"-1":        "-1",
		"000000080": "",
	}
	for in, want := range cases {
		if got := canonicalPort(in); got != want {
			t.Errorf("canonicalPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStripScheme and TestFoldHost cover the remaining two pipeline steps.
func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"reg.example.com":                 "reg.example.com",
		"https://reg.example.com/":        "reg.example.com",
		"http://reg.example.com:8080/v1/": "reg.example.com:8080",
		// No "://" at all: returned untouched, colon or not.
		"reg.example.com:8443": "reg.example.com:8443",
		// Contains "://" but yields no usable authority — url.Parse either
		// errors or returns an empty Host. The input is handed back untouched
		// rather than silently emptied, so the caller's later steps decide.
		"http://":   "http://",
		"://nohost": "://nohost",
		"https:// ": "https:// ",
		"foo://":    "foo://",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBareIPv6WithZone covers the zone-scoped-literal recognizer on its own,
// including the two rejection branches (no "%" at all, and a "%" on something
// that is not an IPv6 literal) that CanonicalHost can only reach indirectly.
func TestBareIPv6WithZone(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantOK   bool
	}{
		{"fe80::1%eth0", "fe80::1%eth0", true},
		{"2001:db8::1%eth0", "2001:db8::1%eth0", true},
		// No "%" — not a zone-scoped literal.
		{"fe80::1", "", false},
		{"reg.example.com", "", false},
		// "%" present, but the part before it is not an IP at all.
		{"host%zone", "", false},
		// "%" present and the prefix parses as an IP, but it is IPv4: the zone
		// form is IPv6-only, so this must be rejected rather than passed through.
		{"10.0.0.1%eth0", "", false},
	}
	for _, tc := range cases {
		host, ok := bareIPv6WithZone(tc.in)
		if host != tc.wantHost || ok != tc.wantOK {
			t.Errorf("bareIPv6WithZone(%q) = (%q, %v), want (%q, %v)",
				tc.in, host, ok, tc.wantHost, tc.wantOK)
		}
	}
}

func TestFoldHost(t *testing.T) {
	cases := map[string]string{
		"REG.Example.COM":  "reg.example.com",
		"reg.example.com.": "reg.example.com",
		"[::1]":            "::1",
		"[2001:DB8::1]":    "2001:db8::1",
		// IDNA lookup rejects underscores, so the host is kept as the
		// lowercased value rather than dropped or mangled.
		"Under_Score.Example.com": "under_score.example.com",
	}
	for in, want := range cases {
		if got := foldHost(in); got != want {
			t.Errorf("foldHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCanonicalHost_Idempotent guards the join invariant: applying the function
// twice equals applying it once, so re-canonicalizing a stored host never drifts.
func TestCanonicalHost_Idempotent(t *testing.T) {
	for _, in := range []string{
		"reg.example.com", "REG.Example.com:443", "https://reg.example.com:8080",
		"CAFÉ.Example.com",                 // IDN: punycode form must re-canonicalize stably
		"::1", "2001:db8::1", "[::1]:8080", // bare + bracketed IPv6
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
