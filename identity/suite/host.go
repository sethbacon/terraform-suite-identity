package suite

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalHost normalizes a registry host so the suite "Consumed by" join
// compares like-for-like across apps. The host captured from a Terraform module
// source address, the registry's service-discovery host, and the registry's own
// public host can differ only in case, a default port, a trailing FQDN dot, an
// accidental scheme prefix, or Unicode (IDN) vs punycode encoding; folding those
// away makes the exact-match join robust to such variants.
//
// It strips any scheme, lowercases the host, removes a trailing dot, folds an
// internationalized (Unicode) host to its punycode ASCII form, unwraps IPv6
// brackets, canonicalizes the port numerically (so :080 folds to :80), and drops
// a default port (:80/:443) while preserving any non-default port. IDN folding is
// best-effort: a host the IDNA "lookup" profile rejects (e.g. underscores) is
// left as the lowercased value, so the function never drops or mangles input.
//
// Userinfo ("@") is never legitimate for a bare host-identity join key — a
// hostname can't contain "@" — so any input carrying it is rejected outright
// (returns ""), regardless of colon count or whether a scheme is present.
//
// Note: :80 and :443 both fold to the bare host by design — the join key is a
// host identity, not an origin, and the scheme is intentionally stripped.
// Because this folding intentionally discards scheme, any code that extends
// cross-app trust based on CanonicalHost equality (e.g. the suite discovery
// client) MUST independently enforce HTTPS on the connection itself rather
// than relying on CanonicalHost equality alone — see the fail-closed-by-
// default hardening of the discovery client's constructor tracked under
// issue #62 (PR #99).
func CanonicalHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// A hostname can never legitimately contain "@" (the URL userinfo
	// delimiter). Reject any input carrying it outright, before any of the
	// scheme/colon handling below: url.Parse would otherwise silently strip
	// userinfo out of a full URL's Host component (e.g. "user@host:1234" has
	// exactly one colon, so net.SplitHostPort happily — and wrongly — treats
	// "user@host" as the whole host), and a naive fallback could do the same
	// for the no-colon and multi-colon shapes. Checking once, up front, for
	// literal "@" closes the whole class in one place instead of only the
	// multi-colon sub-shape.
	if strings.Contains(raw, "@") {
		return ""
	}
	// If a scheme slipped in (e.g. the value came from a full URL), keep only
	// the authority component.
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	var host, port string
	if !strings.Contains(raw, ":") {
		// Fast path: the overwhelmingly common case is a bare hostname with no
		// port and no colon at all. net.SplitHostPort always errors on this
		// shape (there's no port to split off), so historically the code fell
		// back to treating the whole string as the host — which is correct
		// here and must not change.
		host = raw
	} else if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	} else if zoned, ok := bareIPv6WithZone(raw); ok {
		// raw is a bare (unbracketed) IPv6 literal carrying an RFC 4007 zone ID
		// (e.g. "fe80::1%eth0"). net.SplitHostPort demands brackets around an
		// IPv6 host and errors on this shape even though there's no port to
		// recover, and net/url's authority parser also can't be used to
		// recover it (it misreads the "%zone" suffix as an invalid port).
		// Handled directly via net.ParseIP so this legitimate, if rare,
		// address form round-trips unchanged instead of being rejected.
		host = zoned
	} else {
		// raw contains a colon, but it isn't a clean "host:port" or
		// "[ipv6]:port" that net.SplitHostPort accepts, and it isn't a bare
		// zone-scoped IPv6 literal either. This is either a shape net/url's
		// authority parser can still recover cleanly (e.g. a bare, unbracketed
		// IPv6 literal without a zone) or genuinely malformed junk
		// ("host:443:extra") — never legitimate for a bare host-identity join
		// key. Recover via url.Parse against a synthesized authority; anything
		// that doesn't come back clean (parse failure, empty host) is rejected
		// outright (returns "") rather than silently passed through as
		// garbage. (Userinfo is already rejected above, so u.User is never
		// non-nil here.)
		u, err := url.Parse("//" + raw)
		if err != nil || u.Host == "" {
			return ""
		}
		raw = u.Host
		if h, p, err := net.SplitHostPort(raw); err == nil {
			host, port = h, p
		} else {
			host = raw
		}
	}
	// Unwrap IPv6 brackets so bracketed and unbracketed spellings of the same
	// literal fold together (e.g. "[::1]" and "[::1]:443" both → "::1").
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Fold an internationalized host to punycode ASCII so a Unicode source
	// address matches a punycode-stored one. Best-effort: keep the lowercased
	// host if the lookup profile rejects it (the common ASCII host is unchanged).
	if ascii, err := idna.Lookup.ToASCII(host); err == nil && ascii != "" {
		host = ascii
	}
	// Canonicalize the port numerically so equivalent spellings (":80", ":080")
	// fold identically: drop default ports, and re-emit any other port without
	// leading zeros.
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			if n == 80 || n == 443 {
				port = ""
			} else {
				port = strconv.Itoa(n)
			}
		}
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// bareIPv6WithZone recognizes a bare (unbracketed) IPv6 literal that carries an
// RFC 4007 zone ID in the "<addr>%<zone>" form (e.g. "fe80::1%eth0"), returning
// it unchanged with ok=true. Returns ok=false for anything else, including a
// zone-less bare IPv6 literal (net/url's authority parser already recovers
// those cleanly) and non-IPv6 input.
func bareIPv6WithZone(raw string) (host string, ok bool) {
	i := strings.IndexByte(raw, '%')
	if i < 0 {
		return "", false
	}
	if ip := net.ParseIP(raw[:i]); ip == nil || !strings.Contains(raw[:i], ":") {
		return "", false
	}
	return raw, true
}
