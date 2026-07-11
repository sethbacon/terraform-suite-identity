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
// Note: :80 and :443 both fold to the bare host by design — the join key is a
// host identity, not an origin, and the scheme is intentionally stripped.
func CanonicalHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// If a scheme slipped in (e.g. the value came from a full URL), keep only
	// the authority component.
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	host, port := raw, ""
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
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
