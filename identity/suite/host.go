package suite

import (
	"net"
	"net/url"
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
// internationalized (Unicode) host to its punycode ASCII form, and drops a
// default port (:80/:443) while preserving any non-default port. IDN folding is
// best-effort: a host the IDNA "lookup" profile rejects (e.g. underscores) is
// left as the lowercased value, so the function never drops or mangles input.
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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Fold an internationalized host to punycode ASCII so a Unicode source
	// address matches a punycode-stored one. Best-effort: keep the lowercased
	// host if the lookup profile rejects it (the common ASCII host is unchanged).
	if ascii, err := idna.Lookup.ToASCII(host); err == nil && ascii != "" {
		host = ascii
	}
	if port == "" || port == "80" || port == "443" {
		return host
	}
	return net.JoinHostPort(host, port)
}
