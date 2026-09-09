// Package appcreds mints access tokens for app-owned (headless) integrations
// with Azure DevOps and GitHub: the Microsoft Entra client-credentials grant,
// the Entra workload-identity federated exchange, and GitHub App installation
// tokens.
//
// # Why this is here
//
// terraform-registry-backend and terraform-state-manager-backend implemented
// this mechanism independently and identically -- the same token endpoint, the
// same Azure DevOps resource id, the same hand-rolled RS256 app JWT -- and then
// drifted: state-manager grew workload identity federation and credential
// fingerprinting, registry grew an SSRF egress guard and a persistent token
// cache, and neither gained what the other had until someone noticed. Following
// the suite's "library owns mechanism, app owns policy" precedent (#206), the
// mechanism lives here and each app keeps its own storage schema, validation
// rules and API-calling layer.
//
// # What this package does NOT own
//
// Storage and caching policy. The two apps cache very differently on purpose:
// registry persists a token sealed and bound to its provider row, so it survives
// a restart and cannot be replayed against another row; state-manager keeps an
// in-memory map keyed by a credential fingerprint. Neither is wrong, so a Minter
// caches nothing at all and every Mint call performs a real exchange. Cache is
// an optional in-memory implementation for callers that want state-manager's
// shape; callers that persist tokens should keep doing that around this API.
//
// # No package-level state
//
// Everything a test needs to redirect -- the HTTP client, the Entra login host,
// the clock, the workload-identity credential factory -- is a field set through
// an Option. The originals used package vars with OverrideXForTest helpers,
// which is tolerable inside one application and is not tolerable in a library:
// two consumers in one process would overwrite each other's endpoint, and
// parallel tests in the same package would race.
package appcreds

import (
	"errors"
	"net/http"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

// AzureDevOpsResourceID is the fixed Microsoft Entra resource (application) id
// for Azure DevOps. Requesting "<id>/.default" yields a token carrying whatever
// Azure DevOps permissions the app registration has been granted.
//
// Exported because a caller that builds its own azcore credential still has to
// ask for the right audience, and a token minted for the wrong resource
// authenticates to nothing while looking perfectly well-formed.
const AzureDevOpsResourceID = "499b84ac-1321-427f-aa17-267ca6975798"

// DefaultEntraLoginBaseURL is the public Microsoft Entra login host. Sovereign
// and air-gapped clouds use a different one; see WithEntraLoginBaseURL.
const DefaultEntraLoginBaseURL = "https://login.microsoftonline.com"

// defaultHTTPTimeout bounds a token exchange. Minting sits in the request path
// of whatever needed the token, so it fails fast rather than holding the caller.
const defaultHTTPTimeout = 30 * time.Second

// strictGuard is the empty-allowlist httpsafe policy: public hosts reachable,
// private/loopback/link-local refused. Immutable and safe to share.
var strictGuard = httpsafe.MustGuard()

// ErrInvalidCreds is the class returned when credentials are missing a field the
// exchange requires. Callers turn this into a 400 rather than a 502: nothing was
// sent anywhere, so no upstream was at fault.
var ErrInvalidCreds = errors.New("appcreds: invalid credentials")

// Token is a minted access token and the instant it stops being valid.
//
// ExpiresAt is absolute, not a TTL, so a caller can cache it directly without
// having to remember when it was minted -- the bug that a "expires_in seconds"
// field invites every time it is stored.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// Expired reports whether the token is within margin of its expiry. A caller
// deciding whether to re-mint should use a margin of at least a few seconds so
// an in-flight request never races a hard expiry.
func (t Token) Expired(now time.Time, margin time.Duration) bool {
	if t.AccessToken == "" {
		return true
	}
	if t.ExpiresAt.IsZero() {
		// No expiry was reported. Treating it as immortal is the dangerous
		// reading; treat it as spent so the caller re-mints.
		//
		// The comparison below would reach the same answer -- the zero time is
		// year 1, which is never after now -- so no test can tell this branch
		// from its absence, and mutating it away survives. It is kept because
		// it states the intended reading of a zero expiry at the point someone
		// would otherwise have to derive it, and because a future change to the
		// comparison (a clock that can be zero, say) would silently invert it.
		return true
	}
	return !t.ExpiresAt.After(now.Add(margin))
}

// Creds is what every credential type in this package satisfies.
//
// Fingerprint exists so a cache key changes whenever any credential field
// changes, which makes rotation self-invalidating: the rotated credential simply
// hashes to a key nothing was ever stored under.
type Creds interface {
	Validate() error
	Fingerprint() string
}

// Minter performs credential exchanges. The zero value is not usable; build one
// with New.
//
// A Minter is safe for concurrent use, holds no mutable state, and caches
// nothing -- see the package comment.
type Minter struct {
	httpClient             *http.Client
	entraLoginBaseURL      string
	githubAPIBaseURL       string
	now                    func() time.Time
	credentialFactory      FederatedCredentialFactory
	certificateFactory     CertificateCredentialFactory
	managedIdentityFactory ManagedIdentityCredentialFactory
}

// Option configures a Minter.
type Option func(*Minter)

// WithHTTPClient supplies the client used for token exchanges.
//
// Prefer WithEgressGuard unless you have already built a guarded client: an
// unguarded client will follow an attacker-controlled login host straight into
// the internal network, and a token endpoint is exactly the kind of
// operator-configurable URL that makes that reachable.
func WithHTTPClient(c *http.Client) Option {
	return func(m *Minter) {
		if c != nil {
			m.httpClient = c
		}
	}
}

// WithEgressGuard builds the HTTP client from an httpsafe.Guard, so a token
// endpoint pointed at a private address is refused before the request leaves.
func WithEgressGuard(g *httpsafe.Guard) Option {
	return func(m *Minter) {
		if g != nil {
			m.httpClient = httpsafe.NewClient(defaultHTTPTimeout, g)
		}
	}
}

// WithEntraLoginBaseURL overrides the Entra login host -- a sovereign cloud
// (login.microsoftonline.us, login.partner.microsoftonline.cn) or a test server.
// Empty is ignored so a caller can pass an unset config value safely.
func WithEntraLoginBaseURL(u string) Option {
	return func(m *Minter) {
		if u != "" {
			m.entraLoginBaseURL = u
		}
	}
}

// WithGitHubAPIBaseURL overrides the GitHub API host, for GitHub Enterprise
// Server or a test server. Empty is ignored.
func WithGitHubAPIBaseURL(u string) Option {
	return func(m *Minter) {
		if u != "" {
			m.githubAPIBaseURL = u
		}
	}
}

// WithClock replaces time.Now, for tests that assert on expiry arithmetic.
func WithClock(now func() time.Time) Option {
	return func(m *Minter) {
		if now != nil {
			m.now = now
		}
	}
}

// WithFederatedCredentialFactory substitutes how a workload-identity credential
// is built. Its only production use is the default; tests use it to mint without
// a platform that projects a token.
func WithFederatedCredentialFactory(f FederatedCredentialFactory) Option {
	return func(m *Minter) {
		if f != nil {
			m.credentialFactory = f
		}
	}
}

// WithCertificateCredentialFactory substitutes how a certificate credential is
// built. Its only production use is the default; tests use it to mint without
// an app registration that trusts the test certificate.
func WithCertificateCredentialFactory(f CertificateCredentialFactory) Option {
	return func(m *Minter) {
		if f != nil {
			m.certificateFactory = f
		}
	}
}

// WithManagedIdentityCredentialFactory substitutes how a managed-identity
// credential is built. Its only production use is the default; tests use it to
// mint without running on Azure compute.
func WithManagedIdentityCredentialFactory(f ManagedIdentityCredentialFactory) Option {
	return func(m *Minter) {
		if f != nil {
			m.managedIdentityFactory = f
		}
	}
}

// New builds a Minter.
//
// The default HTTP client is GUARDED by the strict httpsafe policy: private,
// loopback and link-local targets are refused, public ones are allowed. That is
// the right default for this package -- every endpoint it talks to
// (login.microsoftonline.com, api.github.com, their sovereign equivalents) is
// public, so the strict policy costs a correct deployment nothing while
// refusing to send a client secret to an internal address.
//
// A caller that must reach a private host -- GitHub Enterprise Server on an
// internal network, a test server on loopback -- passes WithEgressGuard with
// that host allow-listed. Defaulting to unguarded and asking callers to opt IN
// is how the same egress fix reached one copy of a hand-duplicated client and
// not the other two.
func New(opts ...Option) *Minter {
	m := &Minter{
		httpClient:             httpsafe.NewClient(defaultHTTPTimeout, strictGuard),
		entraLoginBaseURL:      DefaultEntraLoginBaseURL,
		githubAPIBaseURL:       DefaultGitHubAPIBaseURL,
		now:                    time.Now,
		credentialFactory:      defaultFederatedCredentialFactory,
		certificateFactory:     defaultCertificateCredentialFactory,
		managedIdentityFactory: defaultManagedIdentityCredentialFactory,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// errNoMinter is returned by a CachedMinter built without one, which is a
// programming error rather than a runtime condition -- surfaced as an error
// instead of a nil dereference so it fails at the call site that made it.
var errNoMinter = errors.New("appcreds: CachedMinter has no Minter")
