// Package tenantscope resolves, once per request, the set of organizations a
// caller is allowed to reach.
//
// It exists here rather than in an application because it was written twice.
// terraform-registry-backend and terraform-state-manager-backend each carry an
// internal/tenantscope, neither imports the other, and by the time this package
// was written they had already diverged into two different authority models
// under one type name — see sethbacon/terraform-suite-identity#206, which sets
// the rule this package follows: THE LIBRARY OWNS MECHANISM, THE APP OWNS POLICY.
//
// # What is mechanism, and what is policy
//
// Mechanism is the shape of the answer and the order the questions are asked in:
// no principal means no scope; a platform administrator reaches everything; an
// organization-bound credential reaches its organization; everyone else reaches
// the organizations their memberships qualify them for; and a lookup that FAILED
// is an error rather than an empty answer. That is identical in both apps and it
// is what this package is.
//
// Everything that decides the CONTENT of those answers is policy, injected:
//
//	Memberships           which memberships qualify, under whose role source
//	PlatformAdmins        what makes someone platform-wide
//	AdminsApplyToAPIKeys  whether a minted credential can be platform-wide
//	KeyBindsOrganization  whether a key's own organization is an authority
//
// Those four are not configurability for its own sake. Each one is a place where
// the two existing copies genuinely disagree, verified in their code rather than
// assumed, and collapsing any of them to a single behaviour would silently break
// one app. Naming them is the point: a difference that has to be passed in is a
// difference somebody had to decide.
//
// # The two disagreements, and why neither side is wrong
//
// PLATFORM ADMIN. In terraform-registry, `admin` in a session IS the
// platform-wide wildcard, so reading it off the request is reading
// platform-adminness. In terraform-state-manager it is not: `admin` is granted
// per organization through an admin-bearing role template and merely SURFACES
// flat, so deriving platform-adminness from it would hand every
// single-organization admin the entire deployment. Hence an interface: registry
// supplies a per-request implementation over the flat scope list, state-manager
// supplies its live platform_admins carrier.
//
// API KEYS. terraform-registry binds a key to the organization named on it,
// because there that column is set at creation and is authoritative. It added
// that branch deliberately (its #719) after a USERLESS organization service key
// — api_keys.user_id IS NULL, the ordinary shape for CI automation — was found
// to have no memberships to resolve, and so received empty lists and refusals on
// its OWN organization.
//
// terraform-state-manager must NOT do that today, and the reason is a fact about
// its data rather than a difference of opinion: its key minting stamps every key
// with the deployment's default organization whoever owns it, so the column
// carries no information. Binding to it would place every key in the default
// organization. The same branch is therefore correct in one app and wrong in the
// other, and it stops being wrong there once that stamping is fixed
// (sethbacon/terraform-state-manager-backend#436).
//
// KeyBindsOrganization is safe to enable only where a key's organization is
// written from the acting organization at creation. If it is a default, leave it
// off — and note that leaving it off leaves the userless-key case unsolved,
// which is what registry's #719 was about.
//
// # One deliberate difference from both copies: a principal comes first
//
// terraform-registry's Resolve reads platform-adminness off the request BEFORE
// it looks for a user id, so a credential carrying `admin` with no principal at
// all — an mTLS client, whose subject is not an identity user — resolves as
// platform-wide there. This package requires a principal first, so it does not.
//
// That is a behaviour change for registry and it is intentional rather than an
// oversight. A platform-wide principal with no identity is unattributable by
// construction: nothing can say who exercised it, which is the property
// identity/auditoutbox exists to preserve and which #876 already tracks as "mTLS
// as an undesigned third source of admin". Adopting this package should be the
// moment that is decided on purpose, not a diff nobody read.
//
// If a deployment genuinely needs a principal-less administrator, the honest
// shape is an identity for it — not an absence of one.
//
// # The zero value permits nothing
//
// Every failure path returns it. No principal, no resolver wired, a principal
// with no qualifying membership: all select nothing rather than everything. The
// one thing NOT reported as an empty scope is a lookup that FAILED — that comes
// back as an error, so a handler answers 500 instead of quietly serving a caller
// an empty world, or, if some later caller inverts the test, everyone else's.
//
// # No HTTP framework
//
// This module has no web-framework dependency and does not acquire one here.
// Callers extract Principal from their own request context and pass it in, the
// same way identity/platformadmin takes a context.Context and a user id.
package tenantscope

import (
	"context"
	"errors"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// ErrAdminsNotConfigured, returned by a PlatformAdmins implementation directly
// or wrapped, means "no carrier is wired here" rather than "this principal is
// not an administrator". Resolve treats it as the former and falls through to
// memberships, because a carrier that is absent WITHHOLDS authority rather than
// granting or denying it.
//
// platformadmin.ErrNotConfigured is accepted identically, so the carrier in this
// module satisfies the contract without an adapter. An application carrying its
// own sentinel should wrap this one.
var ErrAdminsNotConfigured = errors.New("tenantscope: platform-admin carrier is not configured")

// Memberships resolves the organizations in which a principal holds a scope.
//
// An interface and not a concrete repository, for a test reason before an
// abstraction one: the failure this package must get right is a membership
// lookup that ERRORS, and a real repository can only be made to error by taking
// its database away. A one-method seam makes that case a table row.
type Memberships interface {
	OrgScopeForUser(ctx context.Context, userID, required string, rwPairs auth.ReadWritePairs) (store.OrgScope, error)
}

// PlatformAdmins answers whether a principal holds platform-wide authority right
// now.
//
// LIVE, NOT CACHED, where the application's model makes it a lookup: a row
// removed from a platform-admin table should stop elevating on the NEXT request
// rather than whenever the holder's longest session expires. An application
// whose platform-adminness is a claim already present on the request satisfies
// this with a per-request value; that is equally valid and considerably cheaper.
type PlatformAdmins interface {
	IsPlatformAdmin(ctx context.Context, userID string) (bool, error)
}

// PlatformAdminFunc adapts a function to PlatformAdmins, for the per-request
// case where the answer is already on the request and no lookup is needed.
type PlatformAdminFunc func(ctx context.Context, userID string) (bool, error)

// IsPlatformAdmin implements PlatformAdmins.
func (f PlatformAdminFunc) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	return f(ctx, userID)
}

// Credential names how a request authenticated, because the answer changes what
// tenancy it may be resolved to.
//
// It is an enumeration and not a bool for the reason identity's insecure-zero
// class guard exists: the zero value has to be the restrictive answer. A
// Principal a caller forgot to fill in must not be treated as a session and
// become eligible for platform elevation. CredentialUnspecified is therefore
// handled exactly as an API key is — never elevated unless the resolver opts in
// — and it binds to no organization, because it names no key.
type Credential int

const (
	// CredentialUnspecified is the zero value: the caller did not say. Treated
	// as the narrowest reading available.
	CredentialUnspecified Credential = iota

	// CredentialSession is an interactive principal — a session cookie or a
	// bearer token carrying user claims.
	CredentialSession

	// CredentialAPIKey is a minted, long-lived credential.
	CredentialAPIKey
)

// String implements fmt.Stringer for logs and test failures.
func (c Credential) String() string {
	switch c {
	case CredentialSession:
		return "session"
	case CredentialAPIKey:
		return "apikey"
	default:
		return "unspecified"
	}
}

// Principal is what the application extracted from its own request, so that this
// package needs no knowledge of how the request was made.
type Principal struct {
	// UserID is the authenticated user. Empty means there is no principal —
	// an unauthenticated request, or a credential like mTLS whose subject is
	// not an identity user and has no memberships to resolve.
	UserID string

	// Credential is how this request authenticated. The zero value is the
	// restrictive reading; see Credential.
	Credential Credential

	// KeyOrgID is the organization named on an API key, read only when
	// Credential is CredentialAPIKey and the resolver has
	// KeyBindsOrganization set. Empty means the key carries no binding — a
	// legacy row — and the owner's memberships decide instead.
	KeyOrgID string
}

// Scope is the set of organizations a request may reach.
//
// The zero value denies everything, which is why every failure path returns it.
type Scope struct {
	// PlatformAdmin reaches every organization, so OrgIDs is not consulted.
	PlatformAdmin bool

	// OrgIDs is the set this request may reach. Order is not significant.
	OrgIDs []string
}

// Permits reports whether orgID is inside this scope.
func (s Scope) Permits(orgID string) bool {
	if s.PlatformAdmin {
		return true
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		// A row with no organization belongs to no tenant, not to every
		// tenant. Reporting it as permitted is how an unstamped row becomes
		// visible to everybody at once.
		return false
	}
	for _, id := range s.OrgIDs {
		if id == orgID {
			return true
		}
	}
	return false
}

// PermitsPtr is Permits for a nullable column. A NULL organization is permitted
// to nobody but a platform administrator, matching Permits' treatment of "".
func (s Scope) PermitsPtr(orgID *string) bool {
	if s.PlatformAdmin {
		return true
	}
	if orgID == nil {
		return false
	}
	return s.Permits(*orgID)
}

// Empty reports a scope that reaches nothing. It is deliberately independent of
// how the scope came to be empty: "resolved, and permits nothing" is a real
// answer, and it is the caller's job to keep it distinct from "never resolved".
func (s Scope) Empty() bool { return !s.PlatformAdmin && len(s.OrgIDs) == 0 }

// Resolver carries an application's tenancy policy. The zero value resolves
// nothing to anything, which is the correct behaviour for a resolver nobody
// configured.
type Resolver struct {
	// Memberships qualifies a principal's organizations. Nil denies: a
	// resolver without one cannot verify anything, and returning an
	// unfiltered result would be the defect this package exists to close.
	Memberships Memberships

	// Admins decides platform-wide authority. Nil means the application has
	// no platform-wide principal, which is a legitimate model — not an error.
	Admins PlatformAdmins

	// ReadWritePairs is the application's write-implies-read table, passed to
	// Memberships. It is policy: which scope satisfies which is an
	// application's decision about its own vocabulary.
	ReadWritePairs auth.ReadWritePairs

	// AdminsApplyToAPIKeys allows a key-authenticated request to be resolved
	// as platform-wide. Off is the narrower reading and the better default: a
	// credential minted for automation inheriting its owner's platform
	// authority is a privilege escalation nobody asked for at mint time.
	AdminsApplyToAPIKeys bool

	// KeyBindsOrganization treats the organization named on an API key as
	// authoritative for that key. Enable ONLY where that column is written
	// from the acting organization at creation; see the package comment.
	KeyBindsOrganization bool
}

// Resolve returns the organizations this request may reach.
//
// The order is the mechanism, and it is the same in both applications:
//
//  1. No principal, no scope. Nothing to look up, and the empty scope is the
//     honest answer rather than a failure.
//  2. Platform administrators reach everything, so nothing further is asked.
//  3. An organization-bound credential reaches its organization.
//  4. Everyone else reaches what their memberships qualify them for.
//
// A lookup that fails returns the zero scope WITH the error, so a caller that
// ignores the error still selects nothing.
func (r Resolver) Resolve(ctx context.Context, p Principal, required string) (Scope, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	userID := strings.TrimSpace(p.UserID)
	if userID == "" {
		return Scope{}, nil
	}

	if r.Admins != nil && (p.Credential == CredentialSession || r.AdminsApplyToAPIKeys) {
		isAdmin, err := r.Admins.IsPlatformAdmin(ctx, userID)
		switch {
		case errors.Is(err, ErrAdminsNotConfigured), errors.Is(err, platformadmin.ErrNotConfigured):
			// A carrier that is not there withholds authority rather than
			// granting it. Fall through to memberships.
		case err != nil:
			// An authority question that did not resolve is not a completed
			// "no". Return the zero scope WITH the error.
			return Scope{}, err
		case isAdmin:
			return Scope{PlatformAdmin: true}, nil
		}
	}

	if p.Credential == CredentialAPIKey && r.KeyBindsOrganization {
		if orgID := strings.TrimSpace(p.KeyOrgID); orgID != "" {
			return Scope{OrgIDs: []string{orgID}}, nil
		}
		// A key with no binding is a legacy row; its owner's memberships
		// decide, which is what the branch below does.
	}

	if r.Memberships == nil {
		return Scope{}, nil
	}

	orgScope, err := r.Memberships.OrgScopeForUser(ctx, userID, required, r.ReadWritePairs)
	if err != nil {
		return Scope{}, err
	}
	return Scope{OrgIDs: orgScope.OrganizationIDs()}, nil
}
