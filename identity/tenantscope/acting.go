package tenantscope

import (
	"errors"
	"fmt"
	"strings"
)

// ActingOrganizationHeader is the canonical request header carrying the
// organization a caller has selected.
//
// It is named here rather than in either application because both must agree.
// Two applications reading two header names is the same defect this package was
// created to close, one layer up: a frontend shared between them
// (@4cloudguru/cloud-suite-ui) can only send one.
//
// The value is a CLAIM, never an authority. It arrives from the client and is
// worth exactly nothing until ActingOrganization has checked it against a Scope
// the server resolved. A handler that reads this header and uses it directly has
// reintroduced the tenancy bypass it was added to prevent.
const ActingOrganizationHeader = "X-Organization-Id"

var (
	// ErrNoActingOrganization: the caller belongs to no organization that
	// qualifies, so there is nothing to act as. A write must be refused.
	ErrNoActingOrganization = errors.New("tenantscope: caller has no organization to act in")

	// ErrAmbiguousActingOrganization: the caller could act in more than one
	// and did not say which. The request must name one; it is not the
	// server's place to pick.
	ErrAmbiguousActingOrganization = errors.New("tenantscope: caller must name the organization to act in")

	// ErrActingOrganizationNotPermitted: the caller named an organization
	// their scope does not reach. This is the check that makes the header
	// safe, and it is the one a handler skips when it reads the header
	// directly.
	ErrActingOrganizationNotPermitted = errors.New("tenantscope: caller may not act in the named organization")
)

// ActingOrganization resolves the single organization a WRITE belongs to.
//
// # Why a write needs this and a read does not
//
// Scope answers "which organizations may this caller reach?" — a set, and the
// right answer for a read. It is not an answer for a write at all: a caller who
// belongs to three organizations creating a state source is creating it in
// exactly one of them, and a set does not say which.
//
// Choosing implicitly is the thing to avoid, and each obvious shortcut fails a
// different way. Taking the first element makes the choice depend on an ordering
// nobody guarantees and shows the user nothing. Falling back to a deployment
// default is precisely the behaviour that leaves every row owned by one
// organization — see sethbacon/terraform-state-manager-backend#436, where nine
// tables took a column DEFAULT for exactly this reason and the partition turned
// out to be inert. Refusing whenever the caller belongs to more than one turns
// the common case into an error AND hides the bug from single-membership
// testing, which is the worst of both.
//
// So: the request names one, the server verifies it, and the only implicit case
// is the one that cannot be wrong.
//
// # The rules
//
//	selected names an organization the scope reaches   -> that organization
//	selected names one it does not                     -> ErrActingOrganizationNotPermitted
//	selected is empty, scope reaches exactly one        -> that one
//	selected is empty, scope reaches none               -> ErrNoActingOrganization
//	selected is empty, scope reaches several            -> ErrAmbiguousActingOrganization
//	selected is empty, caller is a platform admin       -> ErrAmbiguousActingOrganization
//
// A caller in exactly one organization never has to send the header, so a
// single-organization deployment needs no picker and nothing about it changes.
//
// A platform administrator must always name one. Reaching every organization is
// not the same as belonging to one, and there is no answer to "which of them did
// you mean" that the server can invent.
//
// # What this does NOT check
//
// That the organization EXISTS. For an ordinary caller the question does not
// arise: the scope was resolved from memberships, and there are no memberships
// of an organization that is not there. For a platform administrator it does
// arise, because Permits returns true for any id at all — so an application that
// lets administrators write on behalf of a tenant should confirm the id resolves
// before stamping rows with it. This package will not do it silently, because it
// would mean an identity lookup on every write, and because 000033-style
// partitions deliberately carry no foreign key to identity (which may be a
// different database entirely) — so "exists" is a question only the application
// knows how to ask.
func (r Resolver) ActingOrganization(scope Scope, selected string) (string, error) {
	selected = strings.TrimSpace(selected)

	if selected != "" {
		if !scope.Permits(selected) {
			// Deliberately does not name what the caller COULD have chosen.
			// A refusal that lists the organizations a caller may act in is
			// fine; one that confirms whether the id they guessed exists
			// somewhere in the deployment is a disclosure, and this function
			// cannot tell the two apart.
			return "", fmt.Errorf("%w", ErrActingOrganizationNotPermitted)
		}
		return selected, nil
	}

	if scope.PlatformAdmin {
		return "", fmt.Errorf("%w: a platform administrator reaches every organization and belongs to none, "+
			"so the request must name one", ErrAmbiguousActingOrganization)
	}

	switch len(scope.OrgIDs) {
	case 0:
		return "", fmt.Errorf("%w", ErrNoActingOrganization)
	case 1:
		return scope.OrgIDs[0], nil
	default:
		return "", fmt.Errorf("%w: the caller reaches %d organizations", ErrAmbiguousActingOrganization, len(scope.OrgIDs))
	}
}
