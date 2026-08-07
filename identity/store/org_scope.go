// org_scope.go defines OrgScope, the mandatory tenant constraint carried by
// every accessor in this package that reads or mutates a row of an
// organization-owned table.
//
// Why a type and not just another optional field on a filter struct:
// organization ownership is a property of the SCHEMA (api_keys,
// organization_members and organizations all carry or are an organization id),
// and the defect this closes (terraform-registry #718/#719, and this module's
// own #138/#160/#161/#162) is not "one query forgot its WHERE clause" but a
// CLASS — resource x access-axis. The audit-log list query grew an optional
// OrganizationID filter and one consumer route learned to set it, while the
// by-id read and the export stream over the SAME table kept no tenant predicate
// at all. An optional field makes the unscoped query the DEFAULT, so every new
// access axis re-opens the hole and every fix has to be re-applied per call
// site.
//
// OrgScope inverts that. It is a REQUIRED parameter of every scoped accessor,
// and its ZERO VALUE DENIES EVERYTHING. A caller who forgets to think about
// tenancy gets no rows, not every tenant's rows. Reaching across organizations
// remains possible but must be spelled out with OrgScopeAllOrganizations(),
// which is greppable and reviewable in a way that an absent filter is not.
//
// # One type, not one per table
//
// v0.21.0 shipped this shape as AuditScope, named for the single table it was
// applied to, with an UNEXPORTED predicate builder. That naming and that
// visibility are why the fix did not fan out: the remedy the other tables were
// told to copy was, literally, uncopyable — a consumer could not apply the
// predicate to its own organization-owned tables (terraform-registry's modules,
// providers and SCM providers; terraform-state-manager's states and sources),
// so both consumers hand-rolled a filter per table instead. v0.25.0 renames the
// type to OrgScope, applies it to every organization-owned accessor in the
// package, and EXPORTS the predicate builder (OrgScope.SQL) so a consumer can
// scope its own tables with the same expression this package scopes its own
// with.
//
// # The three things a consumer needs, all exported
//
//  1. OrganizationRepository.OrgScopeForUser — the RESOLVER. Both consumers had
//     written the identical membership-to-scope resolution over this module's
//     own tables (terraform-registry's internal/tenantscope.Resolve and
//     terraform-state-manager's api.adminOrgSet), each loading
//     GetUserMemberships and filtering on RoleTemplateScopes. A parameter type
//     without a resolver would have produced a third copy.
//  2. OrgScope.SQL — the PREDICATE BUILDER, for a consumer's own tables.
//  3. OrgScope.PermitsOrganization — the in-memory check, for rows a consumer
//     has already loaded.
package store

import (
	"context"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// OrgScope constrains an accessor to a set of organizations.
//
// Construct it with OrgScopeOrganizations (an allowlist),
// OrgScopeOrganizationsAndUnowned (an allowlist that also admits rows with no
// owning organization) or OrgScopeAllOrganizations (an explicit, deliberate
// platform-wide access). The zero value permits nothing: it is the fail-closed
// default for a caller that has not decided.
type OrgScope struct {
	orgIDs []string
	all    bool
	// unowned widens the scope to rows whose organization_id is NULL — or, on
	// the users table, to users with no organization membership at all. It is a
	// separate axis from orgIDs, not a member of it, because "no owner" is not
	// an organization anyone can be a member of — see
	// OrgScopeOrganizationsAndUnowned for when that is the right answer.
	unowned bool
}

// OrgScopeOrganizations limits an accessor to rows owned by the given
// organizations. Passing no ids yields a scope that matches nothing, which is
// the correct answer for a principal with no memberships — not a reason to
// widen the query.
//
// Ids are deduplicated and SORTED, so the argument the predicate binds is a
// function of the SET and not of the order a caller happened to iterate a map
// in. That keeps query arguments stable across calls and across replicas, and
// it removes the hand-written sort a consumer building a scope out of a map
// otherwise has to remember (terraform-state-manager's callerAuditScope has
// one, with a comment explaining why).
func OrgScopeOrganizations(orgIDs ...string) OrgScope {
	cleaned := make([]string, 0, len(orgIDs))
	seen := make(map[string]struct{}, len(orgIDs))
	for _, id := range orgIDs {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		cleaned = append(cleaned, id)
	}
	sort.Strings(cleaned)
	return OrgScope{orgIDs: cleaned}
}

// OrgScopeOrganizationsAndUnowned limits an accessor to rows owned by the given
// organizations AND to rows with no owning organization at all
// (organization_id IS NULL; on the users table, a user with no membership row).
//
// This variant exists for consumers whose data mixes org-owned records with
// genuinely platform-level ones. terraform-state-manager writes logins,
// state-file and source actions with a NULL organization_id by design, so
// OrgScopeOrganizations would hide from an organization admin the very events
// they are the intended reviewer of, and OrgScopeAllOrganizations would hand
// them every other tenant's rows. Without a third option a consumer's only
// choices are leak-everything or lose-platform-events, and the predictable
// outcome is that it picks the first one and this class reopens there.
//
// It is deliberately NOT the default: an unowned row is unowned because nobody
// asserted a tenant for it, and on a table where NULL means "not assigned yet"
// rather than "platform-level" — terraform-registry's mirror configurations,
// for instance — treating it as visible is the leak. The consumer decides which
// meaning its own NULLs carry, at the call site, in a greppable form.
//
// Passing no ids is legitimate here and yields "unowned rows only".
func OrgScopeOrganizationsAndUnowned(orgIDs ...string) OrgScope {
	return OrgScopeOrganizations(orgIDs...).WithUnowned()
}

// WithUnowned returns a copy of the scope widened to also admit rows with no
// owning organization.
//
// It exists so a scope obtained from OrgScopeForUser — which cannot know what a
// consumer's NULL owners mean — can be widened at the call site without the
// consumer having to unpack the scope back into an id slice and rebuild it.
// That unpack-and-rebuild is exactly what terraform-state-manager's
// callerAuditScope does today.
//
// Widening the platform-wide scope is a no-op: it already admits everything.
func (s OrgScope) WithUnowned() OrgScope {
	s.unowned = true
	return s
}

// OrgScopeAllOrganizations returns a scope that reaches every organization.
// Reserved for platform-wide operators and for genuinely org-less paths
// (authentication, retention sweeps, health checks, bootstrap). It exists so
// that "reach everything" is an explicit, auditable decision at the call site
// rather than the consequence of an omitted filter.
func OrgScopeAllOrganizations() OrgScope {
	return OrgScope{all: true}
}

// IsAllOrganizations reports whether the scope is the explicit platform-wide
// scope.
func (s OrgScope) IsAllOrganizations() bool { return s.all }

// IncludesUnowned reports whether the scope also selects rows with no owning
// organization.
func (s OrgScope) IncludesUnowned() bool { return s.all || s.unowned }

// MatchesNothing reports whether the scope can never select a row — the
// fail-closed zero value, or an empty organization allowlist that does not also
// admit unowned rows.
func (s OrgScope) MatchesNothing() bool {
	return !s.all && !s.unowned && len(s.orgIDs) == 0
}

// OrganizationIDs returns a copy of the scope's organization allowlist, sorted.
func (s OrgScope) OrganizationIDs() []string {
	out := make([]string, len(s.orgIDs))
	copy(out, s.orgIDs)
	return out
}

// PermitsOrganization reports whether a row owned by orgID (empty meaning an
// org-less row) is inside the scope. Org-less rows are visible only to the
// platform-wide scope or to a scope built with OrgScopeOrganizationsAndUnowned:
// an empty owner cannot be matched against any membership, so admitting it is
// always an explicit decision.
func (s OrgScope) PermitsOrganization(orgID string) bool {
	if s.all {
		return true
	}
	if orgID == "" {
		return s.unowned
	}
	for _, id := range s.orgIDs {
		if id == orgID {
			return true
		}
	}
	return false
}

// String renders the scope for logs and test failures without exposing the full
// id list.
func (s OrgScope) String() string {
	if s.all {
		return "OrgScope(all-organizations)"
	}
	if s.unowned {
		return fmt.Sprintf("OrgScope(%d organization(s) + unowned)", len(s.orgIDs))
	}
	return fmt.Sprintf("OrgScope(%d organization(s))", len(s.orgIDs))
}

// SQL returns the boolean expression that constrains a query to the scope, and
// the arguments that expression binds.
//
// This is the exported form of the predicate every scoped accessor in this
// package applies to its own tables, published so a CONSUMER can apply the same
// constraint to its own organization-owned tables — terraform-registry's
// modules, providers and SCM providers, terraform-state-manager's states and
// sources. Until v0.25.0 it was unexported, which is the mechanical reason the
// v0.21.0 fix stopped at one table: the one remedy shape the consumers were
// told to copy was not reachable from outside the package, so each of them
// hand-rolled a filter per table instead, and the hand-rolled ones do not agree
// with each other about NULL owners or about the empty scope.
//
// # Contract
//
//   - column is a COLUMN REFERENCE the caller controls (e.g.
//     "al.organization_id"). It is interpolated into the returned string, so it
//     must never carry user-supplied text. Scope values never are: they travel
//     as arguments.
//   - paramIndex is the 1-based position the FIRST returned argument will occupy
//     in the caller's argument list — i.e. len(args)+1 at the moment of the
//     call.
//   - The returned args slice has length 0 or 1. Append it unconditionally
//     (args = append(args, scopeArgs...)); length 0 is what a predicate binding
//     no placeholder looks like, and appending a slice handles both cases
//     without a nil check a caller can get wrong.
//   - The returned clause is NEVER EMPTY and is always a self-contained boolean
//     expression, safe to drop into a WHERE directly ("WHERE " + clause) or to
//     compose ("... AND " + clause).
//
// The never-empty guarantee is the load-bearing part. The unexported form
// returned ("", nil) for the platform-wide scope, so a caller that appended the
// result to a query string produced an unfiltered statement for one scope value
// and a filtered one for the others — the fail-open shape the type exists to
// prevent. Now "reach everything" is the literal TRUE and "reach nothing" is
// the literal FALSE, and both are visible in the statement the database
// receives and in any log that captures it.
func (s OrgScope) SQL(column string, paramIndex int) (string, []interface{}) {
	if s.all {
		return "TRUE", nil
	}
	if len(s.orgIDs) == 0 {
		if s.unowned {
			return fmt.Sprintf("%s IS NULL", column), nil
		}
		return "FALSE", nil
	}
	if s.unowned {
		return fmt.Sprintf("(%s = ANY($%d) OR %s IS NULL)", column, paramIndex, column),
			[]interface{}{pq.Array(s.orgIDs)}
	}
	return fmt.Sprintf("%s = ANY($%d)", column, paramIndex), []interface{}{pq.Array(s.orgIDs)}
}

// membershipSQL returns the boolean expression that constrains a USERS-table row
// to the scope, and the arguments it binds.
//
// The users table carries no organization_id: a user is reachable from an
// organization only through organization_members, so the tenant predicate for a
// user is an EXISTS over that join table rather than a column comparison.
//
// This helper is deliberately UNEXPORTED, unlike SQL: it hard-codes this
// module's own organization_members table, so it is not a reusable shape for a
// consumer's schema. A consumer scoping its own join table calls SQL against
// its own column, inside its own EXISTS.
//
// userColumn is the reference to the users-table id being constrained
// ("users.id" inside an UPDATE/DELETE, "u.id" inside an aliased SELECT).
//
// The unowned axis here means "a user with no organization membership at all".
// That is not a widening invented for this file: it is the case
// terraform-state-manager's requireSharedOrgAdminWithTargetUser already lets
// through by hand ("no organization ties for this user at all — nothing
// cross-tenant to protect against"), and expressing it as the same unowned axis
// the audit reads already use is what lets that consumer keep its behaviour
// while stating it at the call site instead of in a middleware branch.
func (s OrgScope) membershipSQL(userColumn string, paramIndex int) (string, []interface{}) {
	if s.all {
		return "TRUE", nil
	}

	notAMember := fmt.Sprintf(
		"NOT EXISTS (SELECT 1 FROM organization_members osm WHERE osm.user_id = %s)", userColumn)

	if len(s.orgIDs) == 0 {
		if s.unowned {
			return notAMember, nil
		}
		return "FALSE", nil
	}

	inScope := fmt.Sprintf(
		"EXISTS (SELECT 1 FROM organization_members osm WHERE osm.user_id = %s AND osm.organization_id = ANY($%d))",
		userColumn, paramIndex)
	args := []interface{}{pq.Array(s.orgIDs)}
	if s.unowned {
		return "(" + inScope + " OR " + notAMember + ")", args
	}
	return inScope, args
}

// andScope appends the scope's tenant predicate to query and returns the
// extended argument list.
//
// It is the SINGLE splice site for a column-based tenant predicate in this
// package. Every scoped accessor routes through it rather than concatenating
// SQL's output itself, which is what makes "does this accessor enforce
// tenancy?" answerable by grep, gives the gosec suppression one home instead of
// one per query, and makes the paramIndex arithmetic — the part a hand-written
// call site gets wrong — a property of the helper rather than of each caller.
//
// Callers MUST pass the args slice as it stands at the splice point: the
// placeholder index is derived from its length, so appending a filter argument
// before splicing and then splicing with a stale slice would bind the wrong
// value. Applying the scope FIRST, before any caller-supplied filter, is the
// convention throughout this package for exactly that reason.
func andScope(query string, s OrgScope, column string, args []interface{}) (string, []interface{}) {
	clause, scopeArgs := s.SQL(column, len(args)+1)
	// #nosec G202 -- clause comes from OrgScope.SQL: one of "TRUE", "FALSE", or a
	// fixed template over an internal column constant and a $N placeholder. Scope
	// values travel as query arguments and are never interpolated.
	return query + " AND " + clause, append(args, scopeArgs...)
}

// andMembershipScope is andScope for the users table, whose tenancy is derived
// through organization_members rather than carried on the row. See
// OrgScope.membershipSQL.
func andMembershipScope(query string, s OrgScope, userColumn string, args []interface{}) (string, []interface{}) {
	clause, scopeArgs := s.membershipSQL(userColumn, len(args)+1)
	// #nosec G202 -- clause comes from OrgScope.membershipSQL: one of "TRUE",
	// "FALSE", or a fixed EXISTS template over an internal table name, an
	// internal column reference and a $N placeholder.
	return query + " AND " + clause, append(args, scopeArgs...)
}

// OrgScopeForUser resolves the organizations in which userID holds the required
// scope, as an OrgScope ready to hand to any scoped accessor in this package.
//
// # Why this lives here
//
// Both consumers had already written it, over THIS module's tables, and neither
// could import the other's copy:
//
//	terraform-registry-backend/backend/internal/tenantscope/tenantscope.go
//	terraform-state-manager-backend/backend/internal/api/admin_org_scope.go
//
// Each loads GetUserMemberships(userID) and keeps the organizations whose ROLE
// TEMPLATE grants the required scope. Shipping OrgScope as a parameter type
// without shipping the resolver would have guaranteed a third copy, and the two
// that exist already disagree in the ways duplicated authorization code always
// does — one sorts the resulting ids and one does not, one can express "no
// repository wired, therefore deny" and one cannot.
//
// # The authority model
//
// Membership alone is NOT authority. The organizations returned are those in
// which the user's role template grants `required` — the same decision the
// per-resource route guards in both consumers already make for their ":id"
// axes. Resolving on bare membership instead would authorize the list and
// create axes strictly more weakly than the by-id axes of the same resources: a
// viewer in org A could enumerate what an operator in org A may manage.
//
// rwPairs carries the consumer's read-implies-write table (auth.HasScope's
// third argument); nil is valid and means no implications. The auth.ScopeAdmin
// wildcard is honoured by auth.HasScope, so a role template carrying it yields
// that organization for every `required`.
//
// # What it deliberately does NOT decide
//
// Whether the caller is PLATFORM-WIDE. That is a property of the TOKEN, or of
// an API key's organization binding, and this package's store layer never sees
// either — the flat, org-less scope union a session JWT carries cannot answer
// "where do you hold this", which is precisely why the membership rows have to
// be read at all. A consumer that has decided its caller is platform-wide uses
// OrgScopeAllOrganizations() instead of calling this, and that call is
// greppable in a way that a widening hidden inside a resolver would not be.
//
// It fails closed in the ways that matter: an empty userID, or a user with no
// qualifying membership, yields the empty scope — which denies — rather than an
// error a caller might ignore its way past; and a failed membership lookup
// returns the zero OrgScope alongside the error, so even a caller that drops
// the error reaches nothing.
func (r *OrganizationRepository) OrgScopeForUser(ctx context.Context, userID, required string, rwPairs auth.ReadWritePairs) (OrgScope, error) {
	if userID == "" {
		return OrgScope{}, nil
	}
	memberships, err := r.GetUserMemberships(ctx, userID)
	if err != nil {
		return OrgScope{}, err
	}
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		if auth.HasScope(m.RoleTemplateScopes, required, rwPairs) {
			orgIDs = append(orgIDs, m.OrganizationID)
		}
	}
	return OrgScopeOrganizations(orgIDs...), nil
}
