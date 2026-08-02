// audit_scope.go defines AuditScope, the mandatory tenant constraint carried by
// every audit-log READ in this package.
//
// Why a type and not just another optional field on AuditFilters: audit_logs is
// an organization-owned table, and the defect this closes (terraform-registry
// #718/#719) is not "one query forgot its WHERE clause" but a CLASS —
// resource x access-axis. The list query grew an optional OrganizationID filter
// and one consumer route learned to set it, while the by-id read and the export
// stream over the SAME table kept no tenant predicate at all. An optional field
// makes the unscoped query the DEFAULT, so every new access axis re-opens the
// hole and every fix has to be re-applied per call site.
//
// AuditScope inverts that. It is a REQUIRED parameter of every read accessor,
// and its ZERO VALUE DENIES EVERYTHING. A caller who forgets to think about
// tenancy gets no rows, not every tenant's rows. Reading across organizations
// remains possible but must be spelled out with AuditScopeAllOrganizations(),
// which is greppable and reviewable in a way that an absent filter is not.
package store

import (
	"fmt"

	"github.com/lib/pq"
)

// AuditScope constrains an audit-log read to a set of organizations.
//
// Construct it with AuditScopeOrganizations (an allowlist) or
// AuditScopeAllOrganizations (an explicit, deliberate platform-wide read).
// The zero value permits nothing: it is the fail-closed default for a caller
// that has not decided.
type AuditScope struct {
	orgIDs []string
	all    bool
	// unowned widens the scope to rows whose organization_id is NULL. It is a
	// separate axis from orgIDs, not a member of it, because "no owner" is not
	// an organization anyone can be a member of — see
	// AuditScopeOrganizationsAndUnowned for when that is the right answer.
	unowned bool
}

// AuditScopeOrganizations limits a read to entries owned by the given
// organizations. Passing no ids yields a scope that matches nothing, which is
// the correct answer for a principal with no memberships — not a reason to
// widen the query.
func AuditScopeOrganizations(orgIDs ...string) AuditScope {
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
	return AuditScope{orgIDs: cleaned}
}

// AuditScopeOrganizationsAndUnowned limits a read to entries owned by the given
// organizations AND to entries with no owning organization at all
// (organization_id IS NULL).
//
// This variant exists for consumers whose audit stream mixes org-owned events
// with genuinely platform-level ones. terraform-state-manager writes logins,
// state-file and source actions with a NULL organization_id by design, so
// AuditScopeOrganizations would hide from an organization admin the very events
// they are the intended reviewer of, and AuditScopeAllOrganizations would hand
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
func AuditScopeOrganizationsAndUnowned(orgIDs ...string) AuditScope {
	scope := AuditScopeOrganizations(orgIDs...)
	scope.unowned = true
	return scope
}

// AuditScopeAllOrganizations returns a scope that reads across every
// organization. Reserved for platform-wide operators and for genuinely
// org-less maintenance paths (retention sweeps, health checks). It exists so
// that "read everything" is an explicit, auditable decision at the call site
// rather than the consequence of an omitted filter.
func AuditScopeAllOrganizations() AuditScope {
	return AuditScope{all: true}
}

// IsAllOrganizations reports whether the scope is the explicit platform-wide
// scope.
func (s AuditScope) IsAllOrganizations() bool { return s.all }

// IncludesUnowned reports whether the scope also selects rows with no owning
// organization.
func (s AuditScope) IncludesUnowned() bool { return s.all || s.unowned }

// MatchesNothing reports whether the scope can never select a row — the
// fail-closed zero value, or an empty organization allowlist that does not also
// admit unowned rows.
func (s AuditScope) MatchesNothing() bool {
	return !s.all && !s.unowned && len(s.orgIDs) == 0
}

// OrganizationIDs returns a copy of the scope's organization allowlist.
func (s AuditScope) OrganizationIDs() []string {
	out := make([]string, len(s.orgIDs))
	copy(out, s.orgIDs)
	return out
}

// PermitsOrganization reports whether a row owned by orgID (empty meaning an
// org-less row) is inside the scope. Org-less rows are visible only to the
// platform-wide scope or to a scope built with
// AuditScopeOrganizationsAndUnowned: an empty owner cannot be matched against
// any membership, so admitting it is always an explicit decision.
func (s AuditScope) PermitsOrganization(orgID string) bool {
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
func (s AuditScope) String() string {
	if s.all {
		return "AuditScope(all-organizations)"
	}
	if s.unowned {
		return fmt.Sprintf("AuditScope(%d organization(s) + unowned)", len(s.orgIDs))
	}
	return fmt.Sprintf("AuditScope(%d organization(s))", len(s.orgIDs))
}

// sqlPredicate returns the SQL fragment and argument that constrain a query to
// the scope, using the supplied column reference and starting placeholder
// index. It returns ("", nil) for the platform-wide scope.
//
// A scope that matches nothing yields a predicate that is false rather than no
// predicate at all, so a fail-closed scope cannot degrade into an unfiltered
// query if a caller ignores the MatchesNothing shortcut.
func (s AuditScope) sqlPredicate(column string, paramIndex int) (string, interface{}) {
	if s.all {
		return "", nil
	}
	if len(s.orgIDs) == 0 {
		if s.unowned {
			return fmt.Sprintf(" AND %s IS NULL", column), nil
		}
		return " AND FALSE", nil
	}
	if s.unowned {
		return fmt.Sprintf(" AND (%s = ANY($%d) OR %s IS NULL)", column, paramIndex, column), pq.Array(s.orgIDs)
	}
	return fmt.Sprintf(" AND %s = ANY($%d)", column, paramIndex), pq.Array(s.orgIDs)
}
