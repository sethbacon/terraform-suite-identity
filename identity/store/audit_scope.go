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

// MatchesNothing reports whether the scope can never select a row — either the
// fail-closed zero value or an empty organization allowlist.
func (s AuditScope) MatchesNothing() bool { return !s.all && len(s.orgIDs) == 0 }

// OrganizationIDs returns a copy of the scope's organization allowlist.
func (s AuditScope) OrganizationIDs() []string {
	out := make([]string, len(s.orgIDs))
	copy(out, s.orgIDs)
	return out
}

// PermitsOrganization reports whether a row owned by orgID (empty meaning an
// org-less row) is inside the scope. Org-less rows are visible only to the
// platform-wide scope: an empty owner cannot be matched against any membership.
func (s AuditScope) PermitsOrganization(orgID string) bool {
	if s.all {
		return true
	}
	if orgID == "" {
		return false
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
		return " AND FALSE", nil
	}
	return fmt.Sprintf(" AND %s = ANY($%d)", column, paramIndex), pq.Array(s.orgIDs)
}
