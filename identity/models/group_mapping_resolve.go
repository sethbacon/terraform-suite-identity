package models

// ResolveGroupMappings decides, for one authenticated principal, which role each
// organization should grant them and which organizations the IdP manages at all.
//
// WHY THIS IS HERE AND NOT IN EACH APPLICATION (#268). This module defined the
// SHAPE of a group mapping and its persistence, but not the rule for which
// mapping wins when two name the same organization and the principal holds both
// groups. Both consuming applications implemented that rule themselves and
// implemented it in OPPOSITE directions -- terraform-registry-backend took the
// first match, terraform-state-manager-backend the last -- so the same stored
// mapping list granted different roles depending on which app read it. Neither
// was wrong against the contract, because the contract was silent on a
// privilege decision.
//
// THE RULE IS FIRST-MATCH-WINS, and it is a decision rather than a discovery.
// Ordering the list strongest-first is then the operator's lever, and the
// property that argues for it is that APPENDING a mapping cannot change the
// outcome for anyone already matched -- which is what an authorization list
// edited incrementally through a UI needs. Last-wins reads naturally as
// config-file layering and was rejected for that reason: under it, adding a row
// silently re-roles principals the operator was not thinking about.
//
// PURE ON PURPOSE. It returns the desired role and the managed set and nothing
// else. It does NOT decide whether a role may be provisioned automatically
// (registry has an admin-floor guard and a credential sweep that state-manager
// does not, and state-manager refuses to auto-provision admin at all), because
// those are policy the applications own. This is the mechanism they were each
// re-deriving.
func ResolveGroupMappings(groups []string, mappings []OIDCGroupMapping) GroupMappingResolution {
	held := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		held[g] = struct{}{}
	}

	res := GroupMappingResolution{
		DesiredRole: make(map[string]string),
		Managed:     make(map[string]struct{}),
	}
	for _, m := range mappings {
		if m.Organization == "" {
			continue
		}
		// MANAGED IS UNCONDITIONAL. An organization any mapping names is
		// IdP-managed whether or not this principal holds the group, because
		// that is what makes a membership REVOCABLE: a principal who has lost
		// the group must be removed from it, and an organization nobody's
		// mapping names must never be touched. Both applications already
		// computed it this way.
		res.Managed[m.Organization] = struct{}{}

		if _, ok := held[m.Group]; !ok {
			continue
		}
		// First match wins: only record when nothing has claimed this
		// organization yet.
		if _, taken := res.DesiredRole[m.Organization]; !taken {
			res.DesiredRole[m.Organization] = m.Role
		}
	}
	return res
}

// GroupMappingResolution is what a membership reconciler needs from a mapping
// list: the role each organization should grant, and the organizations the IdP
// is authoritative over.
//
// An organization present in Managed but absent from DesiredRole is one the IdP
// manages and in which this principal should hold NOTHING -- that is the
// revocation case, and it is why the two are reported separately rather than as
// one map with an empty-string role.
type GroupMappingResolution struct {
	DesiredRole map[string]string
	Managed     map[string]struct{}
}

// Wanted reports the role org should grant, and whether any mapping matched.
func (r GroupMappingResolution) Wanted(org string) (string, bool) {
	role, ok := r.DesiredRole[org]
	return role, ok
}

// IsManaged reports whether any mapping names org at all.
func (r GroupMappingResolution) IsManaged(org string) bool {
	_, ok := r.Managed[org]
	return ok
}
