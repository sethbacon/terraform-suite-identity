package models

import (
	"reflect"
	"testing"
)

// #268 — the precedence rule the two applications each invented, and invented
// differently. These pin the DECISION, so a future change to it has to be
// deliberate rather than incidental.

func TestResolveGroupMappings_FirstMatchWins(t *testing.T) {
	// The exact shape from the issue: a principal holding BOTH groups, two
	// mappings naming ONE organization. Registry answered devops, state-manager
	// answered admin, from the same stored list.
	mappings := []OIDCGroupMapping{
		{Group: "tfr-devops", Organization: "aceo", Role: "devops"},
		{Group: "tfr-admin", Organization: "aceo", Role: "admin"},
	}
	got := ResolveGroupMappings([]string{"tfr-devops", "tfr-admin"}, mappings)

	if role, ok := got.Wanted("aceo"); !ok || role != "devops" {
		t.Errorf("role = %q ok=%v, want devops: the FIRST matching mapping wins", role, ok)
	}
}

// The falsification. Without it, "always take the last" would satisfy nothing
// above but "always take the first entry regardless of whether the group is
// held" would pass, which is a different and much worse rule.
func TestResolveGroupMappings_OnlyHeldGroupsMatch(t *testing.T) {
	mappings := []OIDCGroupMapping{
		{Group: "not-held", Organization: "aceo", Role: "admin"},
		{Group: "held", Organization: "aceo", Role: "viewer"},
	}
	got := ResolveGroupMappings([]string{"held"}, mappings)

	if role, _ := got.Wanted("aceo"); role != "viewer" {
		t.Errorf("role = %q, want viewer: a mapping whose group is not held must not win", role)
	}
}

// APPEND-SAFETY is the property first-wins was chosen for: adding a mapping must
// not change the outcome for a principal already matched.
func TestResolveGroupMappings_AppendingCannotReRoleAnExistingMatch(t *testing.T) {
	base := []OIDCGroupMapping{{Group: "eng", Organization: "aceo", Role: "editor"}}
	appended := append(append([]OIDCGroupMapping{}, base...),
		OIDCGroupMapping{Group: "eng", Organization: "aceo", Role: "viewer"})

	before := ResolveGroupMappings([]string{"eng"}, base)
	after := ResolveGroupMappings([]string{"eng"}, appended)

	if !reflect.DeepEqual(before.DesiredRole, after.DesiredRole) {
		t.Errorf("appending a mapping re-roled an existing match: %v -> %v", before.DesiredRole, after.DesiredRole)
	}
}

// Managed is unconditional: it is what makes a membership revocable.
func TestResolveGroupMappings_ManagedIncludesOrgsWhoseGroupIsNotHeld(t *testing.T) {
	mappings := []OIDCGroupMapping{
		{Group: "held", Organization: "aceo", Role: "editor"},
		{Group: "not-held", Organization: "other", Role: "editor"},
	}
	got := ResolveGroupMappings([]string{"held"}, mappings)

	if !got.IsManaged("other") {
		t.Error("an organization named by a mapping is IdP-managed even when the group is not held; without this a lost group can never be revoked")
	}
	if _, ok := got.Wanted("other"); ok {
		t.Error("managed but unmatched must yield NO desired role -- that is the revocation case")
	}
}

// An organization no mapping names must never be touched.
func TestResolveGroupMappings_UnmanagedOrgIsAbsentEntirely(t *testing.T) {
	got := ResolveGroupMappings([]string{"eng"},
		[]OIDCGroupMapping{{Group: "eng", Organization: "aceo", Role: "editor"}})

	if got.IsManaged("unrelated") {
		t.Error("an organization no mapping names must not be reported as managed")
	}
}

func TestResolveGroupMappings_EmptyOrganizationIsIgnored(t *testing.T) {
	got := ResolveGroupMappings([]string{"eng"},
		[]OIDCGroupMapping{{Group: "eng", Organization: "", Role: "editor"}})
	if len(got.Managed) != 0 || len(got.DesiredRole) != 0 {
		t.Errorf("a mapping naming no organization must contribute nothing: %+v", got)
	}
}
