package tenantscope

import (
	"errors"
	"strings"
	"testing"
)

// MUTATIONS THIS FILE IS BUILT TO CATCH:
//
//	the permission check skipped for a named org  -> TestActingOrganizationRefusesAnOrganizationOutsideTheScope
//	a platform admin defaulted to something       -> TestActingOrganizationMakesAPlatformAdminChoose
//	several organizations silently narrowed to one-> TestActingOrganizationRefusesToChooseForTheCaller
//	an empty scope yielding an organization       -> TestActingOrganizationRefusesWhenThereIsNothingToActIn
//	whitespace treated as a selection             -> TestActingOrganizationTreatsBlankAsUnselected
//	the refusal disclosing what exists            -> TestActingOrganizationRefusalDisclosesNothing

func TestActingOrganizationUsesTheNamedOrganizationWhenPermitted(t *testing.T) {
	var r Resolver
	scope := Scope{OrgIDs: []string{"org-a", "org-b"}}

	got, err := r.ActingOrganization(scope, "org-b")
	if err != nil {
		t.Fatalf("ActingOrganization: %v", err)
	}
	if got != "org-b" {
		t.Errorf("got %q, want org-b", got)
	}

	// Whitespace around a real selection is trimmed, not treated as a
	// different organization.
	if got, err = r.ActingOrganization(scope, "  org-a  "); err != nil || got != "org-a" {
		t.Errorf("got (%q, %v), want (org-a, nil)", got, err)
	}
}

func TestActingOrganizationRefusesAnOrganizationOutsideTheScope(t *testing.T) {
	var r Resolver
	scope := Scope{OrgIDs: []string{"org-a"}}

	got, err := r.ActingOrganization(scope, "org-intruder")
	if !errors.Is(err, ErrActingOrganizationNotPermitted) {
		t.Fatalf("err = %v, want ErrActingOrganizationNotPermitted. This is THE check that makes the "+
			"header safe: the value arrives from the client and is worth nothing until it is tested "+
			"against a scope the server resolved.", err)
	}
	if got != "" {
		t.Errorf("got %q with an error; a refused request must yield no organization to stamp", got)
	}
}

// A platform administrator passes Permits for any id, so the named-organization
// path admits one. That is deliberate: reaching every organization is what the
// role means.
func TestActingOrganizationLetsAPlatformAdminNameAnyOrganization(t *testing.T) {
	var r Resolver
	got, err := r.ActingOrganization(Scope{PlatformAdmin: true}, "org-anything")
	if err != nil {
		t.Fatalf("ActingOrganization: %v", err)
	}
	if got != "org-anything" {
		t.Errorf("got %q, want org-anything", got)
	}
}

func TestActingOrganizationMakesAPlatformAdminChoose(t *testing.T) {
	var r Resolver
	got, err := r.ActingOrganization(Scope{PlatformAdmin: true}, "")
	if !errors.Is(err, ErrAmbiguousActingOrganization) {
		t.Fatalf("err = %v, want ErrAmbiguousActingOrganization. Reaching every organization is not "+
			"belonging to one, and there is no answer the server can invent.", err)
	}
	if got != "" {
		t.Errorf("got %q; a platform administrator was defaulted into an organization", got)
	}
}

// A platform administrator who ALSO holds memberships must still choose. The
// single-membership shortcut below must not fire for them, or an administrator
// with one membership would silently write on behalf of that tenant.
func TestActingOrganizationDoesNotShortcutAnAdminWithOneMembership(t *testing.T) {
	var r Resolver
	got, err := r.ActingOrganization(Scope{PlatformAdmin: true, OrgIDs: []string{"org-a"}}, "")
	if !errors.Is(err, ErrAmbiguousActingOrganization) {
		t.Fatalf("err = %v, want ErrAmbiguousActingOrganization; got organization %q", err, got)
	}
}

func TestActingOrganizationImpliesTheOnlyOrganizationACallerHas(t *testing.T) {
	var r Resolver
	got, err := r.ActingOrganization(Scope{OrgIDs: []string{"org-only"}}, "")
	if err != nil {
		t.Fatalf("ActingOrganization: %v", err)
	}
	if got != "org-only" {
		t.Errorf("got %q, want org-only. A caller in exactly one organization must never have to "+
			"send the header, or a single-organization deployment needs a picker it has no use for.", got)
	}
}

func TestActingOrganizationRefusesToChooseForTheCaller(t *testing.T) {
	var r Resolver
	got, err := r.ActingOrganization(Scope{OrgIDs: []string{"org-a", "org-b", "org-c"}}, "")
	if !errors.Is(err, ErrAmbiguousActingOrganization) {
		t.Fatalf("err = %v, want ErrAmbiguousActingOrganization; got %q. Picking the first element "+
			"depends on an ordering nobody guarantees and shows the user nothing.", err, got)
	}
	if got != "" {
		t.Errorf("got %q; the server chose on the caller's behalf", got)
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("the refusal does not say how many organizations were reachable: %v", err)
	}
}

func TestActingOrganizationRefusesWhenThereIsNothingToActIn(t *testing.T) {
	var r Resolver
	for _, scope := range []Scope{{}, {OrgIDs: []string{}}, {OrgIDs: nil}} {
		got, err := r.ActingOrganization(scope, "")
		if !errors.Is(err, ErrNoActingOrganization) {
			t.Errorf("scope %+v: err = %v, want ErrNoActingOrganization", scope, err)
		}
		if got != "" {
			t.Errorf("scope %+v: got %q; a caller who reaches nothing must not be able to write", scope, got)
		}
	}
}

func TestActingOrganizationTreatsBlankAsUnselected(t *testing.T) {
	var r Resolver
	scope := Scope{OrgIDs: []string{"org-only"}}
	for _, selected := range []string{"", " ", "\t", "\n  "} {
		got, err := r.ActingOrganization(scope, selected)
		if err != nil || got != "org-only" {
			t.Errorf("selected=%q: got (%q, %v); a blank header is an absent one, not an "+
				"organization named \"\" — which Permits refuses, so the caller would be "+
				"refused their own only organization", selected, got, err)
		}
	}
}

// The refusal must not become an oracle. A caller probing ids should not be able
// to tell "that organization exists but is not yours" from "no such organization".
func TestActingOrganizationRefusalDisclosesNothing(t *testing.T) {
	var r Resolver
	scope := Scope{OrgIDs: []string{"org-secret-a", "org-secret-b"}}

	_, err := r.ActingOrganization(scope, "org-intruder")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, secret := range scope.OrgIDs {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal names %q, an organization the caller may reach but did not ask "+
				"about: %v", secret, err)
		}
	}
	if strings.Contains(err.Error(), "org-intruder") {
		t.Errorf("the refusal echoes the caller-supplied id back: %v. It arrives from the client "+
			"and reaching a log or a response body unfiltered is how a header becomes an "+
			"injection surface.", err)
	}
}

func TestActingOrganizationHeaderIsStable(t *testing.T) {
	// Both applications and the shared frontend read this one name. Changing it
	// is a coordinated release, not an edit.
	if ActingOrganizationHeader != "X-Organization-Id" {
		t.Errorf("ActingOrganizationHeader = %q; changing it breaks every caller that already "+
			"sends the old name", ActingOrganizationHeader)
	}
}
