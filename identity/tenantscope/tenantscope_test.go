package tenantscope

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// MUTATIONS THIS FILE IS BUILT TO CATCH, and the test that catches each:
//
//	an empty principal resolving to anything      -> TestResolveWithoutAPrincipalReachesNothing
//	admins consulted for a key by default         -> TestResolveDoesNotElevateAnAPIKeyByDefault
//	an absent carrier denying instead of deferring-> TestResolveFallsThroughWhenNoCarrierIsWired
//	a failed lookup becoming an empty scope       -> TestResolveReportsLookupFailuresAsErrors
//	a nil Memberships resolving unfiltered        -> TestResolveWithoutMembershipsReachesNothing
//	a key binding read when policy is off         -> TestResolveIgnoresAKeyBindingUnlessPolicyEnablesIt
//	an unstamped row permitted to everyone        -> TestPermitsRefusesAnAbsentOrganization
//	the two apps' policies collapsing into one    -> TestResolveReproducesEachApplicationsPolicy

var errLookup = errors.New("database is gone")

type fakeMemberships struct {
	scope store.OrgScope
	err   error
	calls int
	gotID string
	gotRq string
}

func (f *fakeMemberships) OrgScopeForUser(_ context.Context, userID, required string, _ auth.ReadWritePairs) (store.OrgScope, error) {
	f.calls++
	f.gotID, f.gotRq = userID, required
	return f.scope, f.err
}

type fakeAdmins struct {
	isAdmin bool
	err     error
	calls   int
}

func (f *fakeAdmins) IsPlatformAdmin(context.Context, string) (bool, error) {
	f.calls++
	return f.isAdmin, f.err
}

// Compile-time proof that the module's own carrier satisfies the interface. If
// platformadmin.Service stops doing so, this file stops building — which is the
// only way that regression is visible before an application tries to wire it.
var _ PlatformAdmins = (*platformadmin.Carrier)(nil)

func membersOf(orgIDs ...string) *fakeMemberships {
	return &fakeMemberships{scope: store.OrgScopeOrganizations(orgIDs...)}
}

func TestResolveWithoutAPrincipalReachesNothing(t *testing.T) {
	for _, name := range []string{"", "   ", "\t\n"} {
		m := membersOf("org-a")
		r := Resolver{Memberships: m, Admins: &fakeAdmins{isAdmin: true}}
		got, err := r.Resolve(context.Background(), Principal{UserID: name, Credential: CredentialSession}, "state:read")
		if err != nil {
			t.Fatalf("UserID=%q: unexpected error %v", name, err)
		}
		if !got.Empty() {
			t.Errorf("UserID=%q resolved to %+v; a request with no principal must reach nothing", name, got)
		}
		if m.calls != 0 {
			t.Errorf("UserID=%q consulted memberships; there is no principal to look up", name)
		}
	}
}

func TestResolveElevatesAPlatformAdministrator(t *testing.T) {
	m := membersOf("org-a")
	r := Resolver{Memberships: m, Admins: &fakeAdmins{isAdmin: true}}
	got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.PlatformAdmin {
		t.Fatal("a platform administrator did not resolve as one")
	}
	if m.calls != 0 {
		t.Error("memberships were consulted for a platform administrator; nothing further should be asked")
	}
}

func TestResolveDoesNotElevateAnAPIKeyByDefault(t *testing.T) {
	admins := &fakeAdmins{isAdmin: true}
	m := membersOf("org-a")
	r := Resolver{Memberships: m, Admins: admins}

	got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialAPIKey}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PlatformAdmin {
		t.Fatal("an API key was resolved as platform-wide with AdminsApplyToAPIKeys off; " +
			"a credential minted for automation must not inherit its owner's platform authority")
	}
	if admins.calls != 0 {
		t.Errorf("the carrier was consulted %d times for a key request; it should not have been", admins.calls)
	}

	r.AdminsApplyToAPIKeys = true
	got, err = r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialAPIKey}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.PlatformAdmin {
		t.Fatal("AdminsApplyToAPIKeys is on and the key still did not elevate; the flag does nothing")
	}
}

func TestResolveFallsThroughWhenNoCarrierIsWired(t *testing.T) {
	for name, sentinel := range map[string]error{
		"library sentinel":         ErrAdminsNotConfigured,
		"carrier sentinel":         platformadmin.ErrNotConfigured,
		"wrapped library sentinel": fmt.Errorf("app: %w", ErrAdminsNotConfigured),
		"wrapped carrier sentinel": fmt.Errorf("app: %w", platformadmin.ErrNotConfigured),
	} {
		t.Run(name, func(t *testing.T) {
			m := membersOf("org-a")
			r := Resolver{Memberships: m, Admins: &fakeAdmins{err: sentinel}}
			got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read")
			if err != nil {
				t.Fatalf("an absent carrier produced an error: %v", err)
			}
			if m.calls != 1 {
				t.Fatalf("memberships consulted %d times; an absent carrier must WITHHOLD authority "+
					"and defer, not deny outright", m.calls)
			}
			if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-a" {
				t.Errorf("got %+v, want the membership answer", got)
			}
		})
	}
}

func TestResolveReportsLookupFailuresAsErrors(t *testing.T) {
	t.Run("admin lookup", func(t *testing.T) {
		m := membersOf("org-a")
		r := Resolver{Memberships: m, Admins: &fakeAdmins{err: errLookup}}
		got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read")
		if !errors.Is(err, errLookup) {
			t.Fatalf("err = %v, want the lookup failure; an authority question that did not "+
				"resolve is not a completed \"no\"", err)
		}
		if !got.Empty() {
			t.Errorf("got %+v with an error; a caller ignoring the error must still select nothing", got)
		}
		if m.calls != 0 {
			t.Error("memberships were consulted after the carrier failed")
		}
	})

	t.Run("membership lookup", func(t *testing.T) {
		r := Resolver{Memberships: &fakeMemberships{err: errLookup}}
		got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read")
		if !errors.Is(err, errLookup) {
			t.Fatalf("err = %v, want the lookup failure", err)
		}
		if !got.Empty() {
			t.Errorf("got %+v with an error", got)
		}
	})
}

func TestResolveWithoutMembershipsReachesNothing(t *testing.T) {
	r := Resolver{}
	got, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Empty() {
		t.Fatalf("a resolver with no Memberships produced %+v; it cannot verify anything, "+
			"so an unfiltered result would be the defect this package closes", got)
	}
}

func TestResolveBindsAKeyToItsOrganizationWhenPolicySaysSo(t *testing.T) {
	m := membersOf("org-owner")
	r := Resolver{Memberships: m, KeyBindsOrganization: true}

	got, err := r.Resolve(context.Background(),
		Principal{UserID: "u1", Credential: CredentialAPIKey, KeyOrgID: "org-key"}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-key" {
		t.Fatalf("got %+v, want the key's own organization", got)
	}
	if m.calls != 0 {
		t.Error("memberships were consulted for an organization-bound key")
	}
}

// A userless service key is the case registry's #719 was filed about: no
// memberships to resolve, so without the binding branch it receives an empty
// answer on its OWN organization.
func TestResolveBindsAUserlessServiceKey(t *testing.T) {
	m := &fakeMemberships{scope: store.OrgScopeOrganizations()}
	r := Resolver{Memberships: m, KeyBindsOrganization: true}

	got, err := r.Resolve(context.Background(),
		Principal{UserID: "svc", Credential: CredentialAPIKey, KeyOrgID: "org-key"}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Empty() {
		t.Fatal("a userless service key resolved to nothing on its own organization — " +
			"the condition registry #719 fixed")
	}
}

func TestResolveIgnoresAKeyBindingUnlessPolicyEnablesIt(t *testing.T) {
	m := membersOf("org-owner")
	r := Resolver{Memberships: m} // KeyBindsOrganization deliberately off

	got, err := r.Resolve(context.Background(),
		Principal{UserID: "u1", Credential: CredentialAPIKey, KeyOrgID: "org-key"}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-owner" {
		t.Fatalf("got %+v, want the OWNER's memberships. Reading the key's organization here "+
			"would place every key in whatever organization the minting code stamped — which in "+
			"terraform-state-manager is the deployment default, for every key.", got)
	}
}

func TestResolveFallsBackToTheOwnerForAnUnboundKey(t *testing.T) {
	for _, keyOrg := range []string{"", "   "} {
		m := membersOf("org-owner")
		r := Resolver{Memberships: m, KeyBindsOrganization: true}
		got, err := r.Resolve(context.Background(),
			Principal{UserID: "u1", Credential: CredentialAPIKey, KeyOrgID: keyOrg}, "state:read")
		if err != nil {
			t.Fatalf("KeyOrgID=%q: %v", keyOrg, err)
		}
		if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-owner" {
			t.Errorf("KeyOrgID=%q resolved to %+v; a key with no binding is a legacy row and its "+
				"owner's memberships decide", keyOrg, got)
		}
	}
}

func TestResolvePassesThePolicyThroughToMemberships(t *testing.T) {
	m := membersOf("org-a")
	r := Resolver{Memberships: m, ReadWritePairs: auth.ReadWritePairs{"state:read": "state:write"}}
	if _, err := r.Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:drift"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if m.gotID != "u1" || m.gotRq != "state:drift" {
		t.Errorf("memberships saw (%q, %q), want (u1, state:drift)", m.gotID, m.gotRq)
	}
}

func TestResolveToleratesANilContext(t *testing.T) {
	r := Resolver{Memberships: membersOf("org-a")}
	if _, err := r.Resolve(nil, Principal{UserID: "u1", Credential: CredentialSession}, "state:read"); err != nil { //nolint:staticcheck // deliberate
		t.Fatalf("a nil context panicked or errored: %v", err)
	}
}

// TestResolveReproducesEachApplicationsPolicy is the regression this package
// exists for. The two applications had already drifted apart when it was
// written; if one configuration starts behaving like the other, this fails.
func TestResolveReproducesEachApplicationsPolicy(t *testing.T) {
	// terraform-registry: platform-adminness is a flat scope already on the
	// request, keys are bound to their organization, and a key may be admin.
	registry := func(flatAdmin bool) Resolver {
		return Resolver{
			Memberships: membersOf("org-owner"),
			Admins: PlatformAdminFunc(func(context.Context, string) (bool, error) {
				return flatAdmin, nil
			}),
			AdminsApplyToAPIKeys: true,
			KeyBindsOrganization: true,
		}
	}
	// terraform-state-manager: platform-adminness is a live carrier row, a key
	// is never platform-wide, and a key's organization is a default rather than
	// a binding.
	stateManager := func(carrierSaysAdmin bool) Resolver {
		return Resolver{
			Memberships:          membersOf("org-owner"),
			Admins:               &fakeAdmins{isAdmin: carrierSaysAdmin},
			AdminsApplyToAPIKeys: false,
			KeyBindsOrganization: false,
		}
	}

	key := Principal{UserID: "u1", Credential: CredentialAPIKey, KeyOrgID: "org-key"}

	got, err := registry(false).Resolve(context.Background(), key, "state:read")
	if err != nil || len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-key" {
		t.Errorf("registry policy: got %+v (err %v), want the key's organization", got, err)
	}

	got, err = stateManager(false).Resolve(context.Background(), key, "state:read")
	if err != nil || len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-owner" {
		t.Errorf("state-manager policy: got %+v (err %v), want the OWNER's memberships", got, err)
	}

	// The divergence that matters most: an org-admin whose `admin` merely
	// surfaces flat must not become platform-wide under the state-manager
	// policy, and must under registry's.
	if got, _ := registry(true).Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read"); !got.PlatformAdmin {
		t.Error("registry policy: a flat admin scope did not elevate")
	}
	if got, _ := stateManager(false).Resolve(context.Background(), Principal{UserID: "u1", Credential: CredentialSession}, "state:read"); got.PlatformAdmin {
		t.Error("state-manager policy: elevated without a carrier row — every single-organization " +
			"admin would reach the whole deployment")
	}
}

// TestResolveTreatsAnUnspecifiedCredentialAsTheNarrowReading is why Credential is
// an enumeration rather than a bool. A Principal a caller forgot to fill in must
// not be resolved as an interactive session and become eligible for platform
// elevation; the zero value has to be the restrictive answer.
func TestResolveTreatsAnUnspecifiedCredentialAsTheNarrowReading(t *testing.T) {
	admins := &fakeAdmins{isAdmin: true}
	r := Resolver{Memberships: membersOf("org-owner"), Admins: admins}

	got, err := r.Resolve(context.Background(), Principal{UserID: "u1"}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PlatformAdmin {
		t.Fatal("an unspecified credential elevated to platform-wide; a Principal nobody filled " +
			"in must take the narrowest reading available, not the widest")
	}
	if admins.calls != 0 {
		t.Errorf("the carrier was consulted %d times for an unspecified credential", admins.calls)
	}
	if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-owner" {
		t.Errorf("got %+v, want the owner's memberships", got)
	}

	// It names no key, so it binds to no organization either.
	r.KeyBindsOrganization = true
	got, err = r.Resolve(context.Background(), Principal{UserID: "u1", KeyOrgID: "org-key"}, "state:read")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.OrgIDs) != 1 || got.OrgIDs[0] != "org-owner" {
		t.Errorf("got %+v; an unspecified credential is not an API key and must not take a key binding", got)
	}
}

func TestCredentialStringsAreStable(t *testing.T) {
	for c, want := range map[Credential]string{
		CredentialUnspecified: "unspecified",
		CredentialSession:     "session",
		CredentialAPIKey:      "apikey",
		Credential(99):        "unspecified",
	} {
		if got := c.String(); got != want {
			t.Errorf("Credential(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestPermitsRefusesAnAbsentOrganization(t *testing.T) {
	s := Scope{OrgIDs: []string{"org-a"}}
	for _, orgID := range []string{"", "   ", "org-b"} {
		if s.Permits(orgID) {
			t.Errorf("Permits(%q) = true; an unstamped row belongs to no tenant, not to every tenant", orgID)
		}
	}
	if !s.Permits("org-a") {
		t.Error("Permits(org-a) = false for a scope containing it")
	}

	// The case the guard actually exists for. Comparing "" against a set of
	// real ids fails on its own, so the guard looks redundant until the SET
	// contains an empty id — a membership row whose organization was never
	// stamped, which is precisely the row that must not match anything. Without
	// the guard an unstamped row would then be visible to an unstamped scope.
	unstamped := Scope{OrgIDs: []string{"", "org-a"}}
	for _, orgID := range []string{"", "  "} {
		if unstamped.Permits(orgID) {
			t.Errorf("Permits(%q) = true against a scope carrying an empty organization id; "+
				"an unstamped row must match nothing, not another unstamped row", orgID)
		}
	}
	if !unstamped.Permits("org-a") {
		t.Error("a scope carrying an empty id stopped permitting its real organization")
	}
	if !(Scope{PlatformAdmin: true}).Permits("anything") {
		t.Error("a platform administrator was refused")
	}
}

func TestPermitsPtrRefusesNull(t *testing.T) {
	s := Scope{OrgIDs: []string{"org-a"}}
	empty := ""
	if s.PermitsPtr(&empty) {
		t.Error("PermitsPtr(&\"\") = true; an empty organization is not an organization")
	}
	if s.PermitsPtr(nil) {
		t.Error("PermitsPtr(nil) = true; a NULL organization is permitted to nobody but a platform administrator")
	}
	if !(Scope{PlatformAdmin: true}).PermitsPtr(nil) {
		t.Error("a platform administrator was refused a NULL row")
	}
	orgA := "org-a"
	if !s.PermitsPtr(&orgA) {
		t.Error("PermitsPtr(org-a) = false for a scope containing it")
	}
}

func TestEmptyIgnoresHowTheScopeBecameEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope Scope
		want  bool
	}{
		{"zero value", Scope{}, true},
		{"platform admin", Scope{PlatformAdmin: true}, false},
		{"platform admin with no orgs", Scope{PlatformAdmin: true, OrgIDs: nil}, false},
		{"one organization", Scope{OrgIDs: []string{"org-a"}}, false},
	} {
		if got := tc.scope.Empty(); got != tc.want {
			t.Errorf("%s: Empty() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
