package auth_test

import (
	"strings"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

func TestHasScope(t *testing.T) {
	pairs := auth.ReadWritePairs{
		"foo:read": "foo:write",
		"bar:read": "bar:write",
	}

	tests := []struct {
		name       string
		userScopes []string
		required   string
		want       bool
	}{
		{"exact match", []string{"foo:read"}, "foo:read", true},
		{"admin grants all", []string{auth.ScopeAdmin}, "anything:read", true},
		{"write implies read", []string{"foo:write"}, "foo:read", true},
		{"write does not imply other read", []string{"foo:write"}, "bar:read", false},
		{"missing scope", []string{"baz:read"}, "foo:read", false},
		{"empty scopes", []string{}, "foo:read", false},
		{"identity-core users read exact", []string{auth.ScopeUsersRead}, auth.ScopeUsersRead, true},
		{"identity-core admin wildcard", []string{auth.ScopeAdmin}, auth.ScopeUsersRead, true},
		// An empty required scope must never match, even if userScopes contains
		// an accidental empty-string element (e.g. from a naive strings.Split on
		// a value with a trailing/double comma upstream in a consumer).
		{"empty required scope never matches", []string{"foo:read", ""}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.HasScope(tt.userScopes, tt.required, pairs)
			if got != tt.want {
				t.Errorf("HasScope(%v, %q) = %v, want %v", tt.userScopes, tt.required, got, tt.want)
			}
		})
	}
}

func TestHasAnyScope(t *testing.T) {
	pairs := auth.ReadWritePairs{"foo:read": "foo:write"}

	tests := []struct {
		name       string
		userScopes []string
		required   []string
		want       bool
	}{
		{"first matches", []string{"foo:read"}, []string{"foo:read", "bar:read"}, true},
		{"second matches", []string{"bar:read"}, []string{"foo:read", "bar:read"}, true},
		{"none match", []string{"baz:read"}, []string{"foo:read", "bar:read"}, false},
		{"empty required always false", []string{"foo:read"}, []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.HasAnyScope(tt.userScopes, tt.required, pairs)
			if got != tt.want {
				t.Errorf("HasAnyScope(%v, %v) = %v, want %v", tt.userScopes, tt.required, got, tt.want)
			}
		})
	}
}

func TestHasAllScopes(t *testing.T) {
	pairs := auth.ReadWritePairs{"foo:read": "foo:write"}

	tests := []struct {
		name       string
		userScopes []string
		required   []string
		want       bool
	}{
		{"all present", []string{"foo:read", "bar:read"}, []string{"foo:read", "bar:read"}, true},
		{"partial", []string{"foo:read"}, []string{"foo:read", "bar:read"}, false},
		{"empty required always false", []string{}, []string{}, false},
		{"admin covers all", []string{auth.ScopeAdmin}, []string{"anything", "everything"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.HasAllScopes(tt.userScopes, tt.required, pairs)
			if got != tt.want {
				t.Errorf("HasAllScopes(%v, %v) = %v, want %v", tt.userScopes, tt.required, got, tt.want)
			}
		})
	}
}

func TestValidateProvisionableScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		{"clean scope list", []string{"users:read", "organizations:write"}, false},
		{"empty scope list", []string{}, false},
		{"nil scope list", nil, false},
		{"admin present alone", []string{auth.ScopeAdmin}, true},
		{"admin present among other legitimate scopes", []string{"users:read", auth.ScopeAdmin, "organizations:write"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateProvisionableScopes(tt.scopes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProvisionableScopes(%v) error = %v, wantErr %v", tt.scopes, err, tt.wantErr)
			}
		})
	}
}

func TestValidateProvisionableScopes_ErrorNamesAdmin(t *testing.T) {
	err := auth.ValidateProvisionableScopes([]string{auth.ScopeAdmin})
	if err == nil {
		t.Fatal("ValidateProvisionableScopes([admin]) = nil, want error")
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Errorf("ValidateProvisionableScopes error %q does not name %q, making it hard to debug", err.Error(), "admin")
	}
}

// ---------------------------------------------------------------------------
// HasScopeInOrg / HasAnyScopeInOrg / HasAllScopesInOrg
// ---------------------------------------------------------------------------

func TestHasScopeInOrg(t *testing.T) {
	// Regression test for issue #54: these are the org-aware authorization
	// primitives — a role granted in one organization must never authorize an
	// action in another, and a GLOBAL (org-less) token must never satisfy an
	// org-scoped check even if its flat scopes would otherwise match.
	pairs := auth.ReadWritePairs{"foo:read": "foo:write"}

	tests := []struct {
		name     string
		claims   *auth.Claims
		orgID    string
		required string
		want     bool
	}{
		{
			name:     "matching org and scope",
			claims:   &auth.Claims{OrgID: "org-1", Scopes: []string{"foo:read"}},
			orgID:    "org-1",
			required: "foo:read",
			want:     true,
		},
		{
			name:     "matching org, write implies read",
			claims:   &auth.Claims{OrgID: "org-1", Scopes: []string{"foo:write"}},
			orgID:    "org-1",
			required: "foo:read",
			want:     true,
		},
		{
			name:     "wrong org rejected even though scope matches",
			claims:   &auth.Claims{OrgID: "org-1", Scopes: []string{auth.ScopeAdmin, "foo:read"}},
			orgID:    "org-2",
			required: "foo:read",
			want:     false,
		},
		{
			name:     "global (org-less) token always rejected",
			claims:   &auth.Claims{OrgID: "", Scopes: []string{auth.ScopeAdmin, "foo:read"}},
			orgID:    "org-1",
			required: "foo:read",
			want:     false,
		},
		{
			name:     "empty target orgID always rejected",
			claims:   &auth.Claims{OrgID: "org-1", Scopes: []string{"foo:read"}},
			orgID:    "",
			required: "foo:read",
			want:     false,
		},
		{
			name:     "nil claims rejected",
			claims:   nil,
			orgID:    "org-1",
			required: "foo:read",
			want:     false,
		},
		{
			name:     "matching org but missing scope",
			claims:   &auth.Claims{OrgID: "org-1", Scopes: []string{"bar:read"}},
			orgID:    "org-1",
			required: "foo:read",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.HasScopeInOrg(tt.claims, tt.orgID, tt.required, pairs)
			if got != tt.want {
				t.Errorf("HasScopeInOrg(%+v, %q, %q) = %v, want %v", tt.claims, tt.orgID, tt.required, got, tt.want)
			}
		})
	}
}

func TestHasScopeInOrg_CrossOrgIsolation(t *testing.T) {
	// The exact escalation issue #54 describes: a user who is admin in org-1 and
	// merely a viewer in org-2 must not have the org-1 admin scope authorize an
	// org-2 action, when checked via the org-aware primitive against an
	// org-scoped token.
	org1Claims := &auth.Claims{OrgID: "org-1", Scopes: []string{auth.ScopeAdmin}}
	if auth.HasScopeInOrg(org1Claims, "org-2", auth.ScopeUsersRead, nil) {
		t.Fatal("org-1 admin token must not authorize an org-2 action")
	}
	if !auth.HasScopeInOrg(org1Claims, "org-1", auth.ScopeUsersRead, nil) {
		t.Fatal("org-1 admin token must authorize an org-1 action")
	}
}

func TestHasAnyScopeInOrg(t *testing.T) {
	claims := &auth.Claims{OrgID: "org-1", Scopes: []string{"foo:read"}}
	if !auth.HasAnyScopeInOrg(claims, "org-1", []string{"bar:read", "foo:read"}, nil) {
		t.Error("expected true: one of the required scopes matches in the bound org")
	}
	if auth.HasAnyScopeInOrg(claims, "org-2", []string{"foo:read"}, nil) {
		t.Error("expected false: token is bound to a different org")
	}
	if auth.HasAnyScopeInOrg(&auth.Claims{Scopes: []string{"foo:read"}}, "org-1", []string{"foo:read"}, nil) {
		t.Error("expected false: global (org-less) token must never match")
	}
}

func TestHasAllScopesInOrg(t *testing.T) {
	claims := &auth.Claims{OrgID: "org-1", Scopes: []string{"foo:read", "bar:read"}}
	if !auth.HasAllScopesInOrg(claims, "org-1", []string{"foo:read", "bar:read"}, nil) {
		t.Error("expected true: all required scopes present in the bound org")
	}
	if auth.HasAllScopesInOrg(claims, "org-1", []string{"foo:read", "baz:read"}, nil) {
		t.Error("expected false: not all required scopes present")
	}
	if auth.HasAllScopesInOrg(claims, "org-2", []string{"foo:read"}, nil) {
		t.Error("expected false: token is bound to a different org")
	}
	if auth.HasAllScopesInOrg(&auth.Claims{Scopes: []string{"foo:read", "bar:read"}}, "org-1", []string{"foo:read"}, nil) {
		t.Error("expected false: global (org-less) token must never match")
	}
}
