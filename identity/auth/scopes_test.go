package auth_test

import (
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
