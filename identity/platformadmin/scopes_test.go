package platformadmin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

func hasAdmin(scopes []string) bool {
	for _, s := range scopes {
		if s == auth.ScopeAdmin {
			return true
		}
	}
	return false
}

func expectCarrierLookup(mock sqlmock.Sqlmock, userID string, isAdmin bool) {
	mock.ExpectQuery(`SELECT EXISTS.*FROM "platform_admins" WHERE user_id`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(isAdmin))
}

// The carrier is the ONLY source of `admin` on a session. A token that already
// claims it does not keep it; a principal who holds a row gets it whether the
// token claimed it or not.
func TestSessionScopesDerivesAdminFromTheCarrierAndNotTheToken(t *testing.T) {
	cases := []struct {
		name      string
		token     []string
		carrier   bool
		wantAdmin bool
		wantRest  []string
	}{
		{
			name:      "a token claiming admin, with no carrier row, is not an administrator",
			token:     []string{"admin", "modules:read"},
			carrier:   false,
			wantAdmin: false,
			wantRest:  []string{"modules:read"},
		},
		{
			name:      "a token claiming nothing, with a carrier row, is an administrator",
			token:     []string{"modules:read"},
			carrier:   true,
			wantAdmin: true,
			wantRest:  []string{"modules:read"},
		},
		{
			name:      "a token claiming admin, with a carrier row, keeps exactly one admin",
			token:     []string{"admin", "admin", "modules:read"},
			carrier:   true,
			wantAdmin: true,
			wantRest:  []string{"modules:read"},
		},
		{
			name:      "an empty scope set with a carrier row is elevated",
			token:     nil,
			carrier:   true,
			wantAdmin: true,
			wantRest:  []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, mock := newTestCarrier(t)
			expectCarrierLookup(mock, adminA, tc.carrier)

			got, err := c.SessionScopes(context.Background(), adminA, tc.token)
			if err != nil {
				t.Fatalf("SessionScopes: %v", err)
			}
			if hasAdmin(got) != tc.wantAdmin {
				t.Fatalf("SessionScopes = %v; admin present = %v, want %v", got, hasAdmin(got), tc.wantAdmin)
			}
			var rest []string
			for _, s := range got {
				if s != auth.ScopeAdmin {
					rest = append(rest, s)
				}
			}
			if len(rest) == 0 {
				rest = []string{}
			}
			if !reflect.DeepEqual(rest, tc.wantRest) {
				t.Errorf("non-admin scopes = %v, want %v — elevation must not disturb the rest", rest, tc.wantRest)
			}
			// Exactly one admin, not two: the elevation appends to the STRIPPED
			// set, so a duplicate would mean the strip did not happen.
			n := 0
			for _, s := range got {
				if s == auth.ScopeAdmin {
					n++
				}
			}
			if tc.wantAdmin && n != 1 {
				t.Errorf("admin appears %d times in %v, want exactly 1", n, got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

// GUARD elevation-is-per-request. Two calls, two lookups. A cache with any TTL
// at all reintroduces exactly the window that keeping `admin` out of the token
// was meant to close: revocation would take effect whenever the cache happened
// to expire. Both expectations must be consumed, so a memoised second call
// fails ExpectationsWereMet.
func TestSessionScopesResolvesOnEveryCall(t *testing.T) {
	c, mock := newTestCarrier(t)
	// Granted, then revoked between the two requests.
	expectCarrierLookup(mock, adminA, true)
	expectCarrierLookup(mock, adminA, false)

	first, err := c.SessionScopes(context.Background(), adminA, []string{"modules:read"})
	if err != nil {
		t.Fatalf("first SessionScopes: %v", err)
	}
	if !hasAdmin(first) {
		t.Fatalf("first call = %v, want it elevated", first)
	}
	second, err := c.SessionScopes(context.Background(), adminA, []string{"modules:read"})
	if err != nil {
		t.Fatalf("second SessionScopes: %v", err)
	}
	if hasAdmin(second) {
		t.Errorf("second call = %v — the revocation did not take effect on the next request, "+
			"which is the entire reason authority is resolved per request rather than claimed in a token", second)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the second request did not re-read the carrier: %v", err)
	}
}

// A failed lookup returns the STRIPPED scopes with the error, so a caller that
// chooses to continue continues unelevated rather than with whatever the token
// claimed.
func TestSessionScopesReturnsStrippedScopesAlongsideAFailure(t *testing.T) {
	c, mock := newTestCarrier(t)
	sentinel := errors.New("connection reset")
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(sentinel)

	got, err := c.SessionScopes(context.Background(), adminA, []string{"admin", "modules:read"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if hasAdmin(got) {
		t.Errorf("SessionScopes = %v on a failed lookup — the token's own `admin` claim survived "+
			"the failure, which is the fail-open direction", got)
	}
	if !reflect.DeepEqual(got, []string{"modules:read"}) {
		t.Errorf("SessionScopes = %v, want the rest of the scopes preserved", got)
	}
}

// An empty principal never reaches the carrier and is never elevated.
func TestSessionScopesDoesNotElevateAnEmptyPrincipal(t *testing.T) {
	c, mock := newTestCarrier(t)

	got, err := c.SessionScopes(context.Background(), "", []string{"admin", "modules:read"})
	if err != nil {
		t.Fatalf("SessionScopes: %v", err)
	}
	if hasAdmin(got) {
		t.Errorf("SessionScopes = %v for an empty principal", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the empty principal reached the database: %v", err)
	}
}

// The caller's slice is not written through. claims.Scopes is typically
// published elsewhere on a request context, and append into spare capacity
// would mutate that other view.
func TestSessionScopesDoesNotWriteThroughTheCallersSlice(t *testing.T) {
	c, mock := newTestCarrier(t)
	expectCarrierLookup(mock, adminA, true)

	backing := make([]string, 1, 4) // spare capacity: the shape that aliases
	backing[0] = "modules:read"
	before := append([]string(nil), backing...)

	if _, err := c.SessionScopes(context.Background(), adminA, backing); err != nil {
		t.Fatalf("SessionScopes: %v", err)
	}
	if !reflect.DeepEqual(backing, before) {
		t.Errorf("the caller's slice became %v, was %v — the elevation wrote through a shared backing array", backing, before)
	}
}

// GUARD api-key-never-inherits-platform-admin. The property, stated as a test:
// a principal who IS a platform administrator hands an API key their scopes,
// and the key comes back without `admin` — and the carrier is never consulted,
// because KeyScopes cannot consult it. The mock is primed with no expectations,
// so any query at all fails ExpectationsWereMet.
func TestKeyScopesNeverInheritsTheOwnersPlatformAdmin(t *testing.T) {
	_, mock := newTestCarrier(t)

	for _, stored := range [][]string{
		{"admin"},
		{"admin", "modules:read", "modules:write"},
		{"modules:read", "admin"},
	} {
		got := KeyScopes(stored)
		if hasAdmin(got) {
			t.Errorf("KeyScopes(%v) = %v — a long-lived credential kept the platform-admin "+
				"wildcard; every CI token holding this key would carry the highest privilege in the product",
				stored, got)
		}
	}
	// Non-admin scopes are untouched: this strips one thing, it is not a
	// permission filter.
	if got := KeyScopes([]string{"modules:read", "admin", "providers:write"}); !reflect.DeepEqual(got, []string{"modules:read", "providers:write"}) {
		t.Errorf("KeyScopes = %v, want the key's own scopes preserved", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the API-key path consulted the carrier: %v", err)
	}
}

func TestKeyScopesLeavesANonAdminKeyAlone(t *testing.T) {
	in := []string{"modules:read", "providers:read"}
	got := KeyScopes(in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("KeyScopes(%v) = %v", in, got)
	}
	if len(KeyScopes(nil)) != 0 {
		t.Error("KeyScopes(nil) should be empty")
	}
}
