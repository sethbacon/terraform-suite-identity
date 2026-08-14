package platformadmin

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// resolverFromSet answers from a fixed set of live principals and counts its
// lookups, so the memoisation assertion is about calls rather than timing.
func resolverFromSet(live map[string]bool, calls *int) Resolver {
	return ResolverFunc(func(_ context.Context, userID string) (bool, error) {
		if calls != nil {
			*calls++
		}
		return live[userID], nil
	})
}

func grantsFor(userIDs ...string) []Grant {
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	out := make([]Grant, 0, len(userIDs))
	for i, id := range userIDs {
		out = append(out, Grant{UserID: id, GrantedAt: t0.Add(time.Duration(i) * time.Hour)})
	}
	return out
}

func TestRequireAnotherExercisableAdminAcceptsARemainingLivePrincipal(t *testing.T) {
	calls := 0
	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{adminA: true}, &calls))

	if err := predicate(context.Background(), grantsFor(adminA)); err != nil {
		t.Fatalf("predicate refused with a live administrator remaining: %v", err)
	}
	if calls != 1 {
		t.Errorf("resolver called %d times, want 1", calls)
	}
}

func TestRequireAnotherExercisableAdminRefusesWhenNoGrantRemains(t *testing.T) {
	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{adminA: true}, nil))

	err := predicate(context.Background(), nil)
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin — revoking the last administrator leaves "+
			"the application with no recovery path short of hand-written SQL", err)
	}
}

// GUARD orphan-grant-is-not-an-administrator. The carrier holds two rows, but
// the other one names a user who no longer exists. Counting rows — the version
// that needs no resolver — would let the last real administrator revoke
// themselves against a count of two.
func TestRequireAnotherExercisableAdminDoesNotCountAnOrphanedGrant(t *testing.T) {
	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{
		adminA:  true,
		orphanD: false, // grant row survives; the user is gone
	}, nil))

	err := predicate(context.Background(), grantsFor(orphanD))
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin — an orphaned grant elevates nobody, so it "+
			"is a record and not an administrator that remains", err)
	}
}

func TestRequireAnotherExercisableAdminAcceptsALivePrincipalBehindAnOrphan(t *testing.T) {
	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{
		adminA:  true,
		orphanD: false,
	}, nil))

	// The orphan is first in the list; the scan must not stop there.
	if err := predicate(context.Background(), grantsFor(orphanD, adminA)); err != nil {
		t.Fatalf("predicate refused although a live administrator remained behind an orphan: %v", err)
	}
}

// GUARD identity-outage-is-not-mass-orphaning. A resolver that FAILS must abort
// the revocation, not be read as "this one does not count". Collapsing the two
// turns an identity outage into the lockout the floor exists to prevent — and
// the caller must be able to tell the two refusals apart, because one is
// resolved by granting somebody else first and the other by asking again later.
func TestRequireAnotherExercisableAdminAbortsOnAResolverFailure(t *testing.T) {
	down := errors.New("identity database unreachable")
	predicate := RequireAnotherExercisableAdmin(ResolverFunc(
		func(context.Context, string) (bool, error) { return false, down }))

	err := predicate(context.Background(), grantsFor(adminA))
	if !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("err = %v, want ErrIdentityUnavailable", err)
	}
	if errors.Is(err, ErrLastPlatformAdmin) {
		t.Error("an identity outage was reported as 'there is genuinely nobody else' — an " +
			"operator would grant a new administrator to fix a problem that is not that")
	}
	if !errors.Is(err, down) {
		t.Errorf("err = %v, want the resolver's own cause preserved for the operator", err)
	}
}

// A nil resolver cannot establish that anyone remains, so it refuses everything
// rather than assuming every row counts.
func TestRequireAnotherExercisableAdminWithNoResolverRefuses(t *testing.T) {
	predicate := RequireAnotherExercisableAdmin(nil)

	err := predicate(context.Background(), grantsFor(adminA, adminB))
	if !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("err = %v, want ErrIdentityUnavailable — an unwired resolver must not read as "+
			"'assume they all count'", err)
	}
}

// Memoised within one call: the predicate runs inside a revoking transaction and
// a carrier holding repeated ids should not pay for the same lookup twice. Not
// memoised ACROSS calls — that is asserted by the resolver being constructed per
// predicate.
func TestRequireAnotherExercisableAdminResolvesEachPrincipalOnce(t *testing.T) {
	calls := 0
	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{orphanD: false}, &calls))

	err := predicate(context.Background(), grantsFor(orphanD, orphanD, orphanD))
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin", err)
	}
	if calls != 1 {
		t.Errorf("resolver called %d times for one repeated principal, want 1", calls)
	}
}

// End to end through Revoke: the floor's refusal reaches the caller as its own
// sentinel and nothing is deleted.
func TestRevokeRefusesTheLastExercisableAdministrator(t *testing.T) {
	c, mock := newTestCarrier(t)
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	// Two rows in the carrier — but the other names a deleted user.
	expectLockingRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, t0, nil).
		AddRow(orphanD, nil, t0.Add(time.Hour), nil))
	mock.ExpectRollback()

	predicate := RequireAnotherExercisableAdmin(resolverFromSet(map[string]bool{
		adminA:  true,
		orphanD: false,
	}, nil))

	got, err := c.Revoke(context.Background(), adminA, predicate, writingIntent(new(bool)))
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin — the carrier had two rows, but only one "+
			"of them was an administrator", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the refused revocation reached the DELETE: %v", err)
	}
}
