// floor.go is the never-zero administrator floor: the rule that an application
// must not be left with nobody who can administer it.
//
// The refusal itself lives in Carrier.Revoke, which reads the carrier under FOR
// UPDATE and calls a Predicate with the grants that would REMAIN. This file
// supplies the predicate the rule actually needs — the one that counts
// administrators rather than rows.
package platformadmin

import (
	"context"
	"fmt"
)

// Resolver answers whether a grant names a principal that still exists.
//
// TWO ANSWERS AND A FAILURE, kept apart. UserExists returns (false, nil) for
// "this id resolves to nobody" and a non-nil error for "I could not find out".
// Collapsing those — the obvious shape, `func(ctx, id) bool` — is the defect
// this interface exists to prevent: an identity store that is down would report
// every principal as non-existent, the floor would conclude that every
// remaining grant is an orphan, and the last real administrator would be
// allowed to revoke themselves in the middle of an outage.
//
// The application supplies the implementation because only it knows where its
// principals resolve: identity.users on the same connection, on another
// connection, or in another database entirely — which is why the carrier holds
// no foreign key to them (docs/platform-admin.md).
type Resolver interface {
	UserExists(ctx context.Context, userID string) (bool, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, userID string) (bool, error)

// UserExists calls f.
func (f ResolverFunc) UserExists(ctx context.Context, userID string) (bool, error) {
	return f(ctx, userID)
}

// RequireAnotherExercisableAdmin builds the Predicate for Carrier.Revoke: the
// revocation proceeds only if at least one of the REMAINING grants resolves to
// a principal that still exists.
//
// EXERCISABLE, NOT MERELY RECORDED. A grant whose user is gone is a record, not
// an administrator: every elevation path loads the principal before consulting
// the carrier, so an orphan row elevates nobody. Counting rows instead — the
// version that needs no resolver and looks so much simpler — would let the last
// real administrator revoke themselves whenever a deleted colleague's grant was
// still on the table, which is the precise failure this predicate exists to
// prevent and the reason the carrier's missing foreign key has to be paid for
// here.
//
// A LOOKUP FAILURE ABORTS, it does not skip. Treating an unreachable identity
// store as "this one does not count" turns an outage into the lockout. The
// error wraps ErrIdentityUnavailable so a handler can tell it apart from
// ErrLastPlatformAdmin: one is "there is genuinely nobody else" (a conflict the
// operator resolves by granting first) and the other is "ask again later".
//
// A NIL RESOLVER REFUSES EVERYTHING, with ErrIdentityUnavailable. An unwired
// resolver cannot establish that anyone remains, and the fail-open reading —
// "no resolver, so assume they all count" — is the same lockout with a different
// cause. An application that genuinely wants no floor passes its own predicate
// saying so in one line, where a reviewer can see it.
//
// Resolution is memoised for the duration of ONE call, so a carrier holding
// several grants for ids that repeat costs one lookup each. It is not memoised
// across calls: this runs inside a revoking transaction, and a stale answer here
// is an answer about whether the application still has an administrator.
func RequireAnotherExercisableAdmin(r Resolver) Predicate {
	return func(ctx context.Context, remaining []Grant) error {
		if r == nil {
			return fmt.Errorf("%w: no resolver was supplied, so no remaining grant can be shown to be exercisable", ErrIdentityUnavailable)
		}
		seen := make(map[string]bool, len(remaining))
		for _, g := range remaining {
			if exists, ok := seen[g.UserID]; ok {
				if exists {
					return nil
				}
				continue
			}
			exists, err := r.UserExists(ctx, g.UserID)
			if err != nil {
				// Both are wrapped: the sentinel so a handler can classify the
				// refusal, and the resolver's own cause so an operator can see
				// what is actually down.
				return fmt.Errorf("%w: resolving remaining platform-admin grant %s: %w",
					ErrIdentityUnavailable, g.UserID, err)
			}
			seen[g.UserID] = exists
			if exists {
				return nil
			}
		}
		return ErrLastPlatformAdmin
	}
}
