// authority_reduction.go is the transactional authority reduction.
//
// This module owns BOTH organization_members and api_keys, so it is the only
// place in the suite where "take the authority away" and "invalidate the
// credentials that froze a snapshot of it" can be ONE transaction. Everywhere
// else the two halves are separate calls over separate connections, and a
// process that dies between them leaves the credential holding authority the
// membership no longer grants.
//
// # What was already here, and why it was not enough
//
// The pieces existed and were deliberately shaped to compose (#160/#162):
// RemoveAllMembershipsForUser returns the organizations it ACTUALLY emptied as
// an OrgScope, and RevokeAPIKeysForUser accepts exactly that type, so the sweep
// covers exactly where authority was withdrawn. Both consumers wrote that
// two-call composition, and both wrote it correctly. What neither could write
// is atomicity: terraform-registry-backend's internal/credlifecycle says so in
// its own package comment ("best-effort ... rather than atomic"), and
// terraform-state-manager-backend's internal/approles inverts the dependency
// into an AuthorityReducer func the mutation must take — which makes the sweep
// MANDATORY and its flavour explicit, but still runs it after the membership
// write has committed.
//
// This file does not replace either. approles.AuthorityReducer answers "you
// cannot express this mutation without also expressing its sweep"; Reducer
// answers "the mutation and its sweep cannot half-happen". An app adopts them
// independently, call site by call site, with no flag day: the plain repository
// methods are untouched and still compile.
//
// # What is NOT in the transaction, and cannot be
//
// The JWT revoke-all WATERMARK is not this module's table. identity owns the
// per-JTI denylist (revoked_tokens, see TokenRepository) but the per-user
// watermark both apps use for "end every session this principal holds" lives in
// each app's own schema — terraform-registry's user_token_revocations sits on
// the registry's connection, not the identity one. So the watermark reaches the
// transaction only through AppCredentials, which is handed the live *sql.Tx: an
// app whose watermark table is on the identity connection gets true atomicity
// for free, and an app whose watermark is elsewhere gets an explicit, greppable
// place where that limitation lives instead of an unwritten assumption.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// ErrNoReducer reports a Reducer used without a database handle. It is an error
// rather than a nil-receiver no-op because a no-op Reducer reduces nothing AND
// sweeps nothing while reporting success, which is the exact failure this file
// exists to make unreachable.
var ErrNoReducer = errors.New("store: authority reducer has no database handle")

// ErrNoCredentialDecision reports a reduction that supplied no AppCredentials.
//
// It is a SENTINEL rather than a bare error string because the refusal has to be
// identifiable: a test asserting only "some error came back" passes just as well
// when the reduction ran and failed for an unrelated reason, which is how a
// fail-closed guard is verified into existence without ever being verified.
var ErrNoCredentialDecision = errors.New("store: authority reduction supplied no AppCredentials decision")

// Reduced is what one reduction actually did.
//
// It is populated ONLY on the committed path: every failure returns the zero
// value alongside its error, so a caller that ignores the error cannot read a
// populated summary out of a transaction that rolled back. Organizations lists
// the organizations where authority was genuinely withdrawn — not the ones the
// caller asked about — which is the same distinction
// RemoveAllMembershipsForUser draws by returning a scope rather than a count.
type Reduced struct {
	// UserID is the principal whose authority was reduced.
	UserID string
	// Organizations are the organizations in which it was reduced, in the order
	// the reduction reported them. Empty means nothing moved.
	Organizations []string
	// KeysRevoked is how many api_keys rows were deleted.
	KeysRevoked int
	// KeysRetained is how many were deliberately left alone because every scope
	// they carry is still granted by the authority the principal kept. See
	// AuthorityRetained.
	KeysRetained int
}

// AppCredentials sweeps the credential families the APPLICATION owns, inside
// the reduction's transaction.
//
// It is handed the live *sql.Tx on purpose. A writer that opens its own
// connection instead gets the best-effort semantics this file exists to
// replace; a writer that uses the tx commits or rolls back with the membership
// change itself.
//
// AN ERROR ROLLS THE WHOLE REDUCTION BACK. That is the fail-closed direction:
// the alternative — committing the reduction and reporting an incomplete sweep,
// which is what both consumers do today — is precisely the state where a
// credential outlives the authority behind it. A reduction whose credential
// sweep fails must not report success, so it does not happen at all and the
// caller retries.
//
// It is NOT called when nothing was reduced. See Reducer.
type AppCredentials func(ctx context.Context, tx *sql.Tx, red Reduced) error

// NoAppCredentials is the DELIBERATE opt-out: this application has no
// credential family of its own to invalidate here.
//
// It exists because nil must not mean "no sweep needed". A nil AppCredentials
// is a caller that did not decide, and an optional guard is how a guard goes
// silently absent — the same reasoning platformadmin applies to a nil floor
// predicate and approles applies to a nil AuthorityReducer. Passing this
// function by name puts the decision in the diff.
//
// It is also the shape the IdP group-mapping deprovision path REQUIRES, and
// that requirement is a correctness constraint rather than a preference. That
// code runs microseconds before the same request mints a fresh session token. A
// revoke-all watermark is written at full precision while a JWT `iat` is
// floored to the second (RFC 7519), so a watermark set in the same second as
// the token being issued resolves toward "revoked" and the user can never log
// in. Those call sites sweep the API-key family — which this file does, in the
// transaction — and must NOT move the watermark, which is exactly what naming
// this function says.
func NoAppCredentials(context.Context, *sql.Tx, Reduced) error { return nil }

// Reducer performs an authority reduction and the invalidation of the
// credentials derived from it as one transaction.
//
// # The transaction boundary
//
// BEGIN, then, in order:
//
//  1. the reduction itself — the same statement, with the same OrgScope
//     predicate and the same ErrNotFound semantics, that the corresponding
//     repository method issues;
//  2. the retained-authority lookup, re-derived from the rows that SURVIVED
//     step 1 rather than computed by the caller beforehand (a caller-computed
//     "retained" set is read before the write and can be stale by the time the
//     write lands);
//  3. SELECT ... FOR UPDATE over the principal's api_keys rows in the affected
//     organizations, so a concurrent transaction cannot mint or re-scope one
//     between the read and the delete;
//  4. DELETE of the keys whose frozen scopes are no longer retained;
//  5. AppCredentials, for the families this module does not own.
//
// COMMIT. Any failure at any step rolls all of it back: the membership is
// intact and so are the credentials, which is consistent — the principal holds
// exactly what they held before the call, and the caller retries. The state the
// issue describes, membership gone and credentials alive, is unreachable.
//
// # Nothing reduced means nothing swept
//
// When the reduction reports no affected organizations — only the bulk
// RemoveAllMembershipsForUser can, since the by-identifier methods report
// ErrNotFound instead — steps 2 to 5 are SKIPPED and the transaction commits.
// This is approles' authorityChanged=false case, and skipping is not an
// optimisation: AppCredentials is where a platform-wide per-user watermark
// moves, and moving it for a reduction that did not happen ends every session
// that principal holds, everywhere, for no security benefit.
//
// # What it does NOT cover
//
// The role-template family: RoleTemplateRepository.UpdateRoleTemplate and
// DeleteRoleTemplate also reduce derived authority, for every membership
// holding the template rather than for one principal. That sweep belongs in a
// bounded reconciliation rather than an in-request transaction holding locks on
// most of two tables, and is tracked separately as issue #282. The inventory
// guard in authority_reduction_class_test.go records both as exempt with that
// reason, so neither can go unnoticed.
//
// # Wanting the reduction WITHOUT the invalidation
//
// Call the repository method. OrganizationRepository.RemoveMember and its
// siblings are unchanged and still exported; a Reducer is a different symbol,
// so choosing the un-swept reduction is a visible choice in the source rather
// than a forgotten argument. Within a Reducer the only opt-out is
// NoAppCredentials, and it opts out of the app-owned families only — the
// api_keys sweep is what a Reducer IS.
type Reducer struct {
	db *sql.DB
	// rwPairs is the application's read/write scope grammar, used by
	// AuthorityRetained to decide whether a key's frozen scopes are still
	// covered.
	//
	// MANDATORY, and nil is safe rather than convenient: with no pairs,
	// write-implies-read does not apply, so a key carrying "modules:read" is
	// NOT retained under a surviving "modules:write" and is deleted. That
	// over-revokes — it destroys a working credential, and an API key's secret
	// is shown once and is not recoverable — but it never under-revokes, so a
	// caller that gets this wrong loses availability and not containment.
	rwPairs auth.ReadWritePairs
}

// NewReducer builds a Reducer over the identity connection.
//
// db must be the connection organization_members and api_keys live on; they are
// in the same schema, which is what makes the single transaction possible at
// all. rwPairs is the application's scope grammar (see Reducer.rwPairs) — the
// same value it passes to OrganizationRepository.OrgScopeForUser.
func NewReducer(db *sql.DB, rwPairs auth.ReadWritePairs) *Reducer {
	return &Reducer{db: db, rwPairs: rwPairs}
}

// AuthorityRetained reports whether every scope in have is still granted by
// retained — whether a credential frozen with `have` asks for no more than the
// principal currently holds.
//
// This is the difference between "the authority changed" and "the authority was
// REDUCED", and a sweep must key off the latter: deleting API keys is
// irreversible, so sweeping on an increase, or on a mere reordering of an
// unchanged scope list, destroys working credentials fleet-wide for no security
// benefit.
//
// Comparison is by scope SEMANTICS, not slice identity: auth.HasScope resolves
// the admin wildcard and the read/write implication, so ["modules:read"] is
// retained under ["modules:write"] and everything is retained under ["admin"].
// An empty `retained` grants nothing, so any credential carrying at least one
// scope is not retained; a credential with no scopes grants nothing and is
// vacuously retained.
//
// It is exported because terraform-registry-backend already wrote it
// (internal/credlifecycle) and terraform-state-manager-backend needs it: a
// predicate that decides which credentials get destroyed is the last thing that
// should exist in two hand-copies, which is the argument this whole file makes.
func AuthorityRetained(have, retained []string, rwPairs auth.ReadWritePairs) bool {
	for _, s := range have {
		if !auth.HasScope(retained, s, rwPairs) {
			return false
		}
	}
	return true
}

// RemoveMember removes a user from an organization and invalidates the
// credentials that organization's membership backed, in one transaction.
//
// Same contract as OrganizationRepository.RemoveMember for the reduction half:
// scoped, and an error wrapping ErrNotFound when that user is not a member of
// that organization — reported BEFORE anything is swept, and rolling the
// transaction back, so "member removed" is never recorded for a no-op.
func (r *Reducer) RemoveMember(ctx context.Context, orgID, userID string, scope OrgScope, app AppCredentials) (Reduced, error) {
	if scope.MatchesNothing() {
		return Reduced{}, notFound("organization member")
	}
	return r.run(ctx, userID, app, func(ctx context.Context, tx *sql.Tx) ([]string, error) {
		// GUARD org-scope-membership-delete (issues #138, #162).
		query := `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`
		args := []interface{}{orgID, userID}
		query, args = andScope(query, scope, "organization_id", args)

		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to remove member: %w", err)
		}
		if err := requireRow(res, "organization member"); err != nil {
			return nil, err
		}
		return []string{orgID}, nil
	})
}

// UpdateMemberRoleTemplate changes a user's role template in an organization
// and invalidates the credentials whose frozen scopes the new template no
// longer grants, in one transaction.
//
// The retained set is the NEW template's scopes, read back inside the
// transaction from the row the UPDATE just wrote — not supplied by the caller.
// A reassignment that WIDENS authority therefore deletes nothing, and a key
// still covered by the narrower role survives; see AuthorityRetained.
//
// A nil roleTemplateID sets "no role template", which the membership
// projections read as no scopes at all. Nothing is retained, so every key the
// principal holds in that organization goes.
func (r *Reducer) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope OrgScope, app AppCredentials) (Reduced, error) {
	if scope.MatchesNothing() {
		return Reduced{}, notFound("organization member")
	}
	return r.run(ctx, userID, app, func(ctx context.Context, tx *sql.Tx) ([]string, error) {
		// GUARD org-scope-membership-update (issue #138).
		query := `
		UPDATE organization_members
		SET role_template_id = $3
		WHERE organization_id = $1 AND user_id = $2
	`
		args := []interface{}{orgID, userID, roleTemplateID}
		query, args = andScope(query, scope, "organization_id", args)

		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to update member role template: %w", err)
		}
		if err := requireRow(res, "organization member"); err != nil {
			return nil, err
		}
		return []string{orgID}, nil
	})
}

// UpdateMemberRole is UpdateMemberRoleTemplate by template NAME.
//
// The name is resolved INSIDE the transaction, unlike
// OrganizationRepository.UpdateMemberRole which resolves it on the pool: a
// template deleted between the lookup and the update would otherwise leave the
// membership pointing at a row that no longer exists.
func (r *Reducer) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string, scope OrgScope, app AppCredentials) (Reduced, error) {
	if scope.MatchesNothing() {
		return Reduced{}, notFound("organization member")
	}
	return r.run(ctx, userID, app, func(ctx context.Context, tx *sql.Tx) ([]string, error) {
		id, err := lookupRoleTemplateID(ctx, tx, roleTemplateName)
		if err != nil {
			return nil, err
		}

		// GUARD org-scope-membership-update (issue #138).
		query := `
		UPDATE organization_members
		SET role_template_id = $3
		WHERE organization_id = $1 AND user_id = $2
	`
		args := []interface{}{orgID, userID, id}
		query, args = andScope(query, scope, "organization_id", args)

		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to update member role template: %w", err)
		}
		if err := requireRow(res, "organization member"); err != nil {
			return nil, err
		}
		return []string{orgID}, nil
	})
}

// RemoveAllMembershipsForUser removes a user from every organization inside
// scope and invalidates the credentials those memberships backed, in one
// transaction.
//
// This is the SCIM-deprovisioning shape, and it is the one the issue is really
// about: the two-call composition it replaces is documented on
// RevokeAPIKeysForUser and is correct in every respect except that a crash
// between the two calls strands the credentials.
//
// Bulk, so removing nothing is not an error. Removing nothing also means
// nothing is swept and AppCredentials is not called — no authority was reduced
// anywhere, so there is nothing derived from it to invalidate.
func (r *Reducer) RemoveAllMembershipsForUser(ctx context.Context, userID string, scope OrgScope, app AppCredentials) (Reduced, error) {
	if scope.MatchesNothing() {
		return Reduced{UserID: userID}, nil
	}
	return r.run(ctx, userID, app, func(ctx context.Context, tx *sql.Tx) ([]string, error) {
		// GUARD org-scope-membership-sweep (issues #160, #162).
		query := `DELETE FROM organization_members WHERE user_id = $1`
		args := []interface{}{userID}
		query, args = andScope(query, scope, "organization_id", args)
		query += ` RETURNING organization_id`

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to remove all memberships for user %s: %w", userID, err)
		}
		defer func() { _ = rows.Close() }()

		removed := make([]string, 0)
		for rows.Next() {
			var orgID string
			if err := rows.Scan(&orgID); err != nil {
				return nil, fmt.Errorf("failed to scan removed membership for user %s: %w", userID, err)
			}
			removed = append(removed, orgID)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to remove all memberships for user %s: %w", userID, err)
		}
		return removed, nil
	})
}

// run is the transaction boundary every reduction shares. See Reducer.
func (r *Reducer) run(ctx context.Context, userID string, app AppCredentials, reduce func(context.Context, *sql.Tx) ([]string, error)) (Reduced, error) {
	if r == nil || r.db == nil {
		return Reduced{}, ErrNoReducer
	}
	// FAIL-CLOSED ON A MISSING DECISION. nil is not "this application has no
	// credential family"; NoAppCredentials is. Refusing here is what stops a
	// reduction from silently leaving an app-owned credential live.
	if app == nil {
		return Reduced{}, fmt.Errorf("%w for user %s: pass store.NoAppCredentials to state that this "+
			"application has no credential family of its own to invalidate", ErrNoCredentialDecision, userID)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Reduced{}, fmt.Errorf("failed to begin authority reduction for user %s: %w", userID, err)
	}
	// Unconditional: Rollback after a successful Commit is a no-op
	// (sql.ErrTxDone), and this is what makes every early return below a
	// rollback without each one having to remember.
	defer func() { _ = tx.Rollback() }()

	orgIDs, err := reduce(ctx, tx)
	if err != nil {
		return Reduced{}, err
	}

	red := Reduced{UserID: userID, Organizations: orgIDs}
	if len(orgIDs) > 0 {
		if err := r.sweepDerivedKeys(ctx, tx, &red); err != nil {
			return Reduced{}, err
		}
		if err := app(ctx, tx, red); err != nil {
			return Reduced{}, fmt.Errorf("failed to invalidate application credentials for user %s: %w", userID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return Reduced{}, fmt.Errorf("failed to commit authority reduction for user %s: %w", userID, err)
	}
	return red, nil
}

// sweepDerivedKeys deletes, inside tx, every api_keys row red.UserID holds in
// red.Organizations whose frozen scopes the principal's SURVIVING authority no
// longer grants.
//
// Keys with a NULL user_id are organization SERVICE credentials and are not
// derived from anybody's membership, so `user_id = $1` leaves them alone —
// which is the reading migration 000007 made load-bearing when it stopped a
// user delete from manufacturing them.
func (r *Reducer) sweepDerivedKeys(ctx context.Context, tx *sql.Tx, red *Reduced) error {
	retained, err := r.retainedScopes(ctx, tx, red.UserID, red.Organizations)
	if err != nil {
		return err
	}

	// FOR UPDATE: the decision below is made in Go from these rows, so they
	// must not change between the read and the delete. Without the lock a
	// concurrently re-scoped key could be evaluated against its old scopes and
	// kept.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, organization_id, scopes
		FROM api_keys
		WHERE user_id = $1 AND organization_id = ANY($2)
		FOR UPDATE`, red.UserID, red.Organizations)
	if err != nil {
		return fmt.Errorf("failed to read derived api keys for user %s: %w", red.UserID, err)
	}

	var doomed []string
	kept := 0
	err = func() error {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, orgID string
			var scopesJSON []byte
			if err := rows.Scan(&id, &orgID, &scopesJSON); err != nil {
				return fmt.Errorf("failed to scan derived api key for user %s: %w", red.UserID, err)
			}
			var have []string
			if err := json.Unmarshal(scopesJSON, &have); err != nil {
				return fmt.Errorf("failed to unmarshal api key scopes for user %s: %w", red.UserID, err)
			}
			if AuthorityRetained(have, retained[orgID], r.rwPairs) {
				kept++
				continue
			}
			doomed = append(doomed, id)
		}
		return rows.Err()
	}()
	if err != nil {
		return fmt.Errorf("failed to read derived api keys for user %s: %w", red.UserID, err)
	}

	red.KeysRetained = kept
	if len(doomed) == 0 {
		return nil
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ANY($1)`, doomed)
	if err != nil {
		return fmt.Errorf("failed to revoke derived api keys for user %s: %w", red.UserID, err)
	}
	n, err := affectedRows(res, "derived api keys")
	if err != nil {
		return err
	}
	// The rows were selected FOR UPDATE in this transaction, so the DELETE must
	// match every one of them. Fewer means the statement is not deleting what
	// the decision was made about, and reporting a partial sweep as a complete
	// one is the defect this file exists to close — so it aborts the whole
	// reduction rather than returning a count nobody checks.
	if n != int64(len(doomed)) {
		return fmt.Errorf("store: authority reduction for user %s selected %d derived api keys but deleted %d",
			red.UserID, len(doomed), n)
	}
	red.KeysRevoked = int(n)
	return nil
}

// retainedScopes reads, inside tx and AFTER the reduction, the scopes the
// principal still holds in each of orgIDs.
//
// An organization absent from the result is one where the membership is gone,
// which is nil — nothing retained — and NOT an error: that is the ordinary
// outcome of a removal, and treating a missing row as a fault would make the
// commonest reduction the one that always fails.
func (r *Reducer) retainedScopes(ctx context.Context, tx *sql.Tx, userID string, orgIDs []string) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT om.organization_id, COALESCE(rt.scopes, '[]'::jsonb)
		FROM organization_members om
		LEFT JOIN role_templates rt ON rt.id = om.role_template_id
		WHERE om.user_id = $1 AND om.organization_id = ANY($2)`, userID, orgIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to read retained authority for user %s: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	retained := make(map[string][]string, len(orgIDs))
	for rows.Next() {
		var orgID string
		var scopesJSON []byte
		if err := rows.Scan(&orgID, &scopesJSON); err != nil {
			return nil, fmt.Errorf("failed to scan retained authority for user %s: %w", userID, err)
		}
		var scopes []string
		if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal retained authority for user %s: %w", userID, err)
		}
		retained[orgID] = scopes
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read retained authority for user %s: %w", userID, err)
	}
	return retained, nil
}
