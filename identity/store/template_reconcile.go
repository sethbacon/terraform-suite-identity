// template_reconcile.go is the bounded, resumable reconciliation for the
// role-template family (issue #282).
//
// It lives beside authority_reduction.go, in package store, rather than in a
// subpackage. Two reasons: it reuses AuthorityRetained directly with no import
// boundary between the predicate and its caller, and it follows the precedent
// audit_sweep.go already set for a bounded sweep primitive that is not a
// Reducer method — a sibling file in this package, not a package of its own.
//
// # Why this is not a Reducer method
//
// Reducer makes ONE principal's authority change and its credential sweep one
// transaction. A role-template edit or delete reduces authority for EVERY
// membership holding the template — a seeded template ("admin", "viewer") can
// mean most of organization_members and most of api_keys. Doing that the way
// Reducer does it would mean SELECT ... FOR UPDATE across most of api_keys,
// held for the duration of one interactive request. The failure mode of
// getting that wrong is not a stranded credential, it is a fleet-wide
// credential destruction event, irreversible because an API key's secret is
// shown once. That is a decision an operator should be able to see and bound,
// not a side effect of saving a form — hence bounded batches, not one
// transaction, and a preview before any of it runs.
//
// # The ordering this file depends on, and why
//
// PreviewRoleTemplateReconciliation and ReconcileRoleTemplate both read
// `organization_members WHERE role_template_id = $1` — the set of principals
// CURRENTLY holding the template. That predicate is only meaningful BEFORE
// RoleTemplateRepository.DeleteRoleTemplate runs: its ON DELETE SET NULL
// cascade rewrites every one of those rows to role_template_id = NULL in the
// SAME statement that removes the template row, so there is no "after" moment
// at which "who held this template" is answerable from the database at all.
//
// Both functions therefore take the PROPOSED scopes as an explicit argument —
// nil or empty meaning "about to be deleted", the same reading
// organization_members.role_template_id = NULL already carries everywhere else
// in this package (migration 000007's own comment: NULL there is strictly
// less authority, not a re-homing). Neither function reads
// role_templates.scopes. That is what makes it possible to call them BEFORE
// RoleTemplateRepository.UpdateRoleTemplate / DeleteRoleTemplate, with the
// values about to be written, and get the same answer either function would
// give if the write had already landed. The required order is: preview, run
// ReconcileRoleTemplate to completion, THEN mutate. Running it the other way
// round is not merely unnecessary, it is silently wrong for a delete: the
// predicate this file reads has already been erased by the cascade, and
// Scanned == 0 is indistinguishable from a template that never had a member.
//
// THAT ORDER IS NO LONGER A SENTENCE A CONSUMER HAS TO FOLLOW. TemplateWriter
// in template_write.go composes the two so the mutation cannot be expressed
// without the sweep, cannot run before it, and cannot run at all if the sweep
// did not finish. This file remains the primitive underneath — callable
// directly by an application reconciling on its own schedule, which is what
// the preview endpoint in terraform-registry-backend does.
//
// A membership added to the template between a completed reconciliation and
// the mutation that follows it is a real, accepted gap — resumability is
// bought by NOT holding one transaction across the whole sweep, and that is
// the price. Closing it is the caller's decision (re-run before mutating, or
// re-run periodically after); this file only guarantees that every run it is
// given time to finish never leaves a key alive that its own predicate
// identified as unretained.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// ErrNoTemplateReconciler reports a call with no database handle. An error
// rather than a nil-op for the same reason Reducer's ErrNoReducer is: a
// no-op here would report zero impact and sweep zero keys, which is exactly
// what a genuinely empty template also reports — the two must not share a
// code path that can be reached by an omitted handle.
var ErrNoTemplateReconciler = errors.New("store: role-template reconciliation has no database handle")

// TemplateAffected identifies one organization_members row — an
// (organization, user) pair — currently holding the role template being
// reconciled.
type TemplateAffected struct {
	OrganizationID string
	UserID         string
}

// TemplateReconcileImpact is what a proposed role-template change WOULD sweep,
// computed without writing anything.
type TemplateReconcileImpact struct {
	// Scanned is how many (organization, user) pairs currently hold the
	// template — the size of the universe this Impact was computed over,
	// regardless of whether they hold any api_keys at all.
	//
	// It exists so a template with genuinely no members (Scanned == 0) is
	// distinguishable from a query that read nothing because it was pointed
	// at the wrong template, the wrong table, or never ran — which is the
	// estate's recurring failure mode. PreviewRoleTemplateReconciliation
	// always issues its query and reports the count it got, even when that
	// count is zero.
	Scanned int
	// Principals is how many DISTINCT (organization, user) pairs hold at
	// least one api_keys row that AuthorityRetained refuses under the
	// proposed scopes.
	Principals int
	// Keys is the total number of api_keys rows across those principals —
	// exactly what ReconcileRoleTemplate would delete if run to completion
	// against the SAME templateID and proposedScopes right now.
	Keys int
}

// TemplateReconcileResult is what one call to ReconcileRoleTemplate actually
// did.
type TemplateReconcileResult struct {
	// BatchesRun is how many transactions this call opened and committed —
	// including a batch that found nothing, so a genuinely empty template
	// (BatchesRun == 1, PrincipalsChecked == 0) is distinguishable from a call
	// that returned without ever touching the database.
	BatchesRun int
	// PrincipalsChecked is how many (organization, user) pairs were read and
	// evaluated across every batch this call ran — including ones whose keys
	// all turned out to be retained, and ones whose current membership no
	// longer points at templateID (see AuthorityRetained re-verification,
	// below).
	PrincipalsChecked int
	// KeysSwept is how many api_keys rows this call deleted.
	KeysSwept int
	// KeysSpared is how many api_keys rows this call examined and
	// deliberately left alone because AuthorityRetained found them still
	// covered.
	KeysSpared int
	// Cursor is where to resume: the last principal a completed batch
	// examined, in the (organization_id, user_id) ordering this sweep uses.
	// nil means either nothing has run yet or the reconciliation reached the
	// end of the template's membership — Done distinguishes the two.
	Cursor *TemplateAffected
	// Done reports whether this run reached the end of the template's
	// membership. false means ctx was cancelled or MaxBatches was reached
	// before every principal holding the template was checked; resume by
	// passing Cursor as the next call's After.
	Done bool
}

// ReconcileOptions configures one call to ReconcileRoleTemplate.
type ReconcileOptions struct {
	// BatchSize is how many principals ONE batch's transaction examines.
	// Required — see the error ReconcileRoleTemplate returns without one.
	// This module deliberately has no default: the whole point of a bounded
	// sweep is that the caller has sized the transaction it is willing to
	// run, not inherited a number nobody chose for this deployment's table
	// sizes.
	BatchSize int
	// MaxBatches bounds how many batches THIS CALL runs before returning,
	// 0 meaning "until Done or ctx is cancelled". It is a second, explicit
	// stop condition independent of ctx — for a caller that wants "N batches,
	// then yield back to the scheduler" without wiring a context deadline.
	MaxBatches int
	// After resumes a previous, incomplete run: pass the Cursor a prior
	// Result returned. nil starts from the beginning of the template's
	// membership.
	After *TemplateAffected
}

// PreviewRoleTemplateReconciliation reports, without writing anything, how
// many principals and api_keys a reconciliation of templateID against
// proposedScopes would sweep.
//
// proposedScopes is the scope list the template is ABOUT TO carry — nil or
// empty for "about to be deleted". See the package doc for why this is a
// parameter rather than a read of role_templates.scopes, and why this must be
// called before RoleTemplateRepository.DeleteRoleTemplate to mean anything.
//
// This is a plain read: no FOR UPDATE, no transaction, no locks held beyond
// each row's own read. It streams the join and accumulates counts rather than
// materialising the row set, so it is safe to call against a template with an
// unbounded number of members — unlike ReconcileRoleTemplate, it needs no
// batching of its own, because nothing here can block a writer.
//
// This does NOT share a query with ReconcileRoleTemplate — the sweep plans and
// locks in separate, batched statements a live transaction needs and this read
// does not. What the two share, and what actually has to agree, is narrower
// and just as load-bearing: the same `role_template_id = $1` predicate against
// organization_members, and the identical AuthorityRetained(have,
// proposedScopes, rwPairs) call judging each key. Neither this file nor its
// tests re-derive that predicate or reimplement retention — see
// TestIntegrationPreviewAgreesWithTheRealSweep, which runs both against one
// live fixture and fails by name if a change to either statement's WHERE
// clause, or to which AuthorityRetained call a mutation reaches, makes them
// disagree.
func PreviewRoleTemplateReconciliation(ctx context.Context, db *sql.DB, templateID string, proposedScopes []string, rwPairs auth.ReadWritePairs) (TemplateReconcileImpact, error) {
	if db == nil {
		return TemplateReconcileImpact{}, ErrNoTemplateReconciler
	}
	if templateID == "" {
		return TemplateReconcileImpact{}, fmt.Errorf("role-template reconciliation preview: empty template id")
	}

	rows, err := db.QueryContext(ctx, templateAffectedWithKeysQuery, templateID)
	if err != nil {
		return TemplateReconcileImpact{}, fmt.Errorf("role-template reconciliation preview: reading membership for template %s: %w", templateID, err)
	}
	defer func() { _ = rows.Close() }()

	var impact TemplateReconcileImpact
	scanned := make(map[TemplateAffected]struct{})
	doomed := make(map[TemplateAffected]struct{})
	for rows.Next() {
		principal, have, hasKey, serr := scanTemplateAffectedWithKey(rows)
		if serr != nil {
			return TemplateReconcileImpact{}, fmt.Errorf("role-template reconciliation preview: %w", serr)
		}
		scanned[principal] = struct{}{}
		if !hasKey {
			continue
		}
		if AuthorityRetained(have, proposedScopes, rwPairs) {
			continue
		}
		impact.Keys++
		doomed[principal] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return TemplateReconcileImpact{}, fmt.Errorf("role-template reconciliation preview: %w", err)
	}

	impact.Scanned = len(scanned)
	impact.Principals = len(doomed)
	return impact, nil
}

// templateAffectedWithKeysQuery reads every (organization, user) pair holding
// templateID, LEFT JOINed to their api_keys.
//
// LEFT JOIN, not JOIN: a principal with zero api_keys must still produce a row
// (with NULL key columns) so Scanned counts them, rather than being invisible
// to a preview the way it would be with an inner join.
//
// The join key is (organization_id, user_id) on BOTH sides, so a NULL
// api_keys.user_id (an organization SERVICE credential, derived from nobody's
// membership) can never match — the same exclusion sweepDerivedKeys documents
// for the same reason: NULL never equals a NOT NULL organization_members.user_id.
const templateAffectedWithKeysQuery = `
	SELECT om.organization_id, om.user_id, ak.id, ak.scopes
	FROM organization_members om
	LEFT JOIN api_keys ak
	  ON ak.organization_id = om.organization_id AND ak.user_id = om.user_id
	WHERE om.role_template_id = $1
	ORDER BY om.organization_id, om.user_id`

// templateRowScanner is the subset of *sql.Rows this file scans through,
// shared by the plain *sql.Rows the preview reads and (identically) the ones
// a batch reads inside its transaction.
type templateRowScanner interface {
	Scan(dest ...interface{}) error
}

// scanTemplateAffectedWithKey scans one row of templateAffectedWithKeysQuery.
// hasKey is false when the LEFT JOIN found no api_keys row for this principal;
// have is nil in that case.
func scanTemplateAffectedWithKey(row templateRowScanner) (principal TemplateAffected, have []string, hasKey bool, err error) {
	var keyID sql.NullString
	var scopesJSON []byte
	if err := row.Scan(&principal.OrganizationID, &principal.UserID, &keyID, &scopesJSON); err != nil {
		return TemplateAffected{}, nil, false, fmt.Errorf("scanning affected principal: %w", err)
	}
	if !keyID.Valid {
		return principal, nil, false, nil
	}
	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &have); err != nil {
			return TemplateAffected{}, nil, false, fmt.Errorf("unmarshalling api key scopes: %w", err)
		}
	}
	return principal, have, true, nil
}

// ReconcileRoleTemplate sweeps api_keys for the principals holding templateID
// whose frozen scopes proposedScopes no longer covers (see
// PreviewRoleTemplateReconciliation for what proposedScopes means), in batches
// of opts.BatchSize principals, EACH BATCH ITS OWN TRANSACTION.
//
// # Batching: keyset, not OFFSET
//
// Each batch reads the next page of (organization_id, user_id) pairs ordered
// by that tuple, strictly after opts.After (or from the start when nil), via
// LIMIT with no OFFSET. OFFSET pagination re-scans and discards the skipped
// prefix on every page — increasingly expensive as the sweep progresses
// through a large template — and, more importantly, is defined over the
// query's result at the instant it runs: a row inserted or removed ahead of
// the current OFFSET shifts every row after it, so a concurrently-modified
// table can skip or repeat a principal across batches. organization_members is
// not being deleted by this sweep (only api_keys rows are), so the specific
// hazard is smaller here than it would be for a self-deleting table, but
// keyset pagination is the same cost as OFFSET to implement and has neither
// failure mode, so there is no reason to accept it.
//
// # What one batch's transaction does
//
// BEGIN; read the next page of principals; for that page, SELECT their
// api_keys FOR UPDATE, re-joined to organization_members so a principal whose
// CURRENT role_template_id no longer names templateID (reassigned by a
// concurrent edit since the page was planned) is excluded from the lock and
// from the sweep rather than judged against a template it no longer holds;
// evaluate AuthorityRetained per key; DELETE the unretained ones; COMMIT.
//
// A principal whose retained authority still covers what their existing keys
// ask for is left alone, even inside a run that is sweeping other principals
// for the same template edit — that is AuthorityRetained's job, re-run fresh
// for every batch rather than decided once up front.
//
// # Stopping and resuming
//
// ctx is checked before each batch begins, and opts.MaxBatches (if nonzero)
// bounds how many batches this one call runs. Either stopping a run always
// happens AT A BATCH BOUNDARY: the batch in flight when a stop condition is
// noticed has already committed by the time this function checks again, and
// no batch is ever half-applied. A stopped run returns Done == false and a
// non-nil Cursor; call again with that Cursor as the next opts.After to
// continue. This is not treated as an error — being asked to stop partway is
// the primitive doing exactly what a BOUNDED sweep is for.
func ReconcileRoleTemplate(ctx context.Context, db *sql.DB, templateID string, proposedScopes []string, rwPairs auth.ReadWritePairs, opts ReconcileOptions) (TemplateReconcileResult, error) {
	if db == nil {
		return TemplateReconcileResult{}, ErrNoTemplateReconciler
	}
	if templateID == "" {
		return TemplateReconcileResult{}, fmt.Errorf("role-template reconciliation: empty template id")
	}
	if opts.BatchSize <= 0 {
		return TemplateReconcileResult{}, fmt.Errorf("role-template reconciliation: BatchSize must be positive, got %d", opts.BatchSize)
	}

	var result TemplateReconcileResult
	cursor := opts.After

	for {
		if err := ctx.Err(); err != nil {
			result.Done = false
			result.Cursor = cursor
			return result, nil
		}
		if opts.MaxBatches > 0 && result.BatchesRun >= opts.MaxBatches {
			result.Done = false
			result.Cursor = cursor
			return result, nil
		}

		page, swept, spared, err := reconcileOneBatch(ctx, db, templateID, proposedScopes, rwPairs, opts.BatchSize, cursor)
		if err != nil {
			return TemplateReconcileResult{}, err
		}

		result.BatchesRun++
		result.PrincipalsChecked += len(page)
		result.KeysSwept += swept
		result.KeysSpared += spared

		if len(page) == 0 {
			result.Done = true
			result.Cursor = nil
			return result, nil
		}
		cursor = &page[len(page)-1]

		if len(page) < opts.BatchSize {
			// A partial page is the last page: keyset pagination has no more
			// rows past this one to return next time. Cursor stays nil — Done
			// already means "nothing to resume", and reporting a non-nil
			// Cursor here as well would be a second, contradictory answer to
			// the same question.
			result.Done = true
			result.Cursor = nil
			return result, nil
		}
	}
}

// reconcileOneBatch runs exactly one batch — one transaction — of the sweep:
// plan a page of principals, lock and evaluate their api_keys, delete the
// unretained ones, commit. Returns the page it planned (possibly empty) and
// what it swept/spared within it.
func reconcileOneBatch(ctx context.Context, db *sql.DB, templateID string, proposedScopes []string, rwPairs auth.ReadWritePairs, batchSize int, after *TemplateAffected) (page []TemplateAffected, swept, spared int, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("role-template reconciliation: beginning batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	page, err = planBatch(ctx, tx, templateID, after, batchSize)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(page) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, 0, 0, fmt.Errorf("role-template reconciliation: committing empty batch: %w", err)
		}
		return page, 0, 0, nil
	}

	swept, spared, err = sweepBatchKeys(ctx, tx, templateID, proposedScopes, rwPairs, page)
	if err != nil {
		return nil, 0, 0, err
	}

	if err := tx.Commit(); err != nil {
		return nil, 0, 0, fmt.Errorf("role-template reconciliation: committing batch: %w", err)
	}
	return page, swept, spared, nil
}

// planBatchQuery and planBatchQueryAfter read the next page of principals
// holding templateID, ordered for keyset pagination. Two statements rather
// than one built with an optional predicate: the cursor predicate binds two
// extra parameters ($2, $3) ahead of the LIMIT, and the shape is fixed and
// small enough that a runtime-assembled WHERE clause would buy nothing but
// another thing to get wrong.
const planBatchQuery = `
	SELECT organization_id, user_id
	FROM organization_members
	WHERE role_template_id = $1
	ORDER BY organization_id, user_id
	LIMIT $2`

const planBatchQueryAfter = `
	SELECT organization_id, user_id
	FROM organization_members
	WHERE role_template_id = $1 AND (organization_id, user_id) > ($2, $3)
	ORDER BY organization_id, user_id
	LIMIT $4`

// planBatch reads inside tx so the page it returns and the FOR UPDATE read
// that follows share one transaction — not because the page read itself needs
// a lock (nothing here writes organization_members), but because it keeps the
// whole batch's decision-making inside the boundary that commits or rolls
// back as a unit.
func planBatch(ctx context.Context, tx *sql.Tx, templateID string, after *TemplateAffected, batchSize int) ([]TemplateAffected, error) {
	var rows *sql.Rows
	var err error
	if after == nil {
		rows, err = tx.QueryContext(ctx, planBatchQuery, templateID, batchSize)
	} else {
		rows, err = tx.QueryContext(ctx, planBatchQueryAfter, templateID, after.OrganizationID, after.UserID, batchSize)
	}
	if err != nil {
		return nil, fmt.Errorf("role-template reconciliation: planning batch for template %s: %w", templateID, err)
	}
	defer func() { _ = rows.Close() }()

	page := make([]TemplateAffected, 0, batchSize)
	for rows.Next() {
		var p TemplateAffected
		if err := rows.Scan(&p.OrganizationID, &p.UserID); err != nil {
			return nil, fmt.Errorf("role-template reconciliation: scanning planned principal: %w", err)
		}
		page = append(page, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("role-template reconciliation: planning batch for template %s: %w", templateID, err)
	}
	return page, nil
}

// batchKeysQuery locks and reads the api_keys rows belonging to exactly the
// principals in one planned batch, RE-VERIFYING against the live
// organization_members row that each one still holds templateID.
//
// The re-verification is the tie-breaker this module is biased toward: a
// principal reassigned to a different template (or removed) between planBatch
// and this statement — even within the same transaction, under the default
// READ COMMITTED isolation each statement sees a fresh snapshot — is excluded
// from the join and therefore untouched, rather than swept against a template
// it no longer holds.
//
// The batch is passed as two parallel arrays zipped by unnest, joined through
// a subquery rather than a named CTE: a `JOIN <name>` for a CTE would be
// picked up by identity/store's own table-inventory scan
// (authority_reduction_class_test.go's sibling, schema_routing_class_test.go)
// as a reference to a table named "batch" that no migration creates. A `JOIN
// (SELECT …) b` is syntactically invisible to that scanner because it looks
// for a bare identifier after JOIN, not an opening parenthesis.
//
// Explicit ::uuid[] casts on both unnest arguments: unlike `column = ANY($n)`
// elsewhere in this package, there is no column on the other side of `=` at
// parse time to infer the parameter type from, so an unnest with unadorned
// parameters would leave Postgres nothing to infer VOID array element types
// from. The cast removes the ambiguity outright rather than relying on
// inference succeeding.
const batchKeysQuery = `
	SELECT ak.id, ak.organization_id, ak.user_id, ak.scopes
	FROM api_keys ak
	JOIN (
		SELECT unnest($1::uuid[]) AS organization_id, unnest($2::uuid[]) AS user_id
	) b ON b.organization_id = ak.organization_id AND b.user_id = ak.user_id
	JOIN organization_members om
	  ON om.organization_id = ak.organization_id AND om.user_id = ak.user_id
	WHERE om.role_template_id = $3
	FOR UPDATE OF ak`

// sweepBatchKeys locks, evaluates and deletes the unretained api_keys for one
// planned page, inside tx. Returns how many were swept and how many were
// deliberately spared.
func sweepBatchKeys(ctx context.Context, tx *sql.Tx, templateID string, proposedScopes []string, rwPairs auth.ReadWritePairs, page []TemplateAffected) (swept, spared int, err error) {
	orgIDs := make([]string, len(page))
	userIDs := make([]string, len(page))
	for i, p := range page {
		orgIDs[i] = p.OrganizationID
		userIDs[i] = p.UserID
	}

	rows, err := tx.QueryContext(ctx, batchKeysQuery, orgIDs, userIDs, templateID)
	if err != nil {
		return 0, 0, fmt.Errorf("role-template reconciliation: reading locked api keys for template %s: %w", templateID, err)
	}

	var doomed []string
	err = func() error {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, orgID, userID string
			var scopesJSON []byte
			if err := rows.Scan(&id, &orgID, &userID, &scopesJSON); err != nil {
				return fmt.Errorf("scanning locked api key: %w", err)
			}
			var have []string
			if len(scopesJSON) > 0 {
				if err := json.Unmarshal(scopesJSON, &have); err != nil {
					return fmt.Errorf("unmarshalling api key scopes: %w", err)
				}
			}
			if AuthorityRetained(have, proposedScopes, rwPairs) {
				spared++
				continue
			}
			doomed = append(doomed, id)
		}
		return rows.Err()
	}()
	if err != nil {
		return 0, 0, fmt.Errorf("role-template reconciliation: reading locked api keys for template %s: %w", templateID, err)
	}

	if len(doomed) == 0 {
		return 0, spared, nil
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ANY($1)`, doomed)
	if err != nil {
		return 0, 0, fmt.Errorf("role-template reconciliation: sweeping api keys for template %s: %w", templateID, err)
	}
	n, err := affectedRows(res, "template-reconciliation api keys")
	if err != nil {
		return 0, 0, err
	}
	// Same invariant sweepDerivedKeys enforces: the rows were selected FOR
	// UPDATE in THIS transaction, so the DELETE must match every one of them.
	// Fewer means the statement is not deleting what the decision was made
	// about — abort the whole batch rather than report a partial sweep as
	// complete.
	if n != int64(len(doomed)) {
		return 0, 0, fmt.Errorf("role-template reconciliation: selected %d api keys for template %s but deleted %d",
			len(doomed), templateID, n)
	}
	return int(n), spared, nil
}
