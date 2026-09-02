// template_write.go closes issue #282: a role-template edit reduces derived
// authority for every membership holding the template, and the repository
// methods that perform it invalidate nothing.
//
// template_reconcile.go supplies the sweep — bounded, resumable, keyed off
// AuthorityRetained rather than off "the template changed". What it deliberately
// did NOT supply is anything that makes the sweep happen: it left the ordering
// ("preview, reconcile to completion, THEN mutate") as a sentence in a package
// comment for a consumer to follow. This file is that sentence made
// unskippable. A caller who reaches for TemplateWriter cannot express the
// mutation without the reconciliation, cannot get them in the wrong order, and
// cannot mutate on a sweep that did not finish.
//
// # Why this is a separate symbol rather than a change to the repository
//
// The same argument Reducer makes for the membership family, and for the same
// reason it is a different type rather than an extra argument on
// OrganizationRepository.RemoveMember: an application that has decided its
// reduction needs no sweep from THIS module keeps a plain, still-exported
// method to call, and choosing it is visible in the source as a different
// symbol rather than as an omitted argument nobody notices.
//
// That is not a hypothetical: terraform-registry-backend edits templates through
// RoleTemplateRepository and sweeps from its OWN per-app mirror
// (organization_member_roles) rather than from identity.organization_members,
// deliberately, since terraform-suite-identity#206 phase 3b. Forcing every
// consumer through this writer would make that app sweep off the table it
// stopped trusting. What the inventory now records is that the un-swept
// reduction is a CHOICE with a sanctioned alternative, not the only path there
// is.
//
// # Ordering, and why it is not configurable
//
// Reconcile first, mutate second, always. For an update either order finds the
// same membership set, since organization_members.role_template_id is untouched
// by a write to role_templates.scopes. For a DELETE only this order works at
// all: the FK is ON DELETE SET NULL, so the statement that removes the template
// rewrites every "who held it" row in the same breath, and a sweep that ran
// afterwards would find nobody and report a clean zero. A configurable order
// would exist only so that a caller could pick the broken one.
//
// # What is still not atomic, and cannot be
//
// The sweep is many transactions and the mutation is another, so a failure
// between them leaves credentials destroyed for a reduction that did not land.
// That is the fail-closed direction and it is chosen, not conceded: the
// alternative ordering leaves the reduction landed and the credentials alive,
// which is the state issue #282 exists to make unreachable. A caller that sees
// a mutation error after a completed sweep has over-revoked — an availability
// loss, recoverable by re-issuing keys — and the result it gets back reports
// exactly what was swept rather than a zero value, so the over-revocation is
// legible instead of hidden behind the error.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// ErrReconciliationIncomplete reports a template mutation REFUSED because its
// credential reconciliation had not finished.
//
// It is a sentinel because the caller has to be able to tell this apart from a
// failure: nothing is wrong, the sweep was bounded by ctx or MaxBatches exactly
// as the caller asked, and the correct response is to resume from the cursor in
// the returned result and call again — not to retry blindly, and not to give up
// and mutate anyway. Refusing here is the whole point: a template whose
// membership was half-swept and then edited is the un-invalidated credential
// this file exists to prevent, reached one step later.
var ErrReconciliationIncomplete = errors.New("store: role-template reconciliation did not finish; the template was not modified")

// TemplateWriter performs a role-template mutation and the bounded
// reconciliation of the credentials that mutation strands, in that order or not
// at all.
//
// See the file comment for the ordering argument and for what is deliberately
// not atomic.
type TemplateWriter struct {
	db        *sql.DB
	templates *RoleTemplateRepository
	// rwPairs is the application's read/write scope grammar, handed to
	// AuthorityRetained for every key the sweep examines.
	//
	// MANDATORY, and nil is safe rather than convenient — the same trade
	// Reducer documents: with no pairs, write-implies-read does not apply, so a
	// key carrying "modules:read" is not retained under a surviving
	// "modules:write" and is deleted. That over-revokes, and an API key's
	// secret is shown once, so the cost is real; but it never under-revokes, so
	// a caller that gets this wrong loses availability and not containment.
	rwPairs auth.ReadWritePairs
}

// NewTemplateWriter builds a writer over the same *sql.DB every other accessor
// in this package takes.
func NewTemplateWriter(db *sql.DB, rwPairs auth.ReadWritePairs) *TemplateWriter {
	return &TemplateWriter{db: db, templates: NewRoleTemplateRepository(db), rwPairs: rwPairs}
}

// TemplateWritten is what one call did.
//
// Unlike Reduced, which is populated only on the committed path, this is
// populated whenever the sweep ran — INCLUDING when the mutation afterwards
// failed. The deletions a sweep performs are irreversible and are not rolled
// back by a later failure, so reporting a zero value alongside that error would
// describe a database state that does not exist. Every refusal that happens
// BEFORE the sweep (no such template, a system template, an unfinished
// reconciliation) does return the zero value, because in those cases nothing
// was swept and nothing was written.
type TemplateWritten struct {
	// Reconciled is the sweep this call ran, exactly as ReconcileRoleTemplate
	// reported it: batches, principals checked, keys swept and spared.
	Reconciled TemplateReconcileResult
	// Mutated reports whether the template statement actually landed. False
	// with a nil error is unreachable; false with an error means the write
	// failed or was refused, and Reconciled says whether that refusal came
	// before or after credentials were destroyed.
	Mutated bool
}

// UpdateRoleTemplate reconciles the credentials that template.Scopes would
// strand, then writes the template — the same statement, with the same
// is_system rule and the same ErrNotFound semantics, that
// RoleTemplateRepository.UpdateRoleTemplate issues.
//
// The scopes being written are what every affected member RETAINS, so a key
// asking for no more than the new list survives; that judgement is
// AuthorityRetained's, made per key inside the sweep, which is why widening a
// template or reordering an unchanged list destroys nothing.
//
// opts.BatchSize is required. This module has no default for it on purpose: a
// bounded sweep is one whose transaction size the caller chose for this
// deployment's tables.
func (w *TemplateWriter) UpdateRoleTemplate(ctx context.Context, template *models.RoleTemplate, opts ReconcileOptions) (TemplateWritten, error) {
	if template == nil {
		return TemplateWritten{}, fmt.Errorf("role-template write: nil template")
	}
	args, err := updateRoleTemplateArgs(template)
	if err != nil {
		return TemplateWritten{}, err
	}
	return w.write(ctx, template.ID, template.Scopes, opts, func(ctx context.Context) error {
		return execRoleTemplateMutation(ctx, w.db, updateRoleTemplateStmt, template.ID, args...)
	})
}

// DeleteRoleTemplate reconciles the credentials the deletion strands, then
// deletes the template.
//
// The proposed scopes are nil — "about to be deleted" — which is the same
// reading organization_members.role_template_id = NULL already carries in this
// package: strictly less authority, not a re-homing. Every key held by a member
// of this template is therefore unretained unless it carries no scopes at all.
//
// This is the ordering that cannot be reversed. After the delete commits, the
// ON DELETE SET NULL cascade has rewritten every membership row that named the
// template, so a sweep run afterwards reports a clean zero for a template that
// may have had thousands of members — indistinguishable from a template nobody
// held.
func (w *TemplateWriter) DeleteRoleTemplate(ctx context.Context, id uuid.UUID, opts ReconcileOptions) (TemplateWritten, error) {
	return w.write(ctx, id, nil, opts, func(ctx context.Context) error {
		return execRoleTemplateMutation(ctx, w.db, deleteRoleTemplateStmt, id, id)
	})
}

// write is the shared body: refuse what the mutation would refuse anyway, sweep
// to completion, then mutate.
func (w *TemplateWriter) write(ctx context.Context, id uuid.UUID, proposedScopes []string, opts ReconcileOptions, mutate func(context.Context) error) (TemplateWritten, error) {
	if w.db == nil {
		return TemplateWritten{}, ErrNoTemplateReconciler
	}

	// PRE-FLIGHT, and its position is the point. Both statements filter
	// is_system, so a system template matches no row and the mutation reports
	// ErrNotFound — but by then the sweep has already destroyed the keys of
	// everyone holding it, for an edit the database was never going to apply.
	// Reading the template first means the two refusals a caller can hit
	// without any authority moving (no such template, a system template) cost
	// nothing and destroy nothing.
	//
	// It is a check, not the enforcement: the WHERE clause remains what
	// actually refuses the write, so a template that becomes unwritable between
	// this read and the mutation is still refused — just later, and after a
	// sweep. Nothing in this package updates is_system (it is set once, at
	// insert), so that window is not reachable through this module's own API.
	existing, err := w.templates.GetRoleTemplate(ctx, id)
	if err != nil {
		return TemplateWritten{}, err
	}
	if existing.IsSystem {
		return TemplateWritten{}, fmt.Errorf("role template %s not found or is a system template (immutable): %w", id, ErrNotFound)
	}

	reconciled, err := ReconcileRoleTemplate(ctx, w.db, id.String(), proposedScopes, w.rwPairs, opts)
	if err != nil {
		// The sweep failed. Nothing is mutated, and the caller retries: a
		// template whose members are half-swept is exactly the state that must
		// not be followed by the write.
		return TemplateWritten{}, err
	}
	if !reconciled.Done {
		// Bounded by ctx or MaxBatches, as asked. Report what ran — including
		// the cursor to resume from — and refuse the mutation.
		return TemplateWritten{Reconciled: reconciled}, fmt.Errorf(
			"role template %s: swept %d keys across %d principals in %d batches but did not reach the end of its membership: %w",
			id, reconciled.KeysSwept, reconciled.PrincipalsChecked, reconciled.BatchesRun, ErrReconciliationIncomplete)
	}

	if err := mutate(ctx); err != nil {
		// Populated, not zeroed: see TemplateWritten. The keys are gone.
		return TemplateWritten{Reconciled: reconciled}, err
	}
	return TemplateWritten{Reconciled: reconciled, Mutated: true}, nil
}
