//go:build integration

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// Integration guards for the sanctioned role-template write (issue #282).
//
// The sqlmock suite in template_write_test.go proves the statements and their
// order against primed rows. What only a real database can prove is the reason
// that order exists: organization_members.role_template_id is ON DELETE SET
// NULL, so a real DELETE erases the very rows the sweep reads. A mock cannot
// have that opinion — it returns whatever it was primed with, in whatever order
// the test wrote it down.
//
// Run with -tags=integration and TEST_DATABASE_URL set.

// templateScopes reads a template's current scopes, or reports that the row is
// gone.
//
// It returns the DECODED list rather than the raw JSONB text: Postgres
// normalises jsonb on the way out and renders a multi-element array with a
// space after each comma, so a byte-for-byte comparison against the literal a
// test wrote passes for one element and fails for two — a difference about
// jsonb's whitespace, not about anybody's scopes.
func templateScopes(t *testing.T, db *sql.DB, id string) ([]string, bool) {
	t.Helper()
	var raw []byte
	err := db.QueryRow(`SELECT scopes FROM identity.role_templates WHERE id = $1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("reading template scopes: %v", err)
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		t.Fatalf("decoding template scopes %s: %v", raw, err)
	}
	return scopes, true
}

// membersStillPointingAt counts the organization_members rows that still name
// the template — the population the sweep reads, and the one the delete
// cascade rewrites.
func membersStillPointingAt(t *testing.T, db *sql.DB, templateID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM identity.organization_members WHERE role_template_id = $1`,
		templateID).Scan(&n); err != nil {
		t.Fatalf("counting members: %v", err)
	}
	return n
}

// GUARD writer-delete-sweeps-what-the-cascade-would-erase. The whole reason the
// order is fixed, proved against a live cascade rather than asserted.
//
// Deleting the template strands every key its holders carry — the proposed
// scopes are nil, so even a read-only key is unretained — and the writer sweeps
// them BEFORE the delete, while organization_members still says who held it.
// The second half of this test is the falsification: the same delete performed
// the other way round, through the plain repository method, leaves every one of
// those keys alive AND leaves the reconciliation with nothing left to find.
//
// MUTATION: call the repository's DeleteRoleTemplate and reconcile afterwards.
func TestIntegrationWriterDeleteSweepsWhatTheCascadeWouldErase(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	f := seedTemplateFixture(t, db)
	writer := NewTemplateWriter(db, templateReconcileRWPairs)

	if got := membersStillPointingAt(t, db, f.template); got != f.templateMemberCount() {
		t.Fatalf("fixture holds %d members, want %d — the sweep's universe is not what this test thinks",
			got, f.templateMemberCount())
	}

	written, err := writer.DeleteRoleTemplate(ctx, uuid.MustParse(f.template), ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !written.Mutated {
		t.Fatal("Mutated = false after a successful delete")
	}
	if !written.Reconciled.Done {
		t.Fatalf("reconciliation did not finish: %+v", written.Reconciled)
	}
	if written.Reconciled.PrincipalsChecked != f.templateMemberCount() {
		t.Errorf("PrincipalsChecked = %d, want %d — the sweep ran against the wrong membership set",
			written.Reconciled.PrincipalsChecked, f.templateMemberCount())
	}
	// Three of the four holders have a key, and with the template gone none of
	// them retains anything: even subsetKey, which survives a mere narrowing.
	if written.Reconciled.KeysSwept != 3 {
		t.Errorf("KeysSwept = %d, want 3 (a deleted template retains nothing)", written.Reconciled.KeysSwept)
	}

	if _, alive := templateScopes(t, db, f.template); alive {
		t.Error("the template row survived its own delete")
	}
	if got := membersStillPointingAt(t, db, f.template); got != 0 {
		t.Errorf("%d members still name the deleted template; the ON DELETE SET NULL cascade did not run", got)
	}
	for _, id := range []string{f.subsetKey, f.overKey, f.orgBKey} {
		if templateKeyExists(t, db, id) {
			t.Errorf("key %s survived the deletion of the template its holder's authority came from", id)
		}
	}
	// The noise must be untouched: a different template's holder, and an
	// organization service credential derived from nobody's membership.
	for _, id := range []string{f.otherTemplateKey, f.serviceKey} {
		if !templateKeyExists(t, db, id) {
			t.Errorf("key %s was swept, but it does not derive from the deleted template", id)
		}
	}

	// FALSIFICATION. The same operation in the other order, on a fresh fixture:
	// delete first, then reconcile. The cascade has already erased the
	// membership rows, so the sweep reports a clean, complete, empty run — and
	// every stranded key is still live.
	g := seedTemplateFixture(t, db)
	if err := NewRoleTemplateRepository(db).DeleteRoleTemplate(ctx, uuid.MustParse(g.template)); err != nil {
		t.Fatalf("repository delete: %v", err)
	}
	after, err := ReconcileRoleTemplate(ctx, db, g.template, nil, templateReconcileRWPairs, ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("post-delete reconciliation: %v", err)
	}
	if !after.Done || after.PrincipalsChecked != 0 || after.KeysSwept != 0 {
		t.Fatalf("a post-delete sweep found %+v; this test's premise is that the cascade leaves it nothing to find", after)
	}
	if live := templateReconcileLiveKeyCount(t, db, []string{g.subsetKey, g.overKey, g.orgBKey}); live != 3 {
		t.Errorf("%d of 3 stranded keys survived the wrong ordering, want 3 — if this is not 3, the "+
			"ordering this file exists to enforce is no longer load-bearing and the guard above proves nothing", live)
	}
}

// GUARD writer-update-sweeps-only-the-unretained. A narrowing edit destroys the
// keys the new scope list no longer covers and spares the rest, and the
// template really does end up carrying the new scopes.
//
// MUTATION: sweep every key belonging to a holder; or write the template
// without sweeping at all.
func TestIntegrationWriterUpdateSweepsOnlyTheUnretained(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	f := seedTemplateFixture(t, db)
	writer := NewTemplateWriter(db, templateReconcileRWPairs)

	template, err := NewRoleTemplateRepository(db).GetRoleTemplate(ctx, uuid.MustParse(f.template))
	if err != nil {
		t.Fatalf("reading the fixture template: %v", err)
	}
	template.Scopes = reducedTemplateScopes

	written, err := writer.UpdateRoleTemplate(ctx, template, ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !written.Mutated || !written.Reconciled.Done {
		t.Fatalf("write = %+v, want a finished sweep and a landed write", written)
	}
	if written.Reconciled.KeysSwept != f.sweptPrincipalCount() {
		t.Errorf("KeysSwept = %d, want %d", written.Reconciled.KeysSwept, f.sweptPrincipalCount())
	}

	scopes, alive := templateScopes(t, db, f.template)
	if !alive {
		t.Fatal("the template disappeared during an update")
	}
	if !reflect.DeepEqual(scopes, reducedTemplateScopes) {
		t.Errorf("template scopes = %v, want %v — the write did not land", scopes, reducedTemplateScopes)
	}
	if !templateKeyExists(t, db, f.subsetKey) {
		t.Error("a key asking for no more than the narrowed template was destroyed")
	}
	for _, id := range []string{f.overKey, f.orgBKey} {
		if templateKeyExists(t, db, id) {
			t.Errorf("key %s asks for more than the narrowed template still grants and survived", id)
		}
	}
	for _, id := range []string{f.otherTemplateKey, f.serviceKey} {
		if !templateKeyExists(t, db, id) {
			t.Errorf("key %s was swept, but it does not derive from this template", id)
		}
	}
}

// GUARD writer-unfinished-sweep-leaves-the-template-alone. The sqlmock suite
// proves no UPDATE statement is issued; this proves the consequence that
// matters — the template in the database still carries its OLD scopes, so the
// half of the membership whose keys were not reached still holds authority the
// template still grants.
//
// MUTATION: mutate regardless of Done.
func TestIntegrationWriterUnfinishedSweepLeavesTheTemplateAlone(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	f := seedTemplateFixture(t, db)
	writer := NewTemplateWriter(db, templateReconcileRWPairs)

	before, alive := templateScopes(t, db, f.template)
	if !alive {
		t.Fatal("fixture template missing")
	}

	template, err := NewRoleTemplateRepository(db).GetRoleTemplate(ctx, uuid.MustParse(f.template))
	if err != nil {
		t.Fatalf("reading the fixture template: %v", err)
	}
	template.Scopes = reducedTemplateScopes

	// One batch of one principal, out of four: the sweep cannot finish.
	written, err := writer.UpdateRoleTemplate(ctx, template, ReconcileOptions{BatchSize: 1, MaxBatches: 1})
	if !errors.Is(err, ErrReconciliationIncomplete) {
		t.Fatalf("error = %v, want ErrReconciliationIncomplete", err)
	}
	if written.Mutated {
		t.Fatal("the template was written on an unfinished sweep")
	}
	if written.Reconciled.Cursor == nil {
		t.Fatal("no cursor to resume from")
	}

	after, alive := templateScopes(t, db, f.template)
	if !alive {
		t.Fatal("the template disappeared")
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("template scopes changed to %v on an unfinished sweep; they must still be %v", after, before)
	}

	// Resuming from the cursor finishes the job, and only then does the write
	// land — the bounded sweep is resumable, not abandoned.
	resumed, err := writer.UpdateRoleTemplate(ctx, template, ReconcileOptions{
		BatchSize: 10, After: written.Reconciled.Cursor,
	})
	if err != nil {
		t.Fatalf("resumed update: %v", err)
	}
	if !resumed.Mutated || !resumed.Reconciled.Done {
		t.Fatalf("resumed write = %+v, want a finished sweep and a landed write", resumed)
	}
	total := written.Reconciled.KeysSwept + resumed.Reconciled.KeysSwept
	if total != f.sweptPrincipalCount() {
		t.Errorf("swept %d keys across both runs, want %d", total, f.sweptPrincipalCount())
	}
	if scopes, _ := templateScopes(t, db, f.template); !reflect.DeepEqual(scopes, reducedTemplateScopes) {
		t.Errorf("template scopes = %v after the resumed write, want %v", scopes, reducedTemplateScopes)
	}
	if !templateKeyExists(t, db, f.subsetKey) {
		t.Error("the retained key was destroyed by the resumed run")
	}
}

// GUARD writer-preflight-precedes-the-sweep. A system template is immutable:
// both statements filter is_system, so the write would match no row and report
// ErrNotFound. Sweeping first would destroy every holder's API keys for an edit
// the database was never going to apply — irreversibly, since a key's secret is
// shown once.
//
// This lives here rather than beside the other refusal tests because the mock
// cannot see it: under a mutant that sweeps first, sqlmock refuses the sweep's
// unexpected BEGIN, the writer then reads the queued template row and returns
// the same ErrNotFound, and every mocked assertion still passes. Against a real
// database the difference is the thing that matters — the keys are gone.
//
// MUTATION: move the is_system check below the ReconcileRoleTemplate call.
func TestIntegrationWriterRefusesASystemTemplateWithoutSweeping(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	f := seedTemplateFixture(t, db)
	writer := NewTemplateWriter(db, templateReconcileRWPairs)

	// Promote the fixture's template to a system template. Nothing in the
	// module's own API can do this — is_system is set at insert — which is why
	// the pre-flight read of it is stable in practice.
	if _, err := db.ExecContext(ctx, `UPDATE identity.role_templates SET is_system = true WHERE id = $1`,
		f.template); err != nil {
		t.Fatalf("promoting the fixture template: %v", err)
	}

	template, err := NewRoleTemplateRepository(db).GetRoleTemplate(ctx, uuid.MustParse(f.template))
	if err != nil {
		t.Fatalf("reading the fixture template: %v", err)
	}
	template.Scopes = reducedTemplateScopes

	written, err := writer.UpdateRoleTemplate(ctx, template, ReconcileOptions{BatchSize: 2})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound for a system template", err)
	}
	if written.Mutated || written.Reconciled.BatchesRun != 0 {
		t.Errorf("a refused system template reported %+v; nothing may be swept or written", written)
	}

	// The assertion the mock cannot make: every key its holders carry is still
	// there. A sweep that ran before the refusal would have destroyed the two
	// that the narrowed scope list no longer covers.
	for _, id := range []string{f.subsetKey, f.overKey, f.orgBKey} {
		if !templateKeyExists(t, db, id) {
			t.Errorf("key %s was destroyed for an edit the database refused", id)
		}
	}
	if scopes, _ := templateScopes(t, db, f.template); !reflect.DeepEqual(scopes, []string{"users:write", "modules:write"}) {
		t.Errorf("template scopes = %v, want the original list — the refused write landed", scopes)
	}

	// And the delete axis, which strands every key rather than only the
	// unretained ones.
	written, err = writer.DeleteRoleTemplate(ctx, uuid.MustParse(f.template), ReconcileOptions{BatchSize: 2})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete error = %v, want ErrNotFound for a system template", err)
	}
	if written.Reconciled.BatchesRun != 0 {
		t.Errorf("a refused system-template delete swept %+v", written.Reconciled)
	}
	if live := templateReconcileLiveKeyCount(t, db, []string{f.subsetKey, f.overKey, f.orgBKey}); live != 3 {
		t.Errorf("%d of 3 keys survived a refused delete, want 3", live)
	}
}
