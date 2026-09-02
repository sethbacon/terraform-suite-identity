package store

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// Behavioural guards for the sanctioned role-template write (issue #282).
//
// What these prove that template_reconcile_test.go cannot: the sweep and the
// mutation are ONE operation with a fixed order and a precondition. sqlmock's
// expectations are ordered, so "the sweep ran before the write" and "no write
// was issued at all" are both statements this harness can make about real
// statements rather than about a return value.
//
// Every test names the mutation it exists to catch, in the discipline
// authority_reduction_test.go set.

const (
	getRoleTemplateRe    = `SELECT id.*FROM role_templates WHERE id = \$1`
	updateRoleTemplateRe = `UPDATE role_templates SET display_name = \$2, description = \$3, scopes = \$4, updated_at = \$5.*WHERE id = \$1 AND is_system = false`
	deleteRoleTemplateRe = `DELETE FROM role_templates WHERE id = \$1 AND is_system = false`
)

var errWriterDB = errors.New("template writer db error")

// newTemplateWriter builds a writer over a mock, with the same read/write
// grammar the reconciler's own tests use.
func newTemplateWriter(t *testing.T) (*TemplateWriter, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewTemplateWriter(db, reconcileRWPairs), mock
}

// templateRow builds the pre-flight read's row.
func templateRow(id uuid.UUID, isSystem bool) *sqlmock.Rows {
	return sqlmock.NewRows(roleTemplateCols).
		AddRow(id, "editor", "Editor", nil, []byte(`["modules:write"]`), isSystem, time.Now(), time.Now())
}

func editorTemplate(id uuid.UUID, scopes ...string) *models.RoleTemplate {
	return &models.RoleTemplate{ID: id, DisplayName: "Editor", Scopes: scopes}
}

// expectOneFinishedBatch queues a single, final sweep batch: one principal
// (fewer than BatchSize, so the sweep is Done), one key, one delete.
func expectOneFinishedBatch(mock sqlmock.Sqlmock, keyScopes string, deleted bool) {
	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-a"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", keyScopes},
	))
	if deleted {
		mock.ExpectExec(batchDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()
}

// ---------------------------------------------------------------------------
// Refusals that must cost nothing
// ---------------------------------------------------------------------------

// GUARD writer-refuses-nil-db. A writer with no handle sweeps nothing and
// writes nothing, and says so rather than reporting a clean no-op — the same
// reasoning ErrNoReducer and ErrNoTemplateReconciler already encode.
//
// MUTATION: return a zero TemplateWritten and a nil error.
func TestWriterRefusesNilDB(t *testing.T) {
	w := NewTemplateWriter(nil, reconcileRWPairs)

	if _, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(uuid.New(), "modules:read"),
		ReconcileOptions{BatchSize: 2}); !errors.Is(err, ErrNoTemplateReconciler) {
		t.Fatalf("update error = %v, want ErrNoTemplateReconciler", err)
	}
	if _, err := w.DeleteRoleTemplate(context.Background(), uuid.New(),
		ReconcileOptions{BatchSize: 2}); !errors.Is(err, ErrNoTemplateReconciler) {
		t.Fatalf("delete error = %v, want ErrNoTemplateReconciler", err)
	}
}

// GUARD writer-refuses-a-system-template. Both statements filter is_system, so
// a system template matches no row; the writer refuses it up front rather than
// discovering it after the sweep.
//
// THIS TEST PROVES THE REFUSAL, NOT THE ORDERING. It cannot see the ordering:
// under a mutant that sweeps first, the sweep's unexpected BEGIN is refused by
// the mock, the writer then reads the queued template row and returns exactly
// the ErrNotFound asserted here, and the expectation set is satisfied. The
// ordering guard that actually holds is
// TestIntegrationWriterRefusesASystemTemplateWithoutSweeping, where a sweep
// that runs has real, visible consequences — a mocked one has none.
//
// MUTATION: drop the is_system check and let the mutation's WHERE clause do
// the refusing.
func TestWriterRefusesASystemTemplateWithoutSweeping(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, true))

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"),
		ReconcileOptions{BatchSize: 2})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if written.Mutated || written.Reconciled.BatchesRun != 0 {
		t.Errorf("a refused system template reported %+v; nothing may be swept or written", written)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a refusal issued statements it should not have: %v", err)
	}
}

// GUARD writer-missing-template-sweeps-nothing. Same shape for a template that
// does not exist: the sweep would find no members and delete nothing today, but
// it would still open a transaction per batch against a template id the caller
// got wrong.
//
// MUTATION: swallow the pre-flight's ErrNotFound and continue.
func TestWriterRefusesAMissingTemplateWithoutSweeping(t *testing.T) {
	w, mock := newTemplateWriter(t)
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	_, err := w.DeleteRoleTemplate(context.Background(), uuid.New(), ReconcileOptions{BatchSize: 2})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a refusal issued statements it should not have: %v", err)
	}
}

// GUARD writer-requires-a-batch-size. The bounded sweep has no default batch
// size — the caller sizes the transaction it is willing to run — so a writer
// call without one must refuse rather than pick a number, and must refuse
// BEFORE writing.
//
// MUTATION: default BatchSize to some constant when it is zero.
func TestWriterRefusesWithoutABatchSize(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"), ReconcileOptions{})
	if err == nil {
		t.Fatal("a write with no BatchSize succeeded; the sweep must refuse to guess one")
	}
	if written.Mutated {
		t.Error("the template was written despite the sweep refusing to run")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements were issued after the sweep refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The order, and the precondition
// ---------------------------------------------------------------------------

// GUARD writer-sweeps-before-it-writes. The whole contract: the credentials a
// narrowing strands are gone before the narrowing lands. sqlmock's expectations
// are ordered, so queueing the sweep ahead of the UPDATE is the assertion.
//
// MUTATION: issue the UPDATE first and reconcile afterwards.
func TestWriterSweepsBeforeItUpdates(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	expectOneFinishedBatch(mock, `["modules:write"]`, true)
	mock.ExpectExec(updateRoleTemplateRe).WillReturnResult(sqlmock.NewResult(0, 1))

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"),
		ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !written.Mutated {
		t.Error("Mutated = false after a successful write")
	}
	if !written.Reconciled.Done || written.Reconciled.KeysSwept != 1 {
		t.Errorf("reconciliation = %+v, want Done with one key swept", written.Reconciled)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements or their order did not match: %v", err)
	}
}

// GUARD writer-delete-sweeps-before-the-cascade. For a delete this order is not
// a preference: organization_members.role_template_id is ON DELETE SET NULL, so
// the statement that removes the template erases every row saying who held it.
// A sweep afterwards reports a clean zero for a template that had thousands of
// members. The proposed scopes are nil, so every key a member holds is
// unretained unless it carries no scopes at all.
//
// MUTATION: delete the template first, then reconcile.
func TestWriterSweepsBeforeItDeletes(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	expectOneFinishedBatch(mock, `["modules:read"]`, true) // nil retained: even a read scope is stranded
	mock.ExpectExec(deleteRoleTemplateRe).WillReturnResult(sqlmock.NewResult(0, 1))

	written, err := w.DeleteRoleTemplate(context.Background(), id, ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !written.Mutated || written.Reconciled.KeysSwept != 1 {
		t.Errorf("write = %+v, want the key swept and the template deleted", written)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements or their order did not match: %v", err)
	}
}

// GUARD writer-refuses-to-write-on-an-unfinished-sweep. A bounded sweep that
// stopped at its MaxBatches has left some holders' keys alive. Writing the
// narrowed template anyway produces exactly the state issue #282 describes —
// authority reduced, credentials live — reached one step later, and for the
// half of the membership nobody will look at again.
//
// The refusal is a sentinel, not a failure: the result carries the cursor, and
// the caller resumes.
//
// MUTATION: treat Done as advisory and mutate regardless; or return the error
// without the cursor, so resuming means starting over.
func TestWriterRefusesToWriteOnAnUnfinishedSweep(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	// A FULL page (len == BatchSize) means more may follow, so MaxBatches
	// stops the sweep with Done == false.
	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-a"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", `["modules:write"]`},
	))
	mock.ExpectExec(batchDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	// No UPDATE is queued: issuing one is the mutation this guard catches.

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"),
		ReconcileOptions{BatchSize: 1, MaxBatches: 1})
	if !errors.Is(err, ErrReconciliationIncomplete) {
		t.Fatalf("error = %v, want ErrReconciliationIncomplete", err)
	}
	if written.Mutated {
		t.Error("the template was written on a sweep that had not finished")
	}
	if written.Reconciled.Done {
		t.Error("Done = true on a sweep stopped by MaxBatches")
	}
	if written.Reconciled.Cursor == nil {
		t.Fatal("no cursor returned; the caller cannot resume and would have to start over")
	}
	if got := *written.Reconciled.Cursor; got.OrganizationID != "org-1" || got.UserID != "user-a" {
		t.Errorf("cursor = %+v, want the last principal the batch examined", got)
	}
	if written.Reconciled.KeysSwept != 1 {
		t.Errorf("KeysSwept = %d, want the key this batch really deleted", written.Reconciled.KeysSwept)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements did not match — a write after an unfinished sweep is the defect: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Retention, and honest reporting
// ---------------------------------------------------------------------------

// GUARD writer-widening-destroys-nothing. A key asking for no more than the new
// scopes survives, so widening a template — or reordering an unchanged list —
// writes the template and deletes nothing. The judgement is AuthorityRetained's,
// per key, which is why the writer does not need a second "did this narrow?"
// predicate that could disagree with it.
//
// MUTATION: sweep every key belonging to a holder whenever the template is
// written at all.
func TestWriterWideningWritesAndSweepsNothing(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	// have=modules:read under retained=modules:write: retained via the
	// read/write pair, so no DELETE is queued.
	expectOneFinishedBatch(mock, `["modules:read"]`, false)
	mock.ExpectExec(updateRoleTemplateRe).WillReturnResult(sqlmock.NewResult(0, 1))

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:write"),
		ReconcileOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !written.Mutated {
		t.Error("a widening edit was not written")
	}
	if written.Reconciled.KeysSwept != 0 || written.Reconciled.KeysSpared != 1 {
		t.Errorf("reconciliation = %+v, want nothing swept and one key spared", written.Reconciled)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements did not match: %v", err)
	}
}

// GUARD writer-reports-a-sweep-that-outlived-its-write. The sweep is many
// transactions and the mutation is another, so a mutation that fails after a
// completed sweep leaves keys destroyed for a reduction that did not land. That
// is the fail-closed direction and it is chosen — but the caller has to be able
// to SEE it, so the result is populated alongside the error rather than zeroed
// the way Reduced is.
//
// MUTATION: return TemplateWritten{} with the mutation's error, hiding the
// irreversible deletions behind it.
func TestWriterReportsTheSweepWhenTheWriteFails(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	expectOneFinishedBatch(mock, `["modules:write"]`, true)
	mock.ExpectExec(updateRoleTemplateRe).WillReturnError(errWriterDB)

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"),
		ReconcileOptions{BatchSize: 2})
	if err == nil {
		t.Fatal("a failed write reported success")
	}
	if written.Mutated {
		t.Error("Mutated = true after the write failed")
	}
	if written.Reconciled.KeysSwept != 1 {
		t.Errorf("KeysSwept = %d, want the key the sweep really deleted reported alongside the error",
			written.Reconciled.KeysSwept)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("statements did not match: %v", err)
	}
}

// GUARD writer-write-refusal-is-not-swallowed. The pre-flight read is a check,
// not the enforcement: the WHERE clause is what actually refuses. A template
// that stops being writable between the two still gets refused, and the writer
// must surface that rather than report a clean write.
//
// MUTATION: ignore the mutation's error when the sweep succeeded.
func TestWriterSurfacesAZeroRowWrite(t *testing.T) {
	w, mock := newTemplateWriter(t)
	id := uuid.New()
	mock.ExpectQuery(getRoleTemplateRe).WillReturnRows(templateRow(id, false))
	expectOneFinishedBatch(mock, `["modules:write"]`, true)
	mock.ExpectExec(updateRoleTemplateRe).WillReturnResult(sqlmock.NewResult(0, 0))

	written, err := w.UpdateRoleTemplate(context.Background(), editorTemplate(id, "modules:read"),
		ReconcileOptions{BatchSize: 2})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound for a write that matched no row", err)
	}
	if written.Mutated {
		t.Error("Mutated = true for a write that matched no row")
	}
}

// GUARD writer-nil-template-is-refused. A nil template would otherwise
// dereference while assembling the update's arguments, after the caller had
// been told nothing.
//
// MUTATION: drop the nil check.
func TestWriterRefusesANilTemplate(t *testing.T) {
	w, _ := newTemplateWriter(t)
	if _, err := w.UpdateRoleTemplate(context.Background(), nil, ReconcileOptions{BatchSize: 2}); err == nil {
		t.Fatal("a nil template was accepted")
	}
}
