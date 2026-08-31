package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// Behavioural guards for the role-template reconciliation (issue #282).
//
// Same discipline as authority_reduction_test.go: every test here names the
// mutation it exists to catch. sqlmock proves the STATEMENTS, their ordering
// and the transaction boundary of one batch; template_reconcile_integration_test.go
// proves the things sqlmock cannot — atomicity across a real crash/cancel, and
// the `unnest($1::uuid[], $2::uuid[])` binding against real uuid columns.

var reconcileRWPairs = auth.ReadWritePairs{"modules:read": "modules:write"}

const (
	previewQueryRe   = `SELECT om\.organization_id, om\.user_id, ak\.id, ak\.scopes FROM organization_members om LEFT JOIN api_keys ak.*WHERE om\.role_template_id = \$1`
	planQueryRe      = `SELECT organization_id, user_id FROM organization_members WHERE role_template_id = \$1 ORDER BY organization_id, user_id LIMIT \$2`
	planAfterQueryRe = `SELECT organization_id, user_id FROM organization_members WHERE role_template_id = \$1 AND \(organization_id, user_id\) > \(\$2, \$3\) ORDER BY organization_id, user_id LIMIT \$4`
	batchKeysQueryRe = `SELECT ak\.id, ak\.organization_id, ak\.user_id, ak\.scopes FROM api_keys ak JOIN \(.*unnest\(\$1::uuid\[\]\).*unnest\(\$2::uuid\[\]\).*\) b ON.*JOIN organization_members om.*WHERE om\.role_template_id = \$3.*FOR UPDATE OF ak`
	batchDeleteRe    = `DELETE FROM api_keys WHERE id = ANY\(\$1\)`
)

// previewRows builds rows for templateAffectedWithKeysQuery: each entry is
// (orgID, userID, keyID-or-empty, scopesJSON-or-empty). An empty keyID means
// "no api_keys row" (the LEFT JOIN's NULL side) and both key columns are NULL.
func previewRows(entries ...[4]string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"organization_id", "user_id", "id", "scopes"})
	for _, e := range entries {
		orgID, userID, keyID, scopes := e[0], e[1], e[2], e[3]
		if keyID == "" {
			rows.AddRow(orgID, userID, nil, nil)
			continue
		}
		rows.AddRow(orgID, userID, keyID, []byte(scopes))
	}
	return rows
}

// plannedRows builds rows for the plan-batch query: pairs of (orgID, userID).
func plannedRows(pairs ...[2]string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"organization_id", "user_id"})
	for _, p := range pairs {
		rows.AddRow(p[0], p[1])
	}
	return rows
}

// lockedKeyRows builds rows for the FOR-UPDATE batch key read: (id, orgID,
// userID, scopesJSON).
func lockedKeyRows(entries ...[4]string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"id", "organization_id", "user_id", "scopes"})
	for _, e := range entries {
		rows.AddRow(e[0], e[1], e[2], []byte(e[3]))
	}
	return rows
}

// ---------------------------------------------------------------------------
// PreviewRoleTemplateReconciliation
// ---------------------------------------------------------------------------

// GUARD preview-counts-scanned-doomed-and-keys. A principal with no keys is
// counted in Scanned but not Principals; a principal with only retained keys
// is counted in Scanned but not Principals; a principal with an unretained key
// is counted in both, and Keys totals the individual doomed rows.
//
// MUTATION: count every row as a doomed principal regardless of retention, or
// drop the keyless principal from Scanned.
func TestPreviewCountsScannedPrincipalsAndKeys(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(previewQueryRe).WillReturnRows(previewRows(
		[4]string{"org-1", "user-keyless", "", ""},
		[4]string{"org-1", "user-retained", "key-1", `["modules:read"]`},
		[4]string{"org-1", "user-doomed", "key-2", `["users:write"]`},
		[4]string{"org-2", "user-doomed", "key-3", `["users:write"]`},
		[4]string{"org-2", "user-doomed", "key-4", `["audit:read"]`}, // same principal, 2nd doomed key
	))

	impact, err := PreviewRoleTemplateReconciliation(context.Background(), db, "tmpl-1", []string{"modules:write"}, reconcileRWPairs)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}

	want := TemplateReconcileImpact{Scanned: 4, Principals: 2, Keys: 3}
	if impact != want {
		t.Errorf("impact = %+v, want %+v", impact, want)
	}
}

// GUARD preview-empty-universe-is-explicit. A template with zero members must
// report Scanned == 0 by actually issuing and completing the query, not by a
// short-circuit that never reaches the database — ExpectationsWereMet is what
// tells the two apart.
//
// MUTATION: `if err == sql.ErrNoRows { return TemplateReconcileImpact{}, nil }`
// short-circuit before the query, or any path that returns the zero Impact
// without querying.
func TestPreviewEmptyTemplateIsExplicit(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(previewQueryRe).WillReturnRows(previewRows())

	impact, err := PreviewRoleTemplateReconciliation(context.Background(), db, "tmpl-empty", nil, reconcileRWPairs)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the empty-template case must still issue the query: %v", err)
	}
	if impact != (TemplateReconcileImpact{}) {
		t.Errorf("impact = %+v, want the zero value for a template with no members", impact)
	}
}

// GUARD preview-widen-or-reorder-sweeps-nothing, proven directly against
// AuthorityRetained rather than any heuristic of this file's own: every
// existing key's scopes are a SUBSET of proposedScopes (a widening) or the
// SAME set reordered, so nothing is doomed.
func TestPreviewWideningOrReorderingImpactsNothing(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(previewQueryRe).WillReturnRows(previewRows(
		[4]string{"org-1", "user-a", "key-1", `["a","b"]`},
		[4]string{"org-1", "user-b", "key-2", `["a"]`},
	))

	// proposedScopes is the SAME set as the union of what is held, reordered —
	// a widening (adding "c") would pass just as well; reordering is the case
	// TestAuthorityRetained already names directly.
	impact, err := PreviewRoleTemplateReconciliation(context.Background(), db, "tmpl-1", []string{"b", "a"}, nil)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
	want := TemplateReconcileImpact{Scanned: 2, Principals: 0, Keys: 0}
	if impact != want {
		t.Errorf("impact = %+v, want %+v (a widening/reorder must sweep nothing)", impact, want)
	}
}

// GUARD preview-refuses-with-no-handle.
func TestPreviewRefusesNilDB(t *testing.T) {
	_, err := PreviewRoleTemplateReconciliation(context.Background(), nil, "tmpl-1", nil, nil)
	if !errors.Is(err, ErrNoTemplateReconciler) {
		t.Fatalf("err = %v, want ErrNoTemplateReconciler", err)
	}
}

// GUARD preview-refuses-empty-template-id. An empty id would bind an empty
// string against role_template_id — Postgres would reject that uuid literal,
// but refusing it here means the same defensive shape as every other by-id
// accessor in this package, and the database is never touched.
func TestPreviewRefusesEmptyTemplateID(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = PreviewRoleTemplateReconciliation(context.Background(), db, "", nil, nil)
	if err == nil {
		t.Fatal("want an error for an empty template id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an empty template id must not reach the database: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ReconcileRoleTemplate
// ---------------------------------------------------------------------------

// GUARD sweep-one-batch-in-one-transaction. The plan read, the locked key
// read, the delete and the commit happen in that order, all inside BEGIN/COMMIT.
//
// MUTATION: move the plan read or the key read onto r.db instead of the
// transaction — sqlmock's ordered, single-connection queue cannot tell tx from
// pool by itself, which is exactly why the atomicity claim is re-proven live in
// the integration test; this test is the statement-and-ordering half.
func TestReconcileOneBatchInOneTransaction(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows(
		[2]string{"org-1", "user-a"}, [2]string{"org-1", "user-b"},
	))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", `["users:write"]`},  // doomed
		[4]string{"key-2", "org-1", "user-b", `["modules:read"]`}, // spared (write implies read)
	))
	mock.ExpectExec(batchDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// BatchSize 10 with a 2-row page: the page is shorter than BatchSize, so
	// this is recognised as the last page without a second, confirming empty
	// batch — see TestReconcileResumesFromCursorAcrossCalls for the FULL-page
	// case, which does need that extra round trip.
	result, err := ReconcileRoleTemplate(context.Background(), db, "tmpl-1", []string{"modules:write"}, reconcileRWPairs,
		ReconcileOptions{BatchSize: 10})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}

	want := TemplateReconcileResult{
		BatchesRun:        1,
		PrincipalsChecked: 2,
		KeysSwept:         1,
		KeysSpared:        1,
		Done:              true,
	}
	if result != want {
		t.Errorf("result = %+v, want %+v", result, want)
	}
}

// GUARD sweep-empty-template-is-explicit. Same property as the preview: a
// template with zero members must be reported by a batch that actually
// queried and found nothing, not a short-circuit.
//
// MUTATION: `if templateHasNoMembers { return TemplateReconcileResult{Done:
// true}, nil }` computed some other way than running planBatch.
func TestReconcileEmptyTemplateIsExplicit(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows())
	mock.ExpectCommit()

	result, err := ReconcileRoleTemplate(context.Background(), db, "tmpl-empty", nil, reconcileRWPairs,
		ReconcileOptions{BatchSize: 10})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an empty template must still run a batch that queries: %v", err)
	}
	want := TemplateReconcileResult{BatchesRun: 1, Done: true}
	if result != want {
		t.Errorf("result = %+v, want %+v", result, want)
	}
}

// GUARD sweep-widen-or-reorder-sweeps-nothing. Same fixture shape as the
// preview widening test; the batch's own AuthorityRetained call, not a
// heuristic, is what leaves the keys alone.
func TestReconcileWideningOrReorderingSweepsNothing(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-a"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", `["a","b"]`},
	))
	// No ExpectExec: a widening/reorder must never reach the DELETE at all.
	mock.ExpectCommit()

	result, err := ReconcileRoleTemplate(context.Background(), db, "tmpl-1", []string{"b", "a", "c"}, nil,
		ReconcileOptions{BatchSize: 10})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations (a DELETE here means the widening test failed): %v", err)
	}
	if result.KeysSwept != 0 || result.KeysSpared != 1 {
		t.Errorf("result = %+v, want 0 swept and 1 spared", result)
	}
}

// GUARD sweep-delete-count-mismatch-aborts. The rows were locked FOR UPDATE in
// this transaction, so the DELETE must match every one of them; fewer means the
// batch must not report success.
//
// MUTATION: drop the affectedRows/count check after the DELETE.
func TestReconcileAbortsOnPartialDelete(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-a"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", `["users:write"]`},
	))
	// Only 0 rows actually deleted, though 1 was selected FOR UPDATE.
	mock.ExpectExec(batchDeleteRe).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	_, err = ReconcileRoleTemplate(context.Background(), db, "tmpl-1", nil, nil, ReconcileOptions{BatchSize: 10})
	if err == nil {
		t.Fatal("ReconcileRoleTemplate reported success although the DELETE matched fewer rows than were locked")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// GUARD sweep-resumes-across-calls. MaxBatches stops a run mid-template and
// returns a Cursor; a second call with After: Cursor picks up exactly where
// the first left off, and the two calls' totals equal one uninterrupted run.
//
// This is the "resumable position rather than a half-applied all-or-nothing
// transaction" property, exercised through the MaxBatches lever (the context
// -cancellation lever is proven live, against a real crash, in
// template_reconcile_integration_test.go).
func TestReconcileResumesFromCursorAcrossCalls(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// First call: BatchSize 1, MaxBatches 1 — exactly one principal, and the
	// call must return WITHOUT running the second (terminal, empty) batch that
	// TestReconcileEmptyTemplateIsExplicit shows a completed run would.
	mock.ExpectBegin()
	mock.ExpectQuery(planQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-a"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-1", "org-1", "user-a", `["users:write"]`},
	))
	mock.ExpectExec(batchDeleteRe).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	first, err := ReconcileRoleTemplate(context.Background(), db, "tmpl-1", nil, reconcileRWPairs,
		ReconcileOptions{BatchSize: 1, MaxBatches: 1})
	if err != nil {
		t.Fatalf("first ReconcileRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("first call expectations: %v", err)
	}
	if first.Done {
		t.Fatal("first call reported Done although MaxBatches stopped it before the terminal page")
	}
	if first.Cursor == nil || first.Cursor.OrganizationID != "org-1" || first.Cursor.UserID != "user-a" {
		t.Fatalf("first.Cursor = %+v, want the last principal the batch examined", first.Cursor)
	}
	if first.BatchesRun != 1 || first.KeysSwept != 1 {
		t.Errorf("first = %+v, want 1 batch and 1 key swept", first)
	}

	// Second call, resuming from the cursor: the SECOND principal, and the
	// empty terminal page, completing the run.
	mock.ExpectBegin()
	mock.ExpectQuery(planAfterQueryRe).WillReturnRows(plannedRows([2]string{"org-1", "user-b"}))
	mock.ExpectQuery(batchKeysQueryRe).WillReturnRows(lockedKeyRows(
		[4]string{"key-2", "org-1", "user-b", `["modules:read"]`}, // retained: write implies read
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectQuery(planAfterQueryRe).WillReturnRows(plannedRows())
	mock.ExpectCommit()

	second, err := ReconcileRoleTemplate(context.Background(), db, "tmpl-1", []string{"modules:write"}, reconcileRWPairs,
		ReconcileOptions{BatchSize: 1, After: first.Cursor})
	if err != nil {
		t.Fatalf("second ReconcileRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("second call expectations: %v", err)
	}
	if !second.Done {
		t.Error("second call did not reach Done")
	}
	if second.KeysSwept != 0 || second.KeysSpared != 1 {
		t.Errorf("second = %+v, want 0 swept and 1 spared (write implies read)", second)
	}

	// The two calls together checked both principals exactly once.
	if first.PrincipalsChecked+second.PrincipalsChecked != 2 {
		t.Errorf("combined PrincipalsChecked = %d, want 2 (no principal skipped or repeated across the resume)",
			first.PrincipalsChecked+second.PrincipalsChecked)
	}
}

// GUARD sweep-refuses-with-no-handle.
func TestReconcileRefusesNilDB(t *testing.T) {
	_, err := ReconcileRoleTemplate(context.Background(), nil, "tmpl-1", nil, nil, ReconcileOptions{BatchSize: 1})
	if !errors.Is(err, ErrNoTemplateReconciler) {
		t.Fatalf("err = %v, want ErrNoTemplateReconciler", err)
	}
}

// GUARD sweep-refuses-empty-template-id, without touching the database.
func TestReconcileRefusesEmptyTemplateID(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = ReconcileRoleTemplate(context.Background(), db, "", nil, nil, ReconcileOptions{BatchSize: 1})
	if err == nil {
		t.Fatal("want an error for an empty template id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an empty template id must not reach the database: %v", err)
	}
}

// GUARD sweep-refuses-non-positive-batch-size. A caller that has not chosen a
// batch size must not silently get one chosen for it (see ReconcileOptions.
// BatchSize's doc: there is deliberately no default), and the refusal must not
// touch the database.
func TestReconcileRefusesNonPositiveBatchSize(t *testing.T) {
	for _, batchSize := range []int{0, -1} {
		db, mock, err := newSQLMock()
		if err != nil {
			t.Fatalf("new mock: %v", err)
		}

		_, err = ReconcileRoleTemplate(context.Background(), db, "tmpl-1", nil, nil, ReconcileOptions{BatchSize: batchSize})
		if err == nil {
			t.Errorf("BatchSize %d: want an error", batchSize)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("BatchSize %d must not reach the database: %v", batchSize, err)
		}
		_ = db.Close()
	}
}

// GUARD sweep-ctx-cancelled-before-any-batch-still-returns-cleanly. Cancelling
// before the first batch is a zero-progress, resumable stop — not an error —
// and it must not touch the database.
func TestReconcileCtxAlreadyCancelledTouchesNothing(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("new mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := ReconcileRoleTemplate(ctx, db, "tmpl-1", nil, nil, ReconcileOptions{BatchSize: 10})
	if err != nil {
		t.Fatalf("a pre-cancelled context must not be reported as a failure: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a pre-cancelled context must not reach the database: %v", err)
	}
	if result.Done {
		t.Error("Done = true on a run that never started")
	}
	if !reflect.DeepEqual(result, TemplateReconcileResult{Done: false}) {
		t.Errorf("result = %+v, want the zero-progress value", result)
	}
}
