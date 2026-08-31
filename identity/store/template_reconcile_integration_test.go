//go:build integration

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// Integration guards for the role-template reconciliation (issue #282).
//
// Same split of responsibility as authority_reduction_integration_test.go: the
// sqlmock suite in template_reconcile_test.go proves the statements and the
// per-batch control flow; this file proves what only a real transaction
// manager and a real uuid column can —
//
//   - ATOMICITY across a simulated crash: a batch that committed stays
//     committed, a batch that never started leaves no trace, and there is no
//     state in between.
//   - The `unnest($1::uuid[], $2::uuid[])` binding actually reaching real
//     uuid columns (sqlmock accepts whatever it is primed with, which is
//     exactly the gap authority_reduction_integration_test.go's own comment
//     names for `= ANY($n)`).
//   - The brief's own retention scenario, run against a real database rather
//     than mocked rows.
//
// Run with -tags=integration and TEST_DATABASE_URL set.

var templateReconcileRWPairs = auth.ReadWritePairs{"modules:read": "modules:write", "users:read": "users:write"}

// templateFixture is one role template, held by several principals across two
// organizations, plus deliberate noise — another template, another
// organization's key, an organization service credential, and another user —
// every one of which a correct reconciliation must leave untouched.
type templateFixture struct {
	template      string
	otherTemplate string
	orgA, orgB    string

	// Principals HOLDING `template` — every one of these is inside the scan.
	subsetUser  string // scopes are a SUBSET of the reduced template — must SURVIVE
	overUser    string // scopes exceed the reduced template — must be SWEPT
	orgBUser    string // same shape as overUser, but in orgB — must be SWEPT
	keylessUser string // holds the template but has NO api_keys row at all

	subsetKey, overKey, orgBKey string

	// Noise: principals that do NOT hold `template`, so a reconciliation of
	// it must never reach them.
	otherTemplateUser string // holds otherTemplate instead
	otherTemplateKey  string
	serviceKey        string // NULL user_id, derived from nobody's membership
}

// reducedTemplateScopes is the proposed (narrowed) scope set every test in
// this file reconciles `template` against — a role that used to grant
// "users:write" and now grants only "modules:write".
var reducedTemplateScopes = []string{"modules:write"}

func seedTemplateFixture(t *testing.T, db *sql.DB) templateFixture {
	t.Helper()
	ctx := context.Background()
	f := templateFixture{}

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	newID := func() string { return uuid.New().String() }
	newOrg := func(label string) string {
		id := newID()
		mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, id, "reconcile-"+label+"-"+id[:8], label)
		return id
	}
	newUser := func(label string) string {
		id := newID()
		mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, id, "u-"+id[:8]+"@example.test", label)
		return id
	}
	member := func(orgID, userID, templateID string) {
		mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
			orgID, userID, templateID)
	}
	key := func(owner *string, orgID, scopes string) string {
		id := newID()
		mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
		          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
			id, owner, orgID, "k-"+id[:6], "h", "p"+id[:6], []byte(scopes))
		return id
	}

	f.template = newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.template, "reconcile-tmpl-"+f.template[:8], "Reconciled", []byte(`["users:write","modules:write"]`))
	f.otherTemplate = newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.otherTemplate, "reconcile-other-"+f.otherTemplate[:8], "Untouched", []byte(`["users:write"]`))

	f.orgA = newOrg("a")
	f.orgB = newOrg("b")

	f.subsetUser = newUser("subset")
	f.overUser = newUser("over")
	f.orgBUser = newUser("orgb")
	f.keylessUser = newUser("keyless")
	f.otherTemplateUser = newUser("other-template")

	member(f.orgA, f.subsetUser, f.template)
	member(f.orgA, f.overUser, f.template)
	member(f.orgB, f.orgBUser, f.template)
	member(f.orgA, f.keylessUser, f.template)
	member(f.orgA, f.otherTemplateUser, f.otherTemplate)

	f.subsetKey = key(&f.subsetUser, f.orgA, `["modules:read"]`)
	f.overKey = key(&f.overUser, f.orgA, `["users:write"]`)
	f.orgBKey = key(&f.orgBUser, f.orgB, `["users:write"]`)
	f.otherTemplateKey = key(&f.otherTemplateUser, f.orgA, `["users:write"]`)
	f.serviceKey = key(nil, f.orgA, `["users:write"]`)

	return f
}

// templateMemberCount is how many (organization, user) pairs hold f.template —
// the Scanned/PrincipalsChecked universe every test below checks against.
func (f templateFixture) templateMemberCount() int { return 4 }

// sweptPrincipalCount is how many of those hold at least one key that a
// reconciliation against reducedTemplateScopes must sweep.
func (f templateFixture) sweptPrincipalCount() int { return 2 } // overUser, orgBUser

// GUARD retention-survives-a-live-reduction. The brief's own scenario: a
// principal whose CURRENT key scopes are a SUBSET of the template's new,
// reduced scopes must keep their key.
func TestIntegrationReconcileRetainsSubsetScopesAcrossAReduction(t *testing.T) {
	db := identityTestDB(t)
	f := seedTemplateFixture(t, db)

	result, err := ReconcileRoleTemplate(context.Background(), db, f.template, reducedTemplateScopes, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 50})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if !result.Done {
		t.Fatalf("result = %+v, want a completed run", result)
	}

	if !templateKeyExists(t, db, f.subsetKey) {
		t.Error("a key whose scopes (modules:read) are a subset of the reduced template's " +
			"scopes (modules:write implies modules:read) did not survive the reconciliation")
	}
	if templateKeyExists(t, db, f.overKey) {
		t.Error("a key asking for users:write, which the reduced template no longer grants, survived")
	}
	if templateKeyExists(t, db, f.orgBKey) {
		t.Error("the same over-scoped shape in a SECOND organization holding the template survived")
	}
}

// GUARD reconciliation-touches-only-what-it-should. Every noise entry in the
// fixture — another template's key and an organization service credential —
// must be untouched by a reconciliation of `template`.
func TestIntegrationReconcileDoesNotTouchUnrelatedKeys(t *testing.T) {
	db := identityTestDB(t)
	f := seedTemplateFixture(t, db)

	if _, err := ReconcileRoleTemplate(context.Background(), db, f.template, reducedTemplateScopes, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 50}); err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}

	for _, c := range []struct {
		what string
		id   string
	}{
		{"another template's key", f.otherTemplateKey},
		{"the organization SERVICE credential (NULL user_id)", f.serviceKey},
	} {
		if !templateKeyExists(t, db, c.id) {
			t.Errorf("%s was destroyed by a reconciliation of an unrelated template", c.what)
		}
	}
}

// GUARD preview-agrees-with-the-real-sweep. PreviewRoleTemplateReconciliation's
// answer, computed before anything runs, must equal what a completed
// ReconcileRoleTemplate run actually does — same templateID, same
// proposedScopes, same rwPairs. A mutation that changes what one sweeps
// without changing the other (or vice versa) fails THIS test by name.
func TestIntegrationPreviewAgreesWithTheRealSweep(t *testing.T) {
	db := identityTestDB(t)
	f := seedTemplateFixture(t, db)

	impact, err := PreviewRoleTemplateReconciliation(context.Background(), db, f.template, reducedTemplateScopes, templateReconcileRWPairs)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}

	// Small batch size, so the run genuinely spans multiple batches/transactions
	// rather than happening to fit in one — the property under test is that
	// batching doesn't change the total, not merely that one batch is correct.
	result, err := ReconcileRoleTemplate(context.Background(), db, f.template, reducedTemplateScopes, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 1})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if !result.Done {
		t.Fatalf("result = %+v, want a completed run", result)
	}
	if result.BatchesRun < 2 {
		t.Fatalf("BatchesRun = %d with BatchSize 1 and %d members; the fixture must span "+
			"multiple batches for this test to prove anything about batching",
			result.BatchesRun, f.templateMemberCount())
	}

	if impact.Keys != result.KeysSwept {
		t.Errorf("Preview.Keys = %d, ReconcileRoleTemplate swept %d — preview and the real "+
			"sweep disagree", impact.Keys, result.KeysSwept)
	}
	if impact.Principals != f.sweptPrincipalCount() {
		t.Errorf("Preview.Principals = %d, want %d", impact.Principals, f.sweptPrincipalCount())
	}
	// Scanned is every (org, user) holding the template, including the one
	// with no keys at all — PrincipalsChecked from the real run counts the
	// same universe.
	if impact.Scanned != f.templateMemberCount() {
		t.Errorf("Preview.Scanned = %d, want %d (every principal holding the template)", impact.Scanned, f.templateMemberCount())
	}
	if impact.Scanned != result.PrincipalsChecked {
		t.Errorf("Preview.Scanned = %d, ReconcileRoleTemplate checked %d principals",
			impact.Scanned, result.PrincipalsChecked)
	}
}

// GUARD widen-or-reorder-sweeps-nothing-live. Same property as the sqlmock
// test, against a real database: proposing the template's CURRENT (unreduced)
// scopes, reordered, must sweep nothing — proven directly by re-reading
// AuthorityRetained's own contract, not a heuristic.
func TestIntegrationReconcileWideningLeavesEveryKeyLive(t *testing.T) {
	db := identityTestDB(t)
	f := seedTemplateFixture(t, db)

	widened := []string{"modules:write", "users:write", "audit:read"} // superset, reordered
	result, err := ReconcileRoleTemplate(context.Background(), db, f.template, widened, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 50})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	if result.KeysSwept != 0 {
		t.Errorf("KeysSwept = %d on a widening reconciliation, want 0", result.KeysSwept)
	}
	for _, id := range []string{f.subsetKey, f.overKey, f.orgBKey} {
		if !templateKeyExists(t, db, id) {
			t.Errorf("key %s was destroyed by a widening reconciliation", id)
		}
	}
}

// GUARD re-verify-spares-a-principal-reassigned-mid-batch. The tie-breaker
// this module is biased toward: a principal moved to a DIFFERENT template
// between the page being planned and the locked read that follows it must not
// be judged against the template it no longer holds.
//
// This is deliberately NOT a goroutine-timed race: it calls planBatch and
// sweepBatchKeys directly (both package-internal, reachable because this file
// is `package store`) with a real, uncommitted UPDATE run on a SEPARATE
// connection in between them, on the SAME already-open transaction. Under
// PostgreSQL's default READ COMMITTED isolation each statement within an open
// transaction takes a fresh snapshot, so sweepBatchKeys's SELECT sees the
// concurrent UPDATE's committed result even though the surrounding
// transaction began before it — deterministically, with no sleep and no
// timing assumption, which a goroutine-based race could not offer.
//
// A prior mutation pass on this file found that dropping the batch query's
// `role_template_id = $3` predicate entirely still passed every OTHER test in
// this package — the sqlmock suite only caught it by regexp on the SQL TEXT,
// and no existing integration test exercised the property behaviourally. This
// test is what closes that gap.
func TestIntegrationReconcileSparesAPrincipalReassignedMidBatch(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()
	newID := func() string { return uuid.New().String() }

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	template := newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		template, "reconcile-reassign-tmpl-"+template[:8], "Template", []byte(`["users:write"]`))
	other := newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		other, "reconcile-reassign-other-"+other[:8], "Other", []byte(`["users:write"]`))
	org := newID()
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, org, "reconcile-reassign-org-"+org[:8], "Org")
	user := newID()
	mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, user, "u-"+user[:8]+"@example.test", "reassigned")
	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		org, user, template)
	key := newID()
	mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
	          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		key, user, org, "k-"+key[:6], "h", "p"+key[:6], []byte(`["users:write"]`))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	page, err := planBatch(ctx, tx, template, nil, 10)
	if err != nil {
		t.Fatalf("planBatch: %v", err)
	}
	if len(page) != 1 {
		t.Fatalf("page = %v, want exactly the one seeded principal", page)
	}

	// The "concurrent edit": committed on a DIFFERENT connection from the
	// pool, in between the plan read and the locked read — the principal now
	// holds `other`, not `template`.
	if _, err := db.ExecContext(ctx,
		`UPDATE organization_members SET role_template_id = $1 WHERE organization_id = $2 AND user_id = $3`,
		other, org, user); err != nil {
		t.Fatalf("concurrent reassignment: %v", err)
	}

	swept, _, err := sweepBatchKeys(ctx, tx, template, nil, templateReconcileRWPairs, page)
	if err != nil {
		t.Fatalf("sweepBatchKeys: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if swept != 0 {
		t.Errorf("swept = %d, want 0: the principal's membership had already moved to a "+
			"different template by the time the locked read ran, so this key belongs to "+
			"`other` now and must not be judged against `template`", swept)
	}
	if !templateKeyExists(t, db, key) {
		t.Error("a key belonging to a principal reassigned to a DIFFERENT template mid-batch " +
			"was destroyed anyway")
	}
}

// GUARD empty-template-sweeps-nothing-explicitly-live. A template with zero
// members (a freshly created one, held by nobody) must be reported and swept
// as an explicit, examined empty universe.
func TestIntegrationReconcileEmptyTemplateIsExplicit(t *testing.T) {
	db := identityTestDB(t)
	ctx := context.Background()

	emptyTemplate := uuid.New().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		emptyTemplate, "reconcile-empty-"+emptyTemplate[:8], "Empty", []byte(`["modules:write"]`)); err != nil {
		t.Fatalf("seed empty template: %v", err)
	}

	impact, err := PreviewRoleTemplateReconciliation(ctx, db, emptyTemplate, nil, templateReconcileRWPairs)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}
	if impact != (TemplateReconcileImpact{}) {
		t.Errorf("impact = %+v, want the zero value for a template nobody holds", impact)
	}

	result, err := ReconcileRoleTemplate(ctx, db, emptyTemplate, nil, templateReconcileRWPairs, ReconcileOptions{BatchSize: 50})
	if err != nil {
		t.Fatalf("ReconcileRoleTemplate: %v", err)
	}
	want := TemplateReconcileResult{BatchesRun: 1, Done: true}
	if result != want {
		t.Errorf("result = %+v, want %+v — one batch that queried and found nothing, not a "+
			"skipped call", result, want)
	}
}

// GUARD crash-mid-sweep-leaves-a-resumable-position, not a half-applied batch.
//
// Five principals, each with exactly one doomed key, BatchSize 1 so each batch
// covers exactly one principal. MaxBatches: 2 stops the run after exactly two
// committed batches — the same stopping path ctx cancellation takes (both are
// checked at the same loop boundary in ReconcileRoleTemplate and return the
// same way), chosen over a cancelled context here because pgx and
// database/sql both consult ctx.Err() internally an implementation-dependent
// number of times per statement; against a REAL connection that makes "cancel
// after exactly N of MY OWN checks" impossible to calibrate deterministically,
// whereas MaxBatches is compared only against BatchesRun, a value this test
// controls completely. TestReconcileCtxAlreadyCancelledTouchesNothing (mock)
// covers the ctx path in isolation, where no driver is present to blur the
// count.
//
// The database is read DIRECTLY (not through this package) to prove the state
// a real transaction manager leaves behind: exactly 2 keys gone, exactly 3
// still live — never a fraction of one batch's work. Resuming from the
// returned Cursor then finishes the other 3 with no key skipped or
// double-counted.
func TestIntegrationReconcileCrashMidSweepIsResumable(t *testing.T) {
	db := identityTestDB(t)
	f := crashFixture(t, db, 5)

	first, err := ReconcileRoleTemplate(context.Background(), db, f.template, nil, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 1, MaxBatches: 2})
	if err != nil {
		t.Fatalf("first ReconcileRoleTemplate: %v", err)
	}
	if first.Done {
		t.Fatal("first run reported Done although the simulated crash should have stopped it")
	}
	if first.BatchesRun != 2 {
		t.Fatalf("BatchesRun = %d, want exactly 2 (the simulated crash trips before a 3rd begins)", first.BatchesRun)
	}
	if first.Cursor == nil {
		t.Fatal("Cursor = nil after a stopped run; nothing to resume from")
	}

	live := templateReconcileLiveKeyCount(t, db, f.keys)
	if live != 3 {
		t.Fatalf("live keys after the simulated crash = %d, want exactly 3 (5 seeded minus the "+
			"2 committed batches) — anything else means a batch was left half-applied", live)
	}

	second, err := ReconcileRoleTemplate(context.Background(), db, f.template, nil, templateReconcileRWPairs,
		ReconcileOptions{BatchSize: 1, After: first.Cursor})
	if err != nil {
		t.Fatalf("resumed ReconcileRoleTemplate: %v", err)
	}
	if !second.Done {
		t.Fatalf("resumed run did not complete: %+v", second)
	}
	if first.KeysSwept+second.KeysSwept != 5 {
		t.Errorf("total KeysSwept across both calls = %d, want 5 (no key skipped or re-swept)",
			first.KeysSwept+second.KeysSwept)
	}
	if first.PrincipalsChecked+second.PrincipalsChecked != 5 {
		t.Errorf("total PrincipalsChecked across both calls = %d, want 5", first.PrincipalsChecked+second.PrincipalsChecked)
	}
	if templateReconcileLiveKeyCount(t, db, f.keys) != 0 {
		t.Error("a key survived a completed (resumed) reconciliation that swept every principal")
	}
}

// crashFixture is n principals holding one freshly created template, each with
// exactly one api_keys row that is NOT retained under a nil (== "about to be
// deleted") proposed scope set.
type crashFixtureResult struct {
	template string
	keys     []string
}

func crashFixture(t *testing.T, db *sql.DB, n int) crashFixtureResult {
	t.Helper()
	ctx := context.Background()
	newID := func() string { return uuid.New().String() }

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	template := newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		template, "reconcile-crash-"+template[:8], "Crash", []byte(`["users:write"]`))
	org := newID()
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, org, "reconcile-crash-org-"+org[:8], "Crash")

	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		user := newID()
		mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, user, "u-"+user[:8]+"@example.test", "crash")
		mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
			org, user, template)
		key := newID()
		mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
		          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
			key, user, org, "k-"+key[:6], "h", "p"+key[:6], []byte(`["users:write"]`))
		keys = append(keys, key)
	}
	return crashFixtureResult{template: template, keys: keys}
}

func templateReconcileLiveKeyCount(t *testing.T, db *sql.DB, ids []string) int {
	t.Helper()
	live := 0
	for _, id := range ids {
		if templateKeyExists(t, db, id) {
			live++
		}
	}
	return live
}

func templateKeyExists(t *testing.T, db *sql.DB, id string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM identity.api_keys WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("api key existence check: %v", err)
	}
	return ok
}
