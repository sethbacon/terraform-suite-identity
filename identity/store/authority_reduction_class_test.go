package store

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// CLASS TEST for "a statement that reduces derived authority with no
// credential invalidation" (issue #129).
//
// The class is (authority-conferring table) x (mutating statement). The issue
// listed five sites by hand and every one of its line numbers was stale, two of
// its symbol names no longer exist, and it missed three sites — which is the
// argument for deriving the inventory instead of transcribing it.
//
// Mechanism: parse every non-test file in this package, resolve package-level
// string constants the way auditoutbox.Guard does, and report every function
// whose body issues a DELETE or UPDATE against a table that carries authority.
// Each one must then be accounted for — covered by a Reducer method, or exempt
// with a written verdict. A site that is neither fails this test, so the next
// authority-reducing statement somebody adds cannot go unclassified.

// authorityTables are the tables whose rows CONFER authority. organizations and
// users are here because deleting one reduces every membership inside it by
// CASCADE, which is a reduction the statement's own text never mentions.
var authorityTables = []string{
	"organization_members",
	"role_templates",
	"organizations",
	"users",
}

// reductionStmtRe matches the statement kinds that can REMOVE authority.
// INSERT is deliberately absent: the only INSERT into organization_members in
// this package is under UNIQUE(organization_id, user_id), so it raises a unique
// violation rather than moving an existing member's role. An upsert would be a
// different matter — terraform-state-manager's mirror leg is one, and approles
// makes it take an AuthorityReducer for exactly that reason — so if one ever
// lands here this regex has to grow.
var reductionStmtRe = regexp.MustCompile(`(?is)\b(DELETE\s+FROM|UPDATE)\s+"?([a-z_]+)"?`)

// authorityMutator is one function found writing an authority-conferring table.
type authorityMutator struct {
	// Name is the receiver-qualified function name — the stable site identity.
	Name string
	// Position is file:line, for a failure a reader can act on.
	Position string
	// Tables are the authority-conferring tables it mutates, sorted.
	Tables []string
}

// errEmptyUniverse is what a scan that parsed no source reports. A scan that
// read nothing finds no violations and looks EXACTLY like a scan that read
// everything and found none, so the empty universe is an error rather than a
// clean report. TestAuthorityReductionInventoryFloorIsFalsifiable hands it one.
var errEmptyUniverse = errors.New("authority-reduction scan: parsed no source files")

// scanAuthorityMutators parses every non-test .go file directly in dir and
// returns the functions that mutate an authority-conferring table.
func scanAuthorityMutators(dir string) ([]authorityMutator, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, fmt.Errorf("authority-reduction scan: listing %s: %w", dir, err)
	}
	sort.Strings(paths)

	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("authority-reduction scan: parsing %s: %w", p, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, errEmptyUniverse
	}

	consts := packageStringConsts(files)

	var found []authorityMutator
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			tables := mutatedAuthorityTables(fn.Body, consts)
			if len(tables) == 0 {
				continue
			}
			pos := fset.Position(fn.Pos())
			found = append(found, authorityMutator{
				Name:     receiverQualifiedName(fn),
				Position: fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line),
				Tables:   tables,
			})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, nil
}

// packageStringConsts resolves package-level string constants and variables so
// a statement held in one is matched too. terraform-registry-backend's original
// audit guard matched only literals written inside the function body and walked
// straight past its own const-held INSERT; auditoutbox.Guard fixed that there
// and this reproduces the fix rather than the bug.
func packageStringConsts(files []*ast.File) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if s, ok := staticString(vs.Values[i], out); ok {
						out[name.Name] = s
					}
				}
			}
		}
	}
	return out
}

// staticString evaluates a string literal, a resolved identifier, or a
// concatenation of those.
func staticString(expr ast.Expr, resolved map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		s, ok := resolved[e.Name]
		return s, ok
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, okl := staticString(e.X, resolved)
		r, okr := staticString(e.Y, resolved)
		if !okl || !okr {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// mutatedAuthorityTables reports which authority-conferring tables a function
// body issues a DELETE or UPDATE against.
func mutatedAuthorityTables(body *ast.BlockStmt, consts map[string]string) []string {
	hit := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		var s string
		switch e := n.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(e.Value)
			if err != nil {
				return true
			}
			s = v
		case *ast.Ident:
			v, ok := consts[e.Name]
			if !ok {
				return true
			}
			s = v
		default:
			return true
		}
		for _, m := range reductionStmtRe.FindAllStringSubmatch(s, -1) {
			for _, t := range authorityTables {
				if m[2] == t {
					hit[t] = true
				}
			}
		}
		return true
	})
	tables := make([]string, 0, len(hit))
	for t := range hit {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	return tables
}

// receiverQualifiedName renders Type.Method, or the bare name for a free
// function.
func receiverQualifiedName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// authorityVerdict is the written account of one mutator found by the scan.
//
// Every mutator must have one. An entry with no matching mutator fails too, so
// a rename shows up as a stale verdict rather than as a site that quietly
// stopped being classified.
type authorityVerdict struct {
	// Reduces states whether the statement can REMOVE derived authority.
	Reduces bool
	// Covered names the Reducer method that makes this reduction and its
	// credential sweep one transaction. Empty unless Reduces.
	Covered string
	// Reconciled names the method that makes this reduction and its credential
	// sweep one OPERATION — reconcile first, mutate second, or neither — for
	// the reductions whose blast radius rules out doing it in one transaction.
	//
	// It is a third verdict rather than a loose reading of Covered because the
	// guarantee is genuinely weaker and a reader deserves to see which one a
	// site has. Covered means the two halves cannot half-happen. Reconciled
	// means they can — the sweep is many bounded transactions and the mutation
	// is another — but the sweep cannot be SKIPPED, cannot run in the order
	// that silently finds nobody, and cannot be left unfinished with the
	// mutation applied anyway. Collapsing the two would let a future site claim
	// atomicity it does not have.
	Reconciled string
	// Exempt is the written reason a reduction needs neither. Exactly one of
	// Covered, Reconciled and Exempt is set on a reduction; none is set on a
	// non-reduction.
	Exempt string
}

// authorityMutatorVerdicts is the whole class, derived by running the scan and
// then judging what it found — never transcribed from the issue, whose five
// hand-listed sites carried five stale line numbers, two symbol names that no
// longer exist, and missed three sites entirely.
var authorityMutatorVerdicts = map[string]authorityVerdict{
	// ---- reductions the Reducer makes transactional -----------------------
	"OrganizationRepository.RemoveMember": {
		Reduces: true, Covered: "Reducer.RemoveMember",
	},
	"OrganizationRepository.UpdateMemberRoleTemplate": {
		Reduces: true, Covered: "Reducer.UpdateMemberRoleTemplate",
	},
	"OrganizationRepository.RemoveAllMembershipsForUser": {
		Reduces: true, Covered: "Reducer.RemoveAllMembershipsForUser",
	},

	// ---- reductions the DATABASE already closes ---------------------------
	"UserRepository.DeleteUser": {
		Reduces: true,
		Exempt: "api_keys.user_id is ON DELETE CASCADE (migration 000007): the credential " +
			"cannot outlive the principal, in the same statement, with no application " +
			"cooperation at all. Pinned by TestIntegrationUserDeleteDoesNotRehomeItsRows.",
	},
	"OrganizationRepository.Delete": {
		Reduces: true,
		Exempt: "api_keys.organization_id is ON DELETE CASCADE (migration 000001) and so is " +
			"organization_members.organization_id: deleting the organization removes the " +
			"memberships and the keys bound to it in one statement.",
	},

	// ---- reductions a bounded reconciliation covers (issue #282) -----------
	//
	// Both edit the TEMPLATE rather than a membership, so the principals whose
	// authority moves are every member holding it — unbounded, and for a
	// seeded template that is potentially every member in the deployment. That
	// is why these are Reconciled and not Covered: a synchronous in-request
	// transaction over that set would take row locks on most of
	// organization_members and most of api_keys at once, and the failure mode
	// of getting it wrong is a fleet-wide credential destruction event rather
	// than a stranded key.
	//
	// The plain repository methods remain exported and still invalidate
	// nothing, exactly as OrganizationRepository.RemoveMember does beside
	// Reducer.RemoveMember. What changed with #282 is that the un-swept
	// reduction is now a CHOICE with a sanctioned alternative — naming a
	// different symbol — rather than the only path this module offers.
	"RoleTemplateRepository.UpdateRoleTemplate": {
		Reduces: true, Reconciled: "TemplateWriter.UpdateRoleTemplate",
	},
	"RoleTemplateRepository.DeleteRoleTemplate": {
		Reduces: true, Reconciled: "TemplateWriter.DeleteRoleTemplate",
	},

	// The sanctioned path's own statements. They are the SAME two package
	// constants the repository issues, which is why the scan finds them here
	// too — and why there is no second copy of either statement to drift.
	"TemplateWriter.UpdateRoleTemplate": {
		Reduces: true, Reconciled: "TemplateWriter.UpdateRoleTemplate",
	},
	"TemplateWriter.DeleteRoleTemplate": {
		Reduces: true, Reconciled: "TemplateWriter.DeleteRoleTemplate",
	},

	// ---- statements that touch an authority table but reduce nothing ------
	"OrganizationRepository.Update":   {Reduces: false},
	"OrganizationRepository.Rename":   {Reduces: false},
	"UserRepository.UpdateUser":       {Reduces: false},
	"UserRepository.linkOIDCIdentity": {Reduces: false},

	// ---- the Reducer's own statements -------------------------------------
	"Reducer.RemoveMember":                {Reduces: true, Covered: "Reducer.RemoveMember"},
	"Reducer.UpdateMemberRoleTemplate":    {Reduces: true, Covered: "Reducer.UpdateMemberRoleTemplate"},
	"Reducer.UpdateMemberRole":            {Reduces: true, Covered: "Reducer.UpdateMemberRole"},
	"Reducer.RemoveAllMembershipsForUser": {Reduces: true, Covered: "Reducer.RemoveAllMembershipsForUser"},
}

// authorityInventoryFloor is the minimum number of mutators the scan must find.
//
// IT IS NOT A STYLE RULE. A scan that reads zero files reports zero findings and
// is indistinguishable, from the outside, from a scan that read every file and
// found nothing wrong — so the inventory needs a number under it that a broken
// scan cannot meet. The value is today's count: lowering it is the move that
// makes this test vacuous, so lowering it has to be argued for in a diff rather
// than done to make a red test green.
//
// TestAuthorityReductionInventoryFloorIsFalsifiable proves the floor is real by
// handing the scan an EMPTY universe rather than by lowering it.
const authorityInventoryFloor = 17

// GUARD authority-reduction-inventory. Every statement in this package that can
// remove derived authority is either made transactional by a Reducer method or
// carries a written verdict saying why it need not be.
//
// # What this signature can see
//
//   - DELETE and UPDATE against organization_members, role_templates,
//     organizations and users, written as a string literal or held in a
//     package-level string constant or variable, including a concatenation of
//     those.
//   - The receiver-qualified name and file:line of the function issuing it.
//
// # What it CANNOT see, and is therefore not evidence about
//
//   - Delegating wrappers. OrganizationRepository.UpdateMemberRole issues no SQL
//     of its own -- it looks the template up and calls UpdateMemberRoleTemplate
//     -- so it does not appear here at all. A reduction reachable only through a
//     wrapper is invisible to this scan and visible only to the behavioural
//     tests.
//   - Reductions performed by CASCADE. "DELETE FROM users" never names
//     organization_members or api_keys, so the fact that it empties both is
//     encoded in the verdict above by hand, from the migrations, not derived.
//   - Whether an UPDATE actually NARROWS anything. It sees that
//     RoleTemplateRepository.UpdateRoleTemplate writes role_templates.scopes; it
//     cannot see whether the new scope set is smaller than the old one.
//   - Anything outside this package: the consuming applications' own
//     repositories, raw SQL, and psql.
//   - A statement assembled at runtime from a non-constant expression
//     (fmt.Sprintf over a variable table name). None exist here; one that landed
//     would be a blind spot.
func TestAuthorityReductionInventoryIsAccountedFor(t *testing.T) {
	found, err := scanAuthorityMutators(".")
	if err != nil {
		t.Fatalf("the authority-reduction scan could not run, so it establishes nothing: %v", err)
	}

	if len(found) < authorityInventoryFloor {
		t.Fatalf("the scan found %d authority mutators, below the floor of %d — "+
			"it is not looking at what it thinks it is, and a short inventory reports "+
			"no violations for the same reason a clean one does",
			len(found), authorityInventoryFloor)
	}

	byName := make(map[string]authorityMutator, len(found))
	for _, m := range found {
		byName[m.Name] = m
	}

	for _, m := range found {
		v, ok := authorityMutatorVerdicts[m.Name]
		if !ok {
			t.Errorf("%s (%s) mutates %v with no verdict: decide whether it reduces derived "+
				"authority, and either route it through a Reducer method or record why it "+
				"needs no credential sweep",
				m.Name, m.Position, m.Tables)
			continue
		}
		verdicts := 0
		for _, set := range []string{v.Covered, v.Reconciled, v.Exempt} {
			if set != "" {
				verdicts++
			}
		}
		switch {
		case !v.Reduces:
			if verdicts != 0 {
				t.Errorf("%s is recorded as not reducing authority but also carries a "+
					"coverage, reconciliation or exemption note; one of those is wrong", m.Name)
			}
		case verdicts > 1:
			t.Errorf("%s carries more than one verdict (covered/reconciled/exempt); they are "+
				"different guarantees and a site has exactly one", m.Name)
		case verdicts == 0:
			t.Errorf("%s (%s) reduces authority but is neither covered by a Reducer method, "+
				"nor reconciled by a bounded sweep, nor exempt with a stated reason",
				m.Name, m.Position)
		case v.Covered != "":
			if _, ok := byName[v.Covered]; !ok {
				t.Errorf("%s is recorded as covered by %s, but the scan found no such "+
					"statement-issuing method — the coverage claim resolves to nothing",
					m.Name, v.Covered)
			}
		case v.Reconciled != "":
			// Resolved the same way, and for the same reason: a reconciliation
			// claim naming a method that issues no statement is a claim about
			// nothing. The sanctioned writer issues the mutation itself (via
			// the shared package constants) rather than delegating to the
			// repository, which is what keeps it visible to this scan at all.
			if _, ok := byName[v.Reconciled]; !ok {
				t.Errorf("%s is recorded as reconciled by %s, but the scan found no such "+
					"statement-issuing method — the reconciliation claim resolves to nothing",
					m.Name, v.Reconciled)
			}
		}
	}

	for name := range authorityMutatorVerdicts {
		if _, ok := byName[name]; !ok {
			t.Errorf("verdict recorded for %s, which the scan no longer finds: it was renamed, "+
				"moved out of this package, or stopped issuing the statement it was judged on. "+
				"Re-derive the inventory rather than deleting the line", name)
		}
	}
}

// GUARD inventory-floor-is-falsifiable. The floor above is only worth anything
// if a scan that read nothing FAILS it, so this hands the scan an empty universe
// and requires an error rather than a clean, passing, empty report.
//
// It is the falsification the floor needs, and it is deliberately done by
// starving the scan rather than by lowering the constant: lowering the constant
// is how a floor stops being one.
func TestAuthorityReductionInventoryFloorIsFalsifiable(t *testing.T) {
	empty := t.TempDir()

	found, err := scanAuthorityMutators(empty)
	if err == nil {
		t.Fatalf("scanning an empty directory returned %d mutators and no error; a scan that "+
			"parsed nothing must not report a clean inventory, because a clean inventory is "+
			"exactly what a working scan of good code also returns", len(found))
	}
	if !errors.Is(err, errEmptyUniverse) {
		t.Errorf("scanning an empty directory failed with %v, want errEmptyUniverse so a "+
			"caller can tell a starved scan from a parse error", err)
	}
	if len(found) != 0 {
		t.Errorf("a failed scan returned %d mutators; a scan that could not run must "+
			"establish nothing", len(found))
	}

	// And the floor itself: the empty result must be BELOW it. A floor of zero
	// would have passed the check above and this is what says so.
	if len(found) >= authorityInventoryFloor {
		t.Errorf("an empty universe met the inventory floor of %d; the floor cannot detect "+
			"a scan that read nothing", authorityInventoryFloor)
	}
}

// reducerStatements is what one scan of authority_reduction.go saw about where
// its statements are issued.
type reducerStatements struct {
	// TxCalls is how many calls were made on the transaction handle. ASSERT ON
	// IT: zero means the scan is not looking at what it thinks it is.
	TxCalls int
	// PoolUses is how many times r.db is REFERENCED at all, counted
	// unconditionally as the walk sees each node. Exactly one is correct: the
	// BeginTx that opens the transaction.
	//
	// It is deliberately computed WITHOUT consulting the allow-list below, so
	// the guard has two independent readings of the same fact. Blinding the
	// finding branch — the obvious way to make this test green — leaves this
	// count at two and the test still fails.
	PoolUses int
	// Findings are the r.db references that are not the BeginTx receiver:
	// statements, or helpers handed the pool, that would run OUTSIDE the
	// transaction they appear to belong to.
	Findings []string
}

// errNoReducerSource is what a scan that found no *Reducer method reports.
var errNoReducerSource = errors.New("reducer statement scan: parsed no *Reducer methods")

// scanReducerStatements reports where the Reducer's statements are issued.
//
// # Why this is a source scan and not a behavioural test
//
// It was a behavioural test first, and the behavioural test was INERT. sqlmock
// serves a *sql.Tx and its parent *sql.DB from the same mock connection and
// records both against the same ordered expectation queue, so moving a statement
// from tx.QueryContext to r.db.QueryContext changes nothing it can observe:
// every expectation still matches, in order, and the test still passes while the
// statement now runs outside the transaction and commits on its own. That is the
// exact defect this whole file exists to prevent, and the mock cannot see it.
//
// A live PostgreSQL would see it, but the unit-test job has no database — so the
// property is asserted where it is decidable: in the source.
func scanReducerStatements(path string) (reducerStatements, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return reducerStatements{}, fmt.Errorf("reducer statement scan: parsing %s: %w", path, err)
	}

	var out reducerStatements
	methods := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		t := fn.Recv.List[0].Type
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		id, ok := t.(*ast.Ident)
		if !ok || id.Name != "Reducer" {
			continue
		}
		methods++

		// PASS 1 — the allow-list, recorded by POSITION so nothing else can
		// match it. Exactly two uses of the pool are legitimate inside a
		// Reducer: the BeginTx that opens the transaction, and the nil check
		// that refuses a Reducer with no handle. Everything else is a statement
		// that would commit on its own.
		allowed := map[token.Pos]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				sel, ok := e.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "BeginTx" {
					return true
				}
				if recv, ok := sel.X.(*ast.SelectorExpr); ok && isPoolRef(recv) {
					allowed[recv.Pos()] = true
				}
			case *ast.BinaryExpr:
				if e.Op != token.EQL && e.Op != token.NEQ {
					return true
				}
				for _, side := range []ast.Expr{e.X, e.Y} {
					sel, ok := side.(*ast.SelectorExpr)
					if ok && isPoolRef(sel) && isNilIdent(e.X) != isNilIdent(e.Y) {
						allowed[sel.Pos()] = true
					}
				}
			}
			return true
		})

		// PASS 2 — every reference to the pool, and every call on the
		// transaction. A reference is counted whether it is the receiver of a
		// call (r.db.QueryContext) or an ARGUMENT handed to a helper
		// (lookupRoleTemplateID(ctx, r.db, ...)). The argument form is the one
		// that made an earlier version of this scan blind: it issues its
		// statement outside the transaction while never writing r.db.Query
		// anywhere.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				if !isPoolRef(e) {
					return true
				}
				out.PoolUses++
				if !allowed[e.Pos()] {
					out.Findings = append(out.Findings, fmt.Sprintf("%s: %s reaches the "+
						"connection pool outside BeginTx", fset.Position(e.Pos()), receiverQualifiedName(fn)))
				}
			case *ast.CallExpr:
				if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "tx" {
						out.TxCalls++
					}
				}
			}
			return true
		})
	}
	if methods == 0 {
		return reducerStatements{}, errNoReducerSource
	}
	return out, nil
}

// isNilIdent reports whether e is the identifier nil.
func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// isPoolRef reports whether sel is the expression r.db.
func isPoolRef(sel *ast.SelectorExpr) bool {
	if sel.Sel.Name != "db" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "r"
}

// reducerTxStatementFloor is the minimum number of calls on the transaction
// handle the scan must see.
//
// Same reasoning as authorityInventoryFloor: a scan that resolved no statements
// reports no pool calls and looks exactly like a clean one. The value is below
// today's count so an ordinary refactor does not trip it, and far enough above
// zero that a scan pointed at the wrong file cannot meet it.
// TestReducerStatementFloorIsFalsifiable proves it by starving the scan.
const reducerTxStatementFloor = 8

// reducerPoolReferences is how many times a Reducer method may mention r.db:
// once for BeginTx and once for the no-handle refusal. Any other mention is a
// statement that escapes the transaction.
const reducerPoolReferences = 2

// GUARD reduction-statements-are-on-the-transaction. Every statement a Reducer
// issues runs on the transaction; the ONLY thing it may ask the pool for is
// BeginTx.
//
// MUTATION: change any tx.ExecContext / tx.QueryContext in authority_reduction.go
// to r.db.<same>. It still compiles, every behavioural test still passes, and
// this fails with the offending line.
func TestReducerIssuesEveryStatementOnTheTransaction(t *testing.T) {
	got, err := scanReducerStatements("authority_reduction.go")
	if err != nil {
		t.Fatalf("the reducer statement scan could not run, so it establishes nothing: %v", err)
	}

	if got.TxCalls < reducerTxStatementFloor {
		t.Fatalf("the scan saw %d calls on the transaction handle, below the floor of %d — "+
			"it is not resolving the statements it thinks it is, and a scan that resolves "+
			"nothing reports no findings for the same reason a clean one does",
			got.TxCalls, reducerTxStatementFloor)
	}
	// An EXACT count, not a lower bound, and computed without consulting the
	// allow-list. Suppressing the finding branch below is the obvious way to
	// make this test green after moving a statement onto the pool; it leaves
	// this number one too high, and the test still fails.
	if got.PoolUses != reducerPoolReferences {
		t.Errorf("the scan resolved %d references to the connection pool, want exactly %d "+
			"(the BeginTx that opens the transaction, and the nil check that refuses a "+
			"Reducer with no handle). A third one is a statement running outside the "+
			"reduction, or a helper handed the pool", got.PoolUses, reducerPoolReferences)
	}
	for _, f := range got.Findings {
		t.Errorf("%s — that statement commits on its own, outside the reduction it belongs to, "+
			"and no sqlmock-based test can tell the difference", f)
	}
}

// GUARD reducer-statement-floor-is-falsifiable. Starve the scan and require it
// to refuse rather than report a clean, passing, empty result.
func TestReducerStatementFloorIsFalsifiable(t *testing.T) {
	starved := filepath.Join(t.TempDir(), "empty.go")
	if err := os.WriteFile(starved, []byte("package store\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := scanReducerStatements(starved)
	if err == nil {
		t.Fatalf("a file with no *Reducer method scanned clean (%+v); a scan that resolved "+
			"nothing must not be indistinguishable from one that resolved everything", got)
	}
	if !errors.Is(err, errNoReducerSource) {
		t.Errorf("err = %v, want errNoReducerSource", err)
	}
	if got.TxCalls >= reducerTxStatementFloor {
		t.Errorf("a starved scan met the transaction-statement floor of %d; the floor cannot "+
			"detect a scan that resolved nothing", reducerTxStatementFloor)
	}
	if len(got.Findings) != 0 {
		t.Errorf("a failed scan returned %d findings; it must establish nothing", len(got.Findings))
	}
}
