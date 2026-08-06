// canonical_surface_class_test.go is the CLASS TEST for "the module ships more
// than one way to spell one operation" (issues #149, #152, #70).
//
// The class has four members, and they are swept together here rather than
// asserted one file at a time because each is a defect of PRESENCE in the
// module's exported surface, not of behaviour in any single function. Nothing
// in a build fails when a second name for an existing operation appears; a
// human reviewer has to notice, and across three repository types and two auth
// packages, three reviewers in a row did not.
//
//  1. A `Deprecated:` marker on a method that still compiles. It is a comment,
//     so it stops nothing: the next caller reaches for the short, obvious name,
//     the compiler agrees, and the warning is read only by whoever was already
//     going to read the doc. v0.25.0 removed all five markers the module
//     carried — by DELETING the method where a replacement existed, and by
//     making the type checker do the work where one did not.
//  2. Two exported methods on one receiver for one operation. Nineteen of these
//     existed ("Create is an alias for CreateUser to match the admin
//     handlers"). Beyond doubling the surface, each one is a place a future
//     signature change — batch 11's tenancy parameter, for instance — has to
//     land twice, and where landing it once is a silent partial migration.
//  3. Two handle types for one connection. Five constructors took *sql.DB and
//     two took *sqlx.DB, so a consuming application built and injected both for
//     one identity layer.
//  4. More than one way to complete an OIDC exchange. A safe helper shipped
//     BESIDE an omittable one is opt-in security, and the omittable one is what
//     compiles when a caller forgets an option.
//
// Each guard below is bidirectional where it can be: it fails on a new member
// of the class AND on a stale allowlist entry, so the allowlist cannot quietly
// become a list of things that used to be true.
package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// moduleFiles parses every non-test .go file under identity/ (this package's
// own directory and all of its subpackages) and returns them with the FileSet
// used to report positions.
//
// Non-test files only: a test may legitimately name a removed API in a comment
// explaining why it was removed, and this guard is about the shipped surface.
func moduleFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		files[filepath.ToSlash(path)] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk identity/: %v", err)
	}
	if len(files) < 20 {
		// A walk that silently matched almost nothing would make every
		// assertion below vacuously pass.
		t.Fatalf("parsed only %d files under identity/; the walk is not reaching the module", len(files))
	}
	return fset, files
}

// receiverTypeName returns the (pointer-stripped) receiver type name of fd, or
// "" when fd is not a method.
func receiverTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	switch e := fd.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return e.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Member 1: no Deprecated: marker without a deletion plan
// ---------------------------------------------------------------------------

// deprecationRemovalPlan is the allowlist for `Deprecated:` markers. The key is
// the declaration's name; the value must name the release that removes it.
//
// It is EMPTY, and that is the point. The module carried five markers before
// v0.25.0 — TokenManager.Generate, oidc.Provider.GetAuthURL,
// UserWithOrgRoles.GetAllowedScopes, APIKeyRepository.MarkExpiryNotificationSent
// and OrganizationRepository.GetUserCombinedScopes — and every one of them was
// a fully exported, fully working method that named itself a trap in its own
// doc comment while the dangerous call kept compiling. Three had a real
// replacement and were deleted. Two did not, and were foreclosed by the type
// checker instead (see auth.GlobalScopes / auth.OrgScopes): a marker was never
// going to stop the misuse, so the misuse was made not to type-check.
//
// Adding an entry here is therefore a deliberate, reviewable act that commits
// to a removal release. Marking something deprecated and leaving it is what
// this guard exists to prevent.
var deprecationRemovalPlan = map[string]string{}

func TestCanonicalSurface_NoDeprecationWithoutARemovalPlan(t *testing.T) {
	fset, files := moduleFiles(t)

	seen := map[string]bool{}
	for path, f := range files {
		for _, d := range f.Decls {
			var doc *ast.CommentGroup
			var name string
			switch decl := d.(type) {
			case *ast.FuncDecl:
				doc, name = decl.Doc, decl.Name.Name
			case *ast.GenDecl:
				doc = decl.Doc
				if len(decl.Specs) > 0 {
					switch sp := decl.Specs[0].(type) {
					case *ast.TypeSpec:
						name = sp.Name.Name
					case *ast.ValueSpec:
						if len(sp.Names) > 0 {
							name = sp.Names[0].Name
						}
					}
				}
			default:
				continue
			}
			if doc == nil || !strings.Contains(doc.Text(), "Deprecated:") {
				continue
			}
			seen[name] = true
			if _, ok := deprecationRemovalPlan[name]; !ok {
				t.Errorf("%s: %s carries a `Deprecated:` marker with no entry in "+
					"deprecationRemovalPlan. A deprecated declaration that still compiles is a "+
					"trap the next caller falls into, not a remedy: delete it if a replacement "+
					"exists, foreclose the misuse with a type if one does not, or add an entry "+
					"here naming the release that removes it.",
					fset.Position(d.Pos()), name)
			}
			_ = path
		}
	}
	for name := range deprecationRemovalPlan {
		if !seen[name] {
			t.Errorf("%s has a deprecation removal plan but no longer carries a `Deprecated:` "+
				"marker; remove the stale entry so the list keeps meaning what it says", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Member 2: one canonical name per operation
// ---------------------------------------------------------------------------

// aliasDelegations is the allowlist for an exported method whose whole body is
// a call to another EXPORTED method on the same receiver — the shape every one
// of the nineteen removed aliases had.
//
// Delegation to an UNEXPORTED helper is not in this class and is not detected:
// TokenManager.Generate and GenerateForOrg both delegate to `generate`, but
// they are two operations (org-less and org-bound) that share an
// implementation, not two names for one operation, and their parameter types
// now differ.
var aliasDelegations = map[string]string{}

func TestCanonicalSurface_NoExportedMethodIsAnAliasForAnother(t *testing.T) {
	fset, files := moduleFiles(t)

	seen := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() {
				continue
			}
			recv := receiverTypeName(fd)
			if recv == "" || fd.Body == nil || len(fd.Body.List) != 1 {
				continue
			}
			if len(fd.Recv.List[0].Names) == 0 {
				continue
			}
			recvName := fd.Recv.List[0].Names[0].Name

			var call *ast.CallExpr
			switch st := fd.Body.List[0].(type) {
			case *ast.ReturnStmt:
				if len(st.Results) == 1 {
					call, _ = st.Results[0].(*ast.CallExpr)
				}
			case *ast.ExprStmt:
				call, _ = st.X.(*ast.CallExpr)
			}
			if call == nil {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sel.Sel.IsExported() {
				continue
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != recvName {
				continue
			}

			key := recv + "." + fd.Name.Name
			seen[key] = true
			if _, ok := aliasDelegations[key]; !ok {
				t.Errorf("%s: %s is a second exported name for %s.%s — one operation reachable "+
					"under two names. Collapse onto one canonical name and delete this one; "+
					"every later signature change (batch 11's tenancy parameter, for one) "+
					"otherwise has to land on both, and landing it on one is a silent partial "+
					"migration.",
					fset.Position(fd.Pos()), key, recv, sel.Sel.Name)
			}
		}
	}
	for key := range aliasDelegations {
		if !seen[key] {
			t.Errorf("%s is allowlisted as a delegating alias but no longer is; remove the "+
				"stale entry so the list keeps meaning what it says", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Member 3: one database handle type at the module boundary
// ---------------------------------------------------------------------------

// TestCanonicalSurface_NoSqlxInTheExportedAPI pins the collapse of the
// *sql.DB / *sqlx.DB split.
//
// sqlx is still used inside store (RoleTemplateRepository and
// OIDCConfigRepository scan through db-tagged structs, which is what the
// dependency is for). What must not come back is sqlx in a signature a
// consumer has to satisfy: that is what forced both applications to construct
// and thread two handle types for one identity layer, to the point where
// terraform-state-manager-backend wrote sqlx.NewDb(identityDB, "postgres")
// inline at two call sites purely to satisfy a constructor.
func TestCanonicalSurface_NoSqlxInTheExportedAPI(t *testing.T) {
	fset, files := moduleFiles(t)

	mentionsSqlx := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "sqlx" {
				found = true
			}
			return true
		})
		return found
	}

	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() {
				continue
			}
			// An unexported receiver keeps the method off the public surface.
			if recv := receiverTypeName(fd); recv != "" && !ast.IsExported(recv) {
				continue
			}
			if mentionsSqlx(fd.Type) {
				t.Errorf("%s: exported %s has sqlx in its signature. Every constructor in this "+
					"module takes the same *sql.DB; wrap it internally with newSqlxDB instead of "+
					"pushing a second handle type onto every consumer.",
					fset.Position(fd.Pos()), fd.Name.Name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Member 4: one way to complete an OIDC exchange
// ---------------------------------------------------------------------------

// TestCanonicalSurface_OneOIDCExchangeCompletion pins issue #152's remedy.
//
// The finding was that ExchangeCode sent no code_verifier at all when
// WithPKCEVerifier was not passed, and that omitting it compiled cleanly. The
// fix is not an ExchangeAndVerify helper shipped alongside it — that is opt-in
// security, and an opt-in remedy is exactly the shape that produced the finding.
// The fix is that ExchangeAndVerify is the ONLY exported method in the package
// that yields an *oauth2.Token, so there is no second path to reach the token
// endpoint and therefore none that can reach it unbound.
//
// Detecting "yields a token" by return type rather than by name is deliberate:
// a re-added ExchangeCode under any other name is still a second completion
// path, and this catches it.
func TestCanonicalSurface_OneOIDCExchangeCompletion(t *testing.T) {
	fset, files := moduleFiles(t)

	var completions []string
	for path, f := range files {
		if !strings.HasPrefix(path, "auth/oidc/") {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || fd.Type.Results == nil {
				continue
			}
			if recv := receiverTypeName(fd); recv != "" && !ast.IsExported(recv) {
				continue
			}
			for _, res := range fd.Type.Results.List {
				star, ok := res.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				sel, ok := star.X.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "oauth2" || sel.Sel.Name != "Token" {
					continue
				}
				completions = append(completions,
					fd.Name.Name+" ("+fset.Position(fd.Pos()).String()+")")
			}
		}
	}
	sort.Strings(completions)

	if len(completions) != 1 || !strings.HasPrefix(completions[0], "ExchangeAndVerify ") {
		t.Errorf("the oidc package exports %d authorization-code completions, want exactly one "+
			"(ExchangeAndVerify): %v.\nA second exported method that returns an *oauth2.Token is "+
			"a second way to finish a login, and the one a caller reaches for is whichever "+
			"compiles with the arguments in hand — which is how the PKCE binding became "+
			"omittable in the first place (issue #152).",
			len(completions), completions)
	}
}

// ---------------------------------------------------------------------------
// Cross-member: the scope types that replaced two of the deprecations
// ---------------------------------------------------------------------------

// TestCanonicalSurface_ScopeAccessorsAreTyped pins the type-level foreclosure
// that stands in for the two `Deprecated:` markers that had no replacement to
// migrate to.
//
// GetUserCombinedScopes / GetAllowedScopes (the cross-organization union) must
// return auth.GlobalScopes, and GetUserScopesForOrg / GetScopesForOrg (a single
// organization's grant) must return auth.OrgScopes. If either regressed to a
// bare []string, both would once again be assignable to
// TokenManager.GenerateForOrg — and an org-BOUND token minted from a cross-org
// union is precisely the escalation HasScopeInOrg would then honour. That is
// the mistake available to anyone migrating a call site from Generate to
// GenerateForOrg, which is what batch 11 asks every consumer to do.
func TestCanonicalSurface_ScopeAccessorsAreTyped(t *testing.T) {
	want := map[string]string{
		"GetUserCombinedScopes": "GlobalScopes",
		"GetAllowedScopes":      "GlobalScopes",
		"GetUserScopesForOrg":   "OrgScopes",
		"GetScopesForOrg":       "OrgScopes",
	}

	fset, files := moduleFiles(t)
	seen := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Type.Results == nil {
				continue
			}
			wantType, tracked := want[fd.Name.Name]
			if !tracked {
				continue
			}
			seen[fd.Name.Name] = true

			got := ""
			switch res := fd.Type.Results.List[0].Type.(type) {
			case *ast.SelectorExpr: // auth.GlobalScopes, from package models/store
				got = res.Sel.Name
			case *ast.Ident: // GlobalScopes, from within package auth
				got = res.Name
			case *ast.ArrayType:
				got = "[]" + types(res.Elt)
			}
			if got != wantType {
				t.Errorf("%s: %s returns %s, want %s. A bare []string is assignable to both "+
					"scope parameters, which re-opens the cross-organization escalation the "+
					"distinct types exist to foreclose.",
					fset.Position(fd.Pos()), fd.Name.Name, got, wantType)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s was not found in the module; if it was renamed or removed, update this "+
				"guard rather than letting it pass vacuously", name)
		}
	}
}

// types renders a simple type expression for the diagnostic above.
func types(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}
