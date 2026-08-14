// elevation_class_test.go is the CLASS TEST for "something other than a live
// user session acquired platform-admin".
//
// The behavioural tests next door assert what each function returns. This file
// asserts something they cannot: that there is nowhere ELSE in the package for
// an elevation to appear. That distinction is the whole reason API keys not
// inheriting their owner's platform-admin is enforceable at all — registry
// holds the same property with a comment and a single test on one middleware
// branch, and a second branch added later would not have been covered by
// either.
//
// Two assertions, both bidirectional:
//
//  1. KeyScopes is structurally incapable of consulting the carrier. No
//     receiver, no context, no connection, no principal. A rule kept by
//     remembering not to call something is a rule with a half-life; a function
//     with nothing to call it with is not.
//  2. auth.ScopeAdmin is named in exactly the functions listed here by name. A
//     new site — a convenience helper, a "just for the admin UI" shortcut —
//     fails this test rather than shipping, and a stale entry fails it too, so
//     the list cannot quietly become a record of things that used to be true.
package platformadmin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// packageFiles parses every non-test .go file in this package.
func packageFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files[name] = f
	}
	// A walk that matched almost nothing would make every assertion below pass
	// vacuously.
	if len(files) < 4 {
		t.Fatalf("parsed only %d non-test files in this package; the walk is not reaching it", len(files))
	}
	return fset, files
}

// exprString renders a type expression the way it is written in the source.
func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.Ellipsis:
		return "..." + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.FuncType:
		return "func(...)"
	}
	return "?"
}

func fieldTypes(fl *ast.FieldList) []string {
	if fl == nil {
		return nil
	}
	var out []string
	for _, f := range fl.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			out = append(out, exprString(f.Type))
		}
	}
	return out
}

// GUARD api-key-never-inherits-platform-admin, structurally.
//
// KeyScopes is the API-key path's entire elevation surface, and it takes only
// the key's own scopes. Give it a context and a receiver and it becomes
// possible to elevate a key; the reviewer who does that has to change this test
// and say why.
func TestKeyScopesCannotConsultTheCarrier(t *testing.T) {
	_, files := packageFiles(t)

	var fn *ast.FuncDecl
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Name.Name == "KeyScopes" {
				fn = fd
			}
		}
	}
	if fn == nil {
		t.Fatal("KeyScopes not found — this guard would pass vacuously")
	}

	if fn.Recv != nil {
		t.Errorf("KeyScopes has the receiver %v. A method on the Carrier can read the carrier, "+
			"and the point of this function is that the API-key path has nothing to read it with.",
			fieldTypes(fn.Recv))
	}
	params := fieldTypes(fn.Type.Params)
	if len(params) != 1 || params[0] != "[]string" {
		t.Errorf("KeyScopes takes %v, want exactly ([]string). A context, a *sql.DB, a *Carrier or "+
			"a user id are each enough to make an API key inherit its owner's platform-admin — "+
			"which would hand every unattended CI credential the highest privilege in the product.",
			params)
	}
	results := fieldTypes(fn.Type.Results)
	if len(results) != 1 || results[0] != "[]string" {
		t.Errorf("KeyScopes returns %v, want exactly ([]string)", results)
	}
}

// elevationSites is the bidirectional allowlist of functions permitted to name
// auth.ScopeAdmin, with the reason each is allowed to.
// KeyScopes is deliberately absent: it does not name the wildcard at all, it
// delegates to withoutAdmin. TestKeyScopesCannotConsultTheCarrier is what holds
// its shape.
var elevationSites = map[string]string{
	"SessionScopes": "the one elevation: strips the token's claim, re-adds it only for a live carrier row",
	"withoutAdmin":  "the one strip, shared by SessionScopes and KeyScopes",
}

// GUARD one-elevation-site. Every mention of the wildcard scope in this package
// is accounted for.
//
// The failure this prevents is not a wrong answer from any function here — it is
// a THIRD function appearing that also decides who is an administrator, so that
// the question has two answers and a reader has to find both. The estate has
// been here before: registry ended up with the carrier, an org-less scope union
// and mTLS all able to produce `admin`, and closing that took a breaking release.
func TestAuthScopeAdminIsNamedOnlyWhereElevationBelongs(t *testing.T) {
	_, files := packageFiles(t)

	found := map[string]bool{}
	outside := map[string]bool{}
	for name, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				// A package-level var/const naming the wildcard is an
				// elevation site with no function to blame.
				ast.Inspect(decl, func(n ast.Node) bool {
					if namesScopeAdmin(n) {
						outside["package-level declaration in "+name] = true
					}
					return true
				})
				continue
			}
			mentions := false
			ast.Inspect(fd, func(n ast.Node) bool {
				if namesScopeAdmin(n) {
					mentions = true
				}
				return true
			})
			if !mentions {
				continue
			}
			if _, ok := elevationSites[fd.Name.Name]; ok {
				found[fd.Name.Name] = true
				continue
			}
			outside[fd.Name.Name] = true
		}
	}

	if len(outside) > 0 {
		t.Errorf("auth.ScopeAdmin is named in %v, which is not an accounted-for elevation site. "+
			"Every place that can add or remove the platform-admin wildcard has to be one a reader "+
			"can enumerate; add it to elevationSites with the reason it exists, or route it through "+
			"SessionScopes/KeyScopes.", sortedKeys(outside))
	}
	for name, why := range elevationSites {
		if !found[name] {
			t.Errorf("elevationSites lists %q (%s) but it no longer names auth.ScopeAdmin. "+
				"A stale entry makes this allowlist a record of things that used to be true.", name, why)
		}
	}
	if len(found) == 0 {
		t.Fatal("no elevation site was found at all — this guard would pass vacuously")
	}
}

// namesScopeAdmin reports whether n is the selector auth.ScopeAdmin.
func namesScopeAdmin(n ast.Node) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ScopeAdmin" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "auth"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
