package notify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Create builds its column list by STRING CONCATENATION, which is the one thing
// in that statement a placeholder cannot protect: values are bound, names are
// spliced. That is safe only for as long as every name is a literal this package
// wrote, so this file guards the closed set rather than the splice.
//
// It replaces an integration test that tried to prove the VALUE is bound. That
// test could not fail: the column is uuid, so an interpolated value and a bound
// one are rejected identically for every input that differs between them, and a
// guard that cannot fail is worse than no guard because it reads as coverage.
// The reachable risk was never the value.

var safeColumnName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// allowedWriteColumns is the set Create may splice into its INSERT.
var allowedWriteColumns = map[string]bool{
	"organization_id": true,
}

func TestWriteOptionsOnlyEmitAllowedColumnNames(t *testing.T) {
	// Every exported option constructor in the package, applied.
	options := []struct {
		name string
		opt  ChannelWriteOption
	}{
		{"WithOwningOrganization", WithOwningOrganization("aaaaaaaa-0000-4000-8000-000000000001")},
	}
	for _, o := range options {
		w, err := newChannelWrite([]ChannelWriteOption{o.opt})
		if err != nil {
			t.Fatalf("%s: newChannelWrite: %v", o.name, err)
		}
		names, values := w.columns()
		if len(names) != len(values) {
			t.Fatalf("%s: %d column name(s) but %d value(s): the INSERT would bind the wrong "+
				"value to a column", o.name, len(names), len(values))
		}
		for _, name := range names {
			if !safeColumnName.MatchString(name) {
				t.Errorf("%s emits column name %q, which is not a bare identifier and is "+
					"spliced into SQL unquoted", o.name, name)
			}
			if !allowedWriteColumns[name] {
				t.Errorf("%s emits column name %q, which is not in allowedWriteColumns; add it "+
					"deliberately after checking the consumer schemas carry that column", o.name, name)
			}
		}
	}
}

// TestEveryWriteOptionIsCovered keeps the table above honest. Enumerating options
// by hand is exactly the kind of list that goes stale the first time someone adds
// one, and a stale list makes the guard above silently stop covering the new
// option -- a blind check looks identical to a clean one.
func TestEveryWriteOptionIsCovered(t *testing.T) {
	const covered = "WithOwningOrganization"

	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	var found []string
	for _, p := range pkg {
		for _, file := range p.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
					continue
				}
				for _, res := range fn.Type.Results.List {
					if id, ok := res.Type.(*ast.Ident); ok && id.Name == "ChannelWriteOption" {
						found = append(found, fn.Name.Name)
					}
				}
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("no ChannelWriteOption constructors found: this scan is looking at the wrong " +
			"thing, and an empty enumeration passes for free")
	}
	for _, name := range found {
		if !strings.Contains(covered, name) {
			t.Errorf("option constructor %s is not exercised by TestWriteOptionsOnlyEmitAllowedColumnNames; "+
				"add it there so its column name is checked", name)
		}
	}
}
