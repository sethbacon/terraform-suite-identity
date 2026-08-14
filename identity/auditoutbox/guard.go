// guard.go is layer 3: the re-runnable source signature for "a privileged
// mutation with no audit record".
//
// A test asserting that Grant and Revoke refuse a nil IntentWriter proves
// something about the two accessors that exist today. It says nothing about the
// third one somebody adds next year. This does: it fails the moment ANY function
// in a scanned package writes to a protected table without taking an
// IntentWriter, including a helper nobody thought to write a behavioural test
// for.
//
// It is a source scan rather than a type assertion because the property is about
// the shape of the API — "you cannot express this mutation without also
// expressing its audit record" — not about a value. The constraint trigger
// (ddl.go) is the runtime half of the same rule and holds for callers that never
// come through the scanned package at all.
//
// # It lives here so the app can run it
//
// The mutations are in the app's repositories package, in the app's repo, and
// each app would otherwise hand-copy the analyzer. Two copies of a guard are two
// guards, and the second one is always the one that rots. The app's test is
// three lines:
//
//	report, err := auditoutbox.Guard{Tables: []string{"platform_admins"}}.ScanDir(".")
//	if err != nil { t.Fatal(err) }
//	if len(report.Findings) > 0 { t.Error(report.Findings) }
//	if report.Mutators < 2 { t.Fatalf("the scan is not looking at what it thinks it is") }
//
// # What it sees that registry's original did not
//
// terraform-registry-backend's version matched SQL only in string literals
// written INSIDE the function body. Its own outbox INSERT is a package-level
// const — so the same idiom applied to a mutation would have walked straight
// past the guard. This resolves package-level string constants and variables and
// literal concatenation before matching, which is the difference between a guard
// and a guard-shaped test.
package auditoutbox

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrGuard is the sentinel a scan that could not run wraps. A scan that CANNOT
// run establishes nothing about the code it was pointed at, so it is an error
// rather than an empty, passing report.
var ErrGuard = errors.New("identity/auditoutbox: mutation guard")

// defaultWriterTypes are the parameter type names that count as an audit-intent
// writer. Both names are accepted: this package exports IntentWriter, and
// terraform-registry-backend's repositories package already had
// AuditIntentWriter before this one existed.
var defaultWriterTypes = []string{"IntentWriter", "AuditIntentWriter"}

// Guard scans Go source for functions that mutate a protected table without
// taking an audit-intent writer.
type Guard struct {
	// Tables are the protected tables, by unqualified name. A schema-qualified
	// name is accepted and matched on its table part, because the SQL in the
	// scanned package may or may not qualify it.
	Tables []string
	// WriterTypes are the parameter type names that satisfy the requirement.
	// Empty means IntentWriter and AuditIntentWriter.
	WriterTypes []string
}

// Finding is one function that mutates a protected table unaudited.
type Finding struct {
	// Position is the file:line:col of the offending function declaration.
	Position string
	// Func is its name, receiver-qualified where it has one.
	Func string
	// Table is the protected table it writes.
	Table string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s writes to %s but takes no audit-intent writer", f.Position, f.Func, f.Table)
}

// Report is what one scan saw. The counts are for the caller's own
// non-vacuity assertion: a renamed table, a moved file or a changed SQL idiom
// would otherwise make every finding vacuously absent and the test would keep
// reporting green while protecting nothing.
type Report struct {
	// Files is how many non-test source files were parsed.
	Files int
	// Mutators is how many functions were found writing a protected table, with
	// or without a writer. ASSERT ON IT: zero means the scan is not looking at
	// what it thinks it is.
	Mutators int
	// Findings is every unaudited mutator, in source order.
	Findings []Finding
}

// ScanDir parses every non-test .go file directly in dir and reports the
// unaudited mutators.
//
// It does not recurse. The unit of the property is a package: a repository
// package's mutations are the ones its own IntentWriter contract binds, and a
// recursive scan would report findings a reader cannot act on from the failing
// test's location.
func (g Guard) ScanDir(dir string) (Report, error) {
	matchers, err := g.matchers()
	if err != nil {
		return Report{}, err
	}
	writerTypes := g.WriterTypes
	if len(writerTypes) == 0 {
		writerTypes = defaultWriterTypes
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return Report{}, fmt.Errorf("%w: listing %s: %w", ErrGuard, dir, err)
	}
	sort.Strings(paths)

	fset := token.NewFileSet()
	var files []*ast.File
	var report Report
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return Report{}, fmt.Errorf("%w: parsing %s: %w", ErrGuard, path, err)
		}
		files = append(files, file)
		report.Files++
	}
	if report.Files == 0 {
		return Report{}, fmt.Errorf("%w: no non-test Go source in %q — the scan would pass vacuously",
			ErrGuard, dir)
	}

	// Package-level string constants and variables first: SQL is routinely
	// hoisted out of the function that runs it, and a scan that only reads
	// literals in the body walks straight past that.
	consts := packageStrings(files)

	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			hit := ""
			for _, m := range matchers {
				if bodyMutates(fn.Body, consts, m.pattern) {
					hit = m.table
					break
				}
			}
			if hit == "" {
				continue
			}
			report.Mutators++
			if takesWriter(fn, writerTypes) {
				continue
			}
			report.Findings = append(report.Findings, Finding{
				Position: fset.Position(fn.Pos()).String(),
				Func:     funcName(fn),
				Table:    hit,
			})
		}
	}
	return report, nil
}

type tableMatcher struct {
	table   string
	pattern *regexp.Regexp
}

func (g Guard) matchers() ([]tableMatcher, error) {
	if len(g.Tables) == 0 {
		// Failing on an empty universe: a guard with nothing to protect finds
		// nothing and reads as protection.
		return nil, fmt.Errorf("%w: no protected tables named; the scan would pass vacuously", ErrGuard)
	}
	matchers := make([]tableMatcher, 0, len(g.Tables))
	for _, name := range g.Tables {
		t, err := parseTable("protected table", name)
		if err != nil {
			return nil, err
		}
		// Optionally schema-qualified in the SQL, whether or not it was
		// qualified here: `INSERT INTO app.platform_admins` and
		// `INSERT INTO platform_admins` are the same mutation.
		matchers = append(matchers, tableMatcher{
			table: t.String(),
			pattern: regexp.MustCompile(`(?is)(insert\s+into|delete\s+from|update)\s+"?(?:[a-z_][a-z0-9_$]*"?\."?)?` +
				regexp.QuoteMeta(t.name) + `"?\b`),
		})
	}
	return matchers, nil
}

// packageStrings collects package-level string constants and variables whose
// value is a literal, or a concatenation of literals and other such names.
//
// Two passes, so declaration order does not decide what is resolvable: a const
// block that builds one query out of another resolves either way round.
func packageStrings(files []*ast.File) map[string]string {
	raw := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						raw[name.Name] = vs.Values[i]
					}
				}
			}
		}
	}

	resolved := map[string]string{}
	// One pass per name is enough to settle any acyclic chain of references.
	for range raw {
		progressed := false
		for name, expr := range raw {
			if _, done := resolved[name]; done {
				continue
			}
			if s, ok := evalString(expr, resolved); ok {
				resolved[name] = s
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return resolved
}

// evalString folds an expression to a string where it can: a literal, a name
// already resolved, or a concatenation of those.
func evalString(expr ast.Expr, resolved map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(e.Value)
		if err != nil {
			return e.Value, true
		}
		return text, true
	case *ast.Ident:
		s, ok := resolved[e.Name]
		return s, ok
	case *ast.ParenExpr:
		return evalString(e.X, resolved)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, lok := evalString(e.X, resolved)
		right, rok := evalString(e.Y, resolved)
		if !lok || !rok {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// bodyMutates reports whether any string the body can reach is a write against
// the protected table.
func bodyMutates(body *ast.BlockStmt, consts map[string]string, pattern *regexp.Regexp) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(node.Value)
			if err != nil {
				text = node.Value
			}
			if pattern.MatchString(text) {
				found = true
				return false
			}
		case *ast.Ident:
			if text, ok := consts[node.Name]; ok && pattern.MatchString(text) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// takesWriter reports whether fn declares a parameter of one of the writer
// types, named or selector-qualified.
func takesWriter(fn *ast.FuncDecl, writerTypes []string) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		var name string
		switch t := field.Type.(type) {
		case *ast.Ident:
			name = t.Name
		case *ast.SelectorExpr:
			name = t.Sel.Name
		}
		for _, want := range writerTypes {
			if name == want {
				return true
			}
		}
	}
	return false
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		return "(receiver)." + fn.Name.Name
	}
	return fn.Name.Name
}
