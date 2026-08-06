package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This file guards a CLASS, not a bug: "a table this module writes to grows
// without bound because nothing prunes it".
//
// Issue #154 found it on revoked_tokens. The reason it was worth a class guard
// rather than a one-line fix is the shape of the near-miss: a
// CleanupExpiredRevocations method already existed, so the table looked
// maintained. What it lacked was anything that CALLS it — and a prune nobody
// calls is indistinguishable from no prune at all. The same trap is available
// to the next append-only table anyone adds here.
//
// Two invariants are asserted:
//
//  1. Every table the package INSERTs into is classified, and every append-only
//     table has a DELETE with a TIME HORIZON (not merely a delete-by-id, which
//     bounds nothing).
//  2. For revoked_tokens specifically, the prune is reachable from the WRITE
//     PATH: whichever function issues the INSERT must also trigger the prune.
//     This is the invariant that survives a refactor which "simplifies away"
//     the self-prune back into a host-scheduled helper.

// tableGrowth classifies how a table's row count is bounded.
type tableGrowth int

const (
	// growthEntity: one row per administered entity (a user, an organization, a
	// membership, an API key, a configured IdP). The row count is bounded by the
	// size of the estate and shrinks when the entity is deleted, so a
	// delete-by-id is a sufficient lifecycle.
	growthEntity tableGrowth = iota
	// growthAppendOnly: one row per EVENT. The row count grows with time and
	// traffic and is bounded only by something that deletes old rows on a
	// horizon.
	growthAppendOnly
)

// writtenTableGrowth classifies every table this package INSERTs into.
//
// The test below fails if the package writes a table that is missing from this
// map, so adding an append-only table cannot silently skip the bound. It also
// fails on a stale entry, so a removed table cannot pre-authorize a future one
// of the same name.
var writtenTableGrowth = map[string]tableGrowth{
	"users":                growthEntity,
	"organizations":        growthEntity,
	"organization_members": growthEntity,
	"api_keys":             growthEntity,
	"role_templates":       growthEntity,
	"oidc_config":          growthEntity,

	// One row per audit event. Bounded by DeleteAuditLogsBefore, which takes the
	// cutoff from the caller: retention length is a policy decision this module
	// must not make for its hosts, but the PATH has to exist here.
	"audit_logs": growthAppendOnly,
	// One row per revoked token. Bounded by RevokeToken's own self-prune, which
	// is asserted separately below.
	"revoked_tokens": growthAppendOnly,
}

var insertIntoPattern = regexp.MustCompile(`(?i)INSERT\s+INTO\s+([a-z_][a-z0-9_]*)`)

// horizonDeletePattern matches a DELETE against table that carries a
// strictly-less-than comparison on a time column somewhere in the same
// statement (the audit sweep puts its comparison in a subselect).
func horizonDeletePattern(table string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)DELETE\s+FROM\s+` + table + `.{0,500}?(created_at|expires_at|revoked_at)\s*<`)
}

// packageSources returns the package's non-test .go files as name -> contents.
func packageSources(t *testing.T) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read package directory: %v", err)
	}

	sources := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		contents, err := os.ReadFile(name) // #nosec G304 -- test-only read of this package's own source files, enumerated from the package directory
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		sources[name] = string(contents)
	}
	if len(sources) == 0 {
		t.Fatal("no package sources found; this guard would pass vacuously")
	}
	return sources
}

// TestUnboundedGrowthClass_EveryWrittenTableIsBounded asserts that every table
// this package INSERTs into is classified, and that every append-only one has a
// horizon delete.
func TestUnboundedGrowthClass_EveryWrittenTableIsBounded(t *testing.T) {
	sources := packageSources(t)

	written := map[string]bool{}
	all := strings.Builder{}
	for _, contents := range sources {
		all.WriteString(contents)
		all.WriteString("\n")
		for _, match := range insertIntoPattern.FindAllStringSubmatch(contents, -1) {
			written[match[1]] = true
		}
	}
	joined := all.String()

	var unclassified []string
	for table := range written {
		if _, ok := writtenTableGrowth[table]; !ok {
			unclassified = append(unclassified, table)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("these tables are written by this package but not classified in "+
			"writtenTableGrowth: %v\n"+
			"Classify each one. growthAppendOnly requires a delete with a time horizon; "+
			"growthEntity asserts the row count is bounded by the estate, not by traffic.",
			unclassified)
	}

	var stale []string
	for table := range writtenTableGrowth {
		if !written[table] {
			stale = append(stale, table)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("writtenTableGrowth classifies tables this package no longer writes: %v\n"+
			"Remove them, so a stale entry cannot silently pre-classify a future table "+
			"of the same name.", stale)
	}

	for table, growth := range writtenTableGrowth {
		if growth != growthAppendOnly {
			continue
		}
		if !horizonDeletePattern(table).MatchString(joined) {
			t.Errorf("%s is append-only but this package contains no DELETE against it with a "+
				"time horizon (created_at/expires_at/revoked_at < ...). A delete-by-id bounds "+
				"nothing: the table still grows for the life of the deployment.", table)
		}
	}
}

// TestUnboundedGrowthClass_RevocationPruneRidesTheWritePath asserts the prune is
// reachable from the only statement that grows revoked_tokens.
//
// This is the guard against the failure mode issue #154 actually described: a
// cleanup method that exists, is documented, and is never called. Scheduling the
// prune anywhere a host has to opt into leaves the table unbounded on every
// deployment that forgets; attaching it to the write itself cannot be forgotten,
// and this test is what keeps it attached.
func TestUnboundedGrowthClass_RevocationPruneRidesTheWritePath(t *testing.T) {
	const (
		insertMarker = "INSERT INTO revoked_tokens"
		pruneCall    = "maybePruneExpiredRevocations"
	)

	fset := token.NewFileSet()
	var writers []string

	for name := range packageSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			inserts := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && strings.Contains(lit.Value, insertMarker) {
					inserts = true
				}
				return true
			})
			if !inserts {
				continue
			}
			writers = append(writers, fn.Name.Name)

			prunes := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel.Name == pruneCall {
						prunes = true
					}
				case *ast.Ident:
					if fun.Name == pruneCall {
						prunes = true
					}
				}
				return true
			})
			if !prunes {
				t.Errorf("%s writes revoked_tokens but never calls %s: the denylist is only "+
					"self-bounding while the prune rides the write path. Re-attach it, or the "+
					"table grows for the life of any deployment that does not separately "+
					"schedule CleanupExpiredRevocations (issue #154).", fn.Name.Name, pruneCall)
			}
		}
	}

	if len(writers) == 0 {
		t.Fatalf("no function in this package was found inserting into revoked_tokens; "+
			"this guard would pass vacuously (looked for the literal %q)", insertMarker)
	}
	if len(writers) > 1 {
		sort.Strings(writers)
		t.Logf("note: %d functions write revoked_tokens (%s); each must prune", len(writers),
			strings.Join(writers, ", "))
	}
}
