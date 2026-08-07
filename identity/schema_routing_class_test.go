// schema_routing_class_test.go is the CLASS TEST for "the module's queries and
// its migrations disagree about where a table lives" (issues #143, #141).
//
// The class has two members and they are swept together here because both are
// defects of AGREEMENT between three separate inventories that nothing forced
// to match:
//
//  1. Every repository query names its table unqualified while every migration
//     creates it qualified, so which physical table a read reaches is decided by
//     the connection's search_path — a setting this module neither sets nor
//     checked. VerifySchemaRouting checks it now, but an assertion is only worth
//     the completeness of the list it asserts over, so TestRepositoryTables...
//     below re-derives that list from the SQL itself, in both directions.
//  2. notification_channels is addressed by shipped code and created by no
//     migration here. The decision (documented at length in notify/schema.go) is
//     that it stays app-owned, because shipping DDL for it would silently
//     re-point both consumers' reads from their populated public table to a new
//     empty one. TestNoMigrationCreatesNotificationChannels pins that decision
//     so it cannot be reversed by accident — the way to reverse it is to delete
//     a test whose failure message explains why it exists.
//
// Every guard here is bidirectional: it fails on a new member of the class AND
// on a stale entry, so no inventory can quietly become a list of things that
// used to be true.
package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/notify"
)

// sqlTableRef matches a table reference in a SQL string.
//
// Case-SENSITIVE on the keyword and lowercase-only on the name, deliberately:
// every statement in this module writes its keywords in upper case, and the
// prose in error strings ("failed to create user from oidc") writes them in
// lower case. Matching case-insensitively would enrol half the error messages in
// the module as table references.
var sqlTableRef = regexp.MustCompile(`\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)`)

// tablesNamedInSQL returns every table name the string literals under dir name
// in SQL, split into unqualified names and schema-qualified ones.
//
// String literals only, via the parser: a comment may legitimately discuss a
// table this module does not query (and several do), and this check is about the
// SQL that actually ships.
func tablesNamedInSQL(t *testing.T, dir string) (unqualified, qualified []string) {
	t.Helper()

	unq := map[string]bool{}
	qual := map[string]bool{}

	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			for _, m := range sqlTableRef.FindAllStringSubmatch(text, -1) {
				if strings.Contains(m[1], ".") {
					qual[m[1]] = true
				} else {
					unq[m[1]] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return sortedKeys(unq), sortedKeys(qual)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestRepositoryTablesMatchesTheSQLTheModuleEmits keeps RepositoryTables() equal
// to the set of tables identity/store actually addresses.
//
// Both directions matter. A table added to a repository and not to the list is
// a table VerifySchemaRouting silently does not check — the assertion still
// passes while one query keeps resolving wherever search_path sends it. A table
// left in the list after its queries are gone makes the assertion demand a table
// the module no longer needs, which is how an assertion becomes something
// operators disable.
func TestRepositoryTablesMatchesTheSQLTheModuleEmits(t *testing.T) {
	got, _ := tablesNamedInSQL(t, "store")
	if len(got) == 0 {
		t.Fatal("found no table references in identity/store — this check would pass vacuously")
	}

	want := RepositoryTables()
	if strings.Join(got, ",") == strings.Join(want, ",") {
		return
	}

	inWant := map[string]bool{}
	for _, w := range want {
		inWant[w] = true
	}
	inGot := map[string]bool{}
	for _, g := range got {
		inGot[g] = true
	}
	for _, g := range got {
		if !inWant[g] {
			t.Errorf("identity/store addresses %q but RepositoryTables() does not list it, so "+
				"VerifySchemaRouting does not check where it resolves — that one query keeps "+
				"reading whichever schema search_path happens to reach", g)
		}
	}
	for _, w := range want {
		if !inGot[w] {
			t.Errorf("RepositoryTables() lists %q but no statement in identity/store names it; "+
				"a stale entry makes the startup assertion demand a table the module does not "+
				"use, which is how the assertion gets switched off", w)
		}
	}
}

// TestNotifyAddressesOnlyTheAppOwnedChannelTable pins the other half of the
// inventory: identity/notify must address exactly one application table, the
// app-owned one, and it must not creep into the migration-owned set behind
// VerifySchemaRouting's back.
func TestNotifyAddressesOnlyTheAppOwnedChannelTable(t *testing.T) {
	got, _ := tablesNamedInSQL(t, "notify")
	want := []string{notify.ChannelTable}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("identity/notify addresses %v; expected exactly %v.\n"+
			"notification_channels is app-owned and asserted by notify.VerifyChannelTable; "+
			"a second table here is either a migration-owned table that belongs in "+
			"RepositoryTables() (so VerifySchemaRouting covers it) or a second app-owned "+
			"contract that needs its own assertion.", got, want)
	}
}

// TestModuleSQLQualifiesOnlyTheSystemCatalogue pins the routing model itself.
//
// Application tables must stay unqualified — that is what lets one repository
// serve both the shared-schema and app-schema routings, and half-qualifying the
// module would give the worst of both: a search_path that still decides some
// reads, and a hard-coded schema that breaks the other routing entirely.
// Catalogue lookups are the exception and must be pg_catalog-qualified, so an
// introspection query cannot itself be redirected by the search_path it exists
// to inspect.
func TestModuleSQLQualifiesOnlyTheSystemCatalogue(t *testing.T) {
	for _, dir := range []string{"store", "notify"} {
		_, qualified := tablesNamedInSQL(t, dir)
		for _, q := range qualified {
			if strings.HasPrefix(q, "pg_catalog.") {
				continue
			}
			t.Errorf("identity/%s names %q schema-qualified. Application tables in this module "+
				"are addressed unqualified so the connection selects the schema (see "+
				"schema_routing.go); qualifying one statement pins it to a schema the other "+
				"supported routing does not have.", dir, q)
		}
	}
}

// migrationSQL returns every up-migration's text concatenated.
func migrationSQL(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join("migrations", e.Name())) // #nosec G304 -- fixed directory, entries enumerated from it
		if rerr != nil {
			t.Fatalf("read migrations/%s: %v", e.Name(), rerr)
		}
		b.Write(body)
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		t.Fatal("no up-migrations found — this check would pass vacuously")
	}
	return b.String()
}

// TestEveryRepositoryTableIsCreatedQualifiedByAMigration is the other side of
// the disagreement: every table VerifySchemaRouting expects in the identity
// schema must actually be created there.
//
// Without it, the assertion could be satisfied by a table nothing here creates —
// which is the notification_channels situation, and the reason that table is
// deliberately NOT in this set.
func TestEveryRepositoryTableIsCreatedQualifiedByAMigration(t *testing.T) {
	sql := migrationSQL(t)
	for _, table := range RepositoryTables() {
		want := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS\s+` + SchemaName + `\.` + table + `\b`)
		if !want.MatchString(sql) {
			t.Errorf("RepositoryTables() lists %q and VerifySchemaRouting will require it in "+
				"schema %q, but no migration creates %s.%s. Either add the migration or "+
				"remove the table from the assertion set — an assertion for a table this "+
				"module never creates is a startup failure waiting for the first consumer "+
				"that did not create it by hand.", table, SchemaName, SchemaName, table)
		}
	}
}

// TestNoMigrationCreatesNotificationChannels pins the #141 decision.
//
// Adding a migration for notification_channels is the one change in this area
// that looks obviously right and is not. Both consuming applications already
// hold live rows in their own public.notification_channels; a migration here
// creates a second, EMPTY identity.notification_channels, and every connection
// whose search_path puts identity first — the connection a consumer would move
// this repository onto the moment the module claimed the table — starts reading
// the empty one. No error, no missing relation, just an admin UI that reports no
// channels and a notifier that delivers nothing.
//
// If this test ever needs to go, it goes together with a consumer-side row
// migration and a release note, not on its own.
func TestNoMigrationCreatesNotificationChannels(t *testing.T) {
	if strings.Contains(migrationSQL(t), notify.ChannelTable) {
		t.Errorf("a migration in identity/migrations now mentions %s. This module deliberately "+
			"does not create that table: both consumers already hold live rows in their own "+
			"public.%s, and creating an empty %s.%s here silently re-points every "+
			"identity-first connection at the empty one. Moving those rows is a consumer "+
			"deploy step, not module DDL — see the file comment on identity/notify/schema.go.",
			notify.ChannelTable, notify.ChannelTable, SchemaName, notify.ChannelTable)
	}
}

// TestSchemaDocRecordsTheRoutingContract keeps docs/schema.md from drifting back
// to describing the routing as something the reader is merely told about.
//
// The document already explained that the connection selects the schema; what it
// could not tell a reader was how to check that it did. These two names are the
// answer, and a schema reference that omits them sends an operator to configure
// a search_path with no way to confirm it took effect.
func TestSchemaDocRecordsTheRoutingContract(t *testing.T) {
	doc := repoFile(t, "docs/schema.md")
	for _, name := range []string{"VerifySchemaRouting", "ChannelTableDDL", "VerifyChannelTable"} {
		if !strings.Contains(doc, name) {
			t.Errorf("docs/schema.md does not mention %s. The schema reference is where an "+
				"operator goes to find out where the identity tables live; the startup "+
				"assertions that confirm it belong in the same document.", name)
		}
	}
}
