// schema_version_class_test.go is the CLASS TEST for "shipped SQL names a
// column a later migration introduces, and nothing states or checks the
// requirement" (issue #203, and the consumer outage it caused,
// sethbacon/terraform-registry-backend#864).
//
// The reported instance was ONE column: audit_logs.actor_email, written
// unconditionally by AuditRepository.CreateAuditLog and added by migration
// 000007. Fixing only that would have been the usual mistake, because the same
// shape is already present eight more times — migration 000003 added five
// oidc_config columns, two organizations columns and one api_keys column, and
// every one of them is read or written by identity/store with no more of a
// capability check than actor_email has. A consumer stopped at 000002 breaks on
// OIDC config reads instead of on audit writes; the class is the same and the
// enforcement has to be a single floor over all of it, not a patch at the site
// that happened to page someone.
//
// So the guard below does not check for actor_email. It re-derives the WHOLE
// requirement set mechanically and compares it with the hand-written inventory
// in schema_version.go, in both directions, so that:
//
//   - a new query naming a column from a future migration raises
//     RequiredSchemaVersion instead of silently widening the gap, and
//   - an entry left behind after its query is gone cannot keep the floor
//     artificially high, which is how a startup assertion becomes something an
//     operator switches off.
//
// # What the derivation sees, and what it does not
//
// The signature is: every identifier appearing in a Go STRING LITERAL in a file
// whose literals also name at least one migration-owned table, cross-referenced
// against the (table, column) -> introducing-migration map built from the DDL in
// identity/migrations.
//
// It CAN see: every column named literally in SQL that ships, including columns
// that only ever appear in a concatenated column-list constant such as
// oidcConfigColumns, and columns named in a SQL fragment with no FROM clause of
// its own — attribution is per FILE, not per statement, which is what makes
// fragments visible.
//
// It CANNOT see, and these are the honest gaps:
//
//   - Statements whose TABLE name arrives through a fmt verb or a variable
//     rather than a literal. store/audit_sweep.go, platformadmin and
//     auditoutbox all build their table name at runtime, so no table is
//     recognised for those files and every column in them is skipped. Each of
//     the three addresses an APP-OWNED table that no migration here creates, so
//     there is nothing for this signature to say about them — but a future file
//     that builds an identity-owned table name the same way would be invisible.
//   - Requirements that are not a column: an index, a constraint, a default, a
//     widened type, or a NOT NULL added by a later migration. A query relying on
//     `ON CONFLICT (col)` needs the unique index migration 000005 adds, and this
//     derivation cannot tell.
//   - `SELECT *`, which names no columns at all. The module does not use it;
//     nothing enforces that it never will.
//   - Column ATTRIBUTION when several tables in one file share a column name.
//     The derivation credits the LOWEST introducing version among the candidate
//     tables, so an ambiguous name is under-stated rather than invented. The
//     resulting floor is therefore a LOWER BOUND on the true requirement: it can
//     miss a requirement, it cannot manufacture one.
//
// Every one of those gaps argues for the same thing the fix does — a stated
// minimum with an explicit list — rather than for trusting the derivation as
// the whole truth. The derivation's job is to stop the list going stale.
package identity

import (
	"fmt"
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

	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// ---------------------------------------------------------------------------
// The migration side: (table, column) -> the migration that introduces it.
// ---------------------------------------------------------------------------

var (
	sqlLineComment = regexp.MustCompile(`--[^\n]*`)
	createTableRe  = regexp.MustCompile(`(?is)CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+` +
		SchemaName + `\.([a-z_][a-z0-9_]*)\s*\(`)
	addColumnRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + SchemaName +
		`\.([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN(?:\s+IF\s+NOT\s+EXISTS)?\s+([a-z_][a-z0-9_]*)`)
	dropColumnRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + SchemaName +
		`\.([a-z_][a-z0-9_]*)\s+DROP\s+COLUMN(?:\s+IF\s+EXISTS)?\s+([a-z_][a-z0-9_]*)`)
	migrationFileRe = regexp.MustCompile(`^(\d{6})_.+\.up\.sql$`)
	// Leading words that begin a table CONSTRAINT rather than a column.
	tableConstraintKeywords = map[string]bool{
		"primary": true, "foreign": true, "unique": true,
		"check": true, "constraint": true, "exclude": true, "like": true,
	}
)

// timeline records where each column of each table came from.
type timeline struct {
	// intro maps table -> column -> the lowest migration version that creates
	// the column, restricted to columns that still exist at the head of the
	// chain (a column added and later dropped is absent).
	intro map[string]map[string]uint
	// createTables is how many CREATE TABLE statements were parsed, used as a
	// floor: a regex that silently stops matching produces an empty map that
	// looks exactly like a schema with no columns.
	createTables int
	// highest is the highest migration version read.
	highest uint
}

// buildTimeline parses every *.up.sql in dir, in version order, tracking column
// creation and removal. Line comments are stripped first: several up-migrations
// carry commented-out DDL (000006 documents the CONCURRENTLY variants of its
// own indexes that way) and a commented statement must not count as applied.
func buildTimeline(dir string) (timeline, error) {
	tl := timeline{intro: map[string]map[string]uint{}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return tl, fmt.Errorf("read %s: %w", dir, err)
	}
	type migFile struct {
		version uint
		name    string
	}
	var files []migFile
	for _, e := range entries {
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, perr := strconv.ParseUint(m[1], 10, 64)
		if perr != nil {
			return tl, fmt.Errorf("migration %s has an unparseable version: %w", e.Name(), perr)
		}
		files = append(files, migFile{version: uint(v), name: e.Name()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].version < files[j].version })

	dropped := map[string]bool{}
	for _, f := range files {
		body, rerr := os.ReadFile(filepath.Join(dir, f.name)) // #nosec G304 -- fixed directory, entries enumerated from it
		if rerr != nil {
			return tl, fmt.Errorf("read %s: %w", f.name, rerr)
		}
		sql := sqlLineComment.ReplaceAllString(string(body), "")
		tl.highest = f.version

		for _, loc := range createTableRe.FindAllStringSubmatchIndex(sql, -1) {
			tl.createTables++
			table := sql[loc[2]:loc[3]]
			cols, cerr := createTableColumns(sql, loc[1]-1)
			if cerr != nil {
				return tl, fmt.Errorf("%s: CREATE TABLE %s: %w", f.name, table, cerr)
			}
			for _, c := range cols {
				addColumn(tl.intro, table, c, f.version)
			}
		}
		for _, m := range addColumnRe.FindAllStringSubmatch(sql, -1) {
			addColumn(tl.intro, m[1], m[2], f.version)
			delete(dropped, m[1]+"."+m[2])
		}
		for _, m := range dropColumnRe.FindAllStringSubmatch(sql, -1) {
			dropped[m[1]+"."+m[2]] = true
		}
	}

	// A universe with migrations but no parsed CREATE TABLE is a broken parser,
	// not a schema without tables — and it must not be allowed to ANSWER. The
	// distinction matters more than it looks: with the base tables missing, the
	// cross-reference still finds every ADD COLUMN requirement (all of the
	// current ones arrive that way) and returns a set that looks exactly right,
	// while quietly losing the base columns that keep an ambiguous name from
	// being over-attributed. TestTimelineParsesEveryCreateTableInTheMigrations
	// catches the same mutation, but a derivation that reports a confident
	// answer from a half-read universe should not depend on a second guard for
	// its correctness.
	if len(files) > 0 && tl.createTables == 0 {
		return tl, fmt.Errorf("read %d up-migration(s) from %s and parsed no CREATE TABLE at "+
			"all; the DDL parser is not reading them, so every column requirement derived "+
			"from this timeline is derived from nothing", len(files), dir)
	}

	for key := range dropped {
		parts := strings.SplitN(key, ".", 2)
		if cols, ok := tl.intro[parts[0]]; ok {
			delete(cols, parts[1])
		}
	}
	return tl, nil
}

func addColumn(intro map[string]map[string]uint, table, column string, version uint) {
	if intro[table] == nil {
		intro[table] = map[string]uint{}
	}
	if _, seen := intro[table][column]; !seen {
		intro[table][column] = version
	}
}

// createTableColumns returns the column names declared in the parenthesised
// body that starts at open (the index of the '('), skipping table constraints.
//
// It scans for the matching close paren rather than anchoring on a terminator,
// so a column whose definition itself contains parentheses — a DEFAULT call, a
// VARCHAR length, an inline CHECK — cannot truncate the body.
func createTableColumns(sql string, open int) ([]string, error) {
	depth := 0
	end := -1
	for i := open; i < len(sql); i++ {
		switch sql[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("unbalanced parentheses starting at offset %d", open)
	}

	var cols []string
	depth = 0
	var cur strings.Builder
	flush := func() {
		field := strings.TrimSpace(cur.String())
		cur.Reset()
		if field == "" {
			return
		}
		first := strings.Trim(strings.Fields(field)[0], `"`)
		if tableConstraintKeywords[strings.ToLower(first)] {
			return
		}
		// pgquote owns the module's one identifier grammar; a private copy here
		// is what #213 was about.
		if pgquote.ValidIdentifier(first) {
			cols = append(cols, first)
		}
	}
	for i := open + 1; i < end; i++ {
		switch c := sql[i]; {
		case c == '(':
			depth++
			cur.WriteByte(c)
		case c == ')':
			depth--
			cur.WriteByte(c)
		case c == ',' && depth == 0:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return cols, nil
}

// ---------------------------------------------------------------------------
// The code side: which columns does the module's own SQL name?
// ---------------------------------------------------------------------------

// sqlIdentifier TOKENISES a literal into candidate identifiers; it is not a
// grammar. Anything it produces is only treated as a column when it matches a
// column the migrations create, and every name that reaches a comparison has
// already been through pgquote.ValidIdentifier on the DDL side.
var sqlIdentifier = regexp.MustCompile(`[a-z_][a-z0-9_]*`)

// fileSQLFacts is one Go file's string-literal contents, reduced to the two
// things the cross-reference needs.
type fileSQLFacts struct {
	path   string
	tables []string
	idents map[string]bool
}

// collectFileSQLFacts parses every non-test Go file under root and records, per
// file, the unqualified table names its string literals address and every
// lowercase identifier those literals contain.
//
// String literals only, via the go/ast parser: comments in this module discuss
// tables and columns at length (schema_version.go's own doc comment names
// audit_logs.actor_email four times) and this check is about the SQL that ships.
func collectFileSQLFacts(root string) ([]fileSQLFacts, error) {
	var out []fileSQLFacts
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// testdata holds deliberately-broken fixtures for other guards.
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		facts := fileSQLFacts{path: path, idents: map[string]bool{}}
		tables := map[string]bool{}
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
				if !strings.Contains(m[1], ".") {
					tables[m[1]] = true
				}
			}
			for _, id := range sqlIdentifier.FindAllString(text, -1) {
				facts.idents[id] = true
			}
			return true
		})
		facts.tables = sortedKeys(tables)
		out = append(out, facts)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// deriveRequirements cross-references the two sides and returns every
// post-base-migration column the module's SQL names, sorted.
//
// Base-migration columns are excluded on purpose: requiring 000001 is the same
// statement as requiring the identity tables to exist at all, which
// VerifySchemaVersion already makes through the version-0 branch.
func deriveRequirements(root, migrationsDir string) ([]SchemaRequirement, error) {
	tl, err := buildTimeline(migrationsDir)
	if err != nil {
		return nil, err
	}
	files, err := collectFileSQLFacts(root)
	if err != nil {
		return nil, err
	}

	seen := map[SchemaRequirement]bool{}
	for _, f := range files {
		var candidates []string
		for _, t := range f.tables {
			if _, ok := tl.intro[t]; ok {
				candidates = append(candidates, t)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		for ident := range f.idents {
			lowest := uint(0)
			var owners []string
			for _, t := range candidates {
				v, ok := tl.intro[t][ident]
				if !ok {
					continue
				}
				if lowest == 0 || v < lowest {
					lowest = v
					owners = owners[:0]
				}
				if v == lowest {
					owners = append(owners, t)
				}
			}
			if lowest <= 1 {
				continue
			}
			for _, t := range owners {
				seen[SchemaRequirement{Table: t, Column: ident, Version: lowest}] = true
			}
		}
	}

	out := make([]SchemaRequirement, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Column < out[j].Column
	})
	return out, nil
}

// ---------------------------------------------------------------------------
// The guards.
// ---------------------------------------------------------------------------

// requirementProblems is the guard's whole decision, factored out so that
// TestTheRequirementGuardIsNotVacuous can run the REAL comparison against an
// empty universe and confirm it complains. A guard that reads zero things
// passes exactly like one that read everything and found nothing; the only way
// to tell them apart is to hand the guard nothing and watch it fail.
func requirementProblems(want, got []SchemaRequirement) []string {
	var problems []string
	if len(got) == 0 {
		problems = append(problems, "derived NO schema requirements from the module's own SQL. "+
			"Either every post-000001 column has genuinely left the codebase, or the "+
			"extraction stopped working — and an extractor that reads nothing reports a "+
			"clean sweep in exactly the same words as one that read everything")
	}

	inGot := map[SchemaRequirement]bool{}
	for _, r := range got {
		inGot[r] = true
	}
	inWant := map[SchemaRequirement]bool{}
	for _, r := range want {
		inWant[r] = true
	}
	for _, r := range got {
		if !inWant[r] {
			problems = append(problems, fmt.Sprintf(
				"this module's SQL names %s, but schemaRequirements does not list it. "+
					"VerifySchemaVersion therefore lets a consumer start on a schema that "+
					"cannot serve that query, and the failure lands as SQLSTATE 42703 on a "+
					"live request instead of at startup. Add the entry (and raise "+
					"RequiredSchemaVersion if this is now the highest)", r))
		}
	}
	for _, r := range want {
		if !inGot[r] {
			problems = append(problems, fmt.Sprintf(
				"schemaRequirements lists %s, but no string literal in this module names that "+
					"column alongside that table. A stale entry makes the startup assertion "+
					"demand a migration the module no longer needs, which is how an assertion "+
					"gets switched off", r))
		}
	}
	return problems
}

// TestSchemaRequirementsMatchTheSQLTheModuleEmits keeps schemaRequirements
// equal, in both directions, to the set re-derived from the module's string
// literals and the DDL in identity/migrations.
func TestSchemaRequirementsMatchTheSQLTheModuleEmits(t *testing.T) {
	got, err := deriveRequirements(".", "migrations")
	if err != nil {
		t.Fatalf("derive requirements: %v", err)
	}
	for _, p := range requirementProblems(schemaRequirements, got) {
		t.Error(p)
	}
}

// TestTheRequirementGuardIsNotVacuous falsifies the floor directly.
//
// The floor above is "derived NO requirements" — but asserting that a non-empty
// tree yields a non-empty set proves nothing about the guard's behaviour when
// the set IS empty, and that is the state a broken extractor produces. So this
// hands the real comparison an empty universe, twice: a tree with no Go files,
// and a migrations directory with no DDL. Both must produce complaints, and the
// complaints must cover every hand-written requirement rather than just the one
// vacuity line.
func TestTheRequirementGuardIsNotVacuous(t *testing.T) {
	if len(schemaRequirements) == 0 {
		t.Fatal("schemaRequirements is empty, so this falsification has nothing to falsify")
	}

	for _, tc := range []struct {
		name              string
		root, migrationsD string
	}{
		{name: "no Go files", root: t.TempDir(), migrationsD: "migrations"},
		{name: "no migrations", root: ".", migrationsD: t.TempDir()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveRequirements(tc.root, tc.migrationsD)
			if err != nil {
				t.Fatalf("derive requirements: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("expected an empty universe to derive nothing, got %d: %v", len(got), got)
			}
			problems := requirementProblems(schemaRequirements, got)
			// One vacuity complaint plus one per hand-written requirement.
			if want := 1 + len(schemaRequirements); len(problems) != want {
				t.Fatalf("the guard reported %d problem(s) for an empty universe, want %d. "+
					"If it reported none, the guard passes on an extractor that reads nothing "+
					"and every claim it makes about this module is worthless.\n%s",
					len(problems), want, strings.Join(problems, "\n"))
			}
		})
	}
}

// TestTimelineParsesEveryCreateTableInTheMigrations is the floor under the
// OTHER half of the derivation.
//
// buildTimeline's regexes are the single point of failure for every column
// requirement: if CREATE TABLE stops matching, every table vanishes, no file
// has a candidate table, and the cross-reference sweeps an empty set while
// still reporting success. Counting the statements it parsed against the
// statements present in the files makes that silent.
func TestTimelineParsesEveryCreateTableInTheMigrations(t *testing.T) {
	tl, err := buildTimeline("migrations")
	if err != nil {
		t.Fatalf("build timeline: %v", err)
	}

	// Count CREATE TABLE occurrences independently of the parser under test.
	sql := migrationSQL(t)
	want := len(regexp.MustCompile(`(?i)CREATE\s+TABLE`).FindAllString(
		sqlLineComment.ReplaceAllString(sql, ""), -1))
	if want == 0 {
		t.Fatal("no CREATE TABLE statements found in identity/migrations — this check would " +
			"pass vacuously")
	}
	if tl.createTables != want {
		t.Errorf("buildTimeline parsed %d CREATE TABLE statement(s); the migrations contain %d. "+
			"A table the timeline cannot see contributes no columns, so every requirement in "+
			"it is invisible to TestSchemaRequirementsMatchTheSQLTheModuleEmits",
			tl.createTables, want)
	}

	// Every table VerifySchemaRouting expects must appear in the timeline with
	// at least one column, or the cross-reference has no candidate for it.
	for _, table := range RepositoryTables() {
		if len(tl.intro[table]) == 0 {
			t.Errorf("the migration timeline has no columns for %q, so no file addressing that "+
				"table can contribute a requirement", table)
		}
	}
}

// TestRequiredSchemaVersionIsTheMaximumOfTheRequirements keeps the exported
// number and the exported list from disagreeing.
//
// They are two statements of the same fact and consumers read both: the number
// goes into a comparison, the list goes into an operator's error message. A
// number below the list's maximum admits a schema that cannot serve the module;
// a number above it rejects a schema that can, which is an outage of its own.
func TestRequiredSchemaVersionIsTheMaximumOfTheRequirements(t *testing.T) {
	if len(schemaRequirements) == 0 {
		t.Fatal("schemaRequirements is empty; RequiredSchemaVersion has nothing to be the " +
			"maximum of, and this check would pass vacuously")
	}
	var max uint
	for _, r := range schemaRequirements {
		if r.Version > max {
			max = r.Version
		}
	}
	if RequiredSchemaVersion != max {
		t.Errorf("RequiredSchemaVersion is %d but the highest entry in schemaRequirements is "+
			"%d (%v). VerifySchemaVersion compares against the constant and reports the list, "+
			"so a disagreement means it either admits a schema it then names as broken, or "+
			"rejects one with nothing to point at",
			RequiredSchemaVersion, max, UnmetSchemaRequirements(max-1))
	}
}

// TestRequiredSchemaVersionIsSatisfiable pins the floor to something a consumer
// can actually reach: RunMigrations(db, "up") must leave the chain at or above
// it. A constant above the highest migration on disk is an assertion no
// deployment can pass.
func TestRequiredSchemaVersionIsSatisfiable(t *testing.T) {
	versions := migrationVersions(t)
	if len(versions) == 0 {
		t.Fatal("no migrations found — this check would pass vacuously")
	}
	head, err := strconv.ParseUint(versions[len(versions)-1], 10, 64)
	if err != nil {
		t.Fatalf("parse head migration version %q: %v", versions[len(versions)-1], err)
	}
	if RequiredSchemaVersion > uint(head) {
		t.Errorf("RequiredSchemaVersion is %d but the highest migration in identity/migrations "+
			"is %d. VerifySchemaVersion would reject every database, including one migrated to "+
			"head by this module's own RunMigrations", RequiredSchemaVersion, head)
	}
}

// TestSchemaDocRecordsTheVersionRequirement keeps docs/schema.md from
// describing the migration chain without saying how far it has to have run.
//
// The schema reference is where an operator goes when the identity tables are
// involved, and it is the document that already tells them how to read the
// version. It is the wrong place to omit the number that version is compared
// against, and the reason #203 stayed open long enough to cause an outage is
// that the number existed nowhere at all.
func TestSchemaDocRecordsTheVersionRequirement(t *testing.T) {
	doc := repoFile(t, "docs/schema.md")
	for _, name := range []string{"VerifySchemaVersion", "RequiredSchemaVersion"} {
		if !strings.Contains(doc, name) {
			t.Errorf("docs/schema.md does not mention %s. A consumer reading the schema "+
				"reference learns how to inspect the migration version and still not what "+
				"value it has to be", name)
		}
	}
	stated := fmt.Sprintf("%06d", RequiredSchemaVersion)
	if !regexp.MustCompile("requires identity migration `" + stated + "`").MatchString(doc) {
		t.Errorf("docs/schema.md does not state that this module requires identity migration "+
			"`%s`. RequiredSchemaVersion is %d; the document must say so in those words so "+
			"this check keeps the sentence current", stated, RequiredSchemaVersion)
	}
}
