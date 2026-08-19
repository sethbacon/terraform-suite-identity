package identity

// Mechanical doc-vs-code checks.
//
// Every assertion here replaces a sentence in the documentation that a human
// would otherwise have to remember to update. They exist because prose drifts
// silently: docs/schema.md sat on "The current version is 000004" for a whole
// release after 000005 shipped, README.md claimed API-key expiry was
// unenforced after the SQL had started enforcing it, and CONTRIBUTING.md quoted
// a dependency-review severity the workflow did not use. Each of those was a
// correct sentence once.
//
// The rule of thumb for adding to this file: if a doc states a COUNT, a
// THRESHOLD, a VERSION, a PATH or an inventory that some file in the repo is the
// real source of truth for, assert it here rather than trusting the sentence.
// Anything requiring judgement (rationale, guidance, threat modelling) stays
// prose and is not checked.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/suite"
)

// repoFile reads a file relative to the repository root (this package lives one
// directory below it).
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// migrationVersions returns every migration version present in
// identity/migrations, sorted ascending, and fails if any is missing its
// up/down pair.
func migrationVersions(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	ups := map[string]string{}
	downs := map[string]bool{}
	re := regexp.MustCompile(`^(\d{6})_(.+)\.(up|down)\.sql$`)
	for _, e := range entries {
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			t.Errorf("migrations/%s does not match the NNNNNN_name.(up|down).sql convention "+
				"documented in CONTRIBUTING.md", e.Name())
			continue
		}
		if m[3] == "up" {
			ups[m[1]] = m[1] + "_" + m[2]
		} else {
			downs[m[1]] = true
		}
	}
	versions := make([]string, 0, len(ups))
	for v := range ups {
		// docs/schema.md and CONTRIBUTING.md both state migrations are "paired".
		if !downs[v] {
			t.Errorf("migration %s has no .down.sql, contradicting the "+
				"'numbered, paired (.up.sql/.down.sql)' claim in docs/schema.md", v)
		}
		versions = append(versions, v)
	}
	for v := range downs {
		if _, ok := ups[v]; !ok {
			t.Errorf("migration %s has a .down.sql but no .up.sql", v)
		}
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		t.Fatal("no migrations found — this check would pass vacuously")
	}
	return versions
}

// TestSchemaDocMigrationTableIsComplete fails when a migration exists that
// docs/schema.md's migration table does not list.
//
// This is the check that would have caught migration 000005 (the single-active
// OIDC config unique index) shipping entirely undocumented: CONTRIBUTING.md
// designates docs/schema.md as the source of truth for "the new table/column and
// the migration that introduces it", so a migration missing from that table is a
// documentation defect, not a style nit.
func TestSchemaDocMigrationTableIsComplete(t *testing.T) {
	doc := repoFile(t, "docs/schema.md")

	for _, v := range migrationVersions(t) {
		// The table's first column is the version in backticks: | `000005` | …
		row := regexp.MustCompile(`(?m)^\|\s*` + "`" + v + "`" + `\s*\|`)
		if !row.MatchString(doc) {
			t.Errorf("migration %s has no row in docs/schema.md's migration table. "+
				"Add a row whose first cell is the backticked version %s, and update the "+
				"'The current version is ...' line if %s is now the highest.", v, v, v)
		}
	}

	// And the converse: a row for a migration that does not exist.
	rows := regexp.MustCompile("(?m)^\\|\\s*`(\\d{6})`\\s*\\|").FindAllStringSubmatch(doc, -1)
	present := map[string]bool{}
	for _, v := range migrationVersions(t) {
		present[v] = true
	}
	for _, r := range rows {
		if !present[r[1]] {
			t.Errorf("docs/schema.md's migration table lists %s, but no such migration exists "+
				"in identity/migrations/", r[1])
		}
	}
}

// TestSchemaDocCurrentVersionMatchesMigrations pins docs/schema.md's
// "The current version is `NNNNNN`." sentence to the highest migration on disk.
func TestSchemaDocCurrentVersionMatchesMigrations(t *testing.T) {
	doc := repoFile(t, "docs/schema.md")
	versions := migrationVersions(t)
	want := versions[len(versions)-1]

	m := regexp.MustCompile("The current version is `(\\d{6})`").FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("docs/schema.md no longer contains a \"The current version is `NNNNNN`\" sentence; " +
			"either restore it or delete this check deliberately")
	}
	if m[1] != want {
		t.Errorf("docs/schema.md says the current schema version is %s, but the highest migration "+
			"in identity/migrations/ is %s", m[1], want)
	}
}

// TestReadmePackageTableListsEveryPackage fails when the module gains an
// importable package that README.md's package table does not mention.
//
// identity/crypto, identity/httpsafe, identity/mailer and identity/notify were
// all added, shipped and released without ever appearing in that table —
// including identity/crypto.TokenCipher, the ready-made AES-256-GCM helper for
// the OIDC-client-secret gap the other docs repeatedly warn about. A consumer
// reading the README had no way to know it existed.
//
// internal/ packages are deliberately excluded: they are not importable by
// consumers and so are not part of the documented surface.
func TestReadmePackageTableListsEveryPackage(t *testing.T) {
	readme := repoFile(t, "README.md")

	var pkgs []string
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		name := info.Name()
		if name == ".git" || name == "migrations" {
			return filepath.SkipDir
		}
		if strings.HasPrefix(name, ".") && path != ".." {
			return filepath.SkipDir
		}
		if name == "internal" {
			return filepath.SkipDir
		}
		// testdata is excluded for the same reason internal/ is, and more
		// strongly: the go tool ignores it entirely, so nothing under it is a
		// package at all — it is never built, never importable, and cannot be
		// part of a documented surface. identity/auditoutbox keeps the fixture
		// packages its source-scan guard parses there.
		if name == "testdata" {
			return filepath.SkipDir
		}
		// A directory is a package if it holds at least one non-test .go file.
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		hasGo := false
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				hasGo = true
				break
			}
		}
		if !hasGo {
			return nil
		}
		rel, err := filepath.Rel("..", path)
		if err != nil {
			return err
		}
		pkgs = append(pkgs, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("found no packages — this check would pass vacuously")
	}
	sort.Strings(pkgs)

	for _, p := range pkgs {
		// Require a package-TABLE row, not merely a mention: the table's first
		// cell is the import path in backticks. A passing prose reference
		// elsewhere in the README is not the inventory a reader scans.
		row := regexp.MustCompile(`(?m)^\|\s*` + "`" + regexp.QuoteMeta(p) + "`" + `\s*\|`)
		switch n := len(row.FindAllString(readme, -1)); {
		case n == 0:
			t.Errorf("package %s is importable by consumers but has no row in README.md's "+
				"package table (a prose mention elsewhere does not count).\n"+
				"Add a row whose first cell is the backticked import path, plus a usage "+
				"example if it has a public API.", p)
		case n > 1:
			// Two concurrent PRs each added a row for identity/mailer and
			// identity/notify five minutes apart, and neither noticed the other.
			// The duplicates disagreed, so the table said two different things
			// about the same package for twelve days.
			t.Errorf("package %s has %d rows in README.md's package table; a reader "+
				"scanning the inventory cannot tell which is current.\n"+
				"Keep one, and prefer whichever description is still true of the "+
				"code rather than whichever landed last.", p, n)
		}
	}
}

// TestManifestPathMatchesDocs pins the suite manifest route. The path is part of
// the wire contract between the two apps: docs/suite-coupling.md and README.md
// both state it literally, and each consuming app registers its own route from a
// copied literal, so a change to the constant that is not mirrored in the docs
// leaves every reader with the wrong path.
func TestManifestPathMatchesDocs(t *testing.T) {
	for _, f := range []string{"README.md", "docs/suite-coupling.md"} {
		doc := repoFile(t, f)
		if !strings.Contains(doc, suite.ManifestPath) {
			t.Errorf("%s does not mention the manifest path %q (suite.ManifestPath). "+
				"The path is a cross-app wire contract; docs stating a stale path send "+
				"integrators to a 404.", f, suite.ManifestPath)
		}
	}
}

// ---------------------------------------------------------------------------
// CI-gate claims: CONTRIBUTING.md documents the numbers CI actually enforces.
// ---------------------------------------------------------------------------

func mustFind(t *testing.T, name, body, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("could not locate %s in %s (pattern %q). If the file was restructured, "+
			"update this check deliberately rather than deleting it.", name, name, pattern)
	}
	return m[1]
}

// TestContributingCoverageThresholdMatchesCI pins CONTRIBUTING.md's stated
// coverage floor to the value ci.yml enforces.
func TestContributingCoverageThresholdMatchesCI(t *testing.T) {
	ci := repoFile(t, ".github/workflows/ci.yml")
	contributing := repoFile(t, "CONTRIBUTING.md")

	ciTotal := mustFind(t, "ci.yml THRESHOLD", ci, `(?m)^\s*THRESHOLD=(\d+)\s*$`)
	ciPerPkg := mustFind(t, "ci.yml per-package THRESHOLD", ci, `(?m)^\s*THRESHOLD = (\d+)\.0\s*$`)
	docTotal := mustFind(t, "CONTRIBUTING coverage threshold", contributing,
		`Coverage threshold is (\d+)%`)

	if docTotal != ciTotal {
		t.Errorf("CONTRIBUTING.md documents a %s%% coverage threshold but ci.yml enforces %s%%",
			docTotal, ciTotal)
	}
	// The per-package floor is a second, independent gate: a PR can meet the
	// aggregate and still fail. CONTRIBUTING must state both, and both numbers
	// must match.
	if !strings.Contains(contributing, "per-package") {
		t.Error("CONTRIBUTING.md does not mention ci.yml's per-package coverage floor, " +
			"so a contributor can meet the documented total gate and still fail CI")
	}
	if ciPerPkg != ciTotal {
		t.Logf("note: ci.yml's total (%s%%) and per-package (%s%%) floors differ; "+
			"CONTRIBUTING.md must state both", ciTotal, ciPerPkg)
	}
}

// TestContributingGosecVersionMatchesCI pins the gosec version CONTRIBUTING.md
// tells contributors to install to the one CI actually runs, so a local clean
// run means the same thing as a clean CI run.
func TestContributingGosecVersionMatchesCI(t *testing.T) {
	ci := repoFile(t, ".github/workflows/ci.yml")
	contributing := repoFile(t, "CONTRIBUTING.md")

	const pattern = `gosec/v2/cmd/gosec@(v[0-9][^\s"'` + "`" + `]*)`
	ciVersion := mustFind(t, "ci.yml gosec version", ci, pattern)
	docVersion := mustFind(t, "CONTRIBUTING gosec version", contributing, pattern)

	if ciVersion != docVersion {
		t.Errorf("CONTRIBUTING.md tells contributors to install gosec %s but ci.yml runs %s",
			docVersion, ciVersion)
	}
}

// TestContributingDependencyReviewSeverityMatchesCI pins the dependency-review
// gate. CONTRIBUTING.md claimed `fail-on-severity: high` while the workflow used
// `moderate` — a documented control that did not match the real one, in the
// looser direction, so a contributor would under-estimate what CI blocks.
func TestContributingDependencyReviewSeverityMatchesCI(t *testing.T) {
	prChecks := repoFile(t, ".github/workflows/pr-checks.yml")
	contributing := repoFile(t, "CONTRIBUTING.md")

	ciSeverity := mustFind(t, "pr-checks.yml fail-on-severity", prChecks,
		`(?m)^\s*fail-on-severity:\s*(\w+)\s*$`)
	docSeverity := mustFind(t, "CONTRIBUTING fail-on-severity", contributing,
		"fail-on-severity: (\\w+)")

	if ciSeverity != docSeverity {
		t.Errorf("CONTRIBUTING.md documents dependency review at fail-on-severity %q "+
			"but pr-checks.yml uses %q", docSeverity, ciSeverity)
	}
}

// TestDocumentedCIChecksExist fails when CONTRIBUTING.md's list of required CI
// checks names a job that no workflow defines, or omits one that does.
//
// The omission direction matters: ci.yml's "Integration Tests (PostgreSQL)" job
// documents itself as a required status check on main, and
// "Vulnerability Scan (govulncheck)" is a security gate — neither appeared in
// CONTRIBUTING.md's list, so a contributor reading only the docs would not know
// what has to pass.
func TestDocumentedCIChecksExist(t *testing.T) {
	contributing := repoFile(t, "CONTRIBUTING.md")

	jobNames := map[string]bool{}
	for _, wf := range []string{"ci.yml", "pr-checks.yml"} {
		body := repoFile(t, ".github/workflows/"+wf)
		for _, m := range regexp.MustCompile(`(?m)^\s{4}name:\s*(.+?)\s*$`).FindAllStringSubmatch(body, -1) {
			jobNames[strings.Trim(m[1], `"'`)] = true
		}
	}
	if len(jobNames) == 0 {
		t.Fatal("parsed no job names from the workflows — this check would pass vacuously")
	}

	var missing []string
	for name := range jobNames {
		if !strings.Contains(contributing, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("CONTRIBUTING.md does not mention these CI job(s), so a contributor cannot know "+
			"they must pass: %s", strings.Join(missing, ", "))
	}
}

// TestGoDirectiveMatchesDocs pins the Go version floor stated in README.md and
// CONTRIBUTING.md to go.mod's `go` directive.
func TestGoDirectiveMatchesDocs(t *testing.T) {
	gomod := repoFile(t, "go.mod")
	goDirective := mustFind(t, "go.mod go directive", gomod, `(?m)^go (\d+\.\d+)(?:\.\d+)?\s*$`)

	for _, f := range []string{"README.md", "CONTRIBUTING.md"} {
		doc := repoFile(t, f)
		want := fmt.Sprintf("Go %s", goDirective)
		if !strings.Contains(doc, want) {
			t.Errorf("%s does not state the Go floor %q that go.mod's `go` directive sets", f, want)
		}
	}

	// The toolchain directive, when present, is the version CI actually runs
	// (actions/setup-go honours go-version-file). Both docs must acknowledge it,
	// or "requires Go X" understates the real requirement for anyone building
	// with GOTOOLCHAIN=local.
	if m := regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)\s*$`).FindStringSubmatch(gomod); m != nil {
		for _, f := range []string{"README.md", "CONTRIBUTING.md"} {
			if !strings.Contains(repoFile(t, f), m[1]) {
				t.Errorf("go.mod pins `toolchain go%s`, which is what CI builds with, but %s "+
					"does not mention it", m[1], f)
			}
		}
	}
}
