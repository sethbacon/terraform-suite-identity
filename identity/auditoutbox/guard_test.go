package auditoutbox

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func carrierGuard() Guard {
	return Guard{Tables: []string{"platform_admins"}}
}

func findingFuncs(report Report) []string {
	names := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		names = append(names, f.Func)
	}
	sort.Strings(names)
	return names
}

func TestGuardScanDir(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		// wantFindings are the receiver-qualified function names the scan must
		// report, exactly.
		wantFindings []string
		// wantMutators is how many functions write the protected table at all.
		// It is the non-vacuity assertion: a scan that found no mutators has
		// proved nothing about the ones that are there.
		wantMutators int
		wantFiles    int
	}{
		{
			name:         "every mutation carries the contract",
			dir:          "clean",
			wantFindings: nil,
			wantMutators: 2,
			wantFiles:    1,
		},
		{
			name:         "body literal without a writer",
			dir:          "unaudited_literal",
			wantFindings: []string{"(receiver).PurgeAdmin"},
			wantMutators: 2,
			wantFiles:    1,
		},
		{
			// The case registry's body-literals-only scan walked past.
			name:         "package-level const and var SQL without a writer",
			dir:          "unaudited_const",
			wantFindings: []string{"(receiver).Grant", "(receiver).Revoke"},
			wantMutators: 3,
			wantFiles:    1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := carrierGuard().ScanDir(filepath.Join("testdata", tc.dir))
			if err != nil {
				t.Fatalf("ScanDir: %v", err)
			}
			if report.Files != tc.wantFiles {
				t.Errorf("Files = %d, want %d", report.Files, tc.wantFiles)
			}
			if report.Mutators != tc.wantMutators {
				t.Errorf("Mutators = %d, want %d — the scan is not looking at what it thinks it is",
					report.Mutators, tc.wantMutators)
			}
			got := findingFuncs(report)
			if len(got) != len(tc.wantFindings) {
				t.Fatalf("findings = %v, want %v", got, tc.wantFindings)
			}
			for i := range got {
				if got[i] != tc.wantFindings[i] {
					t.Fatalf("findings = %v, want %v", got, tc.wantFindings)
				}
			}
			for _, f := range report.Findings {
				if f.Table != "platform_admins" {
					t.Errorf("finding %v names table %q, want platform_admins", f, f.Table)
				}
				if !strings.Contains(f.Position, "repo.go:") {
					t.Errorf("finding %v carries no usable position", f)
				}
				if !strings.Contains(f.String(), "takes no audit-intent writer") {
					t.Errorf("finding message %q does not say what is wrong", f.String())
				}
			}
		})
	}
}

// A scan that CANNOT run establishes nothing about the code it was pointed at,
// so every unrunnable configuration is an error rather than an empty report.
func TestGuardRefusesAVacuousScan(t *testing.T) {
	tests := []struct {
		name    string
		guard   Guard
		dir     string
		wantMsg string
	}{
		{
			name:    "no protected tables",
			guard:   Guard{},
			dir:     filepath.Join("testdata", "clean"),
			wantMsg: "no protected tables named",
		},
		{
			name:    "no non-test source",
			guard:   carrierGuard(),
			dir:     filepath.Join("testdata", "notests"),
			wantMsg: "no non-test Go source",
		},
		{
			name:    "directory does not exist",
			guard:   carrierGuard(),
			dir:     filepath.Join("testdata", "there-is-no-such-package"),
			wantMsg: "no non-test Go source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.guard.ScanDir(tc.dir)
			if err == nil {
				t.Fatal("ScanDir succeeded, want an error")
			}
			if !errors.Is(err, ErrGuard) {
				t.Errorf("error %v does not wrap ErrGuard", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestGuardRefusesABadTableName(t *testing.T) {
	_, err := Guard{Tables: []string{"platform_admins; DROP TABLE users"}}.ScanDir(filepath.Join("testdata", "clean"))
	if !errors.Is(err, ErrInvalidTable) {
		t.Fatalf("ScanDir with a malformed table = %v, want ErrInvalidTable", err)
	}
}

// The default writer types cover this package's IntentWriter and the name
// terraform-registry-backend's repositories package already used. A caller that
// names its own type is taken at its word.
func TestGuardWriterTypes(t *testing.T) {
	clean := filepath.Join("testdata", "clean")

	report, err := Guard{Tables: []string{"platform_admins"}, WriterTypes: []string{"AuditIntentWriter"}}.ScanDir(clean)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("with only AuditIntentWriter accepted, findings = %v, want both mutators reported",
			findingFuncs(report))
	}

	report, err = Guard{Tables: []string{"platform_admins"}, WriterTypes: []string{"IntentWriter"}}.ScanDir(clean)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %v, want none", findingFuncs(report))
	}
}

// A schema-qualified protected table matches the same SQL, and SQL that
// qualifies the table matches an unqualified protected name. Neither spelling
// may be a way past the guard.
func TestGuardMatchesQualifiedAndUnqualifiedSQL(t *testing.T) {
	report, err := Guard{Tables: []string{"registry.platform_admins"}}.ScanDir(filepath.Join("testdata", "unaudited_literal"))
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.Mutators != 2 || len(report.Findings) != 1 {
		t.Fatalf("a schema-qualified protected name matched %d mutator(s) and %d finding(s), want 2 and 1",
			report.Mutators, len(report.Findings))
	}
}

// This package's own privileged writes go to a table the CONSUMER names, so
// there is nothing here for the guard to protect — but the analyzer itself must
// stay runnable against this package, or the app-side test is the only thing
// exercising it.
func TestGuardRunsAgainstThisPackage(t *testing.T) {
	report, err := Guard{Tables: []string{"audit_outbox"}}.ScanDir(".")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.Files < 5 {
		t.Fatalf("scanned %d file(s) of this package, want at least 5", report.Files)
	}
	if report.Mutators != 0 {
		t.Errorf("this package hardcodes no table name, so it must mutate no literal audit_outbox; "+
			"found %d: %v", report.Mutators, report.Findings)
	}
}
