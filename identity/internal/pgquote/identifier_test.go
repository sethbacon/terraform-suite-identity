package pgquote

// identifier_test.go covers the shared grammar, and the property that made
// sharing it necessary (#213).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestValidIdentifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"lowercase", "platform_admins", true},
		{"leading underscore", "_leading", true},
		{"digits after the first character", "platform_admins_v2", true},
		{"a dollar sign", "audit$outbox", true},
		{"at the length limit", strings.Repeat("a", MaxIdentifierLength), true},

		{"empty", "", false},
		{"a leading digit", "1platform_admins", false},
		{"a hyphen", "platform-admins", false},
		{"a space", "platform admins", false},
		{"a statement terminator", "platform_admins; DROP TABLE users", false},
		{"an embedded double quote", `platform_admins" --`, false},
		{"a dot (this validates ONE part)", "registry.platform_admins", false},
		{"one byte over the limit", strings.Repeat("a", MaxIdentifierLength+1), false},

		// The decision this file exists to settle. PostgreSQL folds an
		// unquoted CREATE TABLE MixedCase to mixedcase, while a quoted
		// "MixedCase" is a different table -- so accepting the name means
		// guessing which the operator meant.
		{"mixed case", "MixedCase", false},
		{"a single capital", "platformAdmins", false},
		{"all caps", "PLATFORM_ADMINS", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidIdentifier(tc.in); got != tc.want {
				t.Errorf("ValidIdentifier(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestLengthIsCheckedInBytesNotRunes.
//
// PostgreSQL's NAMEDATALEN is a BYTE limit, and it TRUNCATES rather than
// refusing -- which is how two distinct configured names silently become one
// object. A rune-based check would accept a name the server then truncates.
//
// The grammar happens to admit only ASCII, so this cannot bite today; it is
// asserted because a future widening of the pattern would make it bite
// silently, and that is the failure mode this limit exists to prevent.
func TestLengthIsCheckedInBytesNotRunes(t *testing.T) {
	// Not valid under the current pattern, but the length arithmetic must be
	// the byte kind regardless of what the pattern admits.
	multibyte := strings.Repeat("é", MaxIdentifierLength) // 2 bytes each
	if len(multibyte) <= MaxIdentifierLength {
		t.Fatal("the fixture is not multibyte; this test proves nothing")
	}
	if ValidIdentifier(multibyte) {
		t.Error("a name that is over the BYTE limit was accepted")
	}
}

// TestNoPackageDefinesItsOwnIdentifierGrammar is the guard, and it is the whole
// point of #213.
//
// Three packages each carried a copy of this pattern, and the copies drifted
// into two different grammars -- so an application wiring two of them together
// got a rule nobody wrote down, arrived at by intersection. A fourth copy would
// do it again, and the drift is invisible until an operator hits it.
func TestNoPackageDefinesItsOwnIdentifierGrammar(t *testing.T) {
	root := moduleRootFromHere(t)
	// An ANCHORED identifier pattern, which is what a validator is.
	//
	// Anchoring is the distinguishing property, and getting this wrong cost two
	// rounds. First it was too broad: an unanchored [a-z_][a-z0-9_$]* appears
	// in SQL-SCANNING regexes (auditoutbox/guard.go's statement matcher, two
	// class tests pulling table names out of query text), which parse
	// identifiers rather than deciding which are acceptable. Flagging those
	// makes the guard cry wolf, and a guard that cries wolf gets deleted --
	// taking the property with it.
	//
	// Then it was too narrow in the direction that mattered: the character
	// class was written as one range plus an underscore, so it matched a strict
	// copy ([a-z_]) and MISSED a permissive one ([A-Za-z_]) -- which is the
	// copy worth catching, because a permissive fork is how this drifted in the
	// first place. The class is now "anything up to the closing bracket".
	suspect := regexp.MustCompile("regexp\\.MustCompile\\(`\\^\\[[^\\]]*_\\]")

	var offenders []string
	scanned := 0
	err := filepath.Walk(filepath.Join(root, "identity"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This package defines it, and this file names it to check.
		if filepath.Dir(path) == filepath.Join(root, "identity", "internal", "pgquote") {
			return nil
		}
		b, readErr := os.ReadFile(path) // #nosec G304 -- test-only walk of the module
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, line := range strings.Split(string(b), "\n") {
			// A comment may legitimately quote the grammar while explaining it.
			if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") {
				continue
			}
			if suspect.MatchString(line) {
				offenders = append(offenders, path+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d Go files: the walk is not reaching the tree, so this guard "+
			"passes without looking at anything", scanned)
	}
	for _, o := range offenders {
		t.Errorf("%s\n\ndefines its own SQL identifier grammar. There is one, in "+
			"identity/internal/pgquote -- use pgquote.ValidIdentifier.\n"+
			"Three packages each had a copy and they drifted into two different grammars, so an "+
			"application wiring two of them together got a rule nobody wrote down (#213).", o)
	}
}

func moduleRootFromHere(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find the module root")
	return ""
}
