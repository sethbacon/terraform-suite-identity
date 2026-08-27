package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestCheckSchemaVersionFailsClosed sweeps every schema state a consumer can
// present. The direction that matters is that ONLY a clean, sufficient version
// returns nil: a check that errored on everything would be caught by the last
// case, and one that admitted everything by the others.
func TestCheckSchemaVersionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  uint
		dirty    bool
		wantErr  bool
		contains []string
	}{
		{
			name: "no chain at all", version: 0, wantErr: true,
			contains: []string{"NEVER been applied", "actor_email", "RunMigrations"},
		},
		{
			name: "base schema only", version: 1, wantErr: true,
			contains: []string{"000001", "idp_type", "actor_email"},
		},
		{
			name: "the version the outage ran on", version: 6, wantErr: true,
			contains: []string{"000006", "audit_logs.actor_email", "42703"},
		},
		{
			name: "exactly the required version", version: RequiredSchemaVersion, wantErr: false,
		},
		{
			name: "beyond the required version", version: RequiredSchemaVersion + 5, wantErr: false,
		},
		{
			name: "sufficient but dirty", version: RequiredSchemaVersion, dirty: true, wantErr: true,
			contains: []string{"DIRTY", "unknown state"},
		},
		{
			name: "insufficient and dirty", version: 2, dirty: true, wantErr: true,
			contains: []string{"DIRTY"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSchemaVersion(tc.version, tc.dirty)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkSchemaVersion(%d, %v) error = %v, want error: %v",
					tc.version, tc.dirty, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrSchemaVersion) {
				t.Errorf("error does not wrap ErrSchemaVersion, so a consumer cannot tell a "+
					"configuration fault from a transport error: %v", err)
			}
			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q — an operator has to be told what to "+
						"DO, not that a query failed.\ngot: %v", want, err)
				}
			}
		})
	}
}

// TestUnmetSchemaRequirementsShrinksMonotonically pins the mapping the error
// message is built from: applying migrations may only remove requirements, and
// reaching RequiredSchemaVersion must remove all of them.
func TestUnmetSchemaRequirementsShrinksMonotonically(t *testing.T) {
	if len(schemaRequirements) == 0 {
		t.Fatal("schemaRequirements is empty; this check would pass vacuously")
	}
	if got := len(UnmetSchemaRequirements(0)); got != len(schemaRequirements) {
		t.Errorf("at version 0, %d of %d requirements are reported unmet; an unmigrated "+
			"database satisfies none of them", got, len(schemaRequirements))
	}
	prev := len(UnmetSchemaRequirements(0))
	for v := uint(1); v <= RequiredSchemaVersion; v++ {
		got := len(UnmetSchemaRequirements(v))
		if got > prev {
			t.Errorf("UnmetSchemaRequirements(%d) reports %d unmet, more than at %d (%d); "+
				"applying a migration cannot add a requirement", v, got, v-1, prev)
		}
		prev = got
	}
	if got := UnmetSchemaRequirements(RequiredSchemaVersion); len(got) != 0 {
		t.Errorf("at RequiredSchemaVersion (%d) these are still reported unmet: %v. The "+
			"constant is supposed to be the version at which every named column exists",
			RequiredSchemaVersion, got)
	}
}

// TestSchemaRequirementsIsCopiedNotAliased keeps a caller from shrinking the
// set the startup assertion reports over.
func TestSchemaRequirementsIsCopiedNotAliased(t *testing.T) {
	got := SchemaRequirements()
	if len(got) == 0 {
		t.Fatal("SchemaRequirements() returned nothing; this check would pass vacuously")
	}
	got[0] = SchemaRequirement{Table: "tampered", Column: "tampered", Version: 999}
	for _, r := range SchemaRequirements() {
		if r.Table == "tampered" {
			t.Fatal("SchemaRequirements() aliases the package-level slice, so a caller that " +
				"writes to the result changes what VerifySchemaVersion reports")
		}
	}
}

// TestVerifySchemaVersionRejectsANilHandle covers the one branch of the
// exported wrapper that needs no database: a nil handle must be a refusal, not
// a panic and not a pass.
func TestVerifySchemaVersionRejectsANilHandle(t *testing.T) {
	err := VerifySchemaVersion(context.Background(), nil)
	if err == nil {
		t.Fatal("VerifySchemaVersion(ctx, nil) returned nil; a startup assertion handed no " +
			"database must refuse, not certify")
	}
	if !errors.Is(err, ErrSchemaVersion) {
		t.Errorf("error does not wrap ErrSchemaVersion: %v", err)
	}
}

// TestSchemaRequirementStringNamesTheMigrationToRun pins the shape an operator
// reads: the column AND the migration that adds it, because the column alone
// does not tell anyone what to run.
func TestSchemaRequirementStringNamesTheMigrationToRun(t *testing.T) {
	got := SchemaRequirement{Table: "audit_logs", Column: "actor_email", Version: 7}.String()
	want := "audit_logs.actor_email (added by migration 000007)"
	if got != want {
		t.Errorf("SchemaRequirement.String() = %q, want %q", got, want)
	}
}
