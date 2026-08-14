package auditoutbox

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTable(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantSchema   string
		wantName     string
		wantSQL      string
		wantErr      bool
		wantErrParts []string
	}{
		{
			name:       "unqualified",
			in:         "audit_outbox",
			wantName:   "audit_outbox",
			wantSQL:    `"audit_outbox"`,
			wantSchema: "",
		},
		{
			name:       "schema qualified",
			in:         "registry.audit_outbox",
			wantSchema: "registry",
			wantName:   "audit_outbox",
			wantSQL:    `"registry"."audit_outbox"`,
		},
		{
			name:       "surrounding whitespace is trimmed",
			in:         "  tsm.audit_outbox  ",
			wantSchema: "tsm",
			wantName:   "audit_outbox",
			wantSQL:    `"tsm"."audit_outbox"`,
		},
		{
			name:         "empty",
			in:           "",
			wantErr:      true,
			wantErrParts: []string{"is empty"},
		},
		{
			name:         "three parts",
			in:           "db.registry.audit_outbox",
			wantErr:      true,
			wantErrParts: []string{"at most 2"},
		},
		{
			// The whole reason table names are validated: they are the one part
			// of a statement that cannot be a bind parameter.
			name:         "statement terminator",
			in:           "audit_outbox; DROP TABLE users",
			wantErr:      true,
			wantErrParts: []string{"not [a-z_]"},
		},
		{
			name:         "quote",
			in:           `audit_outbox" --`,
			wantErr:      true,
			wantErrParts: []string{"not [a-z_]"},
		},
		{
			name:         "comment",
			in:           "audit_outbox/*x*/",
			wantErr:      true,
			wantErrParts: []string{"not [a-z_]"},
		},
		{
			name:         "upper case is refused rather than folded",
			in:           "Registry.Audit_Outbox",
			wantErr:      true,
			wantErrParts: []string{"upper case", "fold"},
		},
		{
			name:         "leading digit",
			in:           "1audit",
			wantErr:      true,
			wantErrParts: []string{"not [a-z_]"},
		},
		{
			name:         "over 63 bytes",
			in:           strings.Repeat("a", 64),
			wantErr:      true,
			wantErrParts: []string{"64-byte", "truncates"},
		},
		{
			name:     "exactly 63 bytes is accepted",
			in:       strings.Repeat("a", 63),
			wantName: strings.Repeat("a", 63),
			wantSQL:  `"` + strings.Repeat("a", 63) + `"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTable("outbox table", tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTable(%q) succeeded, want an error", tc.in)
				}
				if !errors.Is(err, ErrInvalidTable) {
					t.Errorf("error %v does not wrap ErrInvalidTable; a caller cannot match on it", err)
				}
				for _, part := range tc.wantErrParts {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q does not mention %q", err, part)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTable(%q) = %v, want success", tc.in, err)
			}
			if got.schema != tc.wantSchema || got.name != tc.wantName {
				t.Errorf("parseTable(%q) = {%q %q}, want {%q %q}", tc.in, got.schema, got.name, tc.wantSchema, tc.wantName)
			}
			if got.sql() != tc.wantSQL {
				t.Errorf("sql() = %q, want %q", got.sql(), tc.wantSQL)
			}
		})
	}
}

func TestTableString(t *testing.T) {
	qualified, err := parseTable("outbox table", "registry.audit_outbox")
	if err != nil {
		t.Fatal(err)
	}
	if got := qualified.String(); got != "registry.audit_outbox" {
		t.Errorf("String() = %q, want registry.audit_outbox", got)
	}
	bare, err := parseTable("outbox table", "audit_outbox")
	if err != nil {
		t.Fatal(err)
	}
	if got := bare.String(); got != "audit_outbox" {
		t.Errorf("String() = %q, want audit_outbox", got)
	}
}

// derive is what keeps two generated objects from becoming one. PostgreSQL
// truncates an over-long identifier silently, so the refusal has to happen here.
func TestTableDerive(t *testing.T) {
	short, err := parseTable("outbox table", "registry.audit_outbox")
	if err != nil {
		t.Fatal(err)
	}
	got, err := short.derive(assertIntentSuffix)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got.String() != "registry.audit_outbox_assert_intent" {
		t.Errorf("derive = %q, want registry.audit_outbox_assert_intent", got)
	}

	// 63 - len("_assert_intent") == 49, so 50 is one over.
	long, err := parseTable("outbox table", strings.Repeat("a", 50))
	if err != nil {
		t.Fatal(err)
	}
	_, err = long.derive(assertIntentSuffix)
	if err == nil {
		t.Fatal("derive accepted a name that PostgreSQL would truncate; two generated objects could collide")
	}
	if !errors.Is(err, ErrInvalidTable) {
		t.Errorf("error %v does not wrap ErrInvalidTable", err)
	}
	if !strings.Contains(err.Error(), "truncates") {
		t.Errorf("error %q does not explain the truncation", err)
	}
}
