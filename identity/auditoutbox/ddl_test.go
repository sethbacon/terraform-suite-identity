package auditoutbox

import (
	"errors"
	"strings"
	"testing"
)

// The rendered outbox must address the table it was asked for, and nothing else.
// Every statement in outbox.go names these columns, so a rendering that drops
// one produces a table the code cannot use.
func TestOutboxDDLRendersTheTableTheCodeAddresses(t *testing.T) {
	ddl, err := OutboxDDL("registry.audit_outbox")
	if err != nil {
		t.Fatalf("OutboxDDL: %v", err)
	}

	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS "registry"."audit_outbox"`,
		`CREATE OR REPLACE FUNCTION "registry"."audit_outbox_assert_intent"`,
		`"audit_outbox_pending_idx"`,
		`"audit_outbox_delivered_idx"`,
		`"audit_outbox_txid_idx"`,
		// The property, in the DDL: same transaction, matched on the top-level
		// transaction id rather than a foreign key.
		`o.txid = pg_current_xact_id()`,
		`txid            xid8         NOT NULL DEFAULT pg_current_xact_id()`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("OutboxDDL does not contain %q", want)
		}
	}

	// Every column the Go statements name must exist in the rendered table.
	for _, column := range outboxRequiredColumns {
		if !strings.Contains(ddl, "    "+column+" ") {
			t.Errorf("OutboxDDL does not declare %q, which this package's statements name", column)
		}
	}

	// Nothing may leak an unqualified `audit_outbox`: a statement that resolved
	// through search_path instead of the rendered schema is how the trigger
	// reads one table while the relay drains another.
	for _, line := range strings.Split(ddl, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		if strings.Contains(line, " audit_outbox") && !strings.Contains(line, `"audit_outbox"`) {
			t.Errorf("unqualified table reference in rendered DDL: %q", line)
		}
	}
}

func TestOutboxDDLRejectsABadName(t *testing.T) {
	for _, name := range []string{"", "audit_outbox; DROP TABLE users", strings.Repeat("a", 60)} {
		if _, err := OutboxDDL(name); err == nil {
			t.Errorf("OutboxDDL(%q) succeeded, want an error", name)
		} else if !errors.Is(err, ErrInvalidTable) {
			t.Errorf("OutboxDDL(%q) = %v, want an ErrInvalidTable", name, err)
		}
	}
}

func TestOutboxDropDDL(t *testing.T) {
	ddl, err := OutboxDropDDL("registry.audit_outbox")
	if err != nil {
		t.Fatalf("OutboxDropDDL: %v", err)
	}
	for _, want := range []string{
		`DROP FUNCTION IF EXISTS "registry"."audit_outbox_assert_intent"(TEXT, TEXT, TEXT);`,
		`DROP TABLE IF EXISTS "registry"."audit_outbox";`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("OutboxDropDDL does not contain %q", want)
		}
	}
	if _, err := OutboxDropDDL("Nope"); !errors.Is(err, ErrInvalidTable) {
		t.Errorf("OutboxDropDDL(bad) = %v, want ErrInvalidTable", err)
	}
}

func carrierSpec() TriggerSpec {
	return TriggerSpec{
		Outbox:        "registry.audit_outbox",
		Table:         "registry.platform_admins",
		SubjectColumn: "user_id",
		ResourceType:  "platform_admin",
		OnInsert:      "platform_admin.granted",
		OnUpdate:      "platform_admin.updated",
		OnDelete:      "platform_admin.revoked",
	}
}

func TestTriggerDDLPinsTheActionsAndDefersToCommit(t *testing.T) {
	ddl, err := carrierSpec().DDL()
	if err != nil {
		t.Fatalf("DDL: %v", err)
	}

	for _, want := range []string{
		`CREATE OR REPLACE FUNCTION "registry"."platform_admins_require_audit_intent"()`,
		`CREATE CONSTRAINT TRIGGER "platform_admins_require_audit_intent"`,
		`AFTER INSERT OR UPDATE OR DELETE ON "registry"."platform_admins"`,
		// The check runs at COMMIT, so the mutation and its intent may be
		// written in either order within the transaction.
		`DEFERRABLE INITIALLY DEFERRED`,
		// The action is pinned in the database: a revocation cannot commit
		// under a grant's record.
		`PERFORM "registry"."audit_outbox_assert_intent"(NEW."user_id"::text, 'platform_admin', 'platform_admin.granted')`,
		`PERFORM "registry"."audit_outbox_assert_intent"(OLD."user_id"::text, 'platform_admin', 'platform_admin.revoked')`,
		// A repointed subject is two subjects and needs an intent for each.
		`IF NEW."user_id" IS DISTINCT FROM OLD."user_id" THEN`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("TriggerSpec.DDL does not contain %q\n---\n%s", want, ddl)
		}
	}

	if got := strings.Count(ddl, "IF TG_OP"); got != 3 {
		t.Errorf("rendered %d TG_OP branches, want 3 (INSERT, UPDATE, DELETE)", got)
	}
	if got, want := strings.Count(ddl, "END IF;"), 4; got != want {
		t.Errorf("rendered %d END IF, want %d (three branches plus the nested repoint check)", got, want)
	}
}

// An operation left unnamed is UNGUARDED, and the rendered trigger must not
// claim otherwise by firing on it.
func TestTriggerDDLGuardsOnlyTheNamedOperations(t *testing.T) {
	spec := carrierSpec()
	spec.OnUpdate = ""
	spec.OnDelete = ""

	ddl, err := spec.DDL()
	if err != nil {
		t.Fatalf("DDL: %v", err)
	}
	if !strings.Contains(ddl, `AFTER INSERT ON "registry"."platform_admins"`) {
		t.Errorf("want an INSERT-only trigger, got:\n%s", ddl)
	}
	for _, unwanted := range []string{"TG_OP = 'UPDATE'", "TG_OP = 'DELETE'"} {
		if strings.Contains(ddl, unwanted) {
			t.Errorf("rendered %q for an operation the spec left unguarded", unwanted)
		}
	}
}

func TestTriggerSpecValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TriggerSpec)
		wantMsg string
	}{
		{
			name:    "no outbox",
			mutate:  func(s *TriggerSpec) { s.Outbox = "" },
			wantMsg: "outbox table is empty",
		},
		{
			name:    "no table",
			mutate:  func(s *TriggerSpec) { s.Table = "" },
			wantMsg: "guarded table is empty",
		},
		{
			name:    "no subject column",
			mutate:  func(s *TriggerSpec) { s.SubjectColumn = "" },
			wantMsg: "names no SubjectColumn",
		},
		{
			name:    "injected subject column",
			mutate:  func(s *TriggerSpec) { s.SubjectColumn = `user_id"::text, 'x', 'y'); --` },
			wantMsg: "not [a-z_]",
		},
		{
			name:    "no resource type",
			mutate:  func(s *TriggerSpec) { s.ResourceType = "  " },
			wantMsg: "names no ResourceType",
		},
		{
			// Failing on an empty universe: a trigger that guards nothing
			// installs cleanly and reads as protection.
			name: "guards no operation",
			mutate: func(s *TriggerSpec) {
				s.OnInsert, s.OnUpdate, s.OnDelete = "", "", ""
			},
			wantMsg: "guards no operation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := carrierSpec()
			tc.mutate(&spec)
			_, err := spec.DDL()
			if err == nil {
				t.Fatal("DDL succeeded, want an error")
			}
			if !errors.Is(err, ErrInvalidTable) {
				t.Errorf("error %v does not wrap ErrInvalidTable", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tc.wantMsg)
			}
			if _, err := spec.DropDDL(); err == nil {
				t.Error("DropDDL accepted a spec DDL rejected")
			}
		})
	}
}

// A ResourceType is a SQL string literal in the rendered function. It comes
// from the app, so it is quoted rather than interpolated.
func TestTriggerDDLQuotesTheResourceTypeLiteral(t *testing.T) {
	spec := carrierSpec()
	spec.ResourceType = "it's a resource"
	spec.OnUpdate, spec.OnDelete = "", ""

	ddl, err := spec.DDL()
	if err != nil {
		t.Fatalf("DDL: %v", err)
	}
	if !strings.Contains(ddl, `'it''s a resource'`) {
		t.Errorf("the resource type is not escaped as a SQL literal:\n%s", ddl)
	}
}

func TestTriggerDropDDL(t *testing.T) {
	ddl, err := carrierSpec().DropDDL()
	if err != nil {
		t.Fatalf("DropDDL: %v", err)
	}
	for _, want := range []string{
		`DROP TRIGGER IF EXISTS "platform_admins_require_audit_intent" ON "registry"."platform_admins";`,
		`DROP FUNCTION IF EXISTS "registry"."platform_admins_require_audit_intent"();`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DropDDL does not contain %q", want)
		}
	}
}

// The generated names must be refused when they would exceed PostgreSQL's
// 63-byte identifier limit, in both the outbox and the trigger renderers.
func TestTriggerDDLRefusesNamesPostgresWouldTruncate(t *testing.T) {
	spec := carrierSpec()
	spec.Table = "registry." + strings.Repeat("a", 50) // + "_require_audit_intent" = 71
	if _, err := spec.DDL(); err == nil || !errors.Is(err, ErrInvalidTable) {
		t.Fatalf("DDL for an over-long guarded table = %v, want ErrInvalidTable", err)
	}
	spec = carrierSpec()
	spec.Outbox = "registry." + strings.Repeat("a", 55) // + "_assert_intent" = 69
	if _, err := spec.DDL(); err == nil || !errors.Is(err, ErrInvalidTable) {
		t.Fatalf("DDL for an over-long outbox = %v, want ErrInvalidTable", err)
	}
}
