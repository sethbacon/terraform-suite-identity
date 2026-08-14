package auditoutbox

import (
	"context"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// The two mechanisms this module ships for issue #206 have to JOIN UP, and
// "they look compatible" is not the same as "they compile together".
//
// identity/platformadmin is the privileged mutation: its Grant and Revoke take a
// mandatory AuditIntentWriter and run it inside the carrier's own transaction.
// This package is where that writer comes from. Both declare the same underlying
// func type, so the handover is a conversion — but a conversion only exists
// while the two signatures agree, and nothing else in either package would
// notice if one of them changed.
func TestOutboxWriterSatisfiesTheCarriersAuditIntentWriter(t *testing.T) {
	o, mock := newOutbox(t)

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	target := "22222222-2222-2222-2222-222222222222"
	resource := platformadmin.AuditResourceType
	intent := &Intent{
		Action:       platformadmin.AuditActionGranted,
		ResourceType: &resource,
		ResourceID:   &target,
	}

	// The handover, exactly as an application writes it.
	var writer platformadmin.AuditIntentWriter = platformadmin.AuditIntentWriter(o.Writer(intent))

	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer(context.Background(), tx); err != nil {
		t.Fatalf("the carrier's writer did not reach the outbox: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if intent.EventID == "" {
		t.Error("the intent was not enqueued through the converted writer")
	}
}

// The constraint trigger matches the action VERBATIM, so the vocabulary the
// carrier writes and the vocabulary the trigger demands must be one set of
// strings. platformadmin's audit_actions.go says as much in prose; this is the
// assertion, so a rename there fails here rather than at a customer's COMMIT.
func TestTriggerDDLPinsTheCarriersAuditVocabulary(t *testing.T) {
	ddl, err := TriggerSpec{
		Outbox:        "registry.audit_outbox",
		Table:         "registry.platform_admins",
		SubjectColumn: "user_id",
		ResourceType:  platformadmin.AuditResourceType,
		OnInsert:      platformadmin.AuditActionGranted,
		OnDelete:      platformadmin.AuditActionRevoked,
	}.DDL()
	if err != nil {
		t.Fatalf("DDL: %v", err)
	}

	for _, want := range []string{
		`'` + platformadmin.AuditResourceType + `'`,
		`'` + platformadmin.AuditActionGranted + `'`,
		`'` + platformadmin.AuditActionRevoked + `'`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("the rendered trigger does not pin %s, so a carrier mutation would commit "+
				"under an intent the trigger never checked\n%s", want, ddl)
		}
	}
}
