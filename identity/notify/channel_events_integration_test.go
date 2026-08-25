//go:build integration

package notify

import (
	"context"
	"database/sql"
	"testing"
)

func plainChannelTable(t *testing.T, db *sql.DB) {
	t.Helper()
	notifyExec(t, db, `DROP TABLE IF EXISTS public.`+ChannelTable, ChannelTableDDL)
}

// TestIntegrationOmittedEventsDoesNotAbortListEnabledForEvent runs the failure
// this package's own scope suite had to design around.
//
// A channel created with nil Events stored the JSON scalar `null`, and
// jsonb_array_length(events) errors on a scalar. Postgres aborts the STATEMENT,
// not the row -- so ListEnabledForEvent returned an error and nothing was
// notified, including the valid channels that should have matched. That is why
// the assertions below check the sibling as well as the offender: a fix that
// only stopped the error while losing rows would be no fix.
//
// It needs a real server. The failure is the engine refusing an operator, which
// a mock cannot reproduce -- and the DDL's own `DEFAULT '[]'::jsonb` never
// applied here, because Create always supplies the column explicitly.
func TestIntegrationOmittedEventsDoesNotAbortListEnabledForEvent(t *testing.T) {
	ctx := context.Background()
	db := notifyConn(t, notifyTestDSN(t), "")
	plainChannelTable(t, db)

	repo := NewChannelRepository(db)

	if _, err := repo.Create(ctx, &NotificationChannel{
		Name: "subscribed", Type: "webhook", EncryptedTarget: "SEALED-1",
		Events: []string{"drift_detected"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create subscribed: %v", err)
	}
	// Events omitted entirely: the zero value, reached by not setting the field.
	if _, err := repo.Create(ctx, &NotificationChannel{
		Name: "omitted-events", Type: "webhook", EncryptedTarget: "SEALED-2",
		Enabled: true,
	}); err != nil {
		t.Fatalf("create omitted-events: %v", err)
	}

	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT jsonb_typeof(events) FROM `+ChannelTable+` WHERE name = 'omitted-events'`,
	).Scan(&stored); err != nil {
		t.Fatalf("read stored events type: %v", err)
	}
	if stored != "array" {
		t.Errorf("stored jsonb_typeof(events) = %q, want %q -- a scalar aborts every send", stored, "array")
	}

	got, err := repo.ListEnabledForEvent(ctx, "drift_detected")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v -- this is the whole defect: one bad row fails the statement", err)
	}

	names := map[string]bool{}
	for _, ch := range got {
		names[ch.Name] = true
	}
	if !names["subscribed"] {
		t.Error("the explicitly subscribed channel was not returned")
	}
	// An empty filter means "all events" -- the same meaning nil carried in Go,
	// which is why normalising to [] preserves intent rather than changing it.
	if !names["omitted-events"] {
		t.Error("a channel with no event filter must match every event")
	}
}
