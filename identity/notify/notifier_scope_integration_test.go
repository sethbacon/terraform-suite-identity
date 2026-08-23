//go:build integration

package notify

import (
	"context"
	"database/sql"
	"sort"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// FAN-OUT IS EGRESS, which is why this is an integration test: the predicate
// under test is a WHERE clause, and a mock does not evaluate one.
//
// WHAT IS OBSERVED, and why it is not the HTTP delivery. Notify records a
// per-channel delivery result through RecordDelivery, so `last_status` is
// non-NULL for exactly the channels the fan-out REACHED — whether or not the
// POST then succeeded. That isolates the property this change is about (does the
// scope reach the query) from the delivery machinery around it (token cipher,
// egress guard, SMTP relay), which is unrelated and would otherwise decide the
// result. A test that needed delivery to succeed would be testing four things
// and reporting one.

// reachedChannels returns the names of channels the fan-out attempted.
func reachedChannels(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM ` + ChannelTable + ` WHERE last_status IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatalf("read reached channels: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func seedTwoTenantChannels(t *testing.T, db *sql.DB, repo *ChannelRepository) {
	t.Helper()
	seedChannel(t, db, repo, "alpha-hook", integOrgA, []string{"drift_detected"})
	seedChannel(t, db, repo, "beta-hook", integOrgB, []string{"drift_detected"})
}

// TestIntegration_NotifyReachesOnlyTheEventsOwnOrganization is the leak this
// closes: one tenant's infrastructure drift POSTed to another tenant's webhook,
// outside the deployment.
func TestIntegration_NotifyReachesOnlyTheEventsOwnOrganization(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	partitionedChannelTable(t, db)
	repo := NewChannelRepository(db)
	seedTwoTenantChannels(t, db, repo)

	NewNotifier(repo, nil, nil, nil, Options{Source: "test"}).Notify(
		context.Background(),
		Event{Type: "drift_detected", Title: "drift", Message: "alpha's infrastructure"},
		WithOrgScope(store.OrgScopeOrganizations(integOrgA)))

	got := reachedChannels(t, db)
	if len(got) != 1 || got[0] != "alpha-hook" {
		t.Fatalf("fan-out reached %v, want only [alpha-hook]. Reaching beta-hook means one "+
			"tenant's drift left the deployment addressed to another tenant.", got)
	}
}

// TestIntegration_NotifyWithNoScopeStillReachesEveryone is the compatibility
// control. Without it, "scoped" could be implemented as "always empty" and the
// test above would still pass.
func TestIntegration_NotifyWithNoScopeStillReachesEveryone(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	partitionedChannelTable(t, db)
	repo := NewChannelRepository(db)
	seedTwoTenantChannels(t, db, repo)

	NewNotifier(repo, nil, nil, nil, Options{Source: "test"}).Notify(
		context.Background(),
		Event{Type: "drift_detected", Title: "drift", Message: "x"})

	if got := reachedChannels(t, db); len(got) != 2 {
		t.Fatalf("an unscoped fan-out reached %v, want both. A consumer that passes no scope "+
			"must keep the behaviour it had.", got)
	}
}

// TestIntegration_NotifyWithAnEmptyScopeReachesNobody. An event whose row has no
// organization — the ON DELETE SET NULL orphans a partitioned consumer ends up
// with — must deliver to NOBODY rather than to everybody. Failing open here is
// the whole bug, restored through the fix.
func TestIntegration_NotifyWithAnEmptyScopeReachesNobody(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	partitionedChannelTable(t, db)
	repo := NewChannelRepository(db)
	seedTwoTenantChannels(t, db, repo)

	NewNotifier(repo, nil, nil, nil, Options{Source: "test"}).Notify(
		context.Background(),
		Event{Type: "drift_detected", Title: "drift", Message: "x"},
		WithOrgScope(store.OrgScopeOrganizations()))

	if got := reachedChannels(t, db); len(got) != 0 {
		t.Fatalf("an empty scope reached %v; it must reach nobody. Delivering an unowned "+
			"event to every channel is the leak, not a fallback.", got)
	}
}
