//go:build integration

package notify

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// The organization ids below are literals rather than rows in an organizations
// table: this package's tests own no such table (identity's migrations create
// it, terraform-registry and terraform-state-manager each own their own), and
// the predicate under test compares a column to a bound list. Adding a foreign
// key would test the consumer's schema, not this one's statement.
const (
	integOrgA = "aaaaaaaa-0000-4000-8000-000000000001"
	integOrgB = "bbbbbbbb-0000-4000-8000-000000000002"
)

// partitionedChannelTable creates the shape terraform-state-manager has after
// its migration 000033: the canonical table plus a NULLABLE organization_id.
//
// Nullable, and UUID, both on purpose. That migration adds the column nullable
// in its first phase and only makes it NOT NULL in its last, so this is the
// shape the capability has to work against for the whole of the partitioning
// programme, not just at the end of it. UUID is the shape that actually settles
// the question this suite exists to answer: OrgScope.SQL binds a Go []string,
// and whether `uuid = ANY($1)` accepts one is a driver question no unit test
// with a mock can answer.
func partitionedChannelTable(t *testing.T, db *sql.DB) {
	t.Helper()
	notifyExec(t, db,
		`DROP TABLE IF EXISTS public.`+ChannelTable,
		ChannelTableDDL,
		`ALTER TABLE public.`+ChannelTable+` ADD COLUMN `+ChannelOrganizationColumn+` UUID`,
	)
}

// seedChannel creates a channel through the DAO and then assigns its owner
// directly.
//
// The assignment is a separate statement because Create takes no scope and
// writes no owner: a consumer that partitions this table sets the column from a
// DEFAULT in its own migration. Writing it here through raw SQL is this suite
// standing in for that DEFAULT, and it keeps the test honest about which
// statements this package actually owns.
func seedChannel(t *testing.T, db *sql.DB, repo *ChannelRepository, name, orgID string, events []string) string {
	t.Helper()
	ch, err := repo.Create(context.Background(), &NotificationChannel{
		Name: name, Type: "webhook", EncryptedTarget: "SEALED-" + name,
		Events: events, Enabled: true,
	})
	if err != nil {
		t.Fatalf("Create %q: %v", name, err)
	}
	if orgID != "" {
		if _, err := db.Exec(
			`UPDATE `+ChannelTable+` SET `+ChannelOrganizationColumn+` = $1 WHERE id = $2`,
			orgID, ch.ID); err != nil {
			t.Fatalf("assign owner to %q: %v", name, err)
		}
	}
	return ch.ID
}

func channelNames(channels []NotificationChannel) []string {
	names := make([]string, 0, len(channels))
	for _, ch := range channels {
		names = append(names, ch.Name)
	}
	sort.Strings(names)
	return names
}

func equalNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestIntegrationChannelScopeSelectsRowsBothWays is the proof the unit tests
// cannot give: that the SQL this package emits actually selects what the option
// claims, on a real server, against the column type the consuming app really
// has.
//
// Two directions, and both matter. Unscoped must return EVERYTHING — that is the
// behaviour terraform-registry has today and must keep — and scoped must return
// only the tenant's rows, including the driver's willingness to bind a Go
// []string against a `uuid` column through `= ANY($1)`. A mock answers neither.
func TestIntegrationChannelScopeSelectsRowsBothWays(t *testing.T) {
	ctx := context.Background()
	db := notifyConn(t, notifyTestDSN(t), "")
	partitionedChannelTable(t, db)

	repo := NewChannelRepository(db)
	seedChannel(t, db, repo, "a-first", integOrgA, []string{"drift_detected"})
	// a-second subscribes to a DIFFERENT event, not to none. That used to be
	// forced: a channel created with nil events was stored as the JSON scalar
	// `null`, and jsonb_array_length then failed the whole ListEnabledForEvent
	// query. Create normalises nil to `[]` now — see marshalEvents and
	// TestIntegrationOmittedEventsDoesNotAbortListEnabledForEvent — so the
	// constraint is lifted, but this suite is about scoping and still should not
	// depend on it either way.
	seedChannel(t, db, repo, "a-second", integOrgA, []string{"run_failed"})
	seedChannel(t, db, repo, "b-only", integOrgB, []string{"drift_detected"})
	seedChannel(t, db, repo, "unowned", "", []string{"drift_detected"})

	cases := []struct {
		name string
		opts []ChannelQueryOption
		want []string
		why  string
	}{
		{
			name: "no option returns everything, exactly as before",
			opts: nil,
			want: []string{"a-first", "a-second", "b-only", "unowned"},
			why: "this is terraform-registry's call, on a table it partitions by nothing; " +
				"if it ever returns fewer rows, that consumer has silently lost channels",
		},
		{
			name: "one organization sees only its own",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizations(integOrgA))},
			want: []string{"a-first", "a-second"},
			why: "encrypted_target holds a webhook URL anyone holding it can post to, so the " +
				"other tenant's channels are the thing the partition exists to hide",
		},
		{
			name: "the other organization sees only its own",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizations(integOrgB))},
			want: []string{"b-only"},
		},
		{
			name: "both organizations, one scope",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizations(integOrgA, integOrgB))},
			want: []string{"a-first", "a-second", "b-only"},
			why:  "the allowlist really is a list; `= ANY($1)` binds all of it",
		},
		{
			name: "an owned scope does not pick up the unowned row",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizations(integOrgA))},
			want: []string{"a-first", "a-second"},
			why: "a NULL owner is not a member of any organization, so admitting it has to be " +
				"asked for rather than inherited",
		},
		{
			name: "the unowned axis widens to platform-level rows",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizationsAndUnowned(integOrgA))},
			want: []string{"a-first", "a-second", "unowned"},
			why: "a channel written before the consumer's backfill ran is invisible without " +
				"this, which is how an organization admin loses the rows they are the reviewer of",
		},
		{
			name: "platform-wide reaches everything",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeAllOrganizations())},
			want: []string{"a-first", "a-second", "b-only", "unowned"},
		},
		{
			name: "the zero scope reaches nothing",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScope{})},
			want: []string{},
			why: "a caller who opted into scoping and could not say which organization they " +
				"are in must see nothing; this is the fail-closed default the whole type exists for",
		},
		{
			name: "an empty allowlist reaches nothing",
			opts: []ChannelQueryOption{WithOrgScope(store.OrgScopeOrganizations())},
			want: []string{},
			why:  "a principal with no qualifying membership has no channels",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.List(ctx, tc.opts...)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if names := channelNames(got); !equalNames(names, tc.want) {
				t.Errorf("List returned %v, want %v\n%s", names, tc.want, tc.why)
			}
		})
	}

	// The send path is scoped on the same axis as the admin list. An event
	// raised inside one organization must not fan out to another's webhook,
	// which is a worse outcome than a list that shows too much.
	sending, err := repo.ListEnabledForEvent(ctx, "drift_detected",
		WithOrgScope(store.OrgScopeOrganizations(integOrgA)))
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	if names := channelNames(sending); !equalNames(names, []string{"a-first"}) {
		t.Errorf("scoped ListEnabledForEvent delivered to %v, want [a-first] — a-second is in "+
			"scope but subscribes to a different event, and b-only belongs to another tenant", names)
	}
	unscopedSending, err := repo.ListEnabledForEvent(ctx, "drift_detected")
	if err != nil {
		t.Fatalf("ListEnabledForEvent unscoped: %v", err)
	}
	if len(unscopedSending) != 3 {
		t.Errorf("unscoped ListEnabledForEvent matched %d channels, want 3 — the send path "+
			"must be unchanged for the consumer that does not partition this table",
			len(unscopedSending))
	}
}

// TestIntegrationChannelScopeGuardsTheByIDStatements proves the boundary holds
// on the axes an admin UI actually drives: fetch, edit, delete, and the delivery
// stamp.
//
// A tenant boundary that a list read enforces and a by-id mutation does not is
// not a boundary. org_scope.go names that shape as the defect class it exists to
// close — one query learned the predicate, its siblings over the same table did
// not — so every by-id statement is checked here rather than trusted.
func TestIntegrationChannelScopeGuardsTheByIDStatements(t *testing.T) {
	ctx := context.Background()
	db := notifyConn(t, notifyTestDSN(t), "")
	partitionedChannelTable(t, db)

	repo := NewChannelRepository(db)
	ownedByA := seedChannel(t, db, repo, "a-channel", integOrgA, []string{"drift_detected"})

	scopeB := WithOrgScope(store.OrgScopeOrganizations(integOrgB))
	scopeA := WithOrgScope(store.OrgScopeOrganizations(integOrgA))

	if _, err := repo.GetByID(ctx, ownedByA, scopeB); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByID across the boundary = %v, want the not-found sentinel. Reporting "+
			"'forbidden' instead would confirm the channel exists to a caller who may not read it", err)
	}
	if _, err := repo.GetByID(ctx, ownedByA, scopeA); err != nil {
		t.Errorf("GetByID inside the boundary: %v", err)
	}
	if _, err := repo.GetByID(ctx, ownedByA); err != nil {
		t.Errorf("GetByID with no option must still find the channel: %v", err)
	}

	if _, err := repo.Update(ctx, ownedByA, "renamed", "slack", []string{}, false, "", scopeB); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Update across the boundary = %v, want the not-found sentinel", err)
	}
	after, err := repo.GetByID(ctx, ownedByA)
	if err != nil {
		t.Fatalf("GetByID after the rejected update: %v", err)
	}
	if after.Name != "a-channel" || after.Type != "webhook" {
		t.Errorf("the out-of-scope Update changed the row anyway: %+v. A scoped mutation that "+
			"filters its RETURNING but not its WHERE reports not-found and still writes", after)
	}

	if err := repo.RecordDelivery(ctx, ownedByA, "sent", "", time.Now(), scopeB); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RecordDelivery across the boundary = %v, want the not-found sentinel", err)
	}
	if err := repo.Delete(ctx, ownedByA, scopeB); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete across the boundary = %v, want the not-found sentinel", err)
	}
	if _, err := repo.GetByID(ctx, ownedByA); err != nil {
		t.Fatalf("the out-of-scope Delete removed the row: %v", err)
	}
	if err := repo.Delete(ctx, ownedByA, scopeA); err != nil {
		t.Errorf("Delete inside the boundary: %v", err)
	}
}

// TestIntegrationUnpartitionedTableNeedsNoChange is the assertion that
// terraform-registry has nothing to do.
//
// It runs the SHIPPED DDL — no organization_id, the table that consumer really
// has — and drives every statement without options. All of them must work
// exactly as before, and the new startup assertion must be the only thing that
// objects, because it is the only thing that consumer will not be calling.
func TestIntegrationUnpartitionedTableNeedsNoChange(t *testing.T) {
	ctx := context.Background()
	db := notifyConn(t, notifyTestDSN(t), "")
	notifyExec(t, db, `DROP TABLE IF EXISTS public.`+ChannelTable, ChannelTableDDL)

	if _, err := VerifyChannelTable(ctx, db); err != nil {
		t.Fatalf("VerifyChannelTable on the shipped DDL: %v", err)
	}

	repo := NewChannelRepository(db)
	id := seedChannel(t, db, repo, "platform-webhook", "", []string{"cve_detected"})

	if list, err := repo.List(ctx); err != nil || len(list) != 1 {
		t.Fatalf("List = %v (%d rows), want the one channel — a statement that names "+
			"%s here fails with 'column does not exist'", err, len(list), ChannelOrganizationColumn)
	}
	if _, err := repo.GetByID(ctx, id); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if matched, err := repo.ListEnabledForEvent(ctx, "cve_detected"); err != nil || len(matched) != 1 {
		t.Fatalf("ListEnabledForEvent = %v (%d rows), want 1", err, len(matched))
	}
	if _, err := repo.Update(ctx, id, "platform-webhook", "slack", []string{}, true, ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := repo.RecordDelivery(ctx, id, "sent", "", time.Now()); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	err := VerifyChannelOrganizationColumn(ctx, db)
	if err == nil {
		t.Fatal("VerifyChannelOrganizationColumn accepted a table with no organization_id. " +
			"An app that wired WithOrgScope against this table would then discover it as a " +
			"failed query in the admin UI")
	}
	if !errors.Is(err, ErrChannelTable) {
		t.Errorf("error does not wrap ErrChannelTable: %v", err)
	}
}

// TestIntegrationVerifyChannelOrganizationColumnAcceptsThePartitionedShape is
// the other half: the assertion must pass on the shape the partitioning consumer
// really has, nullable column and all. An assertion that fails on the working
// deployment is one somebody switches off.
func TestIntegrationVerifyChannelOrganizationColumnAcceptsThePartitionedShape(t *testing.T) {
	ctx := context.Background()
	db := notifyConn(t, notifyTestDSN(t), "")
	partitionedChannelTable(t, db)

	if _, err := VerifyChannelTable(ctx, db); err != nil {
		t.Fatalf("the extra column must not disturb the shared assertion: %v", err)
	}
	if err := VerifyChannelOrganizationColumn(ctx, db); err != nil {
		t.Fatalf("VerifyChannelOrganizationColumn rejected the shape migration 000033 "+
			"produces (nullable UUID): %v", err)
	}
}
