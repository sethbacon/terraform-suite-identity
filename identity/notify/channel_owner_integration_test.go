//go:build integration

package notify

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// THIS FILE EXISTS BECAUSE sqlmock CANNOT SEE THE BUG IT IS TESTING FOR.
//
// The failure WithOwningOrganization prevents is a column landing at its DEFAULT
// instead of at the caller's value. A mock returns whatever columns its fixture
// declares, so under sqlmock an INSERT that omits organization_id and one that
// names it are indistinguishable -- both "succeed", and the row that would have
// gone to the wrong tenant is never actually written anywhere. Only a real
// PostgreSQL evaluates the DEFAULT, so only a real PostgreSQL can tell the two
// apart. sqlmock tests the Go; this tests the SQL.

const integDefaultOrg = "dddddddd-0000-4000-8000-00000000000d"

// defaultedChannelTable is partitionedChannelTable plus the DEFAULT that
// terraform-state-manager's 000033 attaches -- a static expression standing in
// for tsm_default_organization_id(), which resolves to one fixed organization
// no matter who is calling.
func defaultedChannelTable(t *testing.T, db *sql.DB) {
	t.Helper()
	partitionedChannelTable(t, db)
	notifyExec(t, db,
		`ALTER TABLE public.`+ChannelTable+` ALTER COLUMN `+ChannelOrganizationColumn+
			` SET DEFAULT '`+integDefaultOrg+`'::uuid`)
}

func ownerOf(t *testing.T, db *sql.DB, id string) (string, bool) {
	t.Helper()
	var owner sql.NullString
	err := db.QueryRow(
		`SELECT `+ChannelOrganizationColumn+`::text FROM `+ChannelTable+` WHERE id = $1`, id,
	).Scan(&owner)
	if err != nil {
		t.Fatalf("read owner of %s: %v", id, err)
	}
	return owner.String, owner.Valid
}

func createChannel(t *testing.T, repo *ChannelRepository, name string, opts ...ChannelWriteOption) (*NotificationChannel, error) {
	t.Helper()
	return repo.Create(context.Background(), &NotificationChannel{
		Name: name, Type: "webhook", EncryptedTarget: "SEALED-" + name,
		Events: []string{"drift_detected"}, Enabled: true,
	}, opts...)
}

// TestCreateWithOwningOrganizationBeatsTheDefault is the whole point: the tenant's
// organization must win over the schema's static one.
func TestCreateWithOwningOrganizationBeatsTheDefault(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	defaultedChannelTable(t, db)
	repo := NewChannelRepository(db)

	ch, err := createChannel(t, repo, "beta-webhook", WithOwningOrganization(integOrgB))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	owner, valid := ownerOf(t, db, ch.ID)
	if !valid {
		t.Fatal("organization_id is NULL: the option named the column but bound no value, " +
			"which takes the row out of every tenant's view")
	}
	if owner == integDefaultOrg {
		t.Fatalf("organization_id is the DEFAULT %s, not the caller's %s: the INSERT is "+
			"omitting the column, so every tenant's channel lands in one organization",
			integDefaultOrg, integOrgB)
	}
	if owner != integOrgB {
		t.Fatalf("organization_id = %s, want the caller's %s", owner, integOrgB)
	}
}

// TestCreateWithoutTheOptionStillTakesTheDefault protects the consumers that do
// NOT partition. Making the option mandatory, or always naming the column, would
// break them -- naming it with a zero value writes NULL over a working DEFAULT.
func TestCreateWithoutTheOptionStillTakesTheDefault(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	defaultedChannelTable(t, db)
	repo := NewChannelRepository(db)

	ch, err := createChannel(t, repo, "unpartitioned-webhook")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	owner, valid := ownerOf(t, db, ch.ID)
	if !valid {
		t.Fatal("organization_id is NULL with no option supplied: the statement is naming the " +
			"column unconditionally and has overwritten the consumer's DEFAULT")
	}
	if owner != integDefaultOrg {
		t.Fatalf("organization_id = %s, want the DEFAULT %s", owner, integDefaultOrg)
	}
}

// TestCreateRefusesAnEmptyOwningOrganization covers the case that is invisible at
// the call site: WithOwningOrganization("") must NOT quietly become the DEFAULT,
// because a caller that asked to name the owner and got the schema's answer has
// no way to notice.
func TestCreateRefusesAnEmptyOwningOrganization(t *testing.T) {
	db := notifyConn(t, notifyTestDSN(t), "")
	defer db.Close()
	defaultedChannelTable(t, db)
	repo := NewChannelRepository(db)

	for _, blank := range []string{"", "   ", "\t"} {
		if _, err := createChannel(t, repo, "blank-owner", WithOwningOrganization(blank)); !errors.Is(err, ErrEmptyOwningOrganization) {
			t.Fatalf("Create with WithOwningOrganization(%q) error = %v, want ErrEmptyOwningOrganization", blank, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ` + ChannelTable).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d row(s) written: the refusal happened after the INSERT, not before it", n)
	}
}
