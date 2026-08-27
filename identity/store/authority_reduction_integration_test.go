//go:build integration

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// Integration guards for the transactional authority reduction (issue #129).
//
// The sqlmock suite proves the STATEMENTS and their ordering. It cannot prove
// the two things that matter most here, and saying so is the point of this file:
//
//   - ATOMICITY. sqlmock records a Rollback as an expectation met; only a real
//     transaction manager can show that the membership is still there
//     afterwards. TestIntegrationAuthorityReductionRollsBackTheMembershipToo
//     reads the row back.
//   - THE `= ANY` BINDING against uuid columns. The mock accepts whatever it is
//     primed with, so a []string bound against a uuid[] parameter type looks
//     identical to a working one right up until it reaches a server.
//
// Run with -tags=integration and TEST_DATABASE_URL set.

// reductionFixture is one organization, one user, and four API keys chosen so
// that a sweep which is too wide and a sweep which is too narrow both fail.
type reductionFixture struct {
	org, otherOrg   string
	user, otherUser string
	adminTmpl       string
	viewerTmpl      string

	overScoped   string // the user's key in org, asking for more than viewer grants
	stillCovered string // the user's key in org, covered by viewer
	serviceKey   string // NULL user_id: an organization service credential
	otherOrgKey  string // the user's key in another organization
	otherUsrKey  string // another user's key in org
}

func seedReduction(t *testing.T, db *sql.DB) reductionFixture {
	t.Helper()
	ctx := context.Background()
	f := reductionFixture{}

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	newID := func() string { return uuid.New().String() }

	f.adminTmpl, f.viewerTmpl = newID(), newID()
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.adminTmpl, "reduce-admin-"+f.adminTmpl[:8], "Admin", []byte(`["users:write","modules:write"]`))
	mustExec(`INSERT INTO role_templates (id, name, display_name, scopes) VALUES ($1,$2,$3,$4)`,
		f.viewerTmpl, "reduce-viewer-"+f.viewerTmpl[:8], "Viewer", []byte(`["modules:write"]`))

	f.org, f.otherOrg = newID(), newID()
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, f.org, "reduce-a-"+f.org[:8], "A")
	mustExec(`INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`, f.otherOrg, "reduce-b-"+f.otherOrg[:8], "B")

	f.user, f.otherUser = newID(), newID()
	mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, f.user, "u-"+f.user[:8]+"@example.test", "u")
	mustExec(`INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`, f.otherUser, "o-"+f.otherUser[:8]+"@example.test", "o")

	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		f.org, f.user, f.adminTmpl)
	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		f.otherOrg, f.user, f.adminTmpl)
	mustExec(`INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at) VALUES ($1,$2,$3,NOW())`,
		f.org, f.otherUser, f.adminTmpl)

	key := func(id string, owner *string, org, scopes string) {
		mustExec(`INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
		          VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
			id, owner, org, "k-"+id[:6], "h", "p"+id[:6], []byte(scopes))
	}
	f.overScoped, f.stillCovered = newID(), newID()
	f.serviceKey, f.otherOrgKey, f.otherUsrKey = newID(), newID(), newID()
	key(f.overScoped, &f.user, f.org, `["users:write"]`)
	key(f.stillCovered, &f.user, f.org, `["modules:read"]`)
	key(f.serviceKey, nil, f.org, `["users:write"]`)
	key(f.otherOrgKey, &f.user, f.otherOrg, `["users:write"]`)
	key(f.otherUsrKey, &f.otherUser, f.org, `["users:write"]`)

	return f
}

func keyExists(t *testing.T, db *sql.DB, id string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM identity.api_keys WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("api key existence check: %v", err)
	}
	return ok
}

func memberExists(t *testing.T, db *sql.DB, orgID, userID string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM identity.organization_members WHERE organization_id = $1 AND user_id = $2)`,
		orgID, userID).Scan(&ok); err != nil {
		t.Fatalf("membership existence check: %v", err)
	}
	return ok
}

var reductionRWPairs = auth.ReadWritePairs{"modules:read": "modules:write", "users:read": "users:write"}

// A removal takes the membership and exactly the credentials that membership
// backed: not the service credential, not another organization's, not another
// user's, and not one the principal's surviving authority still covers.
//
// The "not over-swept" half is not decoration. A sweep that deletes every key it
// can see satisfies every "the stranded key is gone" assertion ever written, and
// an API key's secret is shown once — so over-revoking is an unrecoverable
// outage rather than a theoretical one.
func TestIntegrationAuthorityReductionSweepsExactlyWhatItReduced(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)

	red, err := NewReducer(db, reductionRWPairs).
		RemoveMember(context.Background(), f.org, f.user, OrgScopeOrganizations(f.org), NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if red.KeysRevoked != 2 {
		t.Errorf("KeysRevoked = %d, want 2 (the membership is gone, so nothing the user "+
			"held in that organization is still granted)", red.KeysRevoked)
	}
	if memberExists(t, db, f.org, f.user) {
		t.Error("the membership survived the reduction")
	}
	for _, c := range []struct {
		what string
		id   string
		want bool
	}{
		{"the over-scoped key", f.overScoped, false},
		{"the key the removed membership granted", f.stillCovered, false},
		{"the organization SERVICE credential (NULL user_id)", f.serviceKey, true},
		{"the user's key in ANOTHER organization", f.otherOrgKey, true},
		{"ANOTHER user's key in the same organization", f.otherUsrKey, true},
	} {
		if got := keyExists(t, db, c.id); got != c.want {
			t.Errorf("%s: exists = %v, want %v", c.what, got, c.want)
		}
	}
}

// A narrowing keeps the keys the new role still covers and destroys the rest,
// with the retained set re-derived from the row the UPDATE just wrote.
func TestIntegrationAuthorityReductionRetainsWhatTheNewRoleStillGrants(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)

	red, err := NewReducer(db, reductionRWPairs).
		UpdateMemberRoleTemplate(context.Background(), f.org, f.user, &f.viewerTmpl, OrgScopeOrganizations(f.org), NoAppCredentials)
	if err != nil {
		t.Fatalf("UpdateMemberRoleTemplate: %v", err)
	}
	if red.KeysRevoked != 1 || red.KeysRetained != 1 {
		t.Errorf("Reduced = %+v, want 1 revoked and 1 retained", red)
	}
	if keyExists(t, db, f.overScoped) {
		t.Error("a key asking for users:write survived a narrowing to modules:write only")
	}
	if !keyExists(t, db, f.stillCovered) {
		t.Error("a key asking for modules:read was destroyed although the surviving role " +
			"grants modules:write, which implies it")
	}
}

// THE HEADLINE PROPERTY. A credential sweep that fails must leave the authority
// where it was. This is the state the issue describes as unreachable-by-design:
// the membership gone and the credentials alive.
//
// MUTATION: make AppCredentials' error non-fatal in Reducer.run — the shape both
// consumers ship today, where an incomplete sweep is reported after the
// reduction has already committed — and both assertions below fail.
func TestIntegrationAuthorityReductionRollsBackTheMembershipToo(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)

	boom := errors.New("the application's watermark write failed")
	failing := func(context.Context, *sql.Tx, Reduced) error { return boom }

	_, err := NewReducer(db, reductionRWPairs).
		RemoveMember(context.Background(), f.org, f.user, OrgScopeOrganizations(f.org), failing)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the application's failure", err)
	}
	if !memberExists(t, db, f.org, f.user) {
		t.Error("the membership was removed although the credential sweep failed: that is " +
			"exactly the half-applied state this primitive exists to make unreachable")
	}
	if !keyExists(t, db, f.overScoped) {
		t.Error("a key was destroyed by a reduction that did not commit")
	}
}

// The app's writer really is inside the transaction: a row it writes through the
// handed *sql.Tx is visible after the commit, and absent after a rollback.
func TestIntegrationAppCredentialsShareTheReductionTransaction(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity.app_watermarks (
		user_id UUID PRIMARY KEY, revoked_at TIMESTAMP NOT NULL DEFAULT NOW())`); err != nil {
		t.Fatalf("create the app-owned watermark table: %v", err)
	}

	watermark := func(ctx context.Context, tx *sql.Tx, red Reduced) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO identity.app_watermarks (user_id) VALUES ($1)
			 ON CONFLICT (user_id) DO UPDATE SET revoked_at = NOW()`, red.UserID)
		return err
	}

	watermarked := func() bool {
		var ok bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM identity.app_watermarks WHERE user_id = $1)`,
			f.user).Scan(&ok); err != nil {
			t.Fatalf("watermark check: %v", err)
		}
		return ok
	}

	// Rolled back: the reduction fails AFTER the app wrote, so the app's row
	// must be gone too. A writer on its own connection would leave it behind.
	failAfter := func(ctx context.Context, tx *sql.Tx, red Reduced) error {
		if err := watermark(ctx, tx, red); err != nil {
			return err
		}
		return errors.New("and then something else went wrong")
	}
	if _, err := NewReducer(db, reductionRWPairs).
		RemoveMember(ctx, f.org, f.user, OrgScopeOrganizations(f.org), failAfter); err == nil {
		t.Fatal("the reduction reported success although AppCredentials failed")
	}
	if watermarked() {
		t.Error("the application's watermark survived a rolled-back reduction, so it was " +
			"NOT written inside the reduction's transaction")
	}

	// Committed: the same write, on the successful path, lands.
	if _, err := NewReducer(db, reductionRWPairs).
		RemoveMember(ctx, f.org, f.user, OrgScopeOrganizations(f.org), watermark); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if !watermarked() {
		t.Error("the application's watermark did not land on a committed reduction")
	}
}

// The bulk deprovisioning sweeps every organization it emptied, and the `= ANY`
// binding it uses reaches uuid columns with a []string — the thing a mock
// accepts unconditionally.
func TestIntegrationAuthorityReductionBulkDeprovision(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)

	red, err := NewReducer(db, reductionRWPairs).
		RemoveAllMembershipsForUser(context.Background(), f.user, OrgScopeAllOrganizations(), NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if len(red.Organizations) != 2 {
		t.Errorf("Organizations = %v, want both organizations the user belonged to", red.Organizations)
	}
	if red.KeysRevoked != 3 {
		t.Errorf("KeysRevoked = %d, want 3 (both of the user's keys in org, plus the one in "+
			"the other organization)", red.KeysRevoked)
	}
	if !keyExists(t, db, f.serviceKey) {
		t.Error("the bulk sweep destroyed the organization SERVICE credential (NULL user_id), " +
			"which is derived from nobody's membership")
	}
	if !keyExists(t, db, f.otherUsrKey) {
		t.Error("the bulk sweep destroyed another user's key")
	}
	if keyExists(t, db, f.otherOrgKey) {
		t.Error("a key in an organization the user was just removed from survived")
	}
}

// A tenant-scoped reduction cannot reach outside its scope, and the scope
// narrows the sweep with it: no membership removed in an organization means no
// authority reduced there, so nothing is stranded by leaving its keys alone.
func TestIntegrationAuthorityReductionHonoursTheTenantScope(t *testing.T) {
	db := identityTestDB(t)
	f := seedReduction(t, db)

	red, err := NewReducer(db, reductionRWPairs).
		RemoveAllMembershipsForUser(context.Background(), f.user, OrgScopeOrganizations(f.org), NoAppCredentials)
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if len(red.Organizations) != 1 || red.Organizations[0] != f.org {
		t.Errorf("Organizations = %v, want only the scoped organization", red.Organizations)
	}
	if !memberExists(t, db, f.otherOrg, f.user) {
		t.Error("a scoped deprovisioning removed a membership in an organization outside its scope")
	}
	if !keyExists(t, db, f.otherOrgKey) {
		t.Error("a scoped deprovisioning destroyed a key in an organization whose membership " +
			"it did not touch")
	}

	// The out-of-scope by-id reduction is a not-found, and changes nothing.
	_, err = NewReducer(db, reductionRWPairs).
		RemoveMember(context.Background(), f.otherOrg, f.user, OrgScopeOrganizations(f.org), NoAppCredentials)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for a reduction outside the caller's scope", err)
	}
	if !memberExists(t, db, f.otherOrg, f.user) {
		t.Error("an out-of-scope reduction removed the membership anyway")
	}
}
