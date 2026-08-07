//go:build integration

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// rehomingMigration is the migration that removed the delete-driven transitions
// (000007). Named for the same reason hotPathIndexMigration is: the rollback
// below unwinds to a VERSION, so adding a migration after this one does not
// silently turn "roll back 000007" into "roll back whatever is newest".
const rehomingMigration = 7

// delete_tenancy_integration_test.go is the CLASS TEST for "a DELETE re-homes a
// surviving row into a state that already means something else" (issue #142).
//
// The class is a property of the SCHEMA, not of any Go function, which is why it
// is asserted against a live PostgreSQL and not with sqlmock: the transition
// under test is performed by the foreign key, so a test that stubs the database
// away cannot observe it. Every assertion below is of the form "delete the
// parent, then read as a real caller reads, and check the child row is where it
// was — not in the bucket the delete would otherwise have moved it to".
//
// The four referencing columns that were ON DELETE SET NULL before v0.25.0, and
// what NULL already meant in each:
//
//	audit_logs.organization_id  NULL = platform/unowned, which
//	                            OrgScopeOrganizationsAndUnowned deliberately
//	                            ADMITS. Re-homing therefore published a deleted
//	                            organization's history to every other tenant's
//	                            admins. (TestIntegrationOrganizationDelete...)
//	audit_logs.user_id          NULL = "no actor" (a system action). Re-homing
//	                            erased attribution at the moment it mattered
//	                            most. (TestIntegrationUserDelete...)
//	api_keys.user_id            NULL = an organization SERVICE credential, which
//	                            terraform-registry's namespace authorizer exempts
//	                            from any membership check. Re-homing PROMOTED a
//	                            deleted user's personal keys.
//	                            (TestIntegrationUserDelete...)
//	organization_members.role_template_id
//	                            NULL = no scopes at all — the projection
//	                            COALESCEs rt.scopes to '[]', so the manufactured
//	                            state is strictly less authority and is identical
//	                            in meaning to the deliberate
//	                            UpdateMemberRoleTemplate(nil). This one is
//	                            BENIGN and stays SET NULL; the test below pins
//	                            the fail-closed reading so the verdict is
//	                            enforced rather than merely asserted in prose.
//	                            (TestIntegrationRoleTemplateDelete...)

// farPast / farFuture bracket every seeded row, so the export axis's date range
// is never what decides an assertion.
func farPast() time.Time   { return time.Now().Add(-24 * time.Hour) }
func farFuture() time.Time { return time.Now().Add(24 * time.Hour) }

// seedAudit writes one audit row directly rather than through CreateAuditLog, so
// the fixture does not depend on the write path whose projection this batch also
// changes.
func seedAudit(t *testing.T, db *sql.DB, orgID, userID *string, action string) {
	t.Helper()

	if _, err := db.Exec(
		`INSERT INTO identity.audit_logs (organization_id, user_id, action, resource_type, resource_id, ip_address, metadata)
		 VALUES ($1, $2, $3, 'secret', 'r-1', '203.0.113.7', '{"note":"tenant-private"}'::jsonb)`,
		orgID, userID, action); err != nil {
		t.Fatalf("failed to seed audit row %q: %v", action, err)
	}
}

// listActions returns the actions ListAuditLogs reports for scope, which is how
// a consuming application's audit view actually reads the table.
func listActions(t *testing.T, repo *AuditRepository, scope OrgScope) map[string]bool {
	t.Helper()

	logs, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, scope, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs(%s) failed: %v", scope, err)
	}
	seen := make(map[string]bool, len(logs))
	for _, l := range logs {
		seen[l.Action] = true
	}
	return seen
}

// streamActions returns the actions StreamAuditLogs reports for scope. The
// export axis is asserted separately from the list axis on purpose: they are
// different methods over the same table, and terraform-registry#719 is the
// precedent for one of them being fixed while the other kept leaking.
func streamActions(t *testing.T, repo *AuditRepository, scope OrgScope) map[string]bool {
	t.Helper()

	rows, err := repo.StreamAuditLogs(context.Background(), farPast(), farFuture(), scope)
	if err != nil {
		t.Fatalf("StreamAuditLogs(%s) failed: %v", scope, err)
	}
	defer func() { _ = rows.Close() }()

	seen := map[string]bool{}
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil {
			t.Fatalf("failed to read stream columns: %v", err)
		}
		dest := make([]interface{}, len(cols))
		raw := make([][]byte, len(cols))
		for i := range dest {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatalf("failed to scan streamed audit row: %v", err)
		}
		for i, c := range cols {
			if c == "action" {
				seen[string(raw[i])] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("failed to read the audit stream: %v", err)
	}
	return seen
}

func assertVisible(t *testing.T, seen map[string]bool, scope OrgScope, axis string, want ...string) {
	t.Helper()
	for _, action := range want {
		if !seen[action] {
			t.Errorf("%s with %s does not report %q, which is inside the scope. "+
				"A fix that hides rows the reader is entitled to is not a fix.", axis, scope, action)
		}
	}
}

func assertHidden(t *testing.T, seen map[string]bool, scope OrgScope, axis string, notWant ...string) {
	t.Helper()
	for _, action := range notWant {
		if seen[action] {
			t.Errorf("%s with %s reports %q. That row belonged to a DELETED organization: "+
				"the delete moved it into the NULL/unowned bucket, which this scope variant "+
				"deliberately admits, so one tenant's audit history became readable by another "+
				"tenant's admins.", axis, scope, action)
		}
	}
}

// TestIntegrationOrganizationDeleteDoesNotManufactureUnownedAuditRows is the
// headline assertion of issue #142.
//
// Both directions are asserted, and the second is the one that keeps the fix
// honest: a deleted organization's rows must NOT reach the unowned reader, and a
// genuinely unowned row — the shape terraform-state-manager writes on purpose
// for logins and state-file actions — must still reach it. A fix that closed the
// first by narrowing the unowned branch would break the second, and the whole
// reason OrgScopeOrganizationsAndUnowned exists is that a consumer with no
// third option picks "leak everything".
func TestIntegrationOrganizationDeleteDoesNotManufactureUnownedAuditRows(t *testing.T) {
	db := identityTestDB(t)
	repo := NewAuditRepository(db)
	orgs := NewOrganizationRepository(db)

	doomed := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('doomed-tenant') RETURNING id`)
	bystander := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('bystander-tenant') RETURNING id`)

	seedAudit(t, db, &doomed, nil, "doomed.tenant.private")
	seedAudit(t, db, &bystander, nil, "bystander.tenant.private")
	// The row terraform-state-manager writes deliberately with no owner.
	seedAudit(t, db, nil, nil, "platform.login")

	if err := orgs.Delete(context.Background(), doomed, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("Delete(organization) failed: %v", err)
	}

	// The bystander's admin, reading exactly as terraform-state-manager reads.
	unowned := OrgScopeOrganizationsAndUnowned(bystander)

	t.Run("list axis", func(t *testing.T) {
		seen := listActions(t, repo, unowned)
		assertVisible(t, seen, unowned, "ListAuditLogs", "bystander.tenant.private", "platform.login")
		assertHidden(t, seen, unowned, "ListAuditLogs", "doomed.tenant.private")
	})

	t.Run("export axis", func(t *testing.T) {
		seen := streamActions(t, repo, unowned)
		assertVisible(t, seen, unowned, "StreamAuditLogs", "bystander.tenant.private", "platform.login")
		assertHidden(t, seen, unowned, "StreamAuditLogs", "doomed.tenant.private")
	})

	t.Run("by-id axis", func(t *testing.T) {
		id := scanUUID(t, db, `SELECT id FROM identity.audit_logs WHERE action = 'doomed.tenant.private'`)
		_, err := repo.GetAuditLog(context.Background(), id, unowned)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetAuditLog(%s) on a deleted organization's row returned %v, want ErrNotFound. "+
				"The by-id axis is a separate method over the same table and has to agree with the list axis.",
				unowned, err)
		}
	})

	t.Run("organization-scoped read is unaffected", func(t *testing.T) {
		scope := OrgScopeOrganizations(bystander)
		seen := listActions(t, repo, scope)
		assertVisible(t, seen, scope, "ListAuditLogs", "bystander.tenant.private")
		assertHidden(t, seen, scope, "ListAuditLogs", "doomed.tenant.private")
		if seen["platform.login"] {
			t.Error("OrgScopeOrganizations reported an unowned row; the unowned branch is opt-in")
		}
	})

	t.Run("history is retained, still attributed, and platform-readable", func(t *testing.T) {
		// Retention is the other half of "do not re-home": the row must not be
		// destroyed either. A platform operator reading with the explicit
		// all-organizations scope still sees it, and it still names the
		// organization it belonged to.
		seen := listActions(t, repo, OrgScopeAllOrganizations())
		assertVisible(t, seen, OrgScopeAllOrganizations(), "ListAuditLogs",
			"doomed.tenant.private", "bystander.tenant.private", "platform.login")

		var owner *string
		if err := db.QueryRow(
			`SELECT organization_id FROM identity.audit_logs WHERE action = 'doomed.tenant.private'`,
		).Scan(&owner); err != nil {
			t.Fatalf("failed to re-read the deleted organization's audit row: %v", err)
		}
		if owner == nil {
			t.Fatal("the deleted organization's audit row has organization_id = NULL. " +
				"That is the defect: NULL is the platform/unowned bucket, so the delete did not " +
				"merely drop a reference, it MOVED the row into a tenancy state that means " +
				"something else.")
		}
		if *owner != doomed {
			t.Errorf("the audit row now names organization %s, want the organization it belonged to (%s)",
				*owner, doomed)
		}
	})
}

// TestIntegrationUserDeleteDoesNotRehomeItsRows covers the other two members of
// the class, which share a parent (identity.users) and differ in what NULL means
// on the child.
func TestIntegrationUserDeleteDoesNotRehomeItsRows(t *testing.T) {
	db := identityTestDB(t)

	org := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('user-delete-org') RETURNING id`)
	user := scanUUID(t, db,
		`INSERT INTO identity.users (email, name) VALUES ('departing@example.test', 'Departing') RETURNING id`)

	// Written through CreateAuditLog, not raw SQL: resolving the actor's address
	// at write time is part of the write path under test, and a fixture that
	// inserted actor_email itself would prove nothing.
	if err := NewAuditRepository(db).CreateAuditLog(context.Background(), &models.AuditLog{
		UserID:         &user,
		OrganizationID: &org,
		Action:         "user.did.something",
	}); err != nil {
		t.Fatalf("CreateAuditLog failed: %v", err)
	}

	// A PERSONAL key (user_id set) and an organization SERVICE key (user_id
	// NULL). The service key is the control: it must survive untouched, because
	// the point is that the two shapes stop being confusable, not that NULL
	// user_id becomes illegal.
	personal := scanUUID(t, db, fmt.Sprintf(
		`INSERT INTO identity.api_keys (organization_id, user_id, name, key_hash, key_prefix)
		 VALUES (%s, %s, 'personal', 'h1', 'p1') RETURNING id`,
		pq.QuoteLiteral(org), pq.QuoteLiteral(user)))
	service := scanUUID(t, db, fmt.Sprintf(
		`INSERT INTO identity.api_keys (organization_id, user_id, name, key_hash, key_prefix)
		 VALUES (%s, NULL, 'service', 'h2', 'p2') RETURNING id`, pq.QuoteLiteral(org)))

	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.users WHERE id = %s`, pq.QuoteLiteral(user)))

	t.Run("audit attribution survives the actor", func(t *testing.T) {
		var actor *string
		var actorEmail *string
		if err := db.QueryRow(
			`SELECT user_id, actor_email FROM identity.audit_logs WHERE action = 'user.did.something'`,
		).Scan(&actor, &actorEmail); err != nil {
			t.Fatalf("failed to re-read the audit row: %v", err)
		}
		if actor == nil {
			t.Error("deleting the user blanked audit_logs.user_id. NULL there already means " +
				"'no actor / system action', so the delete re-homed a user's actions into the " +
				"shape a system action has — non-repudiation lost at the exact moment " +
				"(account removal) it matters most.")
		} else if *actor != user {
			t.Errorf("audit row names actor %s, want %s", *actor, user)
		}
		if actorEmail == nil || *actorEmail != "departing@example.test" {
			t.Errorf("actor_email is %v, want the denormalised address the row was written with. "+
				"A raw uuid whose users row is gone is not attribution: nothing can resolve it.",
				actorEmail)
		}
	})

	t.Run("the reader still sees the retained actor", func(t *testing.T) {
		logs, _, err := NewAuditRepository(db).ListAuditLogs(
			context.Background(), AuditFilters{}, OrgScopeOrganizations(org), 10, 0)
		if err != nil {
			t.Fatalf("ListAuditLogs failed: %v", err)
		}
		if len(logs) != 1 {
			t.Fatalf("expected exactly one audit row, got %d", len(logs))
		}
		if logs[0].ActorEmail == nil || *logs[0].ActorEmail != "departing@example.test" {
			t.Errorf("ListAuditLogs did not project the retained actor (ActorEmail = %v); "+
				"a column the reader never sees is not a retained trail",
				logs[0].ActorEmail)
		}
		if logs[0].UserEmail != nil {
			t.Errorf("UserEmail is %q; the LEFT JOIN must stay honest about the users row being gone "+
				"rather than being back-filled from the denormalised copy", *logs[0].UserEmail)
		}
	})

	t.Run("personal keys are removed, not promoted to service credentials", func(t *testing.T) {
		var detached bool
		if err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM identity.api_keys WHERE id = $1)`, personal).Scan(&detached); err != nil {
			t.Fatalf("failed to look up the personal key: %v", err)
		}
		if detached {
			var owner *string
			_ = db.QueryRow(`SELECT user_id FROM identity.api_keys WHERE id = $1`, personal).Scan(&owner)
			t.Errorf("the deleted user's personal API key still exists (user_id = %v). "+
				"A NULL user_id is the ORGANIZATION SERVICE CREDENTIAL shape — "+
				"terraform-registry's namespace authorizer exempts it from every membership "+
				"check — so deleting a user PROMOTED their key instead of revoking it.", owner)
		}
	})

	t.Run("genuine service credentials are untouched", func(t *testing.T) {
		var name string
		var owner *string
		if err := db.QueryRow(
			`SELECT name, user_id FROM identity.api_keys WHERE id = $1`, service).Scan(&name, &owner); err != nil {
			t.Fatalf("the organization's service key did not survive an unrelated user delete: %v", err)
		}
		if owner != nil {
			t.Errorf("service key user_id is %q, want NULL", *owner)
		}
	})
}

// TestIntegrationRoleTemplateDeleteLeavesTheMemberFailClosed pins the one member
// of the class whose verdict is BENIGN, so the verdict is enforced by a test
// rather than resting on a reviewer's reading.
//
// organization_members.role_template_id stays ON DELETE SET NULL because NULL
// there means "no scopes at all": the membership projections COALESCE
// rt.scopes to '[]'::jsonb, and UpdateMemberRoleTemplate(nil) is an explicitly
// supported way to reach the same state deliberately. The manufactured state is
// therefore strictly LESS authority and carries no second meaning — the two
// properties whose absence makes the other three defects.
func TestIntegrationRoleTemplateDeleteLeavesTheMemberFailClosed(t *testing.T) {
	db := identityTestDB(t)
	orgs := NewOrganizationRepository(db)
	ctx := context.Background()

	org := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('rt-org') RETURNING id`)
	user := scanUUID(t, db,
		`INSERT INTO identity.users (email, name) VALUES ('member@example.test', 'Member') RETURNING id`)
	tmpl := scanUUID(t, db,
		`INSERT INTO identity.role_templates (name, scopes) VALUES ('temp-admin', '["admin"]'::jsonb) RETURNING id`)

	if err := orgs.AddMemberWithRoleTemplate(ctx, org, user, &tmpl, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate failed: %v", err)
	}

	scopes, err := orgs.GetUserScopesForOrg(ctx, user, org)
	if err != nil {
		t.Fatalf("GetUserScopesForOrg failed: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "admin" {
		t.Fatalf("fixture did not grant the template's scopes: %v", scopes)
	}

	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.role_templates WHERE id = %s`, pq.QuoteLiteral(tmpl)))

	scopes, err = orgs.GetUserScopesForOrg(ctx, user, org)
	if err != nil {
		t.Fatalf("GetUserScopesForOrg after the template delete failed: %v", err)
	}
	if len(scopes) != 0 {
		t.Errorf("the member kept %v after their role template was deleted. The SET NULL on "+
			"organization_members.role_template_id is only benign while NULL reads as NO scopes; "+
			"if it ever reads as 'inherit' this column joins the defect class.", scopes)
	}

	member, err := orgs.GetMember(ctx, org, user, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("GetMember failed: %v", err)
	}
	if member.RoleTemplateID != nil {
		t.Errorf("role_template_id is %q, want NULL", *member.RoleTemplateID)
	}
}

// TestIntegrationDeleteRehomingRollbackHandlesRetainedHistory exercises 000007's
// DOWN migration against the data only the UP migration can produce.
//
// The full down-unwind in identity/db_integration_test.go starts from an empty
// schema, so it never reaches the interesting case: re-adding a foreign key
// requires every value to resolve, and the whole point of the up migration is
// that audit rows outlive their organization. Without the repair UPDATEs in the
// down migration, a rollback on any database where an organization was ever
// deleted fails with a constraint violation mid-migration and leaves the
// migrator DIRTY — on a consumer's startup path, since both applications call
// RunMigrations at boot.
//
// It also pins the loss: the rollback re-nulls exactly the rows the up migration
// was protecting, which is why UPGRADING.md tells operators to roll forward.
func TestIntegrationDeleteRehomingRollbackHandlesRetainedHistory(t *testing.T) {
	db := identityTestDB(t)

	org := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('rollback-org') RETURNING id`)
	user := scanUUID(t, db,
		`INSERT INTO identity.users (email, name) VALUES ('rollback@example.test', 'R') RETURNING id`)
	seedAudit(t, db, &org, &user, "rollback.subject")

	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.organizations WHERE id = %s`, pq.QuoteLiteral(org)))
	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.users WHERE id = %s`, pq.QuoteLiteral(user)))

	// Both columns now hold ids that resolve to nothing — the state the down
	// migration has to repair before it can restore the constraints.
	rollBackTo(t, db, rehomingMigration-1)

	var orgID, userID *string
	if err := db.QueryRow(
		`SELECT organization_id, user_id FROM identity.audit_logs WHERE action = 'rollback.subject'`,
	).Scan(&orgID, &userID); err != nil {
		t.Fatalf("the audit row did not survive the rollback: %v", err)
	}
	if orgID != nil || userID != nil {
		t.Errorf("after the rollback the audit row still names organization=%v user=%v; the "+
			"pre-v0.25.0 schema cannot hold those values, so the down migration must have "+
			"nulled them (lossily, and documented as such)", orgID, userID)
	}

	var hasActorEmail bool
	if err := db.QueryRow(`
		SELECT EXISTS (
		    SELECT 1 FROM information_schema.columns
		    WHERE table_schema = 'identity' AND table_name = 'audit_logs' AND column_name = 'actor_email'
		)`).Scan(&hasActorEmail); err != nil {
		t.Fatalf("failed to check for actor_email after the rollback: %v", err)
	}
	if hasActorEmail {
		t.Error("audit_logs.actor_email survived the rollback; the down migration must fully reverse the up")
	}

	// Rolling forward again must restore the current shape, so the pair is
	// genuinely reversible rather than one-way.
	if err := identity.RunMigrations(db, "up"); err != nil {
		t.Fatalf("re-applying migrations after the rollback failed: %v", err)
	}
	if err := db.QueryRow(`
		SELECT EXISTS (
		    SELECT 1 FROM information_schema.columns
		    WHERE table_schema = 'identity' AND table_name = 'audit_logs' AND column_name = 'actor_email'
		)`).Scan(&hasActorEmail); err != nil {
		t.Fatalf("failed to check for actor_email after re-applying: %v", err)
	}
	if !hasActorEmail {
		t.Error("audit_logs.actor_email was not restored by re-applying the migrations")
	}
}

// TestIntegrationAuditTenancyColumnsAreNotDeleteDriven is the structural guard
// that outlives these behavioural tests: it fails if any referencing column
// whose NULL carries meaning is given back an ON DELETE SET NULL action.
//
// The behavioural tests above prove today's schema is right; this one fails on
// the NEXT migration that re-introduces the class, including on a table or a
// column that did not exist when this batch was written.
func TestIntegrationAuditTenancyColumnsAreNotDeleteDriven(t *testing.T) {
	db := identityTestDB(t)

	type ref struct {
		table  string
		column string
		reason string
	}
	// Columns whose NULL value already means something other than "the parent
	// row went away". None of them may be reachable by a delete.
	meaningfulNulls := []ref{
		{"audit_logs", "organization_id",
			"NULL is the platform/unowned bucket OrgScopeOrganizationsAndUnowned admits"},
		{"audit_logs", "user_id",
			"NULL means 'no actor / system action'"},
		{"api_keys", "user_id",
			"NULL means 'organization service credential', exempt from membership checks"},
	}

	for _, r := range meaningfulNulls {
		var action sql.NullString
		err := db.QueryRow(`
			SELECT c.confdeltype
			FROM pg_constraint c
			JOIN pg_class rel ON rel.oid = c.conrelid
			JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
			JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = c.conkey[1]
			WHERE nsp.nspname = 'identity'
			  AND rel.relname = $1
			  AND c.contype = 'f'
			  AND array_length(c.conkey, 1) = 1
			  AND att.attname = $2`, r.table, r.column).Scan(&action)
		if errors.Is(err, sql.ErrNoRows) {
			continue // no foreign key at all: the transition is impossible
		}
		if err != nil {
			t.Fatalf("failed to read the foreign-key action on identity.%s.%s: %v", r.table, r.column, err)
		}
		// confdeltype: 'n' = SET NULL, 'c' = CASCADE, 'r' = RESTRICT,
		// 'a' = NO ACTION, 'd' = SET DEFAULT.
		if action.String == "n" || action.String == "d" {
			t.Errorf("identity.%s.%s is ON DELETE %s. %s — so a parent delete does not drop a "+
				"reference, it MOVES the row into a state that already carries a different "+
				"meaning, which no reader can distinguish from a row written that way on purpose.",
				r.table, r.column, map[string]string{"n": "SET NULL", "d": "SET DEFAULT"}[action.String], r.reason)
		}
	}
}
