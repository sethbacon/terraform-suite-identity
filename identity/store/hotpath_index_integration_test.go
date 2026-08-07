//go:build integration

package store

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity"
)

// hotPathIndexes are the indexes migration 000006 must create, each paired with
// the table it belongs to.
//
// Restated here rather than derived from the migration on purpose: the point of
// the assertion is that the NAMES the migration creates are the names the
// planner is then observed to choose, so deriving both sides from the same
// source would make it circular.
// hotPathIndexMigration is the migration these indexes belong to. Named so the
// rollback below unwinds to a VERSION rather than by a step count, which is what
// tied this suite to "000006 is the newest migration".
const hotPathIndexMigration = 6

// rollBackTo unwinds migrations one step at a time until the applied version is
// target.
func rollBackTo(t *testing.T, db *sql.DB, target uint) {
	t.Helper()

	for {
		version, dirty, err := identity.GetMigrationVersion(db)
		if err != nil {
			t.Fatalf("GetMigrationVersion failed: %v", err)
		}
		if dirty {
			t.Fatalf("migration state is dirty at version %d; a partially applied migration "+
				"cannot be stepped through", version)
		}
		if version <= target {
			return
		}
		if err := identity.RunMigrationSteps(db, -1); err != nil {
			t.Fatalf("RunMigrationSteps(-1) from version %d failed: %v", version, err)
		}
	}
}

var hotPathIndexes = map[string]string{
	"idx_identity_audit_logs_org_created_at":             "audit_logs",
	"idx_identity_organization_members_user_id":          "organization_members",
	"idx_identity_organization_members_role_template_id": "organization_members",
	"idx_identity_api_keys_organization_id":              "api_keys",
	"idx_identity_api_keys_user_id":                      "api_keys",
	"idx_identity_revoked_tokens_user_id":                "revoked_tokens",
}

// TestIntegrationHotPathIndexes covers migration 000006 end to end against a
// real PostgreSQL: the indexes exist after the up migration, the planner
// actually chooses them for the queries this package emits, and the down
// migration removes them.
//
// The EXPLAIN assertions are the substance. Asserting only that a CREATE INDEX
// ran proves the migration executed, not that the query it was written for got
// faster — and an index the planner declines to use (wrong column order, wrong
// leading column, made partial in a way that excludes the real predicate) is
// indistinguishable from no index at all in production while passing a
// pg_indexes existence check.
func TestIntegrationHotPathIndexes(t *testing.T) {
	db := identityTestDB(t)

	t.Run("indexes exist after the up migration", func(t *testing.T) {
		assertHotPathIndexesPresent(t, db, true)
	})

	seedHotPathFixtures(t, db)

	t.Run("audit list and count use the composite scope index", func(t *testing.T) {
		assertOrgScopePlans(t, db)
	})

	t.Run("audit export stream uses the composite scope index", func(t *testing.T) {
		assertAuditExportPlan(t, db)
	})

	t.Run("membership resolution uses the user_id index", func(t *testing.T) {
		assertMembershipPlans(t, db)
	})

	t.Run("api key listing uses the org and user indexes", func(t *testing.T) {
		assertAPIKeyPlans(t, db)
	})

	t.Run("down migration removes exactly these indexes", func(t *testing.T) {
		// Unwind to just below 000006 rather than taking a fixed single step:
		// RunMigrationSteps(-1) meant "roll back 000006" only while 000006 was
		// the newest migration, so this subtest broke the moment 000007 was
		// added — a test coupled to the migration COUNT instead of to the
		// migration it is about.
		rollBackTo(t, db, hotPathIndexMigration-1)
		assertHotPathIndexesPresent(t, db, false)

		// The indexes migration 000001 created must survive 000006's rollback:
		// a down migration that over-reaches is its own outage.
		for _, preexisting := range []string{
			"idx_identity_audit_logs_created_at",
			"idx_identity_audit_logs_user_id",
			"idx_identity_api_keys_key_prefix",
			"idx_identity_revoked_tokens_expires_at",
		} {
			if !indexExists(t, db, preexisting) {
				t.Errorf("000006's down migration must not drop %s (created by 000001)", preexisting)
			}
		}

		// And re-applying restores them, so the migration is genuinely
		// reversible rather than one-way.
		if err := identity.RunMigrations(db, "up"); err != nil {
			t.Fatalf("re-applying migrations after the rollback failed: %v", err)
		}
		assertHotPathIndexesPresent(t, db, true)
	})
}

func assertHotPathIndexesPresent(t *testing.T, db *sql.DB, want bool) {
	t.Helper()

	names := make([]string, 0, len(hotPathIndexes))
	for name := range hotPathIndexes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		got := indexExists(t, db, name)
		if got == want {
			continue
		}
		if want {
			t.Errorf("migration 000006 must create identity.%s on %s, but it is absent",
				name, hotPathIndexes[name])
		} else {
			t.Errorf("migration 000006's down step must drop identity.%s, but it is still present", name)
		}
	}
}

func indexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'identity' AND indexname = $1)`,
		name,
	).Scan(&exists); err != nil {
		t.Fatalf("failed to check for index %s: %v", name, err)
	}
	return exists
}

// seedHotPathFixtures builds a deliberately SKEWED estate: one organization
// holding the overwhelming majority of rows and one holding a handful.
//
// The skew is what makes the assertions meaningful. On a uniform toy table
// PostgreSQL will sequential-scan everything regardless of the indexes, so a
// plan assertion would prove nothing; and querying the dominant tenant is the
// one case where the pre-existing created_at index is legitimately the better
// plan. Querying the SMALL tenant is the real multi-tenant shape — one
// organization's audit page out of an estate-sized table — and it is the shape
// that has no reasonable plan at all without the composite index.
func seedHotPathFixtures(t *testing.T, db *sql.DB) {
	t.Helper()

	mustExec(t, db, `INSERT INTO identity.organizations (name) VALUES ('bulk-hot'), ('bulk-cold')`)

	mustExec(t, db, `
		INSERT INTO identity.users (email, name)
		SELECT 'bulk-' || g || '@example.test', 'bulk user ' || g
		FROM generate_series(1, 20000) g`)

	mustExec(t, db, `
		INSERT INTO identity.audit_logs (organization_id, action, created_at)
		SELECT (SELECT id FROM identity.organizations WHERE name = 'bulk-hot'),
		       'bulk.event', NOW() - (g * INTERVAL '1 second')
		FROM generate_series(1, 40000) g`)
	mustExec(t, db, `
		INSERT INTO identity.audit_logs (organization_id, action, created_at)
		SELECT (SELECT id FROM identity.organizations WHERE name = 'bulk-cold'),
		       'bulk.event', NOW() - (g * INTERVAL '1 second')
		FROM generate_series(1, 20) g`)

	// Every seeded user is a member of the dominant organization, so
	// `WHERE om.user_id = $1` selects one row out of twenty thousand — the
	// login-time membership lookup, at estate scale.
	mustExec(t, db, `
		INSERT INTO identity.organization_members (organization_id, user_id)
		SELECT (SELECT id FROM identity.organizations WHERE name = 'bulk-hot'), id
		FROM identity.users`)

	mustExec(t, db, `
		INSERT INTO identity.api_keys (organization_id, user_id, name, key_hash, key_prefix)
		SELECT (SELECT id FROM identity.organizations WHERE name = 'bulk-hot'),
		       id, 'bulk key', 'hash-' || id, 'pfx'
		FROM identity.users`)
	mustExec(t, db, `
		INSERT INTO identity.api_keys (organization_id, name, key_hash, key_prefix)
		SELECT (SELECT id FROM identity.organizations WHERE name = 'bulk-cold'),
		       'cold key ' || g, 'cold-hash-' || g, 'pfx'
		FROM generate_series(1, 5) g`)

	mustExec(t, db, `ANALYZE identity.audit_logs`)
	mustExec(t, db, `ANALYZE identity.organization_members`)
	mustExec(t, db, `ANALYZE identity.api_keys`)
	mustExec(t, db, `ANALYZE identity.users`)
	mustExec(t, db, `ANALYZE identity.organizations`)
}

// assertOrgScopePlans EXPLAINs the two statements ListAuditLogs really emits.
//
// The queries come from buildListAuditLogsQueries — the same builder
// ListAuditLogs itself calls — so this proves the plan for the SQL that reaches
// production, not for a hand-copied approximation of it. That distinction is the
// whole point: v0.21.0 made OrgScope mandatory, so this predicate is now on
// every audit read, and an index that fails to match the predicate the builder
// really produces would leave the mandatory control the most expensive query in
// the module.
func assertOrgScopePlans(t *testing.T, db *sql.DB) {
	t.Helper()

	coldOrg := scanUUID(t, db, `SELECT id FROM identity.organizations WHERE name = 'bulk-cold'`)

	countQuery, countArgs, listQuery, listArgs := buildListAuditLogsQueries(
		AuditFilters{}, OrgScopeOrganizations(coldOrg), 50, 0)

	// Guard against the builder silently losing the predicate: if this ever
	// stops being true the plan assertions below would pass vacuously against
	// an unscoped query.
	for _, q := range []string{countQuery, listQuery} {
		if !strings.Contains(q, "al.organization_id = ANY($1)") {
			t.Fatalf("the emitted query no longer carries the OrgScope predicate; "+
				"this test would be asserting the wrong plan.\nQuery was:\n%s", q)
		}
	}
	if !strings.Contains(listQuery, "ORDER BY al.created_at DESC") {
		t.Fatalf("the emitted page query no longer orders by created_at DESC; the composite "+
			"index's second column is chosen for that ORDER BY.\nQuery was:\n%s", listQuery)
	}

	assertPlanUsesIndex(t, "the scoped audit COUNT", "idx_identity_audit_logs_org_created_at",
		explain(t, db, countQuery, countArgs...))
	assertPlanUsesIndex(t, "the scoped audit page query", "idx_identity_audit_logs_org_created_at",
		explain(t, db, listQuery, listArgs...))

	// The unowned variant (OrgScopeOrganizationsAndUnowned, which
	// terraform-state-manager needs because it writes org-less audit rows by
	// design) adds `OR al.organization_id IS NULL`. PostgreSQL btrees index
	// NULLs, so the same index serves it — this is the assertion that would
	// fail if anyone "optimised" the index by making it partial on
	// organization_id IS NOT NULL.
	_, _, unownedList, unownedArgs := buildListAuditLogsQueries(
		AuditFilters{}, OrgScopeOrganizationsAndUnowned(coldOrg), 50, 0)
	if !strings.Contains(unownedList, "IS NULL") {
		t.Fatalf("the unowned scope no longer emits an IS NULL branch:\n%s", unownedList)
	}
	assertPlanUsesIndex(t, "the scoped-plus-unowned audit page query",
		"idx_identity_audit_logs_org_created_at", explain(t, db, unownedList, unownedArgs...))
}

// assertAuditExportPlan covers the export axis — the one that kept leaking after
// terraform-registry#719 was closed on the list axis. It filters on a created_at
// range AND the scope, which is exactly the pair the composite index orders.
func assertAuditExportPlan(t *testing.T, db *sql.DB) {
	t.Helper()

	coldOrg := scanUUID(t, db, `SELECT id FROM identity.organizations WHERE name = 'bulk-cold'`)

	query := `
		SELECT al.id, al.user_id, al.organization_id, al.action, al.resource_type, al.resource_id,
		       al.metadata, al.ip_address, al.created_at,
		       u.email AS user_email, u.name AS user_name
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		WHERE al.created_at >= $1 AND al.created_at <= $2
		  AND al.organization_id = ANY($3)
		ORDER BY al.created_at ASC`

	plan := explain(t, db, query,
		"1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z", pq.Array([]string{coldOrg}))
	assertPlanUsesIndex(t, "the scoped audit export stream",
		"idx_identity_audit_logs_org_created_at", plan)
}

func assertMembershipPlans(t *testing.T, db *sql.DB) {
	t.Helper()

	userID := scanUUID(t, db, `SELECT id FROM identity.users ORDER BY email LIMIT 1`)

	// GetUserMemberships / GetUserWithOrgRoles: the membership+scope resolution
	// that runs on essentially every login and token mint.
	plan := explain(t, db, `
		SELECT om.organization_id, COALESCE(o.name, '') as organization_name,
		       om.role_template_id, om.created_at,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes
		FROM organization_members om
		LEFT JOIN organizations o ON om.organization_id = o.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id
		WHERE om.user_id = $1
		ORDER BY om.created_at DESC`, userID)
	assertPlanUsesIndex(t, "GetUserMemberships", "idx_identity_organization_members_user_id", plan)

	// loadMembershipsForUsers batches the same predicate as `= ANY($1)`.
	plan = explain(t, db, `
		SELECT om.user_id, om.organization_id FROM organization_members om
		WHERE om.user_id = ANY($1)`, pq.Array([]string{userID}))
	assertPlanUsesIndex(t, "loadMembershipsForUsers", "idx_identity_organization_members_user_id", plan)

	// GetUserOrganizations joins on the same column.
	plan = explain(t, db, `
		SELECT o.id, o.name FROM organizations o
		INNER JOIN organization_members om ON o.id = om.organization_id
		WHERE om.user_id = $1
		ORDER BY o.created_at DESC`, userID)
	assertPlanUsesIndex(t, "GetUserOrganizations", "idx_identity_organization_members_user_id", plan)
}

func assertAPIKeyPlans(t *testing.T, db *sql.DB) {
	t.Helper()

	userID := scanUUID(t, db, `SELECT id FROM identity.users ORDER BY email LIMIT 1`)
	coldOrg := scanUUID(t, db, `SELECT id FROM identity.organizations WHERE name = 'bulk-cold'`)

	plan := explain(t, db, `
		SELECT ak.id FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1
		ORDER BY ak.created_at DESC`, userID)
	assertPlanUsesIndex(t, "ListAPIKeysByUser", "idx_identity_api_keys_user_id", plan)

	plan = explain(t, db, `
		SELECT ak.id FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.organization_id = $1
		ORDER BY ak.created_at DESC`, coldOrg)
	assertPlanUsesIndex(t, "ListAPIKeysByOrganization", "idx_identity_api_keys_organization_id", plan)
}

// TestIntegrationHotPathIndexCascades asserts the other half of what these
// indexes are for: identity.users / identity.organizations are deletable, and
// every referencing column that PostgreSQL has to check on that delete now has
// an index. An unindexed referencing column turns a single-row delete into a
// sequential scan of the child table — on audit_logs and revoked_tokens, the two
// tables that grow with traffic.
func TestIntegrationHotPathIndexCascades(t *testing.T) {
	db := identityTestDB(t)

	type ref struct {
		table  string
		column string
	}
	refs := []ref{
		// Since v0.25.0 audit_logs carries no foreign key at all (issue #142:
		// the column is a historical record, not a live reference), so this
		// entry is no longer about a cascade — the index is still required,
		// because it is what serves the mandatory AuditScope predicate on the
		// largest table in the schema, and losing it would be the same outage
		// by a different route.
		{"audit_logs", "organization_id"},
		{"organization_members", "user_id"},
		{"organization_members", "role_template_id"},
		{"api_keys", "organization_id"},
		{"api_keys", "user_id"},
		{"revoked_tokens", "user_id"},
	}

	for _, r := range refs {
		var indexed bool
		if err := db.QueryRow(`
			SELECT EXISTS (
			    SELECT 1
			    FROM pg_index i
			    JOIN pg_class c ON c.oid = i.indrelid
			    JOIN pg_namespace n ON n.oid = c.relnamespace
			    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
			    WHERE n.nspname = 'identity' AND c.relname = $1 AND a.attname = $2
			)`, r.table, r.column).Scan(&indexed); err != nil {
			t.Fatalf("failed to check the leading-column index on identity.%s(%s): %v",
				r.table, r.column, err)
		}
		if !indexed {
			t.Errorf("identity.%s.%s is a referencing column with no index whose LEADING "+
				"column it is; deleting the parent row sequential-scans %s. "+
				"(A composite index that merely contains the column does not count — a btree "+
				"cannot seek on a trailing column, which is exactly the defect "+
				"UNIQUE(organization_id, user_id) hid on organization_members.user_id.)",
				r.table, r.column, r.table)
		}
	}

	// Prove it end to end rather than only structurally: an organization delete
	// cascades through api_keys and leaves audit_logs.organization_id in place
	// (see delete_tenancy_integration_test.go for why it must), and a user
	// delete cascades through organization_members, revoked_tokens and api_keys.
	orgID := scanUUID(t, db, `INSERT INTO identity.organizations (name) VALUES ('cascade-org') RETURNING id`)
	userID := scanUUID(t, db, `INSERT INTO identity.users (email, name) VALUES ('cascade@example.test', 'c') RETURNING id`)
	mustExec(t, db, fmt.Sprintf(
		`INSERT INTO identity.organization_members (organization_id, user_id) VALUES (%s, %s)`,
		pq.QuoteLiteral(orgID), pq.QuoteLiteral(userID)))
	mustExec(t, db, fmt.Sprintf(
		`INSERT INTO identity.api_keys (organization_id, user_id, name, key_hash, key_prefix)
		 VALUES (%s, %s, 'k', 'h', 'p')`, pq.QuoteLiteral(orgID), pq.QuoteLiteral(userID)))
	mustExec(t, db, fmt.Sprintf(
		`INSERT INTO identity.audit_logs (organization_id, user_id, action) VALUES (%s, %s, 'a')`,
		pq.QuoteLiteral(orgID), pq.QuoteLiteral(userID)))
	mustExec(t, db, fmt.Sprintf(
		`INSERT INTO identity.revoked_tokens (jti, user_id, expires_at)
		 VALUES (gen_random_uuid(), %s, NOW() + INTERVAL '1 hour')`, pq.QuoteLiteral(userID)))

	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.organizations WHERE id = %s`, pq.QuoteLiteral(orgID)))
	mustExec(t, db, fmt.Sprintf(`DELETE FROM identity.users WHERE id = %s`, pq.QuoteLiteral(userID)))

	var remaining int
	if err := db.QueryRow(`SELECT count(*) FROM identity.revoked_tokens`).Scan(&remaining); err != nil {
		t.Fatalf("failed to count revoked_tokens after the cascade: %v", err)
	}
	if remaining != 0 {
		t.Errorf("deleting the user should have cascaded its revoked_tokens rows away, %d remain", remaining)
	}
}
