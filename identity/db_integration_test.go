//go:build integration

package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgtype"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// migrationTestDSN points the connection at a query mode that survives the
// schema changing underneath it.
//
// pgx caches a prepared statement per connection by default, so re-executing a
// query whose result type has changed fails once with SQLSTATE 0A000, "cached
// plan must not change result type". That is precisely what this suite does on
// purpose: it asserts a column's contents, steps the migration back down, and
// then asserts the same column through the same SQL text with the type
// reversed. pgx returns the error rather than retrying by design — it cannot
// know whether a retry is safe inside a transaction or a batch — and lib/pq,
// which kept no such cache, never raised it.
//
// describe_exec re-describes each statement instead of caching it, and is the
// one mode pgx documents as safe when the schema is modified. Unlike exec it
// keeps the binary format, so it changes nothing else about how values encode.
func migrationTestDSN(t *testing.T, dsn string) string {
	t.Helper()

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL %q is not a URL: %v", dsn, err)
	}
	q := parsed.Query()
	q.Set("default_query_exec_mode", "describe_exec")
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// Migration versions this test pins deliberately, because it asserts on the
// specific DDL those migrations perform. These are NOT "the latest version" --
// the latest is derived from the embedded FS via
// latestEmbeddedMigrationVersion (see db_test.go), so adding a migration can
// never silently leave this test asserting a stale version, which is exactly
// how migrations 000004 and 000005 went unexercised (issue #140).
const (
	// preRegistryReconciliationVersion is the last version at which
	// role_templates.scopes / api_keys.scopes are still TEXT[] and
	// oidc_config.scopes is still TEXT.
	preRegistryReconciliationVersion uint = 2
	// jsonbScopesVersion is migration 000003, the in-place TEXT[]/TEXT ->
	// JSONB scope-column conversion.
	jsonbScopesVersion uint = 3
	// dropVestigialIsActiveVersion is migration 000004, which drops the
	// vestigial is_active columns from organizations, users, and api_keys.
	dropVestigialIsActiveVersion uint = 4
	// singleActiveOIDCConfigVersion is migration 000005, which deactivates all
	// but the most recently updated active oidc_config row and then enforces
	// the single-active invariant with a partial unique index.
	singleActiveOIDCConfigVersion uint = 5
)

// isActiveDroppedTables are the tables whose vestigial is_active column
// migration 000004 drops.
var isActiveDroppedTables = []string{"organizations", "users", "api_keys"}

// TestIntegrationRunMigrations exercises RunMigrations and GetMigrationVersion
// against a real PostgreSQL database. It covers:
//
//  1. The migration-000003 in-place column-type conversions
//     (role_templates.scopes, api_keys.scopes, oidc_config.scopes: TEXT[]/TEXT
//     -> JSONB, and back on the way down) actually convert seeded, non-trivial
//     data correctly in both directions, not just against empty tables.
//  2. Migration 000004's DROP COLUMN and migration 000005's data-cleanup
//     UPDATE plus partial unique index, in both directions, against seeded
//     data — the DDL that both consuming applications apply at startup.
//  3. The full up/down lifecycle of RunMigrations and GetMigrationVersion,
//     up to the version derived from the embedded migrations FS and back down
//     to 0, including issue #64's fix to the identity schema's down-migration
//     (which used to end with a "DROP SCHEMA" that always failed because
//     golang-migrate's own version-tracking table still lived inside that
//     schema, permanently "dirty"-ing migration state with no in-library way
//     to recover).
//
// It requires a live database reachable via the TEST_DATABASE_URL environment
// variable (a libpq connection string, e.g.
// "postgres://postgres:postgres@localhost:5432/identity_test?sslmode=disable")
// and is skipped otherwise, so `go test ./...` without a database configured
// -- including everyone's default local run -- is unaffected. The
// "integration" build tag additionally keeps it out of ordinary `go test
// ./...` and `go vet ./...` invocations entirely; run it explicitly with:
//
//	go test -tags=integration ./... -run TestIntegrationRunMigrations
func TestIntegrationRunMigrations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", migrationTestDSN(t, dsn))
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach database at TEST_DATABASE_URL: %v", err)
	}

	// Start from a clean slate so re-running this test locally against a
	// persistent database exercises a real up/down cycle rather than
	// tripping over a schema left behind by a previous run.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema before test: %v", err)
	}

	// expectedLatestMigrationVersion is derived from the embedded migrations
	// FS rather than restated as a literal, so it tracks identity/migrations
	// automatically instead of going stale when a migration is added.
	expectedLatestMigrationVersion := latestEmbeddedMigrationVersion(t)

	testJSONBScopeConversion(t, db)

	// Reset again: the sub-test above leaves the schema part-migrated (it
	// deliberately stops short of a full down-unwind, which is covered by the
	// lifecycle test below). Start each sub-test from a known-empty schema.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema before is_active/single-active test: %v", err)
	}

	testIsActiveDropAndSingleActiveOIDCConfig(t, db)

	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema before lifecycle test: %v", err)
	}

	// --- up: apply every migration ---
	if err := RunMigrations(db, "up"); err != nil {
		t.Fatalf("RunMigrations(up) failed: %v", err)
	}

	version, dirty, err := GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after up failed: %v", err)
	}
	if dirty {
		t.Fatalf("expected clean migration state after up, got dirty=true at version %d", version)
	}
	if version != expectedLatestMigrationVersion {
		t.Fatalf("expected migration version %d after up, got %d", expectedLatestMigrationVersion, version)
	}

	// --- up again: golang-migrate's ErrNoChange must be swallowed, so a
	// second "up" against an already-migrated database is a no-op, not an
	// error. ---
	if err := RunMigrations(db, "up"); err != nil {
		t.Fatalf("second RunMigrations(up) should be a no-op, got error: %v", err)
	}

	version, dirty, err = GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after second up failed: %v", err)
	}
	if dirty || version != expectedLatestMigrationVersion {
		t.Fatalf("expected unchanged clean state at version %d after idempotent up, got version=%d dirty=%v",
			expectedLatestMigrationVersion, version, dirty)
	}

	// --- down: fully unwind. Before issue #64's fix this failed with
	// "schema not empty" because migration 000001's down step tried to DROP
	// SCHEMA identity while golang-migrate's own bookkeeping table was still
	// in it, leaving migration state permanently dirty. This is the assertion
	// that guards against that regression returning. ---
	if err := RunMigrations(db, "down"); err != nil {
		t.Fatalf("RunMigrations(down) failed (regression of issue #64): %v", err)
	}

	version, dirty, err = GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion after down failed: %v", err)
	}
	if dirty {
		t.Fatalf("expected clean migration state after down, got dirty=true at version %d", version)
	}
	if version != 0 {
		t.Fatalf("expected migration version 0 after a full down-unwind, got %d", version)
	}
}

// testJSONBScopeConversion seeds representative, non-trivial rows (including
// a multi-value array, a single-value array, an empty array, and -- for
// oidc_config, whose "scopes" column has always been nullable -- an explicit
// NULL) before migrating from version 2 to version 3, and asserts that
// migration 000003's in-place TEXT[]/TEXT -> JSONB column-type conversions
// (and 000003's down-migration reverse conversions) actually convert real
// data correctly, rather than only ever running against empty tables.
//
// It requires db to already have the identity schema absent (a fresh
// "DROP SCHEMA ... CASCADE" state). It drives migration versions explicitly
// (never "up to latest"), because it asserts on the schema shape at exactly
// versions 2 and 3; the full-lifecycle-to-latest coverage lives in
// TestIntegrationRunMigrations. Using RunMigrations(db, "up") here instead
// would silently migrate past 000003 to the newest migration and assert
// against the wrong schema — the defect behind issue #140.
func testJSONBScopeConversion(t *testing.T, db *sql.DB) {
	t.Helper()

	// newMigrator borrows one connection from db and the migrator owns it
	// until closeMigrator hands it back; db itself is never closed by this
	// package, so the rest of this test keeps using it afterwards. This
	// mirrors what RunMigrations/GetMigrationVersion do internally.
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		t.Fatalf("failed to create migrator: %v", err)
	}
	defer closeMigrator(m)

	// --- migrate to version 2 only (pre-registry-reconciliation shape,
	// where role_templates/api_keys.scopes are still TEXT[] and
	// oidc_config.scopes is still TEXT) ---
	if err := m.Migrate(preRegistryReconciliationVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to migrate to version %d: %v", preRegistryReconciliationVersion, err)
	}

	assertCleanAtVersion(t, db, preRegistryReconciliationVersion)

	// --- seed representative rows exercising the conversions in 000003 ---

	// role_templates.scopes: TEXT[] -> JSONB. The seeded 'admin' row (from
	// 000001/000002) already covers a single-element array; add a
	// multi-element one too.
	if _, err := db.Exec(
		`INSERT INTO identity.role_templates (name, display_name, scopes, is_system)
		 VALUES ('custom-role', 'Custom Role', ARRAY['reports:read','reports:write','custom:scope'], false)`,
	); err != nil {
		t.Fatalf("failed to seed role_templates row: %v", err)
	}

	// api_keys.scopes: TEXT[] -> JSONB, including an empty-array edge case.
	if _, err := db.Exec(
		`INSERT INTO identity.api_keys (organization_id, name, key_hash, key_prefix, scopes)
		 VALUES
		     ((SELECT id FROM identity.organizations WHERE name = 'default'),
		      'multi-scope-key', 'hash-multi', 'pfx-multi', ARRAY['sources:read','sources:write']),
		     ((SELECT id FROM identity.organizations WHERE name = 'default'),
		      'empty-scope-key', 'hash-empty', 'pfx-empty', ARRAY[]::text[])`,
	); err != nil {
		t.Fatalf("failed to seed api_keys rows: %v", err)
	}

	// oidc_config.scopes: TEXT (comma-separated) -> JSONB, including a
	// single-value (no comma) and an explicit NULL -- the column has always
	// been nullable, so this is a real, reachable state, not a fabricated one.
	if _, err := db.Exec(
		`INSERT INTO identity.oidc_config (issuer_url, client_id, client_secret_encrypted, redirect_url, scopes)
		 VALUES
		     ('https://issuer.example/multi', 'client-multi', 'secret', 'https://app.example/cb',
		      'openid,email,profile,offline_access'),
		     ('https://issuer.example/single', 'client-single', 'secret', 'https://app.example/cb',
		      'openid'),
		     ('https://issuer.example/null', 'client-null', 'secret', 'https://app.example/cb', NULL)`,
	); err != nil {
		t.Fatalf("failed to seed oidc_config rows: %v", err)
	}

	// --- migrate up to exactly version 3, applying the JSONB conversion ---
	if err := m.Migrate(jsonbScopesVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to migrate from version %d to %d: %v",
			preRegistryReconciliationVersion, jsonbScopesVersion, err)
	}
	assertCleanAtVersion(t, db, jsonbScopesVersion)

	// --- assert the post-migration JSONB values ---
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.role_templates WHERE name = 'admin'`,
		[]string{"admin"})
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.role_templates WHERE name = 'custom-role'`,
		[]string{"reports:read", "reports:write", "custom:scope"})
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.api_keys WHERE name = 'multi-scope-key'`,
		[]string{"sources:read", "sources:write"})
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.api_keys WHERE name = 'empty-scope-key'`,
		[]string{})
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-multi'`,
		[]string{"openid", "email", "profile", "offline_access"})
	assertJSONBScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-single'`,
		[]string{"openid"})
	// A NULL TEXT column converts to a SQL NULL JSONB value (to_jsonb of a
	// NULL input is NULL, not the JSON literal "null" or "[]") -- assert that
	// explicitly rather than assuming array semantics apply.
	assertNullJSONBScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-null'`)

	// --- migrate back down to version 2, reversing only migration 000003 ---
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to step down from version %d to %d: %v",
			jsonbScopesVersion, preRegistryReconciliationVersion, err)
	}
	assertCleanAtVersion(t, db, preRegistryReconciliationVersion)

	// --- assert the down-migration's reverse conversion restored the
	// original TEXT[]/TEXT values ---
	assertTextArrayScopes(t, db, `SELECT scopes FROM identity.role_templates WHERE name = 'admin'`,
		[]string{"admin"})
	assertTextArrayScopes(t, db, `SELECT scopes FROM identity.role_templates WHERE name = 'custom-role'`,
		[]string{"reports:read", "reports:write", "custom:scope"})
	assertTextArrayScopes(t, db, `SELECT scopes FROM identity.api_keys WHERE name = 'multi-scope-key'`,
		[]string{"sources:read", "sources:write"})
	assertTextArrayScopes(t, db, `SELECT scopes FROM identity.api_keys WHERE name = 'empty-scope-key'`,
		[]string{})
	assertTextScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-multi'`,
		"openid,email,profile,offline_access")
	assertTextScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-single'`,
		"openid")
	// Known, pre-existing asymmetry (not introduced by this test, and not
	// issue #64): a NULL TEXT column converts to a NULL JSONB value on the
	// way up, but 000003's down-migration coalesces NULL JSONB to an empty
	// array before converting back (`coalesce(j, '[]'::jsonb)` in
	// _identity_jsonb_to_text_array), so the round trip lands on an empty
	// string rather than restoring NULL. Documented here so it stays a known,
	// asserted behavior instead of silently drifting.
	assertTextScopes(t, db, `SELECT scopes FROM identity.oidc_config WHERE client_id = 'client-null'`,
		"")
}

// testIsActiveDropAndSingleActiveOIDCConfig exercises migrations 000004 and
// 000005 against seeded data, in both directions.
//
// Neither migration had ever been applied end to end against a real PostgreSQL
// before issue #140: the integration job asserted a stale "latest version" of 3
// and was additionally marked continue-on-error, so its failure never surfaced.
// Both consuming applications call RunMigrations at startup, so an untested
// defect in either one surfaces first as a failed deploy against a live
// database — and identity/db.go exposes no Force entry point to clear the dirty
// state a partially applied migration leaves behind.
//
// It asserts:
//   - 000004 drops the vestigial is_active columns from organizations, users
//     and api_keys, and its down step restores them.
//   - 000005's data-safety cleanup UPDATE collapses pre-existing multi-active
//     oidc_config rows down to the single most recently updated one, rather
//     than failing to build its unique index.
//   - 000005's partial unique index is actually enforced by PostgreSQL (a
//     second is_active=true row is rejected), and its down step removes that
//     enforcement.
//
// It requires db to have the identity schema absent on entry.
func testIsActiveDropAndSingleActiveOIDCConfig(t *testing.T, db *sql.DB) {
	t.Helper()

	// See testJSONBScopeConversion: the migrator borrows one connection from
	// db and closeMigrator gives it back; db itself is never closed here.
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		t.Fatalf("failed to create migrator: %v", err)
	}
	defer closeMigrator(m)

	// --- version 3: the vestigial is_active columns still exist ---
	if err := m.Migrate(jsonbScopesVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to migrate to version %d: %v", jsonbScopesVersion, err)
	}
	assertCleanAtVersion(t, db, jsonbScopesVersion)
	for _, table := range isActiveDroppedTables {
		if !columnExists(t, db, table, "is_active") {
			t.Fatalf("precondition failed: identity.%s.is_active should exist at version %d",
				table, jsonbScopesVersion)
		}
	}

	// --- 000004 up: the columns are dropped ---
	if err := m.Migrate(dropVestigialIsActiveVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to migrate to version %d: %v", dropVestigialIsActiveVersion, err)
	}
	assertCleanAtVersion(t, db, dropVestigialIsActiveVersion)
	for _, table := range isActiveDroppedTables {
		if columnExists(t, db, table, "is_active") {
			t.Errorf("migration %d should have dropped identity.%s.is_active, but it still exists",
				dropVestigialIsActiveVersion, table)
		}
	}
	// oidc_config.is_active is explicitly out of 000004's scope: it is read and
	// written via Activate/Deactivate. Assert it survived, so a future edit that
	// over-broadens the DROP COLUMN list is caught here.
	if !columnExists(t, db, "oidc_config", "is_active") {
		t.Errorf("migration %d must not drop identity.oidc_config.is_active (it is actively used)",
			dropVestigialIsActiveVersion)
	}

	// --- seed the multi-active state that 000005's cleanup UPDATE must fix ---
	// Three active rows with distinct updated_at values: only the newest may
	// survive as active. Without the cleanup, CREATE UNIQUE INDEX would fail.
	if _, err := db.Exec(
		`INSERT INTO identity.oidc_config
		     (issuer_url, client_id, client_secret_encrypted, redirect_url, is_active, updated_at)
		 VALUES
		     ('https://issuer.example/oldest', 'client-oldest', 'secret', 'https://app.example/cb',
		      true, NOW() - INTERVAL '2 hours'),
		     ('https://issuer.example/middle', 'client-middle', 'secret', 'https://app.example/cb',
		      true, NOW() - INTERVAL '1 hour'),
		     ('https://issuer.example/newest', 'client-newest', 'secret', 'https://app.example/cb',
		      true, NOW())`,
	); err != nil {
		t.Fatalf("failed to seed multi-active oidc_config rows: %v", err)
	}

	// --- 000005 up: cleanup UPDATE + partial unique index ---
	if err := m.Migrate(singleActiveOIDCConfigVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migration to version %d failed — its data-safety cleanup UPDATE must "+
			"collapse pre-existing multi-active rows before the unique index is built: %v",
			singleActiveOIDCConfigVersion, err)
	}
	assertCleanAtVersion(t, db, singleActiveOIDCConfigVersion)

	var activeCount int
	var activeClientID string
	if err := db.QueryRow(
		`SELECT count(*), coalesce(max(client_id), '') FROM identity.oidc_config WHERE is_active`,
	).Scan(&activeCount, &activeClientID); err != nil {
		t.Fatalf("failed to count active oidc_config rows: %v", err)
	}
	if activeCount != 1 {
		t.Errorf("migration %d's cleanup should leave exactly 1 active oidc_config row, got %d",
			singleActiveOIDCConfigVersion, activeCount)
	}
	if activeClientID != "client-newest" {
		t.Errorf("migration %d's cleanup should keep the most recently updated row active, "+
			"got %q active", singleActiveOIDCConfigVersion, activeClientID)
	}

	// The invariant must be enforced by PostgreSQL, not just by application
	// convention: a second active row has to be rejected outright.
	if _, err := db.Exec(
		`INSERT INTO identity.oidc_config
		     (issuer_url, client_id, client_secret_encrypted, redirect_url, is_active)
		 VALUES ('https://issuer.example/second', 'client-second', 'secret',
		         'https://app.example/cb', true)`,
	); err == nil {
		t.Errorf("migration %d's partial unique index should reject a second active "+
			"oidc_config row, but the insert succeeded", singleActiveOIDCConfigVersion)
	}
	// An inactive row is unaffected by a *partial* index — assert that, so a
	// future edit that drops the WHERE clause (making the index total, and
	// permitting only one inactive row overall) is caught.
	if _, err := db.Exec(
		`INSERT INTO identity.oidc_config
		     (issuer_url, client_id, client_secret_encrypted, redirect_url, is_active)
		 VALUES ('https://issuer.example/inactive-a', 'client-inactive-a', 'secret',
		         'https://app.example/cb', false),
		        ('https://issuer.example/inactive-b', 'client-inactive-b', 'secret',
		         'https://app.example/cb', false)`,
	); err != nil {
		t.Errorf("migration %d's index must be partial (WHERE is_active): multiple inactive "+
			"rows should still be allowed, got: %v", singleActiveOIDCConfigVersion, err)
	}

	// --- 000005 down: enforcement is removed ---
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to step down from version %d: %v", singleActiveOIDCConfigVersion, err)
	}
	assertCleanAtVersion(t, db, dropVestigialIsActiveVersion)
	if _, err := db.Exec(
		`INSERT INTO identity.oidc_config
		     (issuer_url, client_id, client_secret_encrypted, redirect_url, is_active)
		 VALUES ('https://issuer.example/second', 'client-second', 'secret',
		         'https://app.example/cb', true)`,
	); err != nil {
		t.Errorf("migration %d's down step should drop the partial unique index, but a second "+
			"active row was still rejected: %v", singleActiveOIDCConfigVersion, err)
	}

	// --- 000004 down: the vestigial columns are restored ---
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to step down from version %d: %v", dropVestigialIsActiveVersion, err)
	}
	assertCleanAtVersion(t, db, jsonbScopesVersion)
	for _, table := range isActiveDroppedTables {
		if !columnExists(t, db, table, "is_active") {
			t.Errorf("migration %d's down step should restore identity.%s.is_active",
				dropVestigialIsActiveVersion, table)
		}
	}
}

// assertCleanAtVersion asserts the migration state is exactly want and not dirty.
func assertCleanAtVersion(t *testing.T, db *sql.DB, want uint) {
	t.Helper()

	version, dirty, err := GetMigrationVersion(db)
	if err != nil {
		t.Fatalf("GetMigrationVersion failed (expected clean version %d): %v", want, err)
	}
	if dirty || version != want {
		t.Fatalf("expected clean migration state at version %d, got version=%d dirty=%v",
			want, version, dirty)
	}
}

// columnExists reports whether identity.<table>.<column> is present.
func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()

	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS (
		     SELECT 1 FROM information_schema.columns
		     WHERE table_schema = 'identity' AND table_name = $1 AND column_name = $2
		 )`, table, column,
	).Scan(&exists); err != nil {
		t.Fatalf("failed to check identity.%s.%s existence: %v", table, column, err)
	}
	return exists
}

func assertJSONBScopes(t *testing.T, db *sql.DB, query string, want []string) {
	t.Helper()

	var raw []byte
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}

	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("failed to unmarshal JSONB scopes %q: %v", raw, err)
	}

	if !equalStringSlices(got, want) {
		t.Errorf("query %q: got JSONB scopes %v, want %v", query, got, want)
	}
}

func assertNullJSONBScopes(t *testing.T, db *sql.DB, query string) {
	t.Helper()

	var raw sql.NullString
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}
	if raw.Valid {
		t.Errorf("query %q: expected NULL JSONB scopes, got %q", query, raw.String)
	}
}

func assertTextArrayScopes(t *testing.T, db *sql.DB, query string, want []string) {
	t.Helper()

	var got []string
	if err := db.QueryRow(query).Scan(pgtype.NewMap().SQLScanner(&got)); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}

	if !equalStringSlices(got, want) {
		t.Errorf("query %q: got TEXT[] scopes %v, want %v", query, got, want)
	}
}

func assertTextScopes(t *testing.T, db *sql.DB, query string, want string) {
	t.Helper()

	var got sql.NullString
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}

	if got.String != want || !got.Valid {
		t.Errorf("query %q: got TEXT scopes %q (valid=%v), want %q", query, got.String, got.Valid, want)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIntegrationRunMigrationsReleasesPooledConnections is the regression
// guard for issue #139: every exported migration entry point must give the
// connection it borrows back to the caller's pool.
//
// The three entry points take the consuming application's *sql.DB. Until this
// fix each call checked out a dedicated connection (via golang-migrate's
// postgres.WithInstance) and never returned it, so every invocation
// permanently cost the consumer one slot of its MaxOpenConns.
// GetMigrationVersion is the sharp end: it returns nothing but a version and a
// dirty flag, which is exactly the shape of a readiness probe, so a handful of
// probe intervals could drain the pool and leave every request in the
// application waiting on a connection that was never coming back.
//
// The pool is therefore capped at a single connection. With the leak, the
// SECOND borrow has nothing to wait for and blocks forever — so the whole
// sequence runs on its own goroutine under a deadline, which converts that
// hang into a failure with a diagnosis instead of a CI timeout. The
// single-connection pool then has to serve an ordinary query, and the pool's
// own accounting has to agree that nothing is still checked out.
//
// The test name deliberately starts with TestIntegrationRunMigrations so the
// CI job's `-run TestIntegrationRunMigrations` filter selects it.
func TestIntegrationRunMigrationsReleasesPooledConnections(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", migrationTestDSN(t, dsn))
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer func() { _ = db.Close() }()

	// One connection, and no idle-timeout churn that could mask a leak by
	// quietly opening a replacement.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach database at TEST_DATABASE_URL: %v", err)
	}

	if _, err := db.Exec(`DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("failed to reset identity schema before test: %v", err)
	}

	// Exercise every entry point more than once. Each call borrows and must
	// return; only the first can succeed if any of them keeps its connection.
	const versionCalls = 5
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			if err := RunMigrations(db, "up"); err != nil {
				return fmt.Errorf("RunMigrations(up): %w", err)
			}
			if err := RunMigrations(db, "up"); err != nil {
				return fmt.Errorf("second RunMigrations(up): %w", err)
			}
			if err := RunMigrationSteps(db, -1); err != nil {
				return fmt.Errorf("RunMigrationSteps(-1): %w", err)
			}
			if err := RunMigrationSteps(db, 1); err != nil {
				return fmt.Errorf("RunMigrationSteps(1): %w", err)
			}
			for i := 1; i <= versionCalls; i++ {
				if _, _, err := GetMigrationVersion(db); err != nil {
					return fmt.Errorf("GetMigrationVersion call %d: %w", i, err)
				}
			}
			return nil
		}()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("migration entry points failed against a single-connection pool: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatalf("the migration entry points blocked waiting for a connection from a "+
			"pool of 1 after %d version calls: a previous call did not return the "+
			"connection it borrowed (issue #139)", versionCalls)
	}

	if stats := db.Stats(); stats.InUse != 0 {
		t.Errorf("db.Stats().InUse = %d after the full migration sequence, want 0: "+
			"%d connection(s) are still checked out", stats.InUse, stats.InUse)
	}
	if stats := db.Stats(); stats.OpenConnections > 1 {
		t.Errorf("db.Stats().OpenConnections = %d, want at most 1 for a pool capped at 1",
			stats.OpenConnections)
	}

	// The pool must still be able to serve ordinary application traffic. The
	// short deadline is what makes an exhausted pool fail here rather than
	// stall: db.QueryRowContext waits for a free connection.
	probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var one int
	if err := db.QueryRowContext(probeCtx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("the single-connection pool could not serve a query after the migration "+
			"sequence (its only connection was never returned): %v", err)
	}
	if one != 1 {
		t.Fatalf("probe query returned %d, want 1", one)
	}
}
