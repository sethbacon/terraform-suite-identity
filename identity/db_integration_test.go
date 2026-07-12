//go:build integration

package identity

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/lib/pq"
)

// expectedLatestMigrationVersion is the version number of the highest-numbered
// migration under identity/migrations. Update this alongside adding a new
// migration file so TestIntegrationRunMigrations keeps asserting against the
// real latest version instead of silently passing on a stale one.
const expectedLatestMigrationVersion uint = 3

// TestIntegrationRunMigrations exercises RunMigrations and GetMigrationVersion
// against a real PostgreSQL database. It covers two things:
//
//  1. The migration-000003 in-place column-type conversions
//     (role_templates.scopes, api_keys.scopes, oidc_config.scopes: TEXT[]/TEXT
//     -> JSONB, and back on the way down) actually convert seeded, non-trivial
//     data correctly in both directions, not just against empty tables.
//  2. The full up/down lifecycle of RunMigrations and GetMigrationVersion,
//     including issue #64's fix to the identity schema's down-migration (which
//     used to end with a "DROP SCHEMA" that always failed because
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
//
// NOTE: as of this writing, issue #64's down-migration fix
// (fix/64-migration-down-schema-drop, PR #101) has not yet merged to main.
// The final full RunMigrations(db, "down") assertion at the bottom of this
// test therefore fails deterministically today -- that is expected, and is
// exactly the regression this test exists to catch; the CI job that runs it
// is marked continue-on-error until #101 merges. Everything above that final
// assertion (including the JSONB round-trip coverage) does not depend on
// #64 and passes today.
func TestIntegrationRunMigrations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	db, err := sql.Open("postgres", dsn)
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

	testJSONBScopeConversion(t, db)

	// Reset again: the sub-test above leaves the schema at version 2 (it
	// deliberately never runs a full down-unwind, since that's the part of
	// the lifecycle covered separately below and gated on issue #64). Start
	// the up/down lifecycle test from a known-empty schema.
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
	// in it, leaving migration state permanently dirty. See the package doc
	// comment above: this is expected to fail until PR #101 merges. ---
	if err := RunMigrations(db, "down"); err != nil {
		t.Fatalf("RunMigrations(down) failed (regression of issue #64, tracked by PR #101 -- "+
			"see this test's doc comment): %v", err)
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
// "DROP SCHEMA ... CASCADE" state) and deliberately stops at version 2 --
// it never drives a full down-unwind, so it does not depend on issue #64's
// fix (unlike the full lifecycle test in TestIntegrationRunMigrations).
func testJSONBScopeConversion(t *testing.T, db *sql.DB) {
	t.Helper()

	// newMigrator wraps the *sql.DB in a golang-migrate driver that takes
	// ownership of it on Close (see postgres.WithInstance): closing the
	// returned *migrate.Migrate would close db out from under the rest of
	// this test, exactly like RunMigrations/GetMigrationVersion themselves
	// never call Close on the migrators they create internally. So, as they
	// do, we deliberately never call Close here either.
	m, err := newMigrator(db)
	if err != nil {
		t.Fatalf("failed to create migrator: %v", err)
	}

	// --- migrate to version 2 only (pre-registry-reconciliation shape,
	// where role_templates/api_keys.scopes are still TEXT[] and
	// oidc_config.scopes is still TEXT) ---
	if err := m.Migrate(2); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to migrate to version 2: %v", err)
	}

	if version, dirty, err := GetMigrationVersion(db); err != nil {
		t.Fatalf("GetMigrationVersion after migrating to version 2 failed: %v", err)
	} else if dirty || version != 2 {
		t.Fatalf("expected clean state at version 2, got version=%d dirty=%v", version, dirty)
	}

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

	// --- migrate up to version 3, applying the JSONB conversion ---
	if err := RunMigrations(db, "up"); err != nil {
		t.Fatalf("RunMigrations(up) from version 2 to 3 failed: %v", err)
	}
	if version, dirty, err := GetMigrationVersion(db); err != nil {
		t.Fatalf("GetMigrationVersion after migrating to version 3 failed: %v", err)
	} else if dirty || version != expectedLatestMigrationVersion {
		t.Fatalf("expected clean state at version %d, got version=%d dirty=%v",
			expectedLatestMigrationVersion, version, dirty)
	}

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

	// --- migrate back down to version 2, reversing only migration 000003
	// (not the full down-unwind that hits issue #64's DROP SCHEMA bug) ---
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to step down from version 3 to 2: %v", err)
	}
	if version, dirty, err := GetMigrationVersion(db); err != nil {
		t.Fatalf("GetMigrationVersion after stepping down to version 2 failed: %v", err)
	} else if dirty || version != 2 {
		t.Fatalf("expected clean state at version 2 after stepping down, got version=%d dirty=%v", version, dirty)
	}

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
	if err := db.QueryRow(query).Scan(pq.Array(&got)); err != nil {
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
