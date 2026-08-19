//go:build integration

package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// These tests run against their OWN database, derived from TEST_DATABASE_URL by
// suffixing the database name, for the same reason identity/store's suite does:
// they create decoy identity-shaped tables in public, which is exactly what the
// other suites in this repository assume is absent.

const routingTestSuffix = "_routing"

// routingTestDB creates (once) and returns the suite's database name and the
// administrative DSN for it.
func routingTestDB(t *testing.T) (name, baseDSN string) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL must be a postgres:// URL for this suite, got %q (parse error: %v)", dsn, err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	if base == "" {
		t.Fatalf("TEST_DATABASE_URL %q names no database", dsn)
	}
	name = base + routingTestSuffix

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to open the administrative connection: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.Ping(); err != nil {
		t.Fatalf("failed to reach the database at TEST_DATABASE_URL: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE ` + pgquote.Identifier(name)); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" { // duplicate_database
			t.Fatalf("failed to create the %q test database (the role needs CREATEDB): %v", name, err)
		}
	}

	target := *parsed
	target.Path = "/" + name
	return name, target.String()
}

// routingConn opens a pool on the suite's database with the given search_path.
// An empty searchPath leaves the server default (`"$user", public`) in place —
// the configuration both consuming applications' primary pools actually run.
func routingConn(t *testing.T, baseDSN, searchPath string) *sql.DB {
	t.Helper()

	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse %q: %v", baseDSN, err)
	}
	if searchPath != "" {
		q := parsed.Query()
		q.Set("search_path", searchPath)
		parsed.RawQuery = q.Encode()
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatalf("failed to open the test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to reach the test database: %v", err)
	}
	return db
}

func routingExec(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	for _, s := range statements {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("statement failed: %v\n%s", err, s)
		}
	}
}

// decoyPublicSchema is the situation both consuming applications are actually
// in: identity-shaped tables of their own, in public, in the same database as
// identity.*. It is the reason a misrouted read does not fail — every name and
// every column the repositories touch is present, so the query succeeds against
// the wrong rows.
var decoyPublicSchema = []string{
	`DROP SCHEMA IF EXISTS public CASCADE`,
	`CREATE SCHEMA public`,
	`CREATE TABLE public.organizations (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(255) UNIQUE NOT NULL,
		display_name VARCHAR(255),
		description TEXT,
		idp_type VARCHAR(50), idp_name VARCHAR(255),
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		email VARCHAR(255) UNIQUE NOT NULL,
		name VARCHAR(255) NOT NULL,
		oidc_sub VARCHAR(255) UNIQUE,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.role_templates (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		display_name VARCHAR(255), description TEXT,
		scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
		is_system BOOLEAN DEFAULT false,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.organization_members (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		organization_id UUID NOT NULL, user_id UUID NOT NULL, role_template_id UUID,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.api_keys (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID, organization_id UUID NOT NULL,
		name VARCHAR(255) NOT NULL, description TEXT,
		key_hash VARCHAR(255) NOT NULL, key_prefix VARCHAR(20) NOT NULL,
		scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
		expires_at TIMESTAMP, last_used_at TIMESTAMP,
		expiry_notification_sent_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.audit_logs (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID, organization_id UUID,
		action VARCHAR(500) NOT NULL, resource_type VARCHAR(100), resource_id VARCHAR(255),
		ip_address VARCHAR(45), metadata JSONB DEFAULT '{}',
		created_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.oidc_config (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(255) NOT NULL DEFAULT '',
		provider_type VARCHAR(50) NOT NULL DEFAULT 'generic_oidc',
		issuer_url TEXT NOT NULL, client_id VARCHAR(255) NOT NULL,
		client_secret_encrypted TEXT NOT NULL, redirect_url TEXT NOT NULL,
		scopes JSONB DEFAULT '["openid","email","profile"]'::jsonb,
		extra_config JSONB, created_by UUID, updated_by UUID,
		is_active BOOLEAN DEFAULT true,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW())`,
	`CREATE TABLE public.revoked_tokens (
		jti UUID PRIMARY KEY, user_id UUID NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
}

// TestIntegrationSchemaRoutingIsAsserted is the batch-12 gate: a connection
// whose search_path points somewhere other than the schema the deployment
// intends must be caught at construction, not discovered as a split-brain
// identity store.
//
// Every subtest runs against a real PostgreSQL because the defect is entirely a
// property of the server's name resolution. A mock cannot have two tables named
// users.
func TestIntegrationSchemaRoutingIsAsserted(t *testing.T) {
	ctx := context.Background()
	_, baseDSN := routingTestDB(t)

	admin := routingConn(t, baseDSN, "")
	routingExec(t, admin, `DROP SCHEMA IF EXISTS identity CASCADE`)
	routingExec(t, admin, decoyPublicSchema...)
	if err := RunMigrations(admin, "up"); err != nil {
		t.Fatalf("RunMigrations(up) failed: %v", err)
	}
	// One row per schema, distinguishable, so a misrouted read is visible as a
	// wrong VALUE and not merely as an empty result.
	routingExec(t, admin,
		`INSERT INTO public.users (email, name) VALUES ('legacy@example.test', 'Legacy Public User')`,
		`INSERT INTO identity.users (email, name) VALUES ('shared@example.test', 'Shared Identity User')`,
	)

	t.Run("the intended shared-schema routing is accepted", func(t *testing.T) {
		db := routingConn(t, baseDSN, SchemaName+",public")

		if err := VerifySchemaRouting(ctx, db, SchemaName); err != nil {
			t.Fatalf("VerifySchemaRouting rejected a correctly configured connection: %v", err)
		}

		routing, err := ResolveRouting(ctx, db)
		if err != nil {
			t.Fatalf("ResolveRouting: %v", err)
		}
		if !strings.Contains(routing.SearchPath, SchemaName) {
			t.Errorf("SearchPath = %q, want it to name the identity schema", routing.SearchPath)
		}
		for _, r := range routing.Tables {
			if r.Schema != SchemaName {
				t.Errorf("%s resolved to %q, want %q", r.Table, r.Schema, SchemaName)
			}
			if r.Kind != "r" {
				t.Errorf("%s resolved to relkind %q, want an ordinary table", r.Table, r.Kind)
			}
		}
	})

	t.Run("the misroute is silent without the assertion and caught with it", func(t *testing.T) {
		// The shipped default of one consuming application: identity
		// migrations applied, search_path left alone.
		db := routingConn(t, baseDSN, "")

		// First, the defect itself. This is the read a repository makes, on
		// the connection a consumer supplies, and it SUCCEEDS — against the
		// legacy row. No error, no missing relation, no log line.
		var name string
		if err := db.QueryRowContext(ctx, `SELECT name FROM users WHERE email = $1`,
			"legacy@example.test").Scan(&name); err != nil {
			t.Fatalf("the unqualified read failed, which would make this defect self-announcing: %v", err)
		}
		if name != "Legacy Public User" {
			t.Fatalf("unqualified read returned %q; the decoy schema is not set up as intended", name)
		}
		if err := db.QueryRowContext(ctx, `SELECT name FROM users WHERE email = $1`,
			"shared@example.test").Scan(&name); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("the shared identity row was visible on the public connection (err=%v); "+
				"the two schemas are not actually distinct in this fixture", err)
		}

		// Now the assertion the deployment would have made.
		err := VerifySchemaRouting(ctx, db, SchemaName)
		if err == nil {
			t.Fatal("VerifySchemaRouting accepted a connection that reads public.users while " +
				"the deployment asked for the identity schema — this is the exact " +
				"configuration that produces a split-brain identity store")
		}
		if !errors.Is(err, ErrSchemaRouting) {
			t.Errorf("error does not wrap ErrSchemaRouting: %v", err)
		}
		if !strings.Contains(err.Error(), "users resolves to public.users") {
			t.Errorf("error does not name the table it actually reached:\n%v", err)
		}
	})

	t.Run("the app-schema routing is accepted, so the assertion has not deleted it", func(t *testing.T) {
		// The other supported routing, and the reason the queries are not
		// simply qualified with identity.: on this connection the module is
		// correctly operating on the app's own tables.
		db := routingConn(t, baseDSN, "")

		if err := VerifySchemaRouting(ctx, db, "public"); err != nil {
			t.Fatalf("VerifySchemaRouting rejected the app-schema routing, which is the "+
				"shipped default of one consuming application: %v", err)
		}
	})

	t.Run("a search_path that reaches no identity tables at all is caught", func(t *testing.T) {
		routingExec(t, admin, `CREATE SCHEMA IF NOT EXISTS empty_ns`)
		db := routingConn(t, baseDSN, "empty_ns")

		err := VerifySchemaRouting(ctx, db, SchemaName)
		if err == nil {
			t.Fatal("VerifySchemaRouting accepted a connection on which no identity table resolves")
		}
		if !strings.Contains(err.Error(), "resolves to nothing") {
			t.Errorf("error does not report the unresolved names:\n%v", err)
		}
	})

	t.Run("a relation that merely wears a table's name is caught", func(t *testing.T) {
		// to_regclass resolves ANY relation, and so does the planner when it
		// reports "users is not a table". A sequence named users, first on the
		// search_path, resolves in a schema the check would otherwise accept.
		routingExec(t, admin,
			`DROP SCHEMA IF EXISTS decoy_ns CASCADE`,
			`CREATE SCHEMA decoy_ns`,
			`CREATE SEQUENCE decoy_ns.users`,
		)
		db := routingConn(t, baseDSN, "decoy_ns,"+SchemaName)

		err := VerifySchemaRouting(ctx, db, "decoy_ns")
		if err == nil {
			t.Fatal("VerifySchemaRouting accepted a sequence standing in for the users table")
		}
		if !strings.Contains(err.Error(), "not a table a repository can read or write") {
			t.Errorf("error does not explain the relation-kind rejection:\n%v", err)
		}
	})
}
