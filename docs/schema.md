# Identity Schema

This library owns a dedicated, self-contained set of identity tables that the
Terraform tooling suite — the registry and the state manager — can **share**. The
migrations create everything under a Postgres schema named `identity` so the
identity store can sit alongside an app's own `public` schema in the **same
database** without colliding, and so two apps can resolve the *same* user,
organization, and API key.

The schema is delivered as embedded golang-migrate files
(`identity/migrations/*.sql`, embedded via `//go:embed` in `identity/db.go`) and
applied by `identity.RunMigrations(db, "up")`. There is no migration CLI in this
repo; consumers call the runner from their own startup path.

---

## Schema name and routing

The runner always creates and migrates the schema literally named **`identity`**
(`CREATE SCHEMA IF NOT EXISTS identity`; the migration SQL is qualified with
`identity.`). The data layer, by contrast, uses **unqualified** table names, so
*the connection decides the schema*: give the identity repositories a connection
whose `search_path` puts `identity` first to read/write the shared schema, or a
plain `public` connection to keep identity in the app's own schema. See
[README.md](../README.md#schema-routing) for the routing example.

> This library does not read environment variables. Whether an app enables the
> shared schema, and under what flag names, is the **consuming app's** concern —
> the registry, for example, gates it behind its own `TFR_IDENTITY_*` flags. This
> document describes only what the library's migrations create.

---

## The `identity_schema_migrations` version table

The runner is configured with its **own** migration version table —
`identity_schema_migrations` — distinct from any consuming app's migration table:

```go
// identity/db.go
const (
    identitySchemaName      = "identity"
    identityMigrationsTable = "identity_schema_migrations"
)

driver, _ := postgres.WithInstance(db, &postgres.Config{
    SchemaName:      identitySchemaName,
    MigrationsTable: identityMigrationsTable,
})
```

This isolation is what lets the identity migrations and an app's own migrations
coexist in one database: each tracks its own version independently. The migration
state is a single row (golang-migrate semantics) holding the highest applied
version and a `dirty` flag. Inspect it directly:

```sql
SELECT version, dirty FROM identity.identity_schema_migrations;
```

or from Go via `identity.GetMigrationVersion(db)`.

The runner takes a Postgres advisory lock (golang-migrate default) and the
migrations use idempotent DDL (`CREATE … IF NOT EXISTS`, `ON CONFLICT DO
NOTHING`), so it is safe to run from two apps concurrently against the same
database (**detect-and-attach**): whichever app runs first creates the schema, and
the second one finds it already present and attaches.

---

## Tables

All tables live in the `identity` schema. UUID primary keys default to
`gen_random_uuid()`.

| Table                   | Purpose |
| ----------------------- | ------- |
| `organizations`         | Tenancy unit. Unique `name`; optional per-org IdP binding (`idp_type`, `idp_name`). |
| `users`                 | A person. Unique `email`; optional unique `oidc_sub` linking the OIDC subject. |
| `role_templates`        | Named bundles of `scopes` granted to a member. System templates (`is_system`) are seeded; each app extends their scopes at setup. |
| `organization_members`  | Join of `users` ↔ `organizations` with an optional `role_template_id`. Unique per `(organization_id, user_id)`. |
| `api_keys`              | Per-org (optionally per-user) API key. Stores `key_hash` + `key_prefix` (never the raw key), `scopes`, optional `expires_at`. |
| `oidc_config`           | OIDC provider configuration: issuer, client id, encrypted client secret, redirect, scopes; multi-provider after migration 3 (`name`, `provider_type`, `extra_config`). |
| `audit_logs`            | Append-only audit trail: `action`, optional `resource_type`/`resource_id`, `ip_address`, JSONB `metadata`. |
| `revoked_tokens`        | JWT revocation list keyed by `jti`, with `expires_at` so expired entries can be pruned. |
| `org_quotas`            | Per-organization identity quotas (`max_members`, `max_api_keys`; `NULL` = unlimited). Identity-domain only. |
| `system_settings`       | Key/value settings (e.g. `setup_completed`). |

### Notable modelling choices

- **Hashed secrets only.** `api_keys` stores a hash and a short `key_prefix`
  (indexed by `idx_identity_api_keys_key_prefix` for fast lookup); the raw key is
  never persisted. OIDC client secrets are stored **verbatim** in
  `client_secret_encrypted` — the module performs no cryptography, so a caller
  that wants encryption at rest must supply ciphertext (it does not own the
  encryption key). The column keeps its historical name.
- **JWT revocation is separate.** Revoking a JWT writes to `revoked_tokens` (by
  `jti`); revoking an API key is a hard delete of the `api_keys` row. There is no
  soft-revoke flag on tokens.
- **Identity-only quotas.** `org_quotas` covers identity-domain resources
  (members, API keys). Consuming apps own their own domain quotas (sources,
  modules, …) in their own schemas — not here.
- **Cascade behavior.** Memberships and API keys cascade-delete with their
  organization; `api_keys.user_id` and the actor columns on `audit_logs`
  `SET NULL` on user deletion so the audit trail survives the user.
- **The default org is seeded.** Migration 1 inserts a `default` organization, the
  four system role templates, and `setup_completed=false`; migration 2 adds
  `org_quotas` and reconciles those templates to **identity-core scopes only**
  (app-agnostic) — each app then layers its own domain scopes on at setup.

---

## Migrations

Migrations are numbered, paired (`.up.sql` / `.down.sql`), and **additive within
a major version** — both apps consume this schema, so a destructive change would
break whichever app upgrades first. Never edit a released migration file; add a
new sequential pair instead.

| Version | File | What it does |
| ------- | ---- | ------------ |
| `000001` | `000001_identity_schema` | Creates the full base schema: `organizations`, `users`, `role_templates`, `organization_members`, `api_keys` (+ prefix index), `audit_logs` (+ created-at/user-id indexes), `oidc_config`, `system_settings`, `revoked_tokens` (+ expires-at index). Seeds the four system role templates (`admin`, `analyst`, `viewer`, `operator`), the `default` organization, and `setup_completed=false`. |
| `000002` | `000002_org_quota_and_identity_core_roles` | Adds `org_quotas` (per-org `max_members` / `max_api_keys`). Reconciles the seeded role templates to **identity-core scopes only** so the library stays app-agnostic — `admin` keeps the wildcard `admin`, and `operator`/`analyst`/`viewer` are trimmed to identity scopes (`users:read`, `organizations:read`, `api_keys:*`, `audit:read`, `settings:read`, etc.). |
| `000003` | `000003_registry_canonical_identity` | Reconciles the schema to the suite's canonical identity shape. Adds per-org IdP binding (`organizations.idp_type`, `idp_name`); converts `role_templates.scopes` and `api_keys.scopes` from `TEXT[]` to `JSONB`; adds `api_keys.expiry_notification_sent_at`; and widens `oidc_config` to multi-provider (`name`, `provider_type`, `extra_config`, `created_by`, `updated_by`) with `scopes` as a JSON array. Safe in place because these tables hold only seed data until an app cuts over (the `USING` clauses convert seeded values losslessly). |

The current version is `000003`. Each migration has a matching `.down.sql` that
fully reverses it (migration 1's down drops every table and the schema).

### Applying and inspecting

```go
import "github.com/sethbacon/terraform-suite-identity/identity"

// Apply (idempotent; advisory-locked; safe for detect-and-attach).
if err := identity.RunMigrations(db, "up"); err != nil {
    return err
}

// Current version / dirty flag.
version, dirty, err := identity.GetMigrationVersion(db)
```

`db` is a standard `*sql.DB` on the shared PostgreSQL database. `RunMigrations`
also accepts `"down"` to roll back; any other direction is rejected.

---

## See also

- [README.md](../README.md) — packages, the canonical identity model, schema
  routing, and usage examples.
- [docs/suite-coupling.md](suite-coupling.md) — the runtime coupling contract
  (manifest, negotiation, discovery) layered on top of the shared store.
