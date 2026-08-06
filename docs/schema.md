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

The runner takes a Postgres advisory lock (golang-migrate default), and the base
migrations use idempotent DDL (`CREATE … IF NOT EXISTS`, `ON CONFLICT DO
NOTHING`), so it is safe to run from two apps concurrently against the same
database (**detect-and-attach**): whichever app runs first creates the schema, and
the second one finds it already present and attaches. Note the safety comes from the
version table plus the advisory lock, not from the DDL alone — the later migrations
include statements that are not self-idempotent (see the exceptions table below).

---

## Tables

All tables live in the `identity` schema. UUID primary keys default to
`gen_random_uuid()` — except two that are supplied by the caller rather than generated:
`revoked_tokens.jti` (the JTI comes from the token being revoked) and
`org_quotas.organization_id` (a 1:1 FK to `organizations`).

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

> **Not created here: `notification_channels`.** `identity/notify`'s `ChannelRepository`
> reads and writes a `notification_channels` table, but **no migration in this module
> creates it** — the consuming app owns it, because notification delivery is an app
> concern layered on the shared identity store. An app that uses `identity/notify` must
> create the table itself with this exact shape: `id UUID`, `name`/`type`/
> `encrypted_target` `TEXT`, `events` `JSONB`, `enabled` `BOOLEAN`, `last_status`/
> `last_error` `TEXT`, and `last_sent_at`/`created_at`/`updated_at` `TIMESTAMPTZ`. See the
> package doc on `identity/notify/channel_repository.go` for the authoritative column list.
>
> Two tables in the list above are created by the migrations but have **no Go accessor in
> this module**: `org_quotas` and `system_settings`. They exist so both apps agree on the
> shape; each app queries them from its own data layer.

### Notable modelling choices

- **Hashed secrets only.** `api_keys` stores a hash and a short `key_prefix`
  (indexed by `idx_identity_api_keys_key_prefix` for fast lookup); the raw key is
  never persisted. OIDC client secrets are stored **verbatim** in
  `client_secret_encrypted` — `OIDCConfigRepository` performs no cryptography on that
  column, so a caller that wants encryption at rest must supply ciphertext (the
  repository does not own an encryption key). The column keeps its historical name.
  <br>
  This is a gap the module gives you the tool to close: **`identity/crypto`'s
  `TokenCipher`** is an AES-256-GCM authenticated-encryption helper built for exactly
  this (its own doc comment names OIDC client secrets as a target use case), with
  `NewTokenCipherWithPrevious` for key rotation. Seal before writing
  `ClientSecretCiphertext` and open after reading. The key stays with the host — that is
  the part this module deliberately does not own, and the reason the repository itself
  cannot do it for you.
- **API-key expiry is enforced in SQL, in one query.**
  `APIKeyRepository.GetAPIKeysByPrefix` — the lookup an authenticating host runs —
  filters `(expires_at IS NULL OR expires_at > NOW())`, so an expired key never reaches
  `auth.ValidateAPIKey`'s bcrypt comparison. The admin/listing lookups deliberately do
  **not** filter, so an operator can still see expired rows; never build an
  authentication path on those. The filter is pinned by
  `TestGetAPIKeysByPrefix_ExcludesExpired`, so removing it fails the test suite.
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
| `000002` | `000002_org_quota_and_identity_core_roles` | Adds `org_quotas` (per-org `max_members` / `max_api_keys`). Then **overwrites** the seeded role templates' `scopes` with identity-core scopes only, so the library stays app-agnostic — `admin` keeps the wildcard `admin`; `operator` gets `users:read`/`organizations:read`/`api_keys:*`/`audit:read`/`settings:read`; `analyst` gets `organizations:read`/`audit:read`; `viewer` gets `organizations:read`. |
| `000003` | `000003_registry_canonical_identity` | Reconciles the schema to the suite's canonical identity shape. Adds per-org IdP binding (`organizations.idp_type`, `idp_name`); converts `scopes` in place from `TEXT[]`/`TEXT` to `JSONB` on **three** tables — `role_templates`, `api_keys` and `oidc_config`; adds `api_keys.expiry_notification_sent_at`; and widens `oidc_config` to multi-provider (`name`, `provider_type`, `extra_config`, `created_by`, `updated_by`). Safe in place because these tables hold only seed data until an app cuts over (the `USING` clauses convert seeded values losslessly). |
| `000004` | `000004_drop_vestigial_is_active` | Drops `is_active` from `organizations`, `users`, and `api_keys`. An audit confirmed no Go code (models or store, in this library or either consuming app) ever read or wrote these columns — see [README.md](../README.md#notable-modelling-choices) — so the column was a silent no-op rather than a working kill-switch. `oidc_config.is_active` is untouched; it is genuinely used. |
| `000005` | `000005_oidc_config_single_active` | Enforces **at most one active OIDC config** at the database level. First deactivates every active row except the most recently updated one (`UPDATE … SET is_active = false … WHERE is_active AND id NOT IN (… ORDER BY updated_at DESC LIMIT 1)`), so the constraint can be created on existing data; then adds the partial unique index `idx_oidc_config_single_active ON identity.oidc_config (is_active) WHERE is_active`. This is the invariant `GetActiveOIDCConfig`/`ActivateOIDCConfig` rely on, previously enforced only in application code. |

The current version is `000005`.

### Where the "additive" rule has been broken, and why

Migrations must stay additive per
[CONTRIBUTING.md](../CONTRIBUTING.md#database-migrations). Four of the five above are
documented exceptions rather than precedents. Stating them explicitly matters: a reader
planning an upgrade needs to know which migrations can lock a table or reject data that
was previously valid.

| Version | Non-additive operation | Precondition it rests on |
| ------- | ---------------------- | ------------------------ |
| `000002` | Four data `UPDATE`s that rewrite `role_templates.scopes` wholesale. | Runs before any app has seeded its own domain scopes. An app that had already extended the four system templates would have those scopes **overwritten**; each app re-seeds at setup, which is why this is safe in practice. |
| `000003` | In-place `ALTER COLUMN … TYPE` on `role_templates.scopes`, `api_keys.scopes` and `oidc_config.scopes`. Takes a table lock and rewrites the column. | Those tables hold **only seed data until an app cuts over**. This precondition is not verifiable from inside this repository — it depends on consumer state. Verify it against every consumer before releasing a change like this, and prefer expand-and-contract (new column → backfill → swap) if any consumer may hold real data. |
| `000004` | Three `DROP COLUMN IF EXISTS`. | The dropped `is_active` columns were audited as never read or written by any consumer, so no row ever held a non-default value. |
| `000005` | A data `UPDATE` that deactivates rows, plus a `UNIQUE` index that can reject previously-valid data. | Only one OIDC config is ever meant to be active; the `UPDATE` exists precisely so the index can be created on a database that already violates the invariant. Losing "active" on the older rows is the intended repair, not collateral damage. |

### Down migrations

Each migration has a matching `.down.sql`. `000001`'s down drops every identity table but
deliberately **leaves the (now-empty) `identity` schema in place** — see the doc comment
on `RunMigrations` in `identity/db.go`, which spells out the same thing — because another
app may still be attached to it.

Two downs are **best-effort rather than exact reversals**, and both self-label as such:

- `000003`'s `TEXT[]`↔`JSONB` column-type round-trip is not guaranteed to restore the
  original values byte-for-byte.
- `000005` drops the unique index but does **not** resurrect the `is_active` values its
  up-migration cleared.

`000002` and `000004` do reverse exactly (`000004`'s `ADD COLUMN … DEFAULT true` restores
the original shape precisely, since no row could ever have held a non-default value).
None of this is a precedent: new migrations must still fully reverse.

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

For step-wise control there is `identity.RunMigrationSteps(db, n)`: a positive `n`
applies that many migrations, a negative `n` rolls back that many — e.g.
`RunMigrationSteps(db, -1)` undoes only the most recently applied migration,
rather than the whole schema the way `RunMigrations(db, "down")` does.

---

## See also

- [README.md](../README.md) — packages, the canonical identity model, schema
  routing, and usage examples.
- [docs/suite-coupling.md](suite-coupling.md) — the runtime coupling contract
  (manifest, negotiation, discovery) layered on top of the shared store.
