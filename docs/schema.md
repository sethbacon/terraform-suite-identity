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

### Assert the routing at startup

Because the connection decides, the connection can be wrong, and the interesting
failure is not the loud one. `relation "users" does not exist` announces itself.
The failure that does not is the one both consuming applications can reach: they
have identity-**shaped** tables of their own (`public.users`,
`public.organizations`, `public.api_keys`, `public.audit_logs`, …) in the same
database as `identity.*`, so a misordered `search_path` routes authentication
reads and provisioning writes to the legacy tables and **succeeds** — same names,
compatible columns, no error, and a split-brain identity store.

`identity.VerifySchemaRouting` turns that into a startup failure. Call it once,
on the **same pool the repositories are constructed over**, naming the schema the
deployment intends:

```go
// Shared identity schema (pool carries search_path=identity,public).
if err := identity.VerifySchemaRouting(ctx, identityDB, identity.SchemaName); err != nil {
    return err
}

// App-owned identity tables (plain pool; the shared schema is not enabled).
if err := identity.VerifySchemaRouting(ctx, identityDB, "public"); err != nil {
    return err
}
```

It resolves every table in `identity.RepositoryTables()` through `to_regclass` on
one borrowed connection — the same resolution the repositories' own SQL performs
— and fails when any of them lands somewhere other than the named schema,
resolves to nothing, or resolves to a relation that is not a table. The schema is
a parameter rather than an assumption because **both** routings are genuinely
supported; only the consumer knows which one it configured.

`identity.ResolveRouting(ctx, db)` returns the same picture without failing (the
connection's `search_path` and the schema each table resolved to), which is worth
logging at startup.

Do **not** point either function at the migration pool: the migrations are
schema-qualified and do not care about `search_path`, so a consumer that migrates
on a plain connection is correct to do so.

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

### Assert the version at startup

Reading the version is only half of it: nothing told a consumer what to compare
it against. This module's repositories address post-base columns
**unconditionally** — no capability probe, no fallback, no version branch — so
the migration chain is a hard precondition, and a consumer that stops short of it
starts cleanly and then fails on live traffic.

`identity` **requires identity migration `000008`** or later. `RequiredSchemaVersion`
is that number, `SchemaRequirements()` is the list of columns behind it, and
`VerifySchemaVersion` is the check:

```go
// Refuse to serve rather than fail every audited request.
if err := identity.VerifySchemaVersion(ctx, identityDB); err != nil {
    return err
}
```

It fails closed on a chain that has never been applied, a chain below the
required version, a chain marked `dirty`, and a version it cannot read; the error
names the missing columns and the migration that adds each one. `UnmetSchemaRequirements(v)`
returns the same list for an arbitrary version, for a consumer building its own
readiness payload.

| Column | Added by | Read/written by |
| ------ | -------- | --------------- |
| `organizations.idp_type`, `organizations.idp_name` | `000003` | `store.OrganizationRepository` |
| `oidc_config.name`, `provider_type`, `extra_config`, `created_by`, `updated_by` | `000003` | `store.OIDCConfigRepository` |
| `api_keys.expiry_notification_sent_at` | `000003` | `store.APIKeyRepository` |
| `audit_logs.actor_email` | `000007` | `store.AuditRepository.CreateAuditLog` |

The last row is why the check exists. `CreateAuditLog` writes `actor_email` on
every audited request; against a `000006` schema every one of them returns
SQLSTATE `42703`, at request time, in a process whose startup log already said
migrations completed — about the **app's own** chain, which is a different chain.
A consuming app reporting only its own migration version is not reporting this
one.

`VerifySchemaVersion` and `VerifySchemaRouting` answer neighbouring questions and
neither implies the other: the first asks whether the identity chain has been
applied far enough, the second asks whether the connection reaches the tables
that chain created. Call both.

A consumer that calls `identity.RunMigrations(db, "up")` during startup satisfies
the version check by construction and may still call it — the chain is at head
afterwards, so it costs one round trip. A consumer that migrates out of band, or
behind a feature flag, is the case it exists for.

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
| `audit_logs`            | Append-only audit trail: `action`, optional `resource_type`/`resource_id`, `ip_address`, JSONB `metadata`, plus `actor_email` (the acting user's address as it stood at write time). `user_id`/`organization_id` are historical values, **not** foreign keys — see "Delete behavior" below. |
| `revoked_tokens`        | JWT revocation list keyed by `jti`, with `expires_at` so expired entries can be pruned. |
| `org_quotas`            | Per-organization identity quotas (`max_members`, `max_api_keys`; `NULL` = unlimited). Identity-domain only. |
| `system_settings`       | Key/value settings (e.g. `setup_completed`). |

> **Not created here: `notification_channels`.** `identity/notify`'s `ChannelRepository`
> reads and writes a `notification_channels` table, but **no migration in this module
> creates it** — the consuming app owns it, because notification delivery is an app
> concern layered on the shared identity store. That is a decision, not an oversight, and
> it is pinned by a test (`TestNoMigrationCreatesNotificationChannels`): both consuming
> applications already hold live rows in their own `public.notification_channels`, so a
> migration here would create a **second, empty** `identity.notification_channels` and
> every `identity`-first connection would silently re-point to it — same statement, no
> error, no rows. Moving rows across schemas is a consumer deploy step against a database
> this module does not own.
>
> The contract is executable rather than prose. **`notify.ChannelTableDDL`** is the
> canonical `CREATE TABLE` statement — apply it from the consuming app's own migration set
> — and this module's integration tests run that exact statement and then drive every
> `ChannelRepository` method against the result, so the definition cannot drift from the
> code that uses it. **`notify.VerifyChannelTable(ctx, db)`** asserts at startup that the
> table exists with the columns, types and nullability the statements require, and returns
> the schema-qualified name it resolved to — log it; that name is what makes a re-point
> visible. See [UPGRADING.md](../UPGRADING.md) for the consumer-side steps and their order.
>
> **`organization_id` on that table is optional, and deliberately so.** The two consumers do
> not agree about it and both are right: terraform-state-manager partitions notification
> channels by organization (a channel's `encrypted_target` is a webhook URL anyone holding it
> can post to, so cross-tenant enumeration is a real leak), while terraform-registry's
> channels are platform-level destinations for `module_published` and `cve_detected`. A
> predicate baked into the statements would therefore fail the second consumer at
> `column "organization_id" does not exist`, so the column is absent from `ChannelTableDDL`
> and absent from what `VerifyChannelTable` requires — a guard test keeps it out of both.
> An app that does partition them adds the column itself, asserts it with
> `notify.VerifyChannelOrganizationColumn(ctx, db)`, and opts in per call with
> `notify.WithOrgScope(scope)`. The optionality is only about whether the COLUMN exists:
> once a scope is passed, it is an `identity/store` `OrgScope` and keeps every fail-closed
> semantic that type has, including a zero value that selects nothing.
>
> Two tables in the list above are created by the migrations but have **no Go accessor in
> this module**: `org_quotas` and `system_settings`. They exist so both apps agree on the
> shape; each app queries them from its own data layer — and therefore on its own
> connection, which is why they are not in `identity.RepositoryTables()` and not covered by
> `VerifySchemaRouting`. Note that a consuming app with its own `public.system_settings` of
> a different shape has, on an `identity`-first connection, the same unqualified-name
> hazard for **its** queries that `VerifySchemaRouting` closes for this module's; resolve
> those from a connection whose `search_path` reaches the table you mean.

> **Not created here either: the audit outbox and its constraint trigger.**
> `identity/auditoutbox` ships the transactional audit outbox as **mechanism**, and no
> migration in this module creates a single object for it. The outbox has to sit beside
> the mutation it audits — on the app's connection, in the app's schema — and under the
> identity model ([issue #206](https://github.com/sethbacon/terraform-suite-identity/issues/206))
> `audit_logs` becomes per-app as well: each app records the actions taken in it. A
> migration here would create tables in the wrong database as often as not.
>
> So the app owns the objects and this module owns their shape, rendered rather than
> transcribed. **`auditoutbox.OutboxDDL(table)`** emits the outbox table, its three
> partial indexes and the same-transaction assertion function;
> **`auditoutbox.TriggerSpec{…}.DDL()`** emits the `DEFERRABLE INITIALLY DEFERRED`
> constraint trigger that refuses, at COMMIT, any mutation of a guarded table whose
> transaction did not also write a matching intent. `OutboxDropDDL` and
> `TriggerSpec.DropDDL` are the down migrations — **drop the trigger before the outbox
> table it reads**, or every mutation fails at commit with a missing relation instead of a
> clean refusal. This module's integration tests execute the rendered statements and then
> drive the whole delivery path against the result, so the DDL cannot drift from the code
> that uses it.
>
> Nothing is rendered for the destination `audit_logs`: it is the app's existing table.
> The only requirement is that `id` is the primary key or carries a UNIQUE index, which is
> what makes an at-least-once redelivery a no-op rather than a duplicate entry. The
> sink discovers the rest of the shape by probing the connection, so a destination that
> predates `actor_email` (identity migration `000007`) receives the record without it
> instead of rejecting every delivery — the failure
> [registry #864](https://github.com/sethbacon/terraform-registry-backend/issues/864)
> describes. Call `Outbox.Verify` and `TableSink.Verify` at startup and log the
> schema-qualified names they return, for the same reason `VerifyChannelTable`'s name is
> worth logging.

### Which tables are organization-owned, and how that is enforced

Four tables carry (or are) an organization identity, and every accessor that
reads or mutates one of their rows takes a required `store.OrgScope` parameter
whose zero value denies everything (v0.25.0; `AuditScope` for `audit_logs` alone
since v0.21.0):

| Table | How the row's owner is expressed | Predicate emitted |
| --- | --- | --- |
| `organizations` | the row **is** the tenant | `id = ANY($n)` |
| `organization_members` | `organization_id` (NOT NULL) | `organization_id = ANY($n)` |
| `api_keys` | `organization_id` (NOT NULL) | `organization_id = ANY($n)` |
| `audit_logs` | `organization_id` (NULLABLE — a NULL row is platform-level) | `organization_id = ANY($n)`, plus `OR IS NULL` for the orgs+unowned variant |
| `users` | **no owning organization** — derived through `organization_members` | `EXISTS (SELECT 1 FROM organization_members osm WHERE osm.user_id = … AND osm.organization_id = ANY($n))` |

The predicate is applied in SQL, before any caller-supplied filter, so no filter
combination can produce an unscoped query; an out-of-scope target is reported as
`store.ErrNotFound` on every axis, which is why v0.24.0's sentinel is a
precondition for this control rather than an unrelated change. The remaining
tables — `role_templates`, `oidc_config`, `system_settings`, `revoked_tokens`,
`org_quotas` — are either platform-wide configuration or keyed on a user rather
than an organization, and carry no scope parameter.

Accessors deliberately left unscoped are marked `UNSCOPED BY DESIGN` in their doc
comment with the reason; the reasons are authority derivation (the accessors that
COMPUTE a scope), authentication bookkeeping, unattended maintenance, bootstrap,
and the two create axes with no owning organization to check against.

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
- **Delete behavior — a delete never re-homes a row.** Memberships and API keys
  cascade-delete with their organization. Beyond that, each referencing column is
  decided by what a `NULL` in it would *mean*, because on this schema `NULL` is
  rarely inert (migration `000007`, issue #142):
  - `audit_logs.user_id` / `audit_logs.organization_id` carry **no foreign key at
    all**. An audit row is a historical record of who acted and for which
    organization *at the time*, not a live reference, so deleting either parent
    leaves the values in place. The history is retained and stays attributed; a
    deleted organization's rows match no member's scope and are readable only
    through the explicit `AuditScopeAllOrganizations()`. `NULL` therefore has one
    meaning on each column — *the writer asserted no actor / no owning
    organization* — and cannot be manufactured by a delete. (`SET NULL` would
    re-home the row into the platform/unowned bucket that
    `AuditScopeOrganizationsAndUnowned` deliberately admits; `CASCADE` would
    destroy the evidence; `RESTRICT` would make the record's own subject
    undeletable.)
  - `audit_logs.actor_email` denormalises the actor's address at write time, so
    the trail stays resolvable to a person after the `users` row is gone.
  - `api_keys.user_id` is `ON DELETE CASCADE`. A credential is live authority,
    not a record: it must not outlive its principal, and it must never change
    authority *class* on the way out — a `NULL` `user_id` is the
    organization-service-credential shape, which consuming apps exempt from
    membership checks.
  - `organization_members.role_template_id` keeps `ON DELETE SET NULL`. `NULL`
    there means *no scopes at all* (the membership projections `COALESCE`
    `rt.scopes` to `'[]'`), which is strictly less authority and is exactly what
    `UpdateMemberRoleTemplate(nil)` sets deliberately, so the manufactured state
    carries no second meaning.
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
| `000006` | `000006_hot_path_indexes` | Adds indexes for the query shapes the module now forces on every caller. The tenant scope (`AuditScope`, renamed `OrgScope` in v0.25.0) became a required parameter in v0.21.0, so every audit read carries an `organization_id` predicate that had no supporting index: this adds the composite `(organization_id, created_at DESC)` covering both the list/count and export-stream shapes. Also indexes `organization_members(user_id)` (previously only the trailing column of a unique, so unseekable — every membership resolution on the auth path depends on it), `api_keys(user_id)` and `api_keys(organization_id)`, and the two unindexed referencing columns whose parents the module deletes: `organization_members(role_template_id)` (SET NULL) and `revoked_tokens(user_id)` (CASCADE). Index-only and fully reversible. |

| `000007` | `000007_delete_does_not_rehome_rows` | Stops a `DELETE` from moving a surviving row into a state that already means something else (issue #142). Drops the foreign keys on `audit_logs.user_id` and `audit_logs.organization_id` — those columns are a historical record, not live references, and every `ON DELETE` action available to a foreign key is wrong for one (see "Delete behavior" above). Changes `api_keys.user_id` from `SET NULL` to **`ON DELETE CASCADE`**, so deleting a user revokes their personal keys instead of promoting them into the org-service-credential shape. Adds `audit_logs.actor_email` (denormalised actor address, stamped by `CreateAuditLog`) and backfills it for every row whose user still exists. `organization_members.role_template_id` is deliberately untouched. |
| `000008` | `000008_notify_dedup_claims` | Adds `notify_dedup_claims` (`dedup_key TEXT PRIMARY KEY`, `claimed_at TIMESTAMPTZ`), backing `Notifier.Notify`'s optional `Event.DedupKey` (issue #157): an atomic, TTL-bounded claim so a logical occurrence delivered by one caller — a sibling replica, or a periodic trigger that independently rediscovers the same fact — is not redelivered to every configured channel a second time. No expiry sweep; see the migration's own comment for why. |

The current version is `000008`.

### Where the "additive" rule has been broken, and why

Migrations must stay additive per
[CONTRIBUTING.md](../CONTRIBUTING.md#database-migrations). Five of the six above are
documented exceptions rather than precedents. Stating them explicitly matters: a reader
planning an upgrade needs to know which migrations can lock a table or reject data that
was previously valid.

| Version | Non-additive operation | Precondition it rests on |
| ------- | ---------------------- | ------------------------ |
| `000002` | Four data `UPDATE`s that rewrite `role_templates.scopes` wholesale. | Runs before any app has seeded its own domain scopes. An app that had already extended the four system templates would have those scopes **overwritten**; each app re-seeds at setup, which is why this is safe in practice. |
| `000003` | In-place `ALTER COLUMN … TYPE` on `role_templates.scopes`, `api_keys.scopes` and `oidc_config.scopes`. Takes a table lock and rewrites the column. | Those tables hold **only seed data until an app cuts over**. This precondition is not verifiable from inside this repository — it depends on consumer state. Verify it against every consumer before releasing a change like this, and prefer expand-and-contract (new column → backfill → swap) if any consumer may hold real data. |
| `000004` | Three `DROP COLUMN IF EXISTS`. | The dropped `is_active` columns were audited as never read or written by any consumer, so no row ever held a non-default value. |
| `000005` | A data `UPDATE` that deactivates rows, plus a `UNIQUE` index that can reject previously-valid data. | Only one OIDC config is ever meant to be active; the `UPDATE` exists precisely so the index can be created on a database that already violates the invariant. Losing "active" on the older rows is the intended repair, not collateral damage. |
| `000007` | Drops two foreign keys, replaces a third with a stricter `ON DELETE` action, and thereby changes what a `DELETE` on `organizations`/`users` does to rows a consumer is holding. | The old behaviour was the defect: the `SET NULL` actions moved surviving rows into states (`unowned` audit row, org service credential) that already meant something else, and no reader could tell the manufactured state from the deliberate one. The migration cannot repair rows already in that state — see [UPGRADING.md](../UPGRADING.md) for the inventory queries and the two consumer-side changes it requires. |

### Down migrations

Each migration has a matching `.down.sql`. `000001`'s down drops every identity table but
deliberately **leaves the (now-empty) `identity` schema in place** — see the doc comment
on `RunMigrations` in `identity/db.go`, which spells out the same thing — because another
app may still be attached to it.

Three downs are **best-effort rather than exact reversals**, and all three self-label as
such:

- `000003`'s `TEXT[]`↔`JSONB` column-type round-trip is not guaranteed to restore the
  original values byte-for-byte.
- `000005` drops the unique index but does **not** resurrect the `is_active` values its
  up-migration cleared.
- `000007` must null every `audit_logs.user_id` / `organization_id` whose parent row was
  deleted while it was applied — the old foreign keys cannot be re-created otherwise —
  so rolling it back re-opens the leak for exactly the history it was retaining, and
  drops the `actor_email` addresses of users who no longer exist. Roll forward if you
  can; the down migration carries the inventory query for deciding.

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
