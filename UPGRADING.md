# Upgrade notes

Operational guidance for releases that need an action beyond `go get`. Only
releases with such an action appear here; everything else is covered by
[CHANGELOG.md](CHANGELOG.md).

Both consuming applications call `identity.RunMigrations` at process **startup**,
so a migration in this module runs on a deploy, on the startup path, against a
live database. That is the reason a release that ships DDL gets an entry here.

---

## v0.23.0 — migration `000006_hot_path_indexes`

**Non-breaking.** No exported signature changed. Applying the release requires no
code change in a consuming application.

### What it does

Adds six indexes to the `identity` schema:

| Index | Table (column) | Why |
| --- | --- | --- |
| `idx_identity_audit_logs_org_created_at` | `audit_logs (organization_id, created_at DESC)` | The mandatory `AuditScope` predicate (v0.21.0) plus the audit page's `ORDER BY` |
| `idx_identity_organization_members_user_id` | `organization_members (user_id)` | Membership/scope resolution on every login and token mint |
| `idx_identity_organization_members_role_template_id` | `organization_members (role_template_id)` | `ON DELETE SET NULL` from `role_templates` |
| `idx_identity_api_keys_organization_id` | `api_keys (organization_id)` | `ListAPIKeysByOrganization`; `ON DELETE CASCADE` from `organizations` |
| `idx_identity_api_keys_user_id` | `api_keys (user_id)` | `ListAPIKeysByUser`; `ON DELETE SET NULL` from `users` |
| `idx_identity_revoked_tokens_user_id` | `revoked_tokens (user_id)` | `ON DELETE CASCADE` from `users`, on a table that grows with traffic |

### Action required if you have live audit volume

The migration uses plain `CREATE INDEX`, **not** `CREATE INDEX CONCURRENTLY`.
That is deliberate — golang-migrate sends each migration file to PostgreSQL as
one statement, which runs in an implicit transaction block, and `CONCURRENTLY`
is rejected outright there; and a `CONCURRENTLY` build that fails leaves an
`INVALID` index behind that `CREATE INDEX IF NOT EXISTS` then skips forever.

A plain `CREATE INDEX` takes a `SHARE` lock: reads continue, **writes to the
table block for the duration of the build**. On a new or small database that is
milliseconds. On a large existing `audit_logs` it is not, and the block lands on
your API's startup path.

If `identity.audit_logs` is large, build the indexes out of band **before**
deploying, using the same names. The migration's `IF NOT EXISTS` clauses then
find them already present and it becomes a no-op:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_org_created_at
    ON identity.audit_logs (organization_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_user_id
    ON identity.organization_members (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_role_template_id
    ON identity.organization_members (role_template_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_organization_id
    ON identity.api_keys (organization_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_user_id
    ON identity.api_keys (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_revoked_tokens_user_id
    ON identity.revoked_tokens (user_id);
```

Run each statement on its own connection, outside any transaction, then verify
none landed invalid:

```sql
SELECT c.relname
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
WHERE NOT i.indisvalid AND c.relname LIKE 'idx_identity_%';
```

Drop and rebuild any index that row set names.

### Rollback

`000006`'s down migration drops exactly these six indexes and nothing else. It
is index-only, so the rollback is complete rather than best-effort.

### Also in this release: the revocation denylist self-bounds

`TokenRepository.RevokeToken` now prunes expired rows from `revoked_tokens` as
part of the write that grows it — at most once an hour per process, in bounded
batches, keeping rows for one hour past the denied token's own expiry (clock
skew and verifier leeway), and never failing the revocation if the prune fails.

No wiring is required and nothing needs to be scheduled.
`CleanupExpiredRevocations` is unchanged and still available; a host that
already schedules it can keep doing so (it remains an immediate, ungraced sweep)
or drop its ticker.
