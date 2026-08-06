# Upgrade notes

Operational guidance for releases that need an action beyond `go get`. Only
releases with such an action appear here; everything else is covered by
[CHANGELOG.md](CHANGELOG.md).

Both consuming applications call `identity.RunMigrations` at process **startup**,
so a migration in this module runs on a deploy, on the startup path, against a
live database. That is the reason a release that ships DDL gets an entry here.

---

## v0.24.0 — `store.ErrNotFound`: not-found is no longer silent

**BREAKING. No migration.** Every consuming application needs a code review pass
before upgrading — and, critically, **most of the affected call sites still
compile**.

### What changed

Three related contracts:

1. **Reads that miss now return an error wrapping `store.ErrNotFound`**, where they
   previously returned `(nil, nil)`.
2. **By-identifier `UPDATE`/`DELETE`s that match zero rows now return an error
   wrapping `store.ErrNotFound`**, where they previously returned `nil` (success).
3. **Bulk sweeps now return their affected-row count** — a signature change, so
   these are the only ones the compiler catches for you.

`models.OIDCConfig.GetScopes()` also gained an `error` return (it previously
discarded a JSON-unmarshal failure and fell back to the default scopes exactly as
if the column had been empty).

### Why it is breaking in a way the compiler will not tell you

`return nil, nil` becoming `return nil, ErrNotFound` changes no signature, and the
mutators already returned `error`. **A consumer that does**

```go
x, err := repo.GetThing(ctx, id)
if err != nil {
    c.JSON(http.StatusInternalServerError, ...)   // was: only reached on a real failure
    return
}
if x == nil {
    c.JSON(http.StatusNotFound, ...)              // now: DEAD CODE
    return
}
```

**still builds, and turns every previously-correct 404 into a 500.** The same
shape appears in existence probes (`GetUserByEmail` before creating a user,
`GetByName` before creating an organization, `GetMember` before adding a member),
where not-found is the HAPPY path — those become unconditional 500s.

### The migration, in order

**Step 1 — fix the compile errors.** These four signatures changed:

| Before | After |
| --- | --- |
| `APIKeyRepository.DeleteExpiredKeys(ctx) error` | `(ctx) (int64, error)` |
| `OrganizationRepository.RemoveAllMembershipsForUser(ctx, userID) error` | `(ctx, userID) (int64, error)` |
| `OIDCConfigRepository.DeactivateAllOIDCConfigs(ctx) error` | `(ctx) (int64, error)` |
| `TokenRepository.CleanupExpiredRevocations(ctx) error` | `(ctx) (int64, error)` |
| `models.OIDCConfig.GetScopes() []string` | `() ([]string, error)` |

`if err := repo.X(ctx); err != nil {` becomes `if _, err := repo.X(ctx); err != nil {`
(or keep the count and log it).

**Step 2 — grep for the dead nil branch.** Every site of the form
`if err != nil { … }` followed by `if value == nil { … }` needs the two branches
merged or reordered:

```go
x, err := repo.GetThing(ctx, id)
if errors.Is(err, store.ErrNotFound) {
    c.JSON(http.StatusNotFound, ...)
    return
}
if err != nil {
    c.JSON(http.StatusInternalServerError, ...)
    return
}
```

A site already written as `if err != nil || x == nil { … }` keeps working
unchanged — the collapsed check absorbs the new error.

**Step 3 — fix the existence probes.** Anywhere not-found is the SUCCESS case
("is this email free?", "is this name taken?", "is this user already a member?"),
invert the check:

```go
existing, err := repo.GetUserByEmail(ctx, email)
switch {
case err == nil:
    // taken
case errors.Is(err, store.ErrNotFound):
    // free — proceed
default:
    return err
}
```

**Step 4 — make the idempotent loops idempotent again.** SCIM/IdP reconciliation
and deprovisioning loops that call `RemoveMember`, `UpdateMemberRole` or
`RevokeAPIKey` over a set will now abort on the first already-applied element.
Treat `store.ErrNotFound` as "already in the desired state" and continue:

```go
if err := orgRepo.RemoveMember(ctx, orgID, userID); err != nil &&
    !errors.Is(err, store.ErrNotFound) {
    return err
}
```

**Step 5 — decide about repeat DELETEs.** A handler with no prior existence check
that deletes by id (users, organizations, notification channels) now returns an
error on the second call. Either pre-check, or map `store.ErrNotFound` to 404 (or
to 204 if you want the endpoint to stay idempotent).

### Accessors whose behaviour changed

Reads (`(nil, nil)` → `ErrNotFound`): `UserRepository.GetUserByID`,
`GetUserByEmail`, `GetUserByOIDCSub`, `GetUserWithOrgRoles`;
`OrganizationRepository.GetByID`, `GetByName`, `GetDefaultOrganization`,
`GetMember`, `GetMemberWithRole`; `APIKeyRepository.GetAPIKeyByHash`,
`GetAPIKeyByID` (and its `GetByID` alias); `OIDCConfigRepository.GetActiveOIDCConfig`,
`GetOIDCConfig`; `RoleTemplateRepository.GetRoleTemplate`, `GetRoleTemplateByName`
(and its `GetByID` alias); `AuditRepository.GetAuditLog`;
`notify.ChannelRepository.GetByID`, `Update`.

Mutations (`nil` on zero rows → `ErrNotFound`): `UserRepository.UpdateUser`,
`DeleteUser` (and the `Update`/`Delete` aliases); `APIKeyRepository.RevokeAPIKey`
(and `Delete`), `Update`, `UpdateLastUsed`, `MarkExpiryNotificationSent`;
`OrganizationRepository.RemoveMember`, `UpdateMemberRoleTemplate` (and
`UpdateMemberRole`/`UpdateMember`), `Update`, `Rename`, `Delete`;
`OIDCConfigRepository.DeleteOIDCConfig`, `UpdateOIDCConfigExtraConfig`,
`ActivateOIDCConfig`; `notify.ChannelRepository.Delete`, `RecordDelivery`.
`RoleTemplateRepository.UpdateRoleTemplate`/`DeleteRoleTemplate` already errored
on zero rows; their errors now WRAP `ErrNotFound`, so one `errors.Is` covers the
whole package.

`ActivateOIDCConfig` additionally **rolls back** on a miss. Previously, activating
a non-existent id committed the deactivate-all step on its own and returned `nil` —
a deployment silently lost SSO while the admin API reported success.

### What did NOT change

- List and search accessors still return an empty slice and a `nil` error.
- `CheckMembership` still returns `(false, nil, nil)` for a non-member, and
  `GetUserScopesForOrg` still returns an empty scope set. Both absorb the sentinel
  deliberately; both still surface a real database failure.
- `RevokeToken` is still idempotent (zero rows means "already revoked").
- No tenancy semantics changed. That is a separate release.

### Why this shipped first

A write that carries a tenant predicate and matches no row means "that row is not
yours". Without a distinguishable zero-row result, adding such a predicate would
**fail open**: the caller would be told the write succeeded precisely when the
guard stopped it. This release is what makes that guard meaningful.

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
