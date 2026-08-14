# Platform administrators — the carrier

`identity/platformadmin` is the **mechanism** for "who administers this application".
The **table** is yours.

That split is the point. Identity is shared across the suite — one set of users, one set
of organizations, one membership fact. Authorization is per-application: the registry and
the state manager each decide what their own roles mean, and each decides who administers
*it*. So the grant row lives in **your** schema, next to your role definitions and your
audit log, and two applications sharing one identity store keep two independent
administrator populations. Only the mechanism is shared.

---

## What you must supply

| You supply | Why it is yours |
| --- | --- |
| **The table**, via `platformadmin.TableDDL(name)` in your own migration set | The library does not own your schema; see [Required table shape](#required-table-shape). |
| **A `Resolver`** — "does this user id still resolve?" | Only you know where your principals live: the same connection, another schema, or another database. |
| **An `AuditIntentWriter`** — a write on the mutation's own `*sql.Tx` | The library must not assume your audit destination. An outbox, a direct insert, anything transactional. |
| **The management surface and its authorization** | Who may grant and revoke is your policy. Registry gates it on the `admin` scope, alongside its other admin routes. |
| **A grant-target existence check** | Granting to an id that answers to nobody mints an orphan on purpose. `Carrier.Grant` does not resolve the target — your handler should, with the same `Resolver`, and refuse with a 404. |

---

## Required table shape

Do not transcribe this by hand. `platformadmin.TableDDL` returns the canonical statement,
this module's integration tests create the table from that exact statement and then drive
every carrier method against the result, and `TestTableDDLDeclaresExactlyTheColumnsTheStatementsAddress`
keeps the DDL, the startup assertion and the SQL projection from drifting apart.

```go
ddl, err := platformadmin.TableDDL("registry.platform_admins")
// CREATE TABLE IF NOT EXISTS "registry"."platform_admins" (
//     user_id     UUID        PRIMARY KEY,
//     granted_by  UUID,
//     granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
//     note        TEXT
// );
```

| Column | Requirement | What depends on it |
| --- | --- | --- |
| `user_id` | `UUID` (or `text`/`varchar`), **NOT NULL**, and a **non-partial unique index on exactly this column** | Bound by every statement. The unique index is the arbiter for `Grant`'s `ON CONFLICT (user_id) DO NOTHING`; without it *every* grant fails at write time. |
| `granted_by` | `UUID` (or `text`/`varchar`), nullable | Provenance. `NULL` is a value: a grant with no attributable actor — a backfill, or a first-boot bootstrap. |
| `granted_at` | `TIMESTAMPTZ`, **NOT NULL** | Ordering, and scanned into a non-pointer `time.Time`. `timestamp without time zone` silently discards the offset. |
| `note` | `TEXT` (or `varchar`), nullable | The operator's reason. |

Call `carrier.VerifyTable(ctx)` **once at startup**, on the same `*sql.DB` the carrier was
constructed over, and log what it returns. It checks the columns, the types, the
nullability and the unique index, and returns the **schema-qualified name the configured
name actually resolved to** — so a deployment that changes a `search_path`, or acquires a
second `platform_admins` in another schema, sees it in that line instead of discovering it
as an empty administrator list.

### No foreign keys — deliberate

The obvious definition is `user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE`
with `granted_by UUID REFERENCES users(id) ON DELETE SET NULL`. Those constraints cannot
hold across the topologies this suite supports. Your migration creates this table on **your**
connection, while identity data may live:

1. in the same schema as your tables — an FK would work;
2. in a shared `identity` schema your connection also reaches — an FK would work only until
   identity moved, and post-cutover users exist only in `identity.users`, so an FK to a
   pre-cutover copy would refuse their grant;
3. in a **separate database** — Postgres has no cross-database foreign keys at all.

Since (3) is supported, the constraint is not expressible in any deployment without making
the table's definition depend on a topology choice made elsewhere. `terraform-registry-backend`
reached this conclusion twice independently, in migrations `000046` and `000051`.

What the FKs would have bought is bounded and is paid for elsewhere. User ids are UUIDs and
are never reused, so a row left behind by a deleted user grants nothing to anybody — every
elevation path loads the principal first. What it *does* do is sit in the carrier looking
like an administrator, which is why the floor counts only grants that still resolve, and why
sweeping orphans belongs with the rest of your credential lifecycle.

---

## Wiring

```go
carrier, err := platformadmin.New(db, "registry.platform_admins")
if err != nil { return err }

resolved, err := carrier.VerifyTable(ctx)   // once, at startup
if err != nil { return err }
slog.Info("platform-admin carrier", "table", resolved)
```

**Spell the table name the same way in every process.** The floor lock is namespaced by the
name as given, so one process configured with `platform_admins` and another with
`registry.platform_admins` addresses one table under two different locks and the
serialisation between them is lost.

### The authorization path

```go
// USER SESSION — resolved on every request.
scopes, err := carrier.SessionScopes(ctx, user.ID, claims.Scopes)
if err != nil {
    // NOT a denial. An authority question that did not resolve must not be
    // served as a completed "no": that silently downgrades a platform
    // administrator to a 403 during exactly the incident in which they need
    // the admin surface. 500, and `scopes` is already stripped.
    return http.StatusInternalServerError
}

// API KEY — never elevated. There is nothing to elevate it with.
keyScopes := platformadmin.KeyScopes(apiKey.Scopes)
```

`SessionScopes` strips `auth.ScopeAdmin` **first, on every return path**, and re-adds it
only for a live carrier row. `admin` present in a token is a claim about the past; the
carrier is the only thing that makes it true now. That is what buys immediate revocation —
one indexed read on a table with a handful of rows, instead of a 24-hour session carrying
the highest privilege in the product for 24 hours after it was taken away.

`KeyScopes` takes no context, no connection and no principal, so it *cannot* consult the
carrier. A long-lived, often unattended CI credential must not inherit its owner's
authority, and that property is enforced by there being nothing to call rather than by
remembering not to call it. If a key needs to reach an admin-gated surface, give that
surface a scope of its own.

### Granting and revoking

```go
grant, err := carrier.Grant(ctx, targetID, &actorID, &note, myAuditWriter(...))
switch {
case errors.Is(err, platformadmin.ErrAlreadyPlatformAdmin): // 409 — the original
    // provenance is intact; a re-grant does not rewrite who first conferred it.
case errors.Is(err, platformadmin.ErrAuditIntentRequired):  // 500 — refused, unrecorded
}

floor := platformadmin.RequireAnotherExercisableAdmin(myResolver)

err = carrier.Serialize(ctx, func(ctx context.Context) error {
    _, err := carrier.Revoke(ctx, targetID, floor, myAuditWriter(...))
    return err
})
switch {
case errors.Is(err, platformadmin.ErrNotPlatformAdmin):    // 404 (also store.ErrNotFound)
case errors.Is(err, platformadmin.ErrLastPlatformAdmin):   // 409 — grant somebody first
case errors.Is(err, platformadmin.ErrIdentityUnavailable): // 500 — ask again later
case errors.Is(err, platformadmin.ErrNotSerialized):       // 500 — not attempted
}
```

Both arguments are **mandatory**. A privileged mutation with nowhere to record itself does
not happen, and a `Revoke` with no floor predicate is the one way the floor can be silently
absent. An application that genuinely wants no floor passes a predicate that says so, in a
line a reviewer can see.

---

## The three properties, and how each is kept

**1. The floor is never zero.** `Revoke` reads the carrier under `SELECT … FOR UPDATE` and
runs your predicate inside the same transaction as the `DELETE`. Two administrators revoking
each other concurrently serialise: the second one's read blocks, then sees a set with the
first's row already gone. Without the lock both would see the other still present, both
would pass, and the deployment would end with zero administrators — reachable by two
well-formed requests. `TestIntegrationUnserialisedRevocationsReachZero` reproduces exactly
that, permanently, so the guarded test cannot quietly stop exercising the hazard.

**2. An orphaned grant is not an administrator that remains.**
`RequireAnotherExercisableAdmin` counts only grants whose user still resolves. Counting rows
instead would let the last real administrator revoke themselves whenever a deleted
colleague's grant was still on the table. A resolver **failure** aborts rather than skipping:
treating an unreachable identity store as "this one does not count" turns an outage into the
lockout the floor exists to prevent. That is why `Resolver.UserExists` returns
`(bool, error)` and not `bool`.

**3. Serialisation beyond this table.** `Revoke`'s row lock orders revoke against revoke. It
does **not** reach a membership demotion, a user deletion or a GDPR erasure — writes on other
tables, possibly on another connection, that nonetheless reduce who can administer the
application. Run every authority-reducing write inside `carrier.Serialize` and they order
against each other too. The advisory-lock key is derived from your table name, so a second
application in the same database is not blocked by yours.

---

## Not covered by `identity.VerifySchemaRouting`

`VerifySchemaRouting` and `RepositoryTables()` cover the tables `identity/store` and
`identity/notify` name in SQL, because those resolve through `search_path` to tables this
module's migrations create. The carrier resolves to a table this module neither creates nor
names — you supply the name — so it is deliberately outside that contract.
`Carrier.VerifyTable` is its equivalent.
