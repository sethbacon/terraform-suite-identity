-- Index the predicates this module actually emits on its hot paths, and the
-- foreign keys whose parent rows it deletes (issue #154).
--
-- Migration 000001 created four indexes and nothing has added one since. Two of
-- the columns below back a security control that v0.21.0 made MANDATORY:
-- AuditScope is a required parameter of every audit read accessor, so every
-- scoped list, by-id read and export now carries an
-- `organization_id = ANY($n)` / `IS NULL` predicate on the largest table in the
-- schema. Without a matching index the module made the deliberately-mandatory
-- control the most expensive query it emits, and an audit read whose cost
-- scales with the whole estate rather than with one tenant is the first thing
-- an operator is tempted to route around.
--
-- Each index below states the query (or the cascade) that requires it.

-- audit_logs: the mandatory AuditScope predicate, composite with the list
-- query's ORDER BY.
--
-- ListAuditLogs emits, after the guard in audit_repository.go:
--     ... WHERE 1=1 AND al.organization_id = ANY($1) ... ORDER BY al.created_at DESC LIMIT/OFFSET
-- and the same predicate on its COUNT; StreamAuditLogs emits it alongside a
-- created_at range.
--
-- created_at is the SECOND column rather than being left out because the sort
-- and the range are part of the same hot path. Measured on PostgreSQL 16 with
-- 40k rows in one organization and 20 in another, the scoped page query plans
-- as `Index Scan using idx_identity_audit_logs_org_created_at` + a sort of the
-- 20 matched rows; with a bare organization_id index the same rows still have
-- to be sorted, and with no index at all the query is a sequential scan of the
-- whole estate. Including created_at also keeps one tenant's rows contiguous in
-- the index, which is what makes StreamAuditLogs' created_at range a range scan
-- within the tenant instead of a filter over all of it. (The residual sort is
-- an artefact of the `= ANY($n)` array form AuditScope emits; PostgreSQL 17
-- and later can return that scan already ordered.)
--
-- It is deliberately NOT partial. PostgreSQL btree indexes DO index NULLs, so
-- the AuditScopeOrganizationsAndUnowned variant's `OR al.organization_id IS
-- NULL` branch is served by this same index — measured, it plans as a BitmapOr
-- of two Bitmap Index Scans over it. A `WHERE organization_id IS NOT NULL`
-- partial index would silently drop that branch back to a sequential scan.
--
-- It also gives identity.organizations' ON DELETE SET NULL cascade an index to
-- work with: deleting an organization currently scans all of audit_logs.
CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_org_created_at
    ON identity.audit_logs (organization_id, created_at DESC);

-- organization_members.user_id: the authorization-resolution predicate.
--
-- The table's only index on this column is the trailing half of
-- UNIQUE(organization_id, user_id), which a btree cannot seek on. Every
-- `WHERE om.user_id = $1` — GetUserMemberships, GetUserOrganizations,
-- ListUserOrganizations, GetUserWithOrgRoles, loadMembershipsForUsers
-- (`= ANY($1)`), RemoveAllMembershipsForUser — therefore scans the table. That
-- is the membership/scope resolution that runs on essentially every login and
-- token mint. It also indexes the ON DELETE CASCADE from identity.users.
CREATE INDEX IF NOT EXISTS idx_identity_organization_members_user_id
    ON identity.organization_members (user_id);

-- organization_members.role_template_id: no query filters on it, but
-- DeleteRoleTemplate is a shipped method and the column is ON DELETE SET NULL,
-- so deleting a role template scans the whole membership table. Same class of
-- defect as the two above (an unindexed referencing column), so it is closed
-- here rather than left as the one that got away.
CREATE INDEX IF NOT EXISTS idx_identity_organization_members_role_template_id
    ON identity.organization_members (role_template_id);

-- api_keys.organization_id / api_keys.user_id: ListAPIKeysByOrganization,
-- ListAPIKeysByUser and ListByUserAndOrganization filter on these with no index
-- at all (000001 indexes only key_prefix). Both are also referencing columns —
-- organization_id ON DELETE CASCADE, user_id ON DELETE SET NULL — so deleting
-- an organization or a user scans api_keys today.
CREATE INDEX IF NOT EXISTS idx_identity_api_keys_organization_id
    ON identity.api_keys (organization_id);
CREATE INDEX IF NOT EXISTS idx_identity_api_keys_user_id
    ON identity.api_keys (user_id);

-- revoked_tokens.user_id: never read, but it is ON DELETE CASCADE from
-- identity.users on a table that grows with every revocation, so deleting a
-- user scans the denylist. Unindexed-cascade on an append-only table is the
-- growth defect and the index defect meeting in one place.
CREATE INDEX IF NOT EXISTS idx_identity_revoked_tokens_user_id
    ON identity.revoked_tokens (user_id);

-- ---------------------------------------------------------------------------
-- OPERATIONAL NOTE FOR EXISTING DEPLOYMENTS WITH LIVE AUDIT VOLUME
-- ---------------------------------------------------------------------------
-- These are plain CREATE INDEX statements, NOT CREATE INDEX CONCURRENTLY, and
-- that is deliberate:
--
--   * golang-migrate's postgres driver sends each migration file to the server
--     as ONE ExecContext. A multi-statement simple query runs inside an
--     implicit transaction block, and CREATE INDEX CONCURRENTLY is rejected
--     outright there ("CREATE INDEX CONCURRENTLY cannot run inside a
--     transaction block"). The same applies to DROP INDEX CONCURRENTLY in the
--     down migration.
--   * Both consuming applications call identity.RunMigrations at process
--     startup. An online index build is not something to run on the startup
--     path, and a CONCURRENTLY build that fails leaves an INVALID index behind
--     that `CREATE INDEX IF NOT EXISTS` will then skip forever — a silent,
--     permanently-unused index is worse than no index.
--
-- A plain CREATE INDEX takes a SHARE lock on the table: reads continue, writes
-- (audit_logs INSERTs) block for the duration of the build. On a small or new
-- database that is milliseconds. On a large existing audit_logs it is not.
--
-- If you have live audit volume, build the indexes out of band BEFORE deploying
-- the release that runs this migration, using the SAME names — the
-- `IF NOT EXISTS` clauses above then find them already present and this
-- migration becomes a no-op:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_org_created_at
--       ON identity.audit_logs (organization_id, created_at DESC);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_user_id
--       ON identity.organization_members (user_id);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_role_template_id
--       ON identity.organization_members (role_template_id);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_organization_id
--       ON identity.api_keys (organization_id);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_user_id
--       ON identity.api_keys (user_id);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_revoked_tokens_user_id
--       ON identity.revoked_tokens (user_id);
--
-- Run each statement on its own connection, outside any transaction, and then
-- verify none landed INVALID:
--
--   SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
--   WHERE NOT i.indisvalid AND c.relname LIKE 'idx_identity_%';
--
-- Drop and rebuild any row that returns.
