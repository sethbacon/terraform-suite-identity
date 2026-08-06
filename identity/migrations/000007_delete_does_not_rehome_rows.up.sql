-- Stop a DELETE from re-homing a surviving row into a tenancy state that
-- already means something else (issue #142).
--
-- ---------------------------------------------------------------------------
-- THE DEFECT
-- ---------------------------------------------------------------------------
-- Three referencing columns were ON DELETE SET NULL, and on all three NULL was
-- NOT an inert "the parent went away" marker -- it was already a value the
-- readers interpret:
--
--   audit_logs.organization_id  NULL is the platform/unowned bucket.
--                               store.AuditScopeOrganizationsAndUnowned widens a
--                               read to `organization_id IS NULL` ON PURPOSE,
--                               because terraform-state-manager writes logins and
--                               state-file actions with no owning organization by
--                               design. So deleting organization A did not drop a
--                               reference: it PUBLISHED A's entire audit history
--                               -- actions, resource ids, IP addresses, JSONB
--                               metadata -- to every other tenant's admins, as
--                               rows the scope has no way to tell apart from
--                               genuinely platform-level ones.
--
--   audit_logs.user_id          NULL means "no actor" (a system action). Deleting
--                               a user rewrote their actions into the shape a
--                               system action has, destroying attribution at the
--                               exact moment -- account removal -- when the audit
--                               trail's non-repudiation value is what is being
--                               relied on.
--
--   api_keys.user_id            NULL means "organization SERVICE credential".
--                               terraform-registry's namespace authorizer reads a
--                               NULL user_id key as an org service credential and
--                               exempts it from any membership check, so deleting
--                               a user silently PROMOTED their personal keys into
--                               unattributable, permanently valid organization
--                               credentials rather than revoking them.
--
-- The fourth SET NULL in the schema, organization_members.role_template_id, is
-- deliberately LEFT ALONE. NULL there means "no scopes at all" -- the membership
-- projections COALESCE rt.scopes to '[]'::jsonb -- which is strictly LESS
-- authority and is exactly what UpdateMemberRoleTemplate(nil) sets on purpose.
-- The manufactured state carries no second meaning, so it is not a member of
-- this class. (identity/store/delete_tenancy_integration_test.go pins that
-- reading, so the verdict fails a test if it ever stops being true.)
--
-- ---------------------------------------------------------------------------
-- WHY THE FOREIGN KEYS ON audit_logs GO AWAY ENTIRELY
-- ---------------------------------------------------------------------------
-- audit_logs is a HISTORICAL RECORD, not a live reference. Its user_id and
-- organization_id state who acted and for which organization AT THE TIME OF THE
-- EVENT. Every ON DELETE action a foreign key can offer is wrong for that:
--
--   SET NULL     re-homes the row into a state that means something else -- the
--                defect above.
--   SET DEFAULT  the same defect, into a shared bucket instead of the NULL one.
--   CASCADE      destroys the evidence. Deleting an organization (or a user)
--                would erase the record of what it did, which is precisely what
--                an audit trail exists to prevent.
--   RESTRICT /   makes the record's own subject undeletable, or forces an
--   NO ACTION    archive/purge step before every organization delete -- and since
--                every real organization has audit history, the practical
--                outcome is that operators purge, converting a confidentiality
--                leak into the destruction of the trail.
--
-- Keeping the value and dropping the constraint is the only option that retains
-- the history, keeps it attributed, and moves nothing. A deleted organization's
-- rows keep its id, so no live principal's membership can match them: they fall
-- out of every AuditScopeOrganizations / AuditScopeOrganizationsAndUnowned read
-- and remain readable only through the explicit, greppable
-- AuditScopeAllOrganizations() -- which is the correct audience for the history
-- of an organization that no longer exists. No read predicate changes; NULL
-- regains its single meaning, "the writer asserted no owner".
--
-- What is given up is write-time existence checking, and it was never a security
-- control: the constraint accepted ANY organization id that existed, so it never
-- stopped a caller from stamping another tenant's id. It only rejected ids that
-- exist nowhere, and a row carrying one of those matches no scope at all -- it is
-- invisible, which is the fail-closed direction.
--
-- CONSUMER NOTE: a caller that RELIED on the insert failing must now decide
-- explicitly. terraform-state-manager's /audit/ingest degrades a federated entry
-- by nulling the actor columns when CreateAuditLog returns an error; that error
-- will no longer occur, so an unresolvable sibling id is now stored as written
-- and is platform-readable only. See UPGRADING.md.
--
-- ---------------------------------------------------------------------------
-- WHY api_keys GOES TO CASCADE INSTEAD
-- ---------------------------------------------------------------------------
-- An API key is LIVE AUTHORITY, not a record. A credential must not outlive the
-- principal it belongs to, and it must never change authority CLASS on its way
-- out. CASCADE removes it; nothing is re-homed, and the NULL user_id shape stays
-- reserved for keys created that way deliberately. Both consuming applications
-- already sweep a user's credentials before deleting the user; this makes the
-- database fail closed on its own if that sweep is skipped, fails, or is
-- bypassed by raw SQL. (terraform-registry's own legacy schema already declared
-- ON DELETE CASCADE here; the identity schema was the outlier.)
--
-- ---------------------------------------------------------------------------
-- EXISTING DATA
-- ---------------------------------------------------------------------------
-- This migration CANNOT repair rows that were already re-homed. An audit row
-- whose organization_id is already NULL is indistinguishable from one written
-- unowned on purpose, and a NULL-user_id api_keys row is indistinguishable from
-- a real service credential. Both are a deploy-time inventory step, not
-- something DDL can decide -- UPGRADING.md carries the queries.

-- ---------------------------------------------------------------------------
-- 1. Drop the delete-driven transitions.
-- ---------------------------------------------------------------------------
-- Located through pg_constraint rather than by their conventional
-- "<table>_<column>_fkey" names: the names are server-generated, and a migration
-- that silently no-ops because a constraint was named differently would leave
-- the defect in place while reporting success.
DO $$
DECLARE
    target record;
    con    record;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES
            ('audit_logs', 'organization_id'),
            ('audit_logs', 'user_id'),
            ('api_keys',   'user_id')
        ) AS t(tbl, col)
    LOOP
        FOR con IN
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class rel      ON rel.oid = c.conrelid
            JOIN pg_namespace nsp  ON nsp.oid = rel.relnamespace
            JOIN pg_attribute att  ON att.attrelid = rel.oid AND att.attnum = c.conkey[1]
            WHERE nsp.nspname = 'identity'
              AND rel.relname = target.tbl
              AND c.contype = 'f'
              AND array_length(c.conkey, 1) = 1
              AND att.attname = target.col
        LOOP
            EXECUTE format('ALTER TABLE identity.%I DROP CONSTRAINT %I', target.tbl, con.conname);
        END LOOP;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. api_keys.user_id: revoke with the principal, never outlive it.
-- ---------------------------------------------------------------------------
ALTER TABLE identity.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES identity.users(id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- 3. Denormalise the actor, so attribution does not depend on a live users row.
-- ---------------------------------------------------------------------------
-- Retaining user_id (step 1) keeps the row attributed to a stable identifier,
-- but once the users row is gone nothing can resolve that uuid to a person --
-- including for the rows written while the user still existed. audit_logs.
-- actor_email is the address as it stood when the event was recorded; it is
-- stamped by AuditRepository.CreateAuditLog and never updated afterwards, which
-- is the point: it is what was true at the time, not a view of current state.
ALTER TABLE identity.audit_logs ADD COLUMN IF NOT EXISTS actor_email VARCHAR(255);

-- Backfill every row whose actor still exists. Rows whose actor was already
-- deleted stay NULL -- that attribution is gone and this migration will not
-- invent it.
UPDATE identity.audit_logs al
   SET actor_email = u.email
  FROM identity.users u
 WHERE al.user_id = u.id
   AND al.actor_email IS NULL;
