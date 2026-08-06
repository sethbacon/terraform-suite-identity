-- Restore the pre-v0.25.0 delete-driven transitions.
--
-- BEST-EFFORT, and LOSSY in one direction, like 000003's and 000005's downs. It
-- is spelled out here rather than left to be discovered:
--
--   * Re-adding the foreign keys on audit_logs requires every organization_id and
--     user_id to resolve again. Any row whose organization or user was deleted
--     while this migration was applied CANNOT satisfy that, so the UPDATEs below
--     null those columns first -- which is the very re-homing this migration
--     exists to prevent. Rolling back therefore re-opens the leak for exactly
--     the history that was retained while it was applied.
--   * actor_email is dropped, and the addresses it retained for users who no
--     longer exist are not recoverable from anywhere else.
--
-- Roll forward if you can. If you must roll back, inventory the affected rows
-- first:
--
--   SELECT count(*) FROM identity.audit_logs al
--    WHERE al.organization_id IS NOT NULL
--      AND NOT EXISTS (SELECT 1 FROM identity.organizations o WHERE o.id = al.organization_id);

-- 1. Make the data satisfy the constraints again (lossy -- see above).
UPDATE identity.audit_logs al
   SET organization_id = NULL
 WHERE al.organization_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM identity.organizations o WHERE o.id = al.organization_id);

UPDATE identity.audit_logs al
   SET user_id = NULL
 WHERE al.user_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM identity.users u WHERE u.id = al.user_id);

-- 2. Drop the constraint this migration added, by the same name-independent
--    lookup the up migration uses.
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

-- 3. Re-create the original SET NULL foreign keys, with the names migration
--    000001 would have produced.
ALTER TABLE identity.audit_logs
    ADD CONSTRAINT audit_logs_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE SET NULL;

ALTER TABLE identity.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES identity.users(id) ON DELETE SET NULL;

ALTER TABLE identity.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES identity.users(id) ON DELETE SET NULL;

-- 4. Drop the denormalised actor.
ALTER TABLE identity.audit_logs DROP COLUMN IF EXISTS actor_email;
