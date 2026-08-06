-- Reverse migration 000006 by dropping the indexes it created.
--
-- Index-only, so the rollback is complete rather than best-effort: no data was
-- migrated on the way up and none is lost on the way down. Dropping is safe at
-- any time — every query these serve still returns the same rows, just by
-- sequential scan.
--
-- DROP INDEX, not DROP INDEX CONCURRENTLY, for the same reason the up migration
-- uses plain CREATE INDEX: golang-migrate sends the whole file as one
-- statement, which PostgreSQL runs in an implicit transaction block, and the
-- CONCURRENTLY variants are rejected there. A plain DROP INDEX takes a brief
-- ACCESS EXCLUSIVE lock on the table; drop them out of band with
-- DROP INDEX CONCURRENTLY if that matters on a busy deployment.
DROP INDEX IF EXISTS identity.idx_identity_revoked_tokens_user_id;
DROP INDEX IF EXISTS identity.idx_identity_api_keys_user_id;
DROP INDEX IF EXISTS identity.idx_identity_api_keys_organization_id;
DROP INDEX IF EXISTS identity.idx_identity_organization_members_role_template_id;
DROP INDEX IF EXISTS identity.idx_identity_organization_members_user_id;
DROP INDEX IF EXISTS identity.idx_identity_audit_logs_org_created_at;
