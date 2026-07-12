-- Enforce the "at most one active OIDC config" invariant at the database
-- level (issue #60). Previously only ActivateOIDCConfig's transaction kept
-- this true; CreateOIDCConfig could insert a second is_active=true row with
-- no transaction and no check, leaving which row GetActiveOIDCConfig returns
-- implementation-defined.

-- Data-safety cleanup: if any already-migrated database currently has more
-- than one is_active=true row, deactivate all but the most recently updated
-- one first, so the unique index below can be created.
UPDATE identity.oidc_config SET is_active = false, updated_at = NOW()
WHERE is_active = true AND id NOT IN (
    SELECT id FROM identity.oidc_config WHERE is_active = true ORDER BY updated_at DESC LIMIT 1
);

-- Partial unique index: only one row can have is_active=true at a time,
-- enforced by Postgres itself, not just application convention.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_config_single_active ON identity.oidc_config (is_active) WHERE is_active;
