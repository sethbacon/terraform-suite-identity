-- Reverse the single-active-config partial unique index. The cleanup UPDATE
-- from the up migration is not reversible/needed to reverse — dropping the
-- index is sufficient for a down-migration; we do not attempt to resurrect
-- the deactivated rows' prior state.
DROP INDEX IF EXISTS identity.idx_oidc_config_single_active;
