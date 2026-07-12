-- Drop the vestigial is_active columns on organizations, users, and api_keys.
--
-- These columns are never read or written by any Go code (see models/organization.go,
-- models/user.go, models/api_key.go): access/revocation for these three entities is
-- modeled entirely by hard delete / membership removal, not a DB-level active flag.
-- Left in place, the columns are a silent no-op that could mislead an operator into
-- believing a raw `UPDATE ... SET is_active = false` disables/revokes something.
--
-- (identity.oidc_config.is_active is unrelated and out of scope: it is actively read
-- and written via dedicated Activate/Deactivate methods and is left untouched.)
ALTER TABLE identity.organizations DROP COLUMN IF EXISTS is_active;
ALTER TABLE identity.users DROP COLUMN IF EXISTS is_active;
ALTER TABLE identity.api_keys DROP COLUMN IF EXISTS is_active;
