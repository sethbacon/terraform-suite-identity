-- Reverse: re-add the vestigial is_active columns with their original default,
-- restoring the pre-migration schema shape. Nothing reads or writes these columns,
-- so this is a shape-only rollback (no data migration is possible or needed).
ALTER TABLE identity.organizations ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
ALTER TABLE identity.users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
ALTER TABLE identity.api_keys ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
