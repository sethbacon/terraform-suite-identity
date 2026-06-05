-- Reconcile the identity schema to the registry's canonical identity model
-- (the registry is the source of truth; the only per-app variance is the
-- role->scope mapping each app seeds onto role_templates).
--
-- These tables hold only seed data until an app cuts over to the identity
-- schema, so the in-place column type changes below are safe: the USING clauses
-- convert the seeded values losslessly.

-- organizations: per-organization IdP binding.
ALTER TABLE identity.organizations ADD COLUMN IF NOT EXISTS idp_type VARCHAR(50);
ALTER TABLE identity.organizations ADD COLUMN IF NOT EXISTS idp_name VARCHAR(255);

-- role_templates.scopes: TEXT[] -> JSONB (registry stores scopes as a JSON array).
ALTER TABLE identity.role_templates ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.role_templates ALTER COLUMN scopes TYPE JSONB USING to_jsonb(scopes);
ALTER TABLE identity.role_templates ALTER COLUMN scopes SET DEFAULT '[]'::jsonb;

-- api_keys.scopes: TEXT[] -> JSONB; add expiry-notification tracking.
ALTER TABLE identity.api_keys ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.api_keys ALTER COLUMN scopes TYPE JSONB USING to_jsonb(scopes);
ALTER TABLE identity.api_keys ALTER COLUMN scopes SET DEFAULT '[]'::jsonb;
ALTER TABLE identity.api_keys ADD COLUMN IF NOT EXISTS expiry_notification_sent_at TIMESTAMP;

-- oidc_config: registry shape (named, multi-provider, group-mapping extra_config,
-- audit columns) and scopes as a JSON array.
ALTER TABLE identity.oidc_config ADD COLUMN IF NOT EXISTS name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE identity.oidc_config ADD COLUMN IF NOT EXISTS provider_type VARCHAR(50) NOT NULL DEFAULT 'generic_oidc';
ALTER TABLE identity.oidc_config ADD COLUMN IF NOT EXISTS extra_config JSONB;
ALTER TABLE identity.oidc_config ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE identity.oidc_config ADD COLUMN IF NOT EXISTS updated_by UUID;
ALTER TABLE identity.oidc_config ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.oidc_config ALTER COLUMN scopes TYPE JSONB USING to_jsonb(string_to_array(scopes, ','));
ALTER TABLE identity.oidc_config ALTER COLUMN scopes SET DEFAULT '["openid","email","profile"]'::jsonb;
