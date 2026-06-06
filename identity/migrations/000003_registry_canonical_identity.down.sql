-- Reverse the registry-canonical reconciliation (best-effort).

-- Helper: PostgreSQL forbids bare subqueries in ALTER COLUMN ... USING, but
-- allows IMMUTABLE function calls. This converts a JSONB array to TEXT[].
CREATE OR REPLACE FUNCTION _identity_jsonb_to_text_array(j jsonb)
    RETURNS text[] LANGUAGE sql IMMUTABLE AS
$$ SELECT ARRAY(SELECT jsonb_array_elements_text(coalesce(j, '[]'::jsonb))) $$;

-- oidc_config: drop registry-shape columns; scopes JSONB -> comma-separated TEXT.
ALTER TABLE identity.oidc_config ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.oidc_config ALTER COLUMN scopes TYPE TEXT
    USING array_to_string(_identity_jsonb_to_text_array(scopes), ',');
ALTER TABLE identity.oidc_config ALTER COLUMN scopes SET DEFAULT 'openid,email,profile';
ALTER TABLE identity.oidc_config DROP COLUMN IF EXISTS updated_by;
ALTER TABLE identity.oidc_config DROP COLUMN IF EXISTS created_by;
ALTER TABLE identity.oidc_config DROP COLUMN IF EXISTS extra_config;
ALTER TABLE identity.oidc_config DROP COLUMN IF EXISTS provider_type;
ALTER TABLE identity.oidc_config DROP COLUMN IF EXISTS name;

-- api_keys: drop expiry-notification; scopes JSONB -> TEXT[].
ALTER TABLE identity.api_keys DROP COLUMN IF EXISTS expiry_notification_sent_at;
ALTER TABLE identity.api_keys ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.api_keys ALTER COLUMN scopes TYPE TEXT[]
    USING _identity_jsonb_to_text_array(scopes);
ALTER TABLE identity.api_keys ALTER COLUMN scopes SET DEFAULT '{}';

-- role_templates: scopes JSONB -> TEXT[].
ALTER TABLE identity.role_templates ALTER COLUMN scopes DROP DEFAULT;
ALTER TABLE identity.role_templates ALTER COLUMN scopes TYPE TEXT[]
    USING _identity_jsonb_to_text_array(scopes);
ALTER TABLE identity.role_templates ALTER COLUMN scopes SET DEFAULT '{}';

-- organizations: drop IdP binding.
ALTER TABLE identity.organizations DROP COLUMN IF EXISTS idp_name;
ALTER TABLE identity.organizations DROP COLUMN IF EXISTS idp_type;

-- Clean up helper.
DROP FUNCTION _identity_jsonb_to_text_array(jsonb);
