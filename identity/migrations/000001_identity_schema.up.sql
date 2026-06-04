CREATE TABLE IF NOT EXISTS identity.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    oidc_sub VARCHAR(255) UNIQUE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity.role_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity.organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    role_template_id UUID REFERENCES identity.role_templates(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS identity.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    organization_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_api_keys_key_prefix ON identity.api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS identity.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES identity.organizations(id) ON DELETE SET NULL,
    action VARCHAR(500) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    ip_address VARCHAR(45),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_created_at ON identity.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_audit_logs_user_id ON identity.audit_logs(user_id);

CREATE TABLE IF NOT EXISTS identity.oidc_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_url TEXT NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    redirect_url TEXT NOT NULL,
    scopes TEXT DEFAULT 'openid,email,profile',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity.system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity.revoked_tokens (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_revoked_tokens_expires_at ON identity.revoked_tokens(expires_at);

INSERT INTO identity.role_templates (name, display_name, description, scopes, is_system)
VALUES
    ('admin', 'Administrator', 'Full administrative access', ARRAY['admin', 'analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'dashboard:write', 'sources:read', 'sources:write', 'compliance:read', 'compliance:write', 'users:read', 'users:write', 'organizations:read', 'organizations:write', 'api_keys:read', 'api_keys:write', 'audit:read', 'settings:read', 'settings:write'], true),
    ('analyst', 'Analyst', 'Analysis and reporting access', ARRAY['analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'sources:read', 'compliance:read'], true),
    ('viewer', 'Viewer', 'Read-only access', ARRAY['analysis:read', 'reports:read', 'dashboard:read', 'sources:read'], true),
    ('operator', 'Operator', 'Operational access without administration', ARRAY['analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'dashboard:write', 'sources:read', 'sources:write', 'compliance:read', 'compliance:write', 'users:read', 'organizations:read', 'api_keys:read', 'api_keys:write', 'audit:read', 'settings:read'], true)
ON CONFLICT (name) DO NOTHING;

INSERT INTO identity.organizations (name, display_name, description)
VALUES ('default', 'Default Organization', 'Default organization for all users')
ON CONFLICT (name) DO NOTHING;

INSERT INTO identity.system_settings (key, value)
VALUES ('setup_completed', 'false')
ON CONFLICT (key) DO NOTHING;
