-- Per-organization identity quotas. Identity-domain resources only; consuming
-- apps own their own domain quotas (sources, modules, …) in their own schemas.
CREATE TABLE IF NOT EXISTS identity.org_quotas (
    organization_id UUID PRIMARY KEY REFERENCES identity.organizations(id) ON DELETE CASCADE,
    max_members  INTEGER, -- NULL = unlimited
    max_api_keys INTEGER, -- NULL = unlimited
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Reconcile the seeded role templates to identity-core scopes only (app-agnostic).
-- Each consuming app layers its own domain scopes onto these roles at setup
-- (the "identity-core + app-extended" model). 'admin' keeps the wildcard, which
-- implies every app scope.
UPDATE identity.role_templates SET scopes = ARRAY['admin'] WHERE name = 'admin';
UPDATE identity.role_templates SET scopes = ARRAY['users:read', 'organizations:read', 'api_keys:read', 'api_keys:write', 'audit:read', 'settings:read'] WHERE name = 'operator';
UPDATE identity.role_templates SET scopes = ARRAY['organizations:read', 'audit:read'] WHERE name = 'analyst';
UPDATE identity.role_templates SET scopes = ARRAY['organizations:read'] WHERE name = 'viewer';
