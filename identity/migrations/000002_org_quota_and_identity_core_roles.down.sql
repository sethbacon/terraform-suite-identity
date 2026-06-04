-- Restore the role template scopes exactly as seeded by migration 000001.
UPDATE identity.role_templates SET scopes = ARRAY['admin', 'analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'dashboard:write', 'sources:read', 'sources:write', 'compliance:read', 'compliance:write', 'users:read', 'users:write', 'organizations:read', 'organizations:write', 'api_keys:read', 'api_keys:write', 'audit:read', 'settings:read', 'settings:write'] WHERE name = 'admin';
UPDATE identity.role_templates SET scopes = ARRAY['analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'sources:read', 'compliance:read'] WHERE name = 'analyst';
UPDATE identity.role_templates SET scopes = ARRAY['analysis:read', 'reports:read', 'dashboard:read', 'sources:read'] WHERE name = 'viewer';
UPDATE identity.role_templates SET scopes = ARRAY['analysis:read', 'analysis:write', 'reports:read', 'reports:write', 'dashboard:read', 'dashboard:write', 'sources:read', 'sources:write', 'compliance:read', 'compliance:write', 'users:read', 'organizations:read', 'api_keys:read', 'api_keys:write', 'audit:read', 'settings:read'] WHERE name = 'operator';

DROP TABLE IF EXISTS identity.org_quotas;
