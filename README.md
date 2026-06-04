# terraform-suite-identity

Shared identity component for the Terraform tooling suite (registry + state manager).

It is owned by **neither** consuming application: either app can stand the identity
store up at setup time, and whichever app is installed second detects that it already
exists and attaches to it. See ADR 002 in the consuming repositories for the full
rationale.

## Status

Early. The current module provides the **identity schema migration system**:

- A dedicated PostgreSQL `identity` schema with its own `identity_schema_migrations`
  version table, applied via an isolated [golang-migrate](https://github.com/golang-migrate/migrate)
  instance.
- Idempotent (`CREATE … IF NOT EXISTS`, `ON CONFLICT DO NOTHING`) with advisory-lock
  concurrency, giving safe **detect-and-attach** when multiple apps run the migrations
  against the same database.

Future slices will add the shared auth methods (JWT/API key/OIDC/LDAP/SAML/Azure AD/mTLS),
the revocation/session store, identity models, the admin API, and RBAC middleware.

## Usage

```go
import "github.com/sethbacon/terraform-suite-identity/identity"

// Apply identity migrations before the application's own migrations.
if err := identity.RunMigrations(db, "up"); err != nil {
    return err
}
version, dirty, err := identity.GetMigrationVersion(db)
```

`db` is a standard `*sql.DB` connected to the shared PostgreSQL database. Migrations are
additive and backward-compatible by policy; consuming apps pin a minimum module version.

## Compatibility

This module's CI runs contract/integration tests against its consuming applications so a
change that would break a consumer is caught here before release.

## License

Apache-2.0.
