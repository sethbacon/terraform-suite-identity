# terraform-suite-identity

Shared identity & auth component for the Terraform tooling suite (the registry and
the state manager).

It is owned by **neither** consuming application: either app can stand the identity
store up at setup time, and whichever app is installed second detects that it already
exists and attaches to it. See ADR 002 in the consuming repositories for the full
rationale.

The module is a **Go library** — it is linked into each app's binary, not run as a
separate service. Consuming it has no runtime/operational footprint; an app can use the
shared schema or keep identity in its own schema (see [Schema routing](#schema-routing)).

## Packages

| Package | Purpose |
| ------- | ------- |
| `identity` | Migration runner for the dedicated `identity` Postgres schema (isolated golang-migrate instance + `identity_schema_migrations` version table). |
| `identity/models` | The canonical identity data types — `User`, `Organization`, `OrganizationMember` (+ membership views), `APIKey`, `RoleTemplate`, `OIDCConfig`, `AuditLog`. |
| `identity/store` | The data-access layer (repository pattern) for those types, plus `TokenRepository` (JWT revocation). Repos use **unqualified** table names so the connection's `search_path` selects the schema. |
| `identity/auth` | App-neutral auth primitives: scope checking (`HasScope`/`HasAnyScope`/`HasAllScopes` with wildcard `admin` + write-implies-read), the JWT `TokenManager` (HS256, JTI, secret rotation), and API-key generation/validation. |
| `identity/auth/oidc` | A generic OpenID Connect provider (discovery, auth URL, code exchange, ID-token verification, group/user-info extraction). |

## Canonical identity model

The data model is **canonical across the suite** — both apps use the same shapes. The
only per-app variance is the **role → scope mapping**: the module is app-agnostic about
scope *contents*, and each app seeds its own scopes onto `role_templates` at setup (the
"identity-core + app-extended" model).

Notable modelling choices:

- **No soft-active flag on users.** Access derives entirely from organization memberships
  and the scopes their role templates grant; "disabling" a user means removing their
  memberships (or deleting the user).
- **API keys** are usable while they exist and have not passed `expires_at`; revocation is
  a hard delete (no soft flag). JWT revocation is tracked separately in `revoked_tokens`.
- **Multi-org by default** — `UserWithOrgRoles` aggregates scopes across all memberships.

## Installation

```bash
go get github.com/sethbacon/terraform-suite-identity@latest
```

Pin a minimum version in `go.mod`. Schema migrations are additive within a major version.

## Usage

### Migrations

Apply the identity migrations before the application's own migrations:

```go
import "github.com/sethbacon/terraform-suite-identity/identity"

if err := identity.RunMigrations(db, "up"); err != nil {
    return err
}
version, dirty, err := identity.GetMigrationVersion(db)
```

`db` is a standard `*sql.DB` on the shared PostgreSQL database. The runner uses
`CREATE … IF NOT EXISTS` / `ON CONFLICT DO NOTHING` with an advisory lock, so it is safe
for **detect-and-attach** when multiple apps run it against the same database.

### Schema routing

The store repositories use unqualified table names, so *the connection decides the
schema*. An app opts into the shared identity schema by giving the identity repositories a
connection whose `search_path` puts `identity` first, while its own feature tables fall
back to `public`:

```go
// Identity connection → identity schema (feature tables still resolve at public).
dsn := baseDSN + " options='-c search_path=identity,public'"
identityDB, _ := sql.Open("postgres", dsn)

userRepo := store.NewUserRepository(identityDB) // reads/writes identity.users
```

With a plain `public` connection the same repositories operate entirely in the app's own
schema — so adopting the shared schema is **opt-in and reversible** behind a feature flag.

### Data layer

```go
import "github.com/sethbacon/terraform-suite-identity/identity/store"

userRepo := store.NewUserRepository(db)
user, err := userRepo.GetOrCreateUserFromOIDC(ctx, sub, email, name)

apiKeyRepo := store.NewAPIKeyRepository(db)
tokenRepo  := store.NewTokenRepository(db) // revoked_tokens
```

### Auth

```go
import "github.com/sethbacon/terraform-suite-identity/identity/auth"

// Scope checks — the app injects its own write→read pairs and scope set.
ok := auth.HasScope(userScopes, "modules:write", auth.ReadWritePairs{...})

// JWT — secret + issuer injected (never read from the environment by the module).
tm := auth.NewTokenManager([]byte(secret), "terraform-registry")
token, _ := tm.Generate(userID, email, scopes, 24*time.Hour)
claims, _ := tm.Validate(token) // tries current then previous secret (rotation)

// API keys
key, hash, prefix, _ := auth.GenerateAPIKey("tfr")
```

OIDC:

```go
import identityoidc "github.com/sethbacon/terraform-suite-identity/identity/auth/oidc"

prov, _ := identityoidc.NewProvider(identityoidc.Config{
    IssuerURL: issuer, ClientID: id, ClientSecret: secret,
    RedirectURL: cb, Scopes: []string{"openid", "email", "profile"},
    RequireHTTPS: true,
})
```

## Versioning

Released with release-please + goreleaser on Conventional Commits. The module is in the
`0.x` series while the API stabilises — breaking changes bump the **minor** version, and
consumers pin and upgrade in lockstep. Schema migrations are additive.

## Development

```bash
go build ./...
go vet ./...
go test ./... -race -coverprofile=coverage.out -covermode=atomic   # sqlmock — no live DB
gosec ./...
```

The data layer is unit-tested with sqlmock (no live database). The migration runner is
exercised against live PostgreSQL by the consuming apps' integration/UAT suites.

## License

Apache-2.0.
