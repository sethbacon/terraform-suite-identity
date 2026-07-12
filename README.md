# terraform-suite-identity

Shared identity & auth component for the Terraform tooling suite (the Enterprise
Terraform Registry and the state manager).

It is owned by **neither** consuming application: either app can stand the identity
store up at setup time, and whichever app is installed second detects that it already
exists and attaches to it. See ADR 012 (Shared Identity Component) in
terraform-registry-backend for the full rationale.

The module is a **Go library** — it is linked into each app's binary, not run as a
separate service. Consuming it has no runtime/operational footprint; an app can use the
shared schema or keep identity in its own schema (see [Schema routing](#schema-routing)).

## Packages

| Package              | Purpose                                                                                                                                                                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identity`           | Migration runner for the dedicated `identity` Postgres schema (isolated golang-migrate instance + `identity_schema_migrations` version table).                                                                                            |
| `identity/models`    | The canonical identity data types — `User`, `Organization`, `OrganizationMember` (+ membership views), `APIKey`, `RoleTemplate`, `OIDCConfig`, `AuditLog`.                                                                                |
| `identity/store`     | The data-access layer (repository pattern) for those types, plus `TokenRepository` (JWT revocation). Repos use **unqualified** table names so the connection's `search_path` selects the schema.                                          |
| `identity/auth`      | App-neutral auth primitives: scope checking (`HasScope`/`HasAnyScope`/`HasAllScopes` with wildcard `admin` + write-implies-read), the JWT `TokenManager` (HS256, JTI, secret rotation), and API-key generation/validation.                |
| `identity/auth/oidc` | A generic OpenID Connect provider (discovery, auth URL, code exchange, ID-token verification, group/user-info extraction).                                                                                                                |
| `identity/suite`     | The shared runtime-coupling contract used by **both** apps: the capability `Manifest` each app publishes, `NegotiateCompat` version negotiation, the polling `DiscoveryClient`, and `CanonicalHost` for the cross-app "Consumed by" join. |

## Canonical identity model

The data model is **canonical across the suite** — both apps use the same shapes. The
only per-app variance is the **role → scope mapping**: the module is app-agnostic about
scope *contents*, and each app seeds its own scopes onto `role_templates` at setup (the
"identity-core + app-extended" model).

Notable modelling choices:

- **No soft-active flag on users.** Access derives entirely from organization memberships
  and the scopes their role templates grant; "disabling" a user means removing their
  memberships (or deleting the user). (The `users.is_active` column still exists in the
  schema for historical reasons but is intentionally unread/unwritten by the model.)
- **API keys** are usable while they exist and have not passed `expires_at`; revocation is
  a hard delete (no soft flag). JWT revocation is tracked separately in `revoked_tokens`.
- **Multi-org by default** — `UserWithOrgRoles` aggregates scopes across all memberships.

## Installation

```bash
go get github.com/sethbacon/terraform-suite-identity@latest
```

Pin a minimum version in `go.mod`. Schema migrations are additive within a major version.
Requires Go 1.25 or newer.

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
// emailVerified MUST carry the IdP's email_verified claim; an unverified email
// is refused for account linking/creation (returning users are unaffected).
user, err := userRepo.GetOrCreateUserFromOIDC(ctx, sub, email, name, emailVerified)

apiKeyRepo := store.NewAPIKeyRepository(db)
tokenRepo  := store.NewTokenRepository(db) // revoked_tokens
```

Most repositories take a `*sql.DB`, but `RoleTemplateRepository` and
`OIDCConfigRepository` take a `*sqlx.DB`. Wrap the same connection with
`sqlx.NewDb(db, "postgres")` for those two:

```go
sqlxDB := sqlx.NewDb(db, "postgres") // db is the *sql.DB from above

roleRepo := store.NewRoleTemplateRepository(sqlxDB)
oidcRepo := store.NewOIDCConfigRepository(sqlxDB)
```

### Auth

```go
import "github.com/sethbacon/terraform-suite-identity/identity/auth"

// Scope checks — the module ships identity-core scope constants (auth.ScopeUsersRead,
// auth.ScopeOrganizationsWrite, …); apps add their own scopes (e.g. "modules:write")
// and supply the write→read pairs. Using an exported scope here:
ok := auth.HasScope(userScopes, auth.ScopeUsersRead,
    auth.ReadWritePairs{auth.ScopeUsersRead: auth.ScopeUsersWrite})

// JWT — secret + issuer injected (never read from the environment by the module).
tm := auth.NewTokenManager([]byte(secret), "terraform-registry")
token, _ := tm.Generate(userID, email, scopes, 24*time.Hour)
claims, _ := tm.Validate(token) // tries current then previous secret (rotation)

// Issuer pinning — OFF by default (Validate accepts any issuer). In a coupled
// suite that shares one signing secret, pin the trusted issuers so a shared
// secret cannot be replayed from an untrusted minter:
tm.SetAllowedIssuers([]string{"terraform-registry", "terraform-state-manager"})

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

### Suite coupling

`identity/suite` is the shared, framework-free contract both apps import so the
runtime coupling between them cannot drift. It carries no application logic — just
the manifest shape, version negotiation, the discovery poller, and host
normalization.

Each app publishes a capability **`Manifest`** at `GET /api/v1/suite/manifest`.
Its `SchemaVersion` is `suite/v1` (`suite.SchemaVersionV1`), and the contract is
**additive**: never remove or repurpose a field, and consumers
ignore unknown fields (`encoding/json` does this by default), so a newer app can
advertise new capabilities to an older one harmlessly.

```go
import "github.com/sethbacon/terraform-suite-identity/identity/suite"

self := suite.Manifest{
    SchemaVersion: suite.SchemaVersionV1,
    App:           "terraform-registry",
    Version:       buildVersion,
    Identity:      suite.IdentityInfo{Issuer: issuer, SharedStore: true, Schema: "identity"},
}

// Poll the configured sibling's manifest (construct ONLY when an operator set a
// sibling URL). Snapshot() is cheap and safe per request.
dc := suite.NewDiscoveryClient("https://tfstate.example.com", self, 0) // 0 → default 60s
go dc.Start(ctx)
state, sibling := dc.Snapshot() // active / degraded / unreachable / unknown
```

The poller calls `NegotiateCompat` for you (incompatible when the sibling app id is
empty, equals self, or its schema MAJOR differs); call it directly when you receive
a manifest by other means.

**`CanonicalHost`** normalizes a registry host so the suite "Consumed by" join
compares like-for-like across apps — folding away case, a default port (`:80`/`:443`),
a trailing FQDN dot, an accidental scheme prefix, and Unicode (IDN) vs punycode
encoding:

```go
suite.CanonicalHost("https://Registry.Example.com:443/") // "registry.example.com"
```

See the canonical-host and suite-coupling design notes for the full rationale.

## Versioning

Released with release-please on Conventional Commits: release-please raises the release PR
and, when it merges, tags the version and drafts the GitHub Release. `release.yml` then
publishes that draft — there are no build artifacts to attach, since this is a pure Go
library. The module is in the `0.x` series while the API stabilises — breaking changes bump
the **minor** version, and consumers pin and upgrade in lockstep. Schema migrations are
additive.

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
