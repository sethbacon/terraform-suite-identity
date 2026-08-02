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
| `identity/auth/oauthstate` | The OAuth `state` contract: `Manager` mints an unguessable state, stores an **opaque** app payload against it under a TTL, and consumes it exactly once. Ships a `MemoryStore`; HA deployments implement `Store` over their own backend.                     |
| `identity/suite`     | The shared runtime-coupling contract used by **both** apps: the capability `Manifest` each app publishes, `NegotiateCompat` version negotiation, the polling `DiscoveryClient`, and `CanonicalHost` for the cross-app "Consumed by" join. |

## Canonical identity model

The data model is **canonical across the suite** — both apps use the same shapes. The
only per-app variance is the **role → scope mapping**: the module is app-agnostic about
scope *contents*, and each app seeds its own scopes onto `role_templates` at setup (the
"identity-core + app-extended" model).

Notable modelling choices:

- **No soft-active flag on users, api keys, or organizations.** Access derives entirely
  from organization memberships and the scopes their role templates grant; "disabling" a
  user means removing their memberships (or deleting the user). The `is_active` column
  on `users`, `api_keys`, and `organizations` was never read or written by the model on
  any of the three tables, so migration `000004` drops it — do not expect any of them to
  reappear as a working kill-switch. (`oidc_config.is_active` is the one exception: it is
  genuinely read/written by `GetActiveOIDCConfig`/`ActivateOIDCConfig`/
  `DeactivateAllOIDCConfigs`.)
- **API keys** carry an optional `expires_at`, but this library does not enforce it at
  lookup/validate time — `GetAPIKeysByPrefix` (the query the auth path uses) returns rows
  regardless of expiry, and `auth.ValidateAPIKey` is a pure bcrypt comparison with no
  expiry check at all. **Hosts must check `expires_at` themselves** before accepting a key
  as valid. Revocation is a hard delete (no soft flag). JWT revocation is tracked
  separately in `revoked_tokens`, but is likewise host-enforced — see the Auth section
  below.
- **Multi-org by default** — `UserWithOrgRoles` aggregates scopes across all memberships.
  **`GetAllowedScopes`/`GetUserCombinedScopes` union those scopes into one flat, GLOBAL set
  with no per-organization qualifier — do not feed that set into a JWT (or any other
  authorization decision) as "what the user can do" for a specific organization**, since a
  role in one organization would silently authorize an action in another. Use
  `GetScopesForOrg`/`GetUserScopesForOrg` plus `auth.TokenManager.GenerateForOrg` and
  `auth.HasScopeInOrg` instead whenever the decision is scoped to a single organization —
  see the [Auth](#auth) section below.

## Installation

```bash
go get github.com/sethbacon/terraform-suite-identity@latest
```

Pin a minimum version in `go.mod`. Schema migrations are additive within a major version,
with two documented exceptions — an in-place `ALTER COLUMN` (migration `000003`) and a
verified-dead-column `DROP COLUMN` (migration `000004`) — see
[docs/schema.md](docs/schema.md). Requires Go 1.25 or newer.

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

// GLOBAL (org-less) token: `scopes` here is typically a flat union across every
// organization the user belongs to (e.g. GetUserCombinedScopes/GetAllowedScopes).
// Only appropriate for a deliberately suite-wide, org-independent decision —
// see the warning on Generate and the "Multi-org by default" note above.
token, _ := tm.Generate(userID, email, scopes, 24*time.Hour)
claims, _ := tm.Validate(token) // tries current then previous secret (rotation)

// Org-scoped token (preferred for any multi-tenant, per-resource authorization):
// fetch scopes for the SPECIFIC target organization, then bind the token to it.
orgScopes, _ := orgRepo.GetUserScopesForOrg(ctx, userID, orgID)
orgToken, _ := tm.GenerateForOrg(userID, email, orgID, orgScopes, 24*time.Hour)
orgClaims, _ := tm.Validate(orgToken)

// ...and check it with the org-aware counterpart to HasScope, passing the SAME
// orgID as the resource being accessed — this rejects a token bound to a
// different organization (or no organization at all), closing the cross-org
// escalation a flat scope set otherwise leaves open:
ok = auth.HasScopeInOrg(orgClaims, orgID, auth.ScopeUsersRead,
    auth.ReadWritePairs{auth.ScopeUsersRead: auth.ScopeUsersWrite})

// Audience — also OFF by default (Validate skips the aud check unless set).
// Each app in a coupled suite should set THIS app's own identity as the
// audience, so a token minted for one app cannot be replayed against a
// sibling even though they share the signing secret and both appear in
// each other's allowed-issuers list:
tm.SetAudience("terraform-registry")

// API keys
key, hash, prefix, _ := auth.GenerateAPIKey("tfr")
```

**`NewTokenManager`'s issuer pin and audience check are both OFF by default**
(`Validate` accepts any issuer and skips the `aud` check unless you opt in via
`SetAllowedIssuers`/`SetAudience`). That default is fine for a single
standalone app, but is a real gap for a **coupled suite that shares one
signing secret** — today that's `terraform-registry-backend` and
`terraform-state-manager-backend` — because with the defaults left alone, a
token minted by one app validates unchanged at the other.

**Issuer pinning and audience are independent opt-in checks, and a coupled suite needs
both.** `SetAllowedIssuers` alone still lets a trusted sibling's token through unchanged;
`SetAudience` closes that gap by additionally requiring the token to have been minted
*for this app specifically*, so even a token from a trusted sibling issuer is rejected
unless it names this app as its audience.

**If your app shares a secret with another app in the suite, use
`NewCoupledTokenManager` instead of `NewTokenManager`.** It requires
issuer/audience/allowedIssuers up front (returning an error rather than a
misconfigured manager) and calls `SetAllowedIssuers`/`SetAudience` for you, so
the secure configuration is the default path instead of two follow-up calls
you have to remember:

```go
// RECOMMENDED for any app in the shared-secret coupled suite. secret is the
// same secret every sibling app signs/validates with; audience is THIS app's
// own identity; allowedIssuers is {self} plus the trusted sibling issuers.
tm, err := auth.NewCoupledTokenManager(
    []byte(secret),
    "terraform-registry",                                        // this app's issuer
    []string{"terraform-registry", "terraform-state-manager"},    // trusted issuers, incl. self
    "terraform-registry",                                        // this app's audience
)
token, _ := tm.Generate(userID, email, scopes, 24*time.Hour)
claims, _ := tm.Validate(token) // rejects tokens from untrusted issuers or the wrong audience
```

If you'd rather configure an existing `*TokenManager` manually (or need to
change the pin/audience at runtime), the underlying calls are still available
directly:

```go
tm.SetAllowedIssuers([]string{"terraform-registry", "terraform-state-manager"})
tm.SetAudience("terraform-registry")
```

**Revocation is entirely host-enforced.** The module provides no revocation of its own —
only the `JTI` claim, which a host must denylist (e.g. via `store.TokenRepository`) and
check on every request; `Validate` never consults a denylist itself. Two related limits to
plan for: (1) a token stays valid for its full lifetime (`DefaultExpiry` is 1 hour) unless
the host's denylist check runs on the request path, and (2) after `RotateSecret`, a token
signed with the **previous** secret keeps validating until the host calls
`ClearPreviousSecret` — size the rotation-overlap window deliberately.

OIDC:

```go
import identityoidc "github.com/sethbacon/terraform-suite-identity/identity/auth/oidc"

prov, _ := identityoidc.NewProvider(identityoidc.Config{
    IssuerURL: issuer, ClientID: id, ClientSecret: secret,
    RedirectURL: cb, Scopes: []string{"openid", "email", "profile"},
    // HTTPS is required by default; set AllowInsecureIssuer: true only for a
    // local/dev http issuer.
})

// Login: BeginAuthSession takes no state parameter — it mints one, and stores this
// login's nonce, PKCE verifier and your own opaque payload against it.
states, _ := oauthstate.NewManager(oauthstate.NewMemoryStore(0, 0)) // see OAuth state below
payload, _ := json.Marshal(mySessionStruct)                        // whatever YOUR app needs
sess, _ := prov.BeginAuthSession(ctx, states, "oidc-login", payload, oauthstate.DefaultTTL)
redirectUser(sess.URL)

// Callback: the state is verified and consumed once, and hands back everything the
// callback needs — none of it read from the request.
cb, err := prov.CompleteAuthSession(ctx, states, "oidc-login", r.FormValue("state"))
token, _ := prov.ExchangeCode(ctx, code, identityoidc.WithPKCEVerifier(cb.CodeVerifier))
rawIDToken := token.Extra("id_token").(string)
idToken, err := prov.VerifyIDToken(ctx, rawIDToken, identityoidc.WithExpectedNonce(cb.Nonce))
// cb.Payload is your bytes, byte for byte.
```

**Use `BeginAuthSession`/`CompleteAuthSession` for new integrations.** `BeginAuth` is
still correct and supported — it is the right entry point for an app that already owns a
store-and-consume state — but the caller then owns the state's entropy, storage and
single use, plus persisting the nonce and PKCE verifier. The legacy pair,
`GetAuthURL`/`VerifyIDToken` called with no options, provides **no nonce or PKCE
protection** and exists only for backward compatibility.

### OAuth state

`identity/auth/oauthstate` owns the security-critical half of the `state` protocol —
entropy, TTL, single use, and the purpose binding — while the payload stays opaque, so
each app keeps its own session struct without the module needing to unify them:

```go
import "github.com/sethbacon/terraform-suite-identity/identity/auth/oauthstate"

// MemoryStore is single-process (dev/single-replica). For HA, implement Store over
// a shared backend: SET NX EX for PutIfAbsent, GETDEL (or an atomic Lua GET+DEL)
// for Take. The module ships no Redis client of its own.
states, err := oauthstate.NewManager(oauthstate.NewMemoryStore(0, 0)) // 0 = defaults
defer states.Close()

// purpose binds the state to the flow AND the resource; the callback must rebuild it
// from its own route/config, never from the request.
state, err := states.Issue(ctx, "scm:"+providerID, payload, oauthstate.DefaultTTL)
payload, err := states.Consume(ctx, "scm:"+providerID, r.FormValue("state"))
// errors.Is(err, oauthstate.ErrNotFound | ErrExpired | ErrPurposeMismatch)

// Single-use marker for an identifier someone else assigned (e.g. a SAML assertion ID).
fresh, err := states.Reserve(ctx, assertionID, assertionLifetime) // false == replay
```

**A self-describing state is a vulnerability, not a CSRF token.** Building the state as
`fmt.Sprintf("%s:%s", userID, providerID)` and reading the principal back out of it at an
unauthenticated callback is guessable, forgeable and replayable, and it lets an anonymous
caller name whose record the callback writes — that defect is why this package exists.
`Issue` is the only way a state is created here, and it takes no caller-supplied value.

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
//
// NewDiscoveryClient fails closed on a plaintext http:// siblingURL — use
// suite.NewInsecureDiscoveryClient instead for a local/dev loopback sibling.
dc, err := suite.NewDiscoveryClient("https://tfstate.example.com", self, 0) // 0 → default 60s
if err != nil {
    log.Fatal(err)
}
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
additive, with one documented in-place exception (see [docs/schema.md](docs/schema.md)).

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
