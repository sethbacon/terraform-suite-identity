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
| `identity/suite`     | The shared runtime-coupling contract used by **both** apps: the capability `Manifest` each app publishes, `NegotiateCompat` version negotiation, the polling `DiscoveryClient`, `ManifestPath` (the route both apps serve it at), and `CanonicalHost` for the cross-app "Consumed by" join. |
| `identity/crypto`    | `TokenCipher`: AES-256-GCM authenticated encryption for capability-bearing secrets stored at rest (OAuth tokens, webhook destination URLs, **OIDC client secrets**). Key rotation via `NewTokenCipherWithPrevious`; `DeriveTokenCipher`/`GenerateKey`/`GenerateSalt` for key material. The module never owns a key — you supply one. |
| `identity/httpsafe`  | An SSRF-safe HTTP client: outbound requests from library code (and from a host that wants the same guard) are restricted so a user-supplied destination cannot be steered at link-local, loopback or private-range addresses. |
| `identity/mailer`    | An SMTP transport hardened against opportunistic-TLS downgrade, used to deliver notifications. |
| `identity/notify`    | Notification fan-out: `ChannelRepository` over an app-owned `notification_channels` table (encrypted destination targets, decrypted via `identity/crypto`), the `Notifier`, and the API-key-expiry notifier. |

The `notification_channels` table `identity/notify` reads is **owned by the consuming
app**, not created by this module's migrations — see the [schema
reference](docs/schema.md#tables) for the exact shape it must have.

## Canonical identity model

The data model is **canonical across the suite** — both apps use the same shapes. The
only per-app variance is the **role → scope mapping**: the module is app-agnostic about
scope *contents*, and each app seeds its own scopes onto `role_templates` at setup (the
"identity-core + app-extended" model).

### Notable modelling choices

- **No soft-active flag on users, api keys, or organizations.** Access derives entirely
  from organization memberships and the scopes their role templates grant; "disabling" a
  user means removing their memberships (or deleting the user). The `is_active` column
  on `users`, `api_keys`, and `organizations` was never read or written by the model on
  any of the three tables, so migration `000004` drops it — do not expect any of them to
  reappear as a working kill-switch. (`oidc_config.is_active` is the one exception: it is
  genuinely read/written by `GetActiveOIDCConfig`/`ActivateOIDCConfig`/
  `DeactivateAllOIDCConfigs`.)
- **API keys** carry an optional `expires_at`, and **the auth path's lookup enforces it in
  SQL**: `store.APIKeyRepository.GetAPIKeysByPrefix` — the query an authenticating host
  runs to find candidate keys for a presented prefix — filters with
  `(expires_at IS NULL OR expires_at > NOW())`, so an expired key is never returned as a
  candidate. `auth.ValidateAPIKey` is a pure bcrypt comparison and performs no expiry
  check of its own; it does not need to, because it only ever sees candidates the query
  already filtered. A host that re-checks `ExpiresAt` on the returned keys is performing a
  harmless redundant second check.
  <br>
  Two limits worth planning for. First, expiry enforcement lives in **that one query**:
  the admin/listing lookups (`GetAPIKeyByID`, `ListAPIKeysByUser`,
  `ListAPIKeysByOrganization`, `ListAPIKeys`, …) deliberately return expired rows so an
  operator can see and clean them up — **never build an authentication path on those**.
  Second, revocation is a hard delete (no soft flag), so a revoked key disappears rather
  than being marked. JWT revocation is different again: it is tracked in `revoked_tokens`
  but is entirely host-enforced — see the Auth section below.
- **Tenancy is a required parameter, not an optional filter: `store.OrgScope`.**
  Every accessor that reads or mutates a row of an organization-owned table
  (`organizations`, `organization_members`, `api_keys`, `audit_logs`, and `users`
  via its memberships) takes an `OrgScope`, and **its zero value denies
  everything** — a caller that has not thought about tenancy gets no rows rather
  than every tenant's. The predicate is applied in SQL before any caller-supplied
  filter, so no filter combination yields an unscoped query, and an out-of-scope
  target is reported as `store.ErrNotFound` on every axis (including create), so
  the by-id axes cannot become a cross-tenant existence oracle. Reaching across
  organizations is still possible but must be spelled `OrgScopeAllOrganizations()`,
  which is greppable in a way an absent filter is not.
  <br>
  Three pieces are exported because a host needs all three:
  `OrganizationRepository.OrgScopeForUser` resolves the organizations in which a
  user's **role template** grants a scope (membership alone is not authority);
  `OrgScope.SQL(column, paramIndex)` builds the same predicate for a host's **own**
  organization-owned tables and never returns an empty clause; and
  `OrgScope.PermitsOrganization` checks rows already in memory. Accessors that
  deliberately take no scope — authority derivation, authentication bookkeeping,
  unattended maintenance, bootstrap — say `UNSCOPED BY DESIGN` in their doc
  comment with the reason.
- **Not-found has ONE spelling: `store.ErrNotFound`.** Every read that can miss and
  every by-identifier `UPDATE`/`DELETE` that can match zero rows returns an error
  wrapping it; test with `errors.Is(err, store.ErrNotFound)`. Before v0.24.0 a read
  returned `(nil, nil)` and a zero-row mutation returned `nil` — so "I did the work"
  and "there was nothing to do" arrived over the same wire, which made a revoked-nothing
  revocation report success and made the idiomatic `if err != nil { return err }` panic
  on a miss. Three deliberate exceptions: **list/search** accessors return an empty
  slice (an empty result set is an answer, not a miss); **bulk sweeps**
  (`DeleteExpiredKeys`, `RevokeAPIKeysForUser`, `DeactivateAllOIDCConfigs`,
  `CleanupExpiredRevocations`, `DeleteAuditLogsBefore`) return an affected-row **count**,
  and `RemoveAllMembershipsForUser` returns the **set** of organizations it emptied,
  since zero is a normal outcome for a sweep; and `CheckMembership` /
  `GetUserScopesForOrg` **absorb** the sentinel because their `bool` / empty scope set
  already says "nothing matched" in band — both still propagate a real failure, so a
  database fault can never read as "not a member".
- **Multi-org by default** — `UserWithOrgRoles` aggregates scopes across all memberships.
  **`GetAllowedScopes`/`GetUserCombinedScopes` union those scopes into one flat, GLOBAL set
  with no per-organization qualifier — do not feed that set into a JWT (or any other
  authorization decision) as "what the user can do" for a specific organization**, since a
  role in one organization would silently authorize an action in another. Use
  `GetScopesForOrg`/`GetUserScopesForOrg` plus `auth.TokenManager.GenerateForOrg` and
  `auth.HasScopeInOrg` instead whenever the decision is scoped to a single organization —
  see the [Auth](#auth) section below.
  Since v0.25.0 the two sets are **distinct types** rather than two `[]string`s carrying a
  warning: the global accessors return `auth.GlobalScopes`, the per-org accessors return
  `auth.OrgScopes`, and `GenerateForOrg` takes only the latter. Minting an org-bound token
  from a cross-org union therefore does not compile without an explicit
  `auth.OrgScopes(...)` conversion. (A plain `[]string` literal still satisfies either
  parameter; the barrier is between the two library-produced sets, which is where the
  mistake arises.)

## Installation

```bash
go get github.com/sethbacon/terraform-suite-identity@latest
```

Pin a minimum version in `go.mod`. Schema migrations are additive within a major version,
with **four documented exceptions** — a seed-data `UPDATE` (`000002`), in-place
`ALTER COLUMN … TYPE` on three tables (`000003`), a verified-dead-column `DROP COLUMN`
(`000004`), and a data `UPDATE` plus a new `UNIQUE` index (`000005`) — see
[docs/schema.md](docs/schema.md).

Requires **Go 1.25** or newer as the language floor (`go 1.25.0` in `go.mod`). `go.mod`
also pins `toolchain go1.26.5`, which is the version CI builds and tests with; the `go`
command downloads it automatically, so a local Go 1.25 works unless you have set
`GOTOOLCHAIN=local`.

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

Every repository takes the same `*sql.DB` — including `RoleTemplateRepository` and
`OIDCConfigRepository`, which used `sqlx` internally and demanded a `*sqlx.DB` from the
caller until v0.25.0:

```go
roleRepo := store.NewRoleTemplateRepository(db)
oidcRepo := store.NewOIDCConfigRepository(db)
```

Those two still scan through `sqlx`'s db-tagged structs; they now wrap the pool you hand
them (`sqlx.NewDb` adorns an existing `*sql.DB`, it does not open a second one) instead of
making every consumer construct and thread two handle types for one identity layer.

### Auth

```go
import "github.com/sethbacon/terraform-suite-identity/identity/auth"

// Scope checks — the module ships identity-core scope constants (auth.ScopeUsersRead,
// auth.ScopeOrganizationsWrite, …); apps add their own scopes (e.g. "modules:write")
// and supply the write→read pairs. Using an exported scope here:
ok := auth.HasScope(userScopes, auth.ScopeUsersRead,
    auth.ReadWritePairs{auth.ScopeUsersRead: auth.ScopeUsersWrite})

// JWT — secret + issuer injected (never read from the environment by the module).
// Note both parameters are strings here; NewCoupledTokenManager below takes []byte.
tm := auth.NewTokenManager(secret, "terraform-registry")

// GLOBAL (org-less) token: `scopes` is auth.GlobalScopes, the flat union across
// every organization the user belongs to (GetUserCombinedScopes/GetAllowedScopes
// return exactly that type). Only appropriate for a deliberately suite-wide,
// org-independent decision — see the warning on Generate and the "Multi-org by
// default" note above.
globalScopes, _ := orgRepo.GetUserCombinedScopes(ctx, userID) // auth.GlobalScopes
token, _ := tm.Generate(userID, email, globalScopes, 24*time.Hour)
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
    RedirectURL: redirectURL, Scopes: []string{"openid", "email", "profile"},
    // HTTPS is required by default on BOTH the issuer and the redirect URL, and
    // on the endpoints read out of the discovery document; set
    // AllowInsecureIssuer: true only for a local/dev http issuer.

    // REQUIRED for an IdP on an internal address (since v0.25.0). Every request
    // this package makes — discovery, JWKS, token exchange — goes through the
    // egress guard, and a nil guard is the STRICT default: loopback, RFC 1918
    // and link-local are all denied. Build it from the deployment's
    // security.egress.allowlist. See UPGRADING.md.
    EgressGuard: httpsafe.MustGuard("idp.corp.internal"),
    // Optional: a private-CA root pool or mTLS certificates for that IdP. This
    // reaches the guarded transport WITHOUT displacing the guard, which is why
    // supplying an *http.Client on the context is no longer accepted.
    TLSClientConfig: myTLSConfig,
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
// One call exchanges the code AND verifies the ID token, applying this login's
// PKCE verifier and nonce itself. There is no option to pass and none to forget.
token, idToken, err := prov.ExchangeAndVerify(ctx, code, cb)
// cb.Payload is your bytes, byte for byte.
```

**OIDC client secrets are stored verbatim.** `OIDCConfigRepository` reads and writes
`OIDCConfig.ClientSecretCiphertext` exactly as given — it performs no cryptography and
does not own an encryption key. If you want encryption at rest for that column, this
module ships the tool for it: **[`identity/crypto`](identity/crypto/tokencipher.go)'s
`TokenCipher`** (AES-256-GCM, with `NewTokenCipherWithPrevious` for key rotation). Seal
before writing and open after reading; the key stays yours.

**Use `BeginAuthSession`/`CompleteAuthSession` for new integrations.** `BeginAuth` is
still correct and supported — it is the right entry point for an app that already owns a
store-and-consume state, which both suite consumers do, since their state stores also
carry SAML and SCM flows this package never sees. What `BeginAuth` costs you is ownership
of the state's entropy, storage and single use, plus persisting
`AuthChallenge.Session`; what it does NOT cost you is either binding, because both begin
paths hand back the same `CallbackSession` and `ExchangeAndVerify` is the only way to
redeem it.

**There is exactly one way to complete an exchange.** v0.25.0 deleted `GetAuthURL` (a bare
authorization URL with no nonce and no PKCE challenge), and deleted `ExchangeCode`,
`VerifyIDToken` and the `WithPKCEVerifier`/`WithExpectedNonce` options they took. Under
that API, omitting `WithPKCEVerifier` compiled cleanly and sent a token request with no
`code_verifier` at all, leaving the outcome to the identity provider's strictness. Adding
`ExchangeAndVerify` beside it would have left the omittable path in place for whoever
reached for it first, so the omittable path was removed instead: `ExchangeAndVerify` takes
the whole `CallbackSession` and rejects one with an empty nonce or code verifier before it
makes any network call.

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
//
// The guard applies the deployment's egress policy to the poll AND is what
// SiblingPublicURL validates against. A nil guard is the STRICT default (since
// v0.25.0), so a sibling on an internal address — two apps in one cluster, or
// any dev stack — needs the deployment's allow-list here. See UPGRADING.md.
dc, err := suite.NewDiscoveryClient("https://tfstate.example.com", self, 0, egressGuard) // 0 → default 60s
if err != nil {
    log.Fatal(err)
}
go dc.Start(ctx)
state, sibling := dc.Snapshot() // active / degraded / unreachable / unknown

// The sibling's manifest is UNTRUSTED INPUT it asserts about itself — not the
// siblingURL you pinned. To make a follow-up request to it, take the base URL
// and the client from the discovery client, so both carry the same policy:
base, err := dc.SiblingPublicURL(ctx)        // validated; refuses a denied destination
client := dc.GuardedClient(2 * time.Second)  // resolve-and-pin dialing
// To merely RENDER what the sibling claims: sibling.PublicURL.Display().
```

The poller calls `NegotiateCompat` for you; call it directly when you receive a manifest
by other means. It reports incompatible when the sibling app id is empty, when it equals
self, when either side's `SchemaVersion` is empty, or when the two schema MAJORs differ —
five rejection cases in all, listed in
[docs/suite-coupling.md](docs/suite-coupling.md#version-negotiation-negotiatecompat).

The manifest route is `suite.ManifestPath`; register your handler from that constant
rather than a copied literal so the publisher and the discovery client cannot drift apart.

**`CanonicalHost`** normalizes a registry host so the suite "Consumed by" join
compares like-for-like across apps. It folds away case, a default port (`:80`/`:443`,
compared numerically so `:080` folds too), a trailing FQDN dot, an accidental scheme
prefix, IPv6 brackets, and Unicode (IDN) vs punycode encoding. Input that is never
legitimate as a bare host-identity join key — anything containing userinfo (`@`), or a
malformed multi-colon shape like `host:443:extra` — is **rejected outright** and returns
`""`:

```go
suite.CanonicalHost("https://Registry.Example.com:443/") // "registry.example.com"
suite.CanonicalHost("[::1]:443")                         // "::1"
suite.CanonicalHost("attacker@registry.example.com")     // "" (rejected)
```

See the canonical-host and suite-coupling design notes for the full rationale.

## Versioning

Released with release-please on Conventional Commits: release-please raises the release PR
and, when it merges, tags the version and drafts the GitHub Release. `release.yml` then
publishes that draft — there are no build artifacts to attach, since this is a pure Go
library. The module is in the `0.x` series while the API stabilises — breaking changes bump
the **minor** version, and consumers pin and upgrade in lockstep. Schema migrations are
additive, with the documented exceptions listed under
[Installation](#installation) and detailed in [docs/schema.md](docs/schema.md).

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
