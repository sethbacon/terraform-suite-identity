# Upgrade notes

Operational guidance for releases that need an action beyond `go get`. Only
releases with such an action appear here; everything else is covered by
[CHANGELOG.md](CHANGELOG.md).

Both consuming applications call `identity.RunMigrations` at process **startup**,
so a migration in this module runs on a deploy, on the startup path, against a
live database. That is the reason a release that ships DDL gets an entry here.

---

## v0.25.0 — one canonical name per operation; tenancy is a required parameter

**BREAKING. No migration.** Unlike v0.24.0, **every** change here is a compile
error at the call site — including the tenant-scope work in sections 6 and 7,
which adds a required parameter to every accessor that touches an
organization-owned row.

Sections 1–5 are pure renames and deletions: if it builds, it does what it did
before, with two exceptions called out under "Behaviour that changed with the
deletion". Sections 6–7 change what accessors RETURN for a caller whose tenancy
does not cover the target — that is the fix, and it is the part to read
carefully.
**BREAKING. Ships migration `000007`.** Sections 1–5 are the rename/deletion
half: each of those changes is a compile error at the call site, and nothing
about them changes behaviour except the deletions themselves. Two exceptions are
called out under "Behaviour that changed with the deletion" below — read those.

**Section 6 is different, and is the one to read first.** It changes what a
`DELETE` on `organizations` or `users` does to rows your application is already
storing, and most of it will **not** produce a compile error.
## v0.25.0 — the egress guard is no longer optional

> **READ THIS BEFORE DEPLOYING.** This is the one change in v0.25.0 that a clean
> build does **not** cover. Every other v0.25.0 change is a compile error you
> cannot miss. This one compiles, and then **an identity provider or a sibling
> app on an internal address stops being reachable** unless you add allow-list
> configuration. Plan it with the deploy, not after it.

### What changed

The module has shipped `identity/httpsafe` — a resolve-and-pin SSRF guard — for
several releases, and used it for notification webhooks. It did not use it for
OIDC. The relying party built a bare `&http.Client{Timeout: ...}` with Go's
default cross-host redirect policy, and used it to fetch the discovery document,
the JWKS signing keys that decide which ID tokens are valid, and the token
exchange that carries the `client_secret` and the authorization code. Worse,
only the caller-supplied `IssuerURL` and `RedirectURL` were checked at all: the
`token_endpoint` and `jwks_uri` come **out of the discovery document**, so the
issuer chooses them, and they were used verbatim.

A guard the module owns and does not apply to its own most attacker-adjacent
surface is not a control. As of v0.25.0:

- Every outbound request this module makes goes through `httpsafe`. There is now
  exactly one place in the module that constructs an HTTP transport, and a
  structural test fails the build if a second one appears.
- The discovered `token_endpoint` and `jwks_uri` are validated — scheme **and**
  destination — before any credential-bearing request is built.
- `Manifest.PublicURL` is a distinct type (`suite.UntrustedURL`) that will not
  concatenate with a string, so a consumer cannot reuse a sibling-asserted URL
  unguarded by accident.

### The deployment-configuration change

`httpsafe`'s default policy **denies loopback, RFC 1918, link-local (including
the cloud metadata address), CGNAT and IPv6 ULA**. Both consuming apps default
`security.egress.allowlist` to empty. So a deployment whose IdP or sibling lives
on an internal address must now say so explicitly.

**You need this if any of the following is true:**

| Situation | Symptom if you skip it |
| --- | --- |
| Self-hosted / internal IdP (Keycloak, ADFS, Okta on-prem, anything on RFC 1918) | OIDC provider construction fails at startup, naming the denied endpoint |
| Sibling app reachable on a cluster-internal address | Sibling goes `unreachable`; the cross-app panels empty out |
| Any local dev stack (both apps' compose files) | Login and suite discovery both stop working |
| Public IdP (Entra, Okta cloud, Google, Auth0) | Nothing — already permitted |

The value is a **comma-separated** list of hostnames, IPs or CIDRs. Set it on
the environment variable or in the YAML; the two are the same key.

**terraform-registry-backend** — `TFR_SECURITY_EGRESS_ALLOWLIST`
(`security.egress.allowlist`). The list **widens** the deny-list; empty means
deny every internal target.

```yaml
security:
  egress:
    allowlist:
      - keycloak                 # the dev-stack IdP hostname
      - registry.corp.internal   # an internal sibling or IdP
      - 10.42.0.0/16             # or the pod/service CIDR
```

**terraform-state-manager-backend** — `TSM_SECURITY_EGRESS_ALLOWLIST`
(`security.egress.allowlist`). **Careful: this one REPLACES a built-in default**
of `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7` rather than adding to
it, and it is applied only when non-empty. If you set it, re-state the ranges
you still need:

```yaml
security:
  egress:
    allowlist: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "fc00::/7", keycloak]
```

**Dev stacks specifically.** Both stacks run their IdP as a container reachable
by service name, which resolves to a bridge-network RFC 1918 address, so both
need an entry. Add to the backend service's environment:

| Stack | Add |
| --- | --- |
| `terraform-state-manager-frontend/deployments/docker-compose.yml` (IdP `http://keycloak:8180`) | `TSM_SECURITY_EGRESS_ALLOWLIST=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,keycloak,127.0.0.1` |
| `security-orchestration/seam-harness/docker-compose.yml`, registry side (IdP `https://keycloak:8443`) | `TFR_SECURITY_EGRESS_ALLOWLIST=keycloak,tsm-backend,registry-backend` |
| `security-orchestration/seam-harness/docker-compose.yml`, TSM side | `TSM_SECURITY_EGRESS_ALLOWLIST=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,keycloak,registry-backend` |

Allow-listing the **hostname** (`keycloak`) is preferred over the CIDR: it is
narrower, and it survives the container getting a different bridge address.

`AllowInsecureIssuer` / `DEV_MODE` does **not** cover this. The scheme rule and
the destination rule are deliberately separate — opting out of HTTPS does not
also opt out of knowing where your traffic goes.

### Compile errors you will see

| Call | Change |
| --- | --- |
| `guard.ValidateURL(rawURL)` | `guard.ValidateURL(ctx, rawURL)` — pass the request context so a client disconnect cancels the DNS lookup instead of always waiting 5s |
| `suite.NewDiscoveryClient(url, self, interval)` | `suite.NewDiscoveryClient(url, self, interval, guard)` |
| `suite.NewInsecureDiscoveryClient(url, self, interval)` | same, plus `guard` |
| `siblingURL := m.PublicURL` | `siblingURL, err := dc.SiblingPublicURL(ctx)` — or `m.PublicURL.Resolve(ctx, guard)`; to render it, `m.PublicURL.Display()` |
| `PublicURL: cfg.Server.PublicURL` in your own manifest | `PublicURL: suite.UntrustedURL(cfg.Server.PublicURL)` |
| `oidc.ClientContext(ctx, myClient)` before `NewProviderWithContext` | Move TLS material to `Config.TLSClientConfig`; a client on the context is now refused (adopting it would displace the guard, ignoring it would silently drop your private CA) |

`terraform-state-manager-backend`'s `ListStateModuleFreshness` /
`latestRegistryVersion` is the specific consumer that reused `PublicURL` with a
bare client (issue #144). The type change makes it a compile error; fix it with
`dc.SiblingPublicURL(ctx)` and `dc.GuardedClient(freshnessTimeout)`.

### Behaviour changes that are NOT compile errors

- **`ExtractAPIKeyFromHeader` now matches the `Bearer` scheme
  case-insensitively** and accepts SP or HTAB as the separator, per RFC 7235
  §2.1 / RFC 6750 §2.1. This only ever *accepts more*: it previously rejected
  conformant clients sending `bearer <key>`. The credential itself is still
  case-sensitive. No action required.
- **`DeriveTokenCipher` rejects a weak iteration count instead of silently
  raising it.** The old guard was effectively inverted — it upgraded `1` to
  100,000 while honouring `10000` as given — so the weakest value it accepted
  was reachable only by a caller who had thought about the number. The floor is
  now `MinPBKDF2Iterations` (600,000, current OWASP guidance) and anything below
  it returns `ErrIterationsTooLow`. Pass `0` for "no preference" to get
  `DefaultPBKDF2Iterations`. **Neither consumer calls this** (both use
  `NewTokenCipher` with a supplied key), so there is no re-encryption and no
  migration; if you call it with a literal like `100000`, change it.
- **A discovery document advertising a non-HTTPS `token_endpoint`, `jwks_uri`,
  `authorization_endpoint` or `end_session_endpoint` now fails provider
  construction**, gated on the same `AllowInsecureIssuer` opt-out as the issuer
  URL. `userinfo_endpoint` is not checked because this module never fetches it.

---

## v0.25.0 — one canonical name per operation; the deprecated surface is gone

**BREAKING. No migration.** Unlike v0.24.0, **every** change in *this section* is
a compile error at the call site. Nothing in this section changes behaviour
except the deletions themselves; if it builds, it does what it did before. Two
exceptions are called out under "Behaviour that changed with the deletion" below
— read those. (The egress-guard section above is the part of v0.25.0 that does
change behaviour without a compile error; read it too.)

### Why the deprecated methods were deleted rather than re-marked

Five methods carried a `Deprecated:` marker. A marker is a comment: it stops
nothing, and the next caller reaches for whichever short, obvious name compiles.
Three of the five had a real replacement and are gone. The other two —
`TokenManager.Generate` and `OrganizationRepository.GetUserCombinedScopes` — had
no replacement (they are the only way to mint an org-less token and the only
accessor for the cross-organization scope union, and both consumers use them
deliberately), so the misuse they warned about was made not to type-check
instead. See "Scope types" below.

### 1. Alias methods — one name survives per operation

Nineteen exported methods existed only as a second name for an operation already
reachable under another. Rename the call site; the signature is unchanged unless
noted.

| Removed | Use instead |
| --- | --- |
| `UserRepository.Create` | `CreateUser` |
| `UserRepository.Update` | `UpdateUser` |
| `UserRepository.Delete` | `DeleteUser` |
| `UserRepository.List(ctx, limit, offset)` | `ListUsers(ctx, limit, offset)` — **signature change**: also returns the total count, and runs one extra `SELECT COUNT(*)` |
| `UserRepository.GetOrCreateUserByOIDC` | `GetOrCreateUserFromOIDC` |
| `UserRepository.ListUsersWithRoles` | `ListUsers` |
| `APIKeyRepository.Create` | `CreateAPIKey` |
| `APIKeyRepository.GetByID` | `GetAPIKeyByID` |
| `APIKeyRepository.Delete` | `RevokeAPIKey` |
| `APIKeyRepository.ListByUser` | `ListAPIKeysByUser` |
| `APIKeyRepository.ListByOrganization` | `ListAPIKeysByOrganization` |
| `APIKeyRepository.GetAPIKeyByHash` | `GetAPIKeysByPrefix` + `auth.ValidateAPIKey` (see below) |
| `APIKeyRepository.MarkExpiryNotificationSent` | `ClaimExpiryNotification` |
| `OrganizationRepository.CreateOrganization` | `Create` |
| `OrganizationRepository.ListUserOrganizations` | `GetUserOrganizations` |
| `OrganizationRepository.AddMember(member)` | `AddMemberWithRoleTemplate(ctx, orgID, userID, roleTemplateID)` — **signature change** |
| `OrganizationRepository.UpdateMember(member)` | `UpdateMemberRoleTemplate(ctx, orgID, userID, roleTemplateID)` — **signature change** |
| `RoleTemplateRepository.Create` / `GetByID` / `Update` / `Delete` / `List` | `CreateRoleTemplate` / `GetRoleTemplate` / `UpdateRoleTemplate` / `DeleteRoleTemplate` / `ListRoleTemplates` |

`OrganizationRepository` keeps the SHORT name (`Create`) where every other
organization-entity operation on it is already short (`GetByID`, `Update`,
`Rename`, `Delete`, `List`, `Count`, `Search`); the other three repositories keep
the entity-suffixed name, which is what their non-aliased siblings
(`GetUserByEmail`, `GetAPIKeysByPrefix`, `GetRoleTemplateByName`) already use.
The rule is per receiver, and it is "keep the name the surviving operations on
this type already spell".

### 2. Behaviour that changed with the deletion

Two aliases were not behaviourally identical to the method they delegated to.
Both were resolved in favour of the safer side:

- **`AddMember` wrote a caller-supplied `created_at`; `AddMemberWithRoleTemplate`
  writes `NOW()`.** A caller that built the struct without setting `CreatedAt`
  inserted a membership dated `0001-01-01` — a wrong audit timestamp on a
  privilege grant, produced by the zero value. The server clock is now the only
  source. If you were deliberately backdating a membership row, you no longer
  can through this API.
- **`List` ran one query; `ListUsers` runs two.** The page query is identical
  (both go through the same helper); `ListUsers` additionally issues
  `SELECT COUNT(*) FROM users`. Callers that only wanted a page now pay one extra
  round trip and may discard the count.

Also note `GetAPIKeyByHash`. It is deleted rather than renamed because it could
never do what its name suggests: `key_hash` holds a salted bcrypt digest, which is
non-deterministic, so an exact match can only ever find a row whose hash was
round-tripped verbatim out of the database — never one computed from an incoming
key. If you were calling it as an authentication lookup, it was already not
working as one; the authentication path is `GetAPIKeysByPrefix` followed by
`auth.ValidateAPIKey` against each candidate.

### 3. OIDC — `ExchangeAndVerify` is the only way to complete a login

Removed: `Provider.GetAuthURL`, `Provider.ExchangeCode`, `Provider.VerifyIDToken`,
`ExchangeOption`, `VerifyOption`, `WithPKCEVerifier`, `WithExpectedNonce`.

Under the old shape, the PKCE and nonce bindings were opt-in options the caller
carried forward by hand, and **omitting `WithPKCEVerifier` compiled cleanly and
sent a token request with no `code_verifier` at all** — the exchange then
succeeded or failed entirely at the identity provider's discretion (RFC 7636 §4.6
requires a compliant token endpoint to reject it; a lenient one does not). Adding
a safe helper beside it would have left the omittable path in place for whoever
reached for it first.

`AuthChallenge` also changed shape: its `Nonce` and `CodeVerifier` fields moved
into a single `Session CallbackSession` field, so the two bindings are persisted
and returned as one value rather than two strings that can drift apart.

```go
// before
challenge, _ := prov.BeginAuth(state)
save(state, challenge.Nonce, challenge.CodeVerifier)
// ... at the callback:
token, err := prov.ExchangeCode(ctx, code, oidc.WithPKCEVerifier(saved.CodeVerifier))
rawIDToken, ok := token.Extra("id_token").(string)
idToken, err := prov.VerifyIDToken(ctx, rawIDToken, oidc.WithExpectedNonce(saved.Nonce))

// after
challenge, _ := prov.BeginAuth(state)
save(state, challenge.Session)          // one value; CallbackSession is JSON-tagged
// ... at the callback:
token, idToken, err := prov.ExchangeAndVerify(ctx, code, oidc.CallbackSession{
    Nonce:        saved.Nonce,
    CodeVerifier: saved.CodeVerifier,
})
```

On the `BeginAuthSession`/`CompleteAuthSession` path there is nothing to
assemble: pass the `CallbackSession` that `CompleteAuthSession` returns straight
to `ExchangeAndVerify`.

`ExchangeAndVerify` also extracts `id_token` from the token response itself, so
the `token.Extra("id_token").(string)` step (and its own error branch) goes away.

**`ExchangeAndVerify` fails closed on an empty `Nonce` or `CodeVerifier`, before
any network call.** A state entry written by an older version of your app — one
that stored only one of the two, or neither — will therefore fail the callback
rather than complete an unbound exchange. In-flight logins at the moment of
deploy are the realistic case; they surface as a failed login and a retry.

**An ID token with no `nonce` claim is now rejected.** Under the old API, a
token carrying no nonce verified successfully when `WithExpectedNonce` was
omitted, because the `GetAuthURL` flow never requested one. With `GetAuthURL`
gone, every authorization request this package builds carries a nonce, so a
response without one means the provider dropped the binding.

### 4. One database handle type

`store.NewRoleTemplateRepository` and `store.NewOIDCConfigRepository` now take
`*sql.DB`, like every other constructor in the package.

```go
// before
roleRepo := store.NewRoleTemplateRepository(sqlx.NewDb(db, "postgres"))
// after
roleRepo := store.NewRoleTemplateRepository(db)
```

If you already hold a `*sqlx.DB`, pass its embedded `.DB`. Both repositories
still use `sqlx` internally for db-tag struct scanning; it is no longer part of
the contract, so a consuming application no longer builds and threads two handle
types for one identity layer.

### 5. Scope types

`GlobalScopes` and `OrgScopes` are new named `[]string` types in
`identity/auth`. The accessors that produce a scope set are now typed:

| Accessor | Returns |
| --- | --- |
| `OrganizationRepository.GetUserCombinedScopes` | `auth.GlobalScopes` |
| `models.UserWithOrgRoles.GetAllowedScopes` | `auth.GlobalScopes` |
| `OrganizationRepository.GetUserScopesForOrg` | `auth.OrgScopes` |
| `models.UserWithOrgRoles.GetScopesForOrg` | `auth.OrgScopes` |

`TokenManager.Generate` takes `GlobalScopes`; `TokenManager.GenerateForOrg` takes
`OrgScopes`. **Most call sites need no change**: a named slice type and `[]string`
are mutually assignable in Go, so passing one of these values to your own
`[]string` parameter (or a `[]string` literal to either `Generate` variant) still
compiles. What no longer compiles is the one wiring that matters — handing the
cross-organization union to `GenerateForOrg`, which mints an org-BOUND token (the
shape `HasScopeInOrg` honours) carrying another organization's scopes. Doing that
now requires writing `auth.OrgScopes(global)` explicitly, which is greppable and
reviewable.

The places this does surface as a compile error are `reflect.DeepEqual` against a
`[]string` literal and type switches, both of which are almost always in tests.

### 6. `store.OrgScope` — tenancy is now a required parameter, not an optional filter

**BREAKING, and every call site is a compile error.** Issues
[#138](https://github.com/sethbacon/terraform-suite-identity/issues/138),
[#160](https://github.com/sethbacon/terraform-suite-identity/issues/160),
[#161](https://github.com/sethbacon/terraform-suite-identity/issues/161),
[#162](https://github.com/sethbacon/terraform-suite-identity/issues/162).

v0.21.0 closed the cross-tenant read class for `audit_logs` with `AuditScope`: a
value type with a fail-closed zero value, made a required parameter, applied as a
SQL predicate. That fix was correct and it stopped at one table — even though
`audit_scope.go`'s own package doc argued the defect is a CLASS of
(resource x access axis). `api_keys`, `organizations`, `organization_members` and
`users` were the unfixed remainder: `GetAPIKeyByID` returned any organization's
row *including its bcrypt `key_hash`*, `Update` rewrote any organization's key
scopes and expiry, `RevokeAPIKey` deleted any organization's key, and
`GetUserOrganizations` disclosed a user's complete cross-tenant membership list
to any flat `users:read` holder — all on a bare id a handler naturally binds from
a path parameter.

#### `AuditScope` is now `OrgScope`

One type, not one per table. Mechanical rename:

| Removed | Use instead |
| --- | --- |
| `store.AuditScope` | `store.OrgScope` |
| `store.AuditScopeOrganizations` | `store.OrgScopeOrganizations` |
| `store.AuditScopeOrganizationsAndUnowned` | `store.OrgScopeOrganizationsAndUnowned` |
| `store.AuditScopeAllOrganizations` | `store.OrgScopeAllOrganizations` |

Semantics are unchanged, with two additions: ids are now **deduplicated and
sorted** (so the bound argument is a function of the set, not of map iteration
order), and `OrgScope.WithUnowned()` widens an existing scope in place of
unpacking and rebuilding it.

> **Check your source-scanning tests.** `terraform-state-manager`'s
> `TestNoPlatformWideAuditScopeInHandlers` greps for the literal string
> `"AuditScopeAllOrganizations"`. After this rename it keeps compiling and keeps
> passing while checking nothing. Update the literal or the guard is gone.

#### The three things you no longer have to write yourself

These are the point of the release. Both consumers had hand-rolled all three,
because the one remedy shape they were told to copy — `AuditScope.sqlPredicate` —
was **unexported**.

1. **The resolver.** `OrganizationRepository.OrgScopeForUser(ctx, userID,
   required, rwPairs)` returns the organizations in which the user's ROLE
   TEMPLATE grants `required`. It replaces
   `terraform-registry-backend/backend/internal/tenantscope`'s membership branch
   and `terraform-state-manager-backend/backend/internal/api.adminOrgSet`
   verbatim. It deliberately does NOT decide whether the caller is platform-wide
   — that is a property of the token or of an API key's organization binding,
   neither of which the store layer can see. Keep that branch in your resolver
   and call `OrgScopeAllOrganizations()` for it.
2. **The predicate builder.** `OrgScope.SQL(column, paramIndex) (clause, args)`
   is now exported, so you can scope **your own** organization-owned tables
   (registry: modules, providers, SCM providers; state-manager: states, sources)
   with the same expression this package scopes its own with. The clause is
   never empty — `TRUE` for platform-wide, `FALSE` for a scope that matches
   nothing — so appending it can never degrade into an unfiltered statement.
   `paramIndex` is `len(args)+1` at the splice point; append the returned `args`
   slice unconditionally.
3. **The in-memory check.** `OrgScope.PermitsOrganization` (unchanged) for rows
   you have already loaded.

#### What a refused access looks like

Uniformly `store.ErrNotFound` (v0.24.0's sentinel), on **every** axis including
create — never a distinct "forbidden". A caller able to tell "exists but not
yours" from "does not exist" has an existence oracle over other tenants' ids,
which is the disclosure half of this same class. List axes return an empty slice
or a zero count.

#### Migrating a call site

Every scoped accessor gained a trailing `scope store.OrgScope` parameter, so the
compiler names each site. For each one, answer *whose tenancy is this?*

- A route already behind a per-organization guard: pass the scope you resolved
  for that guard.
- An authority-derivation path (login, API-key authentication, a middleware that
  is itself the tenant check): pass `store.OrgScopeAllOrganizations()`. It is
  greppable, which "no argument" was not.
- A background job with no principal: `store.OrgScopeAllOrganizations()`.

Accessors deliberately left **unscoped** are marked `UNSCOPED BY DESIGN` in their
doc comment with the reason: authority derivation (`GetUserMemberships`,
`GetUserCombinedScopes`, `GetUserScopesForOrg`, `GetAPIKeysByPrefix`,
`GetUserByOIDCSub`, `GetOrCreateUserFromOIDC`, `GetUserByEmail`), authentication
bookkeeping (`UpdateLastUsed`), unattended maintenance (`DeleteExpiredKeys`,
`FindExpiringKeys`, `ClaimExpiryNotification`), bootstrap
(`GetDefaultOrganization`), and the two creates with no owning organization to
check against (`OrganizationRepository.Create`, `UserRepository.CreateUser`).

#### Renamed accessor

`APIKeyRepository.ListAll` is now **`ListAPIKeys(ctx, scope)`**. With a scope
parameter the old name is a contradiction (`ListAll(ctx,
OrgScopeOrganizations("a"))`), and both consumers were filtering its result in
memory against a hand-computed admin-organization set — that filter is now the
query's own predicate.

#### Signature changes with a changed RETURN type

`OrganizationRepository.RemoveAllMembershipsForUser(ctx, userID, scope)` now
returns `(OrgScope, error)` instead of `(int64, error)`: the organizations whose
membership it **actually removed**. See the next section for why.

#### The users table

`users` carries no `organization_id`, so its predicate is an `EXISTS` over
`organization_members` — "shares an in-scope organization with the caller", which
is what `terraform-state-manager`'s `requireSharedOrgAdminWithTargetUser` already
computes in Go.

**One behaviour change to decide on.** A user with NO memberships is now DENIED
by a plain organization scope, where that middleware allowed it through ("nothing
cross-tenant to protect against"). To keep the old behaviour, say so at the call
site with `OrgScopeOrganizationsAndUnowned(...)` / `.WithUnowned()` — on this
table the unowned axis means "a user belonging to no organization".

### 7. SCIM deprovisioning: the credential sweep now matches the membership strip

Issues #160 and #162 are one defect with two halves and are fixed together.

SCIM deactivation strips memberships and revokes the credentials those
memberships backed. Before v0.25.0 the two halves disagreed about tenancy: the
registry's strip was tenant-scoped (its #719) while the sweep beside it reached
`RevokeAPIKey` per key with no scope, so a holder of `scim:provision` — obtainable
through membership in a SINGLE organization — irreversibly deleted `api_keys`
rows owned by organizations they had no relationship with. `terraform-state-manager`
had neither half scoped.

Narrowing the sweep must not reintroduce the **stranded credential** defect that
motivated it (registry #732/#736): a key that outlives the authority it was
issued under keeps working from a stale snapshot. The two halves therefore share
one scope, and the second is derived from the first:

```go
removed, err := orgRepo.RemoveAllMembershipsForUser(ctx, userID, scope)
if err != nil {
    return err
}
n, err := keyRepo.RevokeAPIKeysForUser(ctx, userID, removed)
```

`removed` is the set of organizations whose membership was **actually** removed —
not the ones the caller asked about — returned as an `OrgScope` so it is directly
passable to the sweep. A key is revoked exactly when the authority behind it was
just withdrawn, in the same organization, in the same request:

- **Not too wide** — no membership removed in an organization means no authority
  reduced there, so that organization's keys are left alone (#160).
- **Not too narrow** — every organization where authority WAS reduced is, by
  construction, in the sweep's scope, so nothing is stranded (#732/#736).

Replace per-key `RevokeAPIKey` loops in deprovisioning with the single
`RevokeAPIKeysForUser` call. A caller that wants the old count reads
`len(removed.OrganizationIDs())`; one that wants to log WHICH organizations were
touched now can, which the old `int64` never allowed.
### 6. Migration `000007` — a `DELETE` no longer re-homes the rows it leaves behind

This is the behavioural half of the release (issue #142). Three referencing
columns were `ON DELETE SET NULL`, and on all three `NULL` was already a value
the readers *interpret* rather than an inert "the parent went away" marker:

| Column | What `NULL` already meant | What a parent delete therefore did |
| --- | --- | --- |
| `audit_logs.organization_id` | the platform/unowned bucket, which `AuditScopeOrganizationsAndUnowned` widens a read to admit **on purpose** | published a deleted organization's entire audit history — actions, resource ids, IP addresses, JSONB metadata — to every other tenant's admins |
| `audit_logs.user_id` | "no actor" (a system action) | erased attribution at the moment — account removal — when the trail's non-repudiation value is what is being relied on |
| `api_keys.user_id` | "organization **service** credential", which the registry's namespace authorizer exempts from any membership check | promoted a deleted user's personal keys into unattributable, permanently valid organization credentials |

`organization_members.role_template_id` keeps `SET NULL`: there `NULL` means *no
scopes at all*, strictly less authority and exactly what
`UpdateMemberRoleTemplate(nil)` sets deliberately.

#### What the migration does

- **Drops** the foreign keys on `audit_logs.user_id` and
  `audit_logs.organization_id`. Those columns are a historical record of who
  acted and for which organization *at the time*, not live references. Every
  `ON DELETE` action a foreign key can offer is wrong for one — `SET NULL`
  re-homes, `CASCADE` destroys the evidence, `RESTRICT` makes the record's own
  subject undeletable — so the values stay and the constraint goes. A deleted
  organization's rows keep its id, match no member's scope, and remain readable
  only through the explicit `AuditScopeAllOrganizations()`. **No read semantics
  change.**
- **Changes** `api_keys.user_id` to `ON DELETE CASCADE`. A credential must not
  outlive its principal, and must never change authority *class* on the way out.
- **Adds** `audit_logs.actor_email` and backfills it, so attribution survives the
  `users` row.

#### Required: two consumer-side code changes

1. **`StreamAuditLogs` projects one more column.** The export axis hands you raw
   `*sql.Rows` to scan yourself, and `al.actor_email` is now **column 10**,
   between `created_at` and the joined `user_email`/`user_name`. Add the
   destination in that position or the scan fails with
   `sql: expected 12 destination arguments in Scan, not 11`:

   ```go
   rows.Scan(
       &entry.ID, &entry.UserID, &entry.OrganizationID, &entry.Action,
       &entry.ResourceType, &entry.ResourceID, &metadataJSON, &entry.IPAddress,
       &entry.CreatedAt,
       &entry.ActorEmail, // new in v0.25.0
       &entry.UserEmail, &entry.UserName,
   )
   ```

   `ListAuditLogs` and `GetAuditLog` scan internally and need no change; they
   populate the new `models.AuditLog.ActorEmail` field for you.

2. **Do not depend on `CreateAuditLog` failing to detect an unresolvable id.**
   A caller that wrote an audit entry, caught the foreign-key error, nulled the
   actor columns and retried is now on a path that no longer triggers: the
   insert succeeds and the id is stored as written. Decide explicitly instead —
   either resolve the id first and pass `nil` when it does not exist locally, or
   accept that the entry stays stamped and is therefore readable only with
   `AuditScopeAllOrganizations()`. Set `AuditLog.ActorEmail` yourself for an
   actor this database holds no `users` row for.

   (`terraform-state-manager`'s `/audit/ingest` handler has exactly this shape.)

#### Recommended: sweep credentials before deleting a user, still

`ON DELETE CASCADE` on `api_keys.user_id` is a **backstop**, not a replacement
for the sweep. It cannot revoke a JWT whose scopes were embedded at login, and it
runs after the fact. Keep sweeping first; the database now fails closed if the
sweep is skipped, fails, or is bypassed by raw SQL.

#### Deploy step: rows already in the manufactured state

The migration **cannot repair history**. A row that was re-homed before you
upgraded is indistinguishable from one written that way on purpose, so this is an
inventory decision, not something DDL can make. Run both queries before or just
after the deploy:

```sql
-- Audit rows with no owning organization. Expected only for entries your app
-- writes unowned by design (terraform-state-manager's logins, state-file and
-- source actions). Anything else is a formerly-owned row that a past
-- organization delete moved into the platform bucket, and it is readable today
-- by every admin whose scope includes unowned rows.
SELECT date_trunc('day', created_at) AS day, action, count(*)
  FROM identity.audit_logs
 WHERE organization_id IS NULL
 GROUP BY 1, 2
 ORDER BY 1 DESC;

-- API keys with no owning user. Expected only for organization service
-- credentials you created that way. Anything else is a deleted user's personal
-- key that is still authenticating.
SELECT id, organization_id, name, key_prefix, created_at, last_used_at
  FROM identity.api_keys
 WHERE user_id IS NULL
 ORDER BY created_at;
```

Rows in the first result that predate a known organization deletion should be
deleted or moved out of the live table; rows in the second that are not a
deliberate service credential should be revoked.

#### Rollback

`000007`'s down migration is **best-effort and lossy**, and self-labels as such.
Re-creating the old foreign keys requires every value to resolve again, so it
must first null every `audit_logs` row whose organization or user was deleted
while `000007` was applied — re-opening the leak for exactly the history that was
being retained — and it drops `actor_email`. Prefer rolling forward. To size the
loss first:

```sql
SELECT count(*) FROM identity.audit_logs al
 WHERE al.organization_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM identity.organizations o WHERE o.id = al.organization_id);
```
### 6. Schema routing must now be asserted at startup

**No migration. No compile error. This is the one item in v0.25.0 that requires
you to ADD code**, and it is the only item whose omission is silent.

This module's repositories address every table unqualified (`FROM users`) while
its migrations create every table qualified (`identity.users`), so which physical
table a read reaches is decided by the `search_path` of the `*sql.DB` you supply.
Both routings are supported and both are in use:

| `search_path` | Repositories read and write |
| --- | --- |
| `identity,public` | the shared `identity` schema |
| `"$user", public` (server default) | the app's own tables in `public` |

Nothing checked that the connection selected the one you meant. The benign
failure is `relation "users" does not exist`. The dangerous one is the situation
both consuming applications are actually in: identity-**shaped** tables of their
own (`public.users`, `public.organizations`, `public.api_keys`,
`public.audit_logs`, …) in the same database as `identity.*`. A misordered
`search_path` routes authentication reads and provisioning writes to the legacy
tables and **succeeds** — same names, compatible columns, no error — leaving a
split-brain identity store where a user removed from one set is still live in the
other. Where the two settings are independent knobs (migrations on, `search_path`
off is a reachable configuration), that is a one-variable mistake.

Add the assertion once, at startup, on the **same pool the repositories are
constructed over**, naming the schema this deployment intends:

```go
// Shared identity schema (pool carries search_path=identity,public).
if err := identity.VerifySchemaRouting(ctx, identityDB, identity.SchemaName); err != nil {
    return err // refuse to serve rather than read the wrong users table
}

// App-owned identity tables (plain pool, shared schema not enabled).
if err := identity.VerifySchemaRouting(ctx, identityDB, "public"); err != nil {
    return err
}
```

Both calls are worth making. The value is that the deployment **states** which
routing it means, so the configuration knobs that select it can no longer
disagree in silence. If your app gates the shared schema behind a flag, pass the
schema that flag selects — the assertion then fails on exactly the
half-configured combination.

Do **not** put it on the migration pool. The migrations are schema-qualified and
do not care about `search_path`; a consumer that migrates on a plain connection
is correct to do so, and asserting there would fail a working deployment.

`identity.ResolveRouting(ctx, db)` returns the same information without failing —
the `search_path` and the schema each table resolved to. Log it at startup: it is
one line that says which physical tables the identity layer is about to use.

### 7. `notification_channels` — the contract is now executable

**No migration, deliberately.** `identity/notify` reads and writes a
`notification_channels` table that this module does **not** create. That has not
changed, and the reason it has not is worth stating, because shipping the
migration is the change in this area that looks obviously right and is not:

> Both consuming applications already hold live `notification_channels` rows, in
> `public`, created by their own migration sets. A migration here would create a
> **second, empty** `identity.notification_channels`, and every connection whose
> `search_path` puts `identity` first — precisely the connection a consumer would
> move this repository onto once the module claimed the table — would silently
> re-point from the populated table to the empty one. Same statement, no error,
> no rows. Moving rows across schemas is a consumer deploy step against a
> database this module does not own, so the module cannot make that change safely
> and does not attempt to.

What is new is that the contract is no longer prose:

- **`notify.ChannelTableDDL`** is the canonical `CREATE TABLE` statement. Apply
  it from **your own** migration set. It is unqualified, so your migration
  connection's `search_path` places it — the same rule that decides where the
  repository later looks. This module's own integration tests execute this exact
  statement and then drive every `ChannelRepository` method against the result,
  so it cannot drift from the code that uses it.
- **`notify.VerifyChannelTable(ctx, db)`** asserts, at startup, that the table
  the repository will address exists and has the columns, types and nullability
  its statements require, and **returns the schema-qualified name it resolved
  to**. Log that name. It is the line that makes a re-point visible.

```go
channelTable, err := notify.VerifyChannelTable(ctx, appDB) // the pool the repo uses
if err != nil {
    return err
}
slog.Info("notification channels", "table", channelTable)
```

Nullability is asserted, not just types: the DAO scans `id`, `name`, `type`,
`encrypted_target`, `events`, `enabled`, `created_at` and `updated_at` into
non-pointer Go values, so a nullable column there is a scan failure waiting for
its first NULL. `character varying(n)` satisfies a `text` requirement — every
statement here behaves identically on both — but `json` does not satisfy `jsonb`
(the fan-out query uses `jsonb_array_length` and `@>`), `bytea` does not satisfy
`text`, and `timestamp without time zone` does not satisfy `timestamptz`.

**If your table already matches, there is nothing to run.** Both shipped
consumers' tables do. If it does not, reconcile it in your own migration set
against `ChannelTableDDL` **before** deploying the bump, so the new assertion
does not fail the boot that introduces it:

1. Diff your `notification_channels` against `notify.ChannelTableDDL`.
2. If it differs, add a migration in **your** repository that reconciles it, and
   deploy that migration **first** — its own release, before the identity bump.
3. Only then take the identity v0.25.0 bump and add the
   `VerifyChannelTable` call.

**If you decide to move the table into the `identity` schema** — this module does
not ask you to, and does not support it with DDL — the row migration is yours and
its ordering is not optional:

1. Create `identity.notification_channels` from `ChannelTableDDL` on a connection
   whose `search_path` is `identity`.
2. `INSERT INTO identity.notification_channels SELECT * FROM public.notification_channels;`
   **while nothing is writing** — the sealed targets are capability-bearing
   secrets and a partial copy silently disables the channels it missed.
3. Only then move the `ChannelRepository`'s pool to the identity-first
   connection, and confirm with the name `VerifyChannelTable` returns.
4. Keep `public.notification_channels` until step 3 is verified in production.
   Dropping it first turns a rollback into a restore.
### 6. `mailer.Config.UseTLS` is now `TLSMode`, and its zero value encrypts

**Compile error at every call site.** The field is gone, so nothing silently
changes polarity.

`mailer.Config` was the one type in this module whose zero value was the LESS
secure choice. `mailer.Config{Host: h, Port: p, From: f}` — the minimal literal
anyone writes from the field list — left `UseTLS` false, and `Send` then kept
the connection in plaintext and never upgraded. Everything else here fails
closed: `httpsafe.Guard`'s zero value is strict-deny, `oidc.Config` requires an
HTTPS issuer unless `AllowInsecureIssuer` is set, `store.AuditScope`'s zero value
denies everything, `suite.NewDiscoveryClient` refuses a plaintext sibling URL.

| Before | After |
| --- | --- |
| `UseTLS: true` | `TLSMode: mailer.TLSRequired` (or omit the field — this is the zero value) |
| `UseTLS: false` | `TLSMode: mailer.TLSDisabled` |
| `cfg.UseTLS = b` | `cfg.TLSMode = mailer.TLSModeForUseTLS(b)` |

`TLSModeForUseTLS` exists for the case both consumers actually have: a `use_tls`
boolean in a YAML file, in a persisted JSON settings blob and in an admin API
body, none of which can change shape. Use it rather than writing the conditional
at each call site — the polarity is then in one tested place instead of several
hand-written ones.

**Transport behaviour is unchanged** for every configuration that named its
choice. `TLSRequired` does exactly what `UseTLS: true` did (implicit TLS, falling
back to STARTTLS on dial failure, never a silent unencrypted send) and
`TLSDisabled` exactly what `UseTLS: false` did (plaintext, never opportunistically
upgraded).

One behaviour is genuinely new: `Send` now **refuses, before dialling**, to
carry a password over a plaintext connection to a non-local relay
(`TLSDisabled` plus a non-empty `Username`). `net/smtp`'s `PlainAuth` already
refused this, so no configuration that worked before stops working — the
refusal simply arrives earlier, names the setting at fault, and belongs to this
package rather than to whichever auth mechanism `authFor` happens to return. A
plaintext relay on `localhost`/`127.0.0.1`/`::1` is still permitted and now logs
a warning.

#### Check your JSON decode path

Worth an explicit look while migrating. A `use_tls` key that is ABSENT from a
persisted settings blob or a `PUT` body decodes into a plain Go `bool` as
`false`, indistinguishable from an explicit `false` — so a startup path that
assigns that bool over a config default of `true` downgrades the deployment to
plaintext with nothing logged. Decode into a `*bool` and leave `TLSMode` at its
zero value when the key is absent.

### 7. `auth.MaxAPIKeyPrefixLength` is 7 (was 20)

**Compile-safe; a runtime error only for callers minting keys with a prefix
longer than 7 bytes.** Both shipped consumers use 3-byte prefixes (`"tfr"`,
`"tsm"`) and are unaffected. **No existing key is invalidated** — the display
prefix is still `fullKey[:DisplayPrefixLength]`, unchanged.

The persisted `key_prefix` is the sole narrowing predicate of the authentication
lookup, and each row it returns costs the host one bcrypt comparison at
`BcryptCost`. Because the display prefix is the first 10 bytes of
`"<prefix>_<randomPart>"`, a caller-supplied prefix of 9 bytes or more filled
that window completely: `key_prefix` then contained no random characters at all
and was byte-identical for every key the application ever issued. The prefix is
public by design (it is shown in UIs), so anyone could present it and select
every live key as a bcrypt candidate.

The old cap of 20 was derived correctly from bcrypt's 72-byte input window; it
simply predated anyone noticing that a second, tighter window also applied. Both
limits are now enforced together by a compile-time assertion in
`identity/auth/apikey.go`, so the cap cannot be raised back into the degenerate
range without failing the build.

If you mint keys with a longer prefix, shorten it. Existing keys keep
authenticating, but see the next item before assuming that is the end of it.

### 8. `GetAPIKeysByPrefix` is bounded and reports a non-discriminating prefix

`APIKeyRepository.GetAPIKeysByPrefix` now caps its query and returns an error
wrapping the new `store.ErrPrefixNotDiscriminating` when one prefix matches more
than 100 live keys, instead of returning the whole set.

This is for rows already in your table. Tightening the cap above fixes keys
minted from now on; it cannot retroactively fix a `key_prefix` persisted when a
long prefix was permitted. The bound is what stops one of those from still
fanning a single unauthenticated request across the entire table.

A correctly configured deployment cannot reach it — with at least two random
characters in every minted prefix, 100 keys in one bucket takes on the order of
400,000 live keys. If you DO see this error, it is not load and will not pass:
the affected keys were minted with an over-long prefix and must be re-issued.
Treat it as deny-and-alert, not deny-and-retry. Note the refusal returns `nil`
keys, so a caller that checks the error will not enter the bcrypt loop.

---

## v0.24.0 — `store.ErrNotFound`: not-found is no longer silent

**BREAKING. No migration.** Every consuming application needs a code review pass
before upgrading — and, critically, **most of the affected call sites still
compile**.

### What changed

Three related contracts:

1. **Reads that miss now return an error wrapping `store.ErrNotFound`**, where they
   previously returned `(nil, nil)`.
2. **By-identifier `UPDATE`/`DELETE`s that match zero rows now return an error
   wrapping `store.ErrNotFound`**, where they previously returned `nil` (success).
3. **Bulk sweeps now return their affected-row count** — a signature change, so
   these are the only ones the compiler catches for you.

`models.OIDCConfig.GetScopes()` also gained an `error` return (it previously
discarded a JSON-unmarshal failure and fell back to the default scopes exactly as
if the column had been empty).

### Why it is breaking in a way the compiler will not tell you

`return nil, nil` becoming `return nil, ErrNotFound` changes no signature, and the
mutators already returned `error`. **A consumer that does**

```go
x, err := repo.GetThing(ctx, id)
if err != nil {
    c.JSON(http.StatusInternalServerError, ...)   // was: only reached on a real failure
    return
}
if x == nil {
    c.JSON(http.StatusNotFound, ...)              // now: DEAD CODE
    return
}
```

**still builds, and turns every previously-correct 404 into a 500.** The same
shape appears in existence probes (`GetUserByEmail` before creating a user,
`GetByName` before creating an organization, `GetMember` before adding a member),
where not-found is the HAPPY path — those become unconditional 500s.

### The migration, in order

**Step 1 — fix the compile errors.** These four signatures changed:

| Before | After |
| --- | --- |
| `APIKeyRepository.DeleteExpiredKeys(ctx) error` | `(ctx) (int64, error)` |
| `OrganizationRepository.RemoveAllMembershipsForUser(ctx, userID) error` | `(ctx, userID) (int64, error)` |
| `OIDCConfigRepository.DeactivateAllOIDCConfigs(ctx) error` | `(ctx) (int64, error)` |
| `TokenRepository.CleanupExpiredRevocations(ctx) error` | `(ctx) (int64, error)` |
| `models.OIDCConfig.GetScopes() []string` | `() ([]string, error)` |

`if err := repo.X(ctx); err != nil {` becomes `if _, err := repo.X(ctx); err != nil {`
(or keep the count and log it).

**Step 2 — grep for the dead nil branch.** Every site of the form
`if err != nil { … }` followed by `if value == nil { … }` needs the two branches
merged or reordered:

```go
x, err := repo.GetThing(ctx, id)
if errors.Is(err, store.ErrNotFound) {
    c.JSON(http.StatusNotFound, ...)
    return
}
if err != nil {
    c.JSON(http.StatusInternalServerError, ...)
    return
}
```

A site already written as `if err != nil || x == nil { … }` keeps working
unchanged — the collapsed check absorbs the new error.

**Step 3 — fix the existence probes.** Anywhere not-found is the SUCCESS case
("is this email free?", "is this name taken?", "is this user already a member?"),
invert the check:

```go
existing, err := repo.GetUserByEmail(ctx, email)
switch {
case err == nil:
    // taken
case errors.Is(err, store.ErrNotFound):
    // free — proceed
default:
    return err
}
```

**Step 4 — make the idempotent loops idempotent again.** SCIM/IdP reconciliation
and deprovisioning loops that call `RemoveMember`, `UpdateMemberRole` or
`RevokeAPIKey` over a set will now abort on the first already-applied element.
Treat `store.ErrNotFound` as "already in the desired state" and continue:

```go
if err := orgRepo.RemoveMember(ctx, orgID, userID); err != nil &&
    !errors.Is(err, store.ErrNotFound) {
    return err
}
```

**Step 5 — decide about repeat DELETEs.** A handler with no prior existence check
that deletes by id (users, organizations, notification channels) now returns an
error on the second call. Either pre-check, or map `store.ErrNotFound` to 404 (or
to 204 if you want the endpoint to stay idempotent).

### Accessors whose behaviour changed

Reads (`(nil, nil)` → `ErrNotFound`): `UserRepository.GetUserByID`,
`GetUserByEmail`, `GetUserByOIDCSub`, `GetUserWithOrgRoles`;
`OrganizationRepository.GetByID`, `GetByName`, `GetDefaultOrganization`,
`GetMember`, `GetMemberWithRole`; `APIKeyRepository.GetAPIKeyByHash`,
`GetAPIKeyByID` (and its `GetByID` alias); `OIDCConfigRepository.GetActiveOIDCConfig`,
`GetOIDCConfig`; `RoleTemplateRepository.GetRoleTemplate`, `GetRoleTemplateByName`
(and its `GetByID` alias); `AuditRepository.GetAuditLog`;
`notify.ChannelRepository.GetByID`, `Update`.

Mutations (`nil` on zero rows → `ErrNotFound`): `UserRepository.UpdateUser`,
`DeleteUser` (and the `Update`/`Delete` aliases); `APIKeyRepository.RevokeAPIKey`
(and `Delete`), `Update`, `UpdateLastUsed`, `MarkExpiryNotificationSent`;
`OrganizationRepository.RemoveMember`, `UpdateMemberRoleTemplate` (and
`UpdateMemberRole`/`UpdateMember`), `Update`, `Rename`, `Delete`;
`OIDCConfigRepository.DeleteOIDCConfig`, `UpdateOIDCConfigExtraConfig`,
`ActivateOIDCConfig`; `notify.ChannelRepository.Delete`, `RecordDelivery`.
`RoleTemplateRepository.UpdateRoleTemplate`/`DeleteRoleTemplate` already errored
on zero rows; their errors now WRAP `ErrNotFound`, so one `errors.Is` covers the
whole package.

`ActivateOIDCConfig` additionally **rolls back** on a miss. Previously, activating
a non-existent id committed the deactivate-all step on its own and returned `nil` —
a deployment silently lost SSO while the admin API reported success.

### What did NOT change

- List and search accessors still return an empty slice and a `nil` error.
- `CheckMembership` still returns `(false, nil, nil)` for a non-member, and
  `GetUserScopesForOrg` still returns an empty scope set. Both absorb the sentinel
  deliberately; both still surface a real database failure.
- `RevokeToken` is still idempotent (zero rows means "already revoked").
- No tenancy semantics changed. That is a separate release.

### Why this shipped first

A write that carries a tenant predicate and matches no row means "that row is not
yours". Without a distinguishable zero-row result, adding such a predicate would
**fail open**: the caller would be told the write succeeded precisely when the
guard stopped it. This release is what makes that guard meaningful.

---

## v0.23.0 — migration `000006_hot_path_indexes`

**Non-breaking.** No exported signature changed. Applying the release requires no
code change in a consuming application.

### What it does

Adds six indexes to the `identity` schema:

| Index | Table (column) | Why |
| --- | --- | --- |
| `idx_identity_audit_logs_org_created_at` | `audit_logs (organization_id, created_at DESC)` | The mandatory tenant predicate (`AuditScope` in v0.21.0, `OrgScope` since v0.25.0) plus the audit page's `ORDER BY` |
| `idx_identity_organization_members_user_id` | `organization_members (user_id)` | Membership/scope resolution on every login and token mint |
| `idx_identity_organization_members_role_template_id` | `organization_members (role_template_id)` | `ON DELETE SET NULL` from `role_templates` |
| `idx_identity_api_keys_organization_id` | `api_keys (organization_id)` | `ListAPIKeysByOrganization`; `ON DELETE CASCADE` from `organizations` |
| `idx_identity_api_keys_user_id` | `api_keys (user_id)` | `ListAPIKeysByUser`; `ON DELETE SET NULL` from `users` |
| `idx_identity_revoked_tokens_user_id` | `revoked_tokens (user_id)` | `ON DELETE CASCADE` from `users`, on a table that grows with traffic |

### Action required if you have live audit volume

The migration uses plain `CREATE INDEX`, **not** `CREATE INDEX CONCURRENTLY`.
That is deliberate — golang-migrate sends each migration file to PostgreSQL as
one statement, which runs in an implicit transaction block, and `CONCURRENTLY`
is rejected outright there; and a `CONCURRENTLY` build that fails leaves an
`INVALID` index behind that `CREATE INDEX IF NOT EXISTS` then skips forever.

A plain `CREATE INDEX` takes a `SHARE` lock: reads continue, **writes to the
table block for the duration of the build**. On a new or small database that is
milliseconds. On a large existing `audit_logs` it is not, and the block lands on
your API's startup path.

If `identity.audit_logs` is large, build the indexes out of band **before**
deploying, using the same names. The migration's `IF NOT EXISTS` clauses then
find them already present and it becomes a no-op:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_audit_logs_org_created_at
    ON identity.audit_logs (organization_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_user_id
    ON identity.organization_members (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_organization_members_role_template_id
    ON identity.organization_members (role_template_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_organization_id
    ON identity.api_keys (organization_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_api_keys_user_id
    ON identity.api_keys (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_revoked_tokens_user_id
    ON identity.revoked_tokens (user_id);
```

Run each statement on its own connection, outside any transaction, then verify
none landed invalid:

```sql
SELECT c.relname
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
WHERE NOT i.indisvalid AND c.relname LIKE 'idx_identity_%';
```

Drop and rebuild any index that row set names.

### Rollback

`000006`'s down migration drops exactly these six indexes and nothing else. It
is index-only, so the rollback is complete rather than best-effort.

### Also in this release: the revocation denylist self-bounds

`TokenRepository.RevokeToken` now prunes expired rows from `revoked_tokens` as
part of the write that grows it — at most once an hour per process, in bounded
batches, keeping rows for one hour past the denied token's own expiry (clock
skew and verifier leeway), and never failing the revocation if the prune fails.

No wiring is required and nothing needs to be scheduled.
`CleanupExpiredRevocations` is unchanged and still available; a host that
already schedules it can keep doing so (it remains an immediate, ungraced sweep)
or drop its ticker.
