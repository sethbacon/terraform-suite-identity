# Suite Coupling Contract

The `identity/suite` package defines the **runtime coupling contract** between the
two Terraform Suite applications — the registry (`terraform-registry`) and the
state manager (`terraform-state-manager`). When an operator deploys them together,
each app needs to discover the other, agree that they speak a compatible protocol,
and report whether the link is healthy — without either app taking a build-time
dependency on the other.

The package deliberately has **no application or web-framework dependencies**, so
both apps import it identically and the contract cannot drift between them
(`identity/suite/manifest.go`). It is the runtime counterpart to the **shared
identity store** described in [docs/schema.md](schema.md): the schema makes the
two apps *agree on who a user is*; this package makes them *find and negotiate
with each other*.

There are four pieces:

- the **capability manifest** each app publishes,
- **version negotiation** (`NegotiateCompat`),
- the **discovery client** state machine, and
- **`CanonicalHost`**, the host-folding helper that makes the "Consumed by" join
  robust.

---

## The manifest contract

Each app serves a self-description at:

```text
GET /api/v1/suite/manifest
```

The path is the **exported** package constant `suite.ManifestPath`
(`discovery.go`). The discovery client builds its request URL from it, and each
app **should** register its publishing route from it too:

```go
// In the publishing app's router, instead of a copied "/api/v1/suite/manifest":
router.GET(suite.ManifestPath, suiteManifestHandler(cfg))
```

Do that and the publisher and the client provably cannot diverge, because there is
one definition. **Note this is a convention the library enables, not a guarantee it
enforces**: a publisher that registers the route from a hand-copied literal — as
both consuming apps currently do — has to keep that literal in sync by hand. The
failure mode is loud but total (the sibling reports permanently `unreachable`), so
prefer the constant. Changing `ManifestPath`'s value is a breaking wire change for
every already-deployed sibling, not a refactor.

The payload is the `Manifest` struct (`manifest.go`):

```go
type Manifest struct {
    SchemaVersion string            `json:"schemaVersion"` // "suite/v1"
    App           string            `json:"app"`           // "terraform-registry"
    Version       string            `json:"version"`       // semver of the running build
    BuildDate     string            `json:"buildDate,omitempty"`
    PublicURL     UntrustedURL      `json:"publicUrl,omitempty"` // sibling-asserted; see "Trust" below
    Identity      IdentityInfo      `json:"identity"`
    Capabilities  []Capability      `json:"capabilities,omitempty"`
    Links         map[string]string `json:"links,omitempty"`
}

type IdentityInfo struct {
    Issuer      string `json:"issuer"`           // the app's JWT issuer claim
    SharedStore bool   `json:"sharedStore"`      // true only when both apps share one identity DB
    Schema      string `json:"schema,omitempty"` // identity schema name, e.g. "identity"
}

type Capability struct {
    ID string `json:"id"` // e.g. "modules.v1", "state.v1"
}
```

A registry manifest looks like:

```json
{
  "schemaVersion": "suite/v1",
  "app": "terraform-registry",
  "version": "1.2.3",
  "publicUrl": "https://registry.example.com",
  "identity": { "issuer": "terraform-registry", "sharedStore": false, "schema": "identity" },
  "capabilities": [{ "id": "modules.v1" }],
  "links": { "moduleDetail": "/modules/{namespace}/{name}/{system}" }
}
```

### Trust: every field of a *received* manifest is untrusted input

A `Manifest` plays two roles with opposite trust properties.

As the value your app hands to `NewDiscoveryClient` to describe **itself**, every
field comes from your own configuration and is trusted.

As the value `DiscoveryClient.Snapshot()` returns — the **sibling's** parsed
response — every field is asserted by the sibling. It is **not** the
operator-pinned `siblingURL` you configured, and this library does not verify
it: `NegotiateCompat` checks only `app` and the schema MAJOR, both of which
anyone who knows the target app id can satisfy. A sibling that is compromised,
that is itself tricked into echoing an attacker-chosen value, or that is simply
misconfigured with an internal address decides what these fields say.

`publicUrl` is the field consumers reuse to build **further outbound requests**,
so it carries the boundary in its Go type:

```go
type UntrustedURL string

func (u UntrustedURL) Resolve(ctx context.Context, g *httpsafe.Guard) (string, error)
func (u UntrustedURL) Display() string
```

`Resolve` validates against the deployment's egress policy and is the only way
to obtain a URL to fetch. `Display` does not validate and is for rendering and
logging only. The type will not concatenate with a string, so the check cannot
be skipped by accident.

The whole correct sequence — snapshot, notice the value is sibling-asserted,
validate it, and dial it with a client bound to the same policy — is available
as two calls on the client, and you should prefer them:

```go
base, err := dc.SiblingPublicURL(ctx)   // validated against this client's guard
if err != nil {
    return // sibling inactive, advertises nothing, or names a denied address
}
client := dc.GuardedClient(2 * time.Second) // same policy, resolve-and-pin dialing
```

Building the request with a bare `&http.Client{}` instead means Go's default
policy: no destination checks and up to ten cross-host redirects followed. That
turns "any authenticated user opens a panel" into "this backend issues a GET to
whatever address the sibling named, from inside the deployment network" —
including link-local metadata addresses. This is not hypothetical; it is the
defect issue #144 records, in a shipped consumer, against a sibling app that got
the identical field right.

`links` values are sibling-asserted too. The documented contract makes them path
*templates* (`/modules/{namespace}/{name}/{system}`), not absolute URLs, so they
stay plain strings — but a consumer that renders one into a link, or that ever
accepts an absolute URL there, owes it the same treatment. Never grant trust on
`identity.sharedStore` or `identity.issuer` alone.

`IdentityInfo.sharedStore` is the signal a sibling (and the UI) uses to decide
whether single sign-on is actually in effect — it is `true` **only** when both
apps point at one physical identity database. Features that merge data across the
apps (for example, a unified audit timeline) are only coherent under a shared
store and key off this flag.

### The additive-only rule (anti-lockstep)

The manifest **must stay additive: never remove or repurpose a field.** This is
the rule that lets the two apps ship on independent schedules:

- A newer app may add manifest fields or capabilities; an older sibling **ignores
  unknown JSON fields** (`encoding/json` does this by default — covered by
  `TestUnknownFieldsIgnored`). So advertising a new capability to an older peer is
  harmless.
- Removing or renaming a field is a breaking wire change for the *other* app and
  is forbidden within a major schema version.

Because of this rule, `SchemaVersion` carries only the **major** as its
compatibility boundary: minor/patch may evolve freely (see negotiation below).

---

## Version negotiation (`NegotiateCompat`)

Two siblings are compatible only when their schema **major** matches. The major
is the token after the slash, truncated at the first dot:

```go
Major("suite/v1")   // "v1"
Major("suite/v2.3")  // "v2"
Major("v1")          // "v1"  (no slash → returned unchanged)
```

`NegotiateCompat(self, sibling)` returns `(false, reason)` in exactly five cases
and `(true, "")` otherwise:

| Condition | Why it is rejected |
| --------- | ------------------ |
| `sibling.App == ""` | An empty app id means an unparseable or non-suite endpoint. |
| `sibling.App == self.App` | Pointing at yourself — a misconfiguration where the sibling URL resolves back to this app. |
| `Major(self.SchemaVersion) == ""` | This app's own manifest has no schema version — a construction bug here, not a sibling problem; fail closed rather than negotiate against an unknown. |
| `Major(sibling.SchemaVersion) == ""` | The sibling's manifest has no schema version, so there is nothing to compare a major against. |
| `Major(sibling.SchemaVersion) != Major(self.SchemaVersion)` | Incompatible wire protocol (e.g. `suite/v1` vs `suite/v2`). |

The two empty-version cases are what make this fail **closed**: an empty
`SchemaVersion` on either side is treated as incompatible, never as a wildcard that
matches anything.

Note what is **not** checked: the running `Version`, the capability set, and any
minor/patch of `SchemaVersion` are all irrelevant to compatibility — that is the
additive-only rule in action. Only a major schema bump (and a corresponding bump
of `SchemaVersionV1`) ever makes two builds incompatible.

---

## The discovery client state machine

`DiscoveryClient` (`discovery.go`) polls a configured sibling's manifest endpoint,
negotiates compatibility, and caches the last good result. **Construct it only
when an operator has configured a sibling URL** — absence of a URL means
"standalone", not "unreachable".

The manifest fetch carries no request auth or signature, so `NewDiscoveryClient`
fails closed on a plaintext `http://` siblingURL (returns an error instead of a
client) — only transport security defends the fetch from a network-position
attacker injecting a spoofed manifest. Use `NewInsecureDiscoveryClient` instead
only for local/dev setups where the sibling is reached over plaintext HTTP
(e.g. loopback); its name is the deliberate opt-out.

Be precise about the scope of that check: it rejects a **case-insensitive
`http://` prefix** (after trimming trailing slashes) and nothing else. A
scheme-less value such as `sibling.example.com` is accepted at construction time
and fails later at request time; an `https://` URL is accepted, as is any other
scheme. The constructor is a guard against the one mistake that silently works —
configuring plaintext HTTP — not a URL validator. Validate operator-supplied
sibling URLs in the app's own config layer.

```go
self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry", /* … */}
d, err := suite.NewDiscoveryClient("https://tfstate.example.com", self, 0) // 0 → default interval
if err != nil {
    // siblingURL used plaintext http:// — NewDiscoveryClient fails closed. Fix the
    // config, or use suite.NewInsecureDiscoveryClient for a local/dev loopback sibling.
    log.Fatal(err)
}
go d.Start(ctx)                  // poll loop until ctx is cancelled
state, manifest := d.Snapshot()  // cheap; safe per-request
```

### States

`Snapshot()` returns one of four states plus the last-good manifest (nil until the
first success):

| State | `SiblingState` | Meaning |
| ----- | -------------- | ------- |
| Unknown | `"unknown"` | Initial state — not yet polled. |
| Active | `"active"` | Last poll succeeded **and** the sibling is compatible. |
| Degraded | `"degraded"` | A poll just failed, but a prior poll succeeded within the grace window — treat the cached manifest as still usable. |
| Unreachable | `"unreachable"` | Failing beyond the grace window, never reached, or **incompatible** (negotiation failed). |

### Transition rules (`pollOnce`)

Each poll fetches the manifest (a `GET` with a **2-second timeout**), then:

1. **Fetch error** (network failure, non-200, or undecodable body):
   - if the last success was **within** the grace window → **Degraded**;
   - otherwise (never succeeded, or the grace window has elapsed) → **Unreachable**.
   The cached `lastGood` manifest is left untouched, so a degraded sibling still
   exposes its last-known capabilities.
2. **Fetch succeeds but `NegotiateCompat` fails** → **Unreachable** (an
   incompatible sibling is, for coupling purposes, no sibling).
3. **Fetch succeeds and is compatible** → **Active**; cache the manifest and stamp
   the last-success time.

```text
            success + compatible
   ┌──────────────────────────────────────────────┐
   ▼                                                │
[unknown] ──poll──▶ [active] ──fail (≤ grace)──▶ [degraded]
                       │                              │
                       │ fail (> grace)               │ fail (> grace)
                       ▼                              ▼
                 [unreachable] ◀────────────────[unreachable]
                       ▲
                       └── success but incompatible (any state)
```

### Timing defaults

| Knob | Default | Source |
| ---- | ------- | ------ |
| Poll interval | 60s | `defaultPollInterval`; overridable via the `NewDiscoveryClient` arg (non-positive → default). |
| Grace window | 5m | `defaultGraceWindow` (not configurable). |
| Per-poll HTTP timeout | 2s | `pollTimeout`. |

The grace window is what prevents a single transient blip (a slow restart, a brief
network hiccup) from flipping a healthy link straight to **Unreachable** — within
those 5 minutes the link reports **Degraded** and keeps serving the cached
manifest. The client is safe for concurrent use (an `RWMutex` guards the state),
so `Snapshot()` is cheap enough to call on every request.

---

## `CanonicalHost` — host folding for the "Consumed by" join

When the suite shows which modules a piece of state consumes (and, conversely,
which consumers a registry module has), the apps join on **host identity**. The
same registry can be referred to by hosts that differ only cosmetically: the host
captured from a Terraform module **source address**, the registry's
**service-discovery** host, and the registry's own **public** host can vary in
case, a default port, a trailing FQDN dot, an accidental scheme prefix, or Unicode
(IDN) vs punycode encoding. A naive exact-match join would miss those.

`CanonicalHost(raw)` (`host.go`) folds those variants so the exact-match join
compares like-for-like. It:

- trims whitespace, and **rejects any input containing `@`** (userinfo is never
  legitimate in a bare host-identity join key) by returning `""`;
- if a scheme slipped in (a full URL), keeps only the authority;
- splits off any port (`splitHostPort`), handling four shapes: no colon at all, a
  clean `host:port` / `[ipv6]:port`, a bare zone-scoped IPv6 literal such as
  `fe80::1%eth0`, and a `url.Parse` fallback that recovers a bare unbracketed IPv6
  literal like `::1` — while **rejecting** genuinely malformed shapes such as
  `host:443:extra`, again returning `""`;
- unwraps IPv6 brackets, so `[::1]` and `::1` fold to the same key;
- lowercases the host and removes a trailing dot;
- folds an internationalized (Unicode) host to its **punycode ASCII** form via the
  IDNA *lookup* profile, so a Unicode source address matches a punycode-stored
  host;
- canonicalizes the port **numerically**, so `:080` and `:80` fold identically and
  `:08443` becomes `:8443`; drops a **default** port (`:80` / `:443`) while
  preserving any non-default port.

```go
suite.CanonicalHost("Registry.Example.com.")         // "registry.example.com"
suite.CanonicalHost("https://registry.example.com")  // "registry.example.com"
suite.CanonicalHost("registry.example.com:443")      // "registry.example.com"
suite.CanonicalHost("registry.example.com:8443")     // "registry.example.com:8443"
suite.CanonicalHost("регистр.example")               // punycode "xn--..." form
suite.CanonicalHost("[::1]:443")                     // "::1"
suite.CanonicalHost("::1")                           // "::1"  (same key)
suite.CanonicalHost("attacker@registry.example.com") // ""     (rejected)
suite.CanonicalHost("host:443:extra")                // ""     (rejected)
```

IDN folding is **best-effort**: a host the IDNA lookup profile rejects (e.g. one
containing underscores) is left as the lowercased value rather than dropped or
mangled. A non-numeric port (`:notaport`) is likewise re-emitted verbatim.
Empty/whitespace input returns the empty string. Apply it to **both** sides of the
join (the stored host and the incoming host) so they normalize identically.

One pinned known gap: a doubled scheme (`https://https://evil.com`) is mangled
rather than rejected — `url.Parse` reads `https:` as the host, so the real host is
dropped and the result is `"https"`. It is covered by a regression test that
records the behaviour rather than blessing it.

---

## Operator notes

- **The contract is library-defined; the wiring is app-defined.** This package
  supplies the manifest type, negotiation, the discovery state machine, and
  `CanonicalHost`. *Serving* `/api/v1/suite/manifest`, deciding the sibling URL,
  and surfacing the discovery state in the UI are each app's responsibility —
  including the names of any configuration variables (e.g. the registry's
  `TFR_SUITE_*` settings).
- **A standalone app has no `DiscoveryClient`.** No sibling URL means no client
  and no polling — there is nothing to be "unreachable". Coupling is purely
  opt-in.
- **`sharedStore` is the gate for cross-app data features.** Single sign-on and
  any merged-data view are only coherent when both apps point at one physical
  identity database; the manifest's `identity.sharedStore` is how an app knows.

---

## See also

- [docs/schema.md](schema.md) — the shared identity store the coupling sits on.
- [README.md](../README.md) — packages and usage.
- `identity/suite/manifest.go`, `discovery.go`, `host.go` — the implementation,
  with `suite_test.go` / `host_test.go` for executable examples of every rule
  above.
