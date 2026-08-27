# Tenancy Model

**Status: decided (2026-08-26), including the organisation question; not yet
implemented.** This document states the target model for the whole estate. Anything
already built that contradicts it is drift, not precedent — that includes code in this
module.

Read this before changing anything that touches `organization_id`, namespace ownership,
the Terraform protocol surface, or a scoped read in either application.

---

## The two deployment models

**Model A — shared registry.** One hosting organisation. Modules, providers and
binaries are published once and consumed freely by everyone inside. Organisations
exist to divide *teams*: who may edit what, whose policies apply, who approves a
version. Consumption is not gated by organisation.

**Model B — isolated tenants.** Several unrelated organisations on one deployment,
each reachable at its own URL, with no bleed-over. One tenant must not see another's
modules, providers, state or even their *names*.

Both apps were conceived for Model A. Model B is the direction of travel.

---

## The decision

**The host is the content tenant. The organisation is the editorial scope.**

| Concept | Question it answers | Applies to |
|---|---|---|
| **Host** | *Whose registry is this?* | modules, providers, binaries |
| **Organisation** | *Who on my side may edit this, set policy, approve a version?* | teams within one host |

**The state manager is single-host by design.** Its domain has no host in its
addressing — a state file is not addressed as `host/...` the way a module is — so a
second host means a second deployment, not a second tenant inside one.

### Why the host, and not something else

**It is the slot the protocol already has.** A module source is
`host/namespace/name/system`. The registry's own code argues, correctly, that this
grammar has *no slot for an organisation*. It does have one for a host. Using it means
adopting the addressing Terraform already gives us instead of inventing a parallel one.

**The backfill is the only safe one available.** Every existing row belongs to the
deployment's current public host. That is a mechanical, reviewable migration. Every
organisation-based backfill considered for the same tables required human judgement
per table — deciding who owns a pre-existing row — which is exactly where a tenancy
migration discloses.

**It separates two questions that were conflated.** *Whose registry is this* and *who
on my team may edit this* are different questions. Merging them into one column is why
a NULL `organization_id` came to mean "visible to everyone" in one app and "visible to
nobody" in the other, with each app correct about its own model.

---

## Organisations and hosts: N organisations per host, realm per host

**Decided 2026-08-26, superseding the earlier open question.** Several organisations
share one host, and the organisation question is answered by *identity topology*, not
by a schema change in this module.

### Three planes of configuration

The apparent contradiction — "organisations divide teams within a host" versus "an
organisation configures identity, mirrors and binaries, which are host-level
singletons" — dissolves by splitting configuration by the question it answers:

| Plane | Owned by | Contains |
|---|---|---|
| **Platform** | platform admin | storage, host creation, assigning each host's owning organisation |
| **Host** | the host's **owning organisation** | identity/IdP, binaries hosted, provider mirror and version approval, domain and aliases |
| **Organisation** | each organisation | SCM connections, module publishing, scanning preferences, notifications, teams |

When the platform admin creates a host they assign its **owning organisation**. That
organisation configures the host plane. The other organisations on the host are
editorial tenants and configure only their own plane. The platform admin's remit
narrows to the platform plane — a deliberate reduction from today's admin wildcard,
and an authorization refactor in the registry, not a configuration change.

### Identity: one realm per host — and no host column, ever

This module addresses every table **unqualified**; the realm is chosen by the
connection (`schema_routing.go`). That is the mechanism: **one identity realm per
host**, with a host's organisations living inside its realm.

The consequence that decides the earlier question: `organizations.name UNIQUE` becomes
per-host *automatically*, because each host is a separate realm. Two hosts can both
hold an organisation named `platform` with **zero schema changes here**. The earlier
instruction stands, strengthened: this module must not gain a host column — under this
model one would be wrong, not merely premature.

Two costs, stated plainly:

- **Host→realm resolution is a security boundary.** `schema_routing.go` already
  documents that a wrong `search_path` *succeeds silently* — same table names,
  compatible columns, split-brain identity. Realm-per-host multiplies that hazard by
  the number of hosts. The resolver needs a guard that fails closed on an unknown
  host, with the same rigour as the `Host`-header trust below. A convention is not
  enough.
- **Cross-host queries stop existing.** Platform-wide views become fan-outs. That is
  isolation working as intended, but the platform plane therefore needs its own small
  store — the hosts table, `platform_admins`, storage configuration — because it can
  live inside no single realm.

### Storage: content-addressed blobs, capability URLs

Sync of binaries and providers is storage-aware and deduplicates:

```
blobs stored once:        blobs/sha256/<digest>          ← shared, content-addressed
per-host metadata row:    (host, namespace, …) → digest  ← where isolation lives
```

Deduplication means the blob store is deliberately *not* isolated, so isolation moves
entirely to the metadata layer — and provider hashes are public, so a digest is not a
secret. The download flow that makes this safe:

1. the protocol handler resolves the artifact in **this host's** metadata
2. it authorizes the caller for this host — the only authorization decision
3. it issues a **short-TTL signed URL** — a capability, not an address
4. the blob route serves **only valid signatures**, never a bare digest

Three of the four storage backends already work exactly this way — Azure SAS, S3
presigned, GCS signed, each behind `GetURL(path, ttl)` with a 15-minute TTL. The
**local backend is the gap**: its `GetURL` returns an API path served by the
unauthenticated files route with no signature. The build item is an HMAC-signed URL
for the local backend (path + expiry + signature over a server secret, verified by the
files handler), and a deployment check that the cloud buckets themselves refuse public
reads — otherwise the signing is theatre.

Version approval and mirror configuration gate which providers a **host** offers;
today's defect where one shared approval row serves every caller becomes the correct
per-host shape rather than an accident.

## Consequences to design for from the start

### `Host` is a tenancy input, so it must be trusted deliberately

The registry reads `Request.Host` in exactly one place today, for cosmetic URIs. Under
this model it becomes the discriminator, and a spoofed `Host` header is a cross-tenant
read.

Required from day one: a trusted-proxy allowlist, and an **unrecognised host fails
closed** rule. Not later.

### `HostAliases` changes meaning

Today it means *"other hostnames this one registry answers to"* — a convenience that
collapses several names onto one identity. Under host-as-tenant it becomes a
**per-tenant alias list**, and alias resolution becomes security-critical. The same
configuration key, meaning something new. Anything reading it must be revisited.

### Storage keys must be segmented before the SQL is scoped

Object keys carry no tenant segment. If the database is scoped first, the API isolates
while the blob store stays shared — archives remain addressable by guessable paths and
two tenants publishing the same coordinates overwrite each other. That failure
*destroys* rather than discloses, and hides the destruction behind an isolation that
reviews as correct. **Storage keys first, always.**

---

## Do not do these

Each of the first two is a one-way door that would read as ordinary tidy-up.

- **Do not land a global `UNIQUE (namespace, name, system)`.** Registry code refers to
  one it is "migrating to". It closes a documented gap and, in the same stroke, cements
  a single global namespace pool into the schema. Under this model the key is
  `(host, namespace, ...)`.
- **Do not scope reads before segmenting storage keys.** See above.
- **Do not enable the registry's `multi_tenancy.enabled` flag.** Both of its positions
  are wrong: off applies no organisation predicate at all, on filters to the
  organisation literally named `default`. It is scheduled for removal, not repair.
- **Do not use `403` for a cross-tenant miss.** It discloses that the artifact exists,
  which is what isolation forbids. Answer as though it does not exist. The state
  manager already does this and records the reasoning.
- **Do not treat the current route/scope class tests as completion gates.** They
  exclude the unauthenticated surface by construction, so a build could scope almost
  every public route and nothing would fail.

---

## Where this leaves `organization_id IS NULL`

The registry reads NULL as *"shared with everyone"*; the state manager reads it as
*"belongs to nobody"*. Both are right about their own model, which is why the question
could not be settled on its own terms.

Under host-as-tenant it resolves: on a host-scoped row, a NULL organisation means
**"shared within this host"** — one coherent meaning. It stops being a tenancy
statement and becomes an editorial one.

Deciding the model is therefore a prerequisite for that cleanup, not the other way
round.

---

## What is already true

Worth knowing before assuming the target is far away.

- **The management planes already switch.** Both apps read through a fail-closed scope
  type where "reach everything" is an explicit decision at the call site. Model A
  passes the platform-wide scope; Model B passes the caller's allowlist. That half is
  configuration, not refactoring.
- **The registry's consumption surface is Model A by written axiom** — *"reads are
  public; writes are owned"*. Model B does not extend that premise, it replaces it.
- **The state manager is currently neither.** Its state-source reads have been
  organisation-scoped since 2026-08-24 and the configuration that could restore the
  previous behaviour was removed in the same change; its other partition roots are
  still unscoped. Check the **deployed** build before reasoning about any of it.

---

## For agents working elsewhere in the estate

If you are in `security-orchestration`, `shared-workflows`, `cloud-suite-ui` or either
frontend, the parts that most likely reach you:

- An unscoped read is **not automatically a finding**. Under Model A the registry's
  consumption surface is unscoped on purpose. Judge it against this document, and if a
  surface is unscoped *without* a written reason, that is the finding.
- A **guard or gate** that asserts "everything is scoped" will be wrong for the
  registry's public routes. Guards should assert that every unscoped read is
  *declared*, not that none exists.
- **UI work must not assume organisations are global.** Organisations are per-host by
  realm topology: a picker or admin list shows one host's organisations, resolved by
  the connection, never a cross-host union.
