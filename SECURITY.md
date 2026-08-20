# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private security advisory feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
to report issues privately. Include a clear description, reproduction steps, the
potential impact, and any suggested mitigations.

Because this library is embedded in both suite apps (`terraform-registry` and
`terraform-state-manager`), please note whether the issue is reachable from one
or both.

## Supported Versions

This module is pre-1.0 (`0.x`). Only the latest released minor version is
supported; there is no backport policy for older versions. Consumers are
expected to pin and upgrade in lockstep — see the [README](README.md#versioning).

## Scope

This is a Go library, not a running service — it has no independently deployed
attack surface. Reports should concern the library's own code, not the consuming
applications' deployments, which have their own security policies.

Everything in the module is in scope. The security-relevant surfaces, so that
nothing reads as excluded by omission:

| Package | Security-relevant surface |
| ------- | ------------------------- |
| `identity/auth` | JWT minting/validation (signing algorithm, issuer pin, audience, secret rotation), API-key generation and bcrypt validation, scope evaluation including the `admin` wildcard and write-implies-read. |
| `identity/auth/oidc` | Issuer discovery, ID-token verification, nonce and PKCE handling, the HTTPS requirements on issuer and redirect URL. |
| `identity/auth/oauthstate` | OAuth `state` entropy, TTL, single use, and purpose binding. |
| `identity/store` | The data-access layer: query construction, tenancy predicates, API-key expiry filtering, JWT revocation lookups. |
| `identity/crypto` | `TokenCipher` — AES-256-GCM authenticated encryption, key derivation, and key rotation. |
| `identity/httpsafe` | The SSRF egress guard on outbound HTTP. A bypass of this guard **is** in scope. |
| `identity/mailer` | SMTP transport, including resistance to opportunistic-TLS downgrade. |
| `identity/notify` | Notification fan-out, encrypted channel targets, and secret redaction in logs/errors. |
| `identity/suite` | The cross-app coupling contract: manifest handling, version negotiation, the discovery client's transport requirements, and `CanonicalHost` normalization. |
| `identity` | The migration runner (advisory locking, schema isolation). |

See [CONTRIBUTING.md](CONTRIBUTING.md#reporting-security-vulnerabilities) for
additional contributor-facing security expectations (test requirements for
security-sensitive code, the CI security gates — gosec and govulncheck — etc.).

## Shared CI workflows

Part of this repository's CI is **defined in another repository** — [`4cloudguru/shared-workflows`](https://github.com/4cloudguru/shared-workflows) — and called from `.github/workflows/`. That is a real supply-chain relationship, and it is recorded here so an audit of this repository does not stop at this repository's own tree.

**What runs, and where it is pinned.** Each caller in `.github/workflows/` names the shared workflow on its `uses:` line, pinned to a full 40-hex commit SHA with a trailing comment naming the release that SHA is. The tag is a label; the SHA is what runs. An unlabelled SHA is rejected by the workflow-hardening gate, because a bare 40-hex ref cannot be reviewed or updated deliberately.

**Why the pins have to agree across repositories.** A shared definition drifts differently from a duplicated file: every repository looks like it is using "the shared one" while sitting on different commits, which is *harder* to see than divergent files, not easier. A signature in `security-orchestration` (`shared-workflow-pin-parity`) reports **disagreement** between callers of the same shared workflow — it reports disagreement rather than staleness, because a repository deliberately held back is a decision while N repositories disagreeing without anyone deciding is drift.

**What the shared repository is itself protected by.** Its `main` requires its own zizmor and actionlint checks with `enforce_admins` enabled, restricts which third-party actions may run to an explicit allowlist, issues a read-only default `GITHUB_TOKEN`, and runs the workflow-hardening gate against itself.

**What this repository still controls.** Triggers, concurrency, and the secrets it passes. Secrets are passed **by name** — never `secrets: inherit`, which would forward every secret in this repository to a workflow owned by someone else. Any `vars.*` a shared workflow reads resolve against **this** repository, so credentials and their installation scope do not move.
