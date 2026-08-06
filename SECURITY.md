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
