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
attack surface. Reports should concern the library's own code (JWT/API-key/OIDC
auth primitives, the data-access layer, or the suite-coupling contract), not the
consuming applications' deployments, which have their own security policies.

See [CONTRIBUTING.md](CONTRIBUTING.md#reporting-security-vulnerabilities) for
additional contributor-facing security expectations (test requirements for
security-sensitive code, the CI security gates, etc.).
