<!-- markdownlint-disable MD013 -->
# Contributing to terraform-suite-identity

Thank you for your interest in contributing. This is the **shared identity & auth
component** for the Terraform tooling suite — a Go library linked into both the
registry and the state manager. Because both apps import it identically, changes
here affect the whole suite: contributions that uphold correctness, security, and
backward compatibility are especially welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Go Standards](#go-standards)
- [Database Migrations](#database-migrations)
- [The Suite Contract](#the-suite-contract)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Releasing](#releasing)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Documentation](#documentation)

---

## Code of Conduct

This project expects all participants to interact with each other professionally
and respectfully. Harassment, discrimination, or disruptive behavior of any kind
is not acceptable.

---

## Getting Started

### Prerequisites

- Go 1.25 or later — the module sets `go 1.25.0` in `go.mod` as its language floor.
  `go.mod` also pins `toolchain go1.26.6`, and CI resolves its Go version from
  `go.mod` (`actions/setup-go` with `go-version-file`), so **CI builds and tests
  with 1.26.6**. The `go` command downloads that toolchain automatically; if you
  have set `GOTOOLCHAIN=local`, you need 1.26.6 installed locally to match CI.
- A POSIX-ish shell for the `go` toolchain. No database is required for the unit
  test suite — the data layer is tested entirely with [`go-sqlmock`](https://github.com/DATA-DOG/go-sqlmock).
  The one live-PostgreSQL test file is behind a `//go:build integration` tag, so a
  plain `go test ./...` never needs a database.

### Fork and Clone

```bash
git clone https://github.com/sethbacon/terraform-suite-identity.git
cd terraform-suite-identity
go build ./...
go test ./...
```

There is nothing to run — this is a library, not a service. To exercise it
against a live PostgreSQL (the migration runner), use a consuming app's
integration/UAT suite (see [Testing Requirements](#testing-requirements)).

---

## Development Workflow

### Branch Naming

Branch from `main` and target `main`. Use a Conventional-Commit-style prefix that
matches the change:

| Type          | Pattern                  | Example                                |
| ------------- | ------------------------ | -------------------------------------- |
| Feature       | `feat/short-description` | `feat/canonical-host-idn`              |
| Bug fix       | `fix/issue-description`  | `fix/discovery-grace-window`           |
| Documentation | `docs/topic`             | `docs/schema-reference`                |
| Refactor      | `refactor/area`          | `refactor/store-repository-interface`  |

### Conventional Commits

PR titles **must** follow [Conventional Commits](https://www.conventionalcommits.org/).
They are validated on every PR by `amannn/action-semantic-pull-request`
(`.github/workflows/pr-checks.yml`, the **Conventional PR Title** check) with its
default ruleset:

```text
<type>(<optional scope>): <description>
```

| Type       | When to use                                    |
| ---------- | ---------------------------------------------- |
| `feat`     | New library capability (minor version bump)    |
| `fix`      | Bug fix, including security fixes (patch bump)  |
| `perf`     | Performance improvement (patch bump)            |
| `refactor` | Code restructure, no behavior change           |
| `docs`     | Documentation only                             |
| `style`    | Whitespace/formatting only                     |
| `test`     | Adding or fixing tests                         |
| `build`    | Build system / external dependency updates     |
| `ci`       | CI/CD workflow changes                         |
| `chore`    | Maintenance, tooling                           |
| `revert`   | Reverts a previous commit                      |

Common scopes mirror the package layout: `auth`, `store`, `models`, `suite`,
`oidc`, `deps`, `ci`.

> **PR title validation gotcha.** The PR-title check enforces the
> Conventional-Commits *default* type set (the table above). `security` and
> `deps` are **not** accepted as PR-title types — use `fix:` for security fixes
> and `chore:`/`build:` for dependency bumps (Dependabot uses `chore(deps)` /
> `chore(ci)`). Note that release-please *does* recognise extra `security` and
> `deps` changelog sections (`.release-please-config.json`); those apply to
> **commit** messages on `main`, not to the PR title. When you squash-merge, the
> PR title becomes the commit, so a PR-title-valid type is what ends up in the
> changelog.

**Breaking changes** while the module is pre-1.0: see [Releasing](#releasing) —
a breaking change bumps the **minor** version, not the major, because
`bump-minor-pre-major` is enabled.

Keep the subject line concise (≤ 72 characters). Reference issues in the body
with `Closes #123`.

---

## Go Standards

### Formatting, Vetting, and Tidiness

Every commit must pass — CI (`.github/workflows/ci.yml`) runs all of these:

```bash
go build ./...
go vet ./...
go mod tidy   # must produce no diff in go.mod / go.sum
```

The CI **Tests & Quality** job fails the build if `go mod tidy` changes
`go.mod` or `go.sum`, so run it before pushing and commit the result.

### Code Comments

Comments are part of the code and held to the same standard:

- **Package-level doc comments** are required for every package (see the existing
  comment on `package suite` for the bar — it explains *why* the package has no
  app/web-framework dependencies).
- **Exported symbols** must have doc comments.
- Comments explain **why**, not just **what**.

### Library Conventions

These conventions are what make the module safe to embed in two apps at once —
preserve them:

- **No environment reads.** The library never reads `os.Getenv`. Secrets, issuers,
  scope sets, and write→read pairs are **injected by the caller** (e.g.
  `auth.NewTokenManager(secret, issuer)`). This is what keeps it app-neutral — do
  not add a `TFR_*`/`TSM_*` lookup here.
- **App-agnostic scopes.** The library knows scope *mechanics* (`HasScope`, the
  wildcard `admin`, write-implies-read) but not scope *contents*. Each app seeds
  its own role → scope mapping onto `role_templates` at setup.
- **Repository pattern with unqualified table names.** Store repositories must use
  unqualified table names so the connection's `search_path` selects the schema
  (see [docs/schema.md](docs/schema.md)). Do not hard-code `identity.` or
  `public.` in repository SQL — only catalogue lookups may be qualified, and those
  must use `pg_catalog.` so an introspection query cannot itself be redirected by
  the `search_path` it exists to inspect.
  <br>
  Because the connection decides, a **new table means a new entry in
  `identity.repositoryTables`**, which is what `VerifySchemaRouting` asserts over.
  You do not have to remember: `TestRepositoryTablesMatchesTheSQLTheModuleEmits`
  re-derives the list from the SQL in `identity/store` and fails in both
  directions, and `TestModuleSQLQualifiesOnlyTheSystemCatalogue` fails on a
  qualified application table. Both live in
  `identity/schema_routing_class_test.go`.
- **The `suite` package stays dependency-free** of any app or web framework so the
  coupling contract cannot drift between the two apps.
- **Error wrapping.** Use `fmt.Errorf("context: %w", err)` to preserve the chain;
  do not swallow errors.
- **One not-found sentinel.** A read that can miss returns an error wrapping
  `store.ErrNotFound`; a by-identifier `UPDATE`/`DELETE` routes its `sql.Result`
  through `store.requireRow`; a bulk sweep reports its count via
  `store.affectedRows`. Never `return nil, nil` from an accessor, and never add a
  second not-found sentinel — a package with two has none. `sql.ErrNoRows` must
  not escape the repository boundary. Two tests in
  `identity/store/notfound_class_test.go` enforce this structurally
  (`TestNotFoundClass_NoAccessorReturnsNilNil` and
  `TestNotFoundClass_ExecResultDiscardersAreEnumerated`), because the mistake
  changes no signature and would otherwise compile and pass silently.
- **Identifier types are not uniform, and that is deliberate.** Some models type
  an id as `uuid.UUID` (`models.RoleTemplate.ID`, `models.OIDCConfig.ID`) and
  others as `string` or `*string` (`models.OrganizationMember.RoleTemplateID`,
  and every id on `Organization`/`User`). They refer to the same columns, so the
  inconsistency is real (issue #70) — but aligning them is a **breaking change**
  to a module two backends pin, for an ergonomic gain and no security one, so it
  has not been made.
  What matters when adding a field: **match the model you are extending**, do not
  "improve" it toward the other convention. A single model that mixes both is
  worse than the module-wide split, because it puts the conversion inside one
  struct where a reader expects consistency. If a future release does align
  them, it is one breaking change on its own commit — release-please keeps only
  the FIRST `BREAKING CHANGE:` footer per merged commit, so it must not ride
  along with anything else.

---

## Database Migrations

The identity schema migrations live in `identity/migrations/` and are embedded
into the binary with `//go:embed` (`identity/db.go`). They run in a **dedicated
golang-migrate instance** against the `identity` schema with their own
`identity_schema_migrations` version table — never the apps' migration tables.
See [docs/schema.md](docs/schema.md) for the full table and migration reference.

- **Never edit a released migration file.** The migration system treats file
  content as immutable; a changed file means a different checksum and a dirty
  state in any database that already applied it.
- Add a new numbered pair using the next sequential number:
  `0000NN_description.up.sql` and `0000NN_description.down.sql`.
- **Migrations must be additive within a major version.** Both apps consume the
  same schema; a destructive change would break whichever app upgrades first.
  Prefer `ADD COLUMN … IF NOT EXISTS` and new tables. Four shipped migrations
  (`000002`–`000005`) break this rule and are documented exceptions, each resting
  on a stated precondition — read
  [docs/schema.md](docs/schema.md#where-the-additive-rule-has-been-broken-and-why)
  before assuming a similar change is acceptable. In particular, a precondition of
  the form "these tables hold only seed data" is **not verifiable from inside this
  repository**: check it against every consuming app before you rely on it.
- Use idempotent, attach-safe DDL: `CREATE … IF NOT EXISTS`,
  `ON CONFLICT DO NOTHING`. The runner takes an advisory lock so concurrent
  detect-and-attach by two apps is safe (`identity.RunMigrations`).
- The `.down.sql` must fully reverse the `.up.sql`. There are **two** existing
  exceptions, both best-effort and both self-labelled in the file: `000003`'s
  `TEXT[]`↔`JSONB` column-type round-trip, and `000005`'s index drop, which does
  not restore the `is_active` values its up-migration cleared. See
  [docs/schema.md](docs/schema.md#down-migrations). Neither is a precedent: new
  migrations must still fully reverse.
- **A new migration must be added to `docs/schema.md`'s migration table in the same
  PR.** This is enforced — `TestSchemaDocMigrationTableIsComplete` and
  `TestSchemaDocCurrentVersionMatchesMigrations` in `identity/docs_drift_test.go`
  fail when a migration exists that the table does not list, or when the stated
  "current version" is no longer the highest on disk.

There is no migration CLI in this repo. Exercise both directions through a
consuming app, or in a throwaway database via `identity.RunMigrations(db, "up")`
and `identity.RunMigrations(db, "down")`.

---

## The Suite Contract

The `identity/suite` package defines the runtime coupling contract between the
two apps (the manifest, version negotiation, the discovery client, and
`CanonicalHost`). It is documented in [docs/suite-coupling.md](docs/suite-coupling.md).
Two rules are load-bearing and enforced by review:

1. **The manifest is additive-only.** Never remove or repurpose a field on
   `Manifest` (or its nested types). Consumers ignore unknown JSON fields, so new
   fields are safe; removing one is a breaking wire change for the *other* app.
2. **`SchemaVersion` major is the compatibility boundary.** Minor/patch may evolve
   freely. Only bump the `suite/vN` **major** (and `SchemaVersionV1`) for a
   genuinely incompatible wire change — that is the one thing `NegotiateCompat`
   rejects siblings on.

---

## Testing Requirements

Run the full local quality gate before opening a PR. CI rejects anything that
does not pass:

```bash
# 1. Build and vet
go build ./...
go vet ./...

# 2. Tests with coverage (race detector on; sqlmock — no live DB needed)
go test ./... -race -coverprofile=coverage.out -covermode=atomic

# 3. Coverage threshold (CI fails below 75%)
go tool cover -func=coverage.out | grep "^total:"

# 4. Security scan (CI fails on ANY gosec finding)
go install github.com/securego/gosec/v2/cmd/gosec@v2.26.1
gosec ./...
```

- **Coverage threshold is 75%** (`THRESHOLD=75` in `ci.yml`). Keep total coverage
  at or above it.
- **There is a second, per-package 75% floor**, also in `ci.yml`, and it is the one
  that usually bites: the package set is *derived* from `coverage.out`, so every
  package is gated by default and a new package is gated the moment it has tests.
  A PR can clear the aggregate gate and still fail here, because an easy-to-cover
  models package can otherwise mask a security-critical one. Only `identity` is
  EXEMPT (its migration runner needs a live database); adding an exemption is a
  deliberate, CODEOWNER-reviewed act, and a *stale* exemption fails the build too.
- **gosec must be clean.** The module is small, so CI fails on *any* finding. If a
  finding is an accepted risk, suppress it inline and narrowly with
  `// #nosec <rule> -- <justification>` rather than lowering the bar globally.
- **Documentation claims that state a number, a version, a path or an inventory are
  asserted mechanically** in `identity/docs_drift_test.go` — the migration table in
  `docs/schema.md`, the README package table, the manifest path, the coverage
  threshold, the gosec version, the dependency-review severity and the Go floor.
  If you change one of those in code or CI, the corresponding sentence must change
  too or `go test ./identity/` fails. Prefer adding a check there over trusting a
  sentence to stay true.
- The data layer (`identity/store`) is unit-tested with sqlmock; **the default
  `go test ./...` run uses no live database**. The migration runner
  (`identity.RunMigrations`) requires live PostgreSQL: it is exercised in CI by the
  separate, required **Integration Tests (PostgreSQL)** job (`-tags=integration`
  against a `postgres` service container) and by the **consuming apps'**
  integration/UAT suites — add or update those when you change migration behavior.

Security-sensitive code (JWT, API-key generation/validation, OIDC verification,
scope checking) requires tests by default — PRs adding such code without tests
will not be merged.

---

## Pull Request Process

1. **Open an issue first** for substantial changes — especially anything touching
   the schema or the suite contract, which affect both apps.
2. **Branch from `main`** and target `main`.
3. **Use a Conventional Commit PR title** (enforced — see above). Examples:
   - `feat(suite): add buildDate to the capability manifest`
   - `fix(auth): reject empty issuer in TokenManager`
   - `docs: document the identity schema migration list`
4. Write a clear PR description: what changed, why, how you tested it, and the
   issue link.
5. **All CI checks must pass**:
   - **Tests & Quality** (`ci.yml`) — build, vet, `go mod tidy` diff, tests with
     race + coverage, the total and per-package coverage floors.
   - **Integration Tests (PostgreSQL)** (`ci.yml`) — the migration runner against a
     real database, `-tags=integration`. This is a **required status check on
     `main`**: a non-blocking migration gate is the same as no migration gate.
   - **Security Scan (gosec)** (`ci.yml`) — fails on any finding.
   - **Vulnerability Scan (govulncheck)** (`ci.yml`) — known-vulnerability scan of
     the module and its dependencies.
   - **Conventional PR Title** (`pr-checks.yml`).
   - **Dependency review** (`pr-checks.yml`) — `fail-on-severity: moderate`.
   - **Breaking-change footers survive the squash** (`pr-checks.yml`) — fails a PR
     that declares more than one breaking change. See step 7.
   - **release-please can read the merged commit** (`pr-checks.yml`) — rebuilds the
     commit this PR would squash into `main` and parses it with the parser
     release-please itself uses. A message that parser rejects is dropped in
     silence: no changelog entry, no version bump, no `BREAKING CHANGE:` footer,
     and no later run recovers it. The usual cause is a body line that *starts*
     with `name(`, whose brackets must then be flat and closed.
   - **signature-replay / replay** (`signature-replay.yml`) — re-runs every
     recorded defect-class signature across the whole suite and fails when a
     class recorded as fixed matches again, or when a new instance appears that
     no issue covers. Exit 2 means a signature could not RUN, which is a failure
     and never a pass. Not a required check yet.
6. At least one approval is required. `@sethbacon` is the default reviewer/owner
   (`.github/CODEOWNERS`); changes under `.github/` and `identity/` require their
   explicit review.
7. **Squash-merge** into `main` — the PR title becomes the commit subject and every
   commit body in the PR is concatenated beneath it, and that one commit feeds
   release-please.

   That concatenation is why a PR may declare **at most one breaking change**.
   release-please keeps only the *first* `BREAKING CHANGE:` footer of a commit and
   reads a `!` marker only from its header, so a second declaration anywhere in the
   PR is dropped in silence — no changelog entry, no upgrade note, nothing failing
   to say so. Splitting the footers across separate commits does not help; the
   squash puts them back into one body. Either open one PR per breaking change, or
   combine them into a single footer and write each one up in the upgrade guide.
   The **Breaking-change footers survive the squash** check enforces this.

---

## Releasing

Releases are automated; the human actions are merging the release PR and then
approving the `release` deployment environment. The flow is **main-only** and
mirrors the registry's two-stage release.

1. Merging Conventional-Commit PRs to `main` drives
   [release-please](https://github.com/googleapis/release-please)
   (`.github/workflows/release-please.yml`), which keeps an open
   `chore(main): release X.Y.Z` PR with the accumulated `CHANGELOG.md` and the
   next version. Pre-1.0, `feat:` → **minor** bump and `fix:`/`perf:` → patch
   (`bump-minor-pre-major`).
2. release-please uses a **GitHub App token** (`RELEASE_DISPATCH_APP_ID` /
   `RELEASE_DISPATCH_APP_KEY`) so the release PR and the pushed tag trigger CI —
   the default `GITHUB_TOKEN` cannot, due to GitHub's workflow-recursion guard.
3. Squash-merging the release PR pushes a `vX.Y.Z` tag and a **draft** GitHub
   Release (`"draft": true` in `.release-please-config.json`).
4. The tag push triggers `release.yml`, whose `Verify tag is on main` job **guards
   that the tag is reachable from `origin/main`**. The `Publish GitHub Release`
   job then runs behind the **`release` deployment environment**, which requires
   reviewer approval and restricts deployments to `v*` tags — so publishing is a
   deliberate second human step, not an automatic consequence of the tag. This is
   a pure Go library with **no build artifacts** — there are no binaries, container
   images, or signatures to attach (the registry attaches those; this module does
   not).

To publish an already-tagged version manually:
`gh workflow run release.yml --ref vX.Y.Z`.

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private security advisory feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
to report issues privately. Include a clear description, reproduction steps, the
potential impact, and any suggested mitigations. Because this library is embedded
in both suite apps, please note whether the issue is reachable from one or both.

---

## Documentation

Documentation is a first-class deliverable:

- **New library capabilities**: update `README.md` and the relevant `docs/` file.
- **Schema changes**: update [docs/schema.md](docs/schema.md) with the new
  table/column and the migration that introduces it.
- **Suite-contract changes**: update [docs/suite-coupling.md](docs/suite-coupling.md)
  (manifest fields, negotiation rules, discovery states).
- **Behavioral changes**: update any affected usage example in `README.md`.

PRs that introduce user-visible capabilities without corresponding documentation
updates will be asked to add documentation before merge.
