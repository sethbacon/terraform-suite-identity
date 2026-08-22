# Changelog

## [0.33.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.32.0...v0.33.0) (2026-08-22)


### Features

* **notify:** let a consumer name the organization that owns a channel ([#251](https://github.com/sethbacon/terraform-suite-identity/issues/251)) ([2097b1c](https://github.com/sethbacon/terraform-suite-identity/commit/2097b1ca56d02e716bf63f4f2da76ec66f25d87b))

## [0.32.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.31.0...v0.32.0) (2026-08-21)


### Features

* **tenantscope:** resolve a request's organizations here, once, instead of twice ([#248](https://github.com/sethbacon/terraform-suite-identity/issues/248)) ([5546f69](https://github.com/sethbacon/terraform-suite-identity/commit/5546f6997dd423232168908d2ef7c6d9c3b5b07f))
* **tenantscope:** resolve the single organization a write belongs to ([#250](https://github.com/sethbacon/terraform-suite-identity/issues/250)) ([e092670](https://github.com/sethbacon/terraform-suite-identity/commit/e0926708bc23088453f483cb4a38fab6740a57cc))

## [0.31.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.30.2...v0.31.0) (2026-08-21)


### Features

* **notify:** optional organization scope for the channel DAO ([#243](https://github.com/sethbacon/terraform-suite-identity/issues/243)) ([10f1873](https://github.com/sethbacon/terraform-suite-identity/commit/10f18730c167bbc4ba140c2e692d2a8dd04e94b7))

## [0.30.2](https://github.com/sethbacon/terraform-suite-identity/compare/v0.30.1...v0.30.2) (2026-08-21)


### Bug Fixes

* **ci:** refuse to run signature-replay when Dependabot edited the workflow ([#228](https://github.com/sethbacon/terraform-suite-identity/issues/228)) ([359fd23](https://github.com/sethbacon/terraform-suite-identity/commit/359fd23750af07b6dd4400cbb10fc0fd3627c3e3))


### Documentation

* **security:** record the shared-workflow trust relationship, and fix what it invalidated ([#239](https://github.com/sethbacon/terraform-suite-identity/issues/239)) ([243afbe](https://github.com/sethbacon/terraform-suite-identity/commit/243afbefc1e30bdba92be733c31294c3d02db8e2))

## [0.30.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.30.0...v0.30.1) (2026-08-19)


### Documentation

* one row per package in the README table, and a guard that keeps it that way ([#223](https://github.com/sethbacon/terraform-suite-identity/issues/223)) ([4b83476](https://github.com/sethbacon/terraform-suite-identity/commit/4b83476cf654117b9adfd04a5b5e07806f2f44a9))

## [0.30.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.29.0...v0.30.0) (2026-08-19)


### Features

* **pgxparam:** export the mock value converter consumers need ([#221](https://github.com/sethbacon/terraform-suite-identity/issues/221)) ([992beec](https://github.com/sethbacon/terraform-suite-identity/commit/992beec788bf82f457211fa5c08dd6550c2e5307))

## [0.29.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.28.1...v0.29.0) (2026-08-19)


### ci

* allow the deps and security PR title types the release config expects ([#218](https://github.com/sethbacon/terraform-suite-identity/issues/218)) ([07bed04](https://github.com/sethbacon/terraform-suite-identity/commit/07bed04e1072d7f7e8d7533a695c57197a19dd3b))

## [0.28.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.28.0...v0.28.1) (2026-08-18)


### Security

* triage govulncheck findings instead of gating on unfixable ones ([#214](https://github.com/sethbacon/terraform-suite-identity/issues/214)) ([525cf40](https://github.com/sethbacon/terraform-suite-identity/commit/525cf40cfc00ae496eae5c0e3e6d930267218597))

## [0.28.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.27.2...v0.28.0) (2026-08-14)


### Features

* **auditoutbox:** transactional audit outbox as reusable mechanism ([#210](https://github.com/sethbacon/terraform-suite-identity/issues/210)) ([db1ce94](https://github.com/sethbacon/terraform-suite-identity/commit/db1ce943a96b62326d73a88ac20f9960c0a1f86d)), closes [#206](https://github.com/sethbacon/terraform-suite-identity/issues/206)
* **platformadmin:** platform-admin carrier as reusable, app-parameterised mechanism ([#207](https://github.com/sethbacon/terraform-suite-identity/issues/207)) ([610ac41](https://github.com/sethbacon/terraform-suite-identity/commit/610ac410a018d9a8001a010d23669167e3adc867)), closes [#206](https://github.com/sethbacon/terraform-suite-identity/issues/206)


### Bug Fixes

* **deps:** raise the toolchain to go1.26.6 for four stdlib advisories ([#209](https://github.com/sethbacon/terraform-suite-identity/issues/209)) ([aae762a](https://github.com/sethbacon/terraform-suite-identity/commit/aae762a75ec13efe26e6cbc08c5c9ef3f6e4d67c))

## [0.27.2](https://github.com/sethbacon/terraform-suite-identity/compare/v0.27.1...v0.27.2) (2026-08-12)


### Bug Fixes

* **ci:** spend the replay credential on the one private checkout only ([#199](https://github.com/sethbacon/terraform-suite-identity/issues/199)) ([afce19c](https://github.com/sethbacon/terraform-suite-identity/commit/afce19c97469672143b559f7a66a84e672b6b9be))

## [0.27.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.27.0...v0.27.1) (2026-08-12)


### Bug Fixes

* **ci:** point the suite-ui checkout at its new owner ([#197](https://github.com/sethbacon/terraform-suite-identity/issues/197)) ([1ec3533](https://github.com/sethbacon/terraform-suite-identity/commit/1ec3533c502cecbe6474610b316974d4121ccee7))

## [0.27.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.26.0...v0.27.0) (2026-08-10)


### Features

* **notify:** bind the channel target ciphertext to its channel row ([#195](https://github.com/sethbacon/terraform-suite-identity/issues/195)) ([17c81c8](https://github.com/sethbacon/terraform-suite-identity/commit/17c81c808c9dbfce08eb7d65ebc9d279229a3a1f)), closes [#153](https://github.com/sethbacon/terraform-suite-identity/issues/153)

## [0.26.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.25.0...v0.26.0) (2026-08-10)


### Features

* **crypto:** add a transition reader so adopting AAD is a two-deploy change ([#194](https://github.com/sethbacon/terraform-suite-identity/issues/194)) ([3564c49](https://github.com/sethbacon/terraform-suite-identity/commit/3564c4938ac556f8351f76c435b74ee7f5e35825)), closes [#153](https://github.com/sethbacon/terraform-suite-identity/issues/153)
* **crypto:** bind sealed tokens to their storage slot with GCM AAD ([#193](https://github.com/sethbacon/terraform-suite-identity/issues/193)) ([941af5f](https://github.com/sethbacon/terraform-suite-identity/commit/941af5f5e3dc4d0d90f93decac84cf9d255c67fc)), closes [#153](https://github.com/sethbacon/terraform-suite-identity/issues/153)


### Bug Fixes

* **ci:** check out the two ADO extension repos the replay gate requires ([#188](https://github.com/sethbacon/terraform-suite-identity/issues/188)) ([fe7ff89](https://github.com/sethbacon/terraform-suite-identity/commit/fe7ff8982290bc532967508068f29220e6eccd06))
* **ci:** key the coverage exemption on the file, not the whole package ([#190](https://github.com/sethbacon/terraform-suite-identity/issues/190)) ([97bc409](https://github.com/sethbacon/terraform-suite-identity/commit/97bc4090aae0b89b3236975b6e64bca764387ed9))
* **ci:** repair the empty `with:` blocks that broke five workflows at startup ([#186](https://github.com/sethbacon/terraform-suite-identity/issues/186)) ([afbf72d](https://github.com/sethbacon/terraform-suite-identity/commit/afbf72d4469dfcf65009d22151aa79840d1f5356))
* **oidc:** enforce the azp authorized-party rules the library leaves to us ([#189](https://github.com/sethbacon/terraform-suite-identity/issues/189)) ([d53ad1e](https://github.com/sethbacon/terraform-suite-identity/commit/d53ad1e9331d6c421c5f0a44e53d7b7a6bb35f4e))


### Documentation

* record the identifier-type split as a convention rather than a defect ([#191](https://github.com/sethbacon/terraform-suite-identity/issues/191)) ([214d424](https://github.com/sethbacon/terraform-suite-identity/commit/214d42486b63fd32773f16f37c19241e75ef012d))

## [0.25.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.24.0...v0.25.0) (2026-08-07)


### ⚠ BREAKING CHANGES

* **mailer,auth,store:** mailer.Config.UseTLS is replaced by mailer.Config.TLSMode, whose zero value is TLSRequired. Every call site is a compile error; map `UseTLS: true` to `TLSMode: mailer.TLSRequired` (or omit it), `UseTLS: false` to `TLSMode: mailer.TLSDisabled`, and a boolean variable through `mailer.TLSModeForUseTLS(b)`. Transport behaviour is unchanged for any configuration that named its choice. auth.MaxAPIKeyPrefixLength drops from 20 to 7, so GenerateAPIKey now rejects a longer prefix; existing keys keep authenticating. store.APIKeyRepository.GetAPIKeysByPrefix now returns an error wrapping store.ErrPrefixNotDiscriminating instead of a candidate set when one prefix matches more than 100 live keys. See UPGRADING.md.
* **egress:** this release requires a DEPLOYMENT-CONFIGURATION change, not only a code change. httpsafe's default policy denies loopback, RFC 1918 and link-local, and both consumers default security.egress.allowlist to empty — so routing OIDC discovery, JWKS and suite manifest fetches through the guard makes an identity provider or sibling app on an internal address unreachable until it is allow-listed. Any deployment with a self-hosted IdP, a cluster-internal sibling, or a local dev stack MUST set TFR_SECURITY_EGRESS_ALLOWLIST (registry) or TSM_SECURITY_EGRESS_ALLOWLIST (state manager) to a comma-separated list naming those hosts. Note the two differ: the registry's list WIDENS the deny-list, while the state manager's REPLACES its built-in private-range default, so a value set there must re-state 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and fc00::/7. Deployments using only a public IdP need no change. AllowInsecureIssuer and DEV_MODE do NOT cover this: the scheme rule and the destination rule are separate. Compile-error changes: Guard.ValidateURL gains a ctx parameter; suite.NewDiscoveryClient and NewInsecureDiscoveryClient gain a guard parameter; Manifest.PublicURL changes type from string to UntrustedURL. See UPGRADING.md for the exact per-consumer and per-dev-stack values.
* **schema:** migration 000007 changes what a DELETE on organizations or users does to rows a consumer already stores, and most of it produces no compile error. StreamAuditLogs gained al.actor_email as column 10 (between created_at and the joined user_email/user_name), so a caller scanning its rows must add that destination. A caller that depended on CreateAuditLog FAILING on an unresolvable user/organization id — nulling the actor columns and retrying — is on a path that no longer triggers, and must decide the disposition explicitly. Rows already re-homed by a past delete cannot be repaired by DDL and are a deploy-time inventory step; UPGRADING.md carries the queries.
* **store:** store.AuditScope and its three constructors are renamed to store.OrgScope / OrgScopeOrganizations / OrgScopeOrganizationsAndUnowned / OrgScopeAllOrganizations, and 37 accessors on APIKeyRepository, OrganizationRepository and UserRepository gained a required trailing `scope store.OrgScope` parameter, so every call site is a compile error. APIKeyRepository.ListAll is renamed ListAPIKeys (the old name is a contradiction once scoped). APIKeyRepository.RevokeAPIKeysForUser is new. OrganizationRepository.RemoveAllMembershipsForUser now returns (OrgScope, error) instead of (int64, error) — the organizations it actually emptied, which is the credential sweep's scope. notify's userRepo interface changed with GetUserByID. Scope ids are now deduplicated AND sorted. On the users table a membership-less user is now DENIED by a plain organization scope; state the old behaviour with OrgScopeOrganizationsAndUnowned / .WithUnowned(). A consumer whose tests grep source for the literal "AuditScopeAllOrganizations" (state- manager's TestNoPlatformWideAuditScopeInHandlers) will keep passing while checking nothing until the literal is updated. See UPGRADING.md sections 6-7.
* **api:** See UPGRADING.md for the full v0.25.0 migration.

### Features

* **identity:** assert which physical table an unqualified query hits ([#177](https://github.com/sethbacon/terraform-suite-identity/issues/177)) ([30b3622](https://github.com/sethbacon/terraform-suite-identity/commit/30b3622cc5f59fbaf0d293f8a7804b07b22906e5)), closes [#143](https://github.com/sethbacon/terraform-suite-identity/issues/143) [#141](https://github.com/sethbacon/terraform-suite-identity/issues/141)


### Bug Fixes

* **egress:** route every outbound request through the guard the module owns ([#178](https://github.com/sethbacon/terraform-suite-identity/issues/178)) ([27de27b](https://github.com/sethbacon/terraform-suite-identity/commit/27de27be43b64d26ac157f11ed93d096edad9a72))
* **mailer,auth,store:** make the unsafe transport and lookup states unreachable by omission ([#179](https://github.com/sethbacon/terraform-suite-identity/issues/179)) ([33a5cfc](https://github.com/sethbacon/terraform-suite-identity/commit/33a5cfc3ec0c652a8fb00025a9757ff956aecaf8))
* **schema:** a delete must not re-home a row into a tenancy state that means something else ([#176](https://github.com/sethbacon/terraform-suite-identity/issues/176)) ([eb4ecd5](https://github.com/sethbacon/terraform-suite-identity/commit/eb4ecd59c06b596e9ba74ed9ece25e369b0368cb))
* **store:** apply the mandatory tenant scope to every organization-owned accessor ([#175](https://github.com/sethbacon/terraform-suite-identity/issues/175)) ([6d41d42](https://github.com/sethbacon/terraform-suite-identity/commit/6d41d42dda32d87c63af80a7f7d26c7119166bef))


### Refactor

* **api:** delete the deprecated trap surface and canonicalise the repository shape ([#174](https://github.com/sethbacon/terraform-suite-identity/issues/174)) ([669a0f3](https://github.com/sethbacon/terraform-suite-identity/commit/669a0f3ad477e8a0e9a40fe8a70086a82e27f05a))

## [0.24.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.23.0...v0.24.0) (2026-08-06)


### ⚠ BREAKING CHANGES

* **store:** not-found and zero-row mutations are now reported as errors wrapping store.ErrNotFound, and four bulk accessors plus models.OIDCConfig.GetScopes changed signature. Most affected call sites still COMPILE and change behaviour silently: a handler written as `if err != nil { 500 }` followed by `if value == nil { 404 }` keeps building and turns every 404 into a 500, and an existence probe where not-found is the happy path (GetUserByEmail before creating a user, GetByName before creating an organization, GetMember before adding a member) becomes an unconditional 500. Idempotent SCIM/IdP reconciliation loops calling RemoveMember, UpdateMemberRole or RevokeAPIKey now abort on the first already-applied element unless they skip store.ErrNotFound. Signature changes: APIKeyRepository.DeleteExpiredKeys, OrganizationRepository.RemoveAllMembershipsForUser, OIDCConfigRepository.DeactivateAllOIDCConfigs and TokenRepository.CleanupExpiredRevocations now return (int64, error); models.OIDCConfig.GetScopes now returns ([]string, error). See UPGRADING.md for the five-step migration and the full accessor list.

### Bug Fixes

* **store:** report not-found with a single ErrNotFound sentinel ([#172](https://github.com/sethbacon/terraform-suite-identity/issues/172)) ([cf03788](https://github.com/sethbacon/terraform-suite-identity/commit/cf037884230c5a1ae694f6c12907560dfb848f8e))

## [0.23.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.22.1...v0.23.0) (2026-08-06)


### Features

* **store:** index the audit scope predicate and self-bound revocations ([#170](https://github.com/sethbacon/terraform-suite-identity/issues/170)) ([601adfb](https://github.com/sethbacon/terraform-suite-identity/commit/601adfbcc8f8211bc4de0fa38445d2a24affd91b)), closes [#154](https://github.com/sethbacon/terraform-suite-identity/issues/154)


### Bug Fixes

* **auth,store:** fail closed on empty, missing and evicted security input ([#167](https://github.com/sethbacon/terraform-suite-identity/issues/167)) ([a1af44b](https://github.com/sethbacon/terraform-suite-identity/commit/a1af44b204b380c7d08d3d2e9a09824dfc4549bb)), closes [#69](https://github.com/sethbacon/terraform-suite-identity/issues/69) [#134](https://github.com/sethbacon/terraform-suite-identity/issues/134) [#135](https://github.com/sethbacon/terraform-suite-identity/issues/135)
* **db,store:** return borrowed pooled connections and stop handing out cached state ([#169](https://github.com/sethbacon/terraform-suite-identity/issues/169)) ([e045f86](https://github.com/sethbacon/terraform-suite-identity/commit/e045f86487d7f39dc291057c238dcc0fecb86702)), closes [#139](https://github.com/sethbacon/terraform-suite-identity/issues/139) [#147](https://github.com/sethbacon/terraform-suite-identity/issues/147)
* **docs:** reconcile documented controls with the code, and collapse duplicated membership queries ([#171](https://github.com/sethbacon/terraform-suite-identity/issues/171)) ([3199143](https://github.com/sethbacon/terraform-suite-identity/commit/319914303c8481ebd93095eac9889b30c971a373))

## [0.22.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.22.0...v0.22.1) (2026-08-06)


### Bug Fixes

* **ci:** make CI controls able to fail a merge ([#164](https://github.com/sethbacon/terraform-suite-identity/issues/164)) ([041f3cc](https://github.com/sethbacon/terraform-suite-identity/commit/041f3cc2216e44baf34053650da1f2f517d3ddc3))
* **notify:** contain background-job faults instead of crashing the host ([#166](https://github.com/sethbacon/terraform-suite-identity/issues/166)) ([d616d6e](https://github.com/sethbacon/terraform-suite-identity/commit/d616d6e792e28fea099c82e304dc8d0e54fa96e1))

## [0.22.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.21.0...v0.22.0) (2026-08-02)


### Features

* add a store-and-consume OAuth state contract ([#132](https://github.com/sethbacon/terraform-suite-identity/issues/132)) ([628b039](https://github.com/sethbacon/terraform-suite-identity/commit/628b03950d97340aee00c1a9bde218ce3f831c0e))

## [0.21.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.20.3...v0.21.0) (2026-08-02)


### ⚠ BREAKING CHANGES

* require a tenant scope on every audit read accessor ([#130](https://github.com/sethbacon/terraform-suite-identity/issues/130))

### Features

* require a tenant scope on every audit read accessor ([#130](https://github.com/sethbacon/terraform-suite-identity/issues/130)) ([b0c2a25](https://github.com/sethbacon/terraform-suite-identity/commit/b0c2a254ecab262e67a5635ac0c34407f7026fdd))

## [0.20.3](https://github.com/sethbacon/terraform-suite-identity/compare/v0.20.2...v0.20.3) (2026-07-23)


### Bug Fixes

* add organizations:create scope and RoleScopesPermittedBy assignment ceiling ([#126](https://github.com/sethbacon/terraform-suite-identity/issues/126)) ([6f8f063](https://github.com/sethbacon/terraform-suite-identity/commit/6f8f0637a1cfbd79f0f34af772080af1c45856f4)), closes [#125](https://github.com/sethbacon/terraform-suite-identity/issues/125)

## [0.20.2](https://github.com/sethbacon/terraform-suite-identity/compare/v0.20.1...v0.20.2) (2026-07-22)


### Bug Fixes

* **notify:** claim API-key expiry notifications atomically to stop duplicate emails ([#121](https://github.com/sethbacon/terraform-suite-identity/issues/121)) ([ba8a19b](https://github.com/sethbacon/terraform-suite-identity/commit/ba8a19bfd4082004ea2457b4d71c6b0c5d2055fa)), closes [#120](https://github.com/sethbacon/terraform-suite-identity/issues/120)

## [0.20.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.20.0...v0.20.1) (2026-07-18)


### Bug Fixes

* restore two commits dropped by [#115](https://github.com/sethbacon/terraform-suite-identity/issues/115)'s incomplete squash-merge ([#117](https://github.com/sethbacon/terraform-suite-identity/issues/117)) ([f932daf](https://github.com/sethbacon/terraform-suite-identity/commit/f932daf6af6b09f676c345f1630074e1f730169b))

## [0.20.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.19.0...v0.20.0) (2026-07-18)


### Features

* **notify:** shared notification channels, crypto, and SSRF-safe HTTP client ([#115](https://github.com/sethbacon/terraform-suite-identity/issues/115)) ([95ef429](https://github.com/sethbacon/terraform-suite-identity/commit/95ef429c3c10a48a83b7503cbec983cb43b35634))

## [0.19.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.18.1...v0.19.0) (2026-07-17)


### Features

* **mailer:** shared SMTP transport for suite notification systems ([#113](https://github.com/sethbacon/terraform-suite-identity/issues/113)) ([35892dc](https://github.com/sethbacon/terraform-suite-identity/commit/35892dc7a3384897fc146a205941b7b390621caf))

## [0.18.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.18.0...v0.18.1) (2026-07-15)


### Bug Fixes

* close reopened 2026-07-14 audit regressions ([#54](https://github.com/sethbacon/terraform-suite-identity/issues/54), [#66](https://github.com/sethbacon/terraform-suite-identity/issues/66), [#67](https://github.com/sethbacon/terraform-suite-identity/issues/67), [#68](https://github.com/sethbacon/terraform-suite-identity/issues/68), [#70](https://github.com/sethbacon/terraform-suite-identity/issues/70)) ([#110](https://github.com/sethbacon/terraform-suite-identity/issues/110)) ([547c780](https://github.com/sethbacon/terraform-suite-identity/commit/547c780e9d27acad55e86fd09812924beddd1510))

## [0.18.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.17.0...v0.18.0) (2026-07-14)


### ⚠ BREAKING CHANGES

* **oidc:** Config.RequireHTTPS is renamed to Config.AllowInsecureIssuer and the default is inverted (HTTPS is now required unless a caller opts out). Consumers setting RequireHTTPS will fail to compile until updated.

### Bug Fixes

* **oidc:** require HTTPS by default and fail closed on unchecked nonce ([#107](https://github.com/sethbacon/terraform-suite-identity/issues/107)) ([c686346](https://github.com/sethbacon/terraform-suite-identity/commit/c6863468f7aeda95a41a3a5b54ba99db160d7d72)), closes [#103](https://github.com/sethbacon/terraform-suite-identity/issues/103) [#104](https://github.com/sethbacon/terraform-suite-identity/issues/104)
* **store:** complete [#70](https://github.com/sethbacon/terraform-suite-identity/issues/70) code-quality cleanups without breaking consumers ([#109](https://github.com/sethbacon/terraform-suite-identity/issues/109)) ([8190af4](https://github.com/sethbacon/terraform-suite-identity/commit/8190af4048adaa3a5f46a068b33dc0af9706a5ff))

## [0.17.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.16.1...v0.17.0) (2026-07-12)


### Features

* **security:** OIDC nonce/PKCE and identity auth hardening ([#49](https://github.com/sethbacon/terraform-suite-identity/issues/49)) ([cfcd965](https://github.com/sethbacon/terraform-suite-identity/commit/cfcd965bd3a3a84edd4775dbeec60fe0e6c98bb3))


### Bug Fixes

* **auth/oidc:** bound provider HTTP calls with a timeout and reject non-HTTPS redirect URLs when required ([#97](https://github.com/sethbacon/terraform-suite-identity/issues/97)) ([1752515](https://github.com/sethbacon/terraform-suite-identity/commit/1752515dfb46517e6375a48ee5077115d2c56498))
* **auth:** add NewCoupledTokenManager to make issuer pin and audience mandatory ([#93](https://github.com/sethbacon/terraform-suite-identity/issues/93)) ([e9e5181](https://github.com/sethbacon/terraform-suite-identity/commit/e9e5181eb4eda7513803d07bf44bbbc13e17b8f0))
* **auth:** bind JWTs to a single organization and add org-aware scope checks ([8682bfd](https://github.com/sethbacon/terraform-suite-identity/commit/8682bfd6f33af3b4ca5bb3d273dbb6a3b19e0712))
* **auth:** document ScopeAdmin trust boundary and add provisioning guard ([#95](https://github.com/sethbacon/terraform-suite-identity/issues/95)) ([1aa2475](https://github.com/sethbacon/terraform-suite-identity/commit/1aa24759392e4b189f5f452a9eac10b660943678))
* **ci:** correct invalid dependabot.yml schedule interval (biweekly -&gt; weekly) ([#85](https://github.com/sethbacon/terraform-suite-identity/issues/85)) ([ca938c4](https://github.com/sethbacon/terraform-suite-identity/commit/ca938c4651104251e58863c8e4437890ca9eae04))
* **ci:** gate per-package coverage on identity/auth(/oidc)/store and add live-Postgres migration integration test ([#106](https://github.com/sethbacon/terraform-suite-identity/issues/106)) ([b577e55](https://github.com/sethbacon/terraform-suite-identity/commit/b577e5562a72d81d56b1dc8c2904376d0f194359))
* **identity:** stop full migration down-unwind from bricking state ([#101](https://github.com/sethbacon/terraform-suite-identity/issues/101)) ([f5a49ab](https://github.com/sethbacon/terraform-suite-identity/commit/f5a49ab222ad76abcb9eab44d9e467fc79e05a92)), closes [#64](https://github.com/sethbacon/terraform-suite-identity/issues/64)
* **migrations:** drop vestigial is_active columns on organizations/users/api_keys ([#96](https://github.com/sethbacon/terraform-suite-identity/issues/96)) ([76a2faf](https://github.com/sethbacon/terraform-suite-identity/commit/76a2fafc392f96da18c26586b66fd00c600411bb))
* **oidc:** guard discovery-free Provider methods against nil panic ([#76](https://github.com/sethbacon/terraform-suite-identity/issues/76)) ([c48e451](https://github.com/sethbacon/terraform-suite-identity/commit/c48e4511eddc735520a97bbd949429ddef644a45))
* **scopes:** add per-organization scope accessors alongside global union ([4f2b752](https://github.com/sethbacon/terraform-suite-identity/commit/4f2b752e2ea270e8a0c7d00919ba48280b540f6a))
* **security:** rename ClientSecretEncrypted; document module performs no crypto ([#81](https://github.com/sethbacon/terraform-suite-identity/issues/81)) ([45f10d2](https://github.com/sethbacon/terraform-suite-identity/commit/45f10d2fbd1b77b8a3396b59cb6444171a0ebd9c))
* **security:** require verified email for OIDC account linking/creation ([#80](https://github.com/sethbacon/terraform-suite-identity/issues/80)) ([7ffede0](https://github.com/sethbacon/terraform-suite-identity/commit/7ffede0ac1c0bbaa7a095fa76c3e1ab846266cd4))
* **store,auth:** harden API-key contract — expiry filter, doc fixes, prefix cap ([#98](https://github.com/sethbacon/terraform-suite-identity/issues/98)) ([7e09ec1](https://github.com/sethbacon/terraform-suite-identity/commit/7e09ec14bf98c7a2f105d19e317aac91a60f9a91))
* **store:** enforce single-active OIDC config invariant on create ([#100](https://github.com/sethbacon/terraform-suite-identity/issues/100)) ([fc1c829](https://github.com/sethbacon/terraform-suite-identity/commit/fc1c829eb3714ec30c4b5f7f836b7346e975365b))
* **store:** escape LIKE metacharacters in ILIKE search patterns ([#75](https://github.com/sethbacon/terraform-suite-identity/issues/75)) ([d1a919f](https://github.com/sethbacon/terraform-suite-identity/commit/d1a919f99edf4473bcd0a6453c973781402648c9))
* **store:** race-safe OIDC user creation; document cache staleness and not-found contract ([#84](https://github.com/sethbacon/terraform-suite-identity/issues/84)) ([e0300fc](https://github.com/sethbacon/terraform-suite-identity/commit/e0300fc73df8e91b00ea3cb8adeaed36b04073aa))
* **store:** surface silent no-op guards as errors ([#78](https://github.com/sethbacon/terraform-suite-identity/issues/78)) ([f62e6ad](https://github.com/sethbacon/terraform-suite-identity/commit/f62e6adb57c4f5ee2c79624e01c79e9fd3dde3bf))
* **suite:** make NewDiscoveryClient fail closed by default on plaintext HTTP ([#99](https://github.com/sethbacon/terraform-suite-identity/issues/99)) ([525b54f](https://github.com/sethbacon/terraform-suite-identity/commit/525b54f2382707fd13c1496943f7b27d8fb6da1e))
* **suite:** reject unrecoverable userinfo/multi-colon host input; guard empty-schema NegotiateCompat ([#102](https://github.com/sethbacon/terraform-suite-identity/issues/102)) ([da37ef6](https://github.com/sethbacon/terraform-suite-identity/commit/da37ef68160f92fc676d362dfd9bc9e747f44c61))
* **suite:** return an isolated copy from DiscoveryClient.Snapshot ([#77](https://github.com/sethbacon/terraform-suite-identity/issues/77)) ([8f53510](https://github.com/sethbacon/terraform-suite-identity/commit/8f53510cf66c685929c0f8beb0995ffcc6dbab88))


### Documentation

* **readme:** document SetAudience and warn on per-org scope re-checks ([8394180](https://github.com/sethbacon/terraform-suite-identity/commit/83941806dfd4f46ababb1741ff24788490d99334))
* **security:** add SECURITY.md and fix doc/behavior mismatches ([#83](https://github.com/sethbacon/terraform-suite-identity/issues/83)) ([d89db1a](https://github.com/sethbacon/terraform-suite-identity/commit/d89db1a2a4e537b421d98339e195a9435f88ad55))


### Refactor

* **models:** reference canonical auth.ScopeAdmin in HasAdminScope ([#74](https://github.com/sethbacon/terraform-suite-identity/issues/74)) ([3b196d1](https://github.com/sethbacon/terraform-suite-identity/commit/3b196d12901b1bed75c6e05462cfa511aa790f81))
* **store:** dedupe API-key scan logic and role-template lookup; remove unreachable oidc case ([#91](https://github.com/sethbacon/terraform-suite-identity/issues/91)) ([1861108](https://github.com/sethbacon/terraform-suite-identity/commit/1861108f48e554b439d4ad66e290a1212264a21f))

## [0.16.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.16.0...v0.16.1) (2026-06-18)


### Documentation

* add CONTRIBUTING, schema, and suite-coupling docs ([#47](https://github.com/sethbacon/terraform-suite-identity/issues/47)) ([6e53634](https://github.com/sethbacon/terraform-suite-identity/commit/6e536343a70c61ff8fcfd8f9e0ab581a5db2a7d3))
* document the identity/suite package and correct README inaccuracies ([#46](https://github.com/sethbacon/terraform-suite-identity/issues/46)) ([32ae023](https://github.com/sethbacon/terraform-suite-identity/commit/32ae0238d47d3a2836a08b3644347b6065f37ec1))

## [0.16.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.15.0...v0.16.0) (2026-06-15)


### Features

* **suite:** fold IDN hosts to punycode in CanonicalHost ([#44](https://github.com/sethbacon/terraform-suite-identity/issues/44)) ([d15b977](https://github.com/sethbacon/terraform-suite-identity/commit/d15b9778b9e6b6f212f0ee8ad30ac3a90ee3680e))

## [0.15.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.14.0...v0.15.0) (2026-06-15)


### Features

* **suite:** add CanonicalHost helper for cross-app host matching ([#42](https://github.com/sethbacon/terraform-suite-identity/issues/42)) ([0c8ef74](https://github.com/sethbacon/terraform-suite-identity/commit/0c8ef74feb6d8978ca6f353cf6685592fd5124ce))

## [0.14.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.13.0...v0.14.0) (2026-06-14)


### Features

* **auth:** optional issuer pinning in TokenManager ([#40](https://github.com/sethbacon/terraform-suite-identity/issues/40)) ([95f8787](https://github.com/sethbacon/terraform-suite-identity/commit/95f87877881b093a4e01c9af76f1df58e40b49fe))

## [0.13.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.12.0...v0.13.0) (2026-06-13)


### Features

* **suite:** add runtime capability manifest + discovery client ([#36](https://github.com/sethbacon/terraform-suite-identity/issues/36)) ([e80838e](https://github.com/sethbacon/terraform-suite-identity/commit/e80838e24ea4fba6e0f83964635d627049ee94ba))

## [0.12.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.11.3...v0.12.0) (2026-06-07)


### Features

* **store:** select expiry_notification_sent_at in all API key queries ([0e87fff](https://github.com/sethbacon/terraform-suite-identity/commit/0e87ffffa4ccdd3989f2535241316e0c66230ae2))

## [0.11.3](https://github.com/sethbacon/terraform-suite-identity/compare/v0.11.2...v0.11.3) (2026-06-07)


### Bug Fixes

* **store:** tolerate NULL extra_config in oidc_config reads ([#33](https://github.com/sethbacon/terraform-suite-identity/issues/33)) ([25520a1](https://github.com/sethbacon/terraform-suite-identity/commit/25520a1898d50cf92d12783ce9b787a8c5dc5412))

## [0.11.2](https://github.com/sethbacon/terraform-suite-identity/compare/v0.11.1...v0.11.2) (2026-06-06)


### Bug Fixes

* omit API key hash from JSON responses ([#29](https://github.com/sethbacon/terraform-suite-identity/issues/29)) ([ff36284](https://github.com/sethbacon/terraform-suite-identity/commit/ff36284698f1564ff1cb50428ad1c2a7f0b05bf0))

## [0.11.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.11.0...v0.11.1) (2026-06-06)


### Bug Fixes

* migration 000003 down fails — subquery not allowed in USING ([#27](https://github.com/sethbacon/terraform-suite-identity/issues/27)) ([a736f8c](https://github.com/sethbacon/terraform-suite-identity/commit/a736f8c4daee4d5c25bdf619563d5664603b6aab)), closes [#26](https://github.com/sethbacon/terraform-suite-identity/issues/26)

## [0.11.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.10.0...v0.11.0) (2026-06-05)


### ⚠ BREAKING CHANGES

* identity/models and identity/store types changed shape. Consumers must update in lockstep; TSM stays pinned to v0.10.0 until its rewrite adopts this model.

### Features

* adopt the registry identity model as canonical ([#22](https://github.com/sethbacon/terraform-suite-identity/issues/22)) ([5719eee](https://github.com/sethbacon/terraform-suite-identity/commit/5719eee8d551360c75be8e0a1654c88b3564b6b9))

## [0.10.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.9.0...v0.10.0) (2026-06-05)


### Features

* enrich OIDC provider toward the registry superset ([#20](https://github.com/sethbacon/terraform-suite-identity/issues/20)) ([22e77ea](https://github.com/sethbacon/terraform-suite-identity/commit/22e77ea10c378466ad902de02c180b359206f0e7))

## [0.9.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.8.0...v0.9.0) (2026-06-05)


### Features

* add JTI and secret rotation to JWT TokenManager ([#18](https://github.com/sethbacon/terraform-suite-identity/issues/18)) ([5feda34](https://github.com/sethbacon/terraform-suite-identity/commit/5feda34661138eabe4714138b6dbb4984c75406a))

## [0.8.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.7.0...v0.8.0) (2026-06-05)


### Features

* add identity data-access layer (store) ([#16](https://github.com/sethbacon/terraform-suite-identity/issues/16)) ([022031d](https://github.com/sethbacon/terraform-suite-identity/commit/022031dcaf0d23be3256580b229152530cda3347))

## [0.7.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.6.0...v0.7.0) (2026-06-05)


### Features

* add identity data models ([#14](https://github.com/sethbacon/terraform-suite-identity/issues/14)) ([0247053](https://github.com/sethbacon/terraform-suite-identity/commit/0247053e7f5a4cee39683f744932fefabe9b4b84))

## [0.6.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.5.0...v0.6.0) (2026-06-05)


### Features

* add generic OIDC provider ([#12](https://github.com/sethbacon/terraform-suite-identity/issues/12)) ([a6fde90](https://github.com/sethbacon/terraform-suite-identity/commit/a6fde908de31bc2385dd4435dcb3f68e220a3ef1))

## [0.5.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.4.0...v0.5.0) (2026-06-04)


### Features

* add storage-agnostic API key helpers ([#10](https://github.com/sethbacon/terraform-suite-identity/issues/10)) ([3af7cc0](https://github.com/sethbacon/terraform-suite-identity/commit/3af7cc01529cd23f911a6c97913f206500de9089))

## [0.4.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.3.1...v0.4.0) (2026-06-04)


### Features

* add app-neutral JWT TokenManager ([#8](https://github.com/sethbacon/terraform-suite-identity/issues/8)) ([38e5cbe](https://github.com/sethbacon/terraform-suite-identity/commit/38e5cbeec7ea2bbdc3cab79d0da5c9e84b59ecc3))

## [0.3.1](https://github.com/sethbacon/terraform-suite-identity/compare/v0.3.0...v0.3.1) (2026-06-04)


### Bug Fixes

* **auth:** HasAllScopes returns false for empty required list ([#6](https://github.com/sethbacon/terraform-suite-identity/issues/6)) ([2637ec3](https://github.com/sethbacon/terraform-suite-identity/commit/2637ec3912c05d9aa2f554209c780719ce3321c0))

## [0.3.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.2.0...v0.3.0) (2026-06-04)


### Features

* add identity/auth package with scope-checking helpers and identity-core constants ([#4](https://github.com/sethbacon/terraform-suite-identity/issues/4)) ([bdd60e2](https://github.com/sethbacon/terraform-suite-identity/commit/bdd60e2e95eff629d7c077740022e5b0633d91ca))

## [0.2.0](https://github.com/sethbacon/terraform-suite-identity/compare/v0.1.0...v0.2.0) (2026-06-04)


### Features

* add org_quota and reconcile roles to identity-core scopes ([#2](https://github.com/sethbacon/terraform-suite-identity/issues/2)) ([6269865](https://github.com/sethbacon/terraform-suite-identity/commit/626986565c07f7d9321c58d900a63a884d70fa35)), closes [#1](https://github.com/sethbacon/terraform-suite-identity/issues/1)
