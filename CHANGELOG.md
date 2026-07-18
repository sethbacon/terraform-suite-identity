# Changelog

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
