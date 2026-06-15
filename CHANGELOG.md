# Changelog

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
