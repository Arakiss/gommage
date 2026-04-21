# Changelog — gommage-core

All notable changes to the `gommage-core` crate. Public-API semver is
enforced by `cargo-semver-checks` in CI.

## [Unreleased]

### Added

- `PictoLookup` and `PictoConsume` result types for verified picto lookup and
  verified transactional consumption.

### Changed

- Picto lookup/consume paths can now verify ed25519 signatures before granting
  an otherwise gated action.
- Policy hashes now use relative file paths plus substituted effective contents
  instead of absolute host paths and raw YAML.
- Invalid picto creation input returns typed errors instead of panicking.
- Capability mapper regex compilation now uses explicit size and nesting limits.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.1.0-alpha.1...gommage-core-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **ci:** actually set explicit version in gommage-core Cargo.toml ([04b2c3e](https://github.com/Arakiss/gommage/commit/04b2c3e5a499c84e4a795db87732ebfce93e7d2c))
* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. Public API:

- `Capability`, `ToolCall`, `CapabilityMapper`, `Policy`, `Rule`, `Match`,
  `RuleDecision`, `Decision`, `EvalResult`, `MatchedRule`, `Picto`,
  `PictoStore`, `PictoStatus`, `HardStopHit`.
- `evaluate(&[Capability], &Policy) -> EvalResult`.
- `runtime::{HomeLayout, Runtime, Expedition, home_dir}`.
- `hardstop::{HARD_STOPS, check}`.
