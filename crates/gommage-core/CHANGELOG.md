# Changelog — gommage-core

All notable changes to the `gommage-core` crate. Public-API semver is
enforced by `cargo-semver-checks` in CI.

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.1.1-alpha.1...gommage-core-v0.2.0-alpha.1) (2026-04-21)


### Features

* add agent quickstart setup ([8f84fc0](https://github.com/Arakiss/gommage/commit/8f84fc0c61ffa7f463e14920d487c457bd63932b))
* **core:** proptest robustness suite; drop empty fuzz.yml stub ([#12](https://github.com/Arakiss/gommage/issues/12)) ([755af07](https://github.com/Arakiss/gommage/commit/755af07ae07e929fa93b8b0e2a807230098caf57))
* **hardstop:** adversarial corpus and wrapper-evasion patterns ([#8](https://github.com/Arakiss/gommage/issues/8)) ([8132865](https://github.com/Arakiss/gommage/commit/813286502135dbccd506f61b9642099c3faa19f5))
* map agent web and mcp tools ([c3601c6](https://github.com/Arakiss/gommage/commit/c3601c6502a35c6e0b7c735998011a892b3ca7d6))


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Added

- `PictoLookup` and `PictoConsume` result types for verified picto lookup and
  verified transactional consumption.
- Capability mapper stdlib now maps Claude Code `MultiEdit` calls to
  `fs.write:<path>`.
- Capability mapper stdlib now maps Claude Code `Grep`, `WebFetch`,
  `WebSearch`, and MCP tool names.

### Changed

- Picto lookup/consume paths can now verify ed25519 signatures before granting
  an otherwise gated action.
- Policy hashes now use relative file paths plus substituted effective contents
  instead of absolute host paths and raw YAML.
- Invalid picto creation input returns typed errors instead of panicking.
- Capability mapper regex compilation now uses explicit size and nesting limits.
- Capability mapper rules can now match dynamic tool names with
  `tool_pattern` and render the actual tool name with `${tool}`.
- Policy `${HOME}` substitution is now populated even when no expedition is active.
- The determinism regression suite now loads packaged `gommage-stdlib` assets
  instead of repository-root policy and capability mapper files.

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
