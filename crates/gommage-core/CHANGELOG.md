# Changelog — gommage-core

All notable changes to the `gommage-core` crate. Public-API semver is
enforced by `cargo-semver-checks` in CI.

## [0.15.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.14.1-alpha.1...gommage-core-v0.15.0-alpha.1) (2026-06-30)


### Features

* **release:** prepare crates.io publishing ([9426ff4](https://github.com/Arakiss/gommage/commit/9426ff4656fa55a65cc5fc4f5f4d53667518acd5))

## [0.14.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.14.0-alpha.1...gommage-core-v0.14.1-alpha.1) (2026-06-28)

## [0.14.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.13.2-alpha.1...gommage-core-v0.14.0-alpha.1) (2026-06-28)


### Features

* harden hook write context and matcher coverage ([0952518](https://github.com/Arakiss/gommage/commit/0952518f8b91446d20ae2ff1a6d137da1e348c1d))


### Bug fixes

* **shell:** honor backslash escapes in command_substitutions ([#95](https://github.com/Arakiss/gommage/issues/95)) ([90b27d0](https://github.com/Arakiss/gommage/commit/90b27d03fe5ccdb245520fbf101e9756a7d5552e))

## [0.13.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.13.1-alpha.1...gommage-core-v0.13.2-alpha.1) (2026-06-12)


### Bug fixes

* **core:** strip shell redirections before refspec capture ([65411a5](https://github.com/Arakiss/gommage/commit/65411a5d36be735fd556c7feec4405b913ff1c48))
* **mcp:** honor GOMMAGE_BYPASS in the legacy gommage mcp adapter ([a593998](https://github.com/Arakiss/gommage/commit/a59399890dc218d33b465800133e469b9f877ad3))

## [0.13.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.13.0-alpha.1...gommage-core-v0.13.1-alpha.1) (2026-06-04)

## [0.13.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.12.0-alpha.1...gommage-core-v0.13.0-alpha.1) (2026-06-04)


### Features

* **stdlib:** gate publish, persistence, device-write, docker escape ([#79](https://github.com/Arakiss/gommage/issues/79)) ([837a6ae](https://github.com/Arakiss/gommage/commit/837a6aeeb0c552d63637b0bb08ba1a48fa0f086b))

## [0.12.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.11.0-alpha.1...gommage-core-v0.12.0-alpha.1) (2026-06-04)


### Features

* **core:** shell-aware bash mapper closes command-shape gate evasions ([#77](https://github.com/Arakiss/gommage/issues/77)) ([8b08a3b](https://github.com/Arakiss/gommage/commit/8b08a3b4f4f240f864be555ae08b5d419afa1f09))

## [0.11.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.10.0-alpha.1...gommage-core-v0.11.0-alpha.1) (2026-06-04)


### Features

* **cli:** proactively notify when a new gommage version is available ([#74](https://github.com/Arakiss/gommage/issues/74)) ([4149f6c](https://github.com/Arakiss/gommage/commit/4149f6c9a5caf421dafab8e735529db9608a734b))

## [0.10.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.9.1-alpha.1...gommage-core-v0.10.0-alpha.1) (2026-05-24)


### Features

* add agent quickstart setup ([54ee041](https://github.com/Arakiss/gommage/commit/54ee041b6bc7a0fbb34f55c0c6412b151a9a4ece))
* add explain trace and strict policy lint ([a03043c](https://github.com/Arakiss/gommage/commit/a03043c71a6e08e72acd4f26154d8307ac1f162d))
* add out-of-band approval workflow ([5612978](https://github.com/Arakiss/gommage/commit/56129785737db7dbb686c0e4f4c95cc7cbf2aa53))
* add rebuildable sqlite state index ([403cd6a](https://github.com/Arakiss/gommage/commit/403cd6a6b18efb5a8ce2d97ac99d90228441f5fa))
* **core:** proptest robustness suite; drop empty fuzz.yml stub ([#12](https://github.com/Arakiss/gommage/issues/12)) ([86a0bf3](https://github.com/Arakiss/gommage/commit/86a0bf370379136cabaa8925472b120ecd15d50f))
* expand coverage beyond hooks ([77fc3da](https://github.com/Arakiss/gommage/commit/77fc3da5f5e90f4ed2f7d40924a3cc120d4c9d4e))
* **hardstop:** adversarial corpus and wrapper-evasion patterns ([#8](https://github.com/Arakiss/gommage/issues/8)) ([b033f93](https://github.com/Arakiss/gommage/commit/b033f93696f068e5a0493078f738921e55c39e06))
* make approval webhooks recoverable ([69eba2e](https://github.com/Arakiss/gommage/commit/69eba2e869f329a2a4d6af6ce908dd6a4956bd25))
* map agent web and mcp tools ([2878452](https://github.com/Arakiss/gommage/commit/287845271027bc9bf359c5f46556c08cf8c047e3))
* sign approval webhook deliveries ([3bd919a](https://github.com/Arakiss/gommage/commit/3bd919ac0312a2e285c7fd93384977482a67c762))
* **stdlib:** package bundled policy assets ([a2abc3b](https://github.com/Arakiss/gommage/commit/a2abc3b8a19ff28b1924afdd4505a78de01c845a))


### Bug fixes

* **ci:** actually set explicit version in gommage-core Cargo.toml ([04b2c3e](https://github.com/Arakiss/gommage/commit/04b2c3e5a499c84e4a795db87732ebfce93e7d2c))
* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([8d489af](https://github.com/Arakiss/gommage/commit/8d489af5c24036406fc0a6ce6eb0b1abdf214d4f))
* enforce auditable trust guarantees ([47d9731](https://github.com/Arakiss/gommage/commit/47d97312fd4fc6f81883012a907c5a65ad8e1787))
* harden hard-stop parsing and release framing ([0e30b6e](https://github.com/Arakiss/gommage/commit/0e30b6e6d49def2f0136b19a2d187c613e1908c8))
* polish approval webhook diagnostics ([3259397](https://github.com/Arakiss/gommage/commit/32593972ef0f2865d418c15210ace574bbbc8387))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))
* clarify skill and release hygiene ([36b350a](https://github.com/Arakiss/gommage/commit/36b350a0928617c20c81e978ac206408677211e5))

## [0.9.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.9.0-alpha.1...gommage-core-v0.9.1-alpha.1) (2026-05-24)

## [0.9.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.8.0-alpha.1...gommage-core-v0.9.0-alpha.1) (2026-05-07)


### Features

* add rebuildable sqlite state index ([ce5c7a0](https://github.com/Arakiss/gommage/commit/ce5c7a023b7dfbbe3bfb212924775411c2426ea3))

## [0.8.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.7.0-alpha.1...gommage-core-v0.8.0-alpha.1) (2026-04-24)


### Features

* expand coverage beyond hooks ([722a1e1](https://github.com/Arakiss/gommage/commit/722a1e13b375fafb6da0c1cff86cb3ff75533696))

## [0.7.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.6.0-alpha.1...gommage-core-v0.7.0-alpha.1) (2026-04-24)


### Features

* add explain trace and strict policy lint ([19f99fe](https://github.com/Arakiss/gommage/commit/19f99fe63ef9974224a38a56ef70ee995afd34bd))

## [0.6.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.5.1-alpha.1...gommage-core-v0.6.0-alpha.1) (2026-04-23)


### Features

* make approval webhooks recoverable ([4075edd](https://github.com/Arakiss/gommage/commit/4075eddc5242c56c68ea1af74b411c2c5d15ce2e))

## [0.5.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.5.0-alpha.1...gommage-core-v0.5.1-alpha.1) (2026-04-23)


### Bug fixes

* harden hard-stop parsing and release framing ([0490dac](https://github.com/Arakiss/gommage/commit/0490dac4ea2acae60ac2ab105a23cc1454484675))

## [0.5.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.4.1-alpha.1...gommage-core-v0.5.0-alpha.1) (2026-04-23)


### Features

* sign approval webhook deliveries ([acb4417](https://github.com/Arakiss/gommage/commit/acb4417f2ce4e567485448676547b1e10e3b6382))

## [0.4.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.4.0-alpha.1...gommage-core-v0.4.1-alpha.1) (2026-04-23)


### Bug fixes

* polish approval webhook diagnostics ([fc39ab0](https://github.com/Arakiss/gommage/commit/fc39ab07e0fc03f86df0439fb003d1160fb96c72))

## [0.4.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.3.3-alpha.1...gommage-core-v0.4.0-alpha.1) (2026-04-22)


### Features

* add out-of-band approval workflow ([159aa6c](https://github.com/Arakiss/gommage/commit/159aa6c19706ef0a2ea6db92f2407b002fedcf1f))

## [0.3.3-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.3.2-alpha.1...gommage-core-v0.3.3-alpha.1) (2026-04-22)

## [0.3.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.3.1-alpha.1...gommage-core-v0.3.2-alpha.1) (2026-04-22)

## [0.3.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.3.0-alpha.1...gommage-core-v0.3.1-alpha.1) (2026-04-22)

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-core-v0.2.0-alpha.1...gommage-core-v0.3.0-alpha.1) (2026-04-22)


### Features

* **stdlib:** package bundled policy assets ([6e91243](https://github.com/Arakiss/gommage/commit/6e912433db6c130725ab5469195469f51b36ad3d))


### Documentation

* clarify skill and release hygiene ([d74c16d](https://github.com/Arakiss/gommage/commit/d74c16dbe42ca2a6e17e106364904431f03e0bd9))

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
