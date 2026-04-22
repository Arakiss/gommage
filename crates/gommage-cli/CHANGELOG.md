# Changelog — gommage-cli

## [0.5.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.5.0-alpha.1...gommage-cli-v0.5.1-alpha.1) (2026-04-22)


### Bug fixes

* **cli:** label verify policy-test input ([2338899](https://github.com/Arakiss/gommage/commit/2338899a605850c13297c399274e696c70418901))

## [0.5.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.4.0-alpha.1...gommage-cli-v0.5.0-alpha.1) (2026-04-22)


### Features

* **cli:** add aggregated verification gate ([27b4b91](https://github.com/Arakiss/gommage/commit/27b4b91bb0a3196289eca928ef9e510887e71c02))
* **cli:** add gestral terminal logo ([6dfc9cf](https://github.com/Arakiss/gommage/commit/6dfc9cfef691029970a57d424320cc13b88edf1d))
* **cli:** add policy fixture tests ([cde2996](https://github.com/Arakiss/gommage/commit/cde2996829ae6bca8cff2503b984a9d0f5100635))
* **cli:** add semantic smoke checks ([27bd698](https://github.com/Arakiss/gommage/commit/27bd698986fbf8832effc98a659ce0c66dc2d468))
* **stdlib:** package bundled policy assets ([6e91243](https://github.com/Arakiss/gommage/commit/6e912433db6c130725ab5469195469f51b36ad3d))


### Bug fixes

* **cli:** satisfy smoke check lint ([846cb88](https://github.com/Arakiss/gommage/commit/846cb8882e000eb319463f3840f0cb156220d896))


### Documentation

* clarify skill and release hygiene ([d74c16d](https://github.com/Arakiss/gommage/commit/d74c16dbe42ca2a6e17e106364904431f03e0bd9))

## [0.4.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.3.0-alpha.1...gommage-cli-v0.4.0-alpha.1) (2026-04-21)


### Features

* **cli:** install daemon from quickstart ([24fdb35](https://github.com/Arakiss/gommage/commit/24fdb35ad967702c994b5579c37d44ae8261a1bd))

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.2.0-alpha.1...gommage-cli-v0.3.0-alpha.1) (2026-04-21)


### Features

* **cli:** emit structured doctor diagnostics ([0be3d2d](https://github.com/Arakiss/gommage/commit/0be3d2dfbc58dcc68fa13a552e914f3b34484095))

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.1.1-alpha.1...gommage-cli-v0.2.0-alpha.1) (2026-04-21)


### Features

* add agent quickstart setup ([8f84fc0](https://github.com/Arakiss/gommage/commit/8f84fc0c61ffa7f463e14920d487c457bd63932b))
* **audit:** audit-verify --explain with anomaly report ([#10](https://github.com/Arakiss/gommage/issues/10)) ([d2c8450](https://github.com/Arakiss/gommage/commit/d2c84506523faa3ffcbc867eb6806cde7f55c1f5))
* install daemon as user service ([61735ce](https://github.com/Arakiss/gommage/commit/61735cecc6cc52eb0b82414c092a94113312eafa))
* map agent web and mcp tools ([c3601c6](https://github.com/Arakiss/gommage/commit/c3601c6502a35c6e0b7c735998011a892b3ca7d6))


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Added

- `gommage policy init --stdlib`.
- `gommage quickstart` for one-command home, stdlib, permission-import, and hook setup.
- `gommage agent install claude|codex` for targeted hook installation.
- `gommage daemon install|status|uninstall` for user-level launchd/systemd service management.
- `gommage verify` / `--json` for one readiness gate that aggregates doctor, semantic smoke checks, and repeated `--policy-test <file>` fixtures.
- `gommage smoke` / `gommage smoke --json` for semantic post-install fixtures covering hard-stop, fail-closed, allow, ask-picto, web, and MCP policy paths.
- `gommage policy test <file>` / `--json` for user-owned YAML policy regression fixtures with per-case capabilities, matched rule, actual decision, expected decision, and mismatch errors.
- `gommage mascot` / `gommage logo` for the Gommage Gestral terminal logo, with an interactive Gommage Teal to Picto Gold gradient and `--plain` / `NO_COLOR` script-safe output.
- Claude quickstart now includes `Grep`, `WebFetch`, `WebSearch`, and MCP matcher coverage when native allow rules permit those tools.
- `gommage doctor`.
- Structured `gommage explain <audit-id>` output plus `--json`.
- Human TTL suffix parsing for `gommage grant --ttl`.

### Changed

- Picto grant/revoke/confirm actions now emit signed audit lifecycle events.
- `gommage decide` remains evaluation-only and does not consume pictos.
- Invalid picto creation input now exits cleanly instead of panicking.
- Bundled stdlib installation now embeds assets from `gommage-stdlib` instead
  of repository-root paths.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.1.0-alpha.1...gommage-cli-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. `gommage` binary with subcommands for init, expedition,
pictos, policy lint, audit, tail, explain, decide, mcp.
