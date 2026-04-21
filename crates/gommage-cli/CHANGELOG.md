# Changelog — gommage-cli

## [Unreleased]

### Added

- `gommage policy init --stdlib`.
- `gommage quickstart` for one-command home, stdlib, permission-import, and hook setup.
- `gommage agent install claude|codex` for targeted hook installation.
- `gommage daemon install|status|uninstall` for user-level launchd/systemd service management.
- Claude quickstart now includes `Grep`, `WebFetch`, `WebSearch`, and MCP matcher coverage when native allow rules permit those tools.
- `gommage doctor`.
- Structured `gommage explain <audit-id>` output plus `--json`.
- Human TTL suffix parsing for `gommage grant --ttl`.

### Changed

- Picto grant/revoke/confirm actions now emit signed audit lifecycle events.
- `gommage decide` remains evaluation-only and does not consume pictos.
- Invalid picto creation input now exits cleanly instead of panicking.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.1.0-alpha.1...gommage-cli-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. `gommage` binary with subcommands for init, expedition,
pictos, policy lint, audit, tail, explain, decide, mcp.
