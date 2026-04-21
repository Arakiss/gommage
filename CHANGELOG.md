# Changelog

All notable changes to Gommage (the repo as a whole) are documented here.
Per-crate changelogs live in `crates/*/CHANGELOG.md` and are maintained by
release-please.

Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) —
`gommage-core` follows strict public-API semver, enforced by
`cargo-semver-checks` in CI.

## [Unreleased]

### Known issues

- `serde_yaml 0.9.34` is unmaintained upstream. Tracked for replacement with
  `serde_yaml_ng` or `serde_yml` before `v0.2`.
- Daemon lacks SIGHUP policy-reload wiring (the primitive exists in
  `Runtime::reload_policy` but no signal handler is installed yet).
- No TUI dashboard (`gommage watch`) — only CLI tail for now.

## [0.1.0-alpha.1] — 2026-04-21

Initial scaffold. See commit `fcb4dfd` for the full diff.

### Added

- Cargo workspace with 5 crates: `gommage-core`, `gommage-audit`,
  `gommage-cli`, `gommage-daemon`, `gommage-mcp`.
- Deterministic policy evaluator: YAML rules + glob-matched capabilities,
  first-match wins, fail-closed default.
- Capability mapper: regex-driven tool-call → capability template rendering.
- Hardcoded hard-stop set (`rm -rf /*`, `dd if=* of=/dev/*`, fork bomb, etc.).
- Signed pictos: `ed25519` signatures, SQLite store, TTL ≤24 h, atomic
  `consume()`, status lifecycle (`active`/`pending_confirmation`/`spent`/
  `revoked`/`expired`).
- Line-signed append-only audit log with `gommage audit-verify`.
- CLI subcommands: `init`, `expedition start|end|status`, `grant`, `list`,
  `revoke`, `confirm`, `policy check|lint|hash`, `tail [-f]`, `explain`,
  `audit-verify`, `decide`, `mcp`.
- Daemon (`gommage-daemon`) over Unix socket, line-delimited JSON protocol.
- MCP / PreToolUse hook adapter (`gommage-mcp`) compatible with Claude Code.
- Stdlib policies + capability mappers (git, filesystem, package managers,
  cloud deploys).
- Determinism regression suite: 16 fixtures, forward vs shuffled, two-pass
  comparison.
- GitHub Actions: `ci.yml` (fmt, clippy `-D warnings`, test on
  macOS+Linux, policy lint, 10× determinism sweep), `release.yml` (matrix
  build), `fuzz.yml` (scaffolding).

[Unreleased]: https://github.com/Arakiss/gommage/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/Arakiss/gommage/releases/tag/v0.1.0-alpha.1
