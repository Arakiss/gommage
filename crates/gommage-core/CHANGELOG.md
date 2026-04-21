# Changelog — gommage-core

All notable changes to the `gommage-core` crate. Public-API semver is
enforced by `cargo-semver-checks` in CI.

## [0.1.0-alpha.1] — 2026-04-21

Initial release. Public API:

- `Capability`, `ToolCall`, `CapabilityMapper`, `Policy`, `Rule`, `Match`,
  `RuleDecision`, `Decision`, `EvalResult`, `MatchedRule`, `Picto`,
  `PictoStore`, `PictoStatus`, `HardStopHit`.
- `evaluate(&[Capability], &Policy) -> EvalResult`.
- `runtime::{HomeLayout, Runtime, Expedition, home_dir}`.
- `hardstop::{HARD_STOPS, check}`.
