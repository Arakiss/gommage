# Changelog

All notable changes to Gommage (the repo as a whole) are documented here.
Per-crate changelogs live in `crates/*/CHANGELOG.md` and are maintained by
release-please.

Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) —
`gommage-core` follows strict public-API semver, enforced by
`cargo-semver-checks` in CI.

## [Unreleased]

### Added

- Signed audit lifecycle events for picto create/confirm/consume/revoke/reject and policy reloads. `audit-verify` and `audit-verify --explain` now verify mixed decision/event JSONL logs.
- `gommage policy init --stdlib` installs the bundled stdlib policies and capability mappers without requiring manual file copies.
- `gommage quickstart` and `gommage agent install` bootstrap Claude Code/Codex integrations with config backups, stdlib install, Claude native deny-rule import, and hook installation.
- `gommage daemon install|status|uninstall` manages user-level launchd/systemd services so long sessions no longer require a foreground daemon process.
- Stdlib capability coverage for Claude `Grep`, `WebFetch`, `WebSearch`, and MCP tool names (`mcp__<server>__<tool>`), with conservative picto defaults for web/MCP surfaces.
- Sigstore keyless signing for release archives plus installer verification of both Cosign bundles and SHA-256 checksums.
- `gommage doctor` diagnoses the local home, key, policy, capability mapper, audit log, and daemon socket state.
- Structured `gommage explain <audit-id>` output with exact id matching plus `--json` for the raw verified entry shape.
- `gommage grant --ttl` now accepts duration suffixes (`s`, `m`, `h`, `d`) as well as raw seconds.
- Property-based robustness suite (`crates/gommage-core/tests/proptest_robustness.rs`): 4 properties covering the capability mapper, policy YAML parser, picto signature verifier, and evaluator. 1536 randomised inputs per CI run across all four properties. Asserts: no panic on arbitrary tool-call JSON, no panic on arbitrary YAML (either `Ok(Policy)` or typed error), signature verification rejects random 64-byte blobs, evaluator always returns one of the three decision variants.
- `docs/agent-compatibility.md` — per-agent matrix of what Gommage sees, what it does NOT see, what bypasses it, and the recommended OS-level stack to layer underneath. Currently covers Claude Code (all mapped tools) and OpenAI Codex CLI (Bash-only per upstream), plus explicit "why not yet" rows for Cursor, Aider, Cline, Continue, Zed. Positions as a credibility artefact: stale rows are a bug.
- `gommage audit-verify --explain` — forensic report over the entire audit log. Reports entries total vs verified, the signing key's fingerprint (SHA-256[..16] of the verifying key bytes), every anomaly encountered (bad signature, malformed entry, timestamp out of order, mid-log policy version change), the set of policy versions observed, and the set of expeditions seen. Exits 1 when any anomaly fires. Plain `audit-verify` still prints the one-line count and errors on the first bad line.
- `gommage_audit::VerifyReport`, `gommage_audit::Anomaly`, `gommage_audit::explain_log`, `gommage_audit::key_fingerprint` — part of `gommage-audit` public API, guarded by `cargo-semver-checks`.
- Adversarial security regression corpus (`tests/determinism/fixtures/adversarial_*.json`): 10 fixtures covering bypass attempts — shell wrappers (`bash -c`, `sh -c`, `zsh -c`), env-prefix evasion, sudo-wrapped destructive commands, xargs pipelines, newline-injected compound commands, relative-path escapes, Unicode lookalike branch names, `..`-path traversals, documented-limitation symlink-inside-expedition reads. Each fixture asserts the decision Gommage produces today and carries a `note` when the assertion documents a known limitation.
- 9 new hardstop patterns extending compiled-in set: `bash -c *rm -rf /*`, `sh -c *rm -rf /*`, `zsh -c *rm -rf /*`, `env *rm -rf /*`, `sudo bash -c *rm -rf /*`, `sudo sh -c *rm -rf /*`, `*xargs rm -rf*`, plus substring catch-alls `*rm -rf /*` and `*dd if=* of=/dev/*` to cover newline / compound-command evasion.
- Policy default `deny-dotdot-escape` in `10-filesystem.yaml`: any `fs.read` / `fs.write` capability whose path contains `..` is denied before `allow-project-*` can match.
- `docs/input-schema.md` — canonical decision-input contract. Frozen schema for `ToolCall`, explicit list of what the evaluator does NOT read (clock, env, CWD, filesystem state, transcript), path handling rules (opaque UTF-8, no symlink / normalisation / case-folding), and the semver policy that governs future changes to this contract.
- Cross-platform determinism CI matrix: the 10× sweep now runs across `{ubuntu-latest, macos-latest}` × `{C, en_US.UTF-8, de_DE.UTF-8}` (5 combinations total). An umbrella job `determinism sweep (all)` rolls matrix results into a single required status check on branch protection.

### Changed

- Picto lookup and consumption now verify ed25519 signatures before a stored row can convert `ask_picto` into `allow`; tampered rows remain unconsumed and emit `picto_rejected` audit events.
- `gommage-mcp` daemon-absent fallback now writes signed audit entries instead of silently evaluating without audit.
- Policy version hashes now use relative policy file paths plus substituted effective contents, making identical policy trees path-stable across homes while distinguishing different effective canvases.
- Invalid picto creation input now returns typed CLI errors instead of panicking.
- Capability mapper regex compilation now uses explicit size and nesting limits.
- Capability mapper rules can now use `tool_pattern` for dynamic tool names and `${tool}` in capability templates.
- Policy `${HOME}` substitution is now available even when no expedition is active.
- Threat model rewritten around 10 concrete attacker cases (malicious agent binary, hostile local user, malicious repo, forged pictos, TOCTOU between decision and execution, replayed out-of-band approvals, clock skew, Unicode/case-folding tricks, regex DoS in mapper, YAML deserialization attacks). Each case spells out what Gommage does, what it does not, and what to stack on top.
- Canonical decision input now explicitly documented: the evaluator reads only `(capabilities, policy)` — no clock, env, CWD, filesystem state, or transcript. Path strings are treated as opaque UTF-8 with no symlink resolution or normalization.
- `"zero heuristics"` claim redefined brutally: regex matching and glob matching are deterministic transforms and part of the contract, not heuristics; classifiers, ML scoring, prior accumulation, and intent inference are.
- README repositioned from "permission harness" to **"policy decision and audit harness"** — Gommage does not mediate execution and is not a sandbox. Users are pointed at OS-level confinement (AppArmor, SELinux, seccomp, macOS Seatbelt, Codex `--sandbox`) as the complementary layer.

### Added

- Cloud-tools capability pack (`capabilities/cloud-tools.yaml`) mapping `kubectl` (apply, delete, exec, rollout, scale, port-forward, read-only variants), `terraform` (apply, destroy, read-only variants), `aws` (s3 rm/rb, iam write actions, ec2 terminate, read-only variants), and `gh` (pr merge, release create, workflow run, repo delete) into the capability vocabulary.
- Stdlib policy pack `policies/50-cloud-tools.yaml` with conservative defaults: read-only variants pass; every state-mutating action requires a picto except `gh repo delete`, which is policy-level hard-stopped.
- 12 new determinism fixtures covering the cloud tools above (forward + shuffled sweep both green).
- `scripts/install.sh`: one-liner installer that downloads the platform tarball from GitHub Releases, verifies the SHA-256 checksum, and drops the three binaries into `$GOMMAGE_BIN` (default `~/.local/bin`). Refuses to install on checksum mismatch.
- Daemon reloads its policy + capability mappers on `SIGHUP` without restarting — standard Unix convention for long-running daemons. `SIGTERM` and `SIGINT` now trigger graceful shutdown.

### Changed

- Migrated `serde_yaml` → `serde_yaml_ng 0.10.0` via cargo alias (`serde_yaml = { package = "serde_yaml_ng", … }`). Zero in-tree code changes thanks to the alias; the unmaintained upstream is now behind us.

### Removed

- `.github/workflows/fuzz.yml` — the scheduled stub was never populated with real cargo-fuzz targets. Property-based testing via `proptest` now runs on every CI build, covering the same surfaces with tighter feedback and without the nightly-Rust infra.

### Known issues

- No TUI dashboard (`gommage watch`) — only CLI tail for now.
- No webhook out-of-band channel yet.

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
