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

- `gommage beta check` provides a single beta-readiness gate that aggregates
  doctor, smoke, agent integration status, optional policy fixtures, operator
  dashboard availability, and actionable next steps for host test loops.
- Release automation now dispatches `ci.yml` for generated release-please PR
  branches after workspace dependency pin repair, eliminating the manual empty
  commit workaround for required release PR checks.
- `ci.yml` and `audit.yml` now run trusted `pull_request_target` checks only
  for same-repository `release-please--branches--*` PRs, so generated release
  PRs receive real PR checks without broadening elevated-token execution to
  forks or arbitrary branches.
- `gommage tui --snapshot --view onboarding` adds a first-minute operator guide
  with safe setup, beta gate, report bundle, and rollback commands.
- `docs/beta-readiness.md` and a beta-readiness issue template for tracking
  launch blockers with command, workflow, release, and documentation evidence.
- `docs/roadmap.md` with the beta-to-v1 product sequence covering dry-run
  setup planning, redacted report bundles, audit replay, policy suggestions,
  live approvals, MCP gateway mode, policy packs, browser playground, and
  distribution work.
- `gommage quickstart --dry-run --json` emits a stable machine-readable setup
  plan covering home paths, stdlib files, agent hooks, native permission
  imports, daemon service plans, backup expectations, and self-test checks.
- `gommage report bundle --redact --output <file>` writes a diagnostic support
  bundle with CLI/host metadata, redacted environment hints, doctor/verify
  reports, agent status, daemon service hints, and policy/capability inventory.
- `gommage tui` opens a dependency-free, read-only operator dashboard showing
  doctor health, smoke status, Claude/Codex integration status, and next
  actions. `gommage tui --snapshot` prints a plain text dashboard for
  non-interactive terminals and issue reports.
- `gommage tui` now adds a readiness summary, focused diagnostic detail, and
  keyboard focus movement (`j`/`k`) in interactive mode while keeping snapshot
  output plain and issue-friendly.
- `gommage tui --view dashboard|policies|audit|capabilities|recovery|all`
  adds dependency-free operator views for policy inventory, signed audit
  forensics, mapper/capability inspection, and recovery shortcuts. Interactive
  TUI mode can switch views with `1`-`5`.
- README now embeds a sanitized animated TUI demo, with a static SVG fallback,
  so new users can see the operator dashboard before installing.
- `gommage tui --view approvals` adds a first-class approval inbox view.
  Interactive mode now supports two-step `A` approve and `D` deny actions for
  the selected pending request, reusing the same signed audit path as the CLI.
- `gommage approval replay <id>` compares stored approval request capabilities
  against the current policy and reports whether the request still asks for the
  same scope, now allows, now denies, or now hard-stops.
- `gommage approval evidence <id> --redact` emits a JSON support bundle with
  request state, relevant signed audit entries, audit verification summary, and
  operator commands.
- `gommage approval webhook --provider generic|slack|discord` shapes pending
  approval notifications for generic JSON, Slack incoming webhooks, or Discord
  incoming webhooks. Generic JSON remains the stable automation contract.
- `gommage approval template --provider generic|slack|discord|ntfy` prints
  provider setup notes and payload templates without sending network requests.
- `gommage tui --watch` prints repeated plain-text dashboard snapshots for
  headless operators, demos, and issue reports. `--watch-ticks <n>` bounds the
  loop for scripts and CI artifacts.
- `gommage tui --stream` prints a compact live decision/event feed. It reads
  recent events through daemon IPC when the daemon is reachable and falls back
  to the signed audit log for local and CI captures.
- `scripts/sync-workspace-internal-deps.sh` and release workflow repair
  automation keep root workspace internal dependency pins synchronized with
  release-please crate version bumps before release PRs are merged.
- `gommage tui --snapshot --view approvals` now includes selected-request
  detail, replay commands, and redacted evidence-bundle commands.
- Interactive `gommage tui --view approvals` now supports TTL and use-count
  presets before approve confirmation via `t/T` and `u/U`.
- `docs/beta-test-loop.md` documents the host-level beta feedback checklist
  from install through recovery and uninstall evidence.
- The live-doc release-reference check now skips known binary asset extensions
  so README media files do not break documentation CI.
- `ask_picto` decisions now create durable local approval requests in
  `approvals.jsonl` when no usable signed picto exists. Hook reasons include
  the exact `gommage approval approve <id>` next action. Repeated identical
  asks de-duplicate while pending, and create a new suffixed request after a
  prior request has been approved or denied.
- `gommage approval list|show|approve|deny|webhook` manages out-of-band
  approval requests. Approving a request mints an exact-scope signed picto;
  denying it removes the request from pending work; both paths emit signed
  audit events.
- `gommage approval webhook` can dry-run or POST pending approval payloads via
  a fixed `curl` invocation, and `GOMMAGE_APPROVAL_WEBHOOK_URL` enables
  best-effort hook-time webhook delivery without changing the permission
  decision when delivery fails.
- `gommage approval webhook --dry-run --json` now includes the shaped provider
  payload under `requests[].payload`, so generic, Slack, and Discord endpoint
  payloads can be inspected or piped without sending network traffic.
- `gommage approval webhook` can sign outbound approval requests with
  HMAC-SHA256 via `--signing-secret` or `GOMMAGE_APPROVAL_WEBHOOK_SECRET`.
  Dry-run JSON includes the exact signed body and signature headers; delivered
  and failed webhook audit events include non-secret signature metadata.
- Approval JSON timestamps now serialize as RFC3339/ISO-8601 strings while
  still reading legacy alpha approval logs that used time tuples.
- `gommage approval list` now defaults to pending work, supports
  `--status all` for history, and exposes top-level `id`, `created_at`,
  `tool`, and `required_scope` fields while preserving the nested `request`.
- Codex uninstall now leaves `features.codex_hooks` untouched when no Gommage
  Codex hook was found, avoiding rollback of settings Gommage did not own.
- `gommage audit-verify --explain` reports signed bypass activity with
  `bypass_activations` and `hard_stop_bypass_attempts`.
- `gommage uninstall --purge-backups` removes Gommage-created
  `.gommage-bak-*` files for known agent config, binary, and skill surfaces.
- `docs/agent-command-manifest.json` is now the canonical agent command
  contract, and CI executes it directly through
  `scripts/check-agent-command-contracts.sh`.
- `scripts/host-smoke.sh` and `docs/host-smoke.md` capture temp-home and
  reviewed real-home evidence for systemd/CachyOS and launchd/macOS hosts.
- `scripts/check-crates-publish-readiness.sh` and refreshed publishing docs
  with current crates.io evidence, package-gate status, and the explicit
  no-billing/no-publish alpha decision.
- Installer post-install hints now point agents at `quickstart --daemon
  --self-test` and the `gommage verify` readiness gate.
- Installer diagnostics now explain missing `cosign` with OS-aware hints, log
  which GitHub token environment variable is used, expose non-TTY skill-agent
  defaults, and support an explicit `--verify` post-install delegation.
- Installer `--verify` now skips cleanly on fresh installs where the Gommage
  home does not exist yet, instead of reporting the binary install as failed.
- `gommage decide` now suggests `--hook` when stdin looks like a PreToolUse
  payload with `tool_name` / `tool_input`.
- `gommage quickstart` now runs its self-test by default, checks recovery
  decisions in addition to `gommage verify`, and restores touched agent config
  snapshots if the post-install self-test fails.
- `gommage agent uninstall <claude|codex|all>` removes Gommage-managed hook
  groups and can restore the newest validated `.gommage-bak-*` backup.
- `gommage uninstall` provides dry-run cleanup for agent hooks, daemon service
  files, installed skills, binaries, and Gommage home data. Destructive home
  removal requires `--yes`.
- `GOMMAGE_BYPASS=1` for `gommage-mcp` is now policy-only break-glass:
  valid hook payloads still run through compiled hard-stop checks, bypass
  hard-stop attempts deny, and usable homes receive signed `bypass_activated`
  audit events.
- Agent command contract check (`scripts/check-agent-command-contracts.sh`) so
  README and skill command surfaces cannot drift from the binary unnoticed.
- Collision-safe `.gommage-bak-<timestamp>` backups for repeated CLI writes,
  plus installer backups for replaced binaries and installed skill files.
- Signed audit lifecycle events for picto create/confirm/consume/revoke/reject and policy reloads. `audit-verify` and `audit-verify --explain` now verify mixed decision/event JSONL logs.
- `gommage policy init --stdlib` installs the bundled stdlib policies and capability mappers without requiring manual file copies.
- `gommage quickstart` and `gommage agent install` bootstrap Claude Code/Codex integrations with config backups, stdlib install, Claude native deny-rule import, and hook installation.
- Claude Code native permission inheritance now imports supported
  `permissions.allow` entries, including broad tool allows, into a late-order
  `90-claude-allow-import.yaml` policy file while earlier hard-stops, deny
  imports, stdlib denies, and ask rules still win.
- Claude Code native permission import now normalizes `Tool(*)` and `Tool(**)`
  path scopes before grouping so broad read/write rules collapse to one
  capability rule.
- Stdlib recovery policy keeps Gommage readiness commands, basic inspection,
  systemd daemon recovery, and Claude settings backup restore commands
  available after quickstart.
- `gommage agent status <claude|codex>` reports host-agent hook wiring,
  generated Claude native-permission imports, Codex hook feature flags, and
  Codex sandbox warnings in human and JSON formats.
- `gommage daemon install|status|uninstall` manages user-level launchd/systemd services so long sessions no longer require a foreground daemon process.
- Stdlib capability coverage for Claude `Grep`, `WebFetch`, `WebSearch`, and MCP tool names (`mcp__<server>__<tool>`), with conservative picto defaults for web/MCP surfaces.
- Sigstore keyless signing for release archives plus installer verification of both Cosign bundles and SHA-256 checksums.
- `scripts/install.sh --with-skill`, `--skill-only`, and `--skill-agent codex|claude|all` so the verified installer can also install/update the Gommage agent skill for Codex and Claude Code.
- `gommage doctor` diagnoses the local home, key, policy, capability mapper, audit log, and daemon socket state.
- `gommage verify` and `gommage verify --json` aggregate doctor, semantic smoke checks, and repeated `--policy-test <file>` fixtures into one readiness gate for installers, CI, and agent skills.
- `gommage quickstart --self-test` runs the readiness gate after setup, with a
  dry-run mode that prints the planned verification without writing files.
- `gommage smoke` and `gommage smoke --json` run semantic post-install fixtures against the active mapper and policy set, covering hard-stop, fail-closed, allow, ask-picto, web, and MCP paths.
- `gommage policy test <file>` and `--json` run repository-owned YAML policy regression fixtures against the active mapper and policy set, with per-case capabilities, matched rule, actual decision, expected decision, and mismatch errors.
- `gommage policy snapshot` / `capture` reads a tool-call JSON object from
  stdin and emits a YAML regression fixture with the observed decision,
  relevant scope or hard-stop value, and matched rule.
- `gommage policy schema` prints the official JSON Schema for policy fixture
  files so agents, editors, and CI generators can validate fixture YAML before
  running semantic policy checks.
- `gommage map` and `gommage map --json` inspect `ToolCall -> capabilities`
  mapper output without evaluating policy, reading pictos, or writing audit
  entries.
- `--hook` input mode for `gommage map`, `gommage decide`, and
  `gommage policy snapshot`, allowing policy-authoring tools to consume real
  PreToolUse payloads with `tool_name`, `tool_input`, and optional `cwd`.
- `gommage audit-verify --explain --format human` renders the signed audit
  forensic report as a compact human-readable anomaly summary. Plain
  `audit-verify --explain` remains the JSON automation contract.
- `gommage mascot` / `gommage logo` prints the Gommage Gestral terminal logo with a Gommage Teal to Picto Gold gradient in interactive terminals and `--plain` / `NO_COLOR` support for script-safe output.
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
- Repository-distributed agent skill at `skills/gommage` so Codex and Claude
  Code sessions can install, verify, troubleshoot, and operate Gommage without
  rediscovering the project-specific flow.
- `gommage-stdlib` crate with packaged policy and capability mapper YAML for
  future crates.io publishing and package-local CLI embedding.
- Release invariant guard `scripts/check-workspace-internal-deps.sh`, wired
  into CI and release-please, so internal workspace dependency version
  constraints must match the crate versions they point at before alpha tags are
  cut.
- Release-reference drift guard `scripts/check-doc-release-refs.sh`, wired into
  CI and release-please, so living README/docs/script/skill examples use
  `latest` or placeholder tags instead of stale concrete alpha release tags.

### Fixed

- Hard-stop matching for shell commands now uses semantic command segments for
  destructive `rm -rf`/`dd` shapes instead of broad raw-line substring globs,
  so quoted fixture data such as `echo '{"command":"rm -rf /"}'` no longer
  blocks the agent while real direct, wrapped, compound, and substitution
  executions still hard-stop.
- Webhook signing documentation now states the exact canonical string:
  `timestamp + "." + raw_http_body`, matching the HMAC-SHA256 implementation
  and dry-run signature metadata.

### Changed

- README agent guidance now uses short command blocks and stable contract
  tables instead of an oversized all-in-one command block.
- Release automation now treats `gommage-cli-v*` as the only user-facing
  GitHub Release stream. Internal workspace crates still version through
  release-please, but skip GitHub Release publication so the Releases page does
  not present `gommage-mcp`, `gommage-daemon`, or other components as separate
  products.
- `gommage verify` human output now includes a header, top-level status, home,
  pre-init hints, and next actions while preserving the existing section lines
  and leaving `verify --json` unchanged.
- `gommage verify --json` now includes a pre-init hint and skips smoke when
  doctor already failed, avoiding noisy cascades from a missing home.
- `scripts/install.sh` now resolves `latest` by the highest matching
  `gommage-cli-v*` semantic version with a platform asset instead of trusting
  GitHub release API order, and latest installs verify the current CLI command
  contract before reporting success.
- Picto lookup and consumption now verify ed25519 signatures before a stored row can convert `ask_picto` into `allow`; tampered rows remain unconsumed and emit `picto_rejected` audit events.
- `gommage-mcp` daemon-absent fallback now writes signed audit entries instead of silently evaluating without audit.
- Policy version hashes now use relative policy file paths plus substituted effective contents, making identical policy trees path-stable across homes while distinguishing different effective canvases.
- Invalid picto creation input now returns typed CLI errors instead of panicking.
- Release checksums are emitted with archive basenames, and the installer now verifies the downloaded archive hash directly so it tolerates historical checksum path prefixes. `GOMMAGE_VERSION=latest` resolves the newest `gommage-cli-v*` release that contains the current platform archive instead of relying on GitHub's repository-level latest release. Private-release installs can pass `GOMMAGE_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN` for authenticated GitHub downloads.
- Capability mapper regex compilation now uses explicit size and nesting limits.
- Capability mapper rules can now use `tool_pattern` for dynamic tool names and `${tool}` in capability templates.
- Policy `${HOME}` substitution is now available even when no expedition is active.
- Threat model rewritten around 10 concrete attacker cases (malicious agent binary, hostile local user, malicious repo, forged pictos, TOCTOU between decision and execution, replayed out-of-band approvals, clock skew, Unicode/case-folding tricks, regex DoS in mapper, YAML deserialization attacks). Each case spells out what Gommage does, what it does not, and what to stack on top.
- Canonical decision input now explicitly documented: the evaluator reads only `(capabilities, policy)` — no clock, env, CWD, filesystem state, or transcript. Path strings are treated as opaque UTF-8 with no symlink resolution or normalization.
- `"zero heuristics"` claim redefined brutally: regex matching and glob matching are deterministic transforms and part of the contract, not heuristics; classifiers, ML scoring, prior accumulation, and intent inference are.
- README repositioned from "permission harness" to **"policy decision and audit harness"** — Gommage does not mediate execution and is not a sandbox. Users are pointed at OS-level confinement (AppArmor, SELinux, seccomp, macOS Seatbelt, Codex `--sandbox`) as the complementary layer.
- README now frames Gommage as one layer in a broader AI agent harness
  engineering stack and documents the agent skill as part of the install
  surface.
- README now includes a dedicated agent-operator section separating stable
  machine-readable contracts from decorative human-only CLI output.
- `gommage-cli` now embeds bundled defaults through `gommage-stdlib` instead of
  repository-root asset paths.

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

- `gommage tui` is still keyboard-driven and dependency-free; approval
  resolution is confirmation-based, not a full editable form for TTL/uses/reason.
- Signed remote approval callbacks and native ntfy sending remain roadmap
  items. Slack/Discord support is provider-shaped notification payloads, not a
  remote approval protocol.

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
