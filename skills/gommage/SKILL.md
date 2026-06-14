---
name: gommage
description: Install, configure, verify, troubleshoot, or operate the Gommage policy decision and audit harness for AI coding agents. Use when an agent is asked to set up Gommage, wire Claude Code or Codex hooks, install or manage the daemon, diagnose `gommage doctor` output, reason about Gommage policies/capability mappers/pictos/audit logs, evaluate release artifacts, or answer whether crates.io installation is supported.
---

# Gommage

Gommage is a beta policy-as-code harness for AI coding agent tool calls. It is
not an OS sandbox; keep the agent's native sandbox or permission layer enabled
unless the user explicitly chooses otherwise. For existing harnesses, treat
Gommage as a coexistence layer first: inspect dry-runs and status reports before
asking it to replace any host hooks.

The beta contract is explicit and evidence-driven. Read
`docs/beta-contract.md` before claiming beta readiness, and use
`docs/beta-readiness.md` as the launch gate. The existence of
`gommage beta check` means "run the beta gate"; it does not mean the current
host is healthy until the command returns `pass` or an understood, documented
`warn`.

## Fast Path

1. Prefer the verified GitHub Release installer for users:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
```

2. To install binaries plus this agent skill for Codex and Claude Code:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  | sh -s -- --with-skill --skill-agent codex --skill-agent claude
```

3. To install or update only this skill:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  | sh -s -- --skill-only --skill-agent codex --skill-agent claude --no-prompt
```

4. For a pinned release or custom install directory:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  | sh -s -- --version gommage-cli-vX.Y.Z-beta.N --bin-dir "$HOME/.local/bin"
```

5. Set up the target agent. On mature dotfiles or existing hook stacks, inspect
the harness report and dry-run before applying quickstart:

```sh
# `--self-test` is the default; keep it explicit in scripts for readability.
gommage harness diagnose --json
gommage quickstart --agent claude --daemon --dry-run --json
gommage quickstart --agent claude --daemon --dry-run --explain
gommage quickstart --agent claude --daemon --self-test
gommage quickstart --agent codex --daemon --dry-run --json
gommage quickstart --agent codex --daemon --self-test
```

6. Verify:

```sh
gommage doctor
gommage tui --snapshot --view all
gommage tui --snapshot --view onboarding
gommage tui --snapshot --view approvals
gommage tui --snapshot --view metrics
gommage tui --watch --watch-ticks 2 --view approvals
gommage tui --stream --stream-ticks 1 --stream-limit 8
gommage beta check --json
gommage verify --json
gommage doctor --json
gommage smoke --json
sh scripts/launch-demo.sh
gommage report bundle --redact --output gommage-report.json
# Optional, when the repository includes policy fixtures.
gommage beta check --json --policy-test path/to/policy-fixtures.yaml
gommage verify --json --policy-test path/to/policy-fixtures.yaml
```

Treat `beta check --json` as the host-level beta gate. It aggregates doctor,
smoke, agent status, optional policy fixtures, state-index readiness, dashboard
availability, and actionable next steps. `status: "fail"` means the host should
not be used for trusted hook decisions yet; `warn` is acceptable only when the
warning is understood and documented in the beta feedback.

Treat `verify --json` status as:

- `pass`: doctor, built-in smoke checks, and requested policy fixtures passed.
- `warn`: operable, commonly before the first audit entry or without a daemon socket.
- `fail`: do not trust the hook path until fixed.

On a fresh machine, `verify --json` includes a top-level `hint` and reports
`smoke.status: "skip"` when doctor already failed. Follow the hint before
debugging policy semantics.

Treat lower-level `doctor --json` status as:

- `ok`: healthy.
- `warn`: operable, commonly before the first audit entry or without a daemon socket.
- `fail`: do not trust the hook path until fixed.

Treat `smoke --json` status as:

- `pass`: active mapper + policy semantics match the built-in harness fixtures.
- `fail`: do not trust the hook path until the unexpected decision is understood.

Use `gommage verify --json --policy-test <file>` when the repository provides
its own policy fixtures. Treat `status: "fail"` as a policy regression until
the policy or capability mapper change is reviewed.

## Source Checkout

When working inside this repository, source install is acceptable:

```sh
cargo install --path crates/gommage-cli --force
cargo install --path crates/gommage-daemon --force
cargo install --path crates/gommage-mcp --force
```

Do not recommend `cargo install gommage-cli` yet. As of May 7, 2026, the
`gommage-*` crates are not published on crates.io and the manifests
intentionally keep `publish = false`. The bundled stdlib is packaged in
`gommage-stdlib`, but the full publish gate still needs to pass before
crates.io becomes a supported install path.

## Agent Notes

- Agent skill install destinations:
  - Codex: `${CODEX_HOME:-$HOME/.codex}/skills/gommage`
  - Claude Code: `${CLAUDE_HOME:-$HOME/.claude}/skills/gommage`
- The canonical command contract is
  `docs/agent-command-manifest.json`; CI executes it via
  `scripts/check-agent-command-contracts.sh`.
- Host validation evidence should use `scripts/host-smoke.sh`; CachyOS and
  other systemd hosts should pass `--daemon-manager systemd`.
- The shortest local proof path is `sh scripts/launch-demo.sh`. It uses an
  isolated temporary home and captures quickstart dry-run, `ask_picto`,
  one-use picto allow, hard-stop deny, signed audit verification,
  `state.sqlite` rebuild/verify/stats, policy fixtures, beta check, and a TUI
  snapshot without mutating the operator's real agent config.
- Agent automation should prefer `gommage harness diagnose --json`, `gommage harness explain --json`, `gommage harness write-context --dry-run`, `gommage quickstart --dry-run --json`, `gommage quickstart --dry-run --explain`, `gommage beta check --json`, `gommage beta check --json --policy-test <file>`, `gommage verify --json`, `gommage verify --json --policy-test <file>`, `gommage report bundle --redact --output <file>`, `gommage doctor --json`, `gommage agent status claude --json`, `gommage agent status codex --json`, `gommage approval list --json`, `gommage approval list --status all --json`, `gommage approval show <id> --json`, `gommage approval replay <id> --json`, `gommage approval evidence <id> --redact`, `gommage approval webhook --dry-run --json`, `gommage approval template --provider <provider> --json`, `gommage map --json`, `gommage map --json --hook`, `gommage smoke --json`, `gommage sandbox advise --json`, `gommage state rebuild --json`, `gommage state verify --json`, `gommage state stats --json`, `gommage policy schema`, `gommage policy test <file> --json`, `gommage policy check`, `gommage policy layers --json`, `gommage policy lint --strict --json`, `gommage replay --audit <file> --policy <dir> --json`, `gommage policy diff --from <dir> --to <dir> --against <file> --json`, `gommage policy suggest --audit <file> --json`, `gommage explain <audit-id> --trace --json`, `gommage repair agent <agent> --dry-run`, `gommage agent uninstall <agent> --dry-run`, `gommage uninstall --all --dry-run`, and `gommage audit-verify --explain` JSON. `state.sqlite` is a rebuildable read-model only; never treat it as permission authority over `audit.log`, policies, or pictos. `approval list` defaults to pending; use `--status all` for history. `approval webhook --dry-run --json` exposes shaped request bodies in `requests[].payload`; signed dry-runs also expose `requests[].body` and `requests[].signature`. `sandbox advise` is advisory only and is not OS confinement. Use `gommage tui --snapshot`, especially `gommage tui --snapshot --view onboarding` for first-minute operator guidance and `gommage tui --snapshot --view metrics` for a human-readable local health summary, bounded `gommage tui --watch --watch-ticks <n>`, or bounded `gommage tui --stream --stream-ticks <n>` only when a human-readable operator report is useful; do not parse TUI output as a stable contract. Stream/snapshot output includes daemon reachability, active pictos, local counters, webhook DLQ count, and audit anomaly count when available. Use `gommage audit-verify --explain --format human` only for manual forensic review. Do not parse `gommage mascot`, `gommage logo`, or interactive `gommage tui`; they are presentation-only. Interactive `gommage tui --view approvals` may adjust TTL/use-count and approve/deny after y/n confirmation, so agents should not drive it programmatically.
- Existing host setups: quickstart preserves unrelated host hooks by default.
  Use `--replace-hooks` only when the operator intentionally wants Gommage to
  own the whole `PreToolUse` surface. Existing hooks can coexist, but the first
  layer to block determines what the agent sees; if another hook blocks before
  Gommage, Gommage cannot audit that decision.
- Agent-readable context: `gommage harness diagnose --json` is the canonical
  preinstall/local truth source for host hooks, native permission imports,
  coverage boundaries, and next commands. After real quickstart, Gommage writes
  `$GOMMAGE_HOME/AGENT_CONTEXT.md` and
  `$GOMMAGE_HOME/integration-report.json`; future agent sessions should read
  these files or call `gommage harness explain` before making coverage claims.
- Claude Code: `quickstart --agent claude` installs the `PreToolUse` hook,
  imports supported `permissions.deny` entries into `05-claude-import.yaml`,
  and imports supported `permissions.allow` entries into
  `90-claude-allow-import.yaml`. Supported broad allow entries such as `Bash`
  are imported as late allow rules, so earlier hard-stops, denies, ask rules,
  and native deny imports still win. Use `--no-import-native-permissions` when
  the operator wants to author the initial Gommage policy manually.
- Codex CLI: `quickstart --agent codex` enables hooks and installs a Gommage
  matcher for Bash, `apply_patch`, and Codex MCP tool names. `apply_patch`
  payloads are mapped to parsed filesystem write paths and fail closed when
  they cannot be parsed safely. Keep Codex sandboxing enabled because hooks do
  not intercept every shell path or non-shell, non-MCP tool call.
- Dual-agent flows: if Claude launches Codex via `tmux`, shell, or script,
  Gommage sees the outer Claude Bash call only. Inner Codex calls are governed
  only when the invoked Codex session uses a `CODEX_HOME` with Gommage's Codex
  hook installed and the tool call falls inside Gommage's mapped hook surface.
  Prefer a shared `GOMMAGE_HOME` or deliberate org/project policy layer, then
  run both `gommage agent status claude --json` and
  `gommage agent status codex --json` before the handoff.
- MCP gateway: use `gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>` only for stdio MCP servers you intentionally proxy. Allowed `tools/call` requests are forwarded; denied or picto-required calls return MCP tool errors and are not sent upstream.
- Daemon: `--daemon` installs and starts the user-level service. Use `--daemon-no-start` for CI/image builds that should write service files without starting them.
- Quickstart self-test: the readiness gate runs by default. `--self-test` remains accepted for scripts; `--no-self-test` is the manual escape hatch.
- Backups: Gommage writes `.gommage-bak-<timestamp>` backups before replacing agent configs, generated policy imports, daemon service files, installed binaries, or installed skill files when content changes. Unchanged files are not backed up.
- Recovery: use `gommage repair agent claude --dry-run` or `gommage repair agent codex --dry-run` first for old/broken alpha hooks; repair rewrites Gommage-owned hook groups to the current scoped hook while preserving unrelated hooks. Use `gommage agent uninstall claude --restore-backup`, `gommage agent uninstall codex --restore-backup`, or `gommage uninstall --all --dry-run` before destructive cleanup. `--purge-home` requires `--yes`; `--purge-backups` removes Gommage-created `.gommage-bak-*` files only when a clean slate is intentional.
- Break-glass: `GOMMAGE_BYPASS=1` is a policy bypass, not a hard-stop bypass. Valid hook payloads are still mapped and compiled hard-stops still deny; when a usable home/key exists, bypass writes a signed `bypass_activated` audit event. Use only to recover a broken hook path.
- Hard-stop scope for `rm -rf`: this is **any-absolute-path**, not root-only. Despite the `hs.rm-rf-root` id and the `rm -rf /*` glob, `rm -rf` of any argument beginning with `/` is denied (e.g. `/tmp/scratch`, `/home/me/build`), because the glob `*` crosses `/` and a shell-semantic scanner independently flags `rm` with `r`+`f` flags plus a `/`-leading argument (also through `bash -c`, `sudo`/`env` prefixes, `;`/`&&`, and `$(...)`). Relative paths (`./build`, `node_modules`) are deliberately out of scope — gate those at the policy layer. To clear an absolute scratch dir, `cd` into its parent and delete by relative name rather than forcing the gate; there is no picto for a hard-stop. See `THREAT_MODEL.md` for the rationale (intentional blast-radius containment).

## Policy Operations

Useful commands:

```sh
gommage expedition start "<task-name>"
gommage expedition end
gommage policy check
gommage verify --json
gommage verify --json --policy-test path/to/policy-fixtures.yaml
gommage tui --snapshot
gommage tui --snapshot --view all
gommage tui --snapshot --view approvals
gommage tui --snapshot --view metrics
gommage tui --watch --watch-ticks 2 --view approvals
gommage tui --stream --stream-ticks 1 --stream-limit 8
gommage agent status claude --json
gommage agent status codex --json
gommage agent uninstall claude --restore-backup --dry-run
gommage uninstall --all --dry-run
gommage smoke --json
echo '{"tool":"Bash","input":{"command":"git push --force origin main"}}' \
  | gommage map --json
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | gommage map --json --hook
gommage policy schema > gommage-policy-fixture.schema.json
gommage policy test path/to/policy-fixtures.yaml --json
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' \
  | gommage policy snapshot --name main_push_requires_picto
gommage policy suggest --audit path/to/audit.log --json
gommage grant --scope "git.push:main" --uses 1 --ttl 10m --reason "<reason>"
gommage approval list --json
gommage approval list --status all --json
gommage approval replay <approval-id> --json
gommage approval evidence <approval-id> --redact
gommage approval webhook --url "$GOMMAGE_APPROVAL_WEBHOOK_URL" --dry-run --json
gommage approval webhook --url "$GOMMAGE_APPROVAL_WEBHOOK_URL" --dry-run --json --signing-secret "$GOMMAGE_APPROVAL_WEBHOOK_SECRET"
gommage approval template --provider slack --json
gommage audit-verify
gommage audit-verify --explain --format human
gommage explain <audit-id>
```

Policies live in `~/.gommage/policy.d/`; capability mappers live in `~/.gommage/capabilities.d/`. Keep policies and `policy test` fixtures reviewed and versioned. Use `gommage map --json` to inspect raw mapper output before writing rules; add `--hook` when stdin is the real PreToolUse payload. Use `policy schema` before generating or editing fixture YAML, then use `policy snapshot` or `policy snapshot --hook` to capture a real tool call as a starter fixture and review the generated expected decision before committing it. Use `policy suggest --audit <file> --json` only as advisory authoring input: it never mutates active policy and generated fixture drafts are not usable until raw input is captured. Gommage is fail-closed when no rule matches.

## Publishing And Releases

Current beta distribution:

- GitHub Releases provide one platform archive that contains the prebuilt
  `gommage`, `gommage-daemon`, and `gommage-mcp` binaries. The installer copies
  all three into the selected bin directory.
- The installer verifies Sigstore bundle identity and SHA-256 before extracting.
- `~/.gommage/state.sqlite` is a local SQLite read-model for fast TUI metrics
  and stream fallback. Rebuild with `gommage state rebuild`; verify with
  `gommage state verify --json`. The signed `audit.log` remains authoritative.
- Installing the `gommage-mcp` binary does not auto-register a universal MCP
  gateway. Agent hooks invoke it after `quickstart`; gateway mode remains
  explicit per stdio MCP server with `gommage-mcp --gateway --server-name
  <name> -- <stdio-mcp-server>`.
- Use `gommage release verify --all-assets --json --require-sbom --require-provenance` for full beta/RC release evidence. For current-platform checks, use `gommage release verify --json --require-sbom --require-provenance`; from a checkout, `sh scripts/verify-release.sh --json --require-sbom --require-provenance` provides the shell fallback.
- The installer can also install/update this skill with `--with-skill` or `--skill-only`.
- `gommage mascot` / `gommage logo` prints the Gommage Gestral terminal logo. Use `--plain` or `NO_COLOR=1` for script-safe output.
- crates.io is not the supported install path yet.

Before claiming crates.io support, check `docs/publishing.md` and require the package gates there to pass.

## References

Read only the docs needed for the task:

- `README.md`: status, install, quickstart, roadmap.
- `docs/existing-setups.md`: migration, coexistence with existing hooks,
  dual-agent flows, MCP scope, and rollback.
- `docs/beta-contract.md`: beta promise, stable beta surfaces, explicit
  non-promises, recommended trial path, and release transition rule.
- `examples/launch-demo/README.md`: local demo evidence files and recording
  path.
- `docs/diagnostics.md`: `gommage doctor` and machine-readable health checks.
- `docs/agent-compatibility.md`: Claude and Codex coverage boundaries.
- `docs/policy-cookbook.md`: policy patterns and regression fixture examples.
- `docs/release-signing.md`: Sigstore and checksum verification.
- `docs/publishing.md`: crates.io status and publish gates.
- `docs/pictos.md`: signed grants and break-glass behavior.
