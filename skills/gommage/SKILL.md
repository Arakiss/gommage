---
name: gommage
description: Install, configure, verify, troubleshoot, or operate the Gommage policy decision and audit harness for AI coding agents. Use when an agent is asked to set up Gommage, wire Claude Code or Codex hooks, install or manage the daemon, diagnose `gommage doctor` output, reason about Gommage policies/capability mappers/pictos/audit logs, evaluate release artifacts, or answer whether crates.io installation is supported.
---

# Gommage

Gommage is an alpha policy-as-code harness for AI coding agent tool calls. It is not an OS sandbox; keep the agent's native sandbox or permission layer enabled unless the user explicitly chooses otherwise.

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
  | sh -s -- --version gommage-cli-vX.Y.Z-alpha.N --bin-dir "$HOME/.local/bin"
```

5. Set up the target agent:

```sh
gommage quickstart --agent claude --daemon
gommage quickstart --agent codex --daemon
```

6. Verify:

```sh
gommage doctor
gommage verify --json
gommage doctor --json
gommage smoke --json
# Optional, when the repository includes policy fixtures.
gommage verify --json --policy-test path/to/policy-fixtures.yaml
```

Treat `verify --json` status as:

- `pass`: doctor, built-in smoke checks, and requested policy fixtures passed.
- `warn`: operable, commonly before the first audit entry or without a daemon socket.
- `fail`: do not trust the hook path until fixed.

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

Do not recommend `cargo install gommage-cli` yet. As of April 21, 2026, the `gommage-*` crates are not published on crates.io and the manifests intentionally keep `publish = false`. The bundled stdlib is packaged in `gommage-stdlib`, but the full publish gate still needs to pass before crates.io becomes a supported install path.

## Agent Notes

- Agent skill install destinations:
  - Codex: `${CODEX_HOME:-$HOME/.codex}/skills/gommage`
  - Claude Code: `${CLAUDE_HOME:-$HOME/.claude}/skills/gommage`
- Agent automation should prefer `gommage verify --json`, `gommage verify --json --policy-test <file>`, `gommage doctor --json`, `gommage map --json`, `gommage map --json --hook`, `gommage smoke --json`, `gommage policy schema`, `gommage policy test <file> --json`, `gommage policy check`, and `gommage audit-verify --explain` JSON. Use `gommage audit-verify --explain --format human` only for manual forensic review. Do not parse `gommage mascot` or `gommage logo`; they are presentation-only.
- Claude Code: `quickstart --agent claude` installs the `PreToolUse` hook, imports supported `permissions.deny` entries into `05-claude-import.yaml`, and imports narrow supported `permissions.allow` entries into `90-claude-allow-import.yaml`. Broad allow entries such as `Bash` or `*` are hook matcher input only and must be reviewed manually before becoming Gommage allow policy.
- Codex CLI: `quickstart --agent codex` enables hooks and installs a Bash-scoped hook. Codex file tools and MCP calls are outside Gommage's current hook coverage, so keep Codex sandboxing enabled.
- Daemon: `--daemon` installs and starts the user-level service. Use `--daemon-no-start` for CI/image builds that should write service files without starting them.

## Policy Operations

Useful commands:

```sh
gommage expedition start "<task-name>"
gommage expedition end
gommage policy check
gommage verify --json
gommage verify --json --policy-test path/to/policy-fixtures.yaml
gommage smoke --json
echo '{"tool":"Bash","input":{"command":"git push --force origin main"}}' \
  | gommage map --json
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | gommage map --json --hook
gommage policy schema > gommage-policy-fixture.schema.json
gommage policy test path/to/policy-fixtures.yaml --json
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' \
  | gommage policy snapshot --name main_push_requires_picto
gommage grant --scope "git.push:main" --uses 1 --ttl 10m --reason "<reason>"
gommage audit-verify
gommage audit-verify --explain --format human
gommage explain <audit-id>
```

Policies live in `~/.gommage/policy.d/`; capability mappers live in `~/.gommage/capabilities.d/`. Keep policies and `policy test` fixtures reviewed and versioned. Use `gommage map --json` to inspect raw mapper output before writing rules; add `--hook` when stdin is the real PreToolUse payload. Use `policy schema` before generating or editing fixture YAML, then use `policy snapshot` or `policy snapshot --hook` to capture a real tool call as a starter fixture and review the generated expected decision before committing it. Gommage is fail-closed when no rule matches.

## Publishing And Releases

Current alpha distribution:

- GitHub Releases provide prebuilt `gommage`, `gommage-daemon`, and `gommage-mcp` archives.
- The installer verifies Sigstore bundle identity and SHA-256 before extracting.
- The installer can also install/update this skill with `--with-skill` or `--skill-only`.
- `gommage mascot` / `gommage logo` prints the Gommage Gestral terminal logo. Use `--plain` or `NO_COLOR=1` for script-safe output.
- crates.io is not the supported install path yet.

Before claiming crates.io support, check `docs/publishing.md` and require the package gates there to pass.

## References

Read only the docs needed for the task:

- `README.md`: status, install, quickstart, roadmap.
- `docs/diagnostics.md`: `gommage doctor` and machine-readable health checks.
- `docs/agent-compatibility.md`: Claude and Codex coverage boundaries.
- `docs/policy-cookbook.md`: policy patterns and regression fixture examples.
- `docs/release-signing.md`: Sigstore and checksum verification.
- `docs/publishing.md`: crates.io status and publish gates.
- `docs/pictos.md`: signed grants and break-glass behavior.
