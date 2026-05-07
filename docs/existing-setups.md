# Existing Setups And Migration

Gommage can be installed on a machine that already has Claude Code or Codex
rules, hooks, and custom policy scripts. The safe default is coexistence, not
replacement. Treat migration as a reviewable harness change.

## Default Posture

`gommage quickstart` is designed to add Gommage while preserving unrelated host
configuration:

- Claude Code: preserves unrelated `PreToolUse` hook groups unless
  `--replace-hooks` is passed.
- Codex: writes the Gommage Codex hook and enables Codex hooks, but does not
  rewrite Codex sandbox or approval policy.
- Backups: changed host files are backed up next to the original as
  `<name>.gommage-bak-<timestamp>`.
- Rollback: `agent uninstall`, `repair`, and `uninstall --dry-run` are the
  supported recovery surfaces.

Run dry-runs first on mature homes:

```sh
gommage quickstart --agent claude --daemon --dry-run --json
gommage quickstart --agent codex --daemon --dry-run --json
gommage agent status claude --json
gommage agent status codex --json
gommage verify --json
gommage uninstall --all --dry-run
```

## Existing Claude Hooks

Existing shell hooks and Gommage can run together. That is a valid
defense-in-depth posture, but it changes debugging:

- If an existing hook blocks first, the agent sees that hook's message and
  Gommage does not audit the decision.
- If Gommage blocks or asks first, the agent sees the Gommage reason and
  `~/.gommage/audit.log` records the signed decision.
- Use `--replace-hooks` only when the operator has reviewed the migration and
  intentionally wants Gommage to own the whole `PreToolUse` surface.

Use this to inspect and repair:

```sh
gommage agent status claude --json
gommage repair agent claude --dry-run
gommage agent uninstall claude --restore-backup --dry-run
```

## Native Claude Permissions

By default, Gommage imports supported Claude native permission rules:

- `permissions.deny` goes to `~/.gommage/policy.d/05-claude-import.yaml`.
- `permissions.allow` goes to `~/.gommage/policy.d/90-claude-allow-import.yaml`.

Supported broad allow entries such as `Bash` are imported as late allow rules.
This preserves the user's existing Claude posture while earlier hard-stops,
native deny imports, deny rules, and ask rules still win.

Use `--no-import-native-permissions` when you want a fail-closed Gommage policy
from the start and prefer to author allow rules manually.

## Capability Gaps

Gommage is capability-based. If a CLI or tool family is not mapped, policy
cannot target it precisely.

Before relying on a tool family, capture mapper output:

```sh
echo '{"tool":"Bash","input":{"command":"supabase db push"}}' \
  | gommage map --json

cat real-pretooluse-payload.json | gommage map --json --hook
```

If the emitted capability is only `proc.exec:<raw command>` or empty, add a
local mapper under `~/.gommage/capabilities.d/`, then add a policy rule and a
`gommage policy test` fixture.

## Codex Version Split

Codex upstream changed after Gommage's initial Codex integration was written.
Codex `rust-v0.124.0` can emit hooks for `apply_patch`, MCP tools, and
long-running Bash sessions. Gommage's current alpha quickstart still installs a
Bash-scoped Codex matcher and the bundled stdlib maps Bash commands for Codex.

Keep Codex sandboxing enabled:

```sh
codex exec --sandbox read-only "audit this repo"
codex exec --sandbox workspace-write "apply this refactor"
```

Do not widen the Codex matcher by hand and assume policy coverage. If you
experiment with non-Bash Codex hooks, capture real payloads, add mapper rules,
and commit fixtures before trusting the setup.

## MCP Scope

There are two MCP paths:

- Agent hook path: Claude-style `mcp__<server>__<tool>` names are mapped by the
  bundled MCP mapper when the host emits them through `PreToolUse`.
- Gateway path:

  ```sh
  gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>
  ```

  This proxies one stdio MCP server and gates `tools/call` requests before
  forwarding allowed calls upstream.

The gateway covers only the MCP server you intentionally wrap. It does not
cover unrelated MCP servers, built-in file tools, or OS-level effects below the
agent layer.

## Dual-Agent Flows

When one agent launches another, Gommage only sees the layer whose hook is
installed and whose tool call is emitted by that host.

If Claude runs `tmux send-keys -t codex 'codex exec ...'`, the Claude hook sees
the outer `tmux send-keys` command. It does not automatically see Codex's inner
tool calls. The inner Codex session is governed only if it uses a `CODEX_HOME`
with Gommage's Codex hook installed and the tool call falls inside Gommage's
mapped hook surface.

For reliable orchestrator/executor runs:

- use the same `GOMMAGE_HOME` or deliberate org/project policy layers for both
  agents;
- run `gommage agent status claude --json` and
  `gommage agent status codex --json` before the run;
- inspect `gommage policy layers --json`;
- treat denied executor calls as executor failures, not as valid partial
  results.

## Rollback

Inspect rollback before executing it:

```sh
gommage repair agent claude --dry-run
gommage repair agent codex --dry-run
gommage agent uninstall claude --restore-backup --dry-run
gommage agent uninstall codex --restore-backup --dry-run
gommage uninstall --all --dry-run
```

`gommage uninstall --purge-home` requires `--yes` because the selected
`GOMMAGE_HOME` contains the signing key, audit log, policies, local capability
mappers, approvals, and pictos. Use `--purge-backups` only when a clean slate is
intentional.
