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
- Policy: installs strict posture by default. Unmatched shell, file, and
  outbound capabilities remain fail-closed; broad agent convenience allows
  require an explicit `--relaxed`.
- Backups: changed host files are backed up next to the original as
  `<name>.gommage-bak-<timestamp>`.
- Runtime: after all agent and policy edits, a successful quickstart makes one
  bounded daemon reload request. Standalone `agent install` does the same after
  its single integration change. A missing or connection-refused listener is a
  warning; connection, write, or read timeout, another connection error, a
  rejection, or an invalid/incomplete/oversized response fails setup. Rollback
  may issue a second reload to reapply restored files.
- Rollback: `agent uninstall`, `repair`, and `uninstall --dry-run` are the
  supported recovery surfaces.

Run dry-runs first on mature homes:

```sh
gommage harness diagnose --json
gommage quickstart --agent claude --daemon --dry-run --json
gommage quickstart --agent claude --daemon --dry-run --explain
gommage quickstart --agent codex --daemon --dry-run --json
gommage agent status claude --json
gommage agent status codex --json
gommage verify --json
gommage uninstall --all --dry-run
```

Use `agent_integrations[].hook.strategy` and
`agent_integrations[].hook.existing_hook_groups` in the dry-run JSON as the
local source of truth for hook mutation. In the default
`append_preserving_unrelated` strategy, unrelated hook groups are marked
`would_preserve` and stale Gommage-owned hook groups are marked
`would_remove_stale_gommage`. `--replace-hooks` changes the strategy to
`replace_all_existing` and is the only default path that removes unrelated hook
groups.

## Agent-Readable Setup Reports

Gommage does not rely on Claude Code or Codex inferring the install posture from
the README. Use the harness report commands when another agent needs a concise
local truth source:

```sh
gommage harness diagnose --json
gommage harness explain --agent claude
gommage harness explain --agent codex
gommage harness write-context --dry-run
```

`harness diagnose --json` does not install anything. It reports the selected
`GOMMAGE_HOME`, host config paths, whether non-Gommage hooks already exist,
whether a Gommage hook is installed, native Claude permission import counts,
coverage boundaries, and next commands.

After a real `gommage quickstart`, Gommage refreshes:

- `$GOMMAGE_HOME/AGENT_CONTEXT.md`
- `$GOMMAGE_HOME/integration-report.json`

Future agents should read those files or call `gommage harness explain` before
claiming what the local harness covers.

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

By default, Gommage imports supported Claude native deny rules only:

- `permissions.deny` goes to `~/.gommage/policy.d/05-claude-import.yaml`.
- `permissions.allow` remains in Claude Code and is not converted into a
  Gommage policy rule.

This keeps native denies fail-closed without silently turning broad Claude
allows such as `Bash` into Gommage allows. Claude's own permission system still
applies independently; a native allow does not make the same operation an
allow in strict Gommage policy.

Pass `--relaxed` to opt into the legacy convenience posture. Relaxed mode
creates `06-agent-config-writable.yaml` and `95-agent-catch-all.yaml`; for
Claude, supported `permissions.allow` entries are also imported as late rules
in `90-claude-allow-import.yaml`. The `06` layer deliberately grants writes to
selected agent configuration paths before the later blanket home-dotfile deny;
the `90` import and `95` catch-all load late as fallbacks. Compiled hard-stops
remain unconditional, but unmatched routine shell, file, and outbound work can
reach the generated broad allows. This is a deliberate reduction in mediation,
especially for opaque scripts and interpreters.

Use `--no-import-native-permissions` to skip Claude deny import as well. This
flag controls native permission import; it does not select relaxed posture.

## Migrating From Generated Relaxation Layers

Rerun either setup command without `--relaxed` to return the agent integration
to strict posture:

```sh
gommage quickstart --agent claude --dry-run
gommage agent install claude
```

The strict installer preflights these reserved paths before removing anything:

- `06-agent-config-writable.yaml`
- `90-claude-allow-import.yaml`
- `95-agent-catch-all.yaml`

Static generated files must match their canonical bytes. Generated Claude
permission imports must have the constrained generated rule shape and a valid
content digest; digest-less legacy imports require explicit review.
Recognized files are copied to adjacent `.gommage-bak-*` backups and then
removed. If any reserved path contains modified or custom content, installation
fails before any agent-config or reserved-policy write and preserves the file
for manual review. Standalone agent installation restores its active config and
reserved policy inventory if a later write fails. Quickstart starts a broader
journal before home initialization and restores every file/directory it may
create or replace, including key, stdlib, context, host config, and optional
service definition. Move or review custom policy instead of overwriting it.
This cleanup is separate from
`gommage policy init --remove-local-relaxations`, which targets other named
operator policy layers.

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
long-running Bash sessions. Gommage's current beta quickstart installs an
all-tools `PreToolUse` matcher. The bundled stdlib maps Bash commands, parsed
`apply_patch` file paths, and Codex MCP tool names; other emitted tools fail
closed until they have reviewed mapping and policy. Keep sandboxing enabled
because Codex still has execution paths outside its emitted hook contract.

Keep Codex sandboxing enabled:

```sh
codex exec --sandbox read-only "audit this repo"
codex exec --sandbox workspace-write "apply this refactor"
```

Do not narrow the matcher or mistake interception for semantic coverage. For a
new Codex tool, capture real payloads, add mapper rules, and commit fixtures
before allowing it.

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

The gateway is optional compatibility plumbing, not the default hook path.
New agent integrations use `gommage hook --agent <host>`. The gateway covers
only the MCP server you intentionally wrap. It does not cover unrelated MCP
servers, built-in file tools, or OS-level effects below the agent layer.

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
mappers, approvals, and pictos. It removes only Gommage's known inventory and
removes the home directory itself only when nothing unrecognized remains; it
never recursively deletes the caller-selected root. Use `--purge-backups` only
when a clean slate is intentional.
