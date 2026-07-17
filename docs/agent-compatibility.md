# Agent compatibility matrix

What Gommage sees, what it does not, and what can bypass it per agent. This
page documents the tested Gommage beta integration. Confirm current upstream
host behavior and capture real hook payloads before widening coverage; the
packaged capability mapper stdlib in
`crates/gommage-stdlib/capabilities/` is agent-agnostic and usually does not
need code changes. The repository-root `capabilities/` directory is a
review-friendly mirror kept in sync by CI.

If an item is listed as "Bypasses Gommage", that is not a vulnerability — it
is the boundary of what a PreToolUse-level interception layer can observe. Keep
the host's native sandbox enabled when available, and add OS or container
confinement for anything you need caught below the agent layer.

After installing an integration, run `gommage verify --json` to verify the operator path and built-in mapper + policy semantics. If the repository carries policy fixtures, run `gommage verify --json --policy-test <file>` before trusting the hook. A top-level verify `warn` is still an operable install when the only warnings are the missing first audit log or missing daemon socket. A top-level verify `fail` means the hook should not be trusted yet. See [`diagnostics.md`](diagnostics.md).

For migration guidance on mature homes, custom hooks, dual-agent flows, and
rollback, see [`existing-setups.md`](existing-setups.md).

---

## Claude Code (Anthropic)

### What Gommage sees via `PreToolUse` hook

| Tool | Forwarded input | Capability namespace |
|---|---|---|
| `Bash` | `command` | `proc.exec:*`, typed filesystem/Git/Gommage administration effects (including exact `gommage.home.mutate:*` roots), plus every compatible mapper rule (`net.out:*`, `pkg.*`, `deploy.*`, `docker.*`, `k8s.*`, `terraform.*`, `aws.*`, `gh.*`) |
| `Read` | `file_path` | `fs.read:<path>` |
| `Write` | `file_path` | `fs.write:<path>` |
| `Edit` | `file_path` | `fs.write:<path>` |
| `MultiEdit` | `file_path` | `fs.write:<path>` |
| `NotebookEdit` | `notebook_path` | `fs.write:<notebook_path>` |
| `Glob` | `pattern` | `fs.read:<pattern>` |
| `Grep` | `pattern`, `path`, `glob`; hook `cwd` is copied into reserved `__gommage_*` fields when needed | `fs.search:<path-or-glob>`, `fs.read:<path-or-glob>` |
| `WebFetch` | `url` | `net.fetch:<host>`, `net.out:<host>` |
| `WebSearch` | `query` | `net.search:web`, `net.search.query:<query>` |
| `mcp__<server>__<tool>` | full MCP tool name | `mcp.write:<tool>`, `mcp.read:<tool>`, `mcp.call:<tool>` depending on verb-like prefixes |

To extend coverage, add a mapper rule under `~/.gommage/capabilities.d/` — Claude Code forwards the full `tool_name` + `tool_input` object on every hook call. The stdlib defaults intentionally require pictos for WebFetch, WebSearch, write-like MCP tools, and unclassified MCP calls.

`gommage quickstart --agent claude` installs the hook, preserving unrelated
existing `PreToolUse` hook groups unless `--replace-hooks` is passed. It imports
supported `permissions.deny` entries from `~/.claude/settings.json` into
`~/.gommage/policy.d/05-claude-import.yaml`. Strict posture is the default:
supported `permissions.allow` entries remain native to Claude and are not
converted into Gommage policy. Use `--no-import-native-permissions` when you
want to author the initial Gommage policy manually instead of importing even
Claude's native denies.

`--relaxed` explicitly selects the legacy convenience posture. It creates the
generated `06-agent-config-writable.yaml` and `95-agent-catch-all.yaml` broad
allow layers and imports supported Claude allows such as `Bash`,
`Bash(git status *)`, and `Read(./docs/**)` into
`90-claude-allow-import.yaml`. The `06` layer is an early carve-out for selected
agent configuration writes, while the `90` import and `95` catch-all are late
fallbacks. Compiled hard-stops remain unconditional, but the broad fallback
means Gommage no longer completely mediates opaque scripts or interpreters.

Verify the host wiring after quickstart with:

```sh
gommage agent status claude --json
```

This checks the Claude settings file, the installed `PreToolUse` hook group,
and generated native permission import files without parsing the JSON settings
by hand.

### Bypasses Gommage under Claude Code

- Tool calls that Claude Code does not forward to the matched hook group.
- Any shell command the user executes directly in a terminal outside the Claude Code session.
- Runtime-created subprocesses that are not represented in the submitted
  command string. The typed shell analysis recursively walks static compound
  commands, substitutions, transparent wrappers, and static `sh -c`/`bash -c`
  payloads. Dynamic or unsupported forms emit
  `proc.exec.ambiguous:<reason>` and the shipped strict policy denies them, but
  Gommage cannot inspect a new command that a permitted process constructs only
  after execution begins.

### Recommended stack

- Enable Claude Code's native Bash sandbox when its filesystem and network
  contract fits the host; it uses Seatbelt on macOS and bubblewrap on
  Linux/WSL2.
- Keep Claude permission deny/ask rules for every tool boundary they cover. A
  Gommage hook allow does not override them.
- Add a container or stronger host confinement when the native sandbox's
  documented limits do not fit the threat model.
- Use pre-commit or pre-push controls when repository-side enforcement is also
  required outside the agent session.

### Wiring

See [`examples/claude-code-setup.md`](../examples/claude-code-setup.md).

---

## Existing Claude Hook Stacks

Existing hooks and Gommage can coexist. The default installer appends a Gommage
hook group and leaves unrelated shell hooks in place. Current Claude Code hook
semantics run all matching hooks concurrently; a deny from any matching hook
blocks the call. Gommage records and can explain its own decision, but it does
not authenticate, order, or audit another hook's independent result.

Use this sequence before changing a mature Claude home:

```sh
gommage quickstart --agent claude --daemon --dry-run --json
gommage agent status claude --json
gommage repair agent claude --dry-run
gommage uninstall --all --dry-run
```

`--replace-hooks` is a migration flag, not the default safety path.

## OpenAI Codex CLI

### What Gommage sees via `PreToolUse` hook

There are two separate facts to keep straight:

1. **Upstream Codex hook surface.** Codex `rust-v0.124.0` widened hooks so they
   can observe `apply_patch`, MCP tools, and long-running Bash sessions
   ([openai/codex#18391](https://github.com/openai/codex/pull/18391),
   [release notes](https://github.com/openai/codex/releases/tag/rust-v0.124.0)).
   Older Codex releases, including the `0.118.0` line that originally exposed
   [openai/codex#16732](https://github.com/openai/codex/issues/16732), were
   effectively Bash-only for this use case.
2. **Gommage beta default wiring.** `gommage quickstart --agent codex`
   installs an all-tools `PreToolUse` matcher. The bundled stdlib maps Bash
   commands, parsed `apply_patch` file paths, and Codex MCP tool names. An
   emitted call without mapper coverage reaches the evaluator with no resolved
   capability and fails closed. `apply_patch` payloads also fail closed when
   their file list cannot be parsed safely. The installed policy posture is
   strict by default; `--relaxed` is required to add broad generated allows.

| Tool | Upstream Codex 0.124+ hook surface | Gommage quickstart default | Capability produced today |
|---|---|---|---|
| `Bash` | yes | yes | same as Claude Code's Bash mapping |
| long-running Bash session | yes | partially, through Bash hook payloads Gommage receives | same as Bash when emitted as `Bash` |
| `apply_patch` | yes | yes | `fs.write:<parsed path>` for up to 16 parsed patch paths; unsafe/unparsed payloads emit fail-closed patch capabilities |
| Codex MCP tools | yes | yes when emitted as `mcp__server__tool` | same `mcp.read`, `mcp.write`, and `mcp.call` mapping used for Claude-style MCP names |
| other built-in tools | host-dependent | received whenever Codex emits `PreToolUse`; denied until mapped and allowed | none when unmapped |

Codex also exposes a separate `PermissionRequest` hook when it is about to ask
for native approval. Gommage's beta quickstart does not wire Pictos into that
event. Its `PreToolUse` adapter therefore converts an unmatched `ask_picto`
result to a denial rather than claiming an interactive Codex approval path.

### Bypasses Gommage under Codex

- Any Codex operation for which the host emits no `PreToolUse` payload.
- Equivalent work performed through a process or internal path outside the
  host hook contract.
- A tool without a bundled mapper does not bypass the global matcher; it is
  denied as unresolved until an operator adds and tests mapping plus policy.

### Recommended stack

Codex ships OS-level confinement as a first-class feature — **use it**:

| Sandbox mode | Native Codex contract |
|---|---|
| `--sandbox read-only` | Inspect files; edits and command execution require approval. |
| `--sandbox workspace-write` | Read files, edit within the workspace/configured writable roots, and run routine local commands inside that boundary. |
| `--sandbox danger-full-access` | No Codex sandbox restriction on filesystem or network. Use only behind another suitable boundary or when full access is intentional. |

Gommage + Codex is a layered posture: Codex's OS-level sandbox covers file and
network boundaries that are below, outside, or not yet mapped by Gommage;
Gommage governs host-emitted `PreToolUse` calls declaratively and audits its own
decisions. The default matcher is global, while positive semantic support still
depends on captured payloads, mapper rules, and policy fixtures. Other hook
families and operations Codex does not emit remain outside this contract.

For MCP tools that can be routed through a stdio proxy, the optional legacy
gateway `gommage-mcp --gateway --server-name <name> -- <upstream-command>`
provides a narrower alternative only when native hooks are not enough. The gateway evaluates MCP
`tools/call` requests as `mcp__<name>__<tool>`, forwards allowed calls, and
returns an MCP tool error without forwarding denied or picto-required calls.
This does not cover Codex built-in file tools and does not replace Codex's OS
sandbox.

Typical combos:

```sh
# Audit run — read-only, Gommage governs shell calls it sees.
codex exec --sandbox read-only "audit this repo"

# Refactor run — Codex can patch files within cwd (kernel-enforced),
# Gommage governs any Bash the agent wants to run under the default integration.
codex exec --sandbox workspace-write "apply the refactor we discussed"

# Optional MCP server through Gommage's legacy stdio gateway.
gommage-mcp --gateway --server-name filesystem -- <stdio-mcp-server> .
```

### Wiring

See [`examples/codex-setup.md`](../examples/codex-setup.md).
`gommage quickstart --agent codex` writes `~/.codex/hooks.json` and enables
`features.hooks = true`, but it does not convert Codex's OS sandbox or
approval policy into Gommage YAML. Those native controls remain authoritative
for operations outside the host-emitted `PreToolUse` path and for boundaries
below Gommage's semantic mapper coverage.

For custom Codex tools or newly hook-exposed payload shapes, do not narrow the
global matcher or assume that interception equals semantic support. Capture real payloads with
`gommage map --json --hook`, add local capability mappers, and commit policy
fixtures before trusting the result.

Verify the host wiring after quickstart with:

```sh
gommage agent status codex --json
```

This checks `hooks.json`, `config.toml`, `features.hooks`, the installed
`PreToolUse` hook group, and warns when `sandbox_mode = "danger-full-access"`
because Codex's sandbox remains the authority outside mapped hook events.

Older Codex configs may still contain the legacy `features.codex_hooks` flag.
Gommage reports that as a migration warning and rewrites the canonical
`features.hooks` setting when `gommage agent install codex` runs.

For either agent, rerunning `quickstart` or `agent install` without `--relaxed`
backs up and removes recognized Gommage-generated
`06-agent-config-writable.yaml`, `90-claude-allow-import.yaml`, and
`95-agent-catch-all.yaml` layers. Static generated files must match canonical
bytes; dynamic native imports must pass generated-shape and content-digest
validation. A modified or custom file at any reserved path is not removed: the
install stops before any integration write so the operator can review or move
it. On a successful complete policy/hook change, each command makes one bounded
daemon reload request; quickstart does not reload separately for every selected
agent. A reachable daemon must acknowledge it. Only a missing or
connection-refused listener remains a warning, and quickstart rollback may
issue a second reload for restored files.

## Dual-Agent And Nested-Agent Flows

When one agent launches another, Gommage only sees the layer whose hook is
installed and whose tool call is emitted by that host.

For example, if Claude Code runs
`tmux send-keys -t codex 'codex exec ...'`, the Claude hook sees the outer
`tmux send-keys` Bash command. It does not automatically see the commands Codex
runs inside that tmux session. Those inner calls are governed only if the Codex
session uses a `CODEX_HOME` with Gommage's Codex hook installed and the tool call
falls inside Codex/Gommage's mapped hook surface.

For reproducible orchestrator/executor setups:

- use the same `GOMMAGE_HOME` or a deliberate org/project policy layer for both
  agents;
- run `gommage agent status claude --json` and
  `gommage agent status codex --json` before the run;
- inspect active policy order with `gommage policy layers --json`;
- make handoff files robust against partial executor output; a denied inner
  call should be treated as an executor failure, not as valid research.

---

## Why not Cursor, Aider, Cline, Continue, Zed yet

Each fails at least one of: has no hook API, has a hook API that runs after the native permission layer (so our deny cannot override a user's auto-approve), or has documented permission-bypass bugs that make layering fragile.

| Agent | Hook type | Blocker for Gommage today |
|---|---|---|
| **Cursor** | `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` | Hooks run **after** built-in permission checks — cannot override enterprise auto-approve |
| **Aider** | none documented | No extensibility point |
| **Cline** | `PostToolUse`-style | Permission bypass bugs open upstream ([cline/cline#7334](https://github.com/cline/cline/issues/7334)) |
| **Continue** | `PreToolUse` (incomplete) | "Does not intercept all shell calls yet" per upstream |
| **Zed** | regex-in-config only | No programmatic interception |

Revisit when upstream ships a stable, pre-authorisation hook. Roadmap tracks each of these as a separate gate.

---

## Updating this page

Add a row to the matrix when a mapper rule lands. Upstream hook surface changes invalidate this doc — raise a PR to correct the "Bypasses Gommage" list the same day the upstream change ships. The doc is part of Gommage's trust claim; stale rows are a credibility bug.
