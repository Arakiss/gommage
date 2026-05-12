# Agent compatibility matrix

What Gommage sees, what it does not, and what can bypass it per agent. This
page is written against the Gommage beta line and upstream agent behavior known
on **2026-05-12**. If an agent changes its hook surface, this page moves
accordingly; the packaged capability mapper stdlib in
`crates/gommage-stdlib/capabilities/` is agent-agnostic and usually does not
need code changes. The repository-root `capabilities/` directory is a
review-friendly mirror kept in sync by CI.

If an item is listed as "Bypasses Gommage", that is not a vulnerability — it is the boundary of what a PreToolUse-level interception layer can observe. Stack OS-level confinement (AppArmor, SELinux, `seccomp-bpf`, macOS Seatbelt, Codex `--sandbox`) under Gommage for anything you need caught below the agent layer.

After installing an integration, run `gommage verify --json` to verify the operator path and built-in mapper + policy semantics. If the repository carries policy fixtures, run `gommage verify --json --policy-test <file>` before trusting the hook. A top-level verify `warn` is still an operable install when the only warnings are the missing first audit log or missing daemon socket. A top-level verify `fail` means the hook should not be trusted yet. See [`diagnostics.md`](diagnostics.md).

For migration guidance on mature homes, custom hooks, dual-agent flows, and
rollback, see [`existing-setups.md`](existing-setups.md).

---

## Claude Code (Anthropic)

### What Gommage sees via `PreToolUse` hook

| Tool | Forwarded input | Capability namespace |
|---|---|---|
| `Bash` | `command` | `proc.exec:*`, plus every rule that matches the command (`git.push:*`, `net.out:*`, `pkg.*`, `deploy.*`, `docker.*`, `k8s.*`, `terraform.*`, `aws.*`, `gh.*`) |
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
`~/.gommage/policy.d/05-claude-import.yaml`. It also imports supported
`permissions.allow` entries such as `Bash`, `Bash(git status *)`, and
`Read(./docs/**)` into `~/.gommage/policy.d/90-claude-allow-import.yaml`, which
loads after bundled hard-stops, deny imports, deny rules, and ask rules. That
ordering preserves the user's existing Claude posture without letting broad
native allows override Gommage guardrails. Use
`--no-import-native-permissions` when you want to author the initial Gommage
policy manually instead of importing Claude's native permissions.

Verify the host wiring after quickstart with:

```sh
gommage agent status claude --json
```

This checks the Claude settings file, the installed `PreToolUse` hook group,
and generated native permission import files without parsing the JSON settings
by hand.

### Bypasses Gommage under Claude Code

- Tool calls that Claude Code chooses to route below the hook (extremely unusual).
- Any shell command the user executes directly in a terminal outside the Claude Code session.
- Subprocess fork-chains inside a Bash call: Gommage sees the top-level `command` string only. If the command spawns `sh -c '…'` that spawns another, only the outermost string is in `input.command`. Wrapper-evasion hardstops (see `hardstop.rs`) catch the classic shapes; novel wrappers are a hole until added to the stdlib.

### Recommended stack

Claude Code does not ship OS-level sandboxing. If you need it:

- macOS: run Claude Code under `sandbox-exec` with a profile that limits writable paths.
- Linux: run under `bwrap` or a container with a tight bind-mount set.
- Everywhere: `git-hook`-style pre-commit + pre-push fallback if a `git push` gets past the in-session layer.

### Wiring

See [`examples/claude-code-setup.md`](../examples/claude-code-setup.md).

---

## Existing Claude Hook Stacks

Existing hooks and Gommage can coexist. The default installer appends a Gommage
hook group and leaves unrelated shell hooks in place. If an older hook denies a
call before Gommage evaluates it, the agent sees that older hook's message and
Gommage has no decision to audit. If Gommage denies or asks, the agent receives
the Gommage reason and the signed audit log records it.

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
   currently installs a `Bash` matcher and the bundled stdlib maps Bash
   commands. Gommage has not yet shipped default Codex `apply_patch` or Codex
   MCP mappers.

| Tool | Upstream Codex 0.124+ hook surface | Gommage quickstart default | Capability produced today |
|---|---|---|---|
| `Bash` | yes | yes | same as Claude Code's Bash mapping |
| long-running Bash session | yes | partially, through Bash hook payloads Gommage receives | same as Bash when emitted as `Bash` |
| `apply_patch` | yes | no default matcher/mapper yet | none unless the operator adds local mapper + hook coverage |
| Codex MCP tools | yes | no default matcher/mapper yet | none unless routed through `gommage-mcp --gateway` or custom mapper + hook coverage |
| built-in read-only file inspection | not claimed by Gommage | no | none |

### Bypasses Gommage under Codex

- Any Codex tool call that is not matched by the installed Gommage hook group.
  In the current beta quickstart, that means non-Bash Codex hook events.
- Built-in file reads or other internal Codex tools for which no upstream hook
  payload is emitted or no Gommage mapper exists.
- Codex MCP calls unless they are routed through `gommage-mcp --gateway` or the
  operator intentionally wires and tests Codex MCP hook coverage.
- Any action the approval policy auto-approves or blocks before the Gommage hook
  path receives a call.

### Recommended stack

Codex ships OS-level confinement as a first-class feature — **use it**:

| Sandbox mode | Reads | Writes | Network | Shell |
|---|---|---|---|---|
| `--sandbox read-only` (default) | anywhere | none | none | allowed via hook |
| `--sandbox workspace-write` | anywhere | cwd only | none | allowed via hook |
| `--sandbox danger-full-access` | anywhere | anywhere | anywhere | allowed via hook |

Gommage + Codex is a layered posture: Codex's OS-level sandbox covers file and
network boundaries that are below, outside, or not yet mapped by Gommage;
Gommage governs the installed hook surface declaratively and audits it. In the
current Gommage alpha, that installed Codex surface is Bash unless the operator
adds custom hook/mapping coverage.

For MCP tools that can be routed through a stdio proxy, `gommage-mcp
--gateway --server-name <name> -- <upstream-command>` provides a narrower
alternative to relying on the Codex hook. The gateway evaluates MCP
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

# MCP server through Gommage's stdio gateway.
gommage-mcp --gateway --server-name filesystem -- <stdio-mcp-server> .
```

### Wiring

See [`examples/codex-setup.md`](../examples/codex-setup.md).
`gommage quickstart --agent codex` writes `~/.codex/hooks.json` and enables
`features.hooks = true`, but it does not convert Codex's OS sandbox or
approval policy into Gommage YAML. Those native controls remain authoritative
for surfaces outside Gommage's installed matcher and mapper coverage.

Because upstream Codex now supports more hook events than Gommage's default
Codex integration wires, do not widen the matcher by hand and assume security
coverage. If you experiment with `apply_patch` or MCP hook matching, add local
capability mappers, capture real payloads with `gommage map --json --hook`, and
commit policy fixtures before trusting the result.

Verify the host wiring after quickstart with:

```sh
gommage agent status codex --json
```

This checks `hooks.json`, `config.toml`, `features.hooks`, the installed
`PreToolUse` hook group, and warns when `sandbox_mode = "danger-full-access"`
because Gommage's current default Codex integration is still Bash-scoped and
Codex's sandbox remains the file/MCP safety boundary.

Older Codex configs may still contain the legacy `features.codex_hooks` flag.
Gommage reports that as a migration warning and rewrites the canonical
`features.hooks` setting when `gommage agent install codex` runs.

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
