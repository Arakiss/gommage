# Comparison with OpenAI Codex CLI's native permission layer

Gommage works with Codex today, but the split of responsibilities is different
from the Claude Code integration. Codex's built-in model is stronger at the OS
boundary because it ships native sandbox modes. Gommage's current alpha
integration with Codex is narrower than modern Codex itself: the default
Gommage quickstart still wires a Bash-scoped hook, while Codex 0.124+ can emit
additional hook events for `apply_patch`, MCP tools, and long-running Bash
sessions. Read this page before deploying Gommage on a Codex workflow.

## What Codex ships

- **Sandbox modes.** `--sandbox read-only` (default), `--sandbox workspace-write`, `--sandbox danger-full-access`. Enforced at the OS — macOS Seatbelt, Linux `bwrap + seccomp`. These are real confinement, not policy in userspace.
- **Approval policy.** Determines when Codex prompts before executing a sandbox-allowed action. Configured via CLI flags and `~/.codex/config.toml`.
- **`PreToolUse` hook.** Lives in Codex hook configuration. Older Codex
  releases were effectively Bash-only for Gommage's use case. Codex
  `rust-v0.124.0` widened hooks to observe `apply_patch`, MCP tools, and
  long-running Bash sessions. Gommage's default Codex quickstart has not yet
  widened its matcher and bundled mappers to that full upstream surface.
- **MCP bidirectional.** Codex can consume external MCP servers and be wrapped as one.

## What Gommage adds on top of Codex

- **Declarative policy that stacks with the sandbox.** You don't replace `--sandbox workspace-write`; you add a second layer that decides which commands within that sandbox are acceptable right now, in this expedition.
- **Advisory sandbox bridge.** `gommage sandbox advise --json` prints reviewed starter commands for native sandbox layers, always marked advisory only.
- **Break-glass pictos.** Codex's approval policy is either "ask every time" or "auto-approve"; it does not have a signed, TTL'd, usage-bounded primitive. Gommage does.
- **Auditable decisions.** Codex logs sessions; Gommage records each decision with rule name, policy version hash, and signed line in the audit log.

## Current scope limitation

Because Gommage's current Codex quickstart installs a Bash-scoped matcher,
Gommage under Codex **does not see by default**:

- `apply_patch` hook events emitted by modern Codex;
- MCP tool hook events emitted by modern Codex;
- built-in file reads or other internal tools that do not have a Gommage mapper;
- any tool call blocked or approved before the Gommage hook path sees it.

For those, Codex's `--sandbox` modes remain the authoritative layer unless you
add and test local Gommage hook/mapping coverage. A typical combo:

```sh
# Exploratory: OS-confined to reads + Gommage policy on the occasional Bash.
codex exec --sandbox read-only "audit the repo and summarise findings"

# Editing: Codex can write inside the cwd (sandbox), while Bash commands still
# go through Gommage policy under the default integration.
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

If a third-party stdio MCP server can be launched through a proxy, route it
through `gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>`.
That path gates MCP `tools/call` requests as `mcp__<name>__<tool>` before
forwarding. It is intentionally explicit: only the stdio MCP server you wrap is
proxied through Gommage. It does not cover Codex built-in file tools and does
not replace Codex's OS sandbox.

## How they stack

```
┌──────────────────────────────┐
│  Codex CLI                   │
│                              │
│  1. Model plans a tool call  │
│                              │
│  2. Approval policy?         │   ←— ~/.codex/config.toml
│     (ask / auto-approve)     │
│                              │
│  3. Matched PreToolUse hook  │   ←— Codex hook config → gommage-mcp
│     → Gommage evaluates      │       (Bash by default in Gommage alpha)
│                              │
│  4. OS sandbox                │   ←— Seatbelt / bwrap+seccomp
│     (--sandbox mode)         │
│                              │
│  5. Execute (or not)         │
└──────────────────────────────┘
```

Gommage sits at step 3 for tool calls matched by the installed hook group and
mapped by Gommage's capability rules. Steps 1-2 are Codex; step 4 is your
kernel.

## When to prefer Codex + Gommage over Claude Code + Gommage

- You want OS-level confinement as a second layer (Codex has, Claude Code does not).
- Your workload is Bash-heavy or you are willing to add tested mapper coverage
  for any newer Codex hook events you enable manually.
- You already use Codex for other reasons (OpenAI account, platform policies).

## When to prefer Claude Code + Gommage

- You need Gommage to see Read / Write / Edit / Glob / Grep / WebFetch and
  Claude-style MCP tool names through the default integration today.
- You don't need or want OS-level sandboxing (or you're layering your own: containers, nsjail, etc.).

## Roadmap alignment

Upstream Codex has already widened the hook surface beyond Bash in the 0.124
line. Gommage still needs explicit product work before claiming that coverage
by default: widened Codex matcher installation, stdlib mappers for Codex
`apply_patch` and MCP payloads, fixture coverage, and updated host smoke
evidence. Until then, treat non-Bash Codex coverage as an experimental local
extension, not a supported default.
