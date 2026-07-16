# Comparison with OpenAI Codex CLI's native permission layer

Gommage works with Codex today, but the split of responsibilities is different
from the Claude Code integration. Codex supplies native sandbox and approval
controls, while Gommage operates on its matched hook surface. Gommage's current
beta integration with Codex is intentionally scoped: the default quickstart
wires Bash, `apply_patch`, and Codex MCP hook names, while Codex's sandbox
remains authoritative for hook paths Gommage does not see. Read this page
before deploying Gommage on a Codex workflow.

## What Codex ships

- **Sandbox modes.** `--sandbox read-only`, `--sandbox workspace-write`, and
  `--sandbox danger-full-access`. The first two apply Codex's native filesystem
  and network policy; the last disables Codex's sandbox and should be treated as
  unconfined unless another boundary exists.
- **Approval policy.** Determines when Codex prompts before executing a sandbox-allowed action. Configured via CLI flags and `~/.codex/config.toml`.
- **`PreToolUse` hook.** Lives in Codex hook configuration. Older Codex
  releases were effectively Bash-only for Gommage's use case. Codex
  `rust-v0.124.0` widened hooks to observe `apply_patch`, MCP tools, and
  long-running Bash sessions. Gommage's default Codex quickstart maps Bash,
  parsed `apply_patch` file paths, and `mcp__server__tool` names; incomplete
  shell interception and non-shell/non-MCP tools remain native Codex boundaries.
- **MCP bidirectional.** Codex can consume external MCP servers and be wrapped as one.

See the current official Codex
[hooks](https://developers.openai.com/codex/hooks) and
[sandboxing and approvals](https://developers.openai.com/codex/concepts/sandboxing)
documentation before depending on host behavior.

## What Gommage adds on top of Codex

- **Declarative policy that stacks with the sandbox.** You don't replace `--sandbox workspace-write`; you add a second layer that decides which commands within that sandbox are acceptable right now, in this expedition.
- **Advisory sandbox bridge.** `gommage sandbox advise --json` prints reviewed starter commands for native sandbox layers, always marked advisory only.
- **Break-glass pictos.** Codex retains its native approval policy. Gommage adds
  a signed, expiring, usage-bounded grant for the capabilities its integration
  evaluates.
- **Auditable matched decisions.** When a mapped call reaches Gommage and a
  decision is appended successfully, the signed record includes the rule name
  and policy-version hash. The audit log does not prove that every host event
  reached Gommage or that records were never removed.

## Current scope limitation

Gommage under Codex **does not see by default**:

- shell paths that Codex does not emit as matched `Bash` hook events;
- built-in file reads or other internal tools that do not have a Gommage mapper;
- WebSearch and other non-shell, non-MCP tools outside Codex hook coverage;
- equivalent work performed through another tool path that the installed hook
  group or Gommage mapper does not cover.

For those, Codex's `--sandbox` modes remain the authoritative layer unless you
add and test local Gommage hook/mapping coverage. A typical combo:

```sh
# Exploratory: OS-confined to reads + Gommage policy on matched hooks.
codex exec --sandbox read-only "audit the repo and summarise findings"

# Editing: Codex can write inside the cwd (sandbox), while Bash/apply_patch/MCP
# hook events go through Gommage policy under the default integration.
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

If a third-party stdio MCP server can be launched through a proxy, route it
through `gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>`.
That path gates MCP `tools/call` requests as `mcp__<name>__<tool>` before
forwarding. It is intentionally explicit and optional: only the stdio MCP server you wrap is
proxied through Gommage. It does not cover Codex built-in file tools and does
not replace Codex's OS sandbox.

## How they stack

```
┌──────────────────────────────┐
│  Codex CLI                   │
│                              │
│  1. Model plans a tool call  │
│                              │
│  2. Matched PreToolUse hook  │   ←— Codex hook config → gommage hook --agent codex
│     → Gommage evaluates      │       (Bash, apply_patch, MCP by default)
│                              │
│  3. Native approval policy  │   ←— ~/.codex/config.toml
│                              │
│  4. Native Codex sandbox     │   ←— selected sandbox mode
│     (--sandbox mode)         │
│                              │
│  5. Execute (or not)         │
└──────────────────────────────┘
```

Gommage sits at step 2 for tool calls matched by the installed hook group and
mapped by Gommage's capability rules. Codex retains its native approval and
sandbox behavior around that hook decision.

## When Codex + Gommage is a good fit

- Your existing Codex sandbox and approval policy are the native lower layer.
- Your workload relies on Bash, `apply_patch`, or MCP tool calls and you want
  deterministic policy and signed audit for those matched hooks.
- You already use Codex for other reasons (OpenAI account, platform policies).

## When Claude Code + Gommage may fit better

- You need Gommage to see Read / Write / Edit / Glob / Grep / WebFetch and
  Claude-style MCP tool names through the default integration today.
- You already use Claude Code's native permissions and optional Bash sandbox.

## Roadmap alignment

Upstream Codex has already widened the hook surface beyond Bash in the 0.124
line. Gommage's default Codex path now covers Bash, `apply_patch`, and MCP names
when those hook events reach it. Remaining roadmap work is deeper host-smoke
evidence, incomplete shell interception tracking, and any future hook-exposed
tool families that need payload captures and mapper fixtures.
