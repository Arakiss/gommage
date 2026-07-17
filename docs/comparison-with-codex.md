# Comparison with OpenAI Codex CLI's native permission layer

Gommage works with Codex today, but the split of responsibilities is different
from the Claude Code integration. Codex supplies native sandbox and approval
controls, while Gommage operates on its matched hook surface. Gommage's current
beta integration with Codex is intentionally scoped: the default quickstart
sends every host-emitted `PreToolUse` call to Gommage, but only reviewed tool
shapes have positive semantic mapping. Codex's sandbox remains authoritative
for execution paths the host does not emit. Read this page before deploying
Gommage on a Codex workflow.

## What Codex ships

- **Sandbox modes.** `--sandbox read-only`, `--sandbox workspace-write`, and
  `--sandbox danger-full-access`. The first two apply Codex's native filesystem
  and network policy; the last disables Codex's sandbox and should be treated as
  unconfined unless another boundary exists.
- **Approval policy.** Determines when Codex prompts before executing a sandbox-allowed action. Configured via CLI flags and `~/.codex/config.toml`.
- **`PreToolUse` hook.** Lives in Codex hook configuration. Older Codex
  releases were effectively Bash-only for Gommage's use case. Codex
  `rust-v0.124.0` widened hooks to observe `apply_patch`, MCP tools, and
  long-running Bash sessions. Gommage installs an all-tools matcher and maps
  reviewed Bash, parsed `apply_patch`, and `mcp__server__tool` payloads.
  Unknown emitted payloads fail closed; operations not emitted by the host
  remain native Codex boundaries.
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

Gommage under Codex **cannot see**:

- shell or internal execution paths for which Codex emits no `PreToolUse` event;
- equivalent work performed through another process or host path outside that
  hook contract.

An emitted tool without a bundled mapper is different: the global matcher does
see it, but Gommage denies it as unresolved until the operator adds reviewed
mapping, policy, and fixtures.

For those, Codex's `--sandbox` modes remain the authoritative layer unless you
add and test local Gommage hook/mapping coverage. A typical combo:

```sh
# Exploratory: OS-confined to reads + Gommage policy on matched hooks.
codex exec --sandbox read-only "audit the repo and summarise findings"

# Editing: Codex can write inside the cwd (sandbox), while every emitted
# PreToolUse event reaches Gommage and reviewed tool shapes can be allowed.
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
│  2. Global PreToolUse hook   │   ←— Codex hook config → gommage hook --agent codex
│     → Gommage evaluates      │       (unmapped emitted calls fail closed)
│                              │
│  3. Native approval policy  │   ←— ~/.codex/config.toml
│                              │
│  4. Native Codex sandbox     │   ←— selected sandbox mode
│     (--sandbox mode)         │
│                              │
│  5. Execute (or not)         │
└──────────────────────────────┘
```

Gommage sits at step 2 for every tool call Codex emits through `PreToolUse`.
Mapping determines whether a call has reviewed semantic capabilities; it does
not determine whether the global hook runs. Codex retains its native approval
and sandbox behavior around that decision.

## When Codex + Gommage is a good fit

- Your existing Codex sandbox and approval policy are the native lower layer.
- Your workload relies on reviewed Bash, `apply_patch`, or MCP tool calls and
  you want deterministic policy and signed audit for emitted hook events.
- You already use Codex for other reasons (OpenAI account, platform policies).

## When Claude Code + Gommage may fit better

- You need Gommage to see Read / Write / Edit / Glob / Grep / WebFetch and
  Claude-style MCP tool names through the default integration today.
- You already use Claude Code's native permissions and optional Bash sandbox.

## Roadmap alignment

Upstream Codex has already widened the hook surface beyond Bash in the 0.124
line. Gommage now intercepts every emitted `PreToolUse` event and positively
maps reviewed Bash, `apply_patch`, and MCP names. Remaining roadmap work is
deeper host-smoke evidence, tracking operations the host does not emit, and
future tool families that need payload captures and mapper fixtures.
