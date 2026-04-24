# Comparison with OpenAI Codex CLI's native permission layer

Gommage works with Codex today, but the split of responsibilities is different from the Claude Code integration — Codex's built-in model is stronger (OS-level sandboxing) and narrower (hook only fires for Bash). Read this page before deploying Gommage on a Codex workflow.

## What Codex ships

- **Sandbox modes.** `--sandbox read-only` (default), `--sandbox workspace-write`, `--sandbox danger-full-access`. Enforced at the OS — macOS Seatbelt, Linux `bwrap + seccomp`. These are real confinement, not policy in userspace.
- **Approval policy.** Determines when Codex prompts before executing a sandbox-allowed action. Configured via CLI flags and `~/.codex/config.toml`.
- **`PreToolUse` hook.** Lives in `~/.codex/hooks.json` (user) or `.codex/hooks.json` (repo). Currently **fires only for Bash tool calls** (upstream: openai/codex#16732). Schema is near-identical to Claude Code's — same `permissionDecision` / `permissionDecisionReason` contract.
- **MCP bidirectional.** Codex can consume external MCP servers and be wrapped as one.

## What Gommage adds on top of Codex

- **Declarative policy that stacks with the sandbox.** You don't replace `--sandbox workspace-write`; you add a second layer that decides which commands within that sandbox are acceptable right now, in this expedition.
- **Advisory sandbox bridge.** `gommage sandbox advise --json` prints reviewed starter commands for native sandbox layers, always marked advisory only.
- **Break-glass pictos.** Codex's approval policy is either "ask every time" or "auto-approve"; it does not have a signed, TTL'd, usage-bounded primitive. Gommage does.
- **Auditable decisions.** Codex logs sessions; Gommage records each decision with rule name, policy version hash, and signed line in the audit log.

## Current scope limitation

Because Codex's `PreToolUse` hook only intercepts Bash, Gommage under Codex **does not see**:

- File reads via Codex's internal `read_file` / `apply_patch` tools
- File writes / edits via Codex's internal tools
- MCP tool calls Codex issues to other MCP servers

For those, Codex's `--sandbox` modes are the authoritative layer. A typical combo:

```sh
# Exploratory: OS-confined to reads + Gommage policy on the occasional Bash.
codex exec --sandbox read-only "audit the repo and summarise findings"

# Editing: Codex can write inside the cwd (sandbox), but any shell command
# still goes through Gommage policy.
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

If a third-party stdio MCP server can be launched through a proxy, route it
through `gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>`.
That path gates MCP `tools/call` requests as `mcp__<name>__<tool>` before
forwarding. It does not cover Codex built-in file tools and does not replace
Codex's OS sandbox.

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
│  3. If Bash: PreToolUse hook │   ←— ~/.codex/hooks.json → gommage-mcp
│     → Gommage evaluates      │
│                              │
│  4. OS sandbox                │   ←— Seatbelt / bwrap+seccomp
│     (--sandbox mode)         │
│                              │
│  5. Execute (or not)         │
└──────────────────────────────┘
```

Gommage sits at step 3. Steps 1–2 are Codex; step 4 is your kernel.

## When to prefer Codex + Gommage over Claude Code + Gommage

- You want OS-level confinement as a second layer (Codex has, Claude Code does not).
- Your workload is Bash-heavy and the hook surface gap is acceptable.
- You already use Codex for other reasons (OpenAI account, platform policies).

## When to prefer Claude Code + Gommage

- You need Gommage to see Read / Write / Edit / Glob / Grep / WebFetch / MCP tool calls, not just Bash.
- You don't need or want OS-level sandboxing (or you're layering your own: containers, nsjail, etc.).

## Roadmap alignment

When upstream Codex expands `PreToolUse` beyond Bash (tracked at openai/codex#16732), Gommage's capability mappers will grow matching rules and the coverage gap closes automatically — no Gommage version bump needed for a policy-pack update, just a YAML drop.
