# Agent compatibility matrix

What Gommage sees, what it does not, and what can bypass it per agent. This page is written against **current upstream state (April 2026)**. If an agent changes its hook surface, this page moves accordingly; the capability mapper in `capabilities/` is agent-agnostic and usually does not need changes.

If an item is listed as "Bypasses Gommage", that is not a vulnerability — it is the boundary of what a PreToolUse-level interception layer can observe. Stack OS-level confinement (AppArmor, SELinux, `seccomp-bpf`, macOS Seatbelt, Codex `--sandbox`) under Gommage for anything you need caught below the agent layer.

---

## Claude Code (Anthropic)

### What Gommage sees via `PreToolUse` hook

| Tool | Forwarded input | Capability namespace |
|---|---|---|
| `Bash` | `command` | `proc.exec:*`, plus every rule that matches the command (`git.push:*`, `net.out:*`, `pkg.*`, `deploy.*`, `docker.*`, `k8s.*`, `terraform.*`, `aws.*`, `gh.*`) |
| `Read` | `file_path` | `fs.read:<path>` |
| `Write` | `file_path` | `fs.write:<path>` |
| `Edit` | `file_path` | `fs.write:<path>` |
| `NotebookEdit` | `notebook_path` | `fs.write:<notebook_path>` |
| `Glob` | `pattern` | `fs.read:<pattern>` |
| `Grep` | (not currently mapped) | — |
| `WebFetch` | (not currently mapped) | — |
| `WebSearch` | (not currently mapped) | — |
| `mcp__<server>__<tool>` | (not currently mapped) | — |

To extend coverage, add a mapper rule under `~/.gommage/capabilities.d/` — Claude Code forwards the full `tool_name` + `tool_input` object on every hook call, so the information is there regardless of whether the stdlib pack matches it today.

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

## OpenAI Codex CLI

### What Gommage sees via `PreToolUse` hook

Codex's `PreToolUse` hook (as of the 2026-04 upstream state, tracked at [openai/codex#16732](https://github.com/openai/codex/issues/16732)) fires **only for `Bash` tool calls**. Every file-touching tool Codex has built in (its `read_file`, `apply_patch`, and MCP-delivered file tools) goes through without entering Gommage's decision path.

| Tool | Hook fires? | Capability produced |
|---|---|---|
| `Bash` | **yes** | same as Claude Code's Bash mapping |
| `read_file` (Codex built-in) | no | — |
| `apply_patch` / `str_replace` (Codex built-in) | no | — |
| MCP-delivered tools | no (at the PreToolUse layer) | — |

### Bypasses Gommage under Codex

- Every file read and file edit Codex performs via its internal tools.
- Every MCP tool Codex calls through.
- Any action the approval policy auto-approves at the sandbox layer before the hook fires.

### Recommended stack

Codex ships OS-level confinement as a first-class feature — **use it**:

| Sandbox mode | Reads | Writes | Network | Shell |
|---|---|---|---|---|
| `--sandbox read-only` (default) | anywhere | none | none | allowed via hook |
| `--sandbox workspace-write` | anywhere | cwd only | none | allowed via hook |
| `--sandbox danger-full-access` | anywhere | anywhere | anywhere | allowed via hook |

Gommage + Codex is a layered posture: Codex's OS-level sandbox covers the file-touching gap that Gommage cannot see at the hook layer; Gommage governs the Bash surface declaratively and audits.

Typical combos:

```sh
# Audit run — read-only, Gommage governs the occasional shell call.
codex exec --sandbox read-only "audit this repo"

# Refactor run — Codex can patch files within cwd (kernel-enforced),
# Gommage governs any Bash the agent wants to run.
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

### Wiring

See [`examples/codex-setup.md`](../examples/codex-setup.md).

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
