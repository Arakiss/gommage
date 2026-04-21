# OpenAI Codex CLI + Gommage — setup recipe

Codex CLI's `PreToolUse` hook schema is near-identical to Claude Code's: same
`permissionDecision` / `permissionDecisionReason` contract, slightly different
config location. The existing `gommage-mcp` binary is schema-compatible with
both — Codex just points its hook at it.

> **Current scope caveat** (as of April 2026, Codex docs):
> Codex `PreToolUse` fires **only for Bash** tool calls. File reads, writes,
> edits and MCP tool calls do not invoke the hook. For broader coverage today,
> you need to layer Codex's sandbox modes (`--sandbox read-only` /
> `workspace-write`) underneath Gommage.

## 1. Install

Same binaries as the Claude Code setup — one install, both agents.

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
gommage quickstart --agent codex --daemon
gommage doctor --json
```

`quickstart` creates `~/.gommage`, installs the bundled policy/capability
stdlib, writes `~/.codex/hooks.json`, and enables `features.codex_hooks = true`
in `~/.codex/config.toml` with backups. `--daemon` also installs and starts the
user-level service.

`doctor --json` should report top-level `status` as `ok` or `warn`. A warning is
expected before the first audited decision. Treat `fail` as a setup error before
starting Codex.

## 2. Install the daemon service (recommended for long sessions)

The `gommage-mcp` adapter falls back to in-process evaluation when the
daemon socket isn't available, and that fallback still writes signed audit
entries. Running the daemon is recommended for longer sessions because it keeps
policy + mapper rules pre-compiled in memory and centralizes reload/audit
behavior:

```sh
gommage daemon install
# or, during image/bootstrap preparation:
gommage quickstart --agent codex --daemon-no-start
```

Use `gommage daemon status` to inspect the service and
`gommage daemon uninstall` to remove it.

## 3. Start an expedition and use Codex

```sh
cd /path/to/your/project
gommage expedition start "refactor-auth"
codex exec --sandbox workspace-write "refactor the auth middleware"
```

Every Bash command Codex wants to execute is gated through Gommage's
policy. Pictos, audit log, `gommage explain <id>` all behave identically to
the Claude Code flow.

## 4. What Gommage does NOT gate under Codex today

Because Codex only fires `PreToolUse` for Bash, these are NOT intercepted
by Gommage in a Codex session (until Codex widens the hook surface —
tracked upstream: openai/codex#16732):

- File reads via Codex's internal file tools
- File writes/edits via Codex's internal file tools
- MCP tool calls Codex makes to other MCP servers

Use Codex's native `--sandbox` mode as a second layer for those. A typical
conservative combo:

```sh
codex exec --sandbox read-only  "audit the repository and summarise risks"
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

Sandbox mode enforces OS-level confinement (Seatbelt on macOS, `bwrap +
seccomp` on Linux); Gommage enforces your declarative policy on top. The
two layers are complementary.

## 5. Break-glass / picto flow (identical to Claude Code)

```sh
gommage grant --scope "git.push:main" --uses 1 --ttl 10m --reason "hotfix"
codex exec --sandbox workspace-write "create a hotfix branch and push to main"
# First push: picto consumed, allow. Second push: picto spent, ask_picto again.
```

## 6. End the expedition

```sh
gommage expedition end
```
