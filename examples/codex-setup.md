# OpenAI Codex CLI + Gommage — setup recipe

Codex CLI's `PreToolUse` hook schema is near-identical to Claude Code's: same
`permissionDecision` / `permissionDecisionReason` contract, slightly different
config location. The existing `gommage-mcp` binary is schema-compatible with
both — Codex just points its hook at it.

> **Current Gommage beta scope caveat**:
> Codex upstream widened hooks in `rust-v0.124.0` so they can observe
> `apply_patch`, MCP tools, and long-running Bash sessions. Gommage's current
> `quickstart --agent codex` still installs a Bash-scoped matcher and the
> bundled stdlib maps Bash commands only for Codex. Keep Codex's sandbox modes
> (`--sandbox read-only` / `workspace-write`) underneath Gommage, and treat
> non-Bash Codex hook coverage as custom policy/mapping work until Gommage ships
> it by default.

## 1. Install

Same binaries as the Claude Code setup — one install, both agents.

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
gommage quickstart --agent codex --daemon
gommage doctor --json
```

`quickstart` creates `~/.gommage`, installs the bundled policy/capability
stdlib, writes `~/.codex/hooks.json`, and enables `features.hooks = true` in
`~/.codex/config.toml` with backups. `--daemon` also installs and starts the
user-level service.

Older Codex configs may still contain `features.codex_hooks`; Gommage treats
that key as legacy and writes the canonical `features.hooks` setting.

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

Every Bash command Codex wants to execute is gated through Gommage's policy
under the default integration. Pictos, audit log, and `gommage explain <id>`
all behave identically to the Claude Code flow for audited decisions.

## 4. What Gommage does NOT gate under Codex by default today

Because Gommage's default Codex matcher is Bash-scoped, these are NOT
intercepted by Gommage in a Codex session unless you intentionally add and test
local hook/mapping coverage:

- `apply_patch` hook events emitted by modern Codex
- MCP tool hook events emitted by modern Codex
- built-in file reads or other internal tools that do not have a Gommage mapper
- anything blocked or approved before the Gommage hook path receives it

Use Codex's native `--sandbox` mode as the authority for those. A typical
conservative combo:

```sh
codex exec --sandbox read-only  "audit the repository and summarise risks"
codex exec --sandbox workspace-write "apply the refactor we discussed"
```

Sandbox mode enforces OS-level confinement (Seatbelt on macOS, `bwrap +
seccomp` on Linux); Gommage enforces your declarative policy for the hook
surface it sees. The two layers are complementary.

If you experiment with non-Bash Codex hooks, capture the real payload first:

```sh
cat codex-pretooluse-payload.json | gommage map --json --hook
```

Then add a local capability mapper under `~/.gommage/capabilities.d/`, a policy
rule, and a `gommage policy test` fixture before relying on the behavior.

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
