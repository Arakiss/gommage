# OpenAI Codex CLI + Gommage — setup recipe

Codex CLI's `PreToolUse` hook schema is near-identical to Claude Code's: same
`permissionDecision` / `permissionDecisionReason` contract, slightly different
config location. The canonical Codex hook adapter is
`gommage hook --agent codex`, which converts picto-required `ask` decisions to
denials because Gommage does not yet integrate Pictos with Codex's separate
`PermissionRequest` event. The existing `gommage-mcp` binary remains
schema-compatible for older hooks and
optional gateway use, but new Codex installs point at the CLI adapter.

> **Current Gommage beta scope caveat**:
> `quickstart --agent codex` installs an all-tools `PreToolUse` matcher.
> Bundled mapping understands Bash, parsed `apply_patch` paths, and Codex MCP
> names; other emitted calls fail closed until mapped. Keep Codex's sandbox
> modes (`--sandbox read-only` / `workspace-write`) underneath Gommage because
> operations Codex never emits through the hook remain outside Gommage.

## 1. Install

Same binaries as the Claude Code setup — one install, both agents.

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  -o gommage-install.sh
# Inspect gommage-install.sh before executing it.
sh gommage-install.sh
gommage quickstart --agent codex --daemon
gommage doctor --json
```

The compatibility bootstrap above comes from the mutable `main` branch and is
not the immutable reference install path. Replace `main` with a reviewed commit
SHA when that script is inside your threat model. It verifies the selected
release archive before binary writes, but replaces the three binaries
sequentially rather than as one transaction.

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

The `gommage hook --agent codex` adapter falls back to in-process evaluation
when the daemon socket isn't available, and that fallback still writes signed audit
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

Every Codex call emitted through `PreToolUse` reaches Gommage under the default
integration. Reviewed Bash, `apply_patch`, and MCP shapes receive semantic
capabilities; unknown shapes fail closed. Pictos, audit log, and
`gommage explain <id>` all behave identically to the Claude Code flow for
audited decisions.

## 4. What Gommage does NOT gate under Codex by default today

These are NOT positively governed by Gommage in a Codex session:

- shell paths that Codex's hook runtime does not emit as matched `Bash` events
- internal operations for which Codex emits no `PreToolUse` event
- emitted tool shapes without a mapper remain intercepted but fail closed
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

To inspect a real Codex hook payload:

```sh
cat codex-pretooluse-payload.json | gommage map --json --hook
```

Then add or adjust a local capability mapper under `~/.gommage/capabilities.d/`,
a policy rule, and a `gommage policy test` fixture before relying on custom
behavior.

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
