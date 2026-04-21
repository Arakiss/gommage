# Claude Code + Gommage — setup recipe

## 1. Install

```sh
cargo install --path crates/gommage-cli
cargo install --path crates/gommage-daemon
cargo install --path crates/gommage-mcp
# Or, once binaries are published:
#   curl --proto '=https' --tlsv1.2 -sSf https://gommage.dev/install.sh | sh
```

## 2. Quickstart

```sh
gommage quickstart --agent claude
```

That command:

- creates `~/.gommage`;
- installs bundled policies and capability mappers;
- imports supported `permissions.deny` entries from `~/.claude/settings.json`
  into `~/.gommage/policy.d/05-claude-import.yaml`;
- installs the Claude `PreToolUse` hook, preserving existing hooks unless you
  pass `--replace-hooks`;
- backs up changed config files before writing.

Use this when migrating from an older hook stack and you want Gommage to own the
Claude `PreToolUse` surface:

```sh
gommage quickstart --agent claude --replace-hooks
```

## 3. Install the daemon service (optional for long sessions)

Install a user-level service:

```sh
gommage daemon install
```

On macOS this writes `~/Library/LaunchAgents/dev.gommage.daemon.plist` and
loads it with launchd. On Linux this writes
`~/.config/systemd/user/gommage-daemon.service` and enables it with
`systemctl --user`. If you skip this, `gommage-mcp` still uses the audited
in-process fallback.

Useful service commands:

```sh
gommage daemon status
gommage daemon uninstall
```

## 4. Start an expedition

```sh
cd /path/to/your/project
gommage expedition start "feature-auth"
```

## 5. Use Claude Code normally

The hook runs on every tool call. Decisions go to the audit log:

```sh
gommage tail -f
```

## 6. Break-glass when you need to push to main

```sh
gommage grant --scope "git.push:main" --uses 1 --ttl 5m --reason "incident"
```

The next `git push origin main` goes through; the picto is consumed; subsequent pushes again require a fresh grant.

## 7. End the expedition

```sh
gommage expedition end
```

The active context resets. New expedition starts fresh.
