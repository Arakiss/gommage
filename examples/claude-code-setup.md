# Claude Code + Gommage — setup recipe

## 1. Install

```sh
cargo install --path crates/gommage-cli
cargo install --path crates/gommage-daemon
cargo install --path crates/gommage-mcp
# Or, once binaries are published:
#   curl --proto '=https' --tlsv1.2 -sSf https://gommage.dev/install.sh | sh
```

## 2. Initialise the home

```sh
gommage init
# seeds ~/.gommage/ with policy.d/ + capabilities.d/ + key.ed25519
```

## 3. Install stdlib

```sh
gommage policy init --stdlib
gommage policy check
```

## 4. Start the daemon (dev mode)

Open a new terminal pane:

```sh
gommage-daemon --foreground
```

Leave it running.

## 5. Wire the PreToolUse hook

Edit `~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      }
    ]
  }
}
```

## 6. Start an expedition

```sh
cd /path/to/your/project
gommage expedition start "feature-auth"
```

## 7. Use Claude Code normally

The hook runs on every tool call. Decisions go to the audit log:

```sh
gommage tail -f
```

## 8. Break-glass when you need to push to main

```sh
gommage grant --scope "git.push:main" --uses 1 --ttl 5m --reason "incident"
```

The next `git push origin main` goes through; the picto is consumed; subsequent pushes again require a fresh grant.

## 9. End the expedition

```sh
gommage expedition end
```

The active context resets. New expedition starts fresh.
