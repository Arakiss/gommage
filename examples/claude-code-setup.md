# Claude Code + Gommage — setup recipe

## 1. Install

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  -o gommage-install.sh
# Inspect gommage-install.sh before executing it.
sh gommage-install.sh
```

This compatibility path fetches the bootstrap script from the mutable `main`
branch and is not the immutable reference install path. Replace `main` with a
reviewed commit SHA when the bootstrap is inside your threat model. The script
verifies the selected release archive's Sigstore identity and SHA-256 digest
before writing binaries; binary replacement is sequential rather than
transactional.

## 2. Quickstart

```sh
gommage quickstart --agent claude --daemon
gommage doctor --json
```

That command:

- creates `~/.gommage`;
- installs bundled policies and capability mappers;
- imports supported `permissions.deny` entries from `~/.claude/settings.json`
  into `~/.gommage/policy.d/05-claude-import.yaml`;
- leaves `permissions.allow` in Claude Code instead of converting it into a
  Gommage allow rule;
- installs the Claude `PreToolUse` hook, preserving existing hooks unless you
  pass `--replace-hooks`;
- runs the policy/agent readiness gate, then installs and starts the user-level
  daemon service;
- makes one bounded daemon reload attempt on the successful path after policy
  and hook changes; rollback may make a second reload for restored files;
- backs up changed config files before writing.

Strict policy posture is the default: unmatched shell, file, and outbound
capabilities remain fail-closed. Use the legacy convenience posture only when
that broader behavior is intentional:

```sh
gommage quickstart --agent claude --daemon --relaxed
```

`--relaxed` generates `06-agent-config-writable.yaml` and
`95-agent-catch-all.yaml` and imports supported Claude `permissions.allow`
entries into `90-claude-allow-import.yaml`. Rerunning quickstart without
`--relaxed` backs up and removes recognized generated 06/90/95 layers; modified
or custom content at one of those reserved paths stops the operation before any
integration write. Static files require canonical bytes and generated imports
require a valid content digest. Native imports refresh automatically when the
Claude settings change and native import remains enabled; `--replace-hooks`
controls only hook replacement.

`doctor --json` should report top-level `status` as `ok` or `warn`. A warning is
expected before the first audited decision. Treat `fail` as a setup error
before starting Claude Code.

Use this when migrating from an older hook stack and you want Gommage to own the
Claude `PreToolUse` surface:

```sh
gommage quickstart --agent claude --daemon --replace-hooks
```

For mature Claude homes, inspect the plan first:

```sh
gommage quickstart --agent claude --daemon --dry-run --json
gommage agent status claude --json
gommage repair agent claude --dry-run
gommage uninstall --all --dry-run
```

Keeping existing hooks and Gommage together is supported. Claude Code runs all
matching hooks concurrently and blocks when any one denies. Gommage records its
own decision; it does not audit another hook's independent result.

## 3. Daemon service controls

For CI images, dotfile bootstrap, or dry host preparation, write the service
file without starting it:

```sh
gommage quickstart --agent claude --daemon-no-start
```

On macOS this writes `~/Library/LaunchAgents/dev.gommage.daemon.plist` and
loads it with launchd. On Linux this writes
`~/.config/systemd/user/gommage-daemon.service` and enables it with
`systemctl --user`. If you skip daemon installation,
`gommage hook --agent claude` still uses the audited in-process fallback.

Useful service commands:

```sh
gommage daemon install
gommage daemon status
gommage daemon uninstall
```

## 4. Start an expedition

```sh
cd /path/to/your/project
gommage expedition start "feature-auth"
```

## 5. Use Claude Code normally

The installed hook evaluates each tool call that matches its configured
`PreToolUse` group and that Claude Code forwards to the hook. Matched decisions
go to the audit log:

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
