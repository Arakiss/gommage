# Host Smoke

Use this when validating a fresh machine, installer output, or host-agent
integration before asking a human to trust Gommage on a real home directory.

The script is intentionally conservative:

- default mode uses an isolated temporary `HOME`;
- daemon service files are written but not started;
- destructive cleanup is never executed;
- rollback is captured as `gommage uninstall --all --dry-run`;
- every important report is written to a capture directory.

## Prerequisites

Install Gommage first, or run from a source checkout with a built binary.

For source checkouts:

```sh
cargo build --workspace
GOMMAGE_BIN=target/debug/gommage sh scripts/host-smoke.sh --help
```

For release installs:

```sh
gommage --version
sh scripts/host-smoke.sh --help
```

## CachyOS / Arch Path

CachyOS uses systemd user services. Start with the temp-home smoke:

```sh
sh scripts/host-smoke.sh \
  --temp-home \
  --agent claude \
  --daemon-manager systemd \
  --capture-dir gommage-cachyos-claude-smoke
```

For Codex:

```sh
sh scripts/host-smoke.sh \
  --temp-home \
  --agent codex \
  --daemon-manager systemd \
  --capture-dir gommage-cachyos-codex-smoke
```

Only after the temp-home path passes, run against the real home. This mutates
host config and therefore requires explicit confirmation:

```sh
sh scripts/host-smoke.sh \
  --real-home \
  --yes \
  --agent claude \
  --daemon-manager systemd \
  --capture-dir gommage-cachyos-claude-real
```

Review rollback before executing any cleanup:

```sh
sed -n '1,200p' gommage-cachyos-claude-real/uninstall-dry-run.txt
gommage uninstall --all --dry-run --daemon-manager systemd
```

Do not remove real home data with `--purge-home --yes` unless the operator
explicitly decided to delete `~/.gommage`, including its signing key and audit
history.

## macOS Path

macOS uses launchd:

```sh
sh scripts/host-smoke.sh \
  --temp-home \
  --agent claude \
  --daemon-manager launchd \
  --capture-dir gommage-macos-claude-smoke
```

Real-home mode is the same shape, but requires `--real-home --yes`.

## Evidence Files

The capture directory contains:

| File | Purpose |
|---|---|
| `version.txt` | CLI version used for the run. |
| `gommage-daemon-version.txt` | Daemon companion binary version. |
| `gommage-mcp-version.txt` | MCP hook adapter companion binary version. |
| `quickstart-plan.json` | Dry-run setup mutations before writes. |
| `quickstart.txt` | Applied quickstart output with daemon-no-start. |
| `verify.json` | Aggregated readiness gate. |
| `beta-check.json` | Selected-agent beta readiness gate with public policy fixtures. |
| `agent-status.json` | Selected host-agent hook status. |
| `repair-claude-dry-run.txt` | Claude legacy hook repair plan without mutation. |
| `repair-codex-dry-run.txt` | Codex legacy hook repair plan without mutation. |
| `smoke.json` | Built-in semantic policy smoke report. |
| `policy-fixtures.json` | Public policy fixture library result. |
| `tui-snapshot-all.txt` | Full operator dashboard snapshot. |
| `tui-snapshot-onboarding.txt` | First-minute setup/recovery snapshot. |
| `tui-snapshot-metrics.txt` | Local daemon health, active picto, approval, webhook DLQ, and audit counter snapshot. |
| `tui-watch-approvals.txt` | Bounded approvals watch output. |
| `tui-stream.txt` | Bounded operator stream output. |
| `report-bundle.json` | Redacted diagnostic support bundle. |
| `report-bundle.out` | Report bundle command output. |
| `uninstall-dry-run.txt` | Rollback plan for review. |
| `summary.env` | Mode, agent, daemon manager, and capture metadata. |

Attach the capture directory to a beta-readiness issue when reporting host
results. The redacted bundle should be safe to share, but review it before
posting publicly.

## Expected Results

The script should finish with:

```sh
host-smoke: ok
host-smoke: evidence written to <capture-dir>
```

`verify.json` can report `warn` when there is no daemon socket or first audit
log yet. `fail` is not acceptable for beta evidence.
