# Launch Demo

This demo is the public, local-first proof path for Gommage's beta story. It
uses an isolated temporary `HOME` and does not mutate the operator's real
Claude Code, Codex, or Gommage configuration.

Run it from a checkout:

```sh
sh scripts/launch-demo.sh
```

Run it against a prebuilt release binary:

```sh
GOMMAGE_BIN="$HOME/.local/bin/gommage" sh scripts/launch-demo.sh
```

The capture directory contains evidence for the core workflow:

| File | Evidence |
|---|---|
| `00-harness-diagnose-before.json` | The preinstall harness state in the isolated home. |
| `00-quickstart-plan.json` | The dry-run quickstart plan before mutation. |
| `00-quickstart.txt` | The applied isolated quickstart and self-test output. |
| `01-main-push-ask.json` | `git push origin main` requires `git.push:main`. |
| `02-approval-list.json` | The out-of-band approval inbox contains the request. |
| `03-grant-main-push.txt` | A one-use `git.push:main` picto is minted. |
| `04-main-push-allow.json` | The next matching push is allowed and consumes the picto. |
| `05-rm-root-deny.json` | `rm -rf /` is denied by a compiled hard-stop. |
| `06-audit-verify.json` | The signed audit log verifies offline. |
| `07-state-rebuild.json` | `state.sqlite` is rebuilt from `audit.log`. |
| `08-state-verify.json` | `state.sqlite` matches the current signed ledger. |
| `09-state-stats.json` | Fast local counters read from the SQLite read-model. |
| `10-policy-fixtures.json` | Public policy fixtures pass against the active stdlib. |
| `11-beta-check.json` | The host-level beta gate result. |
| `12-tui-snapshot.txt` | Human operator dashboard snapshot. |

For a short screen recording, show the terminal running the script, then open
`01-main-push-ask.json`, `04-main-push-allow.json`, `05-rm-root-deny.json`,
`06-audit-verify.json`, `08-state-verify.json`, and `11-beta-check.json`.

`state.sqlite` is intentionally not a permission authority. The demo rebuilds
it after signed audit evidence exists to show the intended relationship:
authenticated records currently available in `audit.log` are the rebuild
input, while `state.sqlite` is the fast local read-model. Neither artifact
proves that no signed records were removed, reordered, or duplicated.
