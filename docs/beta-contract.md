# Beta Contract

This page defines what the first Gommage beta is allowed to claim. It is a
product contract, not a feature wish list.

Gommage beta is evidence-driven. The gates in
[`beta-readiness.md`](beta-readiness.md) define when a beta release can be
announced. The presence of `gommage beta check` means "run the beta gate"; it
does not mean the current host is healthy until the command returns `pass` or
an understood, documented `warn`.

## Beta Promise

The first beta can claim that a new operator or agent can:

- install signed binaries from GitHub Releases;
- install the Gommage agent skill for Codex and Claude Code;
- inspect a mature host setup before mutating it;
- run quickstart with backups and a self-test;
- understand which agent surfaces are covered and which remain native-host or
  sandbox responsibility;
- trigger `allow`, `deny`, `ask_picto`, picto consumption, signed audit, and
  local state-index evidence in a reproducible demo;
- verify release assets and local readiness with machine-readable commands;
- roll back host integrations without deleting audit evidence by default.

## Stable Enough For Beta

These surfaces are part of the beta operator contract:

| Surface | Contract |
|---|---|
| Installer | Downloads one platform archive, verifies Sigstore and SHA-256 before extraction, installs `gommage`, `gommage-daemon`, and `gommage-mcp`. |
| Hook adapter | New agent hooks call `gommage hook --agent claude` or `gommage hook --agent codex`; `gommage-mcp` remains a compatibility binary and optional stdio MCP gateway. |
| Agent skill | Installed by `--with-skill` or `--skill-only`; teaches agents to diagnose, dry-run, verify, and avoid overclaiming coverage. |
| Harness diagnostics | `gommage harness diagnose --json`, `harness explain`, and `harness write-context --dry-run` are the source of local truth for agents. |
| Quickstart | Additive by default; preserves unrelated Claude hooks, backs up changed files, imports supported native Claude permissions, and self-tests unless disabled. |
| Beta gate | `gommage beta check --json` aggregates doctor, smoke, selected agent status, optional policy fixtures, state-index readiness, dashboard availability, and next commands. |
| Readiness gate | `gommage verify --json` remains the lower-level install/CI readiness gate. |
| Policy fixtures | `gommage policy test <file> --json` is the stable semantic regression contract. |
| Signed audit | `audit.log` is the forensic source of truth and verifies with `gommage audit-verify --explain`. |
| State index | `state.sqlite` is rebuildable from `audit.log` and checked by `gommage state verify --json`; it is never a permission authority. |
| Rollback | `repair`, `agent uninstall`, and `uninstall --dry-run` describe recovery before mutation. |
| Demo | `sh scripts/launch-demo.sh` produces local evidence for the core workflow without touching real host config. |

## Explicit Non-Promises

Beta does not claim:

- OS-level sandboxing or kernel confinement;
- universal interception of every agent action;
- replacement of Claude Code, Codex, or OS-native security controls;
- automatic coverage for every MCP server on the machine;
- default Codex coverage for non-shell/non-MCP tools or shell paths that Codex
  hooks do not emit; the current default Codex surface is Bash, `apply_patch`,
  and Codex MCP tool names when those hook events reach Gommage;
- production security certification;
- crates.io source builds as a replacement for the signed GitHub Release
  binary path.

## Recommended Trial Path

Use this order on a real machine:

```sh
gommage harness diagnose --json
gommage quickstart --agent claude --daemon --dry-run --json
gommage quickstart --agent claude --daemon --dry-run --explain
gommage uninstall --all --dry-run
gommage quickstart --agent claude --daemon --self-test
gommage beta check --json --agent claude --policy-test examples/policy-fixtures.yaml
gommage verify --json --policy-test examples/policy-fixtures.yaml
gommage report bundle --redact --output gommage-report.json
```

Use the launch demo before touching a real home when the goal is to understand
behavior rather than install:

```sh
sh scripts/launch-demo.sh
```

## Existing Harnesses

Gommage is designed for coexistence first. Existing hooks may remain active, but
the first layer to block determines what the agent sees. If another hook denies
before Gommage receives the call, Gommage cannot audit that decision. If
Gommage denies or asks first, the reason is returned by Gommage and the signed
audit log records the decision.

For mature homes, do not infer behavior from the README alone. Run:

```sh
gommage harness diagnose --json
gommage agent status claude --json
gommage agent status codex --json
gommage policy layers --json
```

## Release Transition Rule

The repository moved from alpha to beta only after the required evidence existed
locally and repeatable CI evidence was wired for host-smoke and demo runs. A
future prerelease channel change should follow the same rule: validate the
operator contract first, then change release automation.

The expected first beta product tag shape is:

```text
gommage-cli-vX.Y.Z-beta.1
```

Do not publish a prerelease tag to fix a weak product story. Fix the story
first, then cut the release.
