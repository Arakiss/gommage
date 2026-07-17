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

- install binaries from checksum- and signature-verified GitHub Release
  archives;
- install the Gommage agent skill for Codex and Claude Code;
- inspect a mature host setup before mutating it;
- run quickstart with backups and a self-test;
- understand which agent surfaces are covered and which remain native-host or
  sandbox responsibility;
- trigger `allow`, `deny`, `ask_picto`, picto consumption, independently signed
  audit records, and local state-index evidence in a reproducible demo;
- verify release assets and local readiness with machine-readable commands;
- roll back host integrations without deleting audit evidence by default.

## Stable Enough For Beta

These surfaces are part of the beta operator contract:

| Surface | Contract |
|---|---|
| Installer | Downloads one platform archive, verifies Sigstore and SHA-256 before extraction, then installs `gommage`, `gommage-daemon`, and `gommage-mcp` sequentially with per-file backups. The mutable bootstrap and non-atomic replacement limits remain documented. |
| Hook adapter | New agent hooks call `gommage hook --agent claude` or `gommage hook --agent codex`; `gommage-mcp` remains a compatibility binary and optional stdio MCP gateway. |
| Agent skill | Installed by `--with-skill` or `--skill-only`; teaches agents to diagnose, dry-run, verify, and avoid overclaiming coverage. |
| Harness diagnostics | `gommage harness diagnose --json`, `harness explain`, and `harness write-context --dry-run` report the observed local hook and configuration state for agents; they do not prove a protected service identity. |
| Quickstart | Additive and strict by default; preserves unrelated Claude hooks, backs up changed files, imports supported native Claude denies but not allows, reloads the daemon once after policy changes, and self-tests unless disabled. Broad generated allows require explicit `--relaxed`. |
| Beta gate | `gommage beta check --json` aggregates doctor, smoke, selected agent status, optional policy fixtures, state-index readiness, dashboard availability, and next commands. |
| Readiness gate | `gommage verify --json` remains the lower-level install/CI readiness gate. |
| Policy fixtures | `gommage policy test <file> --json` is the stable semantic regression contract. |
| Signed audit | `gommage audit-verify --explain` authenticates each available decision-v2 or event-v1 record in `audit.log`; the beta does not claim cryptographic completeness, ordering, or uniqueness of the file. |
| State index | State schema v2 records `source_log: "audit.log"`; `state.sqlite` is rebuildable from the available records and checked against the current log snapshot by `gommage state verify --json`. It is never a permission authority or completeness witness. |
| Rollback | `repair`, `agent uninstall`, and `uninstall --dry-run` describe recovery before mutation. |
| Demo | `sh scripts/launch-demo.sh` produces local evidence for the core workflow without touching real host config. |

## Explicit Non-Promises

Beta does not claim:

- OS-level sandboxing or kernel confinement;
- universal interception of every agent action;
- replacement of Claude Code, Codex, or OS-native security controls;
- automatic coverage for every MCP server on the machine;
- semantic support for every Codex tool or any operation Codex does not emit
  through `PreToolUse`; the installed matcher is global, but bundled positive
  mapping remains limited to reviewed tool shapes and unknown emitted calls
  fail closed;
- production security certification;
- crates.io source builds as a replacement for the signed GitHub Release
  binary path;
- protection from a hostile process running as the same UID as the daemon, or a
  separately administered managed authority;
- cryptographic detection of deleted, truncated, reordered, or duplicated audit
  records;
- signature coverage for Picto v1 mutable `uses` and `status` fields outside the
  normal transactional store path;
- a hermetic or reproducible build, compiler provenance, or native execution
  solely because a release archive has a valid Sigstore signature or GitHub
  artifact attestation;
- atomic replacement of all three binaries or automatic rollback after a
  partial install;
- release-signature coverage for remote skill files, whose default ref is the
  mutable `main` branch.

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

Gommage is designed for coexistence first. Existing hooks may remain active.
Current supported-host semantics run all matching hooks concurrently, and a
deny from any hook blocks the call. Gommage records its own signed decision;
it does not authenticate or audit another hook's independent result.

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
