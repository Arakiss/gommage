# Beta Readiness

Gommage is still alpha. The beta line starts when a new operator can install,
verify, and operate the harness without reading source code or guessing which
warnings matter.

This document is the launch gate for public announcements. A checked item needs
evidence: a command, workflow run, release artifact, issue, or explicit product
decision.

## Beta definition

Beta means:

- The signed GitHub Release installer works on macOS and Linux for both
  supported architectures.
- The default setup path has one command for install and one command for
  readiness verification.
- Claude Code and Codex integration limits are explicit and tested.
- Machine-readable diagnostics are stable enough for agents, CI, and docs.
- Policy fixture authoring and regression testing are documented and usable.
- Release automation can cut a complete alpha/beta artifact without manual
  repair.
- Known limitations are documented as limitations, not hidden as roadmap text.

Beta does not mean:

- Production security certification.
- Full sandboxing. Gommage remains a policy decision and audit layer.
- Support for hosts that do not expose a reliable pre-authorisation hook.
- crates.io publication unless the publish gates have passed.

## Required evidence

Before announcing beta, collect and link the following evidence in a tracking
issue:

| Gate | Evidence |
|---|---|
| Installer | Fresh temp-home install from the latest `gommage-cli-v*` release. |
| Release assets | 12 CLI release assets: 4 archives, 4 checksums, 4 Sigstore bundles. |
| Binary introspection | `gommage`, `gommage-daemon`, and `gommage-mcp` all support `--version`. |
| Home setup | `gommage init` and `gommage policy init --stdlib` succeed in a clean home. |
| Readiness gate | `gommage verify --json` exits with `pass` or documented `warn`. |
| Quickstart self-test | `gommage quickstart --self-test` reaches the same readiness gate after setup. |
| Semantic smoke | `gommage smoke --json` exits with `pass`. |
| Operator TUI | `gommage tui --snapshot --view all` shows summary, focus, readiness rows, policy, audit, capability, recovery, and next actions on a clean pre-init home and after quickstart. |
| Approval flow | An `ask_picto` decision creates an approval request; `gommage approval approve <id>` mints an exact-scope picto; the next matching call consumes it; `audit-verify --explain` verifies the signed evidence. |
| Webhook flow | `gommage approval webhook --dry-run` renders pending payloads and a fake or test endpoint proves signed success/failure audit events. |
| Host wiring | `gommage agent status claude --json` and `gommage agent status codex --json` are documented for supported states. |
| Policy fixtures | At least one repository-owned fixture file runs through `gommage policy test --json`. |
| Audit verification | A daemon or MCP decision writes audit and `gommage audit-verify --explain` verifies it. |
| Host smoke | `scripts/host-smoke.sh` temp-home evidence exists for macOS and a systemd Linux host. |
| CI | `ci`, `release`, `audit`, and `scorecard` are green on the release commit. |
| Docs | README, diagnostics, agent compatibility, publishing, and release-signing docs match the current CLI. |
| Packaging | crates.io status is current via `sh scripts/check-crates-publish-readiness.sh`; unpublished crates have an explicit reason. |

## Blocking issues

Treat these as beta blockers:

- A verified installer release is missing any archive, checksum, or Sigstore
  bundle for a supported platform.
- `gommage verify --json` cannot distinguish warning from failure.
- A documented quickstart command fails on a clean macOS or Linux account.
- A companion binary cannot be introspected with `--version`.
- Release automation requires manual tag rewriting or force-pushing.
- Living docs pin stale concrete alpha tags outside changelogs.
- A policy or mapper change alters deterministic decisions without fixture and
  changelog evidence.
- A known host-agent bypass is documented as supported behavior.

## Non-blocking alpha limitations

These can remain open for beta if they are clearly documented:

- Codex hook coverage is Bash-scoped until upstream broadens `PreToolUse`.
- Cursor remains evaluation-only because its hook timing differs from Claude
  Code and Codex.
- crates.io may remain unpublished while GitHub Releases are the supported
  install path.
- Native Slack/Discord/ntfy approval providers can stay on the v1.x roadmap as
  long as the generic webhook payload and local approval commands are verified.

## Operator Smoke

Use [`host-smoke.md`](host-smoke.md) and `scripts/host-smoke.sh` for host
evidence. The default mode runs against a temporary `HOME`, applies quickstart
without starting the daemon, captures `verify`, `agent status`, semantic smoke,
the redacted report bundle, and an uninstall dry-run rollback plan.

## Tracking issue checklist

Use the `Beta readiness` issue template for public launch tracking. Keep one
canonical issue open until every required gate has either evidence or an
explicit non-blocking decision.
