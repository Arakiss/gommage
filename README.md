<p align="center">
  <img src="assets/banner.png" alt="gommage — policy-as-code for AI coding agents" width="100%" />
</p>
<p align="center"><sub><em>The gold dust unmaking the parchment is the gommage. The three pendants below are pictos — signed, short-lived, usage-bounded grants.</em></sub></p>

<p align="center">
  <a href="https://github.com/Arakiss/gommage/actions/workflows/ci.yml"><img src="https://github.com/Arakiss/gommage/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Arakiss/gommage/releases"><img src="https://img.shields.io/github/v/release/Arakiss/gommage?include_prereleases&sort=semver&color=blue" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/rust-1.90%2B-orange.svg" alt="Rust 1.90+"></a>
  <a href="tests/determinism/"><img src="https://img.shields.io/badge/determinism-enforced-brightgreen.svg" alt="Determinism enforced"></a>
</p>

# gommage

> _« ce qui n'a pas lieu d'être, s'efface. »_

Gommage is a deterministic policy and audit layer for matched AI coding-agent tool calls. It evaluates declarative YAML rules, records signed audit evidence, and can require a short-lived signed grant for an exceptional action.

## What it does

Gommage maps an observed tool call to capabilities such as `git.push:refs/heads/main`, `fs.write:**/.git/**`, or `net.out.post`. Capability mapping and layered policy evaluation are deterministic: the same observed call, mapper, and policy layers produce the same policy result regardless of call order or host OS. Each mapped capability is evaluated across the active organization, user, and optional project layers; the final result is the most restrictive contribution (`deny` before unresolved, then `ask_picto`, then `allow`). Picto lookup and consumption are explicit authorization state, so an active, expired, or spent grant changes the final authorization result by design.

An `ask_picto` rule creates a durable approval request when there is no matching grant. A [picto](docs/pictos.md) is signed, time-limited, usage-bounded, revocable, and consumed atomically by the normal daemon path. Each decision or lifecycle event written to `audit.log` is signed independently; the separate approval inbox is unsigned operational state. The current log format authenticates individual records, but does not prove that the file is complete or ordered.

Gommage is public beta software. Start with a non-critical repository, inspect generated policy before relying on it, and use the beta contract as the source for supported claims: [beta contract](docs/beta-contract.md).

## What it does not do

Gommage is a policy decision and audit layer. It does not provide OS-level confinement, mediate every process action, or replace your agent's native permissions.

The current daemon is a user-mode control. The same operating-system user can edit policy and state, invoke reloads, replace the binaries, or access the signing key. `gommage managed status --json` reports `isolation: "none"`, `tamper_resistance: "none"`, and `reference_ready: false`; its deployment modes describe user-owned configuration, not a protected service identity or privilege boundary.

Keep the controls that already protect your machine:

- Claude Code's native permissions, optional Bash sandbox, and any additional
  host controls you use.
- Codex sandboxing, especially for filesystem and network boundaries outside matched hook events.
- Your existing approval and review process for changes with real consequences.

The exact coverage boundary and threat assumptions are documented in the [threat model](THREAT_MODEL.md).

## Supported hosts

The release installer supports macOS and Linux. Windows is not currently supported.

| Host | Default Gommage coverage | Keep enabled |
| --- | --- | --- |
| Claude Code | `Bash`, file tools, `WebFetch` / `WebSearch`, and emitted `mcp__…` tool names | Native permissions, optional Bash sandbox, and any additional host confinement |
| OpenAI Codex CLI | `Bash`, parsed `apply_patch` paths, and emitted `mcp__…` tool names | Codex sandboxing for boundaries outside matched hook events |

Both integrations use the same YAML policies, independently signed audit
records, and Picto store. Coverage is limited to tool calls that the host emits
through a matched hook event. Claude Code can surface an approval request in
its flow. Gommage's current Codex `PreToolUse` adapter returns a denial for a
picto-required call with no matching grant; it does not yet connect Pictos to
Codex's separate `PermissionRequest` event.

Read the host-specific boundaries before rollout: [Claude Code](docs/comparison-with-claude-code.md), [Codex](docs/comparison-with-codex.md), and the [compatibility guide](docs/agent-compatibility.md).

## Try it first

From a checkout, run the isolated demo:

```sh
sh scripts/launch-demo.sh
```

It uses a temporary home and captures an allow, a picto-required action, one-use picto consumption, a hard-stop denial, signed-audit verification, policy fixtures, and a health snapshot. It does not change your real agent configuration.

The demo output and recording guide are in [examples/launch-demo](examples/launch-demo/README.md).

## Install and quickstart

The current compatibility bootstrap installs signed GitHub Release archives,
but it is not yet the immutable reference install path. Download the installer
from mutable `main`, inspect it, and execute it separately; pin the URL to a
reviewed commit when the bootstrap itself is part of your threat model. The
installer verifies the selected archive's Sigstore identity and SHA-256 digest
before writing binaries.

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  -o gommage-install.sh
# Inspect gommage-install.sh before executing it.
sh gommage-install.sh
```

Binary replacement is sequential, not an all-or-nothing transaction. A host
failure can therefore leave a mixed installation. Run `gommage verify --json`
as a post-install health check and keep the installer backups for recovery, but
note that `verify` only reports companion version strings; it does not assert
that the three binaries are mutually compatible. Skill-only installs are a
separate channel, default to the mutable `main` ref, and are not covered by the
release archive signature.

For a new host, choose the agent you use:

```sh
# Claude Code
gommage quickstart --agent claude --daemon --self-test

# OpenAI Codex CLI
gommage quickstart --agent codex --daemon --self-test
```

Then verify the installed path:

```sh
gommage verify --json
```

`quickstart --agent codex` writes the Codex hook configuration. Open a new Codex session after setup so it loads that configuration.

### Existing machines

Gommage adds its integration without replacing unrelated host hooks by default. Inspect the local plan before changing a mature setup:

```sh
gommage harness diagnose --json
gommage quickstart --agent claude --daemon --dry-run --json
gommage quickstart --agent codex --daemon --dry-run --json
```

The [existing setups guide](docs/existing-setups.md) explains coexistence, backups, rollback, dual-agent runs, and MCP gateway scope. For full installation choices, pinned releases, source builds, and updates, see [updating](docs/updating.md) and [release signing](docs/release-signing.md).

## Policy in one rule

Policies live in `~/.gommage/policy.d/`. Rules are ordered; keep them narrow and add a fixture for each intended behavior.

```yaml
- name: gate-main-push
  decision: ask_picto
  required_scope: "git.push:main"
  bind_input: true
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
  reason: "pushes to main require review of the exact observed tool call"
```

`bind_input: true` is available only with `ask_picto`. It binds the resulting picto to the canonical hash of the observed tool call, so a grant for one observed input cannot authorize a different call in the same scope. The default is `false` for compatibility with existing scope-bound policies.

Use `gommage map --json` to inspect capabilities before writing a rule, and test policy intent with a fixture:

```sh
gommage policy test examples/policy-fixtures.yaml --json
```

The [policy cookbook](docs/policy-cookbook.md) covers common patterns, precedence, and regression fixtures. The [Picto guide](docs/pictos.md) covers direct grants, approval requests, callbacks, revocation, and exact-input grants.

## How a decision flows

```text
matched tool call
  -> capability mapping
  -> per-capability evaluation across active policy layers
  -> restrictive aggregation across all capabilities
  -> allow | deny | ask_picto
  -> independently signed audit record
```

For `ask_picto`, Gommage creates or reuses the relevant pending approval request. Approval can mint either a scope-bound picto or, when the rule asks for it, an exact-input picto. A hard stop always remains denied; a picto never bypasses it.

## Documentation

| Need | Read |
| --- | --- |
| Beta scope, guarantees, and exclusions | [Beta contract](docs/beta-contract.md) |
| Threat assumptions and hard-stop boundary | [Threat model](THREAT_MODEL.md) |
| Claude Code and Codex coverage | [Agent compatibility](docs/agent-compatibility.md) |
| Existing hooks, migration, rollback | [Existing setups](docs/existing-setups.md) |
| Rules, precedence, and fixtures | [Policy cookbook](docs/policy-cookbook.md) |
| Grants, approvals, callbacks, and revocation | [Pictos](docs/pictos.md) |
| Health checks and support evidence | [Diagnostics](docs/diagnostics.md) |
| Binary provenance and release verification | [Release signing](docs/release-signing.md) |
| Architecture and state index | [Architecture](docs/architecture.md) |
| Planned work | [Roadmap](docs/roadmap.md) |

Agents should use the repository's [Gommage skill](skills/gommage) and inspect `gommage harness diagnose --json` or `gommage harness explain` before making claims about a specific machine.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the determinism contract, policy-fixture rules, local checks, and release process. Report security issues through [SECURITY.md](SECURITY.md).

## Acknowledgements

The name and terminology are a tribute to _Clair Obscur: Expedition 33_ by Sandfall Interactive. Gommage is an independent project and has no affiliation with Sandfall Interactive.

## License

[MIT](LICENSE)
