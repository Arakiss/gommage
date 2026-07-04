# Breaking changes policy

Gommage is **pre-1.0**. Under [Semantic Versioning](https://semver.org/) pre-1.0
rules, the `0.x` line carries no stability guarantee across minor bumps: a
**minor (`0.y`) bump MAY contain breaking changes** to policy and capability
semantics, the canonical decision input, the audit log schema, daemon IPC, and
CLI flags. Patch (`0.y.z`) bumps stay compatible.

What "breaking" means here is broader than an API signature change. While the
project is pre-1.0, all of the following are treated as breaking and require at
least a **minor** bump:

- a change to the canonical decision input shape or interpretation
  (see [`docs/input-schema.md`](docs/input-schema.md));
- a change to bundled stdlib mapper or policy **decision behaviour** — i.e. a
  tool call that used to map/decide one way now maps/decides differently;
- a tightened compiled hard-stop (it can deny things that previously passed);
- an audit log schema or signature-format change
  (see [`docs/audit-signature-format.md`](docs/audit-signature-format.md));
- a daemon IPC wire-format change or a `gommage-core` public API change.

Additive changes — a new capability namespace, a new policy rule that only
covers previously fail-closed-denied calls, a new optional CLI flag — are **not**
breaking and ship in patch or minor releases.

## What downstream consumers should do

If you depend on the Gommage crates (`gommage-core`, `gommage-stdlib`,
`gommage-audit`, …) as a Rust library, **pin exact versions** until the project
reaches 1.0:

```toml
[dependencies]
gommage-core = "=0.x.y"
```

The crates are published on crates.io (see
[`docs/publishing.md`](docs/publishing.md)). Exact pinning still applies until
1.0 because minor pre-1.0 releases may change policy semantics. Operators who
consume only the installed binaries and YAML policy should read the release
notes on every minor bump and re-run their policy regression fixtures
(`gommage policy test`) and `gommage smoke` before trusting an upgrade.

## How versions are decided

Versions are owned by **release-please** from Conventional Commits; releases are
not tagged by hand. This document describes the *policy*, not specific version
numbers. The repo-level history is tracked in [`CHANGELOG.md`](CHANGELOG.md) and
per-crate history in `crates/*/CHANGELOG.md`. See the
[Versioning and changelog](README.md#versioning-and-changelog) section of the
README for the semver contract this policy implements.
