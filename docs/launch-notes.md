# Launch Notes

These notes are the technical launch handoff for the first beta announcement.
Do not publish them as final copy until the beta release tag exists and
verification links are filled in.

## Positioning

Gommage is a deterministic policy and audit layer for AI coding agent tool
calls that reach a matched hook. It gives operators reviewable YAML policy,
signed short-lived and usage-bounded pictos, independently signed audit records,
and one command to report how the local agent integration is wired.

The beta message is:

> Gommage does not replace your agent sandbox. It makes the permission decisions
> you care about explicit, versionable, and auditable, with deterministic policy
> results for the same mapped call and policy layers across supported hooks.

## What To Show

Use the local demo:

```sh
sh scripts/launch-demo.sh
```

Show these capture files:

- `01-main-push-ask.json`: push to main requires `git.push:main`.
- `03-grant-main-push.txt`: one-use picto minted by the operator.
- `04-main-push-allow.json`: next matching push allowed.
- `05-rm-root-deny.json`: `rm -rf /` blocked by a compiled hard-stop.
- `06-audit-verify.json`: each available audit record verifies offline; this is
  not a completeness proof for the file.
- `08-state-verify.json`: `state.sqlite` matches the current available
  `audit.log` snapshot; this is not a history-completeness proof.
- `11-beta-check.json`: host-level beta gate result.
- `12-tui-snapshot.txt`: human operator dashboard.

## Verification Checklist

Before posting:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sh scripts/check-agent-command-contracts.sh
sh scripts/check-doc-release-refs.sh
sh scripts/launch-demo.sh
```

Also record the exact release PR head SHA, successful `ci.yml`, `audit.yml`,
`codeql.yml`, and `fuzz.yml` runs for that SHA, plus a fresh snapshot of required
branch checks. A workflow dispatch is not a successful check by itself.

After the beta tag exists:

```sh
sh scripts/check-release-assets.sh --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom
gommage release verify --tag <gommage-cli-vX.Y.Z-beta.1> --all-assets --json --require-sbom --require-provenance
gommage release verify --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom --require-provenance
sh scripts/verify-release.sh --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom --require-provenance
```

For every advertised archive, execute the exact released digest on its native
OS/architecture and record the result. The signature and GitHub artifact
attestation authenticate bytes and workflow identity; they do not establish a
hermetic/reproducible build or native execution. Run the partial-install fault
and backup-recovery test as well, because the installer replaces the three
binaries sequentially rather than atomically.

## Links To Include

- README: `https://github.com/Arakiss/gommage`
- Beta contract: `docs/beta-contract.md`
- Launch demo: `examples/launch-demo/README.md`
- Existing setups: `docs/existing-setups.md`
- Agent compatibility: `docs/agent-compatibility.md`
- Threat model: `THREAT_MODEL.md`
- Release verification: `docs/release-signing.md`

## Claims To Avoid

- Do not call it a sandbox.
- Do not claim universal MCP coverage.
- Do not imply Codex hooks cover every shell path, WebSearch, built-in
  non-shell/non-MCP tools, or MCP servers that never emit a matched hook event.
- Do not imply existing hooks are removed automatically.
- Do not imply `state.sqlite` is a permission source.
- Do not present crates.io as the signed release-archive install path. It is a
  Rust-native source-build path; GitHub Releases remain the signed archive path.
- Do not call per-record audit signatures a complete, ordered, or tamper-evident
  ledger; deletion, truncation, reordering, and duplication are not
  cryptographically detected in the current format.
- Do not claim a protected managed authority. The daemon, key, policy, socket,
  approval state, and status checks operate inside one trusted UID.
- Do not imply Picto v1 signatures cover mutable `uses` or `status`; the normal
  SQLite path enforces those fields transactionally.
- Do not call `--require-provenance` hermetic build, compiler provenance,
  reproducibility, or native runtime evidence.
- Do not describe the mutable-`main` compatibility bootstrap or default skill
  ref as immutable or release-signed. Public examples must keep download,
  inspection, and execution separate; Gommage categorically denies `curl | sh`.
- Do not describe three-binary installation as atomic or automatically rolled
  back after a partial failure.

## Release Fields

Fill these after release verification:

```text
Release tag:
Release URL:
Release workflow:
Release head SHA:
Exact-head CI/audit/CodeQL/fuzz runs:
Required-check configuration:
Asset check:
Release verify:
Native smoke per asset digest:
Partial-install recovery:
Host smoke macOS:
Host smoke Linux/systemd:
Launch demo capture:
Known beta warnings:
```
