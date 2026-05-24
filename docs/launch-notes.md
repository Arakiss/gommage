# Launch Notes

These notes are the technical launch handoff for the first beta announcement.
Do not publish them as final copy until the beta release tag exists and
verification links are filled in.

## Positioning

Gommage is a deterministic policy and audit layer for AI coding agent tool
calls. It gives operators reviewable YAML policy, signed single-use pictos,
signed audit evidence, and one command to diagnose whether the local agent
harness is wired correctly.

The beta message is:

> Gommage does not replace your agent sandbox. It makes the permission decisions
> you care about explicit, versionable, auditable, and reproducible across
> Claude Code and Codex-style harnesses.

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
- `06-audit-verify.json`: signed audit evidence verifies offline.
- `08-state-verify.json`: `state.sqlite` matches signed `audit.log`.
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

After the beta tag exists:

```sh
sh scripts/check-release-assets.sh --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom
gommage release verify --tag <gommage-cli-vX.Y.Z-beta.1> --all-assets --json --require-sbom --require-provenance
gommage release verify --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom --require-provenance
sh scripts/verify-release.sh --tag <gommage-cli-vX.Y.Z-beta.1> --json --require-sbom --require-provenance
```

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
- Do not claim crates.io install support until the publish gate passes.

## Release Fields

Fill these after release verification:

```text
Release tag:
Release URL:
Release workflow:
Asset check:
Release verify:
Host smoke macOS:
Host smoke Linux/systemd:
Launch demo capture:
Known beta warnings:
```
