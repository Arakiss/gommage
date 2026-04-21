# Contributing to gommage

Thanks for considering a contribution.

## Ground rules

1. **Determinism is the product.** Any change to the evaluator must pass the full determinism suite (`cargo test -p gommage-core --test determinism`) both in-order and shuffled. CI re-runs it 10× per build. A PR that flakes the suite is a regression.
2. **No heuristics in the evaluator.** If a change needs to read session history, accumulated state, or anything beyond `(policy, capabilities)` → it belongs in the capability mapper or outside Gommage entirely.
3. **Hard-stops are hardcoded.** The hard-stop list lives in `crates/gommage-core/src/hardstop.rs` and is not configurable. Additions require a PR explaining why the operation is categorically unrecoverable.
4. **Policy changes ship as policy packs.** New stdlib rules go into `policies/`; breaking changes to the policy schema bump the schema version field, not the crate version in isolation.
5. **Pictos must stay minimal.** Any new field on a picto must have a clear use case and be justified in the PR; pictos are a security-sensitive surface.
6. **Determinism-critical deps are pinned.** `ed25519-dalek`, `rusqlite`, `globset`, `regex`, `time`, `rand_core`, `sha2`, `base64`, `uuid`, `serde_yaml` are pinned with `=x.y.z` in the root `Cargo.toml`. Bumping one requires a PR with a green determinism suite run and a CHANGELOG note. Plumbing deps (`anyhow`, `thiserror`, `clap`, `tokio`, `serde`, `tracing`) stay on caret.

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/). CI runs `commitlint` on every PR; see `.commitlintrc.yaml` for the exact ruleset.

**Types** (required): `feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `security`.

**Scope** (optional, but when present must be one of): `core`, `audit`, `stdlib`, `cli`, `daemon`, `mcp`, `policies`, `capabilities`, `hardstop`, `picto`, `runtime`, `docs`, `ci`, `deps`, `release`, `security`, `determinism`.

Examples:

```
feat(core): add none_capability NOT-match semantics to policy rules
fix(mapper): escape ${} inside literal template segments
security(hardstop): add mkfs.* variant to the compiled-in hard-stop set
chore(deps): bump rusqlite to =0.34.0 — determinism suite green
```

**Breaking changes**: add `!` after the type (`feat(core)!:`) and include a `BREAKING CHANGE:` footer.

## Semver policy

- `gommage-core` has a strict public-API contract. `cargo-semver-checks` runs in CI on every PR; any breaking change to the public API surface requires a minor (pre-1.0) or major (1.0+) bump.
- `gommage-audit` follows the same contract — the audit log schema is a public API (downstream compliance tools parse it).
- CLI flags and daemon IPC are likewise versioned: breaking changes bump minor (pre-1.0) or major (1.0+), with the migration path documented in the release PR.
- `gommage-stdlib` is user-visible because its YAML can change decisions. A
  stdlib rule or mapper change that changes default behavior requires a
  changelog note and a minor bump while the project is pre-1.0.

## Releases

Automated via `release-please`. Do not tag manually. The bot opens a release PR when enough commits have landed; merging it creates the tag and triggers the binary-build workflow.

## Local dev

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                       # requires `cargo install cargo-deny`
cargo semver-checks check-release -p gommage-core   # requires `cargo install cargo-semver-checks`
```

## Style

- `rustfmt` defaults, no custom `rustfmt.toml` unless we outgrow them.
- `clippy::pedantic` not enforced globally; apply where it clarifies, skip where it produces noise.
- Doc comments on every public item in `gommage-core`.
- YAML policies + capability mappers: one concern per file, lexicographic numeric prefix to control load order (`00-`, `10-`, `20-`, …).
