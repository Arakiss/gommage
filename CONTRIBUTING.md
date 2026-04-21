# Contributing to gommage

Thanks for considering a contribution.

## Ground rules

1. **Determinism is the product.** Any change to the evaluator must pass the full determinism suite (`cargo test -p gommage-core --test determinism`) both in-order and shuffled. A PR that flakes the suite is a regression.
2. **No heuristics in the evaluator.** If a change needs to read session history, accumulated state, or anything beyond `(policy, capabilities)` → it belongs in the capability mapper or outside Gommage entirely.
3. **Hard-stops are hardcoded.** The hard-stop list lives in `crates/gommage-core/src/hardstop.rs` and is not configurable. Additions require a PR explaining why the operation is categorically unrecoverable.
4. **Policy changes ship as policy packs.** New stdlib rules go into `policies/`; breaking changes to the policy schema bump the schema version field, not the crate version in isolation.
5. **Pictos must stay minimal.** Any new field on a picto must have a clear use case and be justified in the PR; pictos are a security-sensitive surface.

## Local dev

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Releasing

Release engineer only. See `.github/workflows/release.yml`.

## Style

- `rustfmt` defaults, no custom `rustfmt.toml` unless we outgrow them.
- `clippy::pedantic` not enforced globally; apply where it clarifies, skip where it produces noise.
- Doc comments on every public item in `gommage-core`.
