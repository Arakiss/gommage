<!--
Thanks for the PR. Keep this template — maintainers scan it during review.

Conventional Commit: the PR title must match `<type>(<scope>): <subject>` where
type ∈ {feat, fix, chore, docs, refactor, perf, test, build, ci, revert,
security} and scope (when present) is one of the scopes listed in
.commitlintrc.yaml. CI will block the merge if it does not.
-->

## Summary

<!-- One or two sentences on what this PR does and why. -->

## Motivation

<!-- What problem does this solve, or what decision does it encode?
     Link the issue, threat-model section, or discussion if one exists. -->

## Determinism impact

<!-- Required for any PR that touches crates/gommage-core,
     crates/gommage-audit, policies/, capabilities/, or any pinned dep. -->

- [ ] No impact (docs, CI-only, tests that do not change decisions).
- [ ] Evaluator / mapper / policy / hardstop change. I have run the determinism suite locally (`cargo test -p gommage-core --test determinism`) and it is green, forward and shuffled.
- [ ] This PR bumps a determinism-critical dep (`ed25519-dalek`, `rusqlite`, `globset`, `regex`, `time`, `rand_core`, `sha2`, `base64`, `uuid`, `serde_yaml_ng`). The full suite ran 10×.
- [ ] This PR adds or modifies a hard-stop. I explain below why the operation is categorically unrecoverable.

## Audit log / public API

<!-- Leave blank if none of these apply. -->

- [ ] Adds, removes, or renames a field in the audit log JSONL schema (breaking — needs migration notes and a semver bump).
- [ ] Changes the public API surface of `gommage-core`. `cargo semver-checks` locally is green.
- [ ] Changes a CLI flag or daemon IPC message. Release notes flagged.

## CHANGELOG

- [ ] This PR will land a CHANGELOG entry via release-please (Conventional Commit title covers it).
- [ ] This PR is intentionally chore/docs/test and should not appear in the user-facing changelog.

## Testing

<!-- Commands you ran, and any that cannot be run in CI. -->

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Notes for reviewers

<!-- Anything that would help the reviewer. Pitfalls, follow-ups, known
     limitations, alternative approaches you considered and rejected. -->
