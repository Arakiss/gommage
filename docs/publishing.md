# Publishing model

Gommage has two distribution channels with different maturity levels.

## Alpha install path

The supported alpha install path is the GitHub Release binary installer:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
```

The installer downloads the `gommage-cli-v*` release archive for the current
OS and architecture, verifies the Sigstore bundle, verifies the SHA-256
checksum, and only then extracts `gommage`, `gommage-daemon`, and
`gommage-mcp` into the install directory.

Treat `gommage-cli-v*` as the product release stream. Internal crate versions
can differ for semver hygiene, and older alpha history may show per-crate
GitHub Releases, but new public GitHub Releases should only be created for the
CLI release that carries the signed binary archives.

Useful installer options:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --version gommage-cli-vX.Y.Z-alpha.N
sh scripts/install.sh --bin-dir "$HOME/.local/bin"
sh scripts/install.sh --with-skill --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-ref main
```

For private release downloads, set `GOMMAGE_GITHUB_TOKEN`, `GH_TOKEN`, or
`GITHUB_TOKEN`.

The agent skill is distributed from `skills/gommage` and can be installed by the
same script without reinstalling binaries. Installer-managed destinations are:

- Codex: `${CODEX_HOME:-$HOME/.codex}/skills/gommage`
- Claude Code: `${CLAUDE_HOME:-$HOME/.claude}/skills/gommage`

Remote skill installs read from `GOMMAGE_SKILL_REF` / `--skill-ref`, defaulting
to `main`. This keeps old binary tags installable while the alpha skill evolves.

## crates.io status

As of April 22, 2026, the `gommage-*` crates are not published on crates.io.
crates.io publishing itself does not require paid billing, but it does require
a crates.io account, an API token, and an explicit maintainer decision to claim
the package names. The manifests intentionally keep `publish = false` until the
publish pipeline is ready. This prevents accidental partial publication while
the API, CLI, and policy stdlib are still changing quickly.

Current evidence:

| Package | crates.io API | Local package gate |
|---|---:|---|
| `gommage-stdlib` | `404` | Passes `cargo package -p gommage-stdlib --allow-dirty`. |
| `gommage-core` | `404` | Blocked as expected until `gommage-stdlib` exists on crates.io. |
| `gommage-audit` | `404` | Blocked as expected until `gommage-core` exists on crates.io. |
| `gommage-cli` | `404` | Blocked as expected until `gommage-audit` exists on crates.io. |
| `gommage-daemon` | `404` | Blocked as expected until `gommage-audit` exists on crates.io. |
| `gommage-mcp` | `404` | Blocked as expected until `gommage-audit` exists on crates.io. |

Refresh the evidence with:

```sh
sh scripts/check-crates-publish-readiness.sh
```

The script treats `404` and `200` registry responses as valid status evidence.
It fails only on unexpected registry errors, an unexpected `cargo package`
failure, or a broken `gommage-stdlib` package gate.

## Intended publish order

When publishing opens, publish crates in dependency order. `gommage-stdlib`
must go first because the determinism test suite uses the packaged stdlib as a
dev-dependency:

1. `gommage-stdlib`
2. `gommage-core`
3. `gommage-audit`
4. `gommage-cli`
5. `gommage-daemon`
6. `gommage-mcp`

The workspace dependencies already carry registry version requirements beside
their local paths so `cargo package` has the metadata it needs after Cargo
strips path dependencies for crates.io consumers.

CI and the release workflow enforce that invariant with:

```sh
sh scripts/sync-workspace-internal-deps.sh --check
```

Repair stale root pins locally with:

```sh
sh scripts/sync-workspace-internal-deps.sh
```

The release workflow also runs this repair step against the generated
release-please PR branch. That keeps root `[workspace.dependencies]` exact
version requirements synchronized with crate version bumps before a release PR
is merged, avoiding stale CLI artifacts after internal crate releases.

The release workflow creates lightweight git tags for internal packages that
set `skip-github-release=true` before release-please runs on `main`. These tags
are not GitHub Releases and carry no binary assets. They exist only to preserve
release-please's previous-release boundary for each workspace crate while
keeping the public Releases tab focused on Gommage as a product.

Verify or repair those internal tag boundaries with:

```sh
sh scripts/tag-skipped-release-please-components.sh --check
sh scripts/tag-skipped-release-please-components.sh
```

After release-please creates or updates a release PR, the release workflow also
dispatches `ci.yml` against the release PR branch. This avoids the previous
manual "empty commit" workaround for required checks: the PR branch is tested
after any automated workspace-pin repair, and maintainers can merge the release
PR only after the same CI contract has run on the exact generated branch.

GitHub may mark bot-authored `pull_request` workflow runs as
`action_required`. To keep release PRs mergeable without manual approvals,
`ci.yml` and `audit.yml` also define a restricted `pull_request_target` path
for same-repository branches named `release-please--branches--*`. Those jobs
check out the release PR head SHA explicitly and skip all other
`pull_request_target` invocations, so elevated-token execution is not broadened
to forks or arbitrary user branches.

Any internal `gommage-*` dependency that points at another workspace crate must
carry an exact `version = "=<crate version>"` requirement next to its local
`path`. This keeps release-please version bumps from creating tags whose binary
builds cannot resolve the workspace.

Publishing readiness is a manual/network gate:

```sh
sh scripts/check-crates-publish-readiness.sh
```

Living release docs are also guarded:

```sh
sh scripts/check-doc-release-refs.sh
```

README, docs, installer comments, workflows, and agent skills should not pin
concrete `gommage-cli-v<version>` tags. Use the installer's `latest` resolution
or placeholder tags such as `gommage-cli-vX.Y.Z-alpha.N` in examples. Changelogs
remain the release-history surface for concrete tags.

## Gates before flipping `publish = false`

First-publish gates are sequential. Before `gommage-stdlib` exists on
crates.io, package commands for crates that depend on it will fail with "no
matching package named `gommage-stdlib` found". That is expected. Package and
publish `gommage-stdlib` first, then run the remaining gates:

```sh
cargo package -p gommage-stdlib
```

After `gommage-stdlib` is available on crates.io:

```sh
cargo package -p gommage-core
cargo package -p gommage-audit
cargo package -p gommage-cli
cargo package -p gommage-daemon
cargo package -p gommage-mcp
```

`gommage-stdlib` owns the packaged policy/capability YAML that `gommage-cli`
embeds at compile time. The repository-root `policies/` and `capabilities/`
directories are review-friendly mirrors; CI must keep them byte-identical to
the packaged crate assets with:

```sh
diff -ru policies crates/gommage-stdlib/policies
diff -ru capabilities crates/gommage-stdlib/capabilities
```

## Release automation target

The target state is:

- GitHub Releases remain the primary install path for end users because they
  provide signed, checksum-verified, prebuilt binaries.
- GitHub Releases should expose the product stream only. Release automation may
  still bump and tag internal crates in the release PR, but non-CLI workspace
  components skip GitHub Release publication.
- crates.io provides `cargo install gommage-cli` for Rust-native users once the
  package gates above pass.
- Release automation publishes crates only after the binary release, SBOM, and
  Sigstore checks are green.
