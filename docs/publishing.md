# Publishing model

Gommage has two distribution channels with different maturity levels.

## Prerelease install path

The current compatibility bootstrap installs signed GitHub Release archives,
but it is not yet the immutable reference install path:

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  -o gommage-install.sh
# Inspect gommage-install.sh before executing it.
sh gommage-install.sh
```

This bootstrap downloads `scripts/install.sh` from the mutable `main` branch.
Keeping download and execution separate makes review possible, but does not
make the source immutable or release-signed. Replace `main` with a reviewed
commit SHA when the bootstrap script is inside your threat model. The installer
downloads the `gommage-cli-v*` release archive for the current OS and
architecture, verifies
the Sigstore bundle and SHA-256 checksum, and only then writes `gommage`,
`gommage-daemon`, and `gommage-mcp` into the install directory.
Operator/package-manager verification can additionally require the CycloneDX
SBOM and GitHub artifact attestation with `gommage release verify` or
`scripts/verify-release.sh`.

The three binaries are replaced sequentially with per-file backups; installation
is not an all-or-nothing transaction. A host failure can leave a mixed version
set, and post-install verification does not roll earlier writes back. Keep the
backups and run `gommage verify --json` as a health check after installation.
That command reports the companion version strings but does not compare their
compatibility, so a passing result is not proof of a coherent three-binary set.
Skill installation is a separate channel: remote skill files default to the
mutable `main` ref and are not covered by the binary archive's Sigstore
signature.

This is binary installation only. It does not register a universal MCP gateway
with Claude Code, Codex, or any other host. New `quickstart` integrations call
the CLI hook adapter, `gommage hook --agent <host>`. The `gommage-mcp` binary
remains for compatibility and opt-in stdio gateway use through
`gommage-mcp --gateway --server-name <name> -- <stdio-mcp-server>`.

Treat `gommage-cli-v*` as the product release tag stream. The public GitHub
Release title should read `Gommage vX.Y.Z...` because users install the product,
not a workspace component. Internal crate versions can differ for semver
hygiene, but new public GitHub Releases should only be created for the CLI tag
that carries the signed binary archives.

## Release hold switch

During repository maintenance, pause release automation with the repository
variable `GOMMAGE_RELEASE_HOLD=true`:

```sh
gh variable set GOMMAGE_RELEASE_HOLD --body true
```

When this variable is set to `true`, the release workflow skips release-please,
tag-triggered binary builds, and release evidence uploads. Normal CI remains
active. Resume release automation by setting the variable to `false` or deleting
it after the maintenance window:

```sh
gh variable set GOMMAGE_RELEASE_HOLD --body false
```

Useful installer options:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --version gommage-cli-vX.Y.Z-beta.N
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
to `main`. This keeps old binary tags installable while the current skill
evolves, but it also makes the default skill bootstrap mutable. Pin a reviewed
commit with `--skill-ref` when reproducibility matters.

## crates.io status

As verified through `cargo search` on July 16, 2026, the public `gommage-*`
crates are published on crates.io:

| Package | crates.io version | Local package gate |
|---|---:|---|
| `gommage-stdlib` | `0.13.0-alpha.1` | Passes `cargo package -p gommage-stdlib --allow-dirty`. |
| `gommage-core` | `0.17.0-alpha.1` | Prepared by `cargo package --no-verify` after published internal deps resolve. |
| `gommage-audit` | `0.7.3-alpha.1` | Prepared by `cargo package --no-verify` after published internal deps resolve. |
| `gommage-cli` | `0.50.0-beta.1` | Prepared by `cargo package --no-verify`; installs the `gommage` binary. |
| `gommage-daemon` | `0.9.0-alpha.1` | Prepared by `cargo package --no-verify`; installs `gommage-daemon`. |
| `gommage-mcp` | `0.11.0-alpha.1` | Prepared by `cargo package --no-verify`; installs `gommage-mcp`. |

The supported Rust-native source-build install path is:

```sh
cargo install gommage-cli --locked
cargo install gommage-daemon --locked
cargo install gommage-mcp --locked
```

GitHub Releases remain the recommended end-user install path because they
provide signed, checksum-verified, prebuilt binaries and install all three
runtime binaries together. crates.io is for users who intentionally want Cargo
to build from source.

Publishing remains an explicit registry mutation. Locally,
`scripts/publish-crates.sh --execute` is mapped to `pkg.cargo:publish` and
requires the same Gommage approval as `cargo publish`. In CI, crates.io publish
is off unless the repository variable `GOMMAGE_CRATES_IO_PUBLISH=true` is set
and the `CARGO_REGISTRY_TOKEN` secret is present.

Refresh the evidence with:

```sh
sh scripts/check-crates-publish-readiness.sh
```

The script treats `200` registry responses as published and `404` responses as
unpublished status evidence for future package names. It fails only on
unexpected registry errors, an unexpected `cargo package` failure, or a broken
`gommage-stdlib` package gate.

Use the local publisher in check mode before any registry mutation:

```sh
sh scripts/publish-crates.sh --check
```

The real local publish command is intentionally separate:

```sh
sh scripts/publish-crates.sh --execute
```

The command publishes in dependency order, skips exact versions that already
exist on crates.io, and waits for each published crate version to become visible
before moving to dependents.

## Intended publish order

Publish crates in dependency order. `gommage-stdlib` must go first because the
determinism test suite uses the packaged stdlib as a dev-dependency:

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

After release-please creates or updates a release PR, the release workflow
resolves its current head SHA and dispatches `ci.yml`, `audit.yml`, `codeql.yml`,
and `fuzz.yml` against that branch. It accepts an existing run only when the
recorded `headSha` matches, and verifies that a newly dispatched run also binds
to that SHA. The dispatcher confirms run creation; it does not wait for a
successful conclusion and does not itself make those workflows required branch
checks. Before merging a release PR, inspect the exact current head and the
repository's current required-check configuration.

Any internal `gommage-*` dependency that points at another workspace crate must
carry an exact `version = "=<crate version>"` requirement next to its local
`path`. This keeps release-please version bumps from creating tags whose binary
builds cannot resolve the workspace.

Publishing readiness is a CI and local network gate:

```sh
sh scripts/check-crates-publish-readiness.sh
```

Living release docs are also guarded:

```sh
sh scripts/check-doc-release-refs.sh
```

README, docs, installer comments, workflows, and agent skills should not pin
concrete `gommage-cli-v<version>` tags. Use the installer's `latest` resolution
or placeholder tags such as `gommage-cli-vX.Y.Z-beta.N` in examples. Changelogs
remain the release-history surface for concrete tags.

Release artifact verification is also a manual/network gate:

```sh
sh scripts/check-release-assets.sh --json
gommage release verify --json
gommage release verify --all-assets --json
sh scripts/verify-release.sh --json
```

Use stricter package-manager gates once the current release line has SBOM and
GitHub artifact attestations:

```sh
sh scripts/check-release-assets.sh --json --require-sbom
gommage release verify --all-assets --require-sbom --require-provenance
gommage release verify --require-sbom --require-provenance
sh scripts/verify-release.sh --require-sbom --require-provenance
```

`--require-provenance` requires GitHub's artifact attestation for each selected
digest and verifies the repository, workflow identity, issuer, and tag ref. It
does not prove a hermetic or reproducible build, compiler provenance, or native
execution on the advertised architecture. Release builds run in read-only jobs
and transfer unsigned archives to a separate publish job that does not check out
repository code; that job validates checksums, signs, attests, and uploads the
transferred bytes. The signature and attestation authenticate those bytes and
the publishing workflow identity, not every process that produced them.

The workflow cross-compiles Linux aarch64 on an x86_64 Linux runner and does not
execute every packaged archive on its native architecture. Four available
archives are distribution inventory, not four native runtime certifications.
Record an exact-asset native smoke result before making an architecture-specific
runtime claim.

## First-publish bootstrap

First-publish gates are sequential. Before `gommage-stdlib` exists on crates.io,
verified package commands for crates that depend on it will fail with "no
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

The helper automates that ordering:

```sh
sh scripts/publish-crates.sh --execute
```

For CI publication after a release, configure:

```sh
gh secret set CARGO_REGISTRY_TOKEN
gh variable set GOMMAGE_CRATES_IO_PUBLISH --body true
```

The release workflow publishes crates only after:

1. the `gommage-cli-v*` binary release is created;
2. all platform archives, checksums, and Sigstore bundles are uploaded;
3. the CycloneDX SBOM is uploaded and attested;
4. `scripts/check-release-assets.sh --require-sbom` passes;
5. `scripts/check-crates-publish-readiness.sh` passes.

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
- crates.io provides `cargo install gommage-cli`, `cargo install
  gommage-daemon`, and `cargo install gommage-mcp` for Rust-native users who
  prefer source builds.
- Release automation publishes crates only after the binary release, SBOM,
  Sigstore, and GitHub artifact attestation checks are green, and only when the
  explicit CI publish variable is enabled.
