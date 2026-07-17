# Release signing

Gommage release archives are signed with Sigstore keyless signing from GitHub
Actions. Each platform archive has three release assets:

- `gommage-<arch>-<os>.tar.gz`
- `gommage-<arch>-<os>.tar.gz.sha256`
- `gommage-<arch>-<os>.tar.gz.sigstore.json`

New CLI releases produced by the current workflow also attach a CycloneDX SBOM:

- `gommage-<tag>.cdx.json`

Older alpha releases may not have the SBOM asset or GitHub artifact
attestations. Treat that as historical release evidence, not the target release
shape for beta.

The `.sigstore.json` file is a Cosign bundle containing the signature,
certificate, and transparency-log proof for the archive. The release workflow
signs the archive with the GitHub Actions OIDC identity for the release tag:

```text
https://github.com/Arakiss/gommage/.github/workflows/release.yml@refs/tags/<tag>
```

The installer verifies both:

1. Cosign bundle against the expected workflow identity and issuer
   `https://token.actions.githubusercontent.com`.
2. SHA-256 checksum for the archive contents.

If either check fails, installation stops before extracting or writing any
binary.

This proves that the selected archive digest was signed by the expected
tag-scoped publishing workflow identity. It does not by itself prove a hermetic
or reproducible build, the compiler that produced the archive, or that the
archive executed successfully on its advertised architecture.

For private repository releases, set `GOMMAGE_GITHUB_TOKEN`, `GH_TOKEN`, or
`GITHUB_TOKEN`; the installer sends it only as a GitHub `Authorization` header
for release API and asset downloads.

When `GOMMAGE_VERSION=latest` (the default), the installer resolves the newest
`gommage-cli-v*` release that contains the platform archive it needs. It does
not rely on GitHub's repository-level "latest release" pointer. `gommage-cli`
is the installable tag channel, and the public release title should be
`Gommage vX.Y.Z...`. Internal crates may have git tags so release-please can
calculate per-crate changelog boundaries, but new internal crate tags should
not become public GitHub Releases and do not carry binary archives.

Manual verification:

```sh
asset=gommage-x86_64-darwin.tar.gz
tag=gommage-cli-vX.Y.Z-beta.N

cosign verify-blob "$asset" \
  --bundle "$asset.sigstore.json" \
  --certificate-identity "https://github.com/Arakiss/gommage/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

shasum -c "$asset.sha256"
```

Operator verification from a checkout:

```sh
gommage release verify --tag gommage-cli-vX.Y.Z-beta.N
gommage release verify --tag gommage-cli-vX.Y.Z-beta.N --json
gommage release verify --tag gommage-cli-vX.Y.Z-beta.N --all-assets --json --require-sbom --require-provenance
sh scripts/verify-release.sh --tag gommage-cli-vX.Y.Z-beta.N
sh scripts/verify-release.sh --tag gommage-cli-vX.Y.Z-beta.N --json
```

Both verification surfaces download the platform archive, checksum, and
Sigstore bundle; verify the release-tag workflow identity; and check GitHub
artifact attestations when present. Use `gommage release verify --all-assets`
with `--require-sbom --require-provenance` for beta, RC, or package-manager
release gates that must verify every supported archive.

Here, `--require-provenance` means that a GitHub artifact attestation for the
selected digest must verify against the repository, tag ref, issuer, and
workflow identity. It is not a claim of hermetic isolation, reproducible builds,
compiler provenance, or SLSA level. `--all-assets` verifies distribution
inventory and evidence for every archive; it does not run those archives.

GitHub artifact attestations are produced with `actions/attest` in the same
tag-scoped workflow after the build jobs transfer their archives to the publish
job. Verify them manually with:

```sh
gh attestation verify "$asset" \
  --repo Arakiss/gommage \
  --cert-identity "https://github.com/Arakiss/gommage/.github/workflows/release.yml@refs/tags/$tag" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --source-ref "refs/tags/$tag"
```

Installer flags:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --version gommage-cli-vX.Y.Z-beta.N
sh scripts/install.sh --bin-dir "$HOME/.local/bin"
sh scripts/install.sh --with-skill --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-ref main
```

`--with-skill` installs the repository Agent Skill after binary verification.
`--skill-only` updates the skill without downloading release binaries or using
Cosign, which is useful for agent setup flows and documentation smoke tests.
Remote skill installs default to `--skill-ref main` so old alpha binary tags can
still be paired with the current setup skill. That skill ref is mutable and its
contents are not covered by the release archive signature; use a reviewed commit
SHA when a reproducible skill install matters.

Checksum assets are generated with the archive basename. The installer hashes
the downloaded archive directly and compares the first field of the `.sha256`
file, so historical checksum files that include a packaging directory still
verify the same archive contents.

When release-please creates a CLI release, the release workflow dispatches its
binary-build path from the new tag ref instead of relying on a recursive tag
push. This keeps the Sigstore identity tied to `refs/tags/<tag>` while using
only the repository `GITHUB_TOKEN`.

Build jobs have read-only repository permissions and upload unsigned archives.
The publish job has release authority, does not check out repository code,
validates the transferred inventory and checksums, then signs, attests, and
uploads those exact bytes. This split reduces the code that runs with publishing
authority. The resulting evidence authenticates the transferred digest and
workflow identity; it cannot retroactively establish how every build process
produced that digest.

crates.io follows the same authority split with a narrower mutation lane. A
credential-free job packages the crates and seals complete registry upload
request bodies. The registry job has no checkout, Cargo, Rust toolchain, or
repository script; after validating inventory, framing, commit, and tag, it
uses crates.io Trusted Publishing to obtain a short-lived OIDC token and sends
only those sealed bytes. No long-lived crates.io token is stored in GitHub.

Linux aarch64 is cross-compiled on an x86_64 Linux runner, and the release
workflow does not natively execute all four packaged archives. Archive presence
must not be presented as native runtime evidence; record a smoke test for the
exact released digest on the target architecture when that claim matters.

For manual `workflow_dispatch` backfills, run the workflow from the same tag ref
that will own the release. The workflow fails closed if the OIDC identity ref
does not match the release tag.
