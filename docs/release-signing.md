# Release signing

Gommage release archives are signed with Sigstore keyless signing from GitHub
Actions. Each platform archive has three release assets:

- `gommage-<arch>-<os>.tar.gz`
- `gommage-<arch>-<os>.tar.gz.sha256`
- `gommage-<arch>-<os>.tar.gz.sigstore.json`

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

For private repository releases, set `GOMMAGE_GITHUB_TOKEN`, `GH_TOKEN`, or
`GITHUB_TOKEN`; the installer sends it only as a GitHub `Authorization` header
for release API and asset downloads.

When `GOMMAGE_VERSION=latest` (the default), the installer resolves the newest
`gommage-cli-v*` release that contains the platform archive it needs. It does
not rely on GitHub's repository-level "latest release" pointer. `gommage-cli`
is the installable product channel. Internal crates may have git tags so
release-please can calculate per-crate changelog boundaries, but new internal
crate tags should not become public GitHub Releases and do not carry binary
archives.

Manual verification:

```sh
asset=gommage-x86_64-darwin.tar.gz
tag=gommage-cli-vX.Y.Z-alpha.N

cosign verify-blob "$asset" \
  --bundle "$asset.sigstore.json" \
  --certificate-identity "https://github.com/Arakiss/gommage/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

shasum -c "$asset.sha256"
```

Installer flags:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --version gommage-cli-vX.Y.Z-alpha.N
sh scripts/install.sh --bin-dir "$HOME/.local/bin"
sh scripts/install.sh --with-skill --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-agent claude
sh scripts/install.sh --skill-only --skill-agent codex --skill-ref main
```

`--with-skill` installs the repository Agent Skill after binary verification.
`--skill-only` updates the skill without downloading release binaries or using
Cosign, which is useful for agent setup flows and documentation smoke tests.
Remote skill installs default to `--skill-ref main` so old alpha binary tags can
still be paired with the current setup skill.

Checksum assets are generated with the archive basename. The installer hashes
the downloaded archive directly and compares the first field of the `.sha256`
file, so historical checksum files that include a packaging directory still
verify the same archive contents.

When release-please creates a CLI release, the release workflow dispatches its
binary-build path from the new tag ref instead of relying on a recursive tag
push. This keeps the Sigstore identity tied to `refs/tags/<tag>` while using
only the repository `GITHUB_TOKEN`.

For manual `workflow_dispatch` backfills, run the workflow from the same tag ref
that will own the release. The workflow fails closed if the OIDC identity ref
does not match the release tag.
