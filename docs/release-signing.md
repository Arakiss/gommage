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

Manual verification:

```sh
asset=gommage-x86_64-darwin.tar.gz
tag=gommage-cli-v0.1.2-alpha.1

cosign verify-blob "$asset" \
  --bundle "$asset.sigstore.json" \
  --certificate-identity "https://github.com/Arakiss/gommage/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

shasum -c "$asset.sha256"
```

Checksum assets are generated with the archive basename. The installer hashes
the downloaded archive directly and compares the first field of the `.sha256`
file, so historical checksum files that include a packaging directory still
verify the same archive contents.

For `workflow_dispatch`, run the workflow from the same tag ref that will own
the release. The workflow fails closed if the OIDC identity ref does not match
the release tag.
