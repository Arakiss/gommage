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

Useful installer options:

```sh
sh scripts/install.sh --help
sh scripts/install.sh --version gommage-cli-v0.4.0-alpha.1
sh scripts/install.sh --bin-dir "$HOME/.local/bin"
```

For private release downloads, set `GOMMAGE_GITHUB_TOKEN`, `GH_TOKEN`, or
`GITHUB_TOKEN`.

## crates.io status

As of April 21, 2026, the `gommage-*` crates are not published on crates.io.
The package names checked during the readiness pass were:

- `gommage-core`
- `gommage-audit`
- `gommage-cli`
- `gommage-daemon`
- `gommage-mcp`

The manifests intentionally keep `publish = false` until the publish pipeline
is ready. This prevents accidental partial publication while the API, CLI, and
policy stdlib are still changing quickly.

## Intended publish order

When publishing opens, publish crates in dependency order:

1. `gommage-core`
2. `gommage-audit`
3. `gommage-cli`
4. `gommage-daemon`
5. `gommage-mcp`

The workspace dependencies already carry registry version requirements beside
their local paths so `cargo package` has the metadata it needs after Cargo
strips path dependencies for crates.io consumers.

## Gates before flipping `publish = false`

Do not publish until all of these pass:

```sh
cargo package -p gommage-core
cargo package -p gommage-audit
cargo package -p gommage-cli
cargo package -p gommage-daemon
cargo package -p gommage-mcp
```

Also confirm that `gommage-cli` packages the embedded policy/capability stdlib
instead of relying on files outside the crate package. Today the source build
embeds `policies/` and `capabilities/` from the repository root; crates.io
packaging must either vendor those files into the package or move the stdlib
into a publishable crate before `cargo install gommage-cli` becomes supported.

## Release automation target

The target state is:

- GitHub Releases remain the primary install path for end users because they
  provide signed, checksum-verified, prebuilt binaries.
- crates.io provides `cargo install gommage-cli` for Rust-native users once the
  package gates above pass.
- Release automation publishes crates only after the binary release, SBOM, and
  Sigstore checks are green.
