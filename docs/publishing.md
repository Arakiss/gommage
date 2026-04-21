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
- `gommage-stdlib`
- `gommage-cli`
- `gommage-daemon`
- `gommage-mcp`

The manifests intentionally keep `publish = false` until the publish pipeline
is ready. This prevents accidental partial publication while the API, CLI, and
policy stdlib are still changing quickly.

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
- crates.io provides `cargo install gommage-cli` for Rust-native users once the
  package gates above pass.
- Release automation publishes crates only after the binary release, SBOM, and
  Sigstore checks are green.
