# Gommage task runner (just).
#
# Install: https://just.systems
#
# Recipes mirror the CI jobs in .github/workflows/ci.yml and the local-dev
# section of CONTRIBUTING.md. Running `just check` locally should produce the
# same verdict as CI on a clean PR.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Default recipe — list what's available.
_default:
    @just --list --unsorted

# Run the same checks CI runs on every PR (skips the 10× determinism sweep).
check: fmt clippy test policy-lint deny
    @echo "--- local check: ok ---"

# Check formatting without modifying files.
fmt:
    cargo fmt --all --check

# Apply formatting fixes in place.
fmt-fix:
    cargo fmt --all

# Clippy with -D warnings across the whole workspace.
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Workspace test suite.
test:
    cargo test --workspace

# One pass of the determinism suite, single-threaded.
determinism:
    cargo test -p gommage-core --test determinism -- --test-threads=1

# Full 10× determinism sweep — run before bumping a determinism-critical pin.
sweep:
    #!/usr/bin/env bash
    set -euo pipefail
    for i in $(seq 1 10); do
        echo "--- sweep $i ---"
        cargo test -p gommage-core --test determinism -- --test-threads=1
    done

# Rebuild CLI, seed throwaway GOMMAGE_HOME, run `gommage policy check`.
policy-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p gommage-cli
    tmp="$(mktemp -d)"
    export GOMMAGE_HOME="$tmp/.gommage"
    ./target/debug/gommage init
    cp policies/*.yaml      "$GOMMAGE_HOME/policy.d/"
    cp capabilities/*.yaml  "$GOMMAGE_HOME/capabilities.d/"
    ./target/debug/gommage policy check

# cargo-deny: advisories, bans, licenses, sources.
deny:
    cargo deny check advisories bans licenses sources

# cargo-semver-checks for gommage-core; defaults baseline to origin/main.
semver BASE="origin/main":
    cargo semver-checks check-release -p gommage-core --baseline-rev {{BASE}}

# Release-profile build of all workspace binaries.
release-build:
    cargo build --release --workspace

# Remove all build artefacts.
clean:
    cargo clean
