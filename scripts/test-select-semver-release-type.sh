#!/bin/sh
# Exercise package-scoped SemVer intent selection in an isolated Git history.
set -eu

CDPATH=''
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
selector="$script_dir/select-semver-release-type.sh"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/gommage-semver-test.XXXXXX")"
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

cd "$temp_dir"
git init -q
git config user.name 'Gommage CI'
git config user.email 'ci@gommage.invalid'
mkdir -p crates/core crates/audit
printf 'pub fn core() {}\n' > crates/core/lib.rs
printf 'pub fn audit() {}\n' > crates/audit/lib.rs
git add crates/core/lib.rs crates/audit/lib.rs
git commit -q -m 'chore: establish baseline'
baseline="$(git rev-parse HEAD)"

expect_release_type() {
  expected="$1"
  package="$2"
  actual="$($selector "$baseline" "$package")"
  if [ "$actual" != "$expected" ]; then
    echo "expected $expected for $package, got $actual" >&2
    exit 1
  fi
}

printf '// patch\n' >> crates/core/lib.rs
git add crates/core/lib.rs
git commit -q -m 'fix(core): preserve compatibility'
expect_release_type patch crates/core
expect_release_type patch crates/audit

printf '// feature\n' >> crates/audit/lib.rs
git add crates/audit/lib.rs
git commit -q -m 'feat(audit): expose verification metadata'
expect_release_type patch crates/core
expect_release_type minor crates/audit

printf '// break\n' >> crates/core/lib.rs
git add crates/core/lib.rs
git commit -q -m 'refactor(core): replace public contract' \
  -m 'BREAKING CHANGE: callers must adopt the replacement contract.'
expect_release_type major crates/core
expect_release_type minor crates/audit

echo 'SemVer release-type selection tests passed'
