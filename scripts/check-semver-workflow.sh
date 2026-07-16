#!/bin/sh
# Ensure unchanged package versions do not turn the SemVer check into a
# no-op. cargo-semver-checks treats an unchanged version as a major release,
# which skips compatibility lints unless the workflow supplies a release type.
set -eu

workflow="${1:-.github/workflows/ci.yml}"

if [ ! -f "$workflow" ]; then
  echo "semver workflow not found: $workflow" >&2
  exit 1
fi

require_literal() {
  literal="$1"
  message="$2"
  if ! grep -Fq -- "$literal" "$workflow"; then
    echo "semver workflow check: $message" >&2
    exit 1
  fi
}

require_literal 'id: semver-mode' \
  'missing version-aware release-type selection'
require_literal 'release_type_for core crates/gommage-core/Cargo.toml' \
  'gommage-core does not select an effective release type'
require_literal 'release_type_for audit crates/gommage-audit/Cargo.toml' \
  'gommage-audit does not select an effective release type'
# These are intentionally literal workflow expressions and shell fragments.
# shellcheck disable=SC2016
require_literal 'echo "${output_name}=patch" >> "$GITHUB_OUTPUT"' \
  'unchanged versions are not forced through patch compatibility checks'
# shellcheck disable=SC2016
require_literal 'release-type: ${{ steps.semver-mode.outputs.core }}' \
  'gommage-core action does not consume the selected release type'
# shellcheck disable=SC2016
require_literal 'release-type: ${{ steps.semver-mode.outputs.audit }}' \
  'gommage-audit action does not consume the selected release type'
require_literal "baseline-rev: origin/\${{ github.base_ref || 'main' }}" \
  'SemVer actions do not compare against the pull-request base'

echo "SemVer workflow checks unchanged versions with patch compatibility"
