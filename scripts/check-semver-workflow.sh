#!/bin/sh
# Ensure unchanged package versions do not turn the SemVer check into a no-op.
# The release type must come from package-scoped Conventional Commits until
# release-please updates manifests, rather than from an unchanged version.
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
  'missing commit-aware release-type selection'
require_literal 'scripts/select-semver-release-type.sh' \
  'release type is not derived from package-scoped Conventional Commits'
require_literal 'scripts/test-select-semver-release-type.sh' \
  'release-type selection regression tests are not wired into CI'
# shellcheck disable=SC2016
require_literal '"origin/${BASE_REF}" crates/gommage-core' \
  'gommage-core does not select an intended release type'
# shellcheck disable=SC2016
require_literal '"origin/${BASE_REF}" crates/gommage-audit' \
  'gommage-audit does not select an intended release type'
# These are intentionally literal workflow expressions.
# shellcheck disable=SC2016
require_literal 'release-type: ${{ steps.semver-mode.outputs.core }}' \
  'gommage-core action does not consume the selected release type'
# shellcheck disable=SC2016
require_literal 'release-type: ${{ steps.semver-mode.outputs.audit }}' \
  'gommage-audit action does not consume the selected release type'
require_literal "baseline-rev: origin/\${{ github.base_ref || 'main' }}" \
  'SemVer actions do not compare against the pull-request base'

echo "SemVer workflow enforces package-scoped Conventional Commit intent"
