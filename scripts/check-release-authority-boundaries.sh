#!/bin/sh
# Enforce the credential boundary in the release workflow. Repository build
# code must run without publication authority; credential-bearing jobs must not
# check out or execute repository code.
set -eu

workflow="${1:-.github/workflows/release.yml}"

if [ ! -f "$workflow" ]; then
  echo "release workflow not found: $workflow" >&2
  exit 1
fi

job_block() {
  job="$1"
  awk -v header="  ${job}:" '
    $0 == header { found = 1 }
    found && $0 != header && /^  [A-Za-z0-9_-]+:$/ { exit }
    found { print }
  ' "$workflow"
}

require_job() {
  job="$1"
  block="$(job_block "$job")"
  if [ -z "$block" ]; then
    echo "release boundary check: missing job $job" >&2
    exit 1
  fi
  printf '%s\n' "$block"
}

reject_pattern() {
  block="$1"
  pattern="$2"
  message="$3"
  if printf '%s\n' "$block" | grep -Eq -- "$pattern"; then
    echo "release boundary check: $message" >&2
    exit 1
  fi
}

require_pattern() {
  block="$1"
  pattern="$2"
  message="$3"
  if ! printf '%s\n' "$block" | grep -Eq -- "$pattern"; then
    echo "release boundary check: $message" >&2
    exit 1
  fi
}

for job in build-binaries build-release-evidence build-crates-publish-bundles; do
  block="$(require_job "$job")"
  reject_pattern "$block" 'contents: write|id-token: write|attestations: write' \
    "$job must stay read-only"
  reject_pattern "$block" 'secrets\.|GH_TOKEN|CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN' \
    "$job must not receive publication credentials"
  require_pattern "$block" 'persist-credentials: false' \
    "$job checkout must not persist a Git credential"
done

crate_build="$(require_job build-crates-publish-bundles)"
require_pattern "$crate_build" 'scripts/prepare-crates-publish-bundles\.mjs' \
  "crate publish bodies must be prepared without registry authority"
require_pattern "$crate_build" 'actions/upload-artifact@[0-9a-f]{40}' \
  "sealed crate publish bodies must cross jobs through a pinned artifact action"

for job in publish-binaries release-evidence; do
  block="$(require_job "$job")"
  reject_pattern "$block" 'actions/checkout|cargo (build|test|run|install)|scripts/' \
    "$job has release authority and must not execute repository code"
done

publish_crates="$(require_job publish-crates)"
reject_pattern "$publish_crates" \
  'actions/checkout|rust-toolchain|rust-cache|cargo (build|package|publish|run|test|install)|scripts/|secrets\.|GH_TOKEN|CARGO_REGISTRY_TOKEN|contents: (read|write)' \
  "publish-crates must not check out, build, execute repository code, or receive a long-lived credential"
reject_pattern "$publish_crates" '(^|[[:space:]])(node|python|python3|ruby|perl)[[:space:]]' \
  "publish-crates must stay an upload-only shell lane"
reject_pattern "$publish_crates" '(^|[[:space:]])(bash|sh|source|\.)[[:space:]]+[^[:space:]]*publish-bundles' \
  "publish-crates must treat transferred artifacts as data, never executable code"
require_pattern "$publish_crates" 'actions: read' \
  "publish-crates may only read the transferred workflow artifact"
require_pattern "$publish_crates" 'id-token: write' \
  "publish-crates must use OIDC instead of a stored registry secret"
require_pattern "$publish_crates" 'actions/download-artifact@[0-9a-f]{40}' \
  "publish-crates must download sealed request bodies through a pinned action"
require_pattern "$publish_crates" 'rust-lang/crates-io-auth-action@[0-9a-f]{40}' \
  "publish-crates must obtain a short-lived token through the pinned official action"
require_pattern "$publish_crates" 'CRATES_IO_TOKEN:.*steps\.crates-io-auth\.outputs\.token' \
  "the short-lived token must be scoped to the opaque upload step"
require_pattern "$publish_crates" 'unset CRATES_IO_TOKEN' \
  "the upload step must remove the token from the child-process environment"
require_pattern "$publish_crates" "--data-binary.*request_path" \
  "publish-crates must upload the previously sealed request body"
require_pattern "$publish_crates" "'https://crates\.io/api/v1/crates/new'" \
  "publish-crates must use the fixed crates.io publish endpoint"

if grep -q 'CARGO_REGISTRY_TOKEN' "$workflow"; then
  echo "release boundary check: release workflow must not reference a stored crates.io token" >&2
  exit 1
fi

validate_line="$(printf '%s\n' "$publish_crates" | grep -n 'Validate sealed publish inventory and framing' | cut -d: -f1)"
auth_line="$(printf '%s\n' "$publish_crates" | grep -n 'Obtain short-lived crates.io token' | cut -d: -f1)"
upload_line="$(printf '%s\n' "$publish_crates" | grep -n 'Upload only sealed registry request bodies' | cut -d: -f1)"
if [ -z "$validate_line" ] || [ -z "$auth_line" ] || [ -z "$upload_line" ] \
  || [ "$validate_line" -ge "$auth_line" ] || [ "$auth_line" -ge "$upload_line" ]; then
  echo "release boundary check: sealed inventory validation must precede OIDC authentication and upload" >&2
  exit 1
fi

echo "release build and publication authority are separated"
