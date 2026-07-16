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
  if printf '%s\n' "$block" | grep -Eq "$pattern"; then
    echo "release boundary check: $message" >&2
    exit 1
  fi
}

require_pattern() {
  block="$1"
  pattern="$2"
  message="$3"
  if ! printf '%s\n' "$block" | grep -Eq "$pattern"; then
    echo "release boundary check: $message" >&2
    exit 1
  fi
}

for job in build-binaries build-release-evidence; do
  block="$(require_job "$job")"
  reject_pattern "$block" 'contents: write|id-token: write|attestations: write' \
    "$job must stay read-only"
  reject_pattern "$block" 'secrets\.|GH_TOKEN|CARGO_REGISTRY_TOKEN' \
    "$job must not receive publication credentials"
  require_pattern "$block" 'persist-credentials: false' \
    "$job checkout must not persist a Git credential"
done

for job in publish-binaries release-evidence; do
  block="$(require_job "$job")"
  reject_pattern "$block" 'actions/checkout|cargo (build|test|run|install)|scripts/' \
    "$job has release authority and must not execute repository code"
done

publish_crates="$(require_job publish-crates)"
job_prefix="$(printf '%s\n' "$publish_crates" | awk '/^    steps:$/ { exit } { print }')"
reject_pattern "$job_prefix" 'GH_TOKEN|CARGO_REGISTRY_TOKEN|secrets\.' \
  "publish-crates credentials must be scoped to individual steps"
require_pattern "$publish_crates" 'persist-credentials: false' \
  "publish-crates checkout must not persist a Git credential"

echo "release build and publication authority are separated"
