#!/usr/bin/env sh
set -eu

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [ -z "$repo_root" ]; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

cd "$repo_root"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

export GOMMAGE_HOME="$tmp_dir/.gommage"

gommage_cmd() {
  if [ -n "${GOMMAGE_BIN:-}" ]; then
    "$GOMMAGE_BIN" "$@"
  else
    cargo run -q -p gommage-cli -- "$@"
  fi
}

gommage_cmd init >/dev/null
gommage_cmd policy init --stdlib >/dev/null
gommage_cmd policy test examples/policy-fixtures.yaml --json >/dev/null

echo "ok public policy fixtures: examples/policy-fixtures.yaml"
