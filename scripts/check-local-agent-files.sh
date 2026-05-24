#!/usr/bin/env sh
# Fail if local-only agent instruction or run-state files are tracked.

set -eu

tracked="$(
  git ls-files | awk '
    $0 == "AGENTS.md" { print }
    $0 == "CLAUDE.md" { print }
    $0 ~ /^\.codex(\/|$)/ { print }
    $0 ~ /^\.claude(\/|$)/ { print }
    $0 ~ /^\.codex-runs(\/|$)/ { print }
  '
)"

if [ -n "$tracked" ]; then
  echo "local agent files must not be tracked:" >&2
  printf '%s\n' "$tracked" | sed 's/^/- /' >&2
  echo "move private agent instructions to local-only storage or .git/info/exclude" >&2
  exit 1
fi

echo "local agent files not tracked"
