#!/usr/bin/env bash
set -euo pipefail

readonly max_lines=1000

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [[ -z "$repo_root" ]]; then
  if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    printf 'error: Rust module size check requires a Git worktree\n' >&2
    exit 1
  fi
fi

if ! repo_root="$(git -C "$repo_root" rev-parse --show-toplevel 2>/dev/null)"; then
  printf 'error: Rust module size check requires a valid Git worktree root\n' >&2
  exit 1
fi

cd "$repo_root"

file_list="$(mktemp "${TMPDIR:-/tmp}/gommage-rust-files.XXXXXX")"
trap 'rm -f "$file_list"' EXIT

if ! git ls-files -z --cached --others --exclude-standard -- '*.rs' >"$file_list"; then
  printf 'error: failed to enumerate Rust source files\n' >&2
  exit 1
fi

checked=0
violations=0

while IFS= read -r -d '' file; do
  [[ -f "$file" ]] || continue

  lines="$(awk 'END { print NR }' "$file")"
  checked=$((checked + 1))

  if ((lines > max_lines)); then
    printf 'error: %s has %d lines; maximum allowed is %d\n' \
      "$file" "$lines" "$max_lines" >&2
    violations=$((violations + 1))
  fi
done <"$file_list"

if ((checked == 0)); then
  printf 'error: Rust module size check found no Rust source files\n' >&2
  exit 1
fi

if ((violations > 0)); then
  printf 'Rust module size check failed: %d file(s) exceed %d lines.\n' \
    "$violations" "$max_lines" >&2
  exit 1
fi

printf 'Rust module size check passed: %d file(s), maximum %d lines.\n' \
  "$checked" "$max_lines"
