#!/bin/sh
set -eu

workflows_dir="${1:-.github/workflows}"

if [ ! -d "$workflows_dir" ]; then
  echo "workflow directory not found: $workflows_dir" >&2
  exit 1
fi

references_file="$(mktemp)"
trap 'rm -f "$references_file"' EXIT HUP INT TERM

find "$workflows_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print \
  | sort \
  | while IFS= read -r workflow; do
      grep -nE '^[[:space:]-]*uses:[[:space:]]*' "$workflow" \
        | sed "s#^#${workflow}:#" \
        || true
    done > "$references_file"

failed=0
while IFS= read -r occurrence; do
  reference="${occurrence#*uses:}"
  reference="${reference%%#*}"
  reference="$(printf '%s' "$reference" | tr -d '[:space:]')"

  case "$reference" in
    ./* | docker://*)
      continue
      ;;
  esac

  if ! printf '%s\n' "$reference" | grep -Eq '@[0-9a-f]{40}$'; then
    echo "mutable GitHub Action reference: $occurrence" >&2
    failed=1
  fi
done < "$references_file"

if [ "$failed" -ne 0 ]; then
  echo "external GitHub Actions must use full immutable commit SHAs" >&2
  exit 1
fi

echo "all external GitHub Actions use immutable commit SHAs"
