#!/bin/sh
# Derive the intended SemVer release type for one workspace package from the
# Conventional Commits that touched it. This lets cargo-semver-checks enforce
# unmarked breakage even before release-please updates package manifests.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <baseline-rev> <package-path>" >&2
  exit 2
fi

baseline_rev="$1"
package_path="$2"

git rev-parse --verify "${baseline_rev}^{commit}" >/dev/null

release_type='patch'
commits="$(git log --format=%H "${baseline_rev}..HEAD" -- "$package_path")"

for commit in $commits; do
  subject="$(git show -s --format=%s "$commit")"
  body="$(git show -s --format=%b "$commit")"

  if printf '%s\n' "$subject" | grep -Eq '^[a-z]+(\([^)]+\))?!:' \
    || printf '%s\n' "$body" | grep -Eq '^BREAKING[ -]CHANGE:'; then
    echo major
    exit 0
  fi

  if printf '%s\n' "$subject" | grep -Eq '^feat(\([^)]+\))?:'; then
    release_type='minor'
  fi
done

echo "$release_type"
