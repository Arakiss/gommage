#!/usr/bin/env sh
# Verify that a gommage-cli GitHub Release has the expected binary artifacts.

set -eu

repo="${GOMMAGE_REPO:-Arakiss/gommage}"
tag="${GOMMAGE_VERSION:-latest}"
json="false"

usage() {
  cat <<'USAGE'
usage: sh scripts/check-release-assets.sh [options]

Options:
  --tag TAG, --version TAG  Release tag to inspect. Default: latest gommage-cli release.
  --repo OWNER/NAME         GitHub repository. Default: Arakiss/gommage.
  --json                    Emit machine-readable JSON.
  -h, --help                Show this help.

The check expects the current beta release channel shape:
  - 4 platform archives
  - 4 .sha256 checksum files
  - 4 .sigstore.json Sigstore bundles

Extra assets are reported as warnings but do not fail the check.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag | --version)
      tag="${2:-}"
      shift 2
      ;;
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --json)
      json="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "release-assets: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v gh >/dev/null 2>&1 || {
  echo "release-assets: required tool not found: gh" >&2
  exit 2
}

if [ -z "$tag" ]; then
  echo "release-assets: empty release tag" >&2
  exit 2
fi

if [ "$tag" = "latest" ]; then
  tag="$(
    gh release list --repo "$repo" --limit 50 --json tagName,publishedAt \
      --jq '[.[] | select(.tagName | startswith("gommage-cli-v"))] | sort_by(.publishedAt) | last | .tagName'
  )"
  if [ -z "$tag" ] || [ "$tag" = "null" ]; then
    echo "release-assets: no gommage-cli release found in $repo" >&2
    exit 1
  fi
fi

asset_names="$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')"
asset_count="$(printf '%s\n' "$asset_names" | awk 'NF { count += 1 } END { print count + 0 }')"
archive_count="$(printf '%s\n' "$asset_names" | awk '/^gommage-(aarch64-darwin|aarch64-linux|x86_64-darwin|x86_64-linux)\.tar\.gz$/ { count += 1 } END { print count + 0 }')"
checksum_count="$(printf '%s\n' "$asset_names" | awk '/^gommage-(aarch64-darwin|aarch64-linux|x86_64-darwin|x86_64-linux)\.tar\.gz\.sha256$/ { count += 1 } END { print count + 0 }')"
sigstore_count="$(printf '%s\n' "$asset_names" | awk '/^gommage-(aarch64-darwin|aarch64-linux|x86_64-darwin|x86_64-linux)\.tar\.gz\.sigstore\.json$/ { count += 1 } END { print count + 0 }')"

expected_assets="
gommage-aarch64-darwin.tar.gz
gommage-aarch64-darwin.tar.gz.sha256
gommage-aarch64-darwin.tar.gz.sigstore.json
gommage-aarch64-linux.tar.gz
gommage-aarch64-linux.tar.gz.sha256
gommage-aarch64-linux.tar.gz.sigstore.json
gommage-x86_64-darwin.tar.gz
gommage-x86_64-darwin.tar.gz.sha256
gommage-x86_64-darwin.tar.gz.sigstore.json
gommage-x86_64-linux.tar.gz
gommage-x86_64-linux.tar.gz.sha256
gommage-x86_64-linux.tar.gz.sigstore.json
"

missing=""
for expected in $expected_assets; do
  if ! printf '%s\n' "$asset_names" | grep -Fx "$expected" >/dev/null 2>&1; then
    missing="${missing}${missing:+
}$expected"
  fi
done

unexpected=""
for asset in $asset_names; do
  if ! printf '%s\n' "$expected_assets" | grep -Fx "$asset" >/dev/null 2>&1; then
    unexpected="${unexpected}${unexpected:+
}$asset"
  fi
done

status="pass"
if [ -n "$missing" ] || [ "$archive_count" -ne 4 ] || [ "$checksum_count" -ne 4 ] || [ "$sigstore_count" -ne 4 ]; then
  status="fail"
elif [ "$asset_count" -ne 12 ] || [ -n "$unexpected" ]; then
  status="warn"
fi

json_string_array() {
  awk '
    BEGIN { printf "["; first = 1 }
    NF {
      gsub(/\\/,"\\\\")
      gsub(/"/,"\\\"")
      if (!first) {
        printf ","
      }
      printf "\"%s\"", $0
      first = 0
    }
    END { printf "]" }
  '
}

if [ "$json" = "true" ]; then
  missing_json="$(printf '%s\n' "$missing" | json_string_array)"
  unexpected_json="$(printf '%s\n' "$unexpected" | json_string_array)"
  release_summary="$(
    gh release view "$tag" --repo "$repo" \
      --json tagName,name,isPrerelease,publishedAt,targetCommitish,url \
      --jq '{tagName,name,isPrerelease,publishedAt,targetCommitish,url}'
  )"
  printf '{\n'
  printf '  "status": "%s",\n' "$status"
  printf '  "release": %s,\n' "$release_summary"
  printf '  "counts": {\n'
  printf '    "assets": %s,\n' "$asset_count"
  printf '    "archives": %s,\n' "$archive_count"
  printf '    "checksums": %s,\n' "$checksum_count"
  printf '    "sigstore_bundles": %s\n' "$sigstore_count"
  printf '  },\n'
  printf '  "expected": {\n'
  printf '    "assets": 12,\n'
  printf '    "archives": 4,\n'
  printf '    "checksums": 4,\n'
  printf '    "sigstore_bundles": 4\n'
  printf '  },\n'
  printf '  "missing": %s,\n' "$missing_json"
  printf '  "unexpected": %s\n' "$unexpected_json"
  printf '}\n'
else
  release_name="$(gh release view "$tag" --repo "$repo" --json name --jq '.name')"
  release_url="$(gh release view "$tag" --repo "$repo" --json url --jq '.url')"
  release_target="$(gh release view "$tag" --repo "$repo" --json targetCommitish --jq '.targetCommitish')"
  echo "release assets: $status"
  echo "tag: $tag"
  echo "name: $release_name"
  echo "target: $release_target"
  echo "assets: $asset_count total, $archive_count archives, $checksum_count checksums, $sigstore_count sigstore bundles"
  echo "url: $release_url"
  if [ -n "$missing" ]; then
    echo "missing:"
    printf '%s\n' "$missing" | sed 's/^/- /'
  fi
  if [ -n "$unexpected" ]; then
    echo "unexpected:"
    printf '%s\n' "$unexpected" | sed 's/^/- /'
  fi
fi

case "$status" in
  fail) exit 1 ;;
  *) exit 0 ;;
esac
