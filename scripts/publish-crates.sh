#!/bin/sh
set -eu

mode="check"
allow_dirty="false"
wait_attempts="${GOMMAGE_CRATES_IO_WAIT_ATTEMPTS:-30}"
wait_seconds="${GOMMAGE_CRATES_IO_WAIT_SECONDS:-10}"
user_agent="${GOMMAGE_CRATES_IO_USER_AGENT:-gommage-crates-publish/0.1 (+https://github.com/Arakiss/gommage)}"

usage() {
  cat <<'USAGE'
Usage: sh scripts/publish-crates.sh [--check|--print-versions|--execute] [--allow-dirty]

Publish the Gommage workspace crates to crates.io in dependency order.

Default mode is --check. It refreshes crates.io status and local package gates
without mutating the registry.

--execute      run real cargo publish commands, skipping crate versions that
               already exist on crates.io
--print-versions
               print the local workspace crate versions in publish order
--allow-dirty  pass --allow-dirty to cargo package/publish; intended only for
               local bootstrap work, never for CI
-h, --help     show this help

Publishing is permanent. The repository policy maps --execute to
pkg.cargo:publish so local operators still need an explicit picto.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check | --dry-run)
      mode="check"
      shift
      ;;
    --print-versions)
      mode="versions"
      shift
      ;;
    --execute)
      mode="execute"
      shift
      ;;
    --allow-dirty)
      allow_dirty="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "publish-crates: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [ -z "$repo_root" ]; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

cd "$repo_root"

for required in cargo curl; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "publish-crates: required tool not found: $required" >&2
    exit 2
  fi
done

if [ "$allow_dirty" = "true" ]; then
  dirty_arg="--allow-dirty"
else
  dirty_arg=""
fi

publish_order="
gommage-stdlib
gommage-core
gommage-audit
gommage-cli
gommage-daemon
gommage-mcp
"

version_for() {
  package="$1"
  pkgid="$(cargo pkgid -p "$package")"
  case "$pkgid" in
    *@*)
      version="${pkgid##*@}"
      ;;
    *#*)
      version="${pkgid##*#}"
      ;;
    *)
      version=""
      ;;
  esac

  if [ -z "$version" ] || [ "$version" = "$pkgid" ]; then
    echo "publish-crates: could not resolve version for $package from cargo pkgid" >&2
    exit 2
  fi
  printf '%s\n' "$version"
}

if [ "$mode" = "check" ]; then
  sh scripts/check-crates-publish-readiness.sh
  for package in $publish_order; do
    version_for "$package" >/dev/null
  done
  exit 0
fi

if [ "$mode" = "versions" ]; then
  echo "== local crate versions =="
  for package in $publish_order; do
    printf '%s %s\n' "$package" "$(version_for "$package")"
  done
  exit 0
fi

version_status() {
  package="$1"
  version="$2"
  curl -sS -A "$user_agent" -o /dev/null -w "%{http_code}" \
    "https://crates.io/api/v1/crates/$package/$version"
}

wait_for_version() {
  package="$1"
  version="$2"
  attempt=1
  while [ "$attempt" -le "$wait_attempts" ]; do
    status="$(version_status "$package" "$version" || true)"
    if [ "$status" = "200" ]; then
      echo "ok $package $version: visible on crates.io"
      return 0
    fi

    echo "wait $package $version: crates.io status ${status:-000} (attempt $attempt/$wait_attempts)"
    sleep "$wait_seconds"
    attempt=$((attempt + 1))
  done

  echo "publish-crates: timed out waiting for $package $version on crates.io" >&2
  exit 1
}

echo "== crates.io publish =="
for package in $publish_order; do
  version="$(version_for "$package")"
  status="$(version_status "$package" "$version" || true)"
  case "$status" in
    200)
      echo "skip $package $version: already published"
      continue
      ;;
    404)
      ;;
    *)
      echo "publish-crates: unexpected crates.io status for $package $version: ${status:-000}" >&2
      exit 1
      ;;
  esac

  echo "package $package $version"
  # shellcheck disable=SC2086
  cargo package -p "$package" $dirty_arg

  echo "publish $package $version"
  # shellcheck disable=SC2086
  cargo publish -p "$package" $dirty_arg

  wait_for_version "$package" "$version"
done

echo
echo "crates.io publish complete"
