#!/bin/sh
set -eu

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [ -z "$repo_root" ]; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

cd "$repo_root"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
user_agent="${GOMMAGE_CRATES_IO_USER_AGENT:-gommage-publish-readiness/0.1 (+https://github.com/Arakiss/gommage)}"

crates="
gommage-stdlib
gommage-core
gommage-audit
gommage-cli
gommage-daemon
gommage-mcp
"

failures=0

echo "== crates.io registry status =="
for crate in $crates; do
  status="$(
    curl -sS -A "$user_agent" -o "$tmp_dir/$crate.crates.json" \
      -w "%{http_code}" \
      "https://crates.io/api/v1/crates/$crate" \
      2>"$tmp_dir/$crate.curl.err" || true
  )"

  case "$status" in
    200)
      echo "ok $crate: published"
      ;;
    404)
      echo "ok $crate: unpublished"
      ;;
    *)
      echo "fail $crate: unexpected crates.io HTTP status ${status:-000}" >&2
      if [ -s "$tmp_dir/$crate.curl.err" ]; then
        sed 's/^/  /' "$tmp_dir/$crate.curl.err" >&2
      fi
      failures=1
      ;;
  esac
done

run_package_gate() {
  crate="$1"
  mode="$2"
  log_file="$tmp_dir/$crate.package.log"

  if [ "$mode" = "verify" ]; then
    if cargo package -p "$crate" --allow-dirty >"$log_file" 2>&1; then
      echo "ok $crate: cargo package verified"
      return
    fi
  else
    if cargo package -p "$crate" --allow-dirty --no-verify >"$log_file" 2>&1; then
      echo "ok $crate: cargo package prepared"
      return
    fi
  fi

  if grep -q "no matching package named .*gommage-" "$log_file"; then
    missing_dep="$(sed -n 's/.*no matching package named `\([^`]*\)`.*/\1/p' "$log_file" | head -n 1)"
    if [ -z "$missing_dep" ]; then
      missing_dep="an internal dependency"
    fi
    echo "pending $crate: publish $missing_dep first"
    if [ "${GOMMAGE_CRATES_READINESS_VERBOSE:-0}" = "1" ]; then
      grep -A3 "no matching package named" "$log_file" | sed 's/^/  /'
    fi
    return
  fi

  echo "fail $crate: unexpected cargo package failure" >&2
  sed 's/^/  /' "$log_file" >&2
  failures=1
}

echo
echo "== local package gates =="
run_package_gate gommage-stdlib verify
run_package_gate gommage-core prepare
run_package_gate gommage-audit prepare
run_package_gate gommage-cli prepare
run_package_gate gommage-daemon prepare
run_package_gate gommage-mcp prepare

if [ "$failures" -ne 0 ]; then
  echo
  echo "crates.io publish readiness check failed" >&2
  exit 1
fi

echo
echo "crates.io publish readiness check complete"
