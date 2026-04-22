#!/usr/bin/env sh
# Regression check for installer "latest" release resolution.

set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fixture="${tmp}/releases.json"
cli_prefix="gommage-cli-v"
mcp_prefix="gommage-mcp-v"
cat > "$fixture" <<JSON
[
  {
    "tag_name": "${cli_prefix}0.9.0-alpha.1",
    "name": "gommage-cli: v0.9.0-alpha.1",
    "assets": [
      { "name": "gommage-aarch64-darwin.tar.gz" }
    ]
  },
  {
    "tag_name": "${cli_prefix}0.8.0-alpha.1",
    "name": "gommage-cli: v0.8.0-alpha.1",
    "assets": [
      { "name": "gommage-aarch64-darwin.tar.gz" }
    ]
  },
  {
    "tag_name": "${mcp_prefix}9.9.9-alpha.1",
    "name": "gommage-mcp: v9.9.9-alpha.1",
    "assets": [
      { "name": "gommage-aarch64-darwin.tar.gz" }
    ]
  },
  {
    "tag_name": "${cli_prefix}0.14.1-alpha.1",
    "name": "gommage-cli: v0.14.1-alpha.1",
    "assets": [
      { "name": "gommage-aarch64-darwin.tar.gz" }
    ]
  },
  {
    "tag_name": "${cli_prefix}0.14.10-alpha.1",
    "name": "gommage-cli: v0.14.10-alpha.1",
    "assets": [
      { "name": "gommage-aarch64-darwin.tar.gz" }
    ]
  },
  {
    "tag_name": "${cli_prefix}0.15.0-alpha.1",
    "name": "gommage-cli: v0.15.0-alpha.1",
    "assets": [
      { "name": "gommage-x86_64-linux.tar.gz" }
    ]
  }
]
JSON

result="$(
  GOMMAGE_INSTALLER_LIBRARY=1 \
  GOMMAGE_RELEASES_JSON="$fixture" \
  sh -c '. ./scripts/install.sh; resolve_latest_cli_release gommage-aarch64-darwin.tar.gz'
)"

expected="${cli_prefix}0.14.10-alpha.1"
if [ "$result" != "$expected" ]; then
  echo "installer latest resolver picked ${result:-<empty>}; expected ${expected}" >&2
  exit 1
fi

missing="$(
  GOMMAGE_INSTALLER_LIBRARY=1 \
  GOMMAGE_RELEASES_JSON="$fixture" \
  sh -c '. ./scripts/install.sh; resolve_latest_cli_release gommage-s390x-linux.tar.gz'
)"

if [ -n "$missing" ]; then
  echo "installer latest resolver returned ${missing}; expected empty for missing asset" >&2
  exit 1
fi

bin_dir="${tmp}/bin"
mkdir -p "$bin_dir"
cat > "${bin_dir}/gommage" <<'SH'
#!/usr/bin/env sh
echo "verify-called"
exit 42
SH
chmod +x "${bin_dir}/gommage"

verify_skip="$(
  GOMMAGE_INSTALLER_LIBRARY=1 \
  sh -c ". ./scripts/install.sh; BIN_DIR='${bin_dir}'; VERIFY_AFTER_INSTALL=1; GOMMAGE_HOME='${tmp}/missing-home'; run_post_install_verify"
)"
case "$verify_skip" in
  *"skipping verify: no Gommage home"*) ;;
  *)
    echo "installer --verify did not skip missing fresh home" >&2
    printf '%s\n' "$verify_skip" >&2
    exit 1
    ;;
esac

echo "installer latest resolver ok"
