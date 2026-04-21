#!/usr/bin/env sh
# Gommage installer.
#
# Usage:
#   curl --proto '=https' --tlsv1.2 -sSf \
#       https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
#
# Installs three binaries into $GOMMAGE_BIN (default: $HOME/.local/bin):
#   - gommage          (cli)
#   - gommage-daemon   (long-running process)
#   - gommage-mcp      (PreToolUse hook adapter)
#
# Downloads release artifacts from GitHub Releases and verifies their Sigstore
# signature bundle plus SHA-256 checksum. Refuses to install if either check
# fails. Requires `cosign` on PATH.
#
# Environment variables:
#   GOMMAGE_VERSION   — release tag to install (default: latest)
#   GOMMAGE_BIN       — install dir (default: $HOME/.local/bin)
#   GOMMAGE_REPO      — github repo slug (default: Arakiss/gommage)
#   GOMMAGE_COSIGN    — cosign binary path/name (default: cosign)
#   GOMMAGE_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN
#                    — optional token for private repo releases

set -eu

REPO="${GOMMAGE_REPO:-Arakiss/gommage}"
VERSION="${GOMMAGE_VERSION:-latest}"
BIN_DIR="${GOMMAGE_BIN:-${HOME}/.local/bin}"
COSIGN="${GOMMAGE_COSIGN:-cosign}"
GITHUB_TOKEN="${GOMMAGE_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"

say()  { printf 'gommage-install: %s\n' "$*"; }
die()  { printf 'gommage-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }
need_cosign() {
  command -v "$COSIGN" >/dev/null 2>&1 || die "required tool not found: $COSIGN (install cosign or set GOMMAGE_COSIGN)"
}
fetch() {
  url="$1"
  out="$2"
  if [ -n "$GITHUB_TOKEN" ]; then
    curl --proto '=https' --tlsv1.2 -sSfL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -o "$out" "$url"
  else
    curl --proto '=https' --tlsv1.2 -sSfL -o "$out" "$url"
  fi
}
fetch_stdout() {
  url="$1"
  if [ -n "$GITHUB_TOKEN" ]; then
    curl --proto '=https' --tlsv1.2 -sSfL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  else
    curl --proto '=https' --tlsv1.2 -sSfL "$url"
  fi
}
resolve_latest_cli_release() {
  wanted_asset="$1"
  fetch_stdout "https://api.github.com/repos/${REPO}/releases?per_page=100" \
    | awk -v wanted_asset="$wanted_asset" '
      /"tag_name": "/ {
        tag = $0
        sub(/.*"tag_name": "/, "", tag)
        sub(/".*/, "", tag)
      }
      /"name": "/ {
        name = $0
        sub(/.*"name": "/, "", name)
        sub(/".*/, "", name)
        if (found == "" && tag ~ /^gommage-cli-v/ && name == wanted_asset) {
          found = tag
        }
      }
      END { if (found != "") print found }
    '
}
asset_api_url() {
  wanted="$1"
  fetch_stdout "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" \
    | awk -v wanted="$wanted" '
      /"url": "https:\/\/api.github.com\/repos\/.*\/releases\/assets\// {
        url = $2
        gsub(/[",]/, "", url)
      }
      /"name": "/ {
        name = $0
        sub(/.*"name": "/, "", name)
        sub(/".*/, "", name)
        if (found == "" && name == wanted && url != "") {
          found = url
        }
      }
      END { if (found != "") print found }
    '
}
fetch_asset() {
  name="$1"
  out="$2"
  if [ -n "$GITHUB_TOKEN" ]; then
    api_url="$(asset_api_url "$name")"
    [ -n "$api_url" ] || die "release asset not found via GitHub API: ${name}"
    curl --proto '=https' --tlsv1.2 -sSfL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/octet-stream" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -o "$out" "$api_url"
  else
    fetch "$base/$name" "$out"
  fi
}

need curl
need_cosign
need tar
need uname
need mkdir
need install
need awk

# --- Detect OS / arch -------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Darwin) os="darwin"  ;;
  Linux)  os="linux"   ;;
  *)      die "unsupported OS: $os (only macOS and Linux are supported)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64"  ;;
  aarch64|arm64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

asset="gommage-${arch}-${os}"
tarball="${asset}.tar.gz"
checksum="${asset}.tar.gz.sha256"
bundle="${asset}.tar.gz.sigstore.json"

# --- Resolve version --------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  say "resolving latest cli release from github.com/${REPO}"
  VERSION="$(resolve_latest_cli_release "$tarball")"
  [ -n "$VERSION" ] || die "could not resolve latest cli release with ${tarball}"
fi
say "installing ${VERSION} for ${arch}-${os}"

# --- Download ---------------------------------------------------------------
base="https://github.com/${REPO}/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "downloading ${tarball}"
fetch_asset "${tarball}"  "${tmp}/${tarball}"
fetch_asset "${checksum}" "${tmp}/${checksum}"
fetch_asset "${bundle}"   "${tmp}/${bundle}"

# --- Verify Sigstore signature ---------------------------------------------
identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}"
issuer="https://token.actions.githubusercontent.com"

say "verifying Sigstore signature"
"$COSIGN" verify-blob "${tmp}/${tarball}" \
  --bundle "${tmp}/${bundle}" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${issuer}" \
  >/dev/null || die "signature verification failed — refusing to install"

# --- Verify checksum --------------------------------------------------------
say "verifying checksum"
cd "$tmp"
set -- $(sed -n '1p' "${checksum}")
expected_hash="${1:-}"
[ -n "$expected_hash" ] || die "could not parse ${checksum}"
[ "${#expected_hash}" -eq 64 ] || die "invalid checksum length in ${checksum}"
case "$expected_hash" in
  *[!0123456789abcdefABCDEF]*) die "invalid checksum format in ${checksum}" ;;
esac

if command -v shasum >/dev/null 2>&1; then
  set -- $(shasum -a 256 "${tarball}")
elif command -v sha256sum >/dev/null 2>&1; then
  set -- $(sha256sum "${tarball}")
else
  die "neither shasum nor sha256sum is available"
fi
actual_hash="${1:-}"
[ "$actual_hash" = "$expected_hash" ] || die "checksum mismatch — refusing to install"
cd - >/dev/null

# --- Extract + install ------------------------------------------------------
mkdir -p "$BIN_DIR"
say "extracting to ${BIN_DIR}"
tar -C "$tmp" -xzf "${tmp}/${tarball}"
for bin in gommage gommage-daemon gommage-mcp; do
  [ -f "${tmp}/${bin}" ] || die "binary ${bin} missing from ${tarball}"
  install -m 0755 "${tmp}/${bin}" "${BIN_DIR}/${bin}"
done

# --- Sanity check -----------------------------------------------------------
if ! echo ":$PATH:" | grep -q ":${BIN_DIR}:"; then
  say "WARNING: ${BIN_DIR} is not in \$PATH"
  say "add this to your shell rc:  export PATH=\"${BIN_DIR}:\$PATH\""
fi

say "installed ${VERSION} to ${BIN_DIR}"
say "run:  ${BIN_DIR}/gommage quickstart --agent claude"
say "codex: ${BIN_DIR}/gommage agent install codex"
say "daemon: ${BIN_DIR}/gommage daemon install"
