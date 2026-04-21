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
# Downloads release artifacts from GitHub Releases and verifies their SHA-256
# checksums. Refuses to install if the checksum does not match.
#
# Environment variables:
#   GOMMAGE_VERSION   — release tag to install (default: latest)
#   GOMMAGE_BIN       — install dir (default: $HOME/.local/bin)
#   GOMMAGE_REPO      — github repo slug (default: Arakiss/gommage)

set -eu

REPO="${GOMMAGE_REPO:-Arakiss/gommage}"
VERSION="${GOMMAGE_VERSION:-latest}"
BIN_DIR="${GOMMAGE_BIN:-${HOME}/.local/bin}"

say()  { printf 'gommage-install: %s\n' "$*"; }
die()  { printf 'gommage-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

need curl
need tar
need uname
need mkdir
need install

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

# --- Resolve version --------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  say "resolving latest release from github.com/${REPO}"
  VERSION="$(
    curl --proto '=https' --tlsv1.2 -sSfL \
      "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep -E '"tag_name":' | head -n1 \
      | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
  )"
  [ -n "$VERSION" ] || die "could not resolve latest release (is the repo public? any releases?)"
fi
say "installing ${VERSION} for ${arch}-${os}"

# --- Download ---------------------------------------------------------------
base="https://github.com/${REPO}/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

tarball="${asset}.tar.gz"
checksum="${asset}.tar.gz.sha256"

say "downloading ${tarball}"
curl --proto '=https' --tlsv1.2 -sSfL -o "${tmp}/${tarball}"  "${base}/${tarball}"
curl --proto '=https' --tlsv1.2 -sSfL -o "${tmp}/${checksum}" "${base}/${checksum}"

# --- Verify checksum --------------------------------------------------------
say "verifying checksum"
cd "$tmp"
if command -v shasum >/dev/null 2>&1; then
  shasum -c "${checksum}" || die "checksum mismatch — refusing to install"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${checksum}" || die "checksum mismatch — refusing to install"
else
  die "neither shasum nor sha256sum is available"
fi
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
