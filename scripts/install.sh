#!/usr/bin/env sh
# Gommage installer.
#
# Usage:
#   curl --proto '=https' --tlsv1.2 -sSf \
#       https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh | sh
#
#   sh scripts/install.sh --version gommage-cli-vX.Y.Z-alpha.N --bin-dir "$HOME/.local/bin"
#
#   sh scripts/install.sh --with-skill --skill-agent codex --skill-agent claude
#
#   sh scripts/install.sh --skill-only --skill-agent codex
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
#   GOMMAGE_INSTALL_SKILL
#                    — auto, yes, or no (default: auto)
#   GOMMAGE_SKILL_AGENTS
#                    — space/comma-separated codex, claude, or all
#   GOMMAGE_SKILL_REF
#                    — git ref for remote skill files (default: main)
#   GOMMAGE_NO_PROMPT
#                    — set to 1 for headless/non-interactive installs
#   GOMMAGE_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN
#                    — optional token for private repo releases

set -eu

REPO="${GOMMAGE_REPO:-Arakiss/gommage}"
VERSION="${GOMMAGE_VERSION:-latest}"
BIN_DIR="${GOMMAGE_BIN:-${HOME}/.local/bin}"
COSIGN="${GOMMAGE_COSIGN:-cosign}"
INSTALL_SKILL="${GOMMAGE_INSTALL_SKILL:-auto}"
SKILL_AGENTS="${GOMMAGE_SKILL_AGENTS:-}"
SKILL_REF="${GOMMAGE_SKILL_REF:-main}"
NO_PROMPT="${GOMMAGE_NO_PROMPT:-0}"
SKILL_ONLY=0
GITHUB_TOKEN="${GOMMAGE_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"

say()  { printf 'gommage-install: %s\n' "$*"; }
die()  { printf 'gommage-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }
usage() {
  cat <<'EOF'
Gommage installer

Usage:
  install.sh [--version <tag>] [--bin-dir <path>] [--repo <owner/name>] [--cosign <path>] [--with-skill] [--skill-agent <agent>] [--help]
  install.sh --skill-only [--skill-agent <agent>] [--repo <owner/name>] [--skill-ref <ref>]

Options:
  --version <tag>       Release tag to install. Default: latest gommage-cli release.
  --bin-dir <path>      Install directory. Default: $HOME/.local/bin.
  --repo <slug>         GitHub repository slug. Default: Arakiss/gommage.
  --cosign <path>       cosign executable. Default: cosign.
  --with-skill          Install the Gommage agent skill after binaries.
  --no-skill            Do not prompt for or install the agent skill.
  --skill-only          Install/update only the Gommage agent skill.
  --skill-agent <agent> Agent skill target: codex, claude, claude-code, or all.
                        May be repeated. Default with --with-skill: codex.
  --skill-ref <ref>     Git ref for remote skill files. Default: main.
  --no-prompt           Never prompt. Auto mode skips skill installation.
  -h, --help            Show this help.

Environment:
  GOMMAGE_VERSION, GOMMAGE_BIN, GOMMAGE_REPO, GOMMAGE_COSIGN
  GOMMAGE_INSTALL_SKILL=auto|yes|no
  GOMMAGE_SKILL_AGENTS="codex claude" or "codex,claude"
  GOMMAGE_SKILL_REF=main
  GOMMAGE_NO_PROMPT=1
  GOMMAGE_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN for private release downloads.

The installer verifies the Sigstore bundle and SHA-256 checksum before it
extracts or writes binaries. Skill installation copies the repository skill to:
  Codex:      ${CODEX_HOME:-$HOME/.codex}/skills/gommage
  Claude Code: ${CLAUDE_HOME:-$HOME/.claude}/skills/gommage
EOF
}
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
has_tty() {
  [ -r /dev/tty ] && [ -w /dev/tty ]
}
prompt_yes_no() {
  prompt="$1"
  printf '%s [y/N] ' "$prompt" > /dev/tty
  answer=""
  IFS= read -r answer < /dev/tty || return 1
  case "$answer" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}
add_skill_agent() {
  agent="$1"
  case "$agent" in
    codex) ;;
    claude|claude-code) agent="claude" ;;
    all)
      add_skill_agent codex
      add_skill_agent claude
      return
      ;;
    *) die "unsupported skill agent: ${agent} (expected codex, claude, or all)" ;;
  esac
  case " ${SKILL_AGENTS} " in
    *" ${agent} "*) ;;
    *) SKILL_AGENTS="${SKILL_AGENTS}${SKILL_AGENTS:+ }${agent}" ;;
  esac
}
normalize_skill_agents() {
  requested="$(printf '%s' "$SKILL_AGENTS" | tr ',' ' ')"
  SKILL_AGENTS=""
  for agent in $requested; do
    add_skill_agent "$agent"
  done
}
prompt_skill_agents() {
  while :; do
    printf 'Install the Gommage agent skill for:\n  1) Codex\n  2) Claude Code\n  3) Codex + Claude Code\nSelection [1]: ' > /dev/tty
    answer=""
    IFS= read -r answer < /dev/tty || answer=""
    case "$answer" in
      ""|1|codex|Codex)
        SKILL_AGENTS="codex"
        return
        ;;
      2|claude|Claude|claude-code|ClaudeCode)
        SKILL_AGENTS="claude"
        return
        ;;
      3|all|both|Both)
        SKILL_AGENTS="codex claude"
        return
        ;;
      *)
        printf 'Please choose 1, 2, or 3.\n' > /dev/tty
        ;;
    esac
  done
}
configure_skill_install() {
  case "$INSTALL_SKILL" in
    auto|yes|no) ;;
    true|1) INSTALL_SKILL=yes ;;
    false|0) INSTALL_SKILL=no ;;
    *) die "invalid GOMMAGE_INSTALL_SKILL value: ${INSTALL_SKILL} (expected auto, yes, or no)" ;;
  esac

  normalize_skill_agents

  if [ "$SKILL_ONLY" -eq 1 ]; then
    INSTALL_SKILL=yes
  elif [ "$INSTALL_SKILL" = "auto" ]; then
    if [ "$NO_PROMPT" = "1" ] || ! has_tty; then
      INSTALL_SKILL=no
    elif prompt_yes_no "Install the Gommage agent skill for Codex or Claude Code now?"; then
      INSTALL_SKILL=yes
    else
      INSTALL_SKILL=no
    fi
  fi

  if [ "$INSTALL_SKILL" = "yes" ] && [ -z "$SKILL_AGENTS" ]; then
    if [ "$NO_PROMPT" != "1" ] && has_tty; then
      prompt_skill_agents
    else
      SKILL_AGENTS="codex"
    fi
  fi
}
skill_ref() {
  printf '%s\n' "$SKILL_REF"
}
local_skill_dir() {
  script_parent="$(CDPATH= cd "$(dirname "$0")/.." 2>/dev/null && pwd -P || true)"
  if [ -n "$script_parent" ] && [ -f "${script_parent}/skills/gommage/SKILL.md" ]; then
    printf '%s\n' "${script_parent}/skills/gommage"
  fi
}
skill_dest_dir() {
  agent="$1"
  case "$agent" in
    codex) printf '%s\n' "${CODEX_HOME:-${HOME}/.codex}/skills/gommage" ;;
    claude) printf '%s\n' "${CLAUDE_HOME:-${HOME}/.claude}/skills/gommage" ;;
    *) die "unsupported skill agent target: ${agent}" ;;
  esac
}
install_skill_file() {
  rel="$1"
  dest="$2"
  local_dir="$3"
  if [ -n "$local_dir" ] && [ -f "${local_dir}/${rel}" ]; then
    install -m 0644 "${local_dir}/${rel}" "$dest"
  else
    ref="$(skill_ref)"
    fetch "https://raw.githubusercontent.com/${REPO}/${ref}/skills/gommage/${rel}" "$dest"
  fi
}
install_skill_for_agent() {
  agent="$1"
  dest_dir="$(skill_dest_dir "$agent")"
  local_dir="$(local_skill_dir)"

  mkdir -p "${dest_dir}/agents"
  install_skill_file "SKILL.md" "${dest_dir}/SKILL.md" "$local_dir"
  install_skill_file "agents/openai.yaml" "${dest_dir}/agents/openai.yaml" "$local_dir"

  say "installed ${agent} skill to ${dest_dir}"
}
install_requested_skills() {
  if [ "$INSTALL_SKILL" != "yes" ]; then
    return
  fi
  for agent in $SKILL_AGENTS; do
    install_skill_for_agent "$agent"
  done
  say "restart Codex or Claude Code so newly installed skills are discovered"
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --bin-dir)
      [ "$#" -ge 2 ] || die "--bin-dir requires a value"
      BIN_DIR="$2"
      shift 2
      ;;
    --repo)
      [ "$#" -ge 2 ] || die "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --cosign)
      [ "$#" -ge 2 ] || die "--cosign requires a value"
      COSIGN="$2"
      shift 2
      ;;
    --with-skill|--install-skill)
      INSTALL_SKILL=yes
      shift
      ;;
    --no-skill)
      INSTALL_SKILL=no
      shift
      ;;
    --skill-only)
      SKILL_ONLY=1
      INSTALL_SKILL=yes
      shift
      ;;
    --skill-agent)
      [ "$#" -ge 2 ] || die "--skill-agent requires a value"
      add_skill_agent "$2"
      shift 2
      ;;
    --skill-ref)
      [ "$#" -ge 2 ] || die "--skill-ref requires a value"
      SKILL_REF="$2"
      shift 2
      ;;
    --no-prompt)
      NO_PROMPT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

need curl
need mkdir
need install
need tr

configure_skill_install

if [ "$SKILL_ONLY" -eq 1 ]; then
  install_requested_skills
  exit 0
fi

need_cosign
need tar
need uname
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

install_requested_skills

# --- Sanity check -----------------------------------------------------------
if ! echo ":$PATH:" | grep -q ":${BIN_DIR}:"; then
  say "WARNING: ${BIN_DIR} is not in \$PATH"
  say "add this to your shell rc:  export PATH=\"${BIN_DIR}:\$PATH\""
fi

say "installed ${VERSION} to ${BIN_DIR}"
say "skills: curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | sh -s -- --skill-only --skill-agent codex --skill-agent claude"
say "claude: ${BIN_DIR}/gommage quickstart --agent claude --daemon"
say "codex:  ${BIN_DIR}/gommage quickstart --agent codex --daemon"
say "health: ${BIN_DIR}/gommage doctor"
