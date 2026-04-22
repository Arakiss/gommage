#!/usr/bin/env sh
# End-to-end host smoke for installers, fresh machines, and agent testers.

set -eu

mode="temp"
agent="claude"
daemon_manager=""
capture_dir=""
keep_temp="false"
yes="false"

usage() {
  cat <<'USAGE'
usage: sh scripts/host-smoke.sh [options]

Modes:
  --temp-home              Run against an isolated temporary HOME (default).
  --real-home              Run against the operator's real HOME. Requires --yes.

Options:
  --agent claude|codex     Agent quickstart/status path to exercise.
  --daemon-manager NAME    launchd or systemd. Defaults from uname.
  --capture-dir DIR        Directory for JSON/text evidence.
  --keep-temp              Do not delete the temporary HOME.
  --yes                    Confirm real-home mutation.
  -h, --help               Show this help.

The script never runs destructive cleanup. It captures `gommage uninstall
--all --dry-run` so the operator can review rollback before executing it.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --temp-home)
      mode="temp"
      shift
      ;;
    --real-home)
      mode="real"
      shift
      ;;
    --agent)
      agent="${2:-}"
      shift 2
      ;;
    --daemon-manager)
      daemon_manager="${2:-}"
      shift 2
      ;;
    --capture-dir)
      capture_dir="${2:-}"
      shift 2
      ;;
    --keep-temp)
      keep_temp="true"
      shift
      ;;
    --yes)
      yes="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "host-smoke: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$agent" in
  claude | codex) ;;
  *)
    echo "host-smoke: --agent must be claude or codex" >&2
    exit 2
    ;;
esac

if [ -z "$daemon_manager" ]; then
  case "$(uname -s)" in
    Darwin) daemon_manager="launchd" ;;
    Linux) daemon_manager="systemd" ;;
    *)
      echo "host-smoke: set --daemon-manager for this OS" >&2
      exit 2
      ;;
  esac
fi

case "$daemon_manager" in
  launchd | systemd) ;;
  *)
    echo "host-smoke: --daemon-manager must be launchd or systemd" >&2
    exit 2
    ;;
esac

gommage_cmd() {
  if [ -n "${GOMMAGE_BIN:-}" ]; then
    "$GOMMAGE_BIN" "$@"
  else
    gommage "$@"
  fi
}

tmp_root=""
cleanup() {
  if [ -n "$tmp_root" ] && [ "$keep_temp" != "true" ]; then
    rm -rf "$tmp_root"
  fi
}
trap cleanup EXIT INT TERM

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -z "$capture_dir" ]; then
  capture_dir="host-smoke-$timestamp"
fi
mkdir -p "$capture_dir"

if [ "$mode" = "real" ]; then
  if [ "$yes" != "true" ]; then
    echo "host-smoke: --real-home mutates host config; rerun with --yes after review" >&2
    exit 2
  fi
else
  tmp_root="$(mktemp -d)"
  export HOME="$tmp_root/home"
  export GOMMAGE_HOME="$HOME/.gommage"
  export GOMMAGE_CLAUDE_SETTINGS="$HOME/.claude/settings.json"
  export GOMMAGE_CODEX_HOOKS="$HOME/.codex/hooks.json"
  export GOMMAGE_CODEX_CONFIG="$HOME/.codex/config.toml"
  export GOMMAGE_SYSTEMD_USER_DIR="$tmp_root/systemd-user"
  export GOMMAGE_LAUNCHD_DIR="$tmp_root/launchd"
  mkdir -p "$HOME/.claude" "$HOME/.codex"
  printf '{"permissions":{"allow":["Bash","Read(./docs/**)"],"deny":["Read(./secrets/**)"]}}\n' \
    > "$GOMMAGE_CLAUDE_SETTINGS"
  printf '{"PreToolUse":[]}\n' > "$GOMMAGE_CODEX_HOOKS"
  printf 'sandbox_mode = "workspace-write"\n[features]\n' > "$GOMMAGE_CODEX_CONFIG"
fi

run_capture() {
  label="$1"
  file="$2"
  shift 2
  echo "host-smoke: $label"
  if "$@" > "$capture_dir/$file" 2> "$capture_dir/$file.err"; then
    return 0
  fi
  cat "$capture_dir/$file.err" >&2
  echo "host-smoke: failed: $label" >&2
  exit 1
}

run_capture "gommage version" "version.txt" gommage_cmd --version
run_capture "quickstart dry-run plan" "quickstart-plan.json" \
  gommage_cmd quickstart --agent "$agent" --daemon --daemon-manager "$daemon_manager" \
    --dry-run --json
run_capture "quickstart apply without daemon start" "quickstart.txt" \
  gommage_cmd quickstart --agent "$agent" --daemon-no-start \
    --daemon-manager "$daemon_manager" --self-test
run_capture "verify readiness" "verify.json" gommage_cmd verify --json
run_capture "agent status" "agent-status.json" \
  gommage_cmd agent status "$agent" --json
run_capture "semantic smoke" "smoke.json" gommage_cmd smoke --json
run_capture "redacted report bundle" "report-bundle.out" \
  gommage_cmd report bundle --redact --force --output "$capture_dir/report-bundle.json"
run_capture "rollback dry-run" "uninstall-dry-run.txt" \
  gommage_cmd uninstall --all --dry-run --daemon-manager "$daemon_manager"

{
  echo "mode=$mode"
  echo "agent=$agent"
  echo "daemon_manager=$daemon_manager"
  echo "capture_dir=$capture_dir"
  if [ "$mode" = "temp" ]; then
    echo "temp_home=$HOME"
    echo "temp_kept=$keep_temp"
  fi
} > "$capture_dir/summary.env"

echo "host-smoke: ok"
echo "host-smoke: evidence written to $capture_dir"
