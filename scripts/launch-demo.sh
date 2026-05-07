#!/usr/bin/env sh
# Reproducible local launch demo for Gommage's beta story.

set -eu

capture_dir=""
keep_home="false"

usage() {
  cat <<'USAGE'
usage: sh scripts/launch-demo.sh [options]

Options:
  --capture-dir DIR   Directory for demo evidence. Default: launch-demo-<utc timestamp>.
  --keep-home         Preserve the temporary HOME/GOMMAGE_HOME and record its path.
  -h, --help          Show this help.

The demo uses an isolated temporary HOME and never mutates the operator's real
agent configuration. It captures:
  - dry-run and applied quickstart inside the isolated HOME;
  - ask_picto for git push to main;
  - a one-use git.push:main picto grant;
  - the next matching push allowed by that picto;
  - a hard-stop deny for rm -rf /;
  - signed audit verification;
  - state.sqlite rebuild, verify, and stats;
  - the host-level beta gate and TUI snapshot.

Set GOMMAGE_BIN=/path/to/gommage to demo a prebuilt binary. Without GOMMAGE_BIN,
the script uses `cargo run -q -p gommage-cli --` from a source checkout, then
falls back to an installed `gommage` on PATH.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --capture-dir)
      [ "$#" -ge 2 ] || {
        echo "launch-demo: --capture-dir requires a value" >&2
        exit 2
      }
      capture_dir="$2"
      shift 2
      ;;
    --keep-home)
      keep_home="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "launch-demo: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
public_fixture="$repo_root/examples/policy-fixtures.yaml"

if [ -z "$capture_dir" ]; then
  capture_dir="launch-demo-$timestamp"
fi
mkdir -p "$capture_dir"

tmp_root="$(mktemp -d)"
cleanup() {
  if [ "$keep_home" != "true" ]; then
    rm -rf "$tmp_root"
  fi
}
trap cleanup EXIT INT TERM

export HOME="$tmp_root/home"
export GOMMAGE_HOME="$HOME/.gommage"
export GOMMAGE_CLAUDE_SETTINGS="$HOME/.claude/settings.json"
export GOMMAGE_CODEX_HOOKS="$HOME/.codex/hooks.json"
export GOMMAGE_CODEX_CONFIG="$HOME/.codex/config.toml"
export GOMMAGE_SYSTEMD_USER_DIR="$tmp_root/systemd-user"
export GOMMAGE_LAUNCHD_DIR="$tmp_root/launchd"
mkdir -p "$HOME/.claude" "$HOME/.codex"
printf '{"permissions":{"allow":["Bash"],"deny":[]}}\n' > "$GOMMAGE_CLAUDE_SETTINGS"
printf '{"PreToolUse":[]}\n' > "$GOMMAGE_CODEX_HOOKS"
printf 'sandbox_mode = "workspace-write"\n[features]\n' > "$GOMMAGE_CODEX_CONFIG"

gommage_cmd() {
  if [ -n "${GOMMAGE_BIN:-}" ]; then
    "$GOMMAGE_BIN" "$@"
  elif [ -f "$repo_root/Cargo.toml" ]; then
    (cd "$repo_root" && cargo run -q -p gommage-cli -- "$@")
  elif command -v gommage >/dev/null 2>&1; then
    gommage "$@"
  else
    echo "launch-demo: set GOMMAGE_BIN or run from a source checkout" >&2
    exit 127
  fi
}

run_capture() {
  label="$1"
  file="$2"
  shift 2
  echo "launch-demo: $label"
  if "$@" > "$capture_dir/$file" 2> "$capture_dir/$file.err"; then
    return 0
  fi
  cat "$capture_dir/$file.err" >&2
  echo "launch-demo: failed: $label" >&2
  exit 1
}

run_capture_stdin() {
  label="$1"
  file="$2"
  input="$3"
  shift 3
  echo "launch-demo: $label"
  if printf '%s' "$input" | "$@" > "$capture_dir/$file" 2> "$capture_dir/$file.err"; then
    return 0
  fi
  cat "$capture_dir/$file.err" >&2
  echo "launch-demo: failed: $label" >&2
  exit 1
}

ask_push='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}'
hard_stop='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'

run_capture "version" "version.txt" gommage_cmd --version
run_capture "preinstall harness report" "00-harness-diagnose-before.json" \
  gommage_cmd harness diagnose --json
run_capture "quickstart dry-run plan" "00-quickstart-plan.json" \
  gommage_cmd quickstart --agent claude --daemon-no-start --dry-run --json
run_capture "quickstart isolated Claude wiring" "00-quickstart.txt" \
  gommage_cmd quickstart --agent claude --daemon-no-start --self-test
run_capture "pre-audit readiness" "verify-before-audit.json" gommage_cmd verify --json
run_capture_stdin "main push asks for picto" "01-main-push-ask.json" "$ask_push" gommage_cmd mcp
run_capture "pending approval list" "02-approval-list.json" gommage_cmd approval list --json
run_capture "mint one-use picto" "03-grant-main-push.txt" \
  gommage_cmd grant --scope git.push:main --uses 1 --ttl 10m --reason "launch demo"
run_capture_stdin "main push consumes picto and allows" "04-main-push-allow.json" "$ask_push" gommage_cmd mcp
run_capture_stdin "hard-stop blocks root deletion" "05-rm-root-deny.json" "$hard_stop" gommage_cmd mcp
run_capture "signed audit verification" "06-audit-verify.json" gommage_cmd audit-verify --explain
run_capture "rebuild state index" "07-state-rebuild.json" gommage_cmd state rebuild --json
run_capture "verify state index" "08-state-verify.json" gommage_cmd state verify --json
run_capture "state counters" "09-state-stats.json" gommage_cmd state stats --json
run_capture "policy fixture contract" "10-policy-fixtures.json" \
  gommage_cmd policy test "$public_fixture" --json
run_capture "beta gate" "11-beta-check.json" \
  gommage_cmd beta check --json --agent claude --policy-test "$public_fixture"
run_capture "operator dashboard snapshot" "12-tui-snapshot.txt" \
  gommage_cmd tui --snapshot --view all

{
  echo "created_at=$timestamp"
  echo "capture_dir=$capture_dir"
  echo "home_kept=$keep_home"
  if [ "$keep_home" = "true" ]; then
    echo "temp_home=$HOME"
    echo "gommage_home=$GOMMAGE_HOME"
  fi
  echo "scenario=ask_picto -> one-use picto allow -> hard-stop deny -> signed audit -> state.sqlite -> beta check"
  echo "ask_output=$capture_dir/01-main-push-ask.json"
  echo "allow_output=$capture_dir/04-main-push-allow.json"
  echo "deny_output=$capture_dir/05-rm-root-deny.json"
  echo "audit_output=$capture_dir/06-audit-verify.json"
  echo "state_output=$capture_dir/08-state-verify.json"
  echo "beta_output=$capture_dir/11-beta-check.json"
} > "$capture_dir/summary.env"

cat > "$capture_dir/README.txt" <<'README'
Gommage launch demo evidence

Read these files in order:
1. 01-main-push-ask.json       - push to main requires git.push:main picto
2. 03-grant-main-push.txt      - operator grants a one-use picto
3. 04-main-push-allow.json     - next matching push is allowed
4. 05-rm-root-deny.json        - compiled hard-stop denies rm -rf /
5. 06-audit-verify.json        - signed audit evidence verifies offline
6. 08-state-verify.json        - state.sqlite matches audit.log
7. 11-beta-check.json          - host beta gate result
8. 12-tui-snapshot.txt         - human operator dashboard snapshot

The temporary HOME is isolated from the operator's real agent configuration.
README

echo "launch-demo: ok"
echo "launch-demo: evidence written to $capture_dir"
