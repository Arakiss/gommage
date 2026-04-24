#!/usr/bin/env sh
# Verify that agent-facing documentation lists commands accepted by this binary.

set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export GOMMAGE_HOME="$tmp/.gommage"
export GOMMAGE_CLAUDE_SETTINGS="$tmp/claude/settings.json"
export GOMMAGE_CODEX_HOOKS="$tmp/codex/hooks.json"
export GOMMAGE_CODEX_CONFIG="$tmp/codex/config.toml"
export GOMMAGE_SYSTEMD_USER_DIR="$tmp/systemd-user"
export GOMMAGE_CONTRACT_REPORT="$tmp/report-bundle.json"
export GOMMAGE_CONTRACT_REPLAY_AUDIT="$tmp/replay-audit.log"
export GOMMAGE_CONTRACT_REPLAY_POLICY="$tmp/replay-policy.d"
mkdir -p "$(dirname "$GOMMAGE_CLAUDE_SETTINGS")" "$(dirname "$GOMMAGE_CODEX_HOOKS")"
mkdir -p "$GOMMAGE_CONTRACT_REPLAY_POLICY"
printf '{"permissions":{"allow":["Bash","Read(./docs/**)"],"deny":["Read(./secrets/**)"]}}\n' > "$GOMMAGE_CLAUDE_SETTINGS"
printf 'sandbox_mode = "workspace-write"\n[features]\n' > "$GOMMAGE_CODEX_CONFIG"
cat > "$GOMMAGE_CONTRACT_REPLAY_POLICY/10-contract.yaml" <<'EOF'
- name: allow-contract-status
  decision: allow
  match:
    any_capability: ["proc.exec:git status"]
  reason: "contract fixture"
EOF
cat > "$GOMMAGE_CONTRACT_REPLAY_AUDIT" <<'EOF'
{"v":1,"id":"contract_audit","ts":"2026-04-24T00:00:00Z","tool":"Bash","input_hash":"sha256:contract","capabilities":["proc.exec:git status"],"decision":{"kind":"allow"},"matched_rule":{"name":"allow-contract-status","file":"old.yaml","index":0},"policy_version":"sha256:old","expedition":null,"sig":"ed25519:test"}
EOF

gommage_cmd() {
  if [ -n "${GOMMAGE_BIN:-}" ]; then
    "$GOMMAGE_BIN" "$@"
  else
    cargo run -q -p gommage-cli -- "$@"
  fi
}

run_manifest_command() {
  label="$1"
  stdin_json="$2"
  shift
  shift
  printf 'contract: %s\n' "$label"
  if [ -n "$stdin_json" ]; then
    printf '%s' "$stdin_json" | gommage_cmd "$@" >/dev/null
  else
    gommage_cmd "$@" >/dev/null
  fi
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to read docs/agent-command-manifest.json" >&2
  exit 1
fi

python3 - docs/agent-command-manifest.json > "$tmp/manifest-runner.sh" <<'PY'
import json
import os
import shlex
import sys

manifest_path = sys.argv[1]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

for command in manifest["commands"]:
    argv = [
        os.environ["GOMMAGE_CONTRACT_REPORT"] if arg == "{report_bundle}"
        else os.environ["GOMMAGE_CONTRACT_REPLAY_AUDIT"] if arg == "{replay_audit}"
        else os.environ["GOMMAGE_CONTRACT_REPLAY_POLICY"] if arg == "{replay_policy}"
        else arg
        for arg in command["argv"]
    ]
    stdin_json = ""
    if command.get("stdin_mode") == "json":
        stdin_json = json.dumps(command["stdin_json"], separators=(",", ":"))
    parts = ["run_manifest_command", command["id"], stdin_json, *argv]
    print(" ".join(shlex.quote(part) for part in parts))
PY

# shellcheck source=/dev/null
. "$tmp/manifest-runner.sh"

printf 'contract: ok\n'
