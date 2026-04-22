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
mkdir -p "$(dirname "$GOMMAGE_CLAUDE_SETTINGS")" "$(dirname "$GOMMAGE_CODEX_HOOKS")"
printf '{"permissions":{"allow":["Bash","Read(./docs/**)"],"deny":["Read(./secrets/**)"]}}\n' > "$GOMMAGE_CLAUDE_SETTINGS"
printf 'sandbox_mode = "workspace-write"\n[features]\n' > "$GOMMAGE_CODEX_CONFIG"

gommage_cmd() {
  if [ -n "${GOMMAGE_BIN:-}" ]; then
    "$GOMMAGE_BIN" "$@"
  else
    cargo run -q -p gommage-cli -- "$@"
  fi
}

check() {
  label="$1"
  shift
  printf 'contract: %s\n' "$label"
  "$@" >/dev/null
}

check "init" gommage_cmd init
check "policy init" gommage_cmd policy init --stdlib
check "quickstart claude" gommage_cmd quickstart --agent claude --no-self-test
check "agent install codex" gommage_cmd agent install codex

check "verify json" gommage_cmd verify --json
check "verify policy fixtures" gommage_cmd verify --json --policy-test examples/policy-fixtures.yaml
check "doctor json" gommage_cmd doctor --json
check "agent status claude" gommage_cmd agent status claude --json
check "agent status codex" gommage_cmd agent status codex --json
check "smoke json" gommage_cmd smoke --json
check "policy schema" gommage_cmd policy schema
check "policy check" gommage_cmd policy check
check "policy test" gommage_cmd policy test examples/policy-fixtures.yaml --json

printf '%s' '{"tool":"Bash","input":{"command":"git push --force origin main"}}' \
  | check "map json" gommage_cmd map --json
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | check "map hook json" gommage_cmd map --json --hook

check "grant creates audit event" gommage_cmd grant --scope test.contract --uses 1 --ttl 60 --reason contract
check "audit verify explain" gommage_cmd audit-verify --explain
check "agent uninstall dry-run" gommage_cmd agent uninstall all --restore-backup --dry-run
check "uninstall dry-run" gommage_cmd uninstall --all --dry-run --daemon-manager systemd

printf 'contract: ok\n'
