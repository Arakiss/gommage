# Diagnostics

`gommage verify` is the default readiness gate for scripts, installers, skills, and CI smoke tests. It aggregates `doctor`, built-in semantic `smoke`, and optional repository policy fixtures into one report.

`gommage tui` is the operator dashboard for humans. It renders the same
high-level readiness model as `verify`, plus host-agent status, pending
approvals, policy inventory, audit state, capability mapper state, recovery
shortcuts, and next actions. Snapshot mode never mutates `GOMMAGE_HOME`; use it
when a terminal is non-interactive, when filing an issue, or when an agent needs
to capture a human-readable report without ANSI control sequences. Automation
should still parse the JSON commands below instead of the TUI.

`gommage tui --view dashboard|approvals|policies|audit|capabilities|recovery|all`
selects operator views. `--view all` is the most useful issue-report snapshot:
it includes readiness, pending approvals, policy inventory, signed audit
summary, mapper inventory, and recovery shortcuts. `gommage tui --watch` prints
the same report repeatedly as plain text; use `--watch-ticks <n>` to bound demos,
CI artifacts, and issue-report captures. `gommage tui --stream` prints a compact
live decision/event feed using daemon IPC when the daemon is reachable and the
signed audit log otherwise. Interactive mode switches views with `1`-`6`. In the
approvals view, `t/T` changes the TTL preset, `u/U` changes the use-count preset,
and `A` / `D` stage an approve/deny action for the selected request. `y` is
still required before mutating state.
The README embeds a sanitized animated demo at `docs/assets/tui-dashboard.gif`
and keeps `docs/assets/tui-dashboard.svg` as a static fallback; update both
assets whenever the TUI's primary sections or vocabulary change.

`gommage doctor` is the lower-level operator installation health check. Use the default text output for humans and `gommage doctor --json` when you need only filesystem/runtime diagnostics.

`gommage agent status <claude|codex>` is the host-agent integration check. Use
`--json` when an installer, skill, or CI script needs to prove that the host
hook is actually wired, that generated Claude native-permission imports are
present when applicable, and that Codex hooks are enabled.

`gommage smoke` is the semantic health check. It runs built-in tool-call fixtures against the active capability mappers and policy set without writing audit entries or consuming pictos. Use `gommage smoke --json` after installing policies or changing policy packs.

`gommage policy test <file>` is the project-owned semantic regression runner. It reads YAML fixtures, evaluates them against the active capability mappers and policy set, and exits non-zero when any expected decision changes.

`gommage audit-verify --explain` is the signed audit forensic report. The
default format is JSON for agent and CI automation. Use
`gommage audit-verify --explain --format human` when a person needs a compact
status, verified-entry count, key fingerprint, bypass counters,
policy-version list, expedition list, and anomaly list.

## Exit codes

| Status | Exit code | Meaning |
|---|---:|---|
| `ok` | 0 | The local home, key, policy, capability mappers, audit log, and daemon socket checks all passed. |
| `warn` | 0 | Gommage can operate, but one or more optional runtime paths are absent. This is expected before the first audited decision or when the daemon is not installed. |
| `fail` | 1 | A required path or contract is broken. Fix before trusting the hook. |

`verify` uses `pass`, `warn`, and `fail`:

| Status | Exit code | Meaning |
|---|---:|---|
| `pass` | 0 | Doctor has no warnings, smoke passed, and every requested policy fixture passed. |
| `warn` | 0 | No hard failure, but doctor reported an operational warning such as a missing first audit log or daemon socket. |
| `fail` | 1 | Doctor failed, smoke failed, or at least one requested policy fixture failed. |

Run the aggregated gate with:

```sh
gommage tui
gommage tui --snapshot --view all
gommage tui --watch --watch-ticks 3 --view approvals
gommage tui --stream --stream-ticks 5
gommage verify --json
gommage verify --json --policy-test examples/policy-fixtures.yaml
```

The JSON report includes top-level `status`, `summary`, `doctor`, `smoke`, and
`policy_tests`. Use the nested reports for the exact failing check, emitted
capabilities, matched rule, and mismatch errors.

`gommage quickstart --self-test` runs the same readiness gate after setup:

```sh
gommage quickstart --agent claude --daemon --self-test
gommage quickstart --agent codex --daemon --self-test
```

With `--dry-run`, self-test prints the planned verification step without
creating `GOMMAGE_HOME` or writing host-agent config:

```sh
gommage quickstart --agent claude --self-test --dry-run
```

Audit verification has its own forensic JSON contract:

```sh
gommage audit-verify --explain
gommage audit-verify --explain --format human
```

The JSON form is stable for agents and uses the same operator vocabulary as the
human form: `policy_versions`, `expeditions`, `bypass_activations`, and
`hard_stop_bypass_attempts`. The human form is intentionally optimized for
review and should not be parsed by automation.

Agent integration status is separate because it reads host config, not the
Gommage home health model:

```sh
gommage agent status claude --json
gommage agent status codex --json
```

The JSON report includes `agent`, top-level `status`, `summary`, and `checks`.
Claude checks cover the settings file, `PreToolUse` hook group, generated deny
imports, and generated narrow allow imports. Codex checks cover `hooks.json`,
`config.toml`, the `PreToolUse` hook group, `features.codex_hooks`, and the
configured sandbox mode. A missing hook or disabled hook feature is `fail`; a
dangerous Codex sandbox is `warn` because Gommage currently governs only the
Bash hook surface under Codex.

## Approval diagnostics

When a policy returns `ask_picto` and no usable signed picto exists, Gommage
records a pending approval request under `~/.gommage/approvals.jsonl`, writes a
signed `approval_requested` audit event, and returns an `ask` reason containing
the exact approval command.

Use these commands for operator triage:

```sh
gommage approval list
gommage approval list --json
gommage approval list --status all --json
gommage approval show <approval-id>
gommage approval replay <approval-id> --json
gommage approval evidence <approval-id> --redact --output approval-evidence.json
gommage approval approve <approval-id> --ttl 10m --uses 1
gommage approval deny <approval-id> --reason "not enough context"
gommage approval webhook --url "$GOMMAGE_APPROVAL_WEBHOOK_URL" --dry-run
gommage approval webhook --url "$GOMMAGE_APPROVAL_WEBHOOK_URL" \
  --signing-secret "$GOMMAGE_APPROVAL_WEBHOOK_SECRET" \
  --signing-key-id "operator-prod"
gommage approval webhook --provider slack --url "$SLACK_WEBHOOK_URL" --dry-run
gommage approval webhook --provider discord --url "$DISCORD_WEBHOOK_URL" --dry-run
gommage approval template --provider ntfy
```

`approval list` defaults to pending work. Use `--status all` when reviewing
historical approved or denied requests. JSON list output keeps the nested
`request` object and also exposes top-level `id`, `created_at`, `tool`, and
`required_scope` fields for simple `jq` queries.

Approving a request mints an exact-scope picto and writes signed
`picto_created` plus `approval_resolved` events. Denying a request writes a
signed `approval_resolved` event with `status: denied`. Webhook delivery is
best-effort: failures are signed as `approval_webhook_failed`, but never change
the permission decision. Dry-run JSON includes the provider-shaped request body
at `requests[].payload`, so endpoint payloads can be inspected without sending.
When `--signing-secret` or `GOMMAGE_APPROVAL_WEBHOOK_SECRET` is set, Gommage
also includes `requests[].body` and `requests[].signature` in dry-run JSON and
sends `x-gommage-signature-*` headers on real delivery. The signature is
`HMAC-SHA256(secret, timestamp + "." + raw_http_body)` and covers the exact
bytes sent to the receiver. Audit events store only non-secret signature
metadata: algorithm, optional key id, timestamp, body SHA-256, and a signature
prefix.
Replay compares the stored request capabilities against the current policy;
evidence bundles collect request state, relevant signed audit lines,
verification summary, and next commands for issue reports.
`gommage tui --snapshot --view approvals` includes selected-request detail and
the same replay/evidence commands. Bounded watch mode is useful when an operator
or agent wants to capture the inbox changing without driving the interactive
TUI:

```sh
gommage tui --watch --watch-ticks 3 --view approvals
```

## JSON shape

The JSON report is intentionally flat so shell scripts can inspect it without understanding the policy engine:

```json
{
  "status": "warn",
  "home": "/Users/alice/.gommage",
  "summary": {
    "failures": 0,
    "warnings": 2
  },
  "checks": [
    {
      "name": "policy",
      "status": "ok",
      "message": "35 rules (sha256:...)",
      "details": {
        "path": "/Users/alice/.gommage/policy.d",
        "rules": 35,
        "version": "sha256:..."
      }
    }
  ]
}
```

Every check has:

- `name`: stable check identifier.
- `status`: `ok`, `warn`, or `fail`.
- `message`: short human-readable summary.
- `details`: optional structured context, usually paths or counts.

## Checks

| Check | Required | Notes |
|---|---:|---|
| `home` | yes | Gommage home exists. Defaults to `~/.gommage` unless `GOMMAGE_HOME` or `--home` is set. |
| `policy_dir` | yes | Contains YAML policy files. Empty policy sets are valid but fail closed. |
| `capabilities_dir` | yes | Contains YAML mapper files that translate tool calls into capabilities. |
| `key` | yes | `key.ed25519` is present and loadable. |
| `expedition` | yes | Missing expedition state is normal; corrupt expedition JSON is a failure. |
| `policy` | yes | Policy files parse, expand variables, and produce a deterministic version hash. |
| `capabilities` | yes | Capability mapper files parse successfully. |
| `audit` | no | Missing audit log is a warning before the first audited decision. Existing logs must verify. |
| `daemon` | no | Missing socket is a warning because the MCP adapter can use the audited in-process fallback. |

## Fresh install expectation

After `gommage quickstart --agent claude --daemon` or `gommage quickstart --agent codex --daemon`, this is healthy:

```sh
gommage doctor --json
```

Expect top-level `status: "warn"` until either:

- a decision has been audited, creating `audit.log`; and
- `gommage daemon install` has started the user-level daemon.

Treat any `fail` check as a setup error. For example, `policy` failures usually mean a malformed YAML rule under `~/.gommage/policy.d/`, while `capabilities` failures point to a malformed mapper under `~/.gommage/capabilities.d/`.

## Semantic smoke test

After the policy files and capability mappers are installed, run:

```sh
gommage smoke --json
```

The report has a top-level `status`:

| Status | Exit code | Meaning |
|---|---:|---|
| `pass` | 0 | Every built-in semantic fixture produced the expected decision. |
| `fail` | 1 | At least one fixture produced an unexpected decision. Do not trust the hook until the policy or mapper change is understood. |

The built-in fixtures cover:

- compiled hard-stop behavior for destructive shell commands;
- fail-closed behavior for unmapped shell commands;
- stdlib allow and ask-picto behavior for Git pushes;
- stdlib web-tool gating for `WebFetch`;
- stdlib MCP gating for write-like `mcp__*` tools.

Each check includes the tool call, canonical `input_hash`, emitted
capabilities, matched rule, expected decision, and actual decision. This makes
`smoke --json` suitable for installer verification, CI images, and agent skills
that need to prove semantic readiness instead of only checking that files exist.

## Policy regression fixtures

Use `policy test` when a repository wants to lock down its own policy behavior:

```yaml
version: 1
cases:
  - name: main_push_requires_picto
    description: Pushes to main should require a signed git.push:main picto.
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: ask_picto
      required_scope: git.push:main
      matched_rule: gate-main-push
```

Run it locally or in CI:

```sh
gommage policy test examples/policy-fixtures.yaml
gommage policy test examples/policy-fixtures.yaml --json
```

Export the fixture contract for editors, agents, and CI generators:

```sh
gommage policy schema > gommage-policy-fixture.schema.json
```

To create the first fixture from a real observed tool call, pipe the same
`ToolCall` JSON shape used by `gommage decide` into `policy snapshot`:

```sh
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' \
  | gommage policy snapshot --name main_push_requires_picto \
  > examples/policy-fixtures.yaml
```

Use `--case-only` when appending the generated case list to an existing fixture
file.

When the question is "what did the mapper emit?" rather than "what decision did
the policy make?", inspect the mapper directly:

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | gommage map --json --hook
```

`gommage map` loads only `capabilities.d/`. It does not load policy files, read
pictos, talk to the daemon, or write audit entries. Use it before writing a new
rule, when debugging mapper coverage, or when an agent needs to propose a
fixture from observed tool traffic. `gommage map`, `gommage decide`, and
`gommage policy snapshot` accept canonical `ToolCall` JSON by default; add
`--hook` when stdin is the actual PreToolUse payload with `tool_name`,
`tool_input`, and optional `cwd`.

The fixture file may be either a mapping with `version: 1` and `cases`, or a
top-level YAML list of cases. Each case supports:

| Field | Required | Meaning |
|---|---:|---|
| `name` | yes | Stable case identifier for humans, agents, and CI logs. |
| `description` | no | Human context for why the behavior matters. |
| `tool` | yes | Agent tool name, for example `Bash`, `WebFetch`, or `mcp__github__create_issue`. |
| `input` | no | Tool input object. Defaults to `{}`. |
| `expect.decision` | yes | One of `allow`, `gommage`, or `ask_picto`. |
| `expect.hard_stop` | no | Expected `gommage` hard-stop boolean. |
| `expect.required_scope` | no | Expected ask-picto scope. |
| `expect.matched_rule` | no | Expected matched policy rule name. |

The JSON report has top-level `status: "pass" | "fail"`, `policy_version`,
`mapper_rules`, `summary`, and per-case `capabilities`, `matched_rule`,
`actual`, `expected`, and `errors`. Treat `fail` as a policy regression until
the policy or mapper change is reviewed.

`gommage policy schema` prints the official JSON Schema for the fixture file
contract. The schema covers both accepted fixture shapes: a mapping with
`version: 1` plus `cases`, or a top-level list of cases. Use it before
`policy test` when an agent generates fixture YAML or when an editor needs
completion and validation.
