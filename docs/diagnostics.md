# Diagnostics

`gommage verify` is the default readiness gate for scripts, installers, skills, and CI smoke tests. It aggregates `doctor`, built-in semantic `smoke`, and optional repository policy fixtures into one report.

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
status, verified-entry count, key fingerprint, policy-version list, expedition
list, and anomaly list.

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
gommage verify --json
gommage verify --json --policy-test examples/policy-fixtures.yaml
```

The JSON report includes top-level `status`, `summary`, `doctor`, `smoke`, and
`policy_tests`. Use the nested reports for the exact failing check, emitted
capabilities, matched rule, and mismatch errors.

Audit verification has its own forensic JSON contract:

```sh
gommage audit-verify --explain
gommage audit-verify --explain --format human
```

The JSON form is stable for agents. The human form is intentionally optimized
for review and should not be parsed by automation.

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
