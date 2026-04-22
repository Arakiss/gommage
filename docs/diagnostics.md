# Diagnostics

`gommage doctor` is the operator installation health check. Use the default text output for humans and `gommage doctor --json` for scripts, installers, skills, and CI smoke tests.

`gommage smoke` is the semantic health check. It runs built-in tool-call fixtures against the active capability mappers and policy set without writing audit entries or consuming pictos. Use `gommage smoke --json` after installing policies or changing policy packs.

## Exit codes

| Status | Exit code | Meaning |
|---|---:|---|
| `ok` | 0 | The local home, key, policy, capability mappers, audit log, and daemon socket checks all passed. |
| `warn` | 0 | Gommage can operate, but one or more optional runtime paths are absent. This is expected before the first audited decision or when the daemon is not installed. |
| `fail` | 1 | A required path or contract is broken. Fix before trusting the hook. |

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
