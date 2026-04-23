# Examples

This directory contains repository-owned operator recipes and the public policy
fixture contract used in docs, beta gates, and CI.

## Public policy fixture library

`policy-fixtures.yaml` is the canonical example fixture file for Gommage. It
mirrors the built-in semantic smoke surfaces:

- compiled hard-stops for destructive shell commands;
- fail-closed behavior for unknown tools;
- stdlib allow and ask-picto Git behavior;
- stdlib gating for `WebFetch`;
- stdlib gating for write-like `mcp__*` tools.

Use it as:

- a starting point for repository-specific policy regression files;
- a machine-readable contract for agents and editors;
- a beta-readiness evidence file in CI and host-smoke loops.

Run it locally:

```sh
gommage policy test examples/policy-fixtures.yaml --json
gommage verify --json --policy-test examples/policy-fixtures.yaml
gommage beta check --json --policy-test examples/policy-fixtures.yaml
```

Extend it by appending snapshot-generated cases:

```sh
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' \
  | gommage policy snapshot --name ask_main_push --case-only
```

Then merge the generated case into `policy-fixtures.yaml` or into a
repository-specific fixture file kept beside your own policies.
