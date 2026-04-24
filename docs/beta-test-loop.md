# Beta Test Loop

Use this checklist when testing Gommage on a real workstation. The goal is not
to prove the happy path once; it is to collect enough evidence that a new user
can install, operate, recover, and uninstall the harness without source-code
knowledge.

Run every command from a normal user shell. Keep native agent sandboxing enabled.

## 1. Install

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
  | sh -s -- --with-skill --skill-agent claude --verify

gommage --version
gommage-mcp --version
gommage-daemon --version
```

Evidence to save:

- installer output showing Sigstore and checksum verification
- versions for all three binaries
- any OS-specific cosign hint if verification cannot run

## 2. Plan Before Mutating

```sh
gommage quickstart --agent claude --daemon --dry-run --json
gommage agent status claude --json
gommage tui --snapshot --view all
gommage tui --snapshot --view onboarding
```

Evidence to save:

- quickstart JSON plan
- current host-agent status
- plain-text TUI snapshot and onboarding view

## 3. Quickstart And Verify

```sh
gommage quickstart --agent claude --daemon --self-test
gommage beta check --json --agent claude --policy-test examples/policy-fixtures.yaml
gommage verify --json
gommage smoke --json
gommage audit-verify --explain
gommage tui --watch --watch-ticks 2 --view approvals
gommage tui --stream --stream-ticks 1 --stream-limit 8
```

Expected result:

- quickstart either passes or rolls back touched agent config
- `beta check --json` is `pass` or a documented `warn`
- `verify --json` is `pass` or a documented `warn`
- `smoke --json` is `pass`
- bounded TUI watch prints two plain-text frames and no ANSI escapes
- bounded TUI stream prints recent decision/event rows and no ANSI escapes

## 4. Approval Flow

Trigger a known `ask_picto` path, then inspect and resolve it:

```sh
gommage approval list
gommage approval show <approval-id>
gommage approval replay <approval-id> --json
gommage approval evidence <approval-id> --redact --output approval-evidence.json
gommage tui --snapshot --view approvals
gommage approval approve <approval-id> --ttl 10m --uses 1 --json
gommage audit-verify --explain
```

Interactive check:

```sh
gommage tui --view approvals
```

In the approvals view, use `t/T` to change TTL, `u/U` to change uses, `A` or
`D` to stage resolution, and `y` or `n` to confirm or cancel.

Evidence to save:

- approval replay JSON
- redacted evidence bundle
- audit verification after resolution
- note whether the TUI controls were clear without reading source

## 5. Webhook Dry Runs

```sh
gommage approval webhook --url "https://approval.example.invalid/hook" --dry-run --json
gommage approval webhook --url "https://approval.example.invalid/hook" \
  --dry-run --json \
  --signing-secret "local-test-secret" \
  --signing-key-id "local-test"
gommage approval webhook --provider slack --url "https://approval.example.invalid/slack" --dry-run --json
gommage approval webhook --provider discord --url "https://approval.example.invalid/discord" --dry-run --json
gommage approval template --provider ntfy --json
```

Evidence to save:

- generic JSON payload shape from `requests[].payload`
- signed generic body from `requests[].body` and signature headers from
  `requests[].signature.headers`
- Slack payload shape from `requests[].payload`
- Discord payload shape from `requests[].payload`
- if you also exercise a failing endpoint, `gommage approval dlq --json`
  showing the dead-lettered delivery after retries are exhausted
- ntfy template output

## 6. Recovery And Uninstall

```sh
gommage report bundle --redact --output gommage-report.json
gommage repair agent claude --dry-run
gommage repair agent codex --dry-run
gommage uninstall --all --restore-backup --purge-backups --dry-run
gommage uninstall --all --restore-backup --purge-backups --yes
gommage agent status claude --json
```

Expected result:

- dry-run lists every touched surface before removal
- uninstall restores agent config backups before removing runtime state
- no Gommage hook remains in host config unless another install intentionally
  recreated it

## Report Template

When filing beta feedback, include:

- OS and version
- shell
- agent and version
- install command used
- `gommage --version`
- failed command and exit code
- relevant redacted output or support bundle
- whether `gommage uninstall --all --restore-backup --dry-run` produced a
  complete rollback plan
