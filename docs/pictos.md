# Pictos

A **picto** is a signed grant that converts an `ask_picto` decision into an `allow`. It is the only mechanism in Gommage that authorizes an otherwise-denied action without editing policy on disk.

## Properties

- **Scope.** Exact string match against the `required_scope` of the policy rule. No wildcards.
- **TTL.** Mandatory. Max 24 h. No ambient, long-lived grants.
- **`max_uses`.** Mandatory. Consumed atomically; once spent, the picto transitions to `spent` and cannot be revived.
- **Signature.** ed25519 over `{id, scope, max_uses, ttl, created_at, reason}` using the daemon's keypair. Gommage verifies the signature before lookup/consume can turn an `ask_picto` into `allow`, so a tampered SQLite row is rejected and audited.
- **Revocable.** `gommage revoke <id>` marks the picto revoked in O(1). Audit log records the revocation.
- **`--require-confirmation`.** Optional. Picto is created in `pending_confirmation`; must be activated via `gommage confirm <id>` (e.g., by a second human) before first use.

## Approval requests

When an `ask_picto` rule matches and no usable picto exists, Gommage creates a
durable approval request in `~/.gommage/approvals.jsonl` and writes a signed
`approval_requested` audit event. The request ID is deterministic for the tuple
`(input_hash, required_scope, policy_version)`, so repeating the same blocked
tool call does not spam duplicate pending requests. If a previous request for
that same tuple was already approved or denied, the next matching ask opens a
new suffixed request ID instead of reviving resolved state.

Human approval is explicit:

```sh
gommage approval list
gommage approval show <approval-id>
gommage approval replay <approval-id>
gommage approval evidence <approval-id> --redact --output approval-evidence.json
gommage approval approve <approval-id> --ttl 10m --uses 1
```

Approval mints an exact-scope picto for the request's `required_scope`; the next
matching tool call consumes that picto and writes `picto_consumed`. A human can
deny instead:

```sh
gommage approval deny <approval-id> --reason "not enough context"
```

The operator TUI exposes the same inbox:

```sh
gommage tui --view approvals
gommage tui --snapshot --view approvals
gommage tui --watch --watch-ticks 3 --view approvals
gommage tui --stream --stream-ticks 5
```

Interactive TUI approval is intentionally two-step. Operators can use `t/T` to
cycle TTL presets and `u/U` to cycle use-count presets, then `A` or `D` stages
the selected pending request. `y` is required before Gommage mints a picto or
records a denial. Snapshot and bounded watch modes are read-only and include
selected-request detail plus replay/evidence commands for support.

Replay and evidence commands are for debugging and support. Replay evaluates the
stored request capabilities against the current policy, so an operator can see
whether the policy still asks for the same scope, now allows, now denies, or now
hard-stops. Evidence bundles are redacted JSON support artifacts containing
request state, relevant signed audit lines, audit verification summary, and next
commands.

Generic webhook delivery is available without changing the decision path:

```sh
gommage approval webhook --url "$GOMMAGE_APPROVAL_WEBHOOK_URL" \
  --attempts 3 \
  --backoff-ms 250 \
  --signing-secret "$GOMMAGE_APPROVAL_WEBHOOK_SECRET"
```

The generic JSON payload is the stable automation contract. `--signing-secret`
adds `x-gommage-signature-*` headers. The signed canonical string is:

```text
<x-gommage-signature-timestamp> + "." + <exact HTTP body bytes>
```

The signature value is `v1=<hex HMAC-SHA256>`. Audit events keep only
non-secret signature metadata for receiver-side correlation. Slack and Discord
incoming webhook payloads are available as presentation formats:

```sh
gommage approval webhook --provider slack --url "$SLACK_WEBHOOK_URL"
gommage approval webhook --provider discord --url "$DISCORD_WEBHOOK_URL"
gommage approval template --provider ntfy
```

Dry-run JSON includes the shaped request body in `requests[].payload` for each
pending approval. That makes generic, Slack, and Discord payloads inspectable
without network delivery, and keeps endpoint tests composable with tools like
`jq` and `curl`.

Real delivery uses bounded retries. When all attempts fail, Gommage keeps the
permission decision as `ask`, appends a dead-letter entry to
`~/.gommage/approval-webhook-dlq.jsonl`, and exposes it through:

```sh
gommage approval dlq --json
```

Receiver verification must use the timestamp and body exactly as delivered:

```python
import hashlib
import hmac

def valid_gommage_signature(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    canonical = timestamp.encode() + b"." + body
    digest = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"v1={digest}", signature)
```

```js
import crypto from "node:crypto";

export function validGommageSignature(secret, timestamp, body, signature) {
  const canonical = Buffer.concat([Buffer.from(timestamp), Buffer.from("."), Buffer.from(body)]);
  const digest = crypto.createHmac("sha256", secret).update(canonical).digest("hex");
  const expected = Buffer.from(`v1=${digest}`);
  const received = Buffer.from(signature);
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}
```

Slack incoming webhooks accept JSON with `text` and optional `blocks`; Discord
incoming webhooks accept JSON `content` and optional `embeds`; ntfy JSON
publishing posts to the server root URL with a `topic`, so Gommage documents an
ntfy template but does not send ntfy directly yet.

If `GOMMAGE_APPROVAL_WEBHOOK_URL` is set in the hook environment, daemon and
MCP fallback paths attempt best-effort webhook delivery at request time. Delivery
success/failure is signed in audit when a home/key exists, including
dead-lettered failures after retries are exhausted. A webhook outage never turns
`ask` into `allow`.

## Lifecycle

```
                 ┌─────────────────────┐
                 │ gommage grant       │
                 └─────────┬───────────┘
                           ▼
              (if --require-confirmation)
           ┌─────────────────────────────┐
           │   pending_confirmation      │
           └───────────┬─────────────────┘
                       │
               gommage confirm <id>
                       ▼
           ┌─────────────────────────────┐
           │         active              │─── ttl passes ───► expired
           └───────────┬─────────────────┘
                       │
                consume (uses++)
                       ▼
              uses == max_uses
                       │
                       ▼
           ┌─────────────────────────────┐
           │          spent              │
           └─────────────────────────────┘

         (at any time)  gommage revoke ──► revoked
```

## Why exact-match scopes

In an early draft, pictos matched on a glob against the rule's `required_scope`. We dropped this for v0.1 because:

1. **Over-broad pictos are the #1 failure mode of every break-glass system.** A picto that says `git.push:*` looks convenient until the day it authorizes a push to `main` you did not intend.
2. **Friction is a feature.** If you find yourself minting three pictos to do one task, that is signal: either the scope granularity in policy is wrong, or the work should be broken up.
3. **V1.0 can add hierarchical wildcards** (e.g. `git.push:release/*`) as an opt-in, not a default.

## Why TTL is capped at 24 h

Any secret-equivalent artifact with an unbounded lifetime eventually becomes a secret-equivalent artifact you forgot you had. The 24 h cap is a forcing function: if you need something for longer, make a policy change in `policy.d/` and review it in a PR — that is the reviewable path.

## Storage

`~/.gommage/pictos.sqlite`. WAL mode. Owner-only permissions inherited from `~/.gommage/`.

## Audit

Picto lifecycle events that mutate authorization state (create, confirm,
consume, revoke, bad-signature rejection), approval request/resolution events,
and approval webhook delivery outcomes are written as signed audit event lines.
Webhook delivery events include non-secret HMAC metadata when a signing secret
was configured.
TTL expiration is enforced at lookup/consume time; expired rows can be swept
separately without being required for a decision.
