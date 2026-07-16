# Pictos

A **picto** is a signed grant that converts an `ask_picto` decision into an
`allow`. It is the normal scoped authorization mechanism for an ask without
editing policy on disk. `GOMMAGE_BYPASS=1` is a separate recovery path that
skips normal policy evaluation for non-compiled-hard-stop calls; it is not a
picto and must not be treated as one.

## Properties

- **Scope.** Exact string match against the `required_scope` of the policy rule.
  No wildcards. Scopes are non-empty ASCII bytes `0x21..=0x7e` (no spaces) and
  at most 512 bytes; policy loading rejects a scope that the Picto store could
  not mint.
- **Optional input binding.** A rule with `bind_input: true` requires the same
  canonical `ToolCall::input_hash` as well as the exact scope. A scope-only
  picto cannot satisfy such a rule.
- **TTL.** Mandatory. Max 24 h. No ambient, long-lived grants.
- **`max_uses`.** Mandatory. Consumed atomically; once spent, the picto transitions to `spent` and cannot be revived.
- **Signature.** ed25519 over the current unversioned, newline-delimited payload
  containing `id`, `scope`, `max_uses`, expiry, creation time, and `reason`,
  using the daemon's keypair. For an input-bound picto, the canonical input hash
  is also signed. Gommage verifies this payload before lookup and consumption.
- **Canonical v1 domain.** `id` and `scope` must contain only visible ASCII
  bytes `0x21..=0x7e`; `id`, `scope`, and `reason` reject control characters,
  Unicode line separators, and the Unicode `Bidi_Control` set.
  Timestamps must be UTC at whole-second precision. UTF-8 byte lengths are
  capped at 128 for `id`, 512 for `scope`, and 4,096 for `reason`; lifetime must be
  1–86,400 seconds; `max_uses` must be positive; an optional input hash must be
  canonical `sha256:<lowercase-hex>`; and the signature must use canonical
  unpadded Base64 and pass strict Ed25519 verification. Signing and verification
  apply the same checks, so delimiter injection, representation malleability,
  and input-bound-to-scope-only row mutation fail closed.
- **Revocable.** `gommage revoke <id>` marks the picto revoked in O(1). Audit log records the revocation.
- **`--require-confirmation`.** Optional. Picto is created in `pending_confirmation`; must be activated via `gommage confirm <id>` (e.g., by a second human) before first use.

## Approval requests

When an `ask_picto` rule matches and no usable picto exists, Gommage creates a
durable approval request in `~/.gommage/approvals.jsonl` and writes a signed
`approval_requested` audit event. The request ID is deterministic for the tuple
`(input_hash, required_scope, bind_input, policy_version)`, so repeating the
same blocked tool call does not spam duplicate pending requests. If a previous
request for that same tuple was already approved or denied, the next matching
ask opens a new suffixed request ID instead of reviving resolved state.

Human approval is explicit:

```sh
gommage approval list
gommage approval show <approval-id>
gommage approval replay <approval-id>
gommage approval evidence <approval-id> --redact --output approval-evidence.json
gommage approval approve <approval-id> --ttl 10m --uses 1
```

Approval mints a scope-only picto for a normal request. It authorizes any call
that matches that exact scope; it is not tied to the input hash shown on the
approval request. Every matching call consumes one use, including a diagnostic
or probe call, so a one-use approval must be followed directly by the intended
retry. When the matching policy rule has `bind_input: true`, approval mints an
exact-input picto instead; only the same canonical tool input can consume it,
and each matching retry still consumes one use. The version 2 JSON action report
exposes this as `picto.kind: "scope_only" | "exact_input"`, together with
`picto.authorizes`, `picto.consumption`, `picto.matching_call_consumes_use`,
`picto.non_matching_call_consumes_use`, and the compatibility field
`picto.input_bound`. The default approval output is a plain
operator summary; add `--json` for the stable agent contract with request,
scope, picto, TTL, uses, and `next_action` fields. A human can deny instead:

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

Interactive TUI approval is intentionally two-step. The approval workbench
shows the tool, scope, scope-only versus exact-input boundary, policy reason,
and chosen TTL/use grant before any forensic detail. Operators can use `t/T`
to cycle TTL presets, `u/U` to cycle use-count presets, `i` to reveal
technical request context, then `A` or `D` to stage the selected pending
request. `y` is required before Gommage mints a picto or records a denial.
Snapshot and bounded watch modes are read-only and include selected-request
detail plus replay/evidence commands for support.

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

Webhook payloads also include a callback envelope:

```json
{
  "bind_input": true,
  "callback": {
    "kind": "gommage_approval_callback",
    "request_id": "apr_...",
    "nonce": "nonce_...",
    "actions": ["approve", "deny"]
  }
}
```

The generic payload exposes `bind_input` so an approval receiver can show
whether approval covers the scope or the exact observed tool input.

The nonce is bound to the pending request id, input hash, required scope,
policy version, and whether the request requires input binding. A remote
approval provider must echo that nonce in a signed callback body:

```json
{
  "kind": "gommage_approval_callback",
  "request_id": "apr_...",
  "action": "approve",
  "nonce": "nonce_...",
  "reason": "reviewed in Slack",
  "ttl": 600,
  "uses": 1
}
```

Gommage verifies the HMAC signature, timestamp freshness, pending request
state, nonce, and binding mode before delegating to the same local approve/deny
path used by the CLI and TUI:

```sh
gommage approval callback \
  --body callback.json \
  --signature "$X_GOMMAGE_SIGNATURE" \
  --timestamp "$X_GOMMAGE_SIGNATURE_TIMESTAMP" \
  --signing-secret "$GOMMAGE_APPROVAL_CALLBACK_SECRET" \
  --dry-run \
  --json
```

Callback processing is local. The receiver supplies the exact callback body,
signature, and timestamp to `gommage approval callback`; Gommage does not run an
inbound HTTP listener or make a remote provider an authorization authority by
itself.

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

## Exact-input grants

Use input binding when approval must cover one exact observed tool call instead
of any call in a policy scope:

```yaml
- name: gate-reviewed-deploy
  decision: ask_picto
  required_scope: "deploy.example:production"
  bind_input: true
  match:
    any_capability:
      - "deploy.example:production"
  reason: "production deploy requires approval of the exact request"
```

`bind_input` defaults to `false` and is valid only with `decision: ask_picto`.
Existing picto rows and direct `gommage grant --scope …` grants remain
scope-only. To mint an exact-input picto, approve the pending request created by
an input-bound rule. A database opened by a newer Gommage version retains old
scope-only pictos; they cannot unlock an input-bound rule.

## Current v1 authority limits

Picto v1 is designed for a trusted operator account, not for resistance to a
hostile process under that same UID:

- The signature does not cover the mutable `uses` or `status` columns. The
  SQLite transaction checks and updates them atomically during normal
  consumption, but a same-UID process that can edit `pictos.sqlite` is inside
  the trusted computing base.
- The signing payload is newline-delimited text rather than a versioned
  canonical structured encoding. Fields are signed, but the payload has no
  encoded schema version or typed field tags. The canonical v1 domain above
  excludes delimiters and malformed encodings so the current field boundaries
  remain unambiguous; a future authority format still needs explicit
  versioning.
- `approvals.jsonl` is unsigned operational state. Request and resolution
  lifecycle events are also written to the signed audit log, but approval JSONL,
  Picto SQLite mutation, and audit append are separate operations rather than
  one atomic authority transaction.
- The same user-owned `key.ed25519` signs both Pictos and audit records. A
  same-UID compromise can read or replace it and forge both kinds of evidence.
- Scope-only Pictos intentionally authorize any call that reaches the same
  `required_scope` until their TTL/use budget is exhausted. Use
  `bind_input: true` when approval is meant for one canonical tool call.

These are documented beta limits, not properties of a shipped managed reference
mode. Keep host sandboxing and native permissions enabled, and do not describe
user-mode Pictos as tamper-resistant against the operator UID.

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
