# Pictos

A **picto** is a signed grant that converts an `ask_picto` decision into an `allow`. It is the only mechanism in Gommage that authorizes an otherwise-denied action without editing policy on disk.

## Properties

- **Scope.** Exact string match against the `required_scope` of the policy rule. No wildcards.
- **TTL.** Mandatory. Max 24 h. No ambient, long-lived grants.
- **`max_uses`.** Mandatory. Consumed atomically; once spent, the picto transitions to `spent` and cannot be revived.
- **Signature.** ed25519 over `{id, scope, max_uses, ttl, created_at, reason}` using the daemon's keypair. Gommage verifies the signature before lookup/consume can turn an `ask_picto` into `allow`, so a tampered SQLite row is rejected and audited.
- **Revocable.** `gommage revoke <id>` marks the picto revoked in O(1). Audit log records the revocation.
- **`--require-confirmation`.** Optional. Picto is created in `pending_confirmation`; must be activated via `gommage confirm <id>` (e.g., by a second human) before first use.

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

Picto lifecycle events that mutate authorization state (create, confirm, consume, revoke, bad-signature rejection) are written as signed audit event lines. TTL expiration is enforced at lookup/consume time; expired rows can be swept separately without being required for a decision.
