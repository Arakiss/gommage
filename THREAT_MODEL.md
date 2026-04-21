# Threat model

Gommage is honest about what it defends and what it does not. If any of these mismatches your assumption, stop and read before deploying.

## In scope

1. **Rogue or drifting agent decisions.** An AI agent invokes a tool call that shouldn't be allowed in the current task. Gommage blocks it via policy.
2. **Classifier drift.** The host agent's built-in classifier silently flips on trivial operations mid-session. Gommage gives you a stable, declarative layer instead.
3. **Grant misuse.** A one-shot grant must not become an ambient capability. Pictos have TTL, max_uses, scope, and signature; revocation is O(1) and visible.
4. **Audit gaps.** Every decision — allow, gommage, ask — is appended to a signed log. `gommage explain <id>` reproduces the decision byte-identically.
5. **Accidental destruction.** `rm -rf /`, `dd if=/dev/zero`, fork bombs and friends are hard-stopped regardless of policy or picto.

## Out of scope

1. **OS-level confinement.** Gommage runs in user space and tells the agent "no" — it does not prevent a compromised process from bypassing it via syscall. Stack it under AppArmor / SELinux / `seccomp-bpf` / macOS sandbox if your threat model requires OS-level confinement.
2. **Agent binary compromise.** If Claude Code or Cursor is backdoored at binary level, Gommage sits behind them and sees whatever they choose to show. Gommage protects _against_ the agent's actions, not _as_ the agent.
3. **Supply chain of the agent.** The Anthropic / npm / PyPI pipelines are outside Gommage's control. Verify your agent's signed releases yourself.
4. **Kernel / hypervisor exploits.** Same as (1) — Gommage is a userspace policy layer, not a kernel mitigation.
5. **Secrets storage.** Gommage does not store secrets. It can protect `secret.read:production` by policy, but the secret store itself (Vault, sops, 1Password) is where those bytes live.
6. **TLS inspection.** Gommage sees tool calls, not wire traffic. If an agent posts data via a valid API call, Gommage decides based on the tool call; it does not inspect the request body beyond what the tool schema exposes. Use `mitmproxy` or an enterprise egress proxy for deep inspection.
7. **Human-in-the-loop coercion.** If a human approver rubber-stamps every `ask`, Gommage can't save them. The out-of-band channel is designed to _enable_ careful review, not enforce it.
8. **Prior-transcript influence.** Gommage's evaluator intentionally does not read the transcript. If you _want_ transcript-aware policy (e.g., "deny this if the previous tool call failed"), you will need to encode it as state in an expedition or picto, explicitly.

## Trust boundaries

```
┌──────────────────────────────┐
│  Agent (untrusted)           │
└──────────────┬───────────────┘
               │ tool calls (JSON)
               ▼
┌──────────────────────────────┐
│  gommage daemon (trusted)    │  <- signed binary, local socket
└──────────────┬───────────────┘
               │ reads
               ▼
┌──────────────────────────────┐
│  ~/.gommage/ (trusted)       │  <- user owns, chmod 0700
│   ├── policy.d/              │
│   ├── capabilities.d/        │
│   ├── pictos.sqlite          │
│   ├── audit.log (signed)     │
│   └── key.ed25519 (chmod 600)│
└──────────────────────────────┘
```

The agent is on the untrusted side of the boundary. It sends tool calls; it does not touch `~/.gommage/` directly. The daemon enforces this by running under the user's UID and refusing IPC that tries to write policy files.

## Key management

- Keypair generated on first `gommage daemon` start.
- `~/.gommage/key.ed25519` — private key. `chmod 0600`. Used for: signing audit log lines, signing pictos, verifying picto signatures.
- Rotate via `gommage key rotate` (audit log notes the rotation and re-signs no prior entries — verification remains valid under the historical key, which is archived).
- **Key compromise posture**: if you believe the private key is compromised, rotate immediately and rerun `gommage audit verify` against the archived key to confirm the integrity of pre-rotation entries.

## What happens when you disagree with a decision

1. `gommage explain <audit-id>` — see the exact rule that fired and the capabilities that matched.
2. Edit the policy file, commit the change.
3. `gommage daemon reload` (or `SIGHUP`).
4. New decisions reflect the change; the audit log records the policy version hash with every entry, so retroactive reviews remain unambiguous.

## Reporting vulnerabilities

See `SECURITY.md` (coming in v0.1 final). For now: email `petruarakiss@gmail.com` with subject `[gommage-security]`.
