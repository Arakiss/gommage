# Threat model

Gommage is a **policy decision and audit harness for AI coding agents**. It decides whether a tool call the agent emitted is allowed, records the decision in a signed log, and optionally requires a signed grant (picto) to proceed. It is **not a sandbox**, it does **not mediate execution**, and it sees only what the host agent forwards through its hook surface.

If any of the sections below mismatches your assumption about what Gommage does, stop and read before deploying.

---

## 1. What Gommage defends against

These are the attacks Gommage **is** designed to make harder or observable.

### 1.1 Rogue or drifting agent decisions

An AI agent, either by accident or under adversarial prompting, chooses to invoke a tool call that is out of bounds for the current task. Examples:

- `rm -rf ~/Projects/other-project/`
- `git push --force origin main`
- `aws s3 rm s3://prod-data/ --recursive`

Gommage denies via policy (`gommage`) or escalates out-of-band (`ask_picto`). The audit log records the attempt regardless of outcome.

### 1.2 Host-agent classifier drift

The agent's built-in permission layer (e.g. Claude Code's transcript-aware classifier) starts flipping on trivial operations mid-session because of accumulated prior. Gommage gives you a stable, declarative second layer whose behaviour cannot drift — same `(mapper, policy, capabilities)` triple → same decision, every time.

### 1.3 Grant misuse (pictos)

A one-shot break-glass grant must not become an ambient capability.

- Pictos have mandatory `max_uses`, TTL ≤ 24 h, ed25519 signature bound to the daemon keypair.
- Revocation is O(1) and visible in the audit log.
- Exact-scope match only — no wildcarding on the picto side.
- `pending_confirmation` status exists for delegated grants that a second human must activate.

### 1.4 Audit gaps

Every decision (`allow`, `gommage`, `ask`) and every authorization-state event (`picto-created`, `picto-confirmed`, `picto-consumed`, `picto-revoked`, `picto-rejected`, policy reload) produces an append-only JSONL entry signed with the daemon keypair. The signature covers the canonical bytes of the entry minus the `sig` field, so killing the daemon mid-write corrupts at most one line; all prior lines stay independently verifiable.

`gommage audit-verify` walks the full log and returns a count of verified entries (or the line number of the first failure).

### 1.5 Accidental catastrophic destruction

A compiled-in hard-stop list rejects a finite, documented set of capabilities regardless of policy, picto, or expedition: `rm -rf /*`, `dd if=* of=/dev/*`, fork bombs, `mkfs*`, `shred /dev/*`, `chmod -R * /`, and similar. The list lives in `crates/gommage-core/src/hardstop.rs` and grows only via reviewed PRs.

`GOMMAGE_BYPASS=1` does not bypass this list. When the hook payload is valid,
`gommage-mcp` maps it through bundled capability rules before honoring bypass;
compiled hard-stop hits still return `deny`. If `~/.gommage/key.ed25519` is
usable, the bypass path writes a signed `bypass_activated` audit event.

---

## 2. Explicit attacker cases (what we actively think about)

Each case lists **what we do**, **what we do not**, and what users should stack on top of Gommage to cover the gap.

### 2.1 Malicious or compromised agent binary

If Claude Code, Codex CLI, Cursor, etc. are themselves backdoored at the binary level and choose not to call the `PreToolUse` hook, Gommage never sees the tool call. The protection here is the agent's own release integrity (signed builds, checksum verification on install). Gommage **does not** verify the agent's binary.

**Stack on top**: OS-level sandbox (macOS Seatbelt, Linux `bwrap + seccomp`, containers).

### 2.2 Malicious local user with shell access

A user with shell access under the same UID as the daemon can:

- Read and modify `~/.gommage/` directly, bypassing the daemon.
- Forge audit log entries using the leaked key.
- Replace `gommage-daemon` with a malicious binary.

Gommage **trusts** the local user. The directory is `chmod 0700` and the key is `chmod 0600`, but that is OS-enforced, not Gommage-enforced. If the threat model includes hostile local users, Gommage is the wrong layer.

### 2.2.1 Agent-controlled hook environment

Some hosts let users or agents configure environment variables for hook
processes. If an agent can set `GOMMAGE_BYPASS=1`, it can intentionally skip
normal policy evaluation. This is a recovery mechanism, not a security grant:

- valid hook payloads still run through compiled hard-stop checks;
- hard-stop matches return `deny` even under bypass;
- usable Gommage homes receive signed `bypass_activated` audit events;
- malformed payloads may still allow without opening home so a broken hook path
  can be recovered.

Do not expose hook environment mutation to untrusted repositories. Use OS
sandboxing and host-agent config review for that boundary.

### 2.3 Malicious repository or working tree

An agent operating on a repo containing hostile content — a symlinked `README.md` pointing at `/etc/shadow`, a `policy.d/` override placed under the repo by an attacker, a file named `../../../etc/passwd` — should not be able to extract capabilities Gommage wouldn't otherwise grant.

Gommage's input specification (see Section 3) treats paths as **opaque strings**: no symlink resolution, no relative-path collapsing, no case-folding. The capability mapper renders `fs.read:<literal path as sent by the agent>`. Globs in policy match on that literal.

**Implication**: your policy patterns should account for likely variations. For example, `fs.write:${EXPEDITION_ROOT}/**` does NOT match `fs.write:/symlink/to/expedition/root/x.txt` because Gommage does not resolve the symlink — the agent would have to produce the canonical path in its tool call for the allow to apply. This is deliberate: the decision boundary is the _string the agent emits_, not the filesystem state.

**Users must**: configure their agent to canonicalize paths before tool use (`realpath`, `fs.realpath` in Node, etc.). Or accept the conservative posture: ambiguous paths get denied by the fail-closed default.

### 2.4 Forged or tampered picto store

An attacker with read access to `~/.gommage/pictos.sqlite` who tries to inject a picto row with a stolen signature, or modify an existing picto's scope/TTL:

- **Signature-based rejection**: at lookup and consume time, Gommage verifies the picto's `signature_b64` against the verifying key derived from the daemon keypair. A tampered row fails verification → rejected → audit entry says "bad signature".
- **But**: if the attacker has the private key (local user compromise, Section 2.2), forgery succeeds. See 2.2.

`gommage audit-verify --explain` verifies the signed audit trail itself and surfaces `picto_rejected` lifecycle events for tampered rows.

### 2.5 TOCTOU between Gommage's decision and the agent's execution

Gommage returns `allow` at time T₀. The agent executes the command at T₁. Between T₀ and T₁, the world can change (file moved, symlink swapped, remote revoked). Gommage does **not** re-check at T₁; the decision is made on the input it saw, period.

This is intentional: Gommage is a decision + audit harness, not an execution mediator. Any OS-level TOCTOU concerns must be addressed by OS-level confinement (Section 2.1 stack recommendations).

### 2.6 Replayed approval via out-of-band channel

When a `ask_picto` decision has no matching picto, the daemon (v1.0) escalates to an out-of-band approval channel (webhook, TUI, push). If an attacker intercepts the approval channel and replays a past approval, they could cause an unauthorized action.

- **Mitigation today**: pictos have single-use (`max_uses: 1` by convention). A replayed picto that references a spent ID fails on consume.
- **Mitigation v1.0**: approval responses will include a nonce bound to the specific `audit_id` they approve, and the daemon will reject approvals whose nonce does not match the current pending decision.

### 2.7 Clock skew / backdated TTL

A picto's TTL is stored as a Unix timestamp at creation time (daemon clock). If the daemon clock drifts backwards, a picto could live longer than intended. If it drifts forwards, pictos expire faster.

Gommage does not implement NTP verification or clock-source validation. We assume the host clock is monotonic and approximately correct. Enterprise operators should run NTP or equivalent; the audit log records the daemon's clock reading at each decision for forensic purposes.

### 2.8 Unicode and encoding tricks

Tool-call inputs are UTF-8 strings. Gommage does **not** Unicode-normalize (no NFC/NFD/NFKC) and does **not** case-fold. A policy rule that matches `git.push:refs/heads/main` will NOT match `git.push:refs/heads/ⅯⅠⅠⅠⅠⅠⅠⅠⅠⅠⅠⅠⅠⅠ` or similar look-alikes.

**Implication**: if your agent accepts non-ASCII branch names or paths, your policy must either explicitly enumerate them or accept the conservative posture (fail-closed default denies anything not explicitly matched).

**Users must**: prefer ASCII-only branch/resource names in policies; add a hard-stop rule banning non-ASCII bytes in sensitive namespaces if needed.

### 2.9 Regex denial-of-service in capability mapper

Capability mapper rules compile user-supplied regex (from `capabilities/*.yaml`). A pathological regex could, on the right input, cause catastrophic backtracking.

- Gommage uses the `regex` crate (Rust, RE2-style, linear-time guaranteed). Catastrophic backtracking is **impossible** by the engine's design.
- A malicious capability rule could still denial-of-service via sheer volume. The mapper sets explicit regex compile limits (`size_limit` and `nest_limit`) and rejects patterns beyond them.

### 2.10 Policy YAML deserialization attacks

`serde_yaml_ng` is the loader. YAML features Gommage does **not** support or parse specially:

- YAML anchors / aliases that expand to megabytes (billion laughs). `serde_yaml_ng` inherits the upstream parser limits; we do not impose a stricter one yet.
- YAML tags invoking custom types — we deserialize into a closed set of types (`RawRule`, `RawMapperRule`); unknown tags error at parse time.
- Duplicate keys — YAML spec is ambiguous, but `serde_yaml_ng` rejects duplicate struct fields in policy and mapper files instead of silently accepting last-wins behavior.

**Today's posture**: users are trusted authors of `~/.gommage/policy.d/*.yaml`. If your policy directory can be written to by an attacker, Gommage is already bypassed (Section 2.2).

---

## 3. Canonical decision input

The evaluator is pure: `evaluate(capabilities: &[Capability], policy: &Policy) -> EvalResult`. It reads nothing else. The mapper is also pure: `map(tool_call: &ToolCall) -> Vec<Capability>`.

`ToolCall` is the single frozen input:

```json
{ "tool": "<string>", "input": <arbitrary JSON value> }
```

What the evaluator **does not** read, by deliberate omission:

- Current working directory, environment variables, user identity, hostname.
- System clock, wall time, duration since last call.
- Previous tool calls, prior audit log entries, the agent's transcript.
- Filesystem state: existence, permissions, symlink targets, file contents.
- Network state, DNS, TLS.

What the mapper does with paths:

- Paths in `tool_input` are passed through as **opaque UTF-8 strings** — no normalization, canonicalization, or symlink resolution.
- Path globs in policy patterns (`fs.write:**/node_modules/**`) match the **string** the agent emitted, not a resolved filesystem path.

What is considered a "heuristic" and therefore **NOT** in Gommage:

- Any classifier, ML model, Bayesian prior, or transcript-aware scoring.
- Any "intent inference" (e.g. "this command looks risky because…").
- Any ordering-dependent state accumulation across decisions.

What **is not** a heuristic (still deterministic, documented behaviour):

- Regex matching against tool inputs to extract capabilities (deterministic, reproducible).
- Glob matching capabilities against policy patterns (deterministic, `globset` crate).
- First-match-wins rule evaluation order (deterministic and part of the contract).
- Hardcoded hard-stop set (deterministic, compiled-in list).

The "zero heuristics" claim specifically means: **no component of the decision reads anything outside `(capabilities, policy)`**. Period. CI proves this by running the determinism suite in forward and shuffled order and asserting byte-identical outputs.

---

## 4. Trust boundaries

```
┌──────────────────────────────┐
│  Agent (untrusted)           │
│  (Claude Code, Codex, …)     │
└──────────────┬───────────────┘
               │ tool calls (JSON over PreToolUse hook)
               ▼
┌──────────────────────────────┐
│  gommage-mcp adapter         │  <- stateless; translates to daemon IPC
└──────────────┬───────────────┘
               │ line-JSON over Unix socket
               ▼
┌──────────────────────────────┐
│  gommage daemon (trusted)    │  <- signed binary, user-local socket
└──────────────┬───────────────┘
               │ reads/writes
               ▼
┌──────────────────────────────┐
│  ~/.gommage/ (trusted)       │  <- chmod 0700; user is the TCB
│   ├── policy.d/              │
│   ├── capabilities.d/        │
│   ├── pictos.sqlite          │
│   ├── audit.log (signed)     │
│   └── key.ed25519 (chmod 0600)│
└──────────────────────────────┘
```

**TCB (Trusted Computing Base)**: the user's UID, the daemon binary, and the `~/.gommage/` directory. Everything outside that boundary (agent, repo contents, network) is treated as untrusted input.

---

## 5. Out of scope (things Gommage does NOT try to do)

1. **OS-level confinement.** Stack under AppArmor / SELinux / `seccomp-bpf` / macOS sandbox / containers if the threat model needs OS-level kill switches.
2. **Agent binary integrity.** Verify your agent's releases independently.
3. **Supply chain of the agent or its SDKs.** Outside Gommage's reach.
4. **Kernel / hypervisor exploits.** User-space policy layer only.
5. **Secrets storage.** Use Vault / 1Password / sops. Gommage can _protect_ access to `secret.read:production` by policy; it does not hold the secret.
6. **TLS inspection / wire-level network control.** Gommage sees what the agent emitted as a tool call. For TLS / DNS inspection, use `mitmproxy` or an enterprise egress proxy.
7. **Human-in-the-loop coercion.** If an approver rubber-stamps every `ask`, Gommage cannot save them. The out-of-band channel exists to _enable_ careful review, not enforce it.
8. **Execution mediation.** Gommage decides and audits; it does not sit in the syscall path of the command. Between Gommage's `allow` and actual execution there is a TOCTOU window Gommage cannot close (Section 2.5).
9. **Transcript-aware policy.** The evaluator intentionally does not read prior context. If you want history-dependent policy, encode it as expedition state or picto scope.
10. **Prevention of user misconfiguration.** A policy file that `allow`s everything is your choice. Gommage will load it, log the decisions, and not second-guess.

---

## 6. Key management

- Keypair generated on first `gommage daemon` start via `OsRng`.
- `~/.gommage/key.ed25519` — private key. 32 bytes, `chmod 0600`. Used for: signing audit log lines, signing pictos, verifying picto signatures.
- No key rotation command in v0.1 (planned for v0.2: `gommage key rotate` with archived history and retroactive verify).
- **If you believe the private key is compromised**: delete `~/.gommage/` (losing audit history is acceptable for compromised state), regenerate, rotate any upstream systems that trusted the compromised key.

---

## 7. Reporting vulnerabilities

See `SECURITY.md` (v0.1 final). Until then, email `petruarakiss@gmail.com` with subject `[gommage-security]` and, if possible, encrypt to the maintainer's public key (available on keys.openpgp.org under the same email). Initial response within 72 hours.

Please do **not** open public GitHub issues for vulnerabilities.

---

## 8. Disagreeing with a decision in production

1. `gommage explain <audit-id>` — shows the exact rule that fired, the capabilities in play, and the policy version hash.
2. Edit `~/.gommage/policy.d/*.yaml` to adjust the rule.
3. `kill -HUP $(pgrep gommage-daemon)` — daemon reloads without restarting.
4. New decisions reflect the change; the audit log records the new policy version hash so retroactive review can reconstruct "which policy was in effect when".
