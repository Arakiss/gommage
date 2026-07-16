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

Gommage denies via policy (`gommage`) or escalates out-of-band (`ask_picto`). A
successfully handled call on the normal hook and daemon path also emits a signed
audit record for the attempt.

### 1.2 Host permission variability

Host permission modes, persistent rules, sandbox configuration, and interactive
approvals can differ between machines and sessions. Gommage adds a declarative
layer with a narrower contract: the same observed call, mapper, and ordered
policy layers produce the same policy result every time. Picto lookup is
separate authorization state, so an active, expired, or spent grant can
intentionally change the final result of an `ask_picto` rule.

### 1.3 Grant misuse (pictos)

A scoped break-glass grant must not become an ambient capability.

- Pictos have mandatory `max_uses`, TTL ≤ 24 h, ed25519 signature bound to the daemon keypair.
- Revocation is O(1) and visible in the audit log.
- Exact-scope match only — no wildcarding on the picto side.
- Rules can opt into `bind_input: true`, which requires a picto signed for the
  exact canonical tool-call hash as well as the required scope. A scope-only
  picto cannot satisfy an input-bound rule.
- `pending_confirmation` status exists for delegated grants that a second human must activate.

Picto schema v1 signs the id, scope, maximum use count, expiry, creation time,
reason, and optional input hash. Mutable `uses` and `status` fields are not in
that signature; the SQLite transaction protects them in the normal daemon path.
Signing and verification reject empty authority identifiers, delimiters and
control characters in text fields, non-integral or non-UTC timestamps, invalid
lifetimes/use counts, non-canonical input hashes, and non-canonical signature
base64. They also cap signed UTF-8 text at 128 bytes for id, 512 for scope, and
4,096 for reason. This keeps the unversioned newline-delimited v1 payload
unambiguous for valid rows, including across input-bound and scope-only grants;
it does not sign mutable `uses` or `status`.
The same user key signs pictos and audit records. This is a user-mode grant
mechanism, not a privilege boundary against the account that owns the store.

### 1.4 Audit gaps

The normal daemon path appends decisions (`allow`, `gommage`, `ask`) and authorization-state events (`picto-created`, `picto-confirmed`, `picto-consumed`, `picto-revoked`, `picto-rejected`, policy reload) as JSONL records signed with the daemon keypair. Decision records use schema v2 and lifecycle events use schema v1. The signature covers the strict canonical bytes of each record minus the `sig` field; duplicate keys, unexpected top-level fields, malformed canonical values, and bad signatures fail verification.

`gommage audit-verify` walks the available file and returns a count of verified records (or the line number of the first failure). Records are independently authenticated: there is no hash chain, signed sequence number, checkpoint, or external witness. Deletion, truncation, reordering, or duplication of otherwise valid records is therefore outside the current cryptographic guarantee.

### 1.5 Accidental catastrophic destruction

A compiled-in hard-stop list rejects a finite, documented set of capabilities regardless of policy, picto, or expedition: `rm -rf /*`, `dd if=* of=/dev/*`, fork bombs, `mkfs*`, `shred /dev/*`, `chmod -R * /`, and similar. The list lives in `crates/gommage-core/src/hardstop.rs` and grows only via reviewed PRs.

Scope note on `rm -rf`: despite the id `hs.rm-rf-root` and the `rm -rf /*` glob, this hard-stop is **any-absolute-path**, not root-only. `rm -rf` with any argument that begins with `/` (e.g. `/tmp/scratch`, `/home/me/build`) is denied; the `*` in the glob crosses `/`, and a second shell-semantic scanner independently flags `rm` with `r`+`f` flags and a `/`-leading argument. Relative paths (`./build`, `node_modules`) are deliberately out of scope — gate those at the policy layer if you need to. This is intentional blast-radius containment, not a root-only check; a force to delete an absolute scratch path is friction by design (there is no picto for a hard-stop). Loosening it to a protected-prefix allow-list is a deliberate, reviewed change, not a bug.

`GOMMAGE_BYPASS=1` does not bypass this list. Hook entry points — the canonical
`gommage hook --agent <host>` command and the legacy `gommage-mcp` /
`gommage mcp` compatibility paths — share one bypass path
(`gommage_stdlib::evaluate_bypass`):
when the hook payload is valid it is mapped through the bundled capability rules
before honoring bypass, and compiled hard-stop hits still return `deny`. If
`~/.gommage/key.ed25519` is usable, the bypass path writes a signed
`bypass_activated` audit event. The variable must be set in the **hook process
environment** (launch the agent with it, or set it on the hook command);
exporting it inside a child shell mid-session does not affect later hook
invocations.

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

The daemon listens on one user-local Unix socket and its line-JSON protocol does
not authenticate peer credentials. A process running as the same UID can call
the exposed decision, reload, ping, and recent-audit operations. `gommage
managed status` checks configuration paths, modes, user-service file presence,
socket presence, hook status, and the current process environment. Its `mode`
is `user_level`, `user_service_file_present`, or `unconfigured`; it reports
`status_requires_root: false`, `isolation: "none"`, `tamper_resistance: "none"`,
and `reference_ready: false` rather than presenting these signals as a protected
policy authority.

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

An agent operating on a repo containing hostile content — a symlinked `README.md` pointing at `/etc/shadow`, a project-local `.gommage/policy.d/` override placed under the repo by an attacker, a file named `../../../etc/passwd` — should not be able to extract capabilities Gommage wouldn't otherwise grant.

Gommage never resolves paths through the filesystem: there is no symlink
resolution, case-folding, or Unicode normalization. Raw paths already present
in a canonical `ToolCall` remain opaque. For supported hook payloads, the
adapter can add reserved absolute path fields by resolving relative paths
lexically against the hook `cwd`; the typed Bash analyzer performs the same
bounded lexical resolution for statically known operands. Before policy
matching, path-shaped capabilities also normalize leading `~`, `~/`, `$HOME/`,
and `${HOME}/` to the `HOME` value used while loading policy. Globs match the
resulting capability string.

**Implication**: your policy patterns should account for likely variations. For
example, `fs.write:${EXPEDITION_ROOT}/**` does NOT match
`fs.write:/symlink/to/expedition/root/x.txt` because Gommage does not resolve
the symlink. The canonical tool call handed to the mapper—including reserved
fields added by the host adapter—is the decision boundary, not filesystem
state.

**Users must**: rely only on adapter path forms they have tested. Integrations
that do not supply trusted `cwd` metadata must send the intended path identity
themselves. If symlink identity matters, canonicalize it before tool use
(`realpath`, `fs.realpath` in Node, etc.) or rely on the conservative
fail-closed result for unmatched forms.

For Bash payloads, Gommage parses a bounded typed shell AST (64 KiB input, 16
levels of nesting, and 512 commands) and unwraps the documented transparent
wrappers such as `command`, `exec`, `env`, `sudo`, `doas`, `timeout`, `nice`,
and `setsid`. Dynamic or unsupported command forms emit an ambiguous execution
capability, which the bundled strict policy denies. Runtime behavior that is
not present in the observed string remains outside the mapper: aliases,
sourced functions, `eval`-generated commands, static `xargs` input,
environment-dependent expansion, and symlink targets are examples. A custom
broad `allow` rule can weaken the bundled policy boundary.

Project-local policy is loaded only when an operator opts into a project layer
through `GOMMAGE_PROJECT_POLICY_DIR` or starts an expedition whose root contains
`.gommage/policy.d`. Treat project policy files as reviewed code. Active layers
are ordered organization, user, then project. A project-layer `allow` is
rejected, so repository-controlled policy can only add `deny` or `ask_picto`
constraints; it cannot positively authorize a capability. `gommage policy
layers --json` shows the exact active order and hash.

### 2.4 Forged or tampered picto store

An attacker with write access to `~/.gommage/pictos.sqlite` who tries to inject a picto row with a stolen signature, or modify a signed field such as scope, limit, timestamp, reason, or input hash:

- **Signature-based rejection**: at lookup and consume time, Gommage verifies the picto's `signature_b64` against the verifying key derived from the daemon keypair. A tampered row fails verification → rejected → audit entry says "bad signature".
- **Lifecycle-state limit**: schema v1 does not sign `uses` or `status`. The normal daemon path updates those fields transactionally, but direct mutation by the trusted local user is not detected by `Picto::verify`.
- **But**: if the attacker has the private key (local user compromise, Section 2.2), forgery succeeds. See 2.2.

`gommage audit-verify --explain` verifies each present signed audit record and
surfaces `picto_rejected` lifecycle events for tampered rows. It does not prove
that the file contains every record that was originally emitted.

### 2.5 TOCTOU between Gommage's decision and the agent's execution

Gommage returns `allow` at time T₀. The agent executes the command at T₁. Between T₀ and T₁, the world can change (file moved, symlink swapped, remote revoked). Gommage does **not** re-check at T₁; the decision is made on the input it saw, period.

This is intentional: Gommage is a decision + audit harness, not an execution mediator. Any OS-level TOCTOU concerns must be addressed by OS-level confinement (Section 2.1 stack recommendations).

### 2.6 Replayed approval via out-of-band channel

When an `ask_picto` decision has no matching picto, Gommage creates a local
approval request and can notify an out-of-band channel (webhook or TUI). If an
attacker intercepts a notification and convinces a human or script to replay a
past approval command, they could try to authorize an unintended action.

- **Scope-only requests.** The compatibility default remains a picto matched by
  exact scope, TTL, and use count. It prevents broad wildcard grants but can
  authorize a different tool call in that same scope. Use it only where scope
  is the intended approval boundary.
- **Input-bound requests.** A rule with `bind_input: true` includes the
  canonical input hash and binding mode in the request identity. Approval mints
  a picto whose signature covers that input hash; lookup and atomic consumption
  require the same scope and input hash. A grant for one call therefore cannot
  authorize another call in the same scope.
- **Callbacks.** `gommage approval callback` verifies the HMAC signature,
  timestamp freshness, pending state, and a nonce bound to request id, input
  hash, scope, policy version, and binding mode before it can apply a local
  approve or deny action. A callback for a different request or binding mode
  fails closed.
- **Audit and confirmation.** Picto use counts are updated atomically by the normal store path. The TUI
  requires an explicit confirmation keystroke. Approval request, resolution,
  webhook delivery, and picto lifecycle events emitted by the daemon are
  independently signed in the audit log.
- **Current limit.** Gommage does not host an inbound callback receiver. A
  local process must provide the callback body, signature, timestamp, and
  shared-secret configuration to `gommage approval callback`. Outbound generic,
  Slack-shaped, and Discord-shaped webhooks remain notification transports.

### 2.7 Clock skew / backdated TTL

A picto's TTL is stored as a Unix timestamp at creation time (daemon clock). If the daemon clock drifts backwards, a picto could live longer than intended. If it drifts forwards, pictos expire faster.

Gommage does not implement NTP verification or clock-source validation. It assumes the host wall clock is approximately correct and is not moved backwards unexpectedly. Enterprise operators should run NTP or equivalent; the audit log records the daemon's clock reading at each decision for forensic purposes.

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

The evaluator is pure: it receives canonical capabilities and ordered policy layers and reads nothing else. The mapper is also pure: `map(tool_call: &ToolCall) -> Vec<Capability>`.

`ToolCall` is the single frozen input:

```json
{ "tool": "<string>", "input": <arbitrary JSON value> }
```

What the evaluator **does not** read, by deliberate omission:

- Current working directory, environment variables, user identity, hostname.
- System clock, wall time, duration since last call.
- Previous tool calls, prior audit log entries, the agent's transcript.
- `state.sqlite` read-model contents.
- Filesystem state: existence, permissions, symlink targets, file contents.
- Network state, DNS, TLS.

What the mapper does with paths:

- Paths already present in canonical `tool_input` are opaque UTF-8 strings: no
  `realpath`, case-folding, Unicode normalization, or symlink resolution.
- The hook adapter may add reserved absolute fields by resolving supported
  relative file-tool paths lexically against its trusted `cwd`. The typed Bash
  analyzer likewise uses the reserved `cwd` for supported static operands,
  collapses `.` and repeated separators, and rejects `..` as ambiguous.
- Before policy matching, path-shaped filesystem capabilities (`fs.read`,
  `fs.search`, `fs.write`) normalize leading home aliases (`~`, `~/`, `$HOME/`,
  `${HOME}/`) to the `HOME` value supplied at policy load.
- Path globs in policy patterns (`fs.write:**/node_modules/**`) match that
  deterministic capability string, not a filesystem-resolved path.

What is considered a "heuristic" and therefore **NOT** in Gommage:

- Any classifier, ML model, Bayesian prior, or transcript-aware scoring.
- Any "intent inference" (e.g. "this command looks risky because…").
- Any ordering-dependent state accumulation across decisions.

What **is not** a heuristic (still deterministic, documented behaviour):

- Regex matching against tool inputs to extract capabilities (deterministic, reproducible).
- Glob matching capabilities against policy patterns (deterministic, `globset` crate).
- The first matching contribution within each layer for each capability (deterministic and part of the contract).
- Restrictive composition across layers and capabilities: `deny` outranks unresolved input, which outranks `ask_picto`, which outranks `allow`.
- Hardcoded hard-stop set (deterministic, compiled-in list).

The "zero heuristics" claim specifically means: **the policy evaluator reads nothing outside its canonical capabilities and policy layers**. CI exercises this contract by running the determinism suite in forward and shuffled order and asserting byte-identical outputs.

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
│  gommage hook adapter        │  <- stateless; translates to daemon IPC
└──────────────┬───────────────┘
               │ line-JSON over Unix socket
               ▼
┌──────────────────────────────┐
│  gommage daemon (trusted)    │  <- trusted binary, user-local socket
└──────────────┬───────────────┘
               │ reads/writes
               ▼
┌──────────────────────────────┐
│  ~/.gommage/ (trusted)       │  <- chmod 0700; user is the TCB
│   ├── policy.d/              │
│   ├── capabilities.d/        │
│   ├── pictos.sqlite          │
│   ├── audit.log (signed)     │
│   ├── state.sqlite (cache)   │
│   └── key.ed25519 (chmod 0600)│
└──────────────────────────────┘
```

**TCB (Trusted Computing Base)**: the user's UID, the daemon binary, and the `~/.gommage/` directory. Everything outside that boundary (agent, repo contents, network) is treated as untrusted input.

The current socket protocol does not authenticate peer credentials beyond the
filesystem boundary supplied by the user-owned home. A future protected or
multi-user authority would require a distinct service identity, authenticated
IPC, independently controlled keys and policy, and an explicit migration path;
that managed reference mode is not shipped today.

`state.sqlite` is inside the trusted home because it may contain indexed audit
metadata, but it is not trusted for permission decisions. It is a local
read-model that can be deleted and rebuilt from `audit.log`; forged or stale
state can mislead an operator view until `gommage state verify`/`rebuild`, but
cannot make the evaluator allow a tool call.

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
10. **Prevention of trusted-layer misconfiguration.** An organization or user policy that broadly allows capabilities weakens the bundled fail-closed posture. Project policy cannot add `allow`; it can tighten a broad trusted rule only for capabilities covered by its own `ask_picto` or deny rules.
11. **Cryptographic log completeness.** Current signatures authenticate individual records, not the presence, order, or uniqueness of the complete history.
12. **Protected managed authority.** The current daemon and status checks operate within one trusted UID; they do not provide authenticated multi-user administration or a separately protected policy owner.

---

## 6. Key management

- Keypair generated with `OsRng` when the Gommage home is first initialized.
- `~/.gommage/key.ed25519` — private key. 32 bytes, `chmod 0600`. The same key signs audit records and pictos; the derived public key verifies both.
- The current CLI has no key-rotation command or independently administered authority key.
- **If you believe the private key is compromised**: delete `~/.gommage/` (losing audit history is acceptable for compromised state), regenerate, rotate any upstream systems that trusted the compromised key.

---

## 7. Reporting vulnerabilities

See `SECURITY.md`. Email `petruarakiss@gmail.com` with subject `[gommage-security]` and, if possible, encrypt to the maintainer's public key (available on keys.openpgp.org under the same email). Initial response within 72 hours.

Please do **not** open public GitHub issues for vulnerabilities.

---

## 8. Disagreeing with a decision in production

1. `gommage explain <audit-id>` — shows the exact rule that fired, the capabilities in play, and the policy version hash.
2. Edit `~/.gommage/policy.d/*.yaml` to adjust the rule.
3. `gommage daemon reload` — reload policy and mapper state without restarting.
4. New decisions reflect the change. The audit record identifies the policy
   version hash in effect; retain the corresponding policy files separately if
   you need to reproduce that version later.
