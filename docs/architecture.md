# Architecture

## Process layout

```
┌──────────┐   JSON over stdio   ┌────────────────┐   line-JSON over Unix   ┌──────────────┐
│  Agent   │ ──────────────────► │  gommage-mcp   │ ──────────────────────► │ gommage-     │
│ (Claude  │                     │    adapter     │                         │  daemon      │
│  Code)   │ ◄────────────────── │                │ ◄────────────────────── │              │
└──────────┘                     └────────────────┘                         └──────┬───────┘
                                                                                   │
                                                                                   ▼
                                                                         ┌──────────────────┐
                                                                         │ ~/.gommage/      │
                                                                         │  policy.d/*.yaml │
                                                                         │  capabilities.d/ │
                                                                         │  approvals.jsonl │
                                                                         │  pictos.sqlite   │
                                                                         │  audit.log       │
                                                                         │  key.ed25519     │
                                                                         └──────────────────┘

                                        ┌───────────────┐
                                        │ gommage (cli) │
                                        └───────┬───────┘
                                                │ direct file / sqlite access
                                                │ for local ops (grant, list, revoke…)
                                                ▼
                                  (same ~/.gommage/ root)
```

Three binaries, one root. The CLI and daemon share state by convention: both
read the same YAML files, both open the same SQLite picto store, and both
append or replay the same approval inbox.

## Request lifecycle

```
┌──────────────────────────────┐
│ 1. Agent emits tool call     │
│    { tool, input }           │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 2. gommage-mcp (hook)        │
│   reads hook JSON            │
│   connects to daemon socket  │
│   sends { op: "decide", ... }│
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 3. Daemon dispatches         │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 4. CapabilityMapper::map     │
│   { tool, input } → Vec<Cap> │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 5. hardstop::check           │
│   if hit → Gommage immediate │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 6. evaluate(caps, policy)    │
│   first-match ordered rule   │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 7. If AskPicto:              │
│    picto_store.find/consume  │
│    else: record approval OOB │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 8. audit.append (signed)     │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 9. Response to agent         │
│    { allow | deny | ask }    │
└──────────────────────────────┘
```

Each step is pure except 4 (reads mapper rules), 7 (reads/writes picto and
approval stores), and 8 (writes audit log). The evaluator itself (step 5 + 6)
is side-effect free and deterministic — the property the determinism suite
proves.

## Invariants

1. **Hard-stop set is compiled-in.** `HARD_STOPS` in `crates/gommage-core/src/hardstop.rs` is the only path by which a capability can be unconditionally blocked. The YAML policy layer cannot expand this list (it can add its own hard-stops, but those have a different code path and audit signature).

2. **Capability set is a pure function of `(tool, input, mapper rules)`.** No env access, no file I/O. This is why the mapper takes a `ToolCall` + pre-loaded rules, never a filesystem path.

3. **Policy evaluation is a pure function of `(capabilities, rules)`.** The evaluator does not read the picto store; that call happens in the daemon _after_ the evaluator returns `AskPicto`. This separation is deliberate — it keeps the evaluator testable in isolation.

4. **Audit log is append-only and line-signed.** Killing the daemon mid-write corrupts at most one line; all prior lines remain independently verifiable.

5. **Socket is user-local.** `~/.gommage/gommage.sock`, owner-only permissions. No TCP in v0.1.

## Determinism

The determinism suite (`crates/gommage-core/tests/determinism.rs`) loads every `.json` fixture under `tests/determinism/fixtures/`, evaluates each against the shipped stdlib, and asserts:

- Forward order matches the oracle.
- Shuffled order (seeded) matches the forward results byte-for-byte.
- Two consecutive forward sweeps are identical (catches hidden mutable state).

CI re-runs the determinism suite **10 times** per build as an additional defense against lurking nondeterminism (HashMap iteration, thread scheduling, etc.). If any single run diverges from the others, CI fails.

## Policy version hash

Every `Policy` carries a `version_hash` field — a SHA-256 over the concatenation of `(relative_file_path, substituted_file_contents)` in lexicographic order. Relative paths make the same policy tree hash identically under different `GOMMAGE_HOME` roots; substituted contents make different effective canvases produce different hashes. The hash goes into every audit entry so `gommage explain <id>` can report not just which rule fired, but which version of the rule set it was.

When multiple policy layers are active, the hash also includes the layer name
before each relative file path. Runtime layer order is:

1. explicit org policy from `GOMMAGE_ORG_POLICY_DIR`
2. explicit project policy from `GOMMAGE_PROJECT_POLICY_DIR`, or
   `<expedition-root>/.gommage/policy.d` when an expedition is active
3. user policy at `$GOMMAGE_HOME/policy.d`

Policy evaluation is still first-match-wins after compiled hard-stops, so
earlier layers have higher precedence. Use `gommage policy layers --json` to
inspect the layer order and effective hash on a host.

## MCP gateway path

`gommage-mcp --gateway --server-name <name> -- <upstream-command>` is a stdio
MCP proxy path for hosts whose native hook surface does not expose all tool
calls. The gateway maps an MCP `tools/call` request to a Gommage tool name of
`mcp__<name>__<tool>`, evaluates it, and only forwards the original JSON-RPC
line to the upstream server when the decision resolves to allow. Denied and
picto-required calls return MCP tool results with `isError: true`; they are not
sent to the upstream process.

## Picto scope matching

V0.1 uses **exact equality** between the required scope and the stored scope. No globbing, no hierarchy. Rationale: over-broad pictos are a security smell; we'd rather surface a second `ask` than silently auto-grant too much.

V1.0 may relax this to scoped wildcards (e.g. `git.push:release/*`). That is an opt-in feature, not a default.

## Why Rust

- Single static binary. No runtime. No dependency drift at install.
- Syscall-level performance for the hot path (`<5ms` p99 is the bar).
- `serde` + `globset` + `regex` + `rusqlite` + `ed25519-dalek` + `tokio` — every dep mature, audited, actively maintained.
- No GC pauses to bias "mismo input → mismo tiempo".

## Why YAML for v0.1

- Read/writable by hand, cat-able, grep-able.
- Covers the 95% case. Teams that need more expressiveness can wait for v1.0's Rego support.
- Avoids introducing a third language (Rust for the daemon, Rego for policy, something else for capabilities). YAML is already in every DevOps toolchain.
