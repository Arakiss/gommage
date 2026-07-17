# Architecture

## Process layout

```
┌──────────┐   JSON over stdio   ┌────────────────┐   line-JSON over Unix   ┌──────────────┐
│  Agent   │ ──────────────────► │ gommage hook   │ ──────────────────────► │ gommage-     │
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
                                                                         │  state.sqlite    │
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

Three binaries, one user-owned root. The CLI and daemon share state by
convention: both read the same YAML files, both open the same SQLite picto
store, and both append or replay the same unsigned approval inbox. Signed
approval lifecycle events are written separately to `audit.log`.

`audit.log` is the authenticated forensic record for decisions and lifecycle events.
`state.sqlite` is a rebuildable read-model owned by the CLI for fast operator
queries. It indexes signed audit entries after `gommage state rebuild`; it is
safe to delete, and no permission decision reads from it.

State schema v2 names its input `source_log: "audit.log"`. `state verify`
compares the index with the current audit-log snapshot; this field does not
upgrade that snapshot into a complete ledger.

Audit signatures authenticate each record independently. They do not form a
hash chain and cannot prove that the file was not truncated, reordered, or
selectively edited by deleting valid lines. Evidence that needs completeness
must be anchored outside the user-owned Gommage home.

## Local control plane

The primary Gommage operation path is CLI + daemon + host hooks:

- `gommage posture` compares the active local policy against bundled strict
  stdlib semantics and names relaxed/custom posture.
- `gommage session doctor` inspects live agent-like processes and whether their
  inferred Claude/Codex homes are wired to Gommage.
- `gommage run codex` builds an explicit Codex launch plan with a selected
  sandbox after validating the Codex home.
- `gommage managed status` inspects a small set of user-mode deployment signals:
  path modes, user-service file presence, socket presence, hook status, and the
  current process's bypass environment.
- `gommage project init` creates reviewed project-local policy and fixtures.

These commands do not change the evaluator contract. They make coverage,
configuration, launch posture, and operator evidence more visible around the
deterministic decision kernel.

## Agent installation posture

`gommage quickstart` and `gommage agent install` configure host hooks and local
policy around the evaluator. They select strict posture by default: no broad
agent convenience layer is generated, unmatched capabilities retain the
evaluator's fail-closed result, and the Claude integration imports supported
native denies into `05-claude-import.yaml` without translating native allows.
Codex sandbox and approval settings remain native Codex configuration.

`--relaxed` is the explicit compatibility path for the previous convenience
posture. It generates `06-agent-config-writable.yaml` and
`95-agent-catch-all.yaml`; the Claude integration also translates supported
native allows into `90-claude-allow-import.yaml`. These are ordinary ordered
policy layers, not a change to evaluator precedence. The `06` configuration
carve-out is deliberately early; the `90` import and `95` catch-all are late
fallbacks. Compiled hard-stops remain unconditional, while unmatched shell,
file, and outbound capabilities may reach broad fallback allows. Opaque runtime
behavior is still outside complete hook-level mediation.

Returning to strict posture is content-aware. The installer first checks all
three reserved relaxation paths. Static generated files must match their
canonical bytes. Dynamic Claude imports must have the generated header,
constrained rule shape, and valid content digest. Digest-less legacy imports
require operator review rather than automatic migration. A mismatch aborts the
operation before any host config or reserved policy write. The installer keeps
a byte-for-byte rollback journal for those active files if a later write fails.
Quickstart captures its broader journal before initializing the Gommage home;
it also records directory modes, the signing key, bundled policy/capability
defaults, context files, runtime files it may initialize, host configuration,
and the optional daemon service file. Rollback removes paths that did not exist
and restores prior bytes, modes, and backup inventory.

After all agent and policy edits, `quickstart` and standalone `agent install`
each make one bounded daemon reload request on a successful setup. Quickstart
does this once across all selected agents rather than once per integration. A
reachable daemon must acknowledge the reload; connection, write, and read
timeouts, other connection errors, rejection, malformed, incomplete, or
oversized responses fail the command. If quickstart rolls back after a later
gate, it may make one additional reload for the restored files. Only a missing
or connection-refused socket counts as an unavailable daemon; the next daemon
start loads the files from disk.

Optional daemon installation is preflighted before any mutation. The resolved
binary must be a canonical regular executable. The policy/agent self-test runs
before service activation; activation itself journals the previous unit bytes
and loaded/enabled state so a failed service-manager command can compensate.

`gommage posture` compares a representative set of active mapper/policy
decisions with the same fixtures evaluated against bundled stdlib. Its
strict/relaxed/custom/failing result describes that sampled semantic
comparison; it is not an exhaustive proof over every possible tool input.
`gommage smoke` applies expected decisions to the active policy and reports a
warning, rather than a failure, when an explicitly relaxable fixture is allowed
by local policy.

`managed status` is diagnostic only. Its `mode` is `user_level`,
`user_service_file_present`, or `unconfigured`, and the report states
`status_requires_root: false`, `isolation: "none"`, `tamper_resistance: "none"`,
and `reference_ready: false`. It does not verify file ownership, a distinct
service principal, a live process identity, or socket peer credentials. The
current service files are a macOS LaunchAgent or systemd user service, not a
protected system authority. Managed reference mode is not shipped by this
architecture.

## Request lifecycle

```
┌──────────────────────────────┐
│ 1. Agent emits tool call     │
│    { tool, input }           │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ 2. gommage hook --agent ...  │
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
│   compositional resolution   │
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

Steps 4 through 6 operate on already-loaded mapper and policy data and are
side-effect free. Step 7 reads or writes picto and approval state, and step 8
writes audit. The policy evaluator itself is deterministic; the final
authorization result can change when picto state changes by design.

## Invariants

1. **Hard-stop set is compiled-in.** `HARD_STOPS` in `crates/gommage-core/src/hardstop.rs` is the only path by which a capability can be unconditionally blocked. The YAML policy layer cannot expand this list (it can add its own hard-stops, but those have a different code path and audit signature).

2. **Capability set is a pure function of `(tool, input, mapper rules)`.** No env access, no file I/O. This is why the mapper takes a `ToolCall` + pre-loaded rules, never a filesystem path.

3. **Policy evaluation is compositional and pure.** Capabilities are normalized,
   byte-sorted, and deduplicated. Compiled hard-stops run first. Each capability
   is then resolved independently: first match is retained only within one
   layer and capability, contributions from `org`, `user`, and `project` are
   aggregated conservatively, and any unresolved capability fails closed.
   Deny beats unresolved, unresolved beats ask, and ask beats allow. The
   evaluator does not read the picto store; that happens after `AskPicto`.

4. **Audit records are independently line-signed.** The writer appends JSONL,
   and prior complete lines remain independently verifiable after an interrupted
   write. This is not cryptographic completeness: deletion, duplication, or
   truncation of valid lines is not detected without an external anchor.

5. **State index is rebuildable.** `state.sqlite` can accelerate TUI metrics,
   recent stream fallback, and local counters, but it is never an evaluator
   input. If stale or missing, operator views fall back to the signed audit
   log.

6. **Socket is user-local.** `~/.gommage/gommage.sock` lives below the mode-0700
   Gommage home. The current line-JSON protocol multiplexes decisions, reload,
   ping, and recent-audit reads on one socket and does not authenticate peer
   credentials. The operator UID is trusted. There is no TCP listener.

## Determinism

The determinism suite (`crates/gommage-core/tests/determinism.rs`) loads every `.json` fixture under `tests/determinism/fixtures/`, evaluates each against the shipped stdlib, and asserts:

- Forward order matches the oracle.
- Shuffled order (seeded) matches the forward results byte-for-byte.
- Two consecutive forward sweeps are identical (catches hidden mutable state).

CI re-runs the determinism suite **10 times** per build as an additional defense against lurking nondeterminism (HashMap iteration, thread scheduling, etc.). If any single run diverges from the others, CI fails.

## Policy version hash

Every `Policy` carries a `version_hash` field. Its versioned hash input includes
the effective home-alias normalizer plus the ordered layer name, relative file
path, and substituted contents for every policy file. Relative paths avoid
binding the hash to one checkout root; substituted contents and normalizer
context distinguish different effective policies. The hash goes into every
decision audit entry.

When multiple policy layers are active, the hash also includes the layer name
before each relative file path. Runtime layer order is:

1. explicit org policy from `GOMMAGE_ORG_POLICY_DIR`
2. user policy at `$GOMMAGE_HOME/policy.d`
3. explicit project policy from `GOMMAGE_PROJECT_POLICY_DIR`, or
   `<expedition-root>/.gommage/policy.d` when an expedition is active

Project policy is tightening-only and cannot contain `allow`. Policy loading
rejects missing or empty `${VAR}` expressions unless they supply a non-empty
`${VAR:-default}`. With no active expedition, `${EXPEDITION_ROOT}` is a
non-matching sentinel rather than an empty string. Use
`gommage policy layers --json` to inspect the active layers and effective hash.

## Optional MCP gateway path

`gommage-mcp --gateway --server-name <name> -- <upstream-command>` is a stdio
MCP proxy path for hosts whose native hook surface does not expose a needed
stdio MCP server. It is not the default agent-hook path; new hooks use
`gommage hook --agent claude` or `gommage hook --agent codex`. The gateway maps
an MCP `tools/call` request to a Gommage tool name of
`mcp__<name>__<tool>`, evaluates it, and only forwards the original JSON-RPC
line to the upstream server when the decision resolves to allow. Denied and
picto-required calls return MCP tool results with `isError: true`; they are not
sent to the upstream process.

Treat this as adapter plumbing, not as the canonical Gommage control path. Use
it only for deliberately wrapped stdio MCP servers where the native hook layer
does not give enough coverage.

## Picto matching

Every picto uses **exact equality** between the required scope and the stored
scope. There is no globbing or hierarchy. Rules may add `bind_input: true` to
require a matching canonical `ToolCall::input_hash` as well. The signature,
lookup, and atomic consume path all use that same hash, so a scope-only picto
cannot satisfy an input-bound rule.

Input binding is opt-in to preserve existing scope-bound policies and direct
`gommage grant` behavior. A request approved under an input-bound rule mints the
bound form; a regular approval or direct grant mints the scope-only form.

The current Picto signature authenticates id, scope, maximum uses, expiry,
creation time, reason, and optional input hash. It does not authenticate the
mutable `uses` or `status` columns; those are enforced transactionally by the
user-owned SQLite store. Approval JSONL, picto mutation, and audit append are
also separate operations rather than one authority transaction. These limits
are why user mode does not claim tamper resistance against the operator UID.

Future scoped wildcards (for example `git.push:release/*`) would be opt-in, not
a default.

## Why Rust

- Three native Rust binaries (`gommage`, `gommage-daemon`, and `gommage-mcp`) with no
  language runtime to install. Platform system libraries may still be linked
  dynamically.
- Syscall-level performance for the hot path (`<5ms` p99 is the bar).
- Determinism-critical dependencies are exactly pinned in the workspace;
  plumbing dependencies use compatible-version requirements and remain subject
  to the lockfile and dependency review.
- Memory safety without a garbage-collected runtime in the evaluator hot path.

## Why YAML for the current policy format

- Read/writable by hand, cat-able, grep-able.
- Keeps policy review separate from the Rust implementation while remaining
  familiar in development and operations toolchains.
- A richer policy engine would require a separate compatibility, determinism,
  and migration design; no alternative engine is promised by the current
  release contract.
