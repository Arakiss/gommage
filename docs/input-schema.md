# Canonical decision input

This document is the **frozen contract** of what Gommage's policy evaluator reads. It is part of the public API of `gommage-core` and moves on strict semver: any change to the shape, field set, or interpretation rules described here is a breaking change to `gommage-core` and requires a major (or minor pre-1.0) version bump.

The determinism guarantee — same input → same decision, every time, on every OS — depends on this contract being tight. Everything not explicitly listed below is, by deliberate omission, **not** part of the input.

---

## 1. The `ToolCall` type

The evaluator's input is built from a single Rust type:

```rust
pub struct ToolCall {
    pub tool: String,
    pub input: serde_json::Value,
}
```

On the wire — which is what agents send over the `PreToolUse` hook or the daemon's Unix socket — this serialises to:

```json
{
  "tool": "<string>",
  "input": <arbitrary JSON value>
}
```

- **`tool`** is an opaque UTF-8 string identifying the agent's tool handle (`"Bash"`, `"Read"`, `"Write"`, `"Edit"`, `"Glob"`, `"Grep"`, `"NotebookEdit"`, etc.). Gommage does not enumerate valid values; capability mappers match on it directly.
- **`input`** is an arbitrary JSON value. Mappers walk into it by dot-path (`input.command`, `input.file_path`, `input.options.recursive`). Unknown fields are ignored by any given rule; the JSON object can grow without breaking existing mappers.

**Two tool calls with the same canonical JSON produce the same decision.** "Canonical" means: `tool` string equal, `input` value structurally equal under object-key-sort and array-preserve. The `ToolCall::input_hash()` method computes this canonicalisation for audit purposes.

The `gommage hook` adapter preserves the agent's `tool_input`, strips any
agent-supplied `__gommage_*` fields, and then may add reserved
`__gommage_*` fields before constructing the canonical `ToolCall`. Today this
is used to resolve hook-relative `Read` / `Write` / `Edit` / `NotebookEdit`,
`apply_patch`, `Grep` / `Glob`, and shell write targets against the hook `cwd`.
When the destination is inside a Git worktree, the adapter may also add branch
context for diagnostics and audit replay. Branch context is deliberately not an
authorizable capability: filesystem decisions are made against the canonical
resolved `fs.write:<path>` effect. Once added, reserved fields are ordinary
input fields and are covered by the audit input hash.

---

## 2. Path handling

Gommage treats every path it sees in `input.*` fields as an **opaque UTF-8 string**. It does not:

- Resolve symlinks (`/proj/link/x.txt` ≠ `/proj/real/x.txt`).
- Collapse relative segments (`/proj/./src/../src/x.txt` ≠ `/proj/src/x.txt`).
- Canonicalise with `realpath` or `fs::canonicalize`.
- Lowercase or case-fold (even on case-insensitive filesystems).
- Apply Unicode normalisation (NFC / NFD / NFKC / NFKD).
- Decode percent-encoded bytes.

There is one deterministic lexical alias rule after mapping and before policy
matching: for path-shaped filesystem capabilities (`fs.read`, `fs.search`,
`fs.write`), leading `~`, `~/`, `$HOME/`, and `${HOME}/` are rewritten to the
same `HOME` value that was supplied to policy loading. This does not touch
`~user`, other environment variables, relative paths, symlinks, or `..`
segments. It only makes shell-spelled home paths and native absolute home paths
reach the same rule.

A policy pattern like `fs.write:${EXPEDITION_ROOT}/**` matches the **capability
string after this lexical home-alias step**. If the agent says
`file_path = "/Users/you/proj/src/x.rs"`, the capability is
`fs.write:/Users/you/proj/src/x.rs` and the glob is matched against that string.
If the hook payload instead says `file_path = "src/x.rs"` with
`cwd = "/Users/you/proj"`, the adapter adds
`__gommage_file_path = "/Users/you/proj/src/x.rs"` so the stdlib emits the
canonical resolved form. It suppresses the raw relative alias when that trusted
resolved field is present, preventing one write from acquiring two policy
identities.

**Why no normalisation?** Every normalisation is a small inference step that depends on filesystem state at decision time. Resolving a symlink today is a different decision than resolving it tomorrow. Gommage's contract is that the decision is a pure function of the input — so the input must carry whatever semantics the agent wants honoured. Agents that want canonicalised behaviour should canonicalise in their tool-call construction (`realpath`, Node `fs.realpath`, etc.) before emitting.

The home-alias rewrite above is not filesystem normalisation: it reads no
filesystem state, uses the policy load environment already needed for `${HOME}`
patterns, and preserves relative-path hard-stop semantics.

The typed Bash analyzer has a separate deterministic rule because its paths are
operands embedded in `input.command`, not native path fields. It collapses
repeated `/` and `.` components, preserves the canonical leading HOME alias,
and rejects any `..` component as `proc.exec.ambiguous:parent-component`. It
never resolves symlinks or consults the filesystem.

**Implication for policy authors**: for real hook traffic, use the canonical
resolved stdlib capability (`fs.write:/absolute/path`) for project-scoped gates.
For raw daemon `ToolCall` JSON that did not pass through the hook adapter, your
patterns still need to account for the literal paths the caller supplied, or
rely on the fail-closed default to deny the rest. Ambient Git branch state is
not part of a filesystem authorization decision.

---

## 3. What the evaluator does NOT read

The list below is **exhaustive** for v0.1. Anything Gommage reads must be added to this list via a pull request documenting the change, plus a corresponding entry in the determinism suite that proves the read is deterministic.

The evaluator does not read:

- **System clock / wall time / monotonic clock.** Decisions do not depend on `now()`.
- **Environment variables.** The policy loader supports `${VAR}` substitution _at load time_ (from a `HashMap` of values the runtime supplies), but the evaluator itself never reads `std::env`.
- **Current working directory.**
- **User identity** (UID, username, HOME, real name).
- **Hostname, domain, IP addresses.**
- **Process state** (parent PID, TTY, session ID).
- **Filesystem state**: whether the path exists, its permissions, its content, its inode, its symlink target.
- **Network state**: DNS resolution, reachability, TLS certificate validity.
- **Previous tool calls, audit log contents, transcripts, prior decisions.**
- **Time between decisions.** Gommage does not implement rate limiting at the evaluator layer.
- **Host agent identity beyond the `tool` string.** The evaluator does not know "is this Claude Code or Codex CLI".

The mapper has a more permissive contract (it reads `tool_call.input` by dot-path) but it does not read anything outside the input either.

---

## 4. The capability mapper's contract

```rust
pub fn map(&self, call: &ToolCall) -> Vec<Capability>;
```

- Input: `&ToolCall`. Rules are tried in load order (lexicographic filenames under `capabilities.d/`, then declaration order within each file).
- Output: `Vec<Capability>`, deterministic in both content and order.
- Each rule must declare exactly one of `tool` or `tool_pattern`. `tool` is an exact string match. `tool_pattern` is a bounded regex matched against `call.tool`; named captures are available to templates.
- For each rule whose tool matcher accepts `call.tool`: every `match_input` regex must fire (on the string extracted from the specified dot-path). If all fire, every `emit` template renders and is pushed into the output.
- Template substitution: `${tool}` → actual tool name, `${capture_name}` → regex capture group from `tool_pattern` or `match_input`, `${input.field.sub}` → JSON dot-path as string. Missing captures or missing input fields render to empty string.
- `HashMap` iteration order is eliminated by sorting `match_input` by dot-path string at rule compile time.

The capability `Vec` is not deduplicated. A rule that emits two capabilities will show both, in order. Multiple rules that each emit will concatenate in rule-declaration order.

### 4.1 Tool boundary

Capabilities are matched on the **operation**, not on the tool handle that requested it. A filesystem read is `fs.read:<path>` whether it arrived as a `Read` tool call or as `cat <path>` inside `Bash`.

The bundled stdlib mapper makes `Bash` file-verbs emit the same filesystem capabilities the dedicated tools do, so the filesystem gates apply tool-agnostically:

- `cat` / `head` / `tail` / `less` / `od` / `xxd` / `base64` / `strings` / `file` emit `fs.read:<path>` (like `Read`).
- `tee`, `cp` / `install` (destination), `sed -i` targets, `dd of=<path>`, and `>` / `>>` redirect targets emit `fs.write:<path>` (like `Write`).
- For hook payloads with trusted `cwd`, relative filesystem paths emit only the
  canonical resolved `fs.read:<cwd>/<path>` or `fs.write:<cwd>/<path>` form.
- Every `Bash` call emits one raw `proc.exec:<command>` capability for the
  original whole command. Parsed AST commands also become deterministic
  candidates for compatibility mapper rules that constrain `input.command`;
  they are not emitted as additional per-segment `proc.exec` capabilities.
  Typed effects still walk compounds and wrappers, so
  `cd /x && cat /etc/shadow` surfaces `fs.read:/etc/shadow`.

Shell effects are derived from a bounded, quote-preserving AST. The analyzer
walks compound commands, static shell payloads, substitutions, wrappers,
redirections, and every statically known operand. If syntax or a
security-relevant destination is dynamic, it emits
`proc.exec.ambiguous:<reason>` and the reference policy denies it before any
generic `proc.exec:*` rule can authorize the command.

Gommage's own administrative CLI is a typed shell effect too. Parsed invocations
emit exactly one of `gommage.authorize`, `gommage.reconfigure`, or
`gommage.disable`; the classifier recognizes absolute binary paths,
transparent wrappers, static shell payloads, global `--home` in any valid
position, and local `cargo run` selections for the `gommage-cli` package or
`gommage` binary (including Cargo's built-in `cargo r` alias). Service
start/restart operations emit reconfigure, while
uninstall, stop, disable, and name-targeted process termination emit disable.
Documented inspection and dry-run forms emit no administration capability.
Unknown or dynamic administration forms emit `proc.exec.ambiguous:*`.
When one of these operations actually mutates an explicitly selected `--home`,
the mapper also emits `gommage.home.mutate:<normalized-path>`. This semantic
effect names the selected authority root; it is not an `fs.write:*` wildcard
and does not cover caller-selected file operands or another home.
The bundled rules for all three administration classes set `bind_input: true`:
the resulting picto only authorizes the exact canonical tool call that was
reviewed, not another command that happens to share its scope.

File operands used internally by known Gommage commands remain visible to file
policy. Callback bodies, replay and policy inputs, policy fixtures, and local
installer paths emit normalized `fs.read:*`; evidence/report outputs, explicit
upgrade directories, project-init roots, and release download directories emit
normalized `fs.write:*` paths. Both `--option FILE` and `--option=FILE` forms
are covered. Dynamic values and parent-relative paths emit
`proc.exec.ambiguous:*` instead of guessing. This prevents the trusted CLI from
becoming an alternate reader or writer for a path that direct file tools could
not access.

The bundled policy denies direct reads of the signing key, picto database,
approval and webhook delivery logs, signed audit log, and state index. Their
bounded operator CLI views remain the intended inspection path outside an
agent-hook decision.
The reference policy protects the canonical Cargo, user-local, Homebrew,
MacPorts, and system binary paths. Operators using a custom install root must
add its exact `fs.write:` paths to their policy until reference mode defines one
canonical release location.

**Recommendation for strict fs gating.** If you need the filesystem gates to hold tightly, restrict or deny raw `Bash` (gate `proc.exec:*` for the shells you do not trust) and route file access through the dedicated `Read` / `Write` / `Edit` tools, whose path arguments map exactly. See [`THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the residual shapes that fail closed but do not yet hit a precise gate scope.

---

## 5. The policy evaluator's contract

```rust
pub fn evaluate(caps: &[Capability], policy: &Policy) -> EvalResult;
```

- Input: capability list (already ordered by the mapper) and compiled policy (rules in declared order from lexicographic files).
- Output: `EvalResult { decision, matched_rule, capabilities, policy_version }`.
- Evaluation algorithm:
  1. `hardstop::check(caps)` — if any hardcoded hard-stop pattern matches any capability, return `Gommage { hard_stop: true }`. This step is not configurable.
  2. Iterate `policy.rules` in order. For each rule, check whether its `Match` clause accepts the capability list. First match wins.
  3. If no rule matched, return `Gommage { reason: "no rule matched (fail-closed)", hard_stop: false }`.
- `Match::matches` semantics: a rule matches iff (a) the `any_capability` patterns are empty **or** at least one matches; (b) every `all_capability` pattern matches at least one cap; (c) no `none_capability` pattern matches any cap.
- Glob patterns compile via `globset` — RE2-style linear-time matching, no catastrophic backtracking possible.

The evaluator is pure. The determinism test suite proves this in CI: the fixture sweep is executed in forward order, in shuffled order (seeded), and twice in forward order — results must be byte-identical between all three passes.

---

## 6. Encoding + serialisation rules

- All strings are UTF-8.
- JSON serialisation follows `serde_json` defaults with one exception: `ToolCall::input_hash()` computes a canonical JSON encoding (keys sorted lexicographically, same string-escape set as `serde_json`). This canonical form is stable across `serde_json` versions.
- The audit log's per-entry signature covers the canonical JSON of the entry minus the `sig` field. Canonicalisation is implemented in `gommage-audit` and has the same stability properties.

---

## 7. Cross-platform determinism

The decision output is identical across:

- Linux and macOS (CI matrix runs tests on both).
- x86_64 and aarch64 (release binaries are built for both on both platforms).
- Different `LANG`/`LC_ALL` values (evaluator does not read locale).
- Different filesystems (APFS, ext4, btrfs, xfs — evaluator does not stat).
- Different Rust versions ≥ MSRV (1.90) (exact pins on determinism-critical crates).

Windows is **not** currently in the CI matrix. Cross-platform Windows behaviour should work — nothing in the evaluator is Unix-specific — but we do not certify it until Windows support is explicitly added (roadmap v1.x).

---

## 8. Versioning this contract

This document is part of `gommage-core`'s public API. Changes follow `cargo-semver-checks` rules:

- Adding a new field to `ToolCall` — **breaking** (removal of a closed shape). Requires minor bump pre-1.0 or major bump post-1.0.
- Changing the semantics of a field (e.g. "paths are now normalised") — **breaking**.
- Adding a new capability namespace to the stdlib mappers — **not breaking** (additive policy-pack change).
- Tightening a hard-stop pattern — **breaking** (can deny things that previously passed).
- Loosening a hard-stop pattern — **not breaking** in contract terms, but always gated by PR review per `CONTRIBUTING.md`.
