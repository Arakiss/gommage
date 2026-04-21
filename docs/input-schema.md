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

---

## 2. Path handling

Gommage treats every path it sees in `input.*` fields as an **opaque UTF-8 string**. It does not:

- Resolve symlinks (`/proj/link/x.txt` ≠ `/proj/real/x.txt`).
- Collapse relative segments (`/proj/./src/../src/x.txt` ≠ `/proj/src/x.txt`).
- Canonicalise with `realpath` or `fs::canonicalize`.
- Lowercase or case-fold (even on case-insensitive filesystems).
- Apply Unicode normalisation (NFC / NFD / NFKC / NFKD).
- Decode percent-encoded bytes.

A policy pattern like `fs.write:${EXPEDITION_ROOT}/**` matches the **literal string** the agent emitted. If the agent says `file_path = "/Users/you/proj/src/x.rs"`, the capability is `fs.write:/Users/you/proj/src/x.rs` and the glob is matched against that string.

**Why no normalisation?** Every normalisation is a small inference step that depends on filesystem state at decision time. Resolving a symlink today is a different decision than resolving it tomorrow. Gommage's contract is that the decision is a pure function of the input — so the input must carry whatever semantics the agent wants honoured. Agents that want canonicalised behaviour should canonicalise in their tool-call construction (`realpath`, Node `fs.realpath`, etc.) before emitting.

**Implication for policy authors**: your patterns must account for likely variations the agent might emit. If your agent sometimes sends relative paths and sometimes absolute, write your policy to accept the forms you care about explicitly, or rely on the fail-closed default to deny the rest.

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
- For each rule whose `tool` field equals `call.tool`: every `match_input` regex must fire (on the string extracted from the specified dot-path). If all fire, every `emit` template renders and is pushed into the output.
- Template substitution: `${capture_name}` → regex capture group, `${input.field.sub}` → JSON dot-path as string. Missing captures or missing input fields render to empty string.
- `HashMap` iteration order is eliminated by sorting `match_input` by dot-path string at rule compile time.

The capability `Vec` is not deduplicated. A rule that emits two capabilities will show both, in order. Multiple rules that each emit will concatenate in rule-declaration order.

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
