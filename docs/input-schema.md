# Canonical decision input

This document is the **frozen contract** of what Gommage's policy evaluator reads. It is part of the public API of `gommage-core` and moves on strict semver: any change to the shape, field set, or interpretation rules described here is a breaking change to `gommage-core` and requires a major (or minor pre-1.0) version bump.

The determinism guarantee — the same canonical tool call, mapper, and policy
produce the same policy result — depends on this contract being tight.
Everything not explicitly listed below is, by deliberate omission, **not** part
of the evaluator input. Picto lookup is separate authorization state.

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

The mapper keeps a deterministic first-seen order and removes duplicate
capability strings. Typed Bash effects are emitted first, followed by
compatibility mapper-rule output in file and declaration order.

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
`proc.exec.ambiguous:<reason>` and the shipped strict stdlib policy denies it
before generic `proc.exec:*` rules can authorize the command. Analysis is capped
at 64 KiB of input, 16 levels of nesting, and 512 commands. It does not execute
shell expansions or resolve aliases, sourced functions, generated scripts, or
opaque interpreter behavior. `eval`, `watch`, `xargs`, and `find -exec` are
therefore marked ambiguous for the whole shell call even when a nested payload
can also be classified semantically.

GitHub pull-request merges are typed shell effects. A statically identified
`gh pr merge` emits a target-bound capability in this form:

```text
gh.pr.merge:<host>/<owner>/<repository>#<pull-request-number>
```

The target identity must come from either an exact GitHub pull-request URL or
an exact numeric target paired with an explicit static `-R` / `--repo`
selector in `HOST/OWNER/REPOSITORY` form. The host is mandatory because the
GitHub CLI can otherwise select it from `GH_HOST`; ports are rejected rather
than normalized. Gommage deliberately does not infer the repository from the
shell's current directory, a local Git remote, environment variables, or any
network lookup: none of those is part of the canonical `ToolCall`. A missing
host or repository selector for a numeric target, a dynamic target or
repository, and unsupported target shapes emit `proc.exec.ambiguous:*` and fail
closed under the reference policy. Typed merge authorization is emitted only
for a single shell command; compounds, pipelines, substitutions, and repeating
dispatchers fail closed. An active `--admin` flag additionally emits
`gh.pr.merge.admin:<host>/<owner>/<repository>#<pull-request-number>`.
Administrative mode is typed only when the same static argv contains exactly
one `--match-head-commit` value that is 40 or 64 hexadecimal characters. A
missing, dynamic, shortened, or repeated head commit fails closed instead of
emitting a typed merge. `--admin=false` remains a normal merge.

`-d` / `--delete-branch` additionally emits
`gh.pr.merge.delete-branch:<host>/<owner>/<repository>#<pull-request-number>`.
The reference policy gives that remote branch deletion its own input-bound
`gh.pr.merge.delete-branch` approval scope. When administrative merge and
branch deletion are requested together, the more specific input-bound
`gh.pr.merge.admin-delete-branch` scope covers the combined mutation. The head
commit remains part of the canonical tool input, so none of these approvals can
authorize a command whose reviewed SHA, flags, or other input differs.

Repository identity is normalized lexically as
`<lowercase-host>/<lowercase-owner>/<lowercase-repository>#<positive-number>`,
with the PR number limited to the signed 64-bit range. This is not GitHub API
resolution: Gommage does not follow redirects, resolve a renamed repository,
equate host aliases, or discover a repository through the current checkout. A
URL or selector that names a different literal identity is a different
authorization target.

`-F` / `--body-file` is a real read path, not inert merge metadata. A static
file emits `fs.read:<normalized-path>` and remains subject to secret-read
policy, plus `gh.pr.merge.body-file:<identity>` and
`net.out.post:<normalized-host>`. The default policy uses the input-bound
`gh.pr.merge.body-file` scope, or the specific `admin-body-file`,
`delete-branch-body-file`, and `admin-delete-branch-body-file` combinations.
A dynamic file fails closed. `-F -` reads standard input; a static redirection
still emits its read, while an opaque stdin source without a resolvable read
fails closed.

Environment mutation does not become ambient mapper input. A static inner
command remains visible through a prefix assignment or an `env NAME=value`
wrapper, so its filesystem, GitHub, and administration effects are retained.
The mutation also emits `proc.exec.ambiguous:shell-environment-mutation` or
`proc.exec.ambiguous:wrapper-environment-mutation`; the shipped strict policy
therefore fails the whole call closed instead of authorizing the inner effect
under potentially changed path or executable resolution.

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
Starting `gommage-daemon` directly is also a typed reconfiguration, whether the
static executable is selected by name, absolute path, or a supported
`cargo run` package/binary selector. Static explicit `--home` adds
`gommage.home.mutate:<normalized-path>` and static explicit `--socket` adds
`fs.write:<normalized-path>` alongside `gommage.reconfigure`. Help/version
inspection emits no administration effect; dynamic or unknown daemon options
fail closed.
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

- Input: capability list and compiled policy (rules grouped into closed `org`,
  `user`, and `project` layers).
- Output: `EvalResult { decision, matched_rule, capabilities, policy_version,
  capability_provenance }`.
- Evaluation algorithm:
  1. Normalize path-shaped home aliases, then byte-sort and deduplicate
     capabilities.
  2. `hardstop::check(caps)` — if any compiled hard-stop matches any capability,
     return `Gommage { hard_stop: true }`. This step is not configurable.
  3. Resolve each capability independently. A rule contributes only when its
     whole-set conditions pass and a positive `any_capability` or
     `all_capability` pattern covers that capability. The first contribution in
     each layer wins for that layer and capability.
  4. Aggregate layer contributions and sibling capabilities conservatively.
     Policy deny beats an unresolved capability, unresolved beats
     `ask_picto`, and `ask_picto` beats allow. Multiple required Picto scopes in
     one call fail closed and require the call to be split.
- `Match::matches` semantics: a rule matches iff (a) the `any_capability` patterns are empty **or** at least one matches; (b) every `all_capability` pattern matches at least one cap; (c) no `none_capability` pattern matches any cap.
- `none_capability` is valid only on `allow` rules and is a condition, never
  positive coverage by itself. A rule with no positive pattern is invalid.
- Project layers are tightening-only: loading a project `allow` rule is an
  error. Layers must be unique and ordered `org`, `user`, `project`.
- Glob patterns compile through `globset` without a backtracking regular-expression engine.

Policy substitution happens before compilation. `${VAR}` fails to load when
the value is missing or empty; `${VAR:-default}` is accepted only with a
non-empty configured value or default. The runtime supplies a non-matching
sentinel for `${EXPEDITION_ROOT}` when no expedition is active, so a scoped
pattern cannot silently become `/**`.

The evaluator is pure. The determinism test suite proves this in CI: the fixture sweep is executed in forward order, in shuffled order (seeded), and twice in forward order — results must be byte-identical between all three passes.

---

## 6. Encoding + serialisation rules

- All strings are UTF-8.
- JSON serialisation follows `serde_json` defaults with one exception:
  `ToolCall::input_hash()` recursively sorts object keys before serializing with
  the current `serde_json` implementation. This is the stable contract within
  a tested build; it is not an RFC 8785 canonicalization or an unchecked claim
  of byte stability across arbitrary future serializer versions.
- The audit log's per-record signature covers the canonical JSON of the received
  record minus `sig`. Decision records are v2 and include signed per-capability
  provenance; event records remain v1. Verification rejects duplicate keys at
  every depth and exact-schema top-level mismatches. Signatures authenticate
  present records but do not prove that the JSONL file is complete.

---

## 7. Cross-platform determinism

Current CI exercises policy determinism across:

- Linux and macOS runners, with repeated forward and shuffled suites.
- Different `LANG`/`LC_ALL` values (evaluator does not read locale).

CI uses the repository Rust toolchain rather than a multi-version MSRV matrix.
Determinism-critical dependencies are exact-pinned to reduce dependency drift;
that configuration is not evidence of execution under multiple Rust versions.

Release automation compiles x86_64 and aarch64 archives for Linux and macOS,
but compilation is not native execution evidence. In particular, Linux
aarch64 is cross-compiled in the release workflow, and the release archives
are not executed on every target architecture there. Do not turn archive
availability into a native-runtime certification claim without a separate
native smoke result for that exact asset digest.

Windows is **not** currently in the CI matrix or supported release archive set.
Do not infer Windows host, path, daemon, or integration behavior from the
portable parts of the evaluator until explicit support and native evidence are
added.

---

## 8. Versioning this contract

This document is part of `gommage-core`'s public API. Changes follow `cargo-semver-checks` rules:

- Adding a new field to `ToolCall` — **breaking** (removal of a closed shape). Requires minor bump pre-1.0 or major bump post-1.0.
- Changing the semantics of a field (e.g. "paths are now normalised") — **breaking**.
- Adding a new capability namespace to the stdlib mappers — **not breaking** (additive policy-pack change).
- Tightening a hard-stop pattern — **breaking** (can deny things that previously passed).
- Loosening a hard-stop pattern — **not breaking** in contract terms, but always gated by PR review per `CONTRIBUTING.md`.
