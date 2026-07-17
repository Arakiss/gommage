# Threat model — scope and residuals

This is the focused, mapper-level companion to the repository-root
[`THREAT_MODEL.md`](../THREAT_MODEL.md). The root document is the full model
(trust boundaries, attacker cases, key management). This one answers two
questions sharply: **what gommage is**, **what it is not**, and where the
shell-aware mapper's coverage ends. Read the root file for everything else.

---

## 1. What gommage IS

A **deterministic policy and audit gate on host-emitted agent tool calls.** New
integrations use an all-tools `PreToolUse` matcher. Reviewed `Bash`, file, web,
and `mcp__*` shapes map to capabilities; an emitted but unmapped shape fails
closed. Gommage evaluates declarative YAML policy and emits `allow` / `deny` /
`ask`, recording its decision in a signed audit record. Calls that the host does
not forward remain outside this boundary.

Capability mapping and policy evaluation are pure functions of the canonical
tool call, loaded mapper, and loaded policy. Picto lookup is separate
authorization state, so an active, expired, or spent grant can intentionally
change the final outcome of an `ask_picto` rule. The mapping and evaluation
contract is frozen in [`input-schema.md`](input-schema.md).

Within that scope, gommage gives you:

- **A tool-agnostic filesystem gate for statically resolved effects.** The
  shell-aware mapper emits typed `fs.read` and `fs.write` capabilities for
  supported `Bash` file verbs (`cat`, `cp`, `tee`, redirects) across compound
  commands, substitutions, and transparent wrappers. A policy that denies
  `fs.write:**/.git/**` catches both `Write` to `.git/config` and
  `cat x > .git/config`.
- **The picto model for `ask` gates.** When a rule decides `ask_picto`, the call
  is held until a matching signed grant (picto) exists. Pictos are scoped,
  TTL'd, usage-bounded, and minted out-of-band — never back through the agent
  transcript.
- **Compiled hard-stops.** A finite, reviewed, compiled-in set of capabilities
  (`rm -rf /*`, `dd if=* of=/dev/*`, `mkfs*`, fork bombs, …) is denied
  unconditionally, ahead of policy, picto, and `GOMMAGE_BYPASS`.
- **A fail-closed default.** Any capability that no rule explicitly allows is
  denied. Unmapped → deny. There is no implicit allow path.

## 2. What gommage IS NOT

**Not an OS sandbox, and not an execution mediator.** Gommage decides and
audits; it does not sit in the syscall path. Between its `allow` and the agent
actually executing the command there is a TOCTOU window it cannot close.

Native agent sandboxing and approval controls remain **authoritative below the
hook.** If the agent's own sandbox blocks a call before the `PreToolUse` hook
fires, gommage never sees it and cannot override that decision; if the call
reaches the hook, gommage makes the local policy decision and audits it. Stack
OS-level confinement (AppArmor / SELinux / `seccomp-bpf` / macOS Seatbelt /
containers / Codex `--sandbox`) underneath gommage — gommage is a policy and
audit layer, not a replacement for any of them. The full out-of-scope list is in
the root [`THREAT_MODEL.md` §5](../THREAT_MODEL.md#5-out-of-scope-things-gommage-does-not-try-to-do).

---

## 3. The shell-aware mapper

The mapper parses a `Bash` `command` with an exact-pinned, quote-preserving
shell AST. It walks compounds, pipelines, static `sh`/`bash -c` payloads,
command substitutions, redirections, and a documented set of transparent
wrappers (`command`, `exec`, `env`, `sudo`, `doas`, `timeout`, `time`, `nice`,
`nohup`, `stdbuf`, and `setsid`). Quoted text remains data. Typed extractors
derive filesystem effects and Git push destination, deletion, force, and
network effects from statically known operands.

The analysis is bounded to 64 KiB of shell input, 16 levels of nesting, and 512
commands. Parse errors, exceeded bounds, dynamic security-relevant operands,
unknown options, and wrappers that change working directory emit a bounded
`proc.exec.ambiguous:<reason>` capability. The shipped strict stdlib policy denies
that namespace before generic `proc.exec:*` rules can authorize it. Operators
can edit that policy or activate the recovery bypass, so this is a policy
property, not an OS confinement guarantee.

For supported hook payloads, the adapter first adds reserved path or `cwd`
fields so dedicated file tools and statically known Bash operands can resolve
relative paths lexically. The Bash analyzer rejects `..` operands as ambiguous.
Before policy matching, path-shaped filesystem capabilities (`fs.read`,
`fs.search`, `fs.write`) also normalize leading `~`, `~/`, `$HOME/`, and
`${HOME}/` to the `HOME` value used when loading policy. None of these steps is
`realpath`: symlinks, `~user`, other variables, and raw calls without adapter
metadata remain outside that resolution.

The effect: a policy gate cannot be evaded by command **shape**. These all
surface `fs.read:/etc/shadow` and are gated like a `Read`:

```sh
cat /etc/shadow
cd /x && cat /etc/shadow
sudo cat /etc/shadow
bash -c "cat /etc/shadow"
echo "$(cat /etc/shadow)"
```

Quoted text is never treated as a verb: `echo 'git push'` is data, not a push.

GitHub pull-request merges are bound to one normalized literal identity:
`<host>/<owner>/<repository>#<pull-request-number>`. A numeric target requires
an explicit static `-R` / `--repo HOST/OWNER/REPOSITORY`; an exact
`https://HOST/OWNER/REPOSITORY/pull/NUMBER` URL carries the same fields. The
normalizer lowercases host, owner, and repository and parses the positive PR
number within the signed 64-bit range, but it does not call GitHub, follow
redirects, resolve renamed repositories, equate host aliases, or infer a remote
from the current checkout. Missing or dynamic identity fields fail closed.

An administrative merge is typed only when `--admin` is paired with one static
`--match-head-commit` value containing exactly 40 or 64 hexadecimal characters.
It emits the input-bound `gh.pr.merge.admin` approval scope in addition to the
target-bound merge capability. `-d` / `--delete-branch` emits a separate remote
mutation and uses the input-bound `gh.pr.merge.delete-branch` scope. A command
that combines both flags uses the more specific input-bound
`gh.pr.merge.admin-delete-branch` scope, so approval of either mutation alone
cannot authorize the combination.

A static `--body-file PATH` adds `fs.read:<PATH>`,
`gh.pr.merge.body-file:<identity>`, and `net.out.post:<host>`. The default pack
requires the input-bound `gh.pr.merge.body-file` scope and the ordinary file
policy must resolve the read. Its combinations use the more specific
`gh.pr.merge.admin-body-file`, `gh.pr.merge.delete-branch-body-file`, or
`gh.pr.merge.admin-delete-branch-body-file` scope. That input-bound gate covers
the static file read and post together unless an earlier policy rule denies the
path; no approval for a subset of the effects authorizes the larger call. An
opaque `--body-file -` without a
static redirected input has no resolvable `fs.read` capability and therefore
fails closed. Input binding covers the canonical tool call and path, not file
bytes or the hook-to-exec TOCTOU window described in section 2.

Environment-changing command prefixes and `env NAME=value` wrappers retain the
typed effects of a statically visible inner command, but also emit a
fail-closed `proc.exec.ambiguous:*` capability. Gommage therefore does not
silently certify the inner GitHub, filesystem, or administration operation
under a modified execution environment.

Direct static starts of `gommage-daemon` are typed as
`gommage.reconfigure`. Explicit static `--home` and `--socket` operands also
surface `gommage.home.mutate:<normalized-path>` and
`fs.write:<normalized-path>`, respectively. This applies to the daemon selected
by executable name, absolute path, or supported `cargo run` package/binary
forms; help/version inspection is read-only, while dynamic or unknown options
fail closed.

---

## 4. Residual shell limits

The AST preserves shell syntax; it does not execute expansions or reproduce a
shell runtime. `git -C`, static `HEAD:main` and `feature/x:release/x` refspecs,
force refspecs such as `+main`, static deletions, transparent wrappers, and
static nested shell payloads are mapped to destination-aware effects. The
remaining limits are runtime-dependent forms such as:

- shell aliases, sourced files, functions defined for later invocation, and
  interpreter-specific behavior outside the parsed shell grammar;
- generated scripts, opaque interpreters, aliases, sourced functions, and
  commands whose final executed argv is not represented as a nested shell AST;
- parameter, arithmetic, glob, or command-substitution results when the
  security-relevant destination cannot be determined statically;
- symlink targets, executable replacement, environment-dependent command
  lookup, and filesystem changes after the decision.

Every `Bash` call still carries one raw `proc.exec:<original command>`
capability, and many dynamic forms also carry `proc.exec.ambiguous:*`. The
shipped strict policy denies the ambiguous namespace. `eval`, `watch`, `xargs`,
and `find -exec` are always ambiguous because their effective calls can contain
effects outside a lane-specific parser. Runtime-dependent forms that leave only
the raw capability can still be authorized by a broad user or organization
`proc.exec:*` allow. The strict default posture does not install such a
catch-all; an explicitly relaxed posture gives up this mediation claim. For
strict filesystem or branch control, retain the ambiguous deny and host
sandbox, keep raw execution allows narrow, or route access through dedicated
tools whose path arguments are explicit (see
[`input-schema.md` §4.1](input-schema.md#41-tool-boundary)).

## 5. Policy can re-open shape-based bypass

The fail-closed posture only holds if your allows stay narrow. A policy that
grants a broad **`proc.exec:*` allow** can reopen runtime-dependent behavior
that leaves only the original whole-command capability. It does not override an
earlier shipped deny for `proc.exec.ambiguous:*` unless that rule is changed or
removed. Derived shell candidates feed compatibility mapper rules, but they are
not emitted as additional per-segment `proc.exec` capabilities.

Keep allows narrow. Project policy cannot contain `allow` rules; it is loaded
after user policy and can only add `ask_picto` or `gommage` contributions.
Organization and user policy can allow, ask, or deny. Evaluation resolves each
normalized capability separately in `org`, `user`, `project` order, keeps
first-match ordering only inside one layer and capability, and then aggregates
conservatively: deny beats unresolved, unresolved beats ask, and ask beats
allow. Use
`gommage policy lint --strict` to surface over-broad rules, and
`gommage policy layers --json` to inspect the active layers and effective hash.

Policy variables are also fail-closed at load time. An unset or empty `${VAR}`
is an error unless the expression has a non-empty `${VAR:-default}`. When no
expedition is active, `${EXPEDITION_ROOT}` resolves to a non-matching sentinel
instead of `/`, preventing project-scoped patterns from broadening to `/**`.

## 6. User-mode authority limit

The opt-in Authority v2 core holds a stable per-database writer lock for each
live instance, refuses symbolic or multiply linked database and lock files,
opens SQLite with `SQLITE_OPEN_NOFOLLOW`, and checks the retained file identity
around every operation. Those controls prevent accidental competing Authority
writers and pathname substitution by users who cannot write the private
directory. They do not turn same-UID advisory locks into a privilege boundary:
a hostile process with that UID can ignore the lock, invoke SQLite directly,
or modify directory entries. Reference deployment therefore still requires a
separate service identity or sandbox in addition to the core storage checks.
Bootstrap publishes a fully committed, checkpointed, closed, and synced genesis
database through a same-directory no-clobber hard link and syncs both directory
transitions. The recovery matrix is fail-closed on supported local Unix
filesystems; it is not a universal power-loss guarantee for remote or exotic
filesystems whose link or sync semantics do not meet those operations.
Authority ledger time is evidence ordering, not a trusted estimate of physical
time: timestamps may be equal, but they cannot decrease. Each append verifies
the signed predecessor, full verification enforces the same invariant, and the
signed timestamp of every retained checkpoint head becomes the minimum time
accepted for successor evidence. A clock rollback therefore fails closed
instead of creating earlier-dated decisions, transitions, or cursors.

The shipped daemon, CLI, key, policy, approval inbox, picto database, and Unix
socket are user-local. A process under the same UID can edit policy and state,
read or replace the signing key, invoke daemon reload, or replace the binaries.
`gommage managed status` only reports path modes, user-service file presence,
socket presence, hook status, and the current process's bypass environment. Its
`mode` is `user_level`, `user_service_file_present`, or `unconfigured`; the
report explicitly sets `status_requires_root: false`, `isolation: "none"`,
`tamper_resistance: "none"`, and `reference_ready: false`. A separate managed
reference-mode authority is not shipped in this version.
