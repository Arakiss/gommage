# Threat model — scope and residuals

This is the focused, mapper-level companion to the repository-root
[`THREAT_MODEL.md`](../THREAT_MODEL.md). The root document is the full model
(trust boundaries, attacker cases, key management). This one answers two
questions sharply: **what gommage is**, **what it is not**, and where the
shell-aware mapper's coverage ends. Read the root file for everything else.

---

## 1. What gommage IS

A **deterministic policy and audit gate on agent tool calls.** When an AI coding
agent decides to run a tool — `Bash`, `Read`, `Write`, `Edit`, a `WebFetch`, an
`mcp__*` call — gommage intercepts that call at the host's `PreToolUse` hook,
maps it to capabilities, evaluates declarative YAML policy, and emits
`allow` / `deny` / `ask`, recording every decision in a signed audit log.

The decision is a pure function of `(tool_call, policy)`: same input → same
decision, every time, on every OS. No classifier, no transcript state, no clock.
The contract is frozen in [`input-schema.md`](input-schema.md).

Within that scope, gommage gives you:

- **A tool-agnostic filesystem gate.** The shell-aware mapper maps `fs.read`,
  `fs.write`, and `proc.*` per shell segment, so `Bash` file-verbs (`cat`,
  `cp`, `tee`, redirects) and compound or wrapped commands are gated the same
  way the dedicated `Read` / `Write` tools are. A policy that denies
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

The mapper decomposes a `Bash` `command` string into shell **segments** (split
on the unquoted operators `&&`, `||`, `;`, `|`, and newlines, honouring quotes
and escapes), strips leading wrappers from each segment (`VAR=value`, `env`,
`sudo`, `timeout`, absolute-path heads, `bash -c "<payload>"`), recurses into
`$(...)` / backtick command substitutions, and surfaces genuine output-redirect
targets. Each resulting candidate is run through the stdlib capability rules.

Before policy matching, path-shaped filesystem capabilities (`fs.read`,
`fs.search`, `fs.write`) normalize leading `~`, `~/`, `$HOME/`, and `${HOME}/`
to the `HOME` value used when loading policy. That is a lexical alias rewrite,
not `realpath`: relative paths, `..`, symlinks, `~user`, and other variables are
left untouched.

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

---

## 4. Residuals (all fail-closed → deny, never an allow-leak)

The mapper is best-effort, not a full POSIX shell. The shapes below are **not
yet mapped to their precise gate scope**, so the specific rule (e.g.
`gate-main-push`, a path-scoped `fs.write`) may not fire. Critically, none of
them is an allow-leak: the whole-command `proc.exec:<command>` capability is
always emitted, the compiled hard-stops still run, and the **fail-closed default
denies anything no rule allowed**. A residual costs you a *generic* deny or a
coarser gate, never a silent pass.

- **`git -C <dir> <subcommand>`** — the `-C` working-directory flag sits between
  `git` and the verb, so the precise `git.*` extractor (which anchors on
  `git <verb>`) may not produce the exact scope. The command still emits
  `proc.exec:git -C …`; deny it generically or extend the rule.
- **`eval` / `xargs` wrappers** — `eval "<string>"` and `… | xargs <cmd>`
  build or dispatch a command whose final argv the mapper does not reconstruct.
  The wrapper itself is visible as `proc.exec:eval …` / `proc.exec:xargs …`;
  the wrapped operation is not separately scoped.
- **Refspec `HEAD:main`** — `git push origin HEAD:main` pushes to `main` via a
  source\:destination refspec, but the branch extractor reads the literal ref
  token and does not resolve `HEAD:main` to `refs/heads/main`. It denies
  generically rather than hitting the precise `gate-main-push` scope.

The lesson for these is the same: rely on the fail-closed backstop, and for
strict filesystem or branch gating, restrict raw `Bash` and route operations
through the dedicated tools (see
[`input-schema.md` §4.1](input-schema.md#41-tool-boundary)).

## 5. Operator and org policy can re-open shape-based bypass

The fail-closed posture only holds if your allows stay narrow. A policy that
grants a broad **`proc.exec:*` allow** (or any wildcard that swallows the
per-segment `proc.exec` candidates) re-opens shape-based bypass: a wrapped or
compound command that the mapper could not scope precisely now matches the broad
allow instead of falling through to the fail-closed deny.

Keep allows narrow. Prefer denying or `ask`-gating the specific operations you
care about over granting a wide `proc.exec` allow. Use
`gommage policy lint --strict` to surface over-broad rules, and
`gommage policy layers --json` to confirm an org or project layer has not
introduced a wide allow ahead of your gates.
