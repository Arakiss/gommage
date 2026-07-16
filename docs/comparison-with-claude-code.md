# Comparison with Claude Code's native controls

Gommage complements Claude Code's permission rules, hooks, and optional Bash
sandbox. It does not replace them. The default integration adds a deterministic
capability-policy decision at Claude Code's `PreToolUse` boundary for the tool
names Gommage maps.

## What Claude Code ships

- **Permission rules and modes.** Claude Code supports `allow`, `ask`, and
  `deny` rules across user, project, managed, and other settings scopes. Native
  deny and ask rules continue to apply even when a hook returns allow.
- **`PreToolUse` hooks.** These run before the permission prompt. A hook can
  block a call, force a prompt, or let the normal flow continue. A blocking hook
  takes precedence over an allow rule.
- **Optional OS-enforced Bash sandboxing.** Claude Code can constrain Bash and
  its subprocesses with filesystem and network policy, using Seatbelt on macOS
  and bubblewrap on Linux/WSL2. This boundary applies to Bash, not every Claude
  tool, and has documented escape and configuration limits.

See Claude Code's official
[permission](https://code.claude.com/docs/en/permissions),
[hook](https://code.claude.com/docs/en/hooks), and
[sandbox](https://code.claude.com/docs/en/sandboxing) documentation for the
current host contract.

## What Gommage adds

- **Capability policy.** Active organization, user, and optional project YAML
  layers evaluate mapped effects such as `git.push:main` and
  `fs.write:<path>`. Project policy can tighten but cannot add `allow` rules.
- **Cross-tool mapping.** A supported Bash file operation and a dedicated
  Claude file tool can reach the same filesystem capability instead of relying
  only on the host tool name and raw argument pattern.
- **Signed, expiring, usage-bounded grants.** Pictos provide Gommage's own
  revocable approval mechanism, including optional exact-input binding.
- **Independently signed audit records.** Each record Gommage successfully
  appends can be verified offline. The current format does not prove file
  completeness or order.
- **A tested determinism contract.** Gommage's mapper and policy evaluator run
  the forward/shuffled determinism matrix in CI. This is a claim about Gommage,
  not about undocumented Claude Code internals.

## How the layers interact

For a tool name matched by the installed hook group, Claude Code invokes
Gommage at `PreToolUse` before the normal permission prompt:

- a Gommage deny blocks the call;
- a Gommage `ask_picto` result enters the documented approval path;
- a Gommage allow does not override a native Claude deny or ask rule;
- if enabled, Claude Code's sandbox still constrains Bash and its subprocesses
  after the policy layers allow execution.

Calls Claude Code does not forward to the matched hook, runtime behavior absent
from the submitted tool input, and direct terminal commands remain outside
Gommage. The exact default mapper coverage is maintained in
[`agent-compatibility.md`](agent-compatibility.md).

## When native Claude controls may be enough

- The native permission rules and optional Bash sandbox already express the
  boundary you need.
- You do not need Gommage's cross-tool capabilities, Pictos, or signed decision
  records.
- Your required operation is outside the mapped `PreToolUse` surface.

## When the combined stack helps

- The same capability should be governed consistently across Bash and dedicated
  tools.
- Policy needs organization, user, and tightening-only project composition.
- An operator needs a short-lived or exact-input grant without editing a
  persistent allow rule.
- You want Gommage's deterministic policy result and independently verifiable
  decision records while retaining Claude Code's native permission and sandbox
  controls.
