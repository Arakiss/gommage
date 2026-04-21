# Comparison with Claude Code's native permission layer

Gommage does not attempt to _replace_ Claude Code's built-in permission system. It attempts to give you a layer you can own.

## What Claude Code ships

Claude Code embeds:

- An in-binary classifier that reads the session transcript and assigns a prior "risk score" to the running agent.
- A `PreToolUse` hook mechanism that lets you slot your own shell command before each tool call (see the official hooks docs).
- A `settings.json` schema with `permissions.allow` / `permissions.deny` for static allow/deny lists matched on tool name + input.

## What Gommage adds

- **Declarative policy.** Your rules live in `~/.gommage/policy.d/*.yaml`. They are the only source of truth. Editing them is reviewable.
- **Capability-level matching.** Policies match on abstract capabilities (`git.push:main`, `fs.write:**/node_modules/**`), not on tool name + raw input strings.
- **Signed, TTL'd, usage-bounded grants.** The native `permissions.allow` list is permanent. Pictos are ephemeral and revocable.
- **Line-signed audit log.** Every decision is recorded and re-verifiable.
- **Determinism guarantee.** The CI runs the determinism suite 10× per build. The classifier makes no such guarantee.

## How they interact

Claude Code's native classifier runs BEFORE the `PreToolUse` hook. That means:

- If the classifier is going to block a call, it blocks before Gommage sees it. The classifier is still authoritative for whatever it decides to flag.
- If the classifier allows the call, it goes to the `PreToolUse` hook. That is where `gommage-mcp` steps in and applies your declarative policy.

**The two layers stack.** If you find that the classifier is over-blocking, you cannot fix that from Gommage — that is in-binary behavior. But you can make the rest of your policy reproducible and debuggable, which is often the bigger win.

## When not to use Gommage

- You're fine with the native classifier's decisions. Use what you have.
- You need OS-level confinement (AppArmor / SELinux / `seccomp-bpf` / macOS sandbox). Gommage is a userspace policy layer, complementary but not a replacement.
- You want an agent-agnostic layer at the OS boundary — Gommage is at the agent boundary.

## When Gommage shines

- Long sessions where the classifier drifts into "paranoid mode" on trivial operations.
- Teams that need their permission rules to be reviewable in PRs.
- Workflows where you want to grant a one-shot `git push origin main` without editing persistent config.
- Anyone wanting a signed, verifiable audit trail of agent decisions.

## Roadmap note

Once Gommage supports generic MCP (v1.0), the same policy + picto store works for Cursor, Continue, Aider, and any agent that speaks MCP. That is the long-term positioning: one policy layer, any agent.
