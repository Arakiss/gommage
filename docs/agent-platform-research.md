# Agent Platform Research Cadence

This is the recurring compatibility research log for Gommage's host-agent
surfaces. Treat it as part of the product safety loop: upstream agent behavior
changes invalidate Gommage's trust claims until the matrix, tests, and docs are
updated.

Last research pass: **2026-05-12**

Local baselines used in this pass:

- Codex CLI: `0.130.0`
- Claude Code: `2.1.139`

Primary sources checked:

- OpenAI Codex hooks: <https://developers.openai.com/codex/hooks>
- OpenAI Codex configuration reference:
  <https://developers.openai.com/codex/config-reference>
- OpenAI Codex config schema:
  <https://developers.openai.com/codex/config-schema.json>
- OpenAI Codex sandboxing:
  <https://developers.openai.com/codex/concepts/sandboxing>
- OpenAI Codex skills: <https://developers.openai.com/codex/skills>
- OpenAI Codex plugins:
  <https://developers.openai.com/codex/plugins/build>
- OpenAI Codex app server:
  <https://developers.openai.com/codex/app-server>
- Claude Code hooks: <https://code.claude.com/docs/en/hooks>
- Claude Code settings: <https://code.claude.com/docs/en/settings>
- Claude Code MCP: <https://code.claude.com/docs/en/mcp>

## Current Findings

### Codex

- The local Codex `0.130.0` feature list exposes `hooks` as the stable hook
  feature. It does not list `codex_hooks`. The generated config schema includes
  `features.hooks`; some OpenAI docs pages still mention
  `features.codex_hooks`. Gommage should write the canonical
  `features.hooks = true` and treat `features.codex_hooks` as legacy.
- Codex discovers lifecycle hooks from `hooks.json`, inline `[hooks]` in
  `config.toml`, and plugin-bundled lifecycle config. If multiple hook sources
  exist, matching hooks all run; higher-precedence config layers do not replace
  lower-precedence hooks.
- Codex hook events relevant to Gommage are `PreToolUse`,
  `PermissionRequest`, `PostToolUse`, `UserPromptSubmit`, `Stop`, and
  `SessionStart`.
- Codex matchers for `PreToolUse`, `PermissionRequest`, and `PostToolUse`
  apply to `tool_name`. Current tool names include `Bash`, `apply_patch`, and
  MCP names such as `mcp__server__tool`; `apply_patch` can also be matched with
  `Edit` or `Write`.
- Codex hook coverage is still not a complete enforcement boundary.
  `unified_exec` gives richer shell handling, but hook interception is
  documented as incomplete, and non-shell / non-MCP tools such as WebSearch are
  outside the current hook surface.
- Codex `PreToolUse` can deny a Bash command through hook JSON or exit code 2.
  `permissionDecision = "allow"` / `"ask"`, `updatedInput`, and additional
  context on `PreToolUse` are parsed but currently fail open.
- Codex `PermissionRequest` can allow, deny, or decline a prompt before the
  normal approval flow. If multiple matching hooks decide, deny wins.
- Codex `PostToolUse` can add context or replace the visible result, but it
  cannot undo side effects because the tool already ran.
- Codex sandboxing remains the lower-level safety boundary. The current
  low-risk automation baseline is still `sandbox_mode = "workspace-write"` plus
  `approval_policy = "on-request"`, optionally with `approvals_reviewer =
  "auto_review"`.
- Codex now has stronger distribution primitives for Gommage-adjacent assets:
  skills, plugins, plugin-bundled MCP servers, plugin-bundled lifecycle hooks,
  and external-agent config import for Claude artifacts such as `CLAUDE.md`,
  skills, plugins, and MCP config.
- Codex telemetry includes hook and tool metrics (`hooks.run`,
  `hooks.run.duration_ms`, tool and MCP call metrics). Gommage can eventually
  correlate its signed audit log with host telemetry without making telemetry a
  decision input.

### Claude Code

- Claude Code hook configuration now spans user, project, local project,
  managed policy, plugin hooks, and hook definitions inside skills or agents.
- Claude Code supports more hook handler types than Gommage currently writes:
  `command`, `prompt`, `agent`, `http`, and `mcp_tool`.
- Claude Code hooks can be inspected with `/hooks`, including source and handler
  type. Gommage docs should point users there when debugging coexistence.
- Claude Code common hook fields include `session_id`, `transcript_path`,
  `cwd`, and `permission_mode`. Some events also expose effort/model-related
  fields.
- Claude Code supports hook-injected `additionalContext`, including from
  `UserPromptSubmit`, `SessionStart`, and supported JSON hook outputs.
- Claude Code event coverage is broader than Gommage's current default wiring:
  `ConfigChange`, `CwdChanged`, `FileChanged`, `WorktreeCreate`,
  `WorktreeRemove`, `PreCompact`, `SessionEnd`, `Elicitation`, async hooks,
  and subagent-oriented stop behavior.
- `ConfigChange` hooks can block settings changes from taking effect, except
  enterprise policy settings, which still fire hooks for auditing but cannot be
  blocked.
- `PreToolUse` can return `permissionDecision = "defer"` in non-interactive
  `-p` mode for integrations that need to pause and resume a deferred tool
  call through an external UI.
- Async hooks let Claude continue while background validation runs; when the
  hook finishes, `systemMessage` or `additionalContext` can be delivered on a
  later turn.
- Claude Code settings now make `permissions.deny` the documented way to hide
  sensitive files from discovery and reads. Gommage's import path should keep
  treating deny imports as high priority.

## Product Implications

Priority order:

1. **Fix Codex hook feature config.** Write `features.hooks = true`, keep
   status/uninstall compatibility for legacy `features.codex_hooks`, and update
   docs.
2. **Build a real hook payload capture matrix.** Capture Codex and Claude Code
   payloads for every event before widening Gommage claims.
3. **Codex `apply_patch` support.** Add matcher coverage, mapper rules, policy
   fixtures, and host smoke evidence before making it default.
4. **Codex MCP hook support.** Either map Codex MCP hook payloads directly or
   keep recommending `gommage-mcp --gateway` until direct coverage has fixtures.
5. **Codex `PermissionRequest` integration.** Explore using Gommage policy and
   active pictos to deny or allow eligible approval requests. Do not auto-allow
   broad approvals until the policy semantics are explicit.
6. **Post-use audit lanes.** Use `PostToolUse` for audit enrichment and
   validation feedback, not as a preventive control.
7. **Claude `ConfigChange` guard.** Add optional protection for Claude settings,
   plugin, and skill changes so host configuration drift is auditable and, when
   possible, blockable.
8. **Claude async validation.** Consider a Gommage-managed async validation
   pattern for tests/formatters after file writes, clearly separate from
   preventive policy.
9. **Distribution packaging.** Package Gommage skill, hook wiring, and optional
   MCP gateway helpers as Codex and Claude plugins once the installer path is
   stable enough.

## Routine Cadence

Run this research pass:

- every two weeks while Gommage is beta;
- before every beta release;
- immediately when a tester reports host-agent config or hook drift.

Checklist:

1. Record local versions:
   - `codex --version`
   - `codex features list`
   - `claude --version`
   - `claude --help`
2. Re-read official docs linked at the top of this file.
3. Re-run repository drift search:
   - `rg -n "codex_hooks|features\\.hooks|PreToolUse|PermissionRequest|PostToolUse|ConfigChange|Worktree|Elicitation" docs README.md examples crates -S`
4. Compare docs and local CLI behavior. When they disagree, prefer generated
   schemas and local feature lists for config keys, and document the conflict.
5. Update `docs/agent-compatibility.md`, `docs/comparison-with-codex.md`,
   `docs/comparison-with-claude-code.md`, and examples in the same PR.
6. Do not claim support for a new hook surface until all of these exist:
   - captured real payloads;
   - mapper tests;
   - policy fixtures;
   - host smoke evidence;
   - updated rollback/diagnostic docs.

## Standing Non-Goals

- Do not replace Codex or Claude native permissions.
- Do not describe hooks as OS confinement.
- Do not rely on host telemetry as an input to deterministic policy decisions.
- Do not widen default hook matchers without mapper coverage and fixtures.
