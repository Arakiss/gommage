# Product Roadmap

Gommage is an alpha policy decision and audit harness for AI coding agents. The
roadmap is deliberately ordered around trust: first make installation and
recovery boring, then make policy authoring excellent, then expand approvals,
host coverage, and ecosystem distribution.

The beta bar is tracked separately in [`beta-readiness.md`](beta-readiness.md).
This page describes the product sequence after the current signed alpha
installer line.

## Roadmap principles

- Runtime decisions stay deterministic. Advisory generators may use richer
  context, but `allow` / `deny` / `ask` must remain a pure function of mapped
  capabilities and policy.
- Every feature that mutates a user's system needs a dry-run, adjacent backup,
  and rollback story.
- Human-facing output can be beautiful; agent-facing output must be stable
  JSON or versioned YAML.
- New policy behavior needs fixtures before it is trusted.
- Gommage composes with native agent permissions and OS sandboxes; it does not
  pretend a hook is a sandbox.

## Milestone 0: Beta Safety And DX

Goal: a new operator can install, inspect, verify, recover, and report issues
without reading source code or improvising shell recovery.

Features:

- `gommage quickstart --dry-run --json`
  - Reports every file, hook, skill, service, policy import, backup, and
    self-test that quickstart would touch.
  - Marks risky native permission imports as skipped with actionable reasons.
- `gommage report bundle --redact`
  - Produces a support bundle with `verify --json`, `doctor --json`, agent
    status, release/version data, service state, policy hashes, and redacted
    config snippets.
- Agent command manifest
  - A single versioned manifest defines stable commands used by README, skills,
    docs, and CI command-contract tests.
- Host E2E smoke matrix
  - Fresh install and rollback drills for macOS, Ubuntu, Fedora or Arch family,
    and an explicit CachyOS operator script.

Primary code surfaces:

- `crates/gommage-cli/src/quickstart.rs`
- `crates/gommage-cli/src/verify.rs`
- `crates/gommage-cli/src/doctor.rs`
- `crates/gommage-cli/src/agent_status.rs`
- `scripts/check-agent-command-contracts.sh`
- `skills/gommage/SKILL.md`
- `docs/diagnostics.md`

Exit criteria:

- `quickstart --dry-run --json` is safe on a dirty real home.
- Report bundles contain enough data to debug install failures without asking
  for raw dotfiles.
- The documented CachyOS test path runs without deadlocking the agent.

## Milestone 1: Policy Authoring Flywheel

Goal: users can move from observed tool calls to reviewed policy, fixtures, and
regression protection in one loop.

Features:

- `gommage replay --audit <file> --policy <dir>`
  - Re-evaluates historical audit entries against a new policy set.
  - Reports decisions that would change before the operator trusts the policy.
- `gommage policy diff --from <dir> --to <dir> --against <audit.log>`
  - Summarizes allow-to-deny, deny-to-allow, and ask-scope changes.
- `gommage policy suggest`
  - Generates candidate YAML rules and fixture cases from audit logs, native
    permissions, or captured hook payloads.
  - Never writes active policy without an explicit review/write flag.
- `gommage explain --trace`
  - Shows canonical tool call, emitted capabilities, evaluated rule order,
    shadowed rules, picto matching, and fixture suggestions.
- `gommage policy lint --strict`
  - Detects unreachable rules, overbroad allows, duplicate denials, invalid
    picto scopes, mapper rules without fixtures, and capabilities no mapper can
    emit.

Primary code surfaces:

- `crates/gommage-cli/src/audit_cmd.rs`
- `crates/gommage-cli/src/policy_cmd.rs`
- `crates/gommage-cli/src/map.rs`
- `crates/gommage-core/src/evaluator.rs`
- `crates/gommage-core/src/policy.rs`
- `tests/determinism/`
- `examples/policy-fixtures.yaml`

Exit criteria:

- A real audit log can be replayed against two policies with a stable JSON
  report.
- Suggested rules produce fixtures before they are considered usable.
- Strict lint can run in CI and fail only on actionable policy issues.

## Milestone 2: Live Operator Loop

Goal: approval and audit become a live workflow instead of scattered commands.

Features:

- Operator watch mode
  - `gommage tui --watch --watch-ticks <n>` now provides bounded plain-text
    refreshes for demos, headless operators, and issue reports.
  - `gommage tui --stream --stream-ticks <n>` now provides a compact live
    decision/event feed backed by daemon IPC with signed audit-log fallback.
    Next step: merge in active pictos and daemon health without making human
    output an automation contract.
- Local picto approval flow
  - The CLI approval path, TUI approve/deny confirmation, and TUI TTL/use-count
    presets now exist. Next step is a richer inline form with editable reason
    text and policy-context preview.
- Approval provider interface
  - Generic, Slack-shaped, and Discord-shaped webhook payloads now exist through
    `gommage approval webhook`, including payloads in dry-run JSON and optional
    HMAC-SHA256 signatures over `<timestamp>.<exact HTTP body>`. Next step is
    native provider callbacks and native ntfy provider support.
- Metrics endpoint
  - Local counters for decisions, denials, asks, picto outcomes, audit anomalies,
    and daemon health.

Primary code surfaces:

- `crates/gommage-cli/src/main.rs`
- `crates/gommage-cli/src/audit_cmd.rs`
- `crates/gommage-daemon/src/main.rs`
- `crates/gommage-core/src/picto.rs`
- `docs/pictos.md`
- `docs/architecture.md`

Exit criteria:

- A user can approve a one-shot picto from the TUI, tune grant TTL/use-count
  before confirmation, and verify the audit entry afterward.
- Webhook approval supports signed callbacks or an equivalent replay-resistant
  confirmation channel.
- Human TUI output is never part of an automation contract.

## Milestone 3: Host Coverage Beyond Hooks

Goal: broaden useful coverage without overstating what Gommage can observe.

Features:

- MCP gateway mode
  - A policy-enforcing MCP proxy for agents whose native hook surface is missing
    or incomplete.
- Project-local harness mode
  - `gommage project init` creates reviewed fixtures and project policy that can
    be layered with user policy.
- Policy inheritance
  - Explicit precedence: hard-stops, org, project, user imports, local pictos.
- Sandbox bridge
  - Generate Codex, bwrap, AppArmor, or macOS Seatbelt suggestions from policy
    intent, documented as advisory confinement helpers.

Primary code surfaces:

- `crates/gommage-mcp/src/main.rs`
- `crates/gommage-core/src/runtime.rs`
- `crates/gommage-core/src/mapper.rs`
- `docs/agent-compatibility.md`
- `THREAT_MODEL.md`

Exit criteria:

- MCP gateway has fixtures proving read/write/call forwarding and denial
  behavior.
- Project policy layering is deterministic and documented.
- Sandbox bridge output is clearly advisory and never described as equivalent
  to policy enforcement.

## Milestone 4: Ecosystem And Distribution

Goal: make Gommage easy to adopt, inspect, package, and share.

Features:

- Signed policy packs
  - `gommage pack search`, `pack install`, `pack verify`, and pack-level
    fixtures/changelogs.
- Browser playground
  - Static WASM or JSON playground for mapping, evaluation, explain traces, and
    fixture generation without sending data to a server.
- crates.io publishing
  - Publish crates in dependency order after the package gates are green.
- Homebrew tap and AUR package
  - Keep the signed GitHub Release installer as the source of truth, but make
    native package-manager installs available for common operator paths.
- SBOM and provenance
  - Add SBOM assets, GitHub artifact attestations, and a `verify-release`
    command for operators.

Primary code surfaces:

- `scripts/install.sh`
- `scripts/check-crates-publish-readiness.sh`
- `docs/publishing.md`
- `.github/workflows/`
- `crates/gommage-stdlib/`

Exit criteria:

- Package-manager installs verify the same signed release artifacts or document
  their trust boundary clearly.
- Policy packs cannot install without version and provenance evidence.
- `cargo install gommage-cli` is supported only after the publish gate passes.

## Recommended execution order

1. Ship Milestone 0 before any public beta announcement.
2. Ship `replay`, `policy diff`, and `explain --trace` before `policy suggest`.
3. Ship `policy suggest` before community policy packs.
4. Extend TUI watch with decision-stream and active-picto panes before remote
   approval providers.
5. Ship MCP gateway before claiming broader host support.
6. Ship package-manager integrations only after the signed release installer has
   stayed green through multiple alpha releases.

## 1.0 Bar

Version 1.0 is the point where Gommage should feel like a product people can
recommend without caveats beyond the documented threat model. The release does
not need every deferred idea, but it does need excellence in the core loop.

Required product qualities:

- Install, quickstart, verify, TUI inspection, report bundle, and uninstall are
  a complete loop on macOS and Linux without hand-written recovery shell.
- `gommage tui` is a polished local command center: readable on small terminals,
  keyboard navigable, useful without docs, and explicitly separate from stable
  JSON automation contracts.
- Policy authoring has a flywheel: capture or replay observed calls, explain
  the decision trace, generate candidate fixtures, and review before writing.
- Approval flows are out-of-band and auditable. A picto can be created,
  confirmed, consumed, revoked, approved from a pending request, denied, and
  explained without relying on chat memory.
- Recovery behavior is boring: every command that mutates host config has a
  dry-run, backup, restore, and purge story.

Required trust qualities:

- Hard-stops, bypass semantics, picto lifecycle, audit verification, and release
  signing all have regression tests and public docs.
- `audit-verify --explain` is good enough for forensics: it reports bypasses,
  anomalies, policy versions, expeditions, and signed lifecycle events.
- Host support claims are narrow and evidence-backed. Unsupported hook timing is
  named as unsupported instead of hidden behind roadmap language.
- Release assets include archives, checksums, Sigstore bundles, and provenance
  evidence for every supported platform.

Required ecosystem qualities:

- GitHub Releases remain the source of truth for signed binaries.
- crates.io publication is either complete for the public crates or explicitly
  deferred with current gate evidence.
- Homebrew/AUR/native packages verify the same trust boundary or document their
  weaker boundary clearly.
- Skills, README, command manifest, and CI command-contract tests are generated
  or checked from one stable source of truth.

## Deferred ideas

- Team-shared encrypted picto store.
- Native Slack app.
- Organization policy registry.
- Automatic OS sandbox enforcement.
- Enterprise admin console.

These may be valuable, but they should wait until the beta safety and policy
authoring loops are stable.
