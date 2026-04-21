<p align="center">
  <img src="assets/banner.png" alt="gommage — policy-as-code for AI coding agents" width="100%" />
</p>
<p align="center"><sub><em>The gold dust unmaking the parchment is the gommage. The three pendants below are pictos — signed, single-use grants.</em></sub></p>

# gommage

> _« ce qui n'a pas lieu d'être, s'efface. »_

**Policy-as-code for AI coding agents. Zero heuristics. No prior accumulation. You own the rules.**

Gommage is an independent permission harness for AI coding agents. It supports **Claude Code** and **OpenAI Codex CLI** today via their `PreToolUse` hooks. It sits in front of the agent's tool calls and applies a declarative policy — the same way Kubernetes admission controllers or OPA sit in front of a cluster. Same input, same decision, every time. No classifier, no Bayesian prior accumulating over the transcript, no mystery denies halfway through a task.

## Why

Modern coding agents ship their security layer baked into the binary: a heuristic classifier reads the transcript, assigns a risk prior, and silently vetoes tool calls it dislikes. In short sessions this is invisible. In long sessions the prior drifts: the classifier enters "paranoid mode" and starts denying trivial operations that would have passed earlier. You can't audit it, can't tune it, can't disable it. A 30-second task becomes 30 minutes of fighting the tool.

Gommage takes the opposite stance:

- **Deterministic.** Same `{tool, input}` + same policy → same decision, every time. No state leaks from the transcript into the evaluator.
- **Declarative.** Policies are YAML in `~/.gommage/policy.d/`. Version them, review them in PRs, `cat` them to understand why something got denied.
- **Capability-first.** Tool calls are mapped to capabilities (`git.push:main`, `fs.write:**/node_modules/**`, `net.out:api.stripe.com`). Policies match on capabilities, not on command strings.
- **Break-glass is real.** _Pictos_ (signed, TTL'd, usage-bounded grants) are first-class citizens of the policy. If a picto matches, it passes — no secret layer vetoing from above. The only override is a hardcoded, documented, finite hard-stop set.
- **Out-of-band approval.** `ask` decisions escalate to a human channel (TUI, webhook, push) — never back to the transcript. Keeps the agent and the approver on different wires.

## Status

**v0.1.0-alpha** — usable with **Claude Code** (all tool types) and **OpenAI Codex CLI** (Bash tool only; Codex's `PreToolUse` hook is currently Bash-scoped upstream, tracked at [openai/codex#16732](https://github.com/openai/codex/issues/16732)). Rough edges expected. See [ROADMAP](#roadmap).

## Positioning

Gommage is an **opt-in complement** to whatever permission layer your agent ships with — not an attack on it. You can run both: the native classifier stays where it is, and Gommage handles the decisions you want to own. You'll probably find that once Gommage is handling the policy, the native layer has nothing to flag.

## Install

```sh
# macOS / Linux — one-liner (v0.1 onwards)
curl --proto '=https' --tlsv1.2 -sSf https://gommage.dev/install.sh | sh

# From source (today)
cargo install --path crates/gommage-cli
```

## Quickstart

```sh
# Start an expedition (a.k.a. task context)
gommage expedition start "refactor-auth-middleware"

# Run the daemon (dev mode — logs to stderr)
gommage-daemon --foreground

# Wire the PreToolUse hook in whichever agent(s) you use:
#
# Claude Code — ~/.claude/settings.json
# {
#   "hooks": {
#     "PreToolUse": [
#       { "matcher": "*", "hooks": [{ "type": "command", "command": "gommage-mcp" }] }
#     ]
#   }
# }
#
# OpenAI Codex CLI — ~/.codex/hooks.json
# {
#   "PreToolUse": [
#     { "matcher": "Bash", "hooks": [{ "type": "command", "command": "gommage-mcp" }] }
#   ]
# }
#
# See examples/claude-code-setup.md and examples/codex-setup.md.

# Check a policy file
gommage policy lint ~/.gommage/policy.d/10-defaults.yaml

# Grant a one-shot picto for pushing to main
gommage grant \
  --scope "git.push:main" \
  --uses 1 \
  --ttl 10m \
  --reason "hotfix for INC-2461"

# Watch decisions live
gommage tail

# Explain a past decision
gommage explain <audit-id>

# Close the expedition (resets the canvas)
gommage expedition end
```

## Architecture

```
┌──────────┐     tool call     ┌─────────────────────┐
│  Agent   │ ────────────────► │  gommage daemon     │
│          │                   │                     │
│ Claude   │ ◄─── decision ─── │  • Capability mapper│
│ Code     │                   │  • Policy evaluator │
│ Cursor…  │                   │  • Picto store      │
└──────────┘                   │  • Audit writer     │
                               └──────────┬──────────┘
                                          │
                                          ▼
                               ┌─────────────────────┐
                               │ ~/.gommage/         │
                               │  ├─ policy.d/*.yaml │
                               │  ├─ capabilities.d/ │
                               │  ├─ pictos.sqlite   │
                               │  ├─ audit.log       │
                               │  └─ key.ed25519     │
                               └─────────────────────┘
```

Full details in [`docs/architecture.md`](docs/architecture.md).

## Vocabulary

Borrowed from _Expedition 33_ (Sandfall Interactive, 2025) — functional, not ornamental:

| Term | Meaning |
|---|---|
| **Picto** | A signed grant with scope + TTL + max_uses. Gives an agent a temporary capability. |
| **Gommaged** | Verb. "Your tool call got gommaged" = denied by policy. |
| **Canvas** | The active set of policies governing a task. |
| **Expedition** | An atomic task/session. `gommage expedition start/end`. |

## Policy example

```yaml
# ~/.gommage/policy.d/10-defaults.yaml

- name: no-writes-to-build-artifacts
  decision: gommage
  match:
    any_capability:
      - "fs.write:**/node_modules/**"
      - "fs.write:**/.next/**"
      - "fs.write:**/.git/**"
  reason: "build artifacts are not edit targets"

- name: gate-main-push
  decision: ask_picto
  required_scope: "git.push:main"
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
  reason: "pushes to main require a signed picto"

- name: allow-project-reads
  decision: allow
  match:
    all_capability:
      - "fs.read:${EXPEDITION_ROOT}/**"
```

Full cookbook in [`docs/policy-cookbook.md`](docs/policy-cookbook.md).

## Determinism guarantee

Gommage ships a regression suite that runs ~10k `{tool, input}` fixtures with an expected decision oracle, in-order and shuffled. If any decision flips based on ordering, the build fails. See [`tests/determinism/`](tests/determinism/).

## Roadmap

**v0.1 (MVP)** — this release
- Daemon + CLI + PreToolUse hook adapter
- Supported agents: **Claude Code** (all tool types), **OpenAI Codex CLI** (Bash tool only — limited by Codex's current hook surface)
- YAML policy + capability mappers for Bash / git / vercel / bun / docker
- Pictos (signed, TTL, usage-bounded)
- Append-only signed audit log
- Hardcoded hard-stop set
- Determinism-critical deps pinned with `=x.y.z`, `cargo-deny` + `cargo-semver-checks` + conventional-commits in CI, release-please for automated versioning

**v1.0** — hackable by others
- Rego policies via `regorus`
- TUI dashboard (`gommage watch`) with live approvals
- Broader Codex coverage once upstream `PreToolUse` widens past Bash (openai/codex#16732)
- Cursor integration (Cursor has hooks but they run _after_ the native permission layer — needs a different wiring path; evaluated for v1.0)
- Generic MCP server mode for agents without a PreToolUse concept
- Community policy packs in `gommage-policies/`
- Webhook out-of-band
- Signed binary releases + SBOM

**Not planned** — either no hook API or known permission-bypass bugs in the hook layer: Aider, Zed, Continue, Cline. Revisited when upstream matures.

**v1.x** — scale
- Push approvals (ntfy, Slack native)
- Prometheus metrics endpoint
- Team-shared picto store (encrypted on S3)
- Policy inheritance (org → project → user)

## Not in scope

Gommage is a permission harness, not a security product:

- **Not an OS permission system.** AppArmor / SELinux operate below it; they are complementary.
- **Does not defend the agent binary itself.** If Claude Code is compromised at binary level, Gommage cannot help.
- **Not a secrets manager.** Use Vault / 1Password / sops; Gommage _protects_ them, doesn't store them.
- **Not a network proxy.** Use `mitmproxy` if you need TLS inspection.
- **Not generic policy-as-code.** OPA covers that. Gommage is optimized for the narrow case "AI agent decides to exec X".

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full statement.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT. See [`LICENSE`](LICENSE).
