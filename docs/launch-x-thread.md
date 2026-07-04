# X Thread Draft

Draft only. Replace placeholders after the beta release exists and verification
passes.

## Thread

1. Gommage beta is out: deterministic policy-as-code for AI coding agent tool
   calls.

   It sits between Claude Code / Codex-style hooks and the operation the agent
   wants to run, maps tool calls into capabilities, evaluates YAML policy, and
   writes signed audit evidence.

2. The core idea: keep your sandbox, but make the permission layer you care
   about explicit.

   `git push main`, deploys, cloud CLIs, package installs, write-like MCP
   calls, and dangerous shell patterns become reviewable policy instead of
   hidden prompt memory.

3. Pictos are the break-glass path.

   A push to main can require `git.push:main`; the operator grants a signed,
   TTL-bound, one-use picto; the next matching call passes; the grant is
   consumed and recorded.

4. The audit log is the source of truth.

   Every decision is signed line-by-line. `state.sqlite` is only a rebuildable
   local read-model for fast dashboards and counters. Delete it and rebuild from
   `audit.log`.

5. Existing harnesses are supported as a coexistence path.

   Gommage dry-runs first, preserves unrelated hooks by default, backs up
   changed host files, imports supported Claude permissions into YAML, and
   gives agents a local harness report instead of asking them to guess.

6. What it does not claim:

   It is not an OS sandbox, not universal MCP interception, and not a
   replacement for Codex sandbox modes or host-native controls. Boundaries are
   documented because trust starts with knowing what is not covered.

7. Try the local demo from a checkout:

   ```sh
   sh scripts/launch-demo.sh
   ```

   It captures ask-picto, one-use picto allow, hard-stop deny, signed audit
   verification, state rebuild/verify, beta check, and a TUI snapshot in an
   isolated temporary home.

8. Install path:

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf \
     https://raw.githubusercontent.com/Arakiss/gommage/main/scripts/install.sh \
     | sh -s -- --with-skill --skill-agent codex --skill-agent claude
   ```

   Release archives are Sigstore-signed and checksum-verified before install.

9. Useful links:

   - Repo: https://github.com/Arakiss/gommage
   - Beta contract: `docs/beta-contract.md`
   - Existing setups: `docs/existing-setups.md`
   - Agent compatibility: `docs/agent-compatibility.md`
   - Threat model: `THREAT_MODEL.md`

10. Beta means the operator path is now testable end to end, not that the work
    is done.

    Next focus: broader Codex hook coverage, crates.io publishing gate,
    package-manager installs, optional MCP gateway evidence, and community
    policy packs.

## Short Post

Gommage beta: deterministic policy-as-code for AI coding agent tool calls.

It maps Claude Code / Codex-style tool calls to capabilities, evaluates YAML
policy, supports signed one-use pictos for break-glass actions, and writes
offline-verifiable signed audit logs.

Demo:

```sh
sh scripts/launch-demo.sh
```

Repo: https://github.com/Arakiss/gommage
