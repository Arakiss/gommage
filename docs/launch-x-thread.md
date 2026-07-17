# X Thread Draft

Draft only. Do not publish until every required gate in `beta-readiness.md` has
current evidence for the exact release head and asset digests. In particular,
the four native-architecture smokes, partial-install recovery test, required
check snapshot, and successful exact-head workflow runs must be attached to the
launch record.

## Thread

1. Gommage beta is out: deterministic policy-as-code for AI coding agent tool
   calls.

   It sits between Claude Code / Codex-style hooks and the operation the agent
   wants to run, maps tool calls into capabilities, evaluates YAML policy, and
   writes independently signed audit records.

2. The core idea: keep your sandbox, but make the permission layer you care
   about explicit.

   `git push main`, deploys, cloud CLIs, package installs, write-like MCP
   calls, and dangerous shell patterns become reviewable policy instead of
   hidden prompt memory.

3. Pictos are the break-glass path.

   A push to main can require `git.push:main`; the operator grants a signed,
   TTL-bound, one-use picto; the next matching call passes; the grant is
   consumed and recorded.

4. The audit log is authenticated evidence, with an explicit limit.

   Each available decision or lifecycle event is signed independently.
   `state.sqlite` is only a rebuildable local read-model for fast dashboards and
   counters. The current signatures do not prove that records were not deleted,
   truncated, reordered, or duplicated.

5. Existing harnesses are supported as a coexistence path.

   Gommage dry-runs first, preserves unrelated hooks by default, backs up
   changed host files, imports supported Claude denies into YAML while leaving
   native allows outside strict Gommage policy, and gives agents a local harness
   report instead of asking them to guess.

6. What it does not claim:

   It is not an OS sandbox, not universal MCP interception, and not a
   replacement for Codex sandbox modes or host-native controls. Boundaries are
   documented because trust starts with knowing what is not covered. The current
   daemon also trusts its operating-system user; it is not a separately protected
   managed authority.

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
     -o gommage-install.sh
   # Inspect gommage-install.sh before executing it.
   sh gommage-install.sh \
     --with-skill --skill-agent codex --skill-agent claude
   ```

   Release archives are Sigstore-signed and checksum-verified before binary
   writes. The bootstrap above comes from mutable `main`, skill files use a
   separate mutable channel by default, and the three binaries are replaced
   sequentially rather than atomically. This is a compatibility bootstrap, not
   the immutable reference path; review or commit-pin it when it is inside your
   threat model.

9. Useful links:

   - Repo: https://github.com/Arakiss/gommage
   - Beta contract: `docs/beta-contract.md`
   - Existing setups: `docs/existing-setups.md`
   - Agent compatibility: `docs/agent-compatibility.md`
   - Threat model: `THREAT_MODEL.md`

10. Beta means the operator path is now testable end to end, not that the work
    is done.

    Next focus: a separately protected authority mode, cryptographic audit
    completeness, a versioned Picto authority format, atomic install recovery,
    reproducible build evidence, and exact-asset native runtime coverage.

## Short Post

Gommage beta: deterministic policy-as-code for AI coding agent tool calls.

It maps Claude Code / Codex-style tool calls to capabilities, evaluates YAML
policy, supports signed one-use pictos for break-glass actions, and writes
offline-verifiable, independently signed audit records. It remains a user-mode
policy layer, not an OS sandbox or a cryptographically complete ledger.

Demo:

```sh
sh scripts/launch-demo.sh
```

Repo: https://github.com/Arakiss/gommage
