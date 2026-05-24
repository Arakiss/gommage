# Gommage Agent Operating Rules

These rules are part of the project contract for autonomous coding agents
working in this repository.

## Default Work Loop

- Communicate with the developer in Spanish.
- Keep code, comments, committed documentation, and commit messages in English.
- Prefer Bun for JavaScript tooling and the existing Rust/Just commands for
  repository validation.
- Start meaningful sessions with `nahuali briefing` when the CLI is available.
- Commit and push coherent checkpoints frequently during long work sessions.

## Goals First

Use native Codex Goals as the default loop for sustained work. Start or keep a
Goal active when the task is larger than one normal turn and has a verifiable
stopping condition, especially release trains, RC hardening, migrations, large
refactors, retry loops, eval iterations, and multi-checkpoint product work.

A good project Goal must name:

- the single durable objective;
- the stopping condition;
- non-goals and risk boundaries;
- files, docs, issues, or run files to inspect first;
- validation commands and artifacts;
- when to commit, push, publish, or pause.

Do not replace an active Goal unless the developer asks, the objective is
actually achieved, or the work is genuinely blocked. While a Goal is active,
treat it as the primary execution contract.

## Ralph-In-Loop

Use `$ralph-in-loop` when the work needs durable phase governance, auditability,
or continuation across context transitions. Ralph is not a replacement for a
native Goal when Goals are available. Prefer this relationship:

- Goal: primary autonomous execution harness and stop condition.
- Ralph run files: durable plan, evidence log, phase state, and resume surface.
- Nahuali: durable memory for decisions, outcomes, and future intentions.

For long RC/release work, it is usually correct to use both: keep the native
Goal active and maintain `.codex-runs/<date>-<slug>/` as the auditable run
state.

Re-evaluate whether Ralph is still needed at each major checkpoint. If the Goal
alone now carries the objective and evidence clearly, stop expanding Ralph
scope. If the work remains multi-phase, release-sensitive, or likely to span
context transitions, keep Ralph updated.

## RC And Release Work

For RC hardening and release trains:

- Do not publish empty or noise releases.
- Publish prerelease artifacts only after meaningful user-facing or
  release-readiness changes.
- Verify release assets with strict gates, including full supported platform
  matrix checks when available.
- Keep installer, update/upgrade, host-smoke, launch-demo, evals, docs, and
  CI/release automation aligned.
- Stop only when `main` is clean and synced, relevant GitHub checks are green,
  latest installable artifacts are verified, no in-scope blockers remain, and
  durable state records the evidence.

Out of scope unless the developer explicitly asks:

- crates.io publication;
- OS-level sandbox claims or confinement promises;
- destructive real-home mutation;
- unrelated backlog work during a focused release train.
