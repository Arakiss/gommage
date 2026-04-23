# Changelog — gommage-mcp

## [0.5.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.4.1-alpha.1...gommage-mcp-v0.5.0-alpha.1) (2026-04-23)


### Features

* add out-of-band approval workflow ([159aa6c](https://github.com/Arakiss/gommage/commit/159aa6c19706ef0a2ea6db92f2407b002fedcf1f))
* map agent web and mcp tools ([c3601c6](https://github.com/Arakiss/gommage/commit/c3601c6502a35c6e0b7c735998011a892b3ca7d6))
* sign approval webhook deliveries ([acb4417](https://github.com/Arakiss/gommage/commit/acb4417f2ce4e567485448676547b1e10e3b6382))


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))
* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))
* harden bypass audit semantics ([3663dc9](https://github.com/Arakiss/gommage/commit/3663dc94ef01fe94a1527bf29985a1b85942f76d))
* harden hard-stop parsing and release framing ([0490dac](https://github.com/Arakiss/gommage/commit/0490dac4ea2acae60ac2ab105a23cc1454484675))
* polish recovery diagnostics ([1b7e7c1](https://github.com/Arakiss/gommage/commit/1b7e7c1e55ee90dc6d91218df7896e44e33b940b))
* prevent quickstart deadlocks ([2d9c967](https://github.com/Arakiss/gommage/commit/2d9c967faff8f7b1199d08fac2a43363fa6b7e26))
* satisfy strict clippy gate ([b5385cb](https://github.com/Arakiss/gommage/commit/b5385cb640195fa647a00ce5c00dd8b49b7fe596))
* support companion binary introspection ([a2db821](https://github.com/Arakiss/gommage/commit/a2db821d2829cebf4d2083fda000a9682dab634d))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))
* lock agent command contracts ([5056758](https://github.com/Arakiss/gommage/commit/505675890ec4b3d128c2eab03615b99ace38b54e))

## [0.4.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.4.0-alpha.1...gommage-mcp-v0.4.1-alpha.1) (2026-04-23)


### Bug fixes

* harden hard-stop parsing and release framing ([0490dac](https://github.com/Arakiss/gommage/commit/0490dac4ea2acae60ac2ab105a23cc1454484675))

## [0.4.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.3.1-alpha.1...gommage-mcp-v0.4.0-alpha.1) (2026-04-23)


### Features

* sign approval webhook deliveries ([acb4417](https://github.com/Arakiss/gommage/commit/acb4417f2ce4e567485448676547b1e10e3b6382))

## [0.3.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.3.0-alpha.1...gommage-mcp-v0.3.1-alpha.1) (2026-04-23)

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.5-alpha.1...gommage-mcp-v0.3.0-alpha.1) (2026-04-22)


### Features

* add out-of-band approval workflow ([159aa6c](https://github.com/Arakiss/gommage/commit/159aa6c19706ef0a2ea6db92f2407b002fedcf1f))

## [0.2.5-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.4-alpha.1...gommage-mcp-v0.2.5-alpha.1) (2026-04-22)

## [0.2.4-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.3-alpha.1...gommage-mcp-v0.2.4-alpha.1) (2026-04-22)


### Bug fixes

* harden bypass audit semantics ([3663dc9](https://github.com/Arakiss/gommage/commit/3663dc94ef01fe94a1527bf29985a1b85942f76d))
* polish recovery diagnostics ([1b7e7c1](https://github.com/Arakiss/gommage/commit/1b7e7c1e55ee90dc6d91218df7896e44e33b940b))

## [0.2.3-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.2-alpha.1...gommage-mcp-v0.2.3-alpha.1) (2026-04-22)


### Bug fixes

* prevent quickstart deadlocks ([2d9c967](https://github.com/Arakiss/gommage/commit/2d9c967faff8f7b1199d08fac2a43363fa6b7e26))
* satisfy strict clippy gate ([b5385cb](https://github.com/Arakiss/gommage/commit/b5385cb640195fa647a00ce5c00dd8b49b7fe596))


### Documentation

* lock agent command contracts ([5056758](https://github.com/Arakiss/gommage/commit/505675890ec4b3d128c2eab03615b99ace38b54e))

## [Unreleased]

### Added

- `GOMMAGE_BYPASS=1` break-glass mode can still recover malformed hook
  payloads without opening `~/.gommage`, but valid payloads now run through
  compiled hard-stop checks and write signed `bypass_activated` audit events
  when a usable home/key exists.

## [0.2.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.1-alpha.1...gommage-mcp-v0.2.2-alpha.1) (2026-04-22)


### Bug fixes

* support companion binary introspection ([a2db821](https://github.com/Arakiss/gommage/commit/a2db821d2829cebf4d2083fda000a9682dab634d))

## [0.2.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.2.0-alpha.1...gommage-mcp-v0.2.1-alpha.1) (2026-04-22)

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.1.1-alpha.1...gommage-mcp-v0.2.0-alpha.1) (2026-04-21)


### Features

* map agent web and mcp tools ([c3601c6](https://github.com/Arakiss/gommage/commit/c3601c6502a35c6e0b7c735998011a892b3ca7d6))


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Changed

- Claude `Grep` and `Glob` hook inputs are enriched with reserved
  `__gommage_*` path fields derived from hook `cwd`, allowing relative search
  tools to map to deterministic filesystem capabilities.
- Daemon-absent fallback now writes signed audit entries and uses verified
  picto lookup/consume semantics.
- Fallback is only used when the daemon socket is absent; daemon protocol
  errors no longer silently re-run in-process.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-mcp-v0.1.0-alpha.1...gommage-mcp-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. PreToolUse hook adapter. Compatible with Claude Code and —
verified via research, integration pending — OpenAI Codex CLI, whose
`~/.codex/hooks.json` PreToolUse schema is near-identical.
