# Changelog — gommage-stdlib

## [0.13.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.12.0-alpha.1...gommage-stdlib-v0.13.0-alpha.1) (2026-07-04)


### Features

* add operational watchlist cleanup ([db41128](https://github.com/Arakiss/gommage/commit/db4112843e9d3acadae0995215b6936c8ecc5563))

## [0.12.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.11.0-alpha.1...gommage-stdlib-v0.12.0-alpha.1) (2026-07-04)


### Features

* add audit friction stats ([b772b3e](https://github.com/Arakiss/gommage/commit/b772b3e6ea92159aa20f142a7f288ab4caf4841d))


### Bug fixes

* harden agent hook entrypoint ([22e5ce6](https://github.com/Arakiss/gommage/commit/22e5ce619fb9a4ed42c46ee79f677c8ece78b1f0))

## [0.11.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.10.0-alpha.1...gommage-stdlib-v0.11.0-alpha.1) (2026-06-30)


### Features

* **release:** prepare crates.io publishing ([9426ff4](https://github.com/Arakiss/gommage/commit/9426ff4656fa55a65cc5fc4f5f4d53667518acd5))

## [0.10.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.9.0-alpha.1...gommage-stdlib-v0.10.0-alpha.1) (2026-06-28)


### Features

* **stdlib:** allow routine gh pr merges ([#101](https://github.com/Arakiss/gommage/issues/101)) ([e71967b](https://github.com/Arakiss/gommage/commit/e71967b006a9bb6627eb248f3de52ae96858239b))

## [0.9.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.8.1-alpha.1...gommage-stdlib-v0.9.0-alpha.1) (2026-06-28)


### Features

* harden hook write context and matcher coverage ([0952518](https://github.com/Arakiss/gommage/commit/0952518f8b91446d20ae2ff1a6d137da1e348c1d))

## [0.8.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.8.0-alpha.1...gommage-stdlib-v0.8.1-alpha.1) (2026-06-12)


### Bug fixes

* **core:** strip shell redirections before refspec capture ([65411a5](https://github.com/Arakiss/gommage/commit/65411a5d36be735fd556c7feec4405b913ff1c48))
* **mcp:** honor GOMMAGE_BYPASS in the legacy gommage mcp adapter ([a593998](https://github.com/Arakiss/gommage/commit/a59399890dc218d33b465800133e469b9f877ad3))
* **release:** break stdlib-core dep cycle that crashed release-please ([260ec53](https://github.com/Arakiss/gommage/commit/260ec5359adc80e1bd3c9c9175194964d3f90325))

## [0.8.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.7.0-alpha.1...gommage-stdlib-v0.8.0-alpha.1) (2026-06-04)


### Features

* **stdlib:** gate exfil, dangerous perms, config-hijack, env-injection ([#81](https://github.com/Arakiss/gommage/issues/81)) ([3b17e45](https://github.com/Arakiss/gommage/commit/3b17e4530727c3a8c1d302c8a172e29eaac9c820))

## [0.7.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.6.0-alpha.1...gommage-stdlib-v0.7.0-alpha.1) (2026-06-04)


### Features

* **stdlib:** gate publish, persistence, device-write, docker escape ([#79](https://github.com/Arakiss/gommage/issues/79)) ([837a6ae](https://github.com/Arakiss/gommage/commit/837a6aeeb0c552d63637b0bb08ba1a48fa0f086b))

## [0.6.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.5.0-alpha.1...gommage-stdlib-v0.6.0-alpha.1) (2026-06-04)


### Features

* **core:** shell-aware bash mapper closes command-shape gate evasions ([#77](https://github.com/Arakiss/gommage/issues/77)) ([8b08a3b](https://github.com/Arakiss/gommage/commit/8b08a3b4f4f240f864be555ae08b5d419afa1f09))

## [0.5.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.4.0-alpha.1...gommage-stdlib-v0.5.0-alpha.1) (2026-05-24)


### Features

* expand Codex hook coverage ([9e162d9](https://github.com/Arakiss/gommage/commit/9e162d92689b1c947095c8b9c86ff9069732d7ea))
* polish beta operator experience ([df0bb25](https://github.com/Arakiss/gommage/commit/df0bb25aee60c541503e5ede1df5b1845cdfeba1))
* **stdlib:** package bundled policy assets ([a2abc3b](https://github.com/Arakiss/gommage/commit/a2abc3b8a19ff28b1924afdd4505a78de01c845a))


### Bug fixes

* polish recovery diagnostics ([48f256f](https://github.com/Arakiss/gommage/commit/48f256fd887f7aee124e81f57ee4d00a796bd5ed))
* prevent quickstart deadlocks ([fb5a2a4](https://github.com/Arakiss/gommage/commit/fb5a2a4f45c7301df06ba274e9f88a7531b9725c))


### Documentation

* lock agent command contracts ([1c42980](https://github.com/Arakiss/gommage/commit/1c429807f093b70c5abba1c421e13e385c5938f5))

## [0.4.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.3.0-alpha.1...gommage-stdlib-v0.4.0-alpha.1) (2026-05-24)


### Features

* expand Codex hook coverage ([720b1ba](https://github.com/Arakiss/gommage/commit/720b1ba0250fa654d6febdca56ff00653517e80b))

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.2.2-alpha.1...gommage-stdlib-v0.3.0-alpha.1) (2026-04-22)


### Features

* polish beta operator experience ([ce4e33c](https://github.com/Arakiss/gommage/commit/ce4e33cb41dca1da6a87b0f9eadcd92752cbb6fe))

## [0.2.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.2.1-alpha.1...gommage-stdlib-v0.2.2-alpha.1) (2026-04-22)


### Bug fixes

* polish recovery diagnostics ([1b7e7c1](https://github.com/Arakiss/gommage/commit/1b7e7c1e55ee90dc6d91218df7896e44e33b940b))

## [0.2.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.2.0-alpha.1...gommage-stdlib-v0.2.1-alpha.1) (2026-04-22)


### Bug fixes

* prevent quickstart deadlocks ([2d9c967](https://github.com/Arakiss/gommage/commit/2d9c967faff8f7b1199d08fac2a43363fa6b7e26))


### Documentation

* lock agent command contracts ([5056758](https://github.com/Arakiss/gommage/commit/505675890ec4b3d128c2eab03615b99ace38b54e))

## [Unreleased]

### Added

- `03-recovery.yaml` keeps Gommage readiness and basic inspection commands
  available after quickstart while loading after hard-stops and native deny
  imports. Commands that mutate service or settings state are not recovery
  allows.

### Changed

- Bash filesystem and Git push capabilities now use typed AST effects with
  canonical destinations, while dynamic security-relevant shell effects are
  denied early through `proc.exec.ambiguous:*`.
- Filesystem policies now receive a single canonical resolved path capability;
  Git branch context remains audit metadata instead of an authorizable write
  capability.
- Harness integrity gates exact semantic Gommage administration capabilities
  and protects the actual approval log, webhook dead-letter log, expedition,
  socket, and SQLite sidecar paths. Administrative pictos are input-bound so
  approval of one command cannot authorize another command with the same scope.
  Exact `gommage.home.mutate:<path>` effects are covered only alongside their
  corresponding administration class; they do not authorize generic file
  writes.
- Harness integrity denies direct reads of the private signing key and local
  authorization/audit state. Bounded operator CLI views remain available while
  arbitrary agent file reads cannot use that data directly.

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.1.0-alpha.1...gommage-stdlib-v0.2.0-alpha.1) (2026-04-22)


### Features

* **stdlib:** package bundled policy assets ([6e91243](https://github.com/Arakiss/gommage/commit/6e912433db6c130725ab5469195469f51b36ad3d))

## [Unreleased]

### Added

- Packaged policy and capability mapper stdlib assets for CLI embedding and
  future crates.io publishing.

## [0.1.0-alpha.1] — 2026-04-21

Initial alpha crate with bundled policy YAML and capability mapper YAML.
