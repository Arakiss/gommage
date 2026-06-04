# Changelog — gommage-stdlib

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

- `03-recovery.yaml` keeps Gommage readiness commands, basic inspection,
  systemd daemon recovery, and Claude settings backup restore commands
  available after quickstart while loading after hard-stops and native deny
  imports.

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-stdlib-v0.1.0-alpha.1...gommage-stdlib-v0.2.0-alpha.1) (2026-04-22)


### Features

* **stdlib:** package bundled policy assets ([6e91243](https://github.com/Arakiss/gommage/commit/6e912433db6c130725ab5469195469f51b36ad3d))

## [Unreleased]

### Added

- Packaged policy and capability mapper stdlib assets for CLI embedding and
  future crates.io publishing.

## [0.1.0-alpha.1] — 2026-04-21

Initial alpha crate with bundled policy YAML and capability mapper YAML.
