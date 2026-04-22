# Changelog — gommage-stdlib

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
