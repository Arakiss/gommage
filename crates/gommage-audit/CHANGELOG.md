# Changelog — gommage-audit

## [0.2.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-audit-v0.2.0-alpha.1...gommage-audit-v0.2.1-alpha.1) (2026-04-22)

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-audit-v0.1.1-alpha.1...gommage-audit-v0.2.0-alpha.1) (2026-04-21)


### Features

* **audit:** audit-verify --explain with anomaly report ([#10](https://github.com/Arakiss/gommage/issues/10)) ([d2c8450](https://github.com/Arakiss/gommage/commit/d2c84506523faa3ffcbc867eb6806cde7f55c1f5))


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Added

- Signed audit event entries for picto lifecycle and policy reload events.
- Mixed decision/event log verification support in `verify_log` and
  `explain_log`.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-audit-v0.1.0-alpha.1...gommage-audit-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. `AuditWriter`, `AuditEntry`, `verify_log`, `AuditError`.
JSONL format, ed25519 per-line signatures, canonical JSON byte-order.
