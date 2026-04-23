# Changelog — gommage-daemon

## [0.3.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.3.0-alpha.1...gommage-daemon-v0.3.1-alpha.1) (2026-04-23)

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.5-alpha.1...gommage-daemon-v0.3.0-alpha.1) (2026-04-22)


### Features

* add out-of-band approval workflow ([159aa6c](https://github.com/Arakiss/gommage/commit/159aa6c19706ef0a2ea6db92f2407b002fedcf1f))

## [0.2.5-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.4-alpha.1...gommage-daemon-v0.2.5-alpha.1) (2026-04-22)

## [0.2.4-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.3-alpha.1...gommage-daemon-v0.2.4-alpha.1) (2026-04-22)

## [0.2.3-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.2-alpha.1...gommage-daemon-v0.2.3-alpha.1) (2026-04-22)

## [0.2.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.1-alpha.1...gommage-daemon-v0.2.2-alpha.1) (2026-04-22)

## [0.2.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.2.0-alpha.1...gommage-daemon-v0.2.1-alpha.1) (2026-04-21)


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Changed

- Picto consumption now verifies signatures before allowing gated decisions.
- Picto consume/reject and policy reload events now write signed audit entries.

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-daemon-v0.1.0-alpha.1...gommage-daemon-v0.2.0-alpha.1) (2026-04-21)


### Features

* **daemon:** reload policy on SIGHUP, graceful shutdown on SIGTERM/SIGINT ([37134e5](https://github.com/Arakiss/gommage/commit/37134e5158eb7fb7ad554bdabc469c4db7411516))


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. Unix-socket daemon, line-delimited JSON protocol, `Decide`/
`Reload`/`Ping` ops.
