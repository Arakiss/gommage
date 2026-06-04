# Changelog — gommage-cli

## [0.39.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.38.0-beta.1...gommage-cli-v0.39.0-beta.1) (2026-06-04)


### Features

* **cli:** generate agent-friendly posture on install ([#72](https://github.com/Arakiss/gommage/issues/72)) ([fec8eac](https://github.com/Arakiss/gommage/commit/fec8eac846f229f9b17fdcee9a4fdb9449e4a04a))

## [0.38.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.37.0-beta.1...gommage-cli-v0.38.0-beta.1) (2026-05-24)


### Features

* add agent quickstart setup ([54ee041](https://github.com/Arakiss/gommage/commit/54ee041b6bc7a0fbb34f55c0c6412b151a9a4ece))
* add agent-readable harness diagnostics ([c5aa215](https://github.com/Arakiss/gommage/commit/c5aa2158841374ebc60ce8929f7a13814af9f8d7))
* add beta readiness gate ([fd730e2](https://github.com/Arakiss/gommage/commit/fd730e26d7f6b90a312f1b140a39466b40ad6201))
* add explain trace and strict policy lint ([a03043c](https://github.com/Arakiss/gommage/commit/a03043c71a6e08e72acd4f26154d8307ac1f162d))
* add Gommage update and upgrade commands ([b8b83d0](https://github.com/Arakiss/gommage/commit/b8b83d0a48c263f8e4f0967508714665423396d0))
* add host smoke evidence script ([6330843](https://github.com/Arakiss/gommage/commit/6330843d178c68618c7cd31c8e4e7101d9cea71a))
* add legacy agent repair ([1a04c16](https://github.com/Arakiss/gommage/commit/1a04c16f350ca45a410055f8c84f7fb6abef4901))
* add operator dashboard tui ([3c13709](https://github.com/Arakiss/gommage/commit/3c1370965b97b66f8d8768f47acff0b3dea27de1))
* add out-of-band approval workflow ([5612978](https://github.com/Arakiss/gommage/commit/56129785737db7dbb686c0e4f4c95cc7cbf2aa53))
* add policy diff ([9b6c8a5](https://github.com/Arakiss/gommage/commit/9b6c8a51b889ca6be28a8c5c7c6d1678263ba615))
* add policy replay ([8dae554](https://github.com/Arakiss/gommage/commit/8dae554b6520a010b475d7208bdd48cc666e30e1))
* add policy suggest ([8a73385](https://github.com/Arakiss/gommage/commit/8a73385eaaf163b47a4666ae9a08ef8b2ca8220e))
* add rebuildable sqlite state index ([403cd6a](https://github.com/Arakiss/gommage/commit/403cd6a6b18efb5a8ce2d97ac99d90228441f5fa))
* add redacted report bundles ([5a15834](https://github.com/Arakiss/gommage/commit/5a15834dfec3a7005f2f7af472f4053f9899c86e))
* add release verification command ([96aec4b](https://github.com/Arakiss/gommage/commit/96aec4b33c56987249692613b96ab7e80cc969bc))
* add reversible uninstall ([368a147](https://github.com/Arakiss/gommage/commit/368a1479f8b5d4bdf888e22a9bd77688f836761c))
* add tui onboarding view ([106e142](https://github.com/Arakiss/gommage/commit/106e142f624e4fec571045be9ab65e5291f6c701))
* **audit:** audit-verify --explain with anomaly report ([#10](https://github.com/Arakiss/gommage/issues/10)) ([1e26e68](https://github.com/Arakiss/gommage/commit/1e26e6899a59dd58e47159c942634ab10eec3a96))
* **cli:** accept hook payloads for authoring ([791647a](https://github.com/Arakiss/gommage/commit/791647a6ec0fb4742ce50f191361bdd21ba1bdde))
* **cli:** add aggregated verification gate ([f412491](https://github.com/Arakiss/gommage/commit/f41249196073a66d7c1578259b05b167cc0d8b26))
* **cli:** add gestral terminal logo ([de10b2f](https://github.com/Arakiss/gommage/commit/de10b2ff54eafc52d17590862652d2c537438c6f))
* **cli:** add policy fixture tests ([f924669](https://github.com/Arakiss/gommage/commit/f924669305aae593a264c92ce13318155cc71802))
* **cli:** add semantic smoke checks ([9bccc94](https://github.com/Arakiss/gommage/commit/9bccc947256ad735692d015bc619c59ae4fc9935))
* **cli:** capture policy fixture snapshots ([4832c5c](https://github.com/Arakiss/gommage/commit/4832c5ccde0ccd38bf45fce459784ac39dac5ba0))
* **cli:** emit structured doctor diagnostics ([ef2126f](https://github.com/Arakiss/gommage/commit/ef2126f67e2e3c258faba4b1098072e180e27309))
* **cli:** expose policy fixture schema ([e9b60a3](https://github.com/Arakiss/gommage/commit/e9b60a30b1e68e806c39b502ba3feb00ec2e4850))
* **cli:** import narrow native allows ([8aa2bd6](https://github.com/Arakiss/gommage/commit/8aa2bd6f845be063fdeae415ac50f115b61c46f3))
* **cli:** inspect capability mapping ([838abad](https://github.com/Arakiss/gommage/commit/838abadd9323895ed74b8b15c4c043d726b6f44f))
* **cli:** install daemon from quickstart ([7bcf1b1](https://github.com/Arakiss/gommage/commit/7bcf1b1a8137e2163377ecdc04b6c574a32dc2a1))
* **cli:** render audit verify reports ([27ab754](https://github.com/Arakiss/gommage/commit/27ab754938f82811190ee8eff9c2346bfb280e20))
* **cli:** report agent integration status ([3213435](https://github.com/Arakiss/gommage/commit/3213435cc5442995940d0b893a4a4bfd95a78903))
* **cli:** self-test quickstart setup ([33f66ee](https://github.com/Arakiss/gommage/commit/33f66ee51aa6d8182c8375988fb08438409c19a0))
* define beta launch readiness ([bf465ce](https://github.com/Arakiss/gommage/commit/bf465ce664c23a0e1811f9324254f69cae8f8a42))
* expand Codex hook coverage ([9e162d9](https://github.com/Arakiss/gommage/commit/9e162d92689b1c947095c8b9c86ff9069732d7ea))
* expand coverage beyond hooks ([77fc3da](https://github.com/Arakiss/gommage/commit/77fc3da5f5e90f4ed2f7d40924a3cc120d4c9d4e))
* expose hook coexistence dry-run plan ([ef63937](https://github.com/Arakiss/gommage/commit/ef639378f39a9a3f59a30b464d165aa46758aa9d))
* improve operator loop visibility ([aa3b633](https://github.com/Arakiss/gommage/commit/aa3b633c4f70b439cdcd9cebde13fdb08996549d))
* install daemon as user service ([3efd799](https://github.com/Arakiss/gommage/commit/3efd799c9b66653aaa887ac4c51de58399fd5e4e))
* make approval webhooks recoverable ([69eba2e](https://github.com/Arakiss/gommage/commit/69eba2e869f329a2a4d6af6ce908dd6a4956bd25))
* map agent web and mcp tools ([2878452](https://github.com/Arakiss/gommage/commit/287845271027bc9bf359c5f46556c08cf8c047e3))
* plan quickstart dry runs ([59ca928](https://github.com/Arakiss/gommage/commit/59ca928aaad5b478ca04b8c9847d49e2376cb035))
* polish approval operator workflow ([f6b25fa](https://github.com/Arakiss/gommage/commit/f6b25faa109b767d1f09b9289fe646132defa204))
* polish beta operator experience ([df0bb25](https://github.com/Arakiss/gommage/commit/df0bb25aee60c541503e5ede1df5b1845cdfeba1))
* refine operator tui feedback loop ([6f11128](https://github.com/Arakiss/gommage/commit/6f11128b8286479b73b01c665d25c10281b58e73))
* sign approval webhook deliveries ([3bd919a](https://github.com/Arakiss/gommage/commit/3bd919ac0312a2e285c7fd93384977482a67c762))
* **stdlib:** package bundled policy assets ([a2abc3b](https://github.com/Arakiss/gommage/commit/a2abc3b8a19ff28b1924afdd4505a78de01c845a))
* stream live decision activity ([b48d21a](https://github.com/Arakiss/gommage/commit/b48d21a6f69f87b1095aee50d220c75bd2fa99af))
* verify full release asset matrix ([4c44e0d](https://github.com/Arakiss/gommage/commit/4c44e0dfa2f4df7d782cb25a5efb6a38147bf3cb))


### Bug fixes

* clarify install readiness failures ([71b5099](https://github.com/Arakiss/gommage/commit/71b5099f9a8149c61edf7963a23b2f37dd3542ec))
* **cli:** avoid agent status test shadowing ([04a0ce5](https://github.com/Arakiss/gommage/commit/04a0ce5dfe5828964c9bf7666639f6c6bdf27cee))
* **cli:** avoid verify report type collision ([5b8a400](https://github.com/Arakiss/gommage/commit/5b8a400499a0c5b8849d0b08d72a89db17c1146c))
* **cli:** label verify policy-test input ([5f41080](https://github.com/Arakiss/gommage/commit/5f4108048f050babab16dd5327b64e1585180241))
* **cli:** satisfy smoke check lint ([fe309b2](https://github.com/Arakiss/gommage/commit/fe309b2e68716c3e8aaf0bf1f72166aa3328ef25))
* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([8d489af](https://github.com/Arakiss/gommage/commit/8d489af5c24036406fc0a6ce6eb0b1abdf214d4f))
* enforce auditable trust guarantees ([47d9731](https://github.com/Arakiss/gommage/commit/47d97312fd4fc6f81883012a907c5a65ad8e1787))
* harden bypass audit semantics ([d9f9b37](https://github.com/Arakiss/gommage/commit/d9f9b37e6980862aeac221e95252b54ef96a89f3))
* keep state counters clippy-clean ([c7c6666](https://github.com/Arakiss/gommage/commit/c7c66663d63128cf13b2bbef9318cc1ec2c0aff7))
* polish approval webhook diagnostics ([3259397](https://github.com/Arakiss/gommage/commit/32593972ef0f2865d418c15210ace574bbbc8387))
* polish recovery diagnostics ([48f256f](https://github.com/Arakiss/gommage/commit/48f256fd887f7aee124e81f57ee4d00a796bd5ed))
* preserve replaced install surfaces ([c6b1153](https://github.com/Arakiss/gommage/commit/c6b115348537af4ac68ed0ecf6b835e969dcc02f))
* prevent quickstart deadlocks ([fb5a2a4](https://github.com/Arakiss/gommage/commit/fb5a2a4f45c7301df06ba274e9f88a7531b9725c))
* satisfy strict clippy gate ([d03ff0c](https://github.com/Arakiss/gommage/commit/d03ff0ce78f4f5465a9d8d6066cb8be856141f48))
* support companion binary introspection ([77b67cc](https://github.com/Arakiss/gommage/commit/77b67cc91d4282671593103d89fe53232865872e))
* use canonical Codex hook feature flag ([a402569](https://github.com/Arakiss/gommage/commit/a402569a45a4e80e83153709f201a7a8a16f3323))


### Refactor

* **cli:** keep command modules bounded ([462910f](https://github.com/Arakiss/gommage/commit/462910f725a8b37abf4e99686622a1cf83d26629))
* keep approval webhook options cohesive ([08bc8f9](https://github.com/Arakiss/gommage/commit/08bc8f97b4e6168950d6d4502ac6e091f2cfa48b))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))
* clarify existing harness integration ([8cadd98](https://github.com/Arakiss/gommage/commit/8cadd98a2c5e4ac13ecf76e7b25d4d5932851f63))
* clarify skill and release hygiene ([36b350a](https://github.com/Arakiss/gommage/commit/36b350a0928617c20c81e978ac206408677211e5))
* lock agent command contracts ([1c42980](https://github.com/Arakiss/gommage/commit/1c429807f093b70c5abba1c421e13e385c5938f5))
* promote public policy fixture contract ([d32fe1c](https://github.com/Arakiss/gommage/commit/d32fe1ca4e56d5b5cb49f4de0bc9d1115755a0ca))

## [0.37.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.36.0-beta.1...gommage-cli-v0.37.0-beta.1) (2026-05-24)


### Features

* expand Codex hook coverage ([720b1ba](https://github.com/Arakiss/gommage/commit/720b1ba0250fa654d6febdca56ff00653517e80b))

## [0.36.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.35.0-beta.1...gommage-cli-v0.36.0-beta.1) (2026-05-12)


### Features

* add Gommage update and upgrade commands ([5ae7f8c](https://github.com/Arakiss/gommage/commit/5ae7f8c3bde385d811a3ace0a952e5ee75bb8636))


### Bug fixes

* use canonical Codex hook feature flag ([3add3f6](https://github.com/Arakiss/gommage/commit/3add3f6fb6927bc53f29283832cfad9204622bc2))

## [0.35.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.34.0-beta.1...gommage-cli-v0.35.0-beta.1) (2026-05-07)


### Features

* expose hook coexistence dry-run plan ([9d2b990](https://github.com/Arakiss/gommage/commit/9d2b9905ef711fcfd80ab4491dcf4231d92536b9))

## [0.34.0-beta.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.33.0-alpha.1...gommage-cli-v0.34.0-beta.1) (2026-05-07)


### Features

* define beta launch readiness ([3a9cc9e](https://github.com/Arakiss/gommage/commit/3a9cc9ec050fbc7d06edf70e72d7f7673988ea01))

## [0.33.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.32.0-alpha.1...gommage-cli-v0.33.0-alpha.1) (2026-05-07)


### Features

* add rebuildable sqlite state index ([ce5c7a0](https://github.com/Arakiss/gommage/commit/ce5c7a023b7dfbbe3bfb212924775411c2426ea3))


### Bug fixes

* keep state counters clippy-clean ([b3ba7c6](https://github.com/Arakiss/gommage/commit/b3ba7c6a3bea82f0252674e56ef372f763191265))

## [0.32.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.31.0-alpha.1...gommage-cli-v0.32.0-alpha.1) (2026-05-07)


### Features

* add agent-readable harness diagnostics ([10acba8](https://github.com/Arakiss/gommage/commit/10acba88d298f314f460747c69ad0b9c80963c9f))


### Documentation

* clarify existing harness integration ([dd0501c](https://github.com/Arakiss/gommage/commit/dd0501c6e3e8657c25988097d173586933726023))

## [0.31.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.30.0-alpha.1...gommage-cli-v0.31.0-alpha.1) (2026-04-24)


### Features

* add release verification command ([480e163](https://github.com/Arakiss/gommage/commit/480e16348d1e5648e3195e44932272cf3c1247ee))

## [0.30.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.29.0-alpha.1...gommage-cli-v0.30.0-alpha.1) (2026-04-24)


### Features

* expand coverage beyond hooks ([722a1e1](https://github.com/Arakiss/gommage/commit/722a1e13b375fafb6da0c1cff86cb3ff75533696))

## [0.29.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.28.0-alpha.1...gommage-cli-v0.29.0-alpha.1) (2026-04-24)


### Features

* improve operator loop visibility ([5118fbf](https://github.com/Arakiss/gommage/commit/5118fbf95ca9c94e6adf2ef7e7a49c36da0efb00))

## [0.28.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.27.0-alpha.1...gommage-cli-v0.28.0-alpha.1) (2026-04-24)


### Features

* add policy suggest ([1524aeb](https://github.com/Arakiss/gommage/commit/1524aeb31a0e7c884d30e6abc6ad8b807b720fbc))

## [0.27.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.26.0-alpha.1...gommage-cli-v0.27.0-alpha.1) (2026-04-24)


### Features

* add explain trace and strict policy lint ([19f99fe](https://github.com/Arakiss/gommage/commit/19f99fe63ef9974224a38a56ef70ee995afd34bd))

## [0.26.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.25.0-alpha.1...gommage-cli-v0.26.0-alpha.1) (2026-04-24)


### Features

* add policy diff ([833e2e7](https://github.com/Arakiss/gommage/commit/833e2e79c74d8e6a6af674a60352f3b3591bf67c))

## [0.25.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.24.0-alpha.1...gommage-cli-v0.25.0-alpha.1) (2026-04-24)


### Features

* add policy replay ([054e8b3](https://github.com/Arakiss/gommage/commit/054e8b354ed2eaa51ce4d495aa75a81067d15561))

## [0.24.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.23.0-alpha.1...gommage-cli-v0.24.0-alpha.1) (2026-04-24)


### Features

* add legacy agent repair ([625cff6](https://github.com/Arakiss/gommage/commit/625cff667d8ddf896a5eab44d044d1255b647042))

## [0.23.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.22.0-alpha.1...gommage-cli-v0.23.0-alpha.1) (2026-04-23)


### Features

* make approval webhooks recoverable ([4075edd](https://github.com/Arakiss/gommage/commit/4075eddc5242c56c68ea1af74b411c2c5d15ce2e))


### Documentation

* promote public policy fixture contract ([e778dea](https://github.com/Arakiss/gommage/commit/e778deacb96aa9cedf4cca019f8f2a2c8c48c575))

## [0.22.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.21.0-alpha.1...gommage-cli-v0.22.0-alpha.1) (2026-04-23)


### Features

* add beta readiness gate ([fca0d17](https://github.com/Arakiss/gommage/commit/fca0d17fe715deef66818e13574edc636304a936))
* add tui onboarding view ([58bd0a1](https://github.com/Arakiss/gommage/commit/58bd0a126aa074b0bf1161c64bb758e6ec5309b0))

## [0.21.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.20.1-alpha.1...gommage-cli-v0.21.0-alpha.1) (2026-04-23)


### Features

* sign approval webhook deliveries ([acb4417](https://github.com/Arakiss/gommage/commit/acb4417f2ce4e567485448676547b1e10e3b6382))
* stream live decision activity ([0529185](https://github.com/Arakiss/gommage/commit/0529185588d89f8f22279bd476e54d8f75773e8f))


### Refactor

* keep approval webhook options cohesive ([9e8b36b](https://github.com/Arakiss/gommage/commit/9e8b36b3e32339ef8e41e5c2d30b4e90637a8825))

## [0.20.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.20.0-alpha.1...gommage-cli-v0.20.1-alpha.1) (2026-04-23)


### Bug fixes

* polish approval webhook diagnostics ([fc39ab0](https://github.com/Arakiss/gommage/commit/fc39ab07e0fc03f86df0439fb003d1160fb96c72))

## [0.20.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.19.0-alpha.1...gommage-cli-v0.20.0-alpha.1) (2026-04-22)


### Features

* refine operator tui feedback loop ([4704688](https://github.com/Arakiss/gommage/commit/47046884faf746f39d983b3dc73d932e75e8ad3b))

## [0.19.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.18.0-alpha.1...gommage-cli-v0.19.0-alpha.1) (2026-04-22)


### Features

* polish approval operator workflow ([bcbe54e](https://github.com/Arakiss/gommage/commit/bcbe54e3e1753932c697222503d5680d334aac67))

## [0.18.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.17.0-alpha.1...gommage-cli-v0.18.0-alpha.1) (2026-04-22)


### Features

* add out-of-band approval workflow ([159aa6c](https://github.com/Arakiss/gommage/commit/159aa6c19706ef0a2ea6db92f2407b002fedcf1f))

## [0.17.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.16.1-alpha.1...gommage-cli-v0.17.0-alpha.1) (2026-04-22)


### Features

* polish beta operator experience ([ce4e33c](https://github.com/Arakiss/gommage/commit/ce4e33cb41dca1da6a87b0f9eadcd92752cbb6fe))

## [0.16.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.16.0-alpha.1...gommage-cli-v0.16.1-alpha.1) (2026-04-22)


### Bug fixes

* harden bypass audit semantics ([3663dc9](https://github.com/Arakiss/gommage/commit/3663dc94ef01fe94a1527bf29985a1b85942f76d))
* polish recovery diagnostics ([1b7e7c1](https://github.com/Arakiss/gommage/commit/1b7e7c1e55ee90dc6d91218df7896e44e33b940b))

## [0.16.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.15.0-alpha.1...gommage-cli-v0.16.0-alpha.1) (2026-04-22)


### Features

* add operator dashboard tui ([36fadbe](https://github.com/Arakiss/gommage/commit/36fadbe3c113309e015304b6854d9cb8a6a85972))

## [0.15.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.14.1-alpha.1...gommage-cli-v0.15.0-alpha.1) (2026-04-22)


### Features

* add host smoke evidence script ([ec5dd56](https://github.com/Arakiss/gommage/commit/ec5dd56537a122257f5f0afca01d36bfbc091cc6))
* add redacted report bundles ([b32c1f5](https://github.com/Arakiss/gommage/commit/b32c1f5b64c2c9efde7d0f42347961e28c8e7dcb))
* plan quickstart dry runs ([aa35045](https://github.com/Arakiss/gommage/commit/aa3504549082ad32fe4292e919162ee2321f5341))

## [0.14.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.14.0-alpha.1...gommage-cli-v0.14.1-alpha.1) (2026-04-22)


### Bug fixes

* preserve replaced install surfaces ([73992c0](https://github.com/Arakiss/gommage/commit/73992c0de4b2cf004a98a495d0535ec62f8f6702))

## [0.14.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.13.0-alpha.1...gommage-cli-v0.14.0-alpha.1) (2026-04-22)


### Features

* add reversible uninstall ([d4fe299](https://github.com/Arakiss/gommage/commit/d4fe2999dee26fe9826ecd778dac630cf786b32e))


### Bug fixes

* clarify install readiness failures ([9654aa4](https://github.com/Arakiss/gommage/commit/9654aa488c181862ddeabe5f3e85ab28ac807268))
* prevent quickstart deadlocks ([2d9c967](https://github.com/Arakiss/gommage/commit/2d9c967faff8f7b1199d08fac2a43363fa6b7e26))
* satisfy strict clippy gate ([b5385cb](https://github.com/Arakiss/gommage/commit/b5385cb640195fa647a00ce5c00dd8b49b7fe596))


### Documentation

* lock agent command contracts ([5056758](https://github.com/Arakiss/gommage/commit/505675890ec4b3d128c2eab03615b99ace38b54e))

## [Unreleased]

### Features

- `gommage quickstart` runs self-test by default, verifies recovery decisions,
  and rolls back touched agent configs on self-test failure.
- `gommage agent uninstall <claude|codex|all>` and `gommage uninstall` provide
  reversible cleanup and dry-run recovery surfaces.
- Agent command contract script verifies README/skill-facing commands against
  the current binary.

### Bug fixes

- Claude native permission import now carries broad supported
  `permissions.allow` entries forward instead of creating a fail-closed
  deadlock after hook installation.
- `gommage verify --json` reports a pre-init hint and skips smoke when doctor
  already failed.
- The installer now logs token source, gives OS-aware cosign hints, makes
  non-TTY skill defaults explicit, supports `--verify`, and uses fixed-string
  PATH matching.
- Repeated CLI writes now create collision-safe `.gommage-bak-<timestamp>`
  backups, and the installer backs up replaced binaries and skill files.

## [0.13.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.12.2-alpha.1...gommage-cli-v0.13.0-alpha.1) (2026-04-22)


### Features

* **cli:** self-test quickstart setup ([9acff72](https://github.com/Arakiss/gommage/commit/9acff72882ba647e063cbae1cabc1e2077f7d540))

## [0.12.2-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.12.1-alpha.1...gommage-cli-v0.12.2-alpha.1) (2026-04-22)


### Bug fixes

* support companion binary introspection ([a2db821](https://github.com/Arakiss/gommage/commit/a2db821d2829cebf4d2083fda000a9682dab634d))

## [0.12.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.12.0-alpha.1...gommage-cli-v0.12.1-alpha.1) (2026-04-22)


### Refactor

* **cli:** keep command modules bounded ([3374122](https://github.com/Arakiss/gommage/commit/3374122ccbbb9bb9b873b402e6aea1cb698fc80c))

## [0.12.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.11.0-alpha.1...gommage-cli-v0.12.0-alpha.1) (2026-04-22)


### Features

* **cli:** report agent integration status ([cbc5e90](https://github.com/Arakiss/gommage/commit/cbc5e90d6289f8d2a77baf6e28c0c4e7435a235d))


### Bug fixes

* **cli:** avoid agent status test shadowing ([637738f](https://github.com/Arakiss/gommage/commit/637738fe0f41e3b5c8666d1e06b71be19729a3a6))

## [0.11.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.10.0-alpha.1...gommage-cli-v0.11.0-alpha.1) (2026-04-22)


### Features

* **cli:** import narrow native allows ([92fc003](https://github.com/Arakiss/gommage/commit/92fc003bc39df3b600aa95477a507ac9d6c1a0b1))

## [0.10.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.9.0-alpha.1...gommage-cli-v0.10.0-alpha.1) (2026-04-22)


### Features

* **cli:** accept hook payloads for authoring ([3297630](https://github.com/Arakiss/gommage/commit/32976309dcc8dd793f2874f3d4f168ad3f76a1c7))

## [0.9.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.8.0-alpha.1...gommage-cli-v0.9.0-alpha.1) (2026-04-22)


### Features

* **cli:** inspect capability mapping ([147d2b4](https://github.com/Arakiss/gommage/commit/147d2b420d97f619b7833d974db6fc734c1df398))

## [0.8.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.7.0-alpha.1...gommage-cli-v0.8.0-alpha.1) (2026-04-22)


### Features

* **cli:** expose policy fixture schema ([f14833b](https://github.com/Arakiss/gommage/commit/f14833bae475c27b1d2db345a2c3fb3adcb24bfa))

## [0.7.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.6.0-alpha.1...gommage-cli-v0.7.0-alpha.1) (2026-04-22)


### Features

* **cli:** render audit verify reports ([5807f08](https://github.com/Arakiss/gommage/commit/5807f080600f39871b47fd67b21b84ddf7d7a2fc))


### Bug fixes

* **cli:** avoid verify report type collision ([26421b3](https://github.com/Arakiss/gommage/commit/26421b3876bead33989891728b383bfc7c29e759))

## [0.6.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.5.1-alpha.1...gommage-cli-v0.6.0-alpha.1) (2026-04-22)


### Features

* **cli:** capture policy fixture snapshots ([be1d1e7](https://github.com/Arakiss/gommage/commit/be1d1e73acb25900e7bf61a82448e5338da296de))

## [0.5.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.5.0-alpha.1...gommage-cli-v0.5.1-alpha.1) (2026-04-22)


### Bug fixes

* **cli:** label verify policy-test input ([2338899](https://github.com/Arakiss/gommage/commit/2338899a605850c13297c399274e696c70418901))

## [0.5.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.4.0-alpha.1...gommage-cli-v0.5.0-alpha.1) (2026-04-22)


### Features

* **cli:** add aggregated verification gate ([27b4b91](https://github.com/Arakiss/gommage/commit/27b4b91bb0a3196289eca928ef9e510887e71c02))
* **cli:** add gestral terminal logo ([6dfc9cf](https://github.com/Arakiss/gommage/commit/6dfc9cfef691029970a57d424320cc13b88edf1d))
* **cli:** add policy fixture tests ([cde2996](https://github.com/Arakiss/gommage/commit/cde2996829ae6bca8cff2503b984a9d0f5100635))
* **cli:** add semantic smoke checks ([27bd698](https://github.com/Arakiss/gommage/commit/27bd698986fbf8832effc98a659ce0c66dc2d468))
* **stdlib:** package bundled policy assets ([6e91243](https://github.com/Arakiss/gommage/commit/6e912433db6c130725ab5469195469f51b36ad3d))


### Bug fixes

* **cli:** satisfy smoke check lint ([846cb88](https://github.com/Arakiss/gommage/commit/846cb8882e000eb319463f3840f0cb156220d896))


### Documentation

* clarify skill and release hygiene ([d74c16d](https://github.com/Arakiss/gommage/commit/d74c16dbe42ca2a6e17e106364904431f03e0bd9))

## [0.4.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.3.0-alpha.1...gommage-cli-v0.4.0-alpha.1) (2026-04-21)


### Features

* **cli:** install daemon from quickstart ([24fdb35](https://github.com/Arakiss/gommage/commit/24fdb35ad967702c994b5579c37d44ae8261a1bd))

## [0.3.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.2.0-alpha.1...gommage-cli-v0.3.0-alpha.1) (2026-04-21)


### Features

* **cli:** emit structured doctor diagnostics ([0be3d2d](https://github.com/Arakiss/gommage/commit/0be3d2dfbc58dcc68fa13a552e914f3b34484095))

## [0.2.0-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.1.1-alpha.1...gommage-cli-v0.2.0-alpha.1) (2026-04-21)


### Features

* add agent quickstart setup ([8f84fc0](https://github.com/Arakiss/gommage/commit/8f84fc0c61ffa7f463e14920d487c457bd63932b))
* **audit:** audit-verify --explain with anomaly report ([#10](https://github.com/Arakiss/gommage/issues/10)) ([d2c8450](https://github.com/Arakiss/gommage/commit/d2c84506523faa3ffcbc867eb6806cde7f55c1f5))
* install daemon as user service ([61735ce](https://github.com/Arakiss/gommage/commit/61735cecc6cc52eb0b82414c092a94113312eafa))
* map agent web and mcp tools ([c3601c6](https://github.com/Arakiss/gommage/commit/c3601c6502a35c6e0b7c735998011a892b3ca7d6))


### Bug fixes

* enforce auditable trust guarantees ([fef1098](https://github.com/Arakiss/gommage/commit/fef1098ea15b3796c578d9a5a55b20e472d532de))

## [Unreleased]

### Added

- `gommage quickstart --self-test` for running the readiness gate after setup,
  with dry-run support for plan-only installer checks.
- `gommage policy init --stdlib`.
- `gommage quickstart` for one-command home, stdlib, permission-import, and hook setup.
- `gommage agent install claude|codex` for targeted hook installation.
- `gommage daemon install|status|uninstall` for user-level launchd/systemd service management.
- `gommage verify` / `--json` for one readiness gate that aggregates doctor, semantic smoke checks, and repeated `--policy-test <file>` fixtures.
- `gommage smoke` / `gommage smoke --json` for semantic post-install fixtures covering hard-stop, fail-closed, allow, ask-picto, web, and MCP policy paths.
- `gommage policy test <file>` / `--json` for user-owned YAML policy regression fixtures with per-case capabilities, matched rule, actual decision, expected decision, and mismatch errors.
- `gommage policy snapshot` / `capture` for turning a tool-call JSON object
  from stdin into a YAML policy regression fixture.
- `gommage policy schema` for exporting the official JSON Schema used by
  agents, editors, and CI generators when creating policy fixture files.
- `gommage map` / `gommage map --json` for inspecting raw capability mapper
  output without evaluating policy, reading pictos, or writing audit entries.
- `--hook` input mode for `gommage map`, `gommage decide`, and
  `gommage policy snapshot`, allowing policy-authoring tools to consume real
  PreToolUse payloads with `tool_name`, `tool_input`, and optional `cwd`.
- `gommage audit-verify --explain --format human` for manual signed-audit
  forensic review. Plain `audit-verify --explain` remains JSON for automation.
- `gommage mascot` / `gommage logo` for the Gommage Gestral terminal logo, with an interactive Gommage Teal to Picto Gold gradient and `--plain` / `NO_COLOR` script-safe output.
- Claude quickstart now includes `Grep`, `WebFetch`, `WebSearch`, and MCP matcher coverage when native allow rules permit those tools.
- `gommage doctor`.
- Structured `gommage explain <audit-id>` output plus `--json`.
- Human TTL suffix parsing for `gommage grant --ttl`.

### Changed

- Picto grant/revoke/confirm actions now emit signed audit lifecycle events.
- `gommage decide` remains evaluation-only and does not consume pictos.
- Invalid picto creation input now exits cleanly instead of panicking.
- Bundled stdlib installation now embeds assets from `gommage-stdlib` instead
  of repository-root paths.

## [0.1.1-alpha.1](https://github.com/Arakiss/gommage/compare/gommage-cli-v0.1.0-alpha.1...gommage-cli-v0.1.1-alpha.1) (2026-04-21)


### Bug fixes

* **deps:** drop version pin on internal workspace crate deps ([#4](https://github.com/Arakiss/gommage/issues/4)) ([17d9fa7](https://github.com/Arakiss/gommage/commit/17d9fa7a0224bf18b28b4232210e77cab5f08f00))


### Documentation

* add changelogs and semver/commit policy ([6463288](https://github.com/Arakiss/gommage/commit/6463288e9f22573b57ad78b1b7b0d182733714c6))

## [0.1.0-alpha.1] — 2026-04-21

Initial release. `gommage` binary with subcommands for init, expedition,
pictos, policy lint, audit, tail, explain, decide, mcp.
