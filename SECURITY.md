# Security policy

Gommage is a policy decision and audit harness for AI coding agents. It is security-adjacent by design. Please read `THREAT_MODEL.md` for the scope of what Gommage defends against and what it explicitly does not.

## Reporting a vulnerability

**Do not open a public GitHub issue for a vulnerability.**

Email `petruarakiss@gmail.com` with the subject prefix `[gommage-security]`.

If possible, encrypt the report to the maintainer's public PGP key, published on `keys.openpgp.org` under the same email address.

Please include:

- A description of the issue and its impact.
- Reproduction steps (ideally a minimal repository or CLI invocation).
- Your assessment of the severity (CVSS or a plain-English "what is the worst case").
- Any disclosure deadline you have in mind. We prefer 90 days from receipt for a coordinated disclosure, shorter if the issue is already being exploited in the wild.

## Initial response

You will hear back within **72 hours** with:

- Acknowledgement of receipt.
- Whether the issue is in scope (see `THREAT_MODEL.md` §5 for the out-of-scope list).
- A CVE request timeline if applicable.

## Scope reminders

Gommage's threat model is explicit about what is in and out of scope. The following classes of report will be treated as informative rather than exploitable:

- Command behavior that depends on runtime state Gommage does not observe, such as shell aliases, sourced functions, `eval`-generated commands, static `xargs` input, environment-dependent expansion, or symlink resolution. These residual boundaries are documented in `THREAT_MODEL.md` and `docs/input-schema.md`.
- Symlink-resolution bypasses. Gommage deliberately does not resolve symlinks (see `docs/input-schema.md` §2).
- TOCTOU between Gommage's decision and the agent's execution (`THREAT_MODEL.md` §2.5).
- Human approver rubber-stamping every `ask` (`THREAT_MODEL.md` §5.7).
- Any attack that assumes a hostile local user under the same UID as the daemon. Gommage trusts the user (`THREAT_MODEL.md` §2.2).
- Deletion, truncation, reordering, or duplication of otherwise valid audit records. Current signatures authenticate each record independently; the log has no cryptographic chain or external completeness witness.
- Direct mutation of a picto's `uses` or `status` by the trusted local user. Picto schema v1 signs authority fields such as scope, limits, timestamps, reason, and optional input hash, while SQLite enforces mutable lifecycle state in the normal daemon path.

Reports in these classes are still welcome — they may become a new hardstop pattern or a policy-pack default, or a documentation hardening. They just will not be tracked as CVEs.

In scope and will be treated as CVEs:

- Signature verification bypass on audit log or pictos (`gommage-audit::verify_log`, `gommage-audit::explain_log`, `Picto::verify`).
- Evaluator non-determinism (`gommage-core::evaluate` producing different results for the same `(capabilities, policy)`).
- Bypass of a documented compiled hard stop or a fail-closed typed-shell case, including a supported transparent wrapper or an ambiguous command form that the bundled strict policy is documented to deny.
- Policy YAML parser panic, hang, or memory-exhaustion on crafted input.
- An IPC request that crosses the documented same-UID boundary, or a daemon request that gains authority not exposed by the documented user-local protocol.
- Release verification accepting an archive whose digest, Sigstore workflow identity, issuer, or requested attestation constraints do not match.

## Embargo and credit

The default is coordinated disclosure. We will:

- Keep the advisory private until a fix is released.
- Credit you in the release notes by name / handle / email, your choice. No credit if you prefer anonymity.
- Offer to co-author the advisory text.

If you need to disclose before we have a fix (e.g. the issue is already public elsewhere), we will work with you to minimise harm.

## No bug bounty

Gommage is a privately maintained open-source project. There is no paid bounty program. Thanks are real; money is not.

## Historical advisories

None yet. This section will list CVEs once they exist.
