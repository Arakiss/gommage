# Audit log signature format

The audit log (`$GOMMAGE_HOME/audit.log`) is **line-delimited JSON**: one entry
per line, each line independently **ed25519-signed**. The signature covers the
canonical JSON of the entry **minus its `sig` field**, so verification is
line-local — kill the daemon mid-write and at most the last line is corrupt;
every line before it stays independently verifiable.

The format is implemented in `crates/gommage-audit/src/lib.rs`. The field set
below is exhaustive; treat it as a frozen contract (audit schema changes are
breaking — see [`BREAKING_CHANGES.md`](../BREAKING_CHANGES.md)).

---

## 1. Two entry kinds

Every line is one of two records, both at schema version `v: 1`.

### Decision entries

Written for each policy decision. Fields, in this order:

| Field | Type | Notes |
|---|---|---|
| `v` | integer | Audit schema version (`1`). |
| `id` | string | UUIDv7 (time-ordered). |
| `ts` | string | RFC 3339 UTC timestamp. |
| `tool` | string | The agent tool handle (`"Bash"`, `"Read"`, …). |
| `input_hash` | string | `sha256:<hex>` over the canonical tool input. |
| `capabilities` | array of string | Capabilities the mapper emitted. |
| `decision` | object | The `Decision` enum, internally tagged on `kind` (`{"kind":"allow"}`, `{"kind":"gommage","reason":…,"hard_stop":…}`, `{"kind":"ask_picto","required_scope":…,"reason":…,"bind_input":true}`). `bind_input` is omitted when false. |
| `matched_rule` | object \| null | `{ name, file, index }` of the rule that fired, or null. |
| `policy_version` | string | `sha256:<hex>` policy version hash in effect. |
| `expedition` | string \| null | Active expedition name, if any. |
| `sig` | string | `ed25519:<base64>` over the canonical bytes of everything above. |

### Event entries

Written for lifecycle events (picto created/confirmed/consumed/revoked/rejected,
approval requested/resolved, webhook delivered/failed/dead-lettered, pictos
expired, policy reloaded, bypass activated). Distinguished by `"kind":"event"`:

| Field | Type | Notes |
|---|---|---|
| `v` | integer | Audit schema version (`1`). |
| `id` | string | UUIDv7. |
| `ts` | string | RFC 3339 UTC timestamp. |
| `kind` | string | Always `"event"` (this is how a reader tells the two record kinds apart). |
| `event` | object | Tagged by `type` (snake_case), e.g. `{"type":"bypass_activated", …}`. |
| `sig` | string | `ed25519:<base64>` over the canonical bytes of everything above. |

Example decision line (wrapped for readability; one physical line in the file):

```json
{"v":1,"id":"...","ts":"2026-06-04T12:00:00Z","tool":"Bash",
 "input_hash":"sha256:...","capabilities":["git.push:refs/heads/main"],
 "decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"..."},
 "matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},
 "policy_version":"sha256:...","expedition":null,"sig":"ed25519:..."}
```

---

## 2. What the signature covers

The per-line signature is computed over a **canonical rendering** of the entry
with the `sig` field removed:

- Decision entries are canonicalised over `v, id, ts, tool, input_hash,
  capabilities, decision, matched_rule, policy_version, expedition`.
- Event entries are canonicalised over `v, id, ts, kind, event`.

Canonical rendering sorts object keys lexicographically at every level, preserves
array order, and uses `serde_json`'s string escaping for strings. This canonical
form is deliberately independent of `serde_json` field ordering so the signed
bytes are stable across serde versions. The signature string is
`ed25519:<standard-base64-no-pad>` of the 64-byte ed25519 signature, produced by
the daemon keypair (`$GOMMAGE_HOME/key.ed25519`).

---

## 3. Verifying the chain — `gommage audit-verify`

`gommage audit-verify` walks the whole log and verifies every line against the
verifying key derived from the daemon keypair:

```sh
# Walk the log; print "ok <n> entries verified" or fail at the first bad line.
gommage audit-verify

# Forensic report that does not abort on the first failure: counts, key
# fingerprint, bypass activations, and per-line anomalies (malformed entry, bad
# signature, timestamp out of order, policy-version change, hard-stop bypass
# attempt). Exits non-zero if any anomaly is present.
gommage audit-verify --explain
gommage audit-verify --explain --format human
```

The strict walk (`verify_log`) stops at the first line whose signature does not
verify and reports the line number. The `--explain` report (`explain_log`) keeps
going, recording each anomaly, so a forensic review sees the whole picture rather
than only the first failure.

---

## 4. Explaining a single decision — `gommage explain <id>`

`gommage explain <audit-id>` looks the entry up by `id` and shows it. With
`--trace` it re-evaluates the recorded capabilities against the **current**
policy and reports which rule fired, the active vs audited decision, and the
policy version in effect:

```sh
# Show one audit entry (decision or event) by id.
gommage explain <audit-id>
gommage explain <audit-id> --json

# Re-run the recorded capabilities through current policy: which rule fired,
# shadowed matches, the audit vs active policy version, fixture-authoring hints.
gommage explain <audit-id> --trace --json
```

The audit entry stores `input_hash` and the emitted `capabilities`, not the raw
tool input, so a trace re-evaluates from the capability list, not from the
original command string. Each decision entry carries its `policy_version` hash,
which is how `explain --trace` reports whether the rule set has changed since the
decision was recorded.

---

## 5. Key management

The signing key is the daemon ed25519 keypair at `$GOMMAGE_HOME/key.ed25519`
(`chmod 0600`), generated on first daemon start. The same key signs audit lines
and pictos and verifies picto signatures. Key rotation and compromise handling
are covered in the root [`THREAT_MODEL.md` §6](../THREAT_MODEL.md#6-key-management).
