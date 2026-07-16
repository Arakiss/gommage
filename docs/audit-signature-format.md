# Audit log signature format

The audit log (`$GOMMAGE_HOME/audit.log`) is **line-delimited JSON**: one record
per line, each record independently **ed25519-signed**. The signature covers the
canonical JSON of that record **minus its `sig` field**, so authentication is
line-local. This is a per-record signature format, not a hash chain: it proves
the content of records that are present, but not that records were never
deleted, reordered, duplicated, or truncated.

The format is implemented in `crates/gommage-audit/src/lib.rs`. The field set
below is exhaustive; treat it as a frozen contract (audit schema changes are
breaking — see [`BREAKING_CHANGES.md`](../BREAKING_CHANGES.md)).

---

## 1. Record kinds and versions

Every line is one of two record kinds. New decisions use schema version `v: 2`;
lifecycle events remain at `v: 1`. The verifier also accepts legacy `v: 1`
decision records so existing logs remain readable.

### Decision entries

Written for each policy decision. Fields, in this order:

| Field | Type | Notes |
|---|---|---|
| `v` | integer | Decision audit schema version (`2` for new records; legacy `1` is verification-only). |
| `id` | string | UUIDv7 (time-ordered). |
| `ts` | string | RFC 3339 UTC timestamp. |
| `tool` | string | The agent tool handle (`"Bash"`, `"Read"`, …). |
| `input_hash` | string | `sha256:<hex>` over the canonical tool input. |
| `capabilities` | array of string | Capabilities the mapper emitted. |
| `capability_provenance` | array of object | Required in v2. One signed entry per normalized capability, including resolution status, effective decision, and the first matching contribution from each policy layer. Absent in legacy v1. |
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
{"v":2,"id":"...","ts":"2026-06-04T12:00:00Z","tool":"Bash",
 "input_hash":"sha256:...","capabilities":["git.push:refs/heads/main"],
 "capability_provenance":[{"capability":"git.push:refs/heads/main","status":"resolved","effective_decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"..."},"contributions":[{"layer":"user","layer_index":0,"file_index":0,"rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"..."}}]}],
 "decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"..."},
 "matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},
 "policy_version":"sha256:...","expedition":null,"sig":"ed25519:..."}
```

---

## 2. What the signature covers

The per-line signature is computed over a **canonical rendering** of the entry
with the `sig` field removed:

- Decision v2 entries are canonicalised over `v, id, ts, tool, input_hash,
  capabilities, capability_provenance, decision, matched_rule, policy_version,
  expedition`. Legacy v1 omits `capability_provenance`.
- Event entries are canonicalised over `v, id, ts, kind, event`.

Canonical rendering sorts object keys lexicographically at every level, preserves
array order, and uses `serde_json`'s string escaping for strings. This canonical
form is deliberately independent of JSON object field order. Verification
rejects duplicate object keys at every nesting depth, unsupported schema
versions, missing or unexpected top-level fields, and malformed signature
encodings. Nested fields are preserved when reconstructing the received signed
payload, so an unknown nested mutation is not silently dropped before signature
verification. The signature string is
`ed25519:<standard-base64-no-pad>` of the 64-byte ed25519 signature, produced by
the daemon keypair (`$GOMMAGE_HOME/key.ed25519`).

---

## 3. Verifying records — `gommage audit-verify`

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

### What verification proves

A successful verification proves that every non-empty record currently in the
file has an accepted schema and a valid signature under the supplied key. It
does **not** prove log completeness or append order:

- records can be removed or the file can be truncated without invalidating the
  signatures of the remaining records;
- a copied valid record can be duplicated, and ordering is only checked
  heuristically through timestamps by `--explain`;
- a holder of `$GOMMAGE_HOME/key.ed25519` can forge valid records;
- there is no external checkpoint, sequence number, previous-record digest, or
  transparency service in this format.

For evidence that must survive compromise or prove completeness, export or
anchor verified log snapshots outside the Gommage home. `state.sqlite` is only
a rebuildable read model and does not add this guarantee.

---

## 4. Explaining a single decision — `gommage explain <id>`

`gommage explain <audit-id>` looks the entry up by `id`, verifies that selected
record under the home verifying key, and only then shows it. A malformed or
signature-invalid selected record fails without printing its provenance. With
`--trace` it re-evaluates the signed capability list against the **current**
policy and compares the active result with the audited result:

```sh
# Show one audit entry (decision or event) by id.
gommage explain <audit-id>
gommage explain <audit-id> --json

# Re-run the recorded capabilities through current policy: audited and active
# per-capability/layer provenance, normalized active capabilities, policy
# version comparison, and fixture-authoring hints.
gommage explain <audit-id> --trace --json
```

The audit entry stores `input_hash` and the emitted `capabilities`, not the raw
tool input, so a trace re-evaluates from the capability list, not from the
original command string. Each decision entry carries its `policy_version` hash,
which is how `explain --trace` reports whether the rule set has changed since the
decision was recorded. Decision schema v2 also signs
`capability_provenance`, so the trace reports the historical contribution from
each policy layer directly. Schema v1 records remain verifiable, but their
historical per-capability provenance is explicitly `null`/unavailable instead
of being reconstructed from today's policy.

The `audited_primary_matched_rule` and `active_primary_matched_rule` fields are
compatibility summaries of the aggregate decision. They are not complete
explanations for mixed-capability calls; the corresponding
`*_capability_provenance` arrays are authoritative. The trace JSON no longer
emits synthetic global `rules` or `shadowed_rules` arrays because compositional
evaluation has first-match ordering only within one layer and one capability.

---

## 5. Key management

The signing key is the daemon ed25519 keypair at `$GOMMAGE_HOME/key.ed25519`
(`chmod 0600`), generated when the Gommage home is initialized. The same key
signs audit lines and pictos and verifies picto signatures. User mode treats the
operator UID and this key file as trusted: a process under the same UID can read
or replace both. Key rotation and compromise handling are covered in the root
[`THREAT_MODEL.md` §6](../THREAT_MODEL.md#6-key-management).
