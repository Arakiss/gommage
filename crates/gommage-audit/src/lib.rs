//! Append-only audit log for Gommage decisions.
//!
//! Each decision produces one JSONL line of the form:
//!
//! ```json
//! {"v":2,"id":"...","ts":"...","tool":"Bash","input_hash":"sha256:...",
//!  "capabilities":["git.push:refs/heads/main"],"decision":{...},
//!  "capability_provenance":[],
//!  "matched_rule":{"name":"gate-main-push","file":"...","index":0},
//!  "policy_version":"sha256:...","sig":"ed25519:..."}
//! ```
//!
//! The signature covers the canonical bytes of the object **minus the `sig`
//! field itself**, so verification is line-local: kill the daemon mid-write
//! and at most the last line is corrupt — everything before is still valid.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gommage_core::{Capability, CapabilityProvenance, Decision, EvalResult, MatchedRule, ToolCall};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod stream;
pub use stream::{AuditStreamItem, recent_stream_items};

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed at line {line}")]
    BadSignature { line: usize },
    #[error("unsupported {record_kind} audit schema version {version} at line {line}")]
    UnsupportedSchema {
        line: usize,
        record_kind: &'static str,
        version: u64,
    },
    #[error("invalid {record_kind} audit schema at line {line}: {reason}")]
    InvalidSchema {
        line: usize,
        record_kind: &'static str,
        reason: String,
    },
    #[error("time: {0}")]
    Time(#[from] time::error::Format),
}

const LEGACY_DECISION_SCHEMA_VERSION: u32 = 1;
const DECISION_SCHEMA_VERSION: u32 = 2;
const EVENT_SCHEMA_VERSION: u32 = 1;
const DECISION_V1_FIELDS: &[&str] = &[
    "v",
    "id",
    "ts",
    "tool",
    "input_hash",
    "capabilities",
    "decision",
    "matched_rule",
    "policy_version",
    "expedition",
    "sig",
];
const DECISION_V2_FIELDS: &[&str] = &[
    "v",
    "id",
    "ts",
    "tool",
    "input_hash",
    "capabilities",
    "capability_provenance",
    "decision",
    "matched_rule",
    "policy_version",
    "expedition",
    "sig",
];
const EVENT_V1_FIELDS: &[&str] = &["v", "id", "ts", "kind", "event", "sig"];

#[derive(Debug, Clone, Deserialize)]
pub struct AuditEntry {
    #[serde(rename = "v")]
    pub version: u32,
    pub id: String,
    pub ts: String,
    pub tool: String,
    pub input_hash: String,
    pub capabilities: Vec<Capability>,
    /// Deterministic per-capability policy provenance. Legacy v1 entries do
    /// not contain this field and deserialize to an empty vector. V2 entries
    /// always serialize it, including when it is empty, so their signed shape
    /// is unambiguous.
    #[serde(default)]
    pub capability_provenance: Vec<CapabilityProvenance>,
    pub decision: Decision,
    pub matched_rule: Option<MatchedRule>,
    pub policy_version: String,
    pub expedition: Option<String>,
    /// `ed25519:<base64>` signature over everything above.
    pub sig: String,
}

impl Serialize for AuditEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let include_provenance = self.version != LEGACY_DECISION_SCHEMA_VERSION;
        let mut entry =
            serializer.serialize_struct("AuditEntry", if include_provenance { 12 } else { 11 })?;
        entry.serialize_field("v", &self.version)?;
        entry.serialize_field("id", &self.id)?;
        entry.serialize_field("ts", &self.ts)?;
        entry.serialize_field("tool", &self.tool)?;
        entry.serialize_field("input_hash", &self.input_hash)?;
        entry.serialize_field("capabilities", &self.capabilities)?;
        if include_provenance {
            entry.serialize_field("capability_provenance", &self.capability_provenance)?;
        }
        entry.serialize_field("decision", &self.decision)?;
        entry.serialize_field("matched_rule", &self.matched_rule)?;
        entry.serialize_field("policy_version", &self.policy_version)?;
        entry.serialize_field("expedition", &self.expedition)?;
        entry.serialize_field("sig", &self.sig)?;
        entry.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventEntry {
    #[serde(rename = "v")]
    pub version: u32,
    pub id: String,
    pub ts: String,
    pub kind: String,
    pub event: AuditEvent,
    /// `ed25519:<base64>` signature over everything above.
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    PictoCreated {
        id: String,
        scope: String,
        max_uses: u32,
        ttl_expires_at: String,
        require_confirmation: bool,
    },
    PictoConfirmed {
        id: String,
    },
    PictoRevoked {
        id: String,
    },
    PictoConsumed {
        id: String,
        scope: String,
        uses: u32,
        max_uses: u32,
        status: String,
    },
    PictoRejected {
        id: String,
        scope: String,
        reason: String,
    },
    ApprovalRequested {
        id: String,
        tool: String,
        input_hash: String,
        required_scope: String,
        reason: String,
        policy_version: String,
    },
    ApprovalResolved {
        id: String,
        status: String,
        reason: String,
        picto_id: Option<String>,
    },
    ApprovalWebhookDelivered {
        id: String,
        url: String,
        status: Option<i32>,
        attempts: u32,
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<WebhookSignatureAudit>,
    },
    ApprovalWebhookFailed {
        id: String,
        url: String,
        error: String,
        attempts: u32,
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<WebhookSignatureAudit>,
    },
    ApprovalWebhookDeadLettered {
        id: String,
        url: String,
        dead_letter_id: String,
        provider: String,
        attempts: u32,
        source: String,
        error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<WebhookSignatureAudit>,
    },
    PictosExpired {
        count: usize,
    },
    PolicyReloaded {
        source: String,
        rules: usize,
        mapper_rules: usize,
        policy_version: String,
    },
    BypassActivated {
        tool: String,
        input_hash: String,
        capabilities: Vec<Capability>,
        original_decision: String,
        original_reason: String,
        hard_stop: bool,
        bypass_decision: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSignatureAudit {
    pub algorithm: String,
    pub key_id: Option<String>,
    pub timestamp: String,
    pub body_sha256: String,
    pub signature_prefix: String,
}

pub struct AuditWriter {
    path: PathBuf,
    file: File,
    key: SigningKey,
}

impl AuditWriter {
    pub fn open(path: &Path, key: SigningKey) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            key,
        })
    }

    pub fn append(
        &mut self,
        call: &ToolCall,
        eval: &EvalResult,
        expedition: Option<&str>,
    ) -> Result<AuditEntry, AuditError> {
        let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let id = uuid::Uuid::now_v7().to_string();
        let mut entry = AuditEntry {
            version: DECISION_SCHEMA_VERSION,
            id,
            ts,
            tool: call.tool.clone(),
            input_hash: call.input_hash(),
            capabilities: eval.capabilities.clone(),
            capability_provenance: eval.capability_provenance.clone(),
            decision: eval.decision.clone(),
            matched_rule: eval.matched_rule.clone(),
            policy_version: eval.policy_version.clone(),
            expedition: expedition.map(str::to_string),
            sig: String::new(),
        };
        let payload = canonical_decision_v2_bytes(&entry);
        let sig: Signature = self.key.sign(&payload);
        entry.sig = format!(
            "ed25519:{}",
            base64::encode_standard_no_pad(sig.to_bytes().as_slice())
        );

        let line = serde_json::to_string(&entry)?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(entry)
    }

    pub fn append_event(&mut self, event: AuditEvent) -> Result<AuditEventEntry, AuditError> {
        let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let id = uuid::Uuid::now_v7().to_string();
        let mut entry = AuditEventEntry {
            version: EVENT_SCHEMA_VERSION,
            id,
            ts,
            kind: "event".to_string(),
            event,
            sig: String::new(),
        };
        let payload = canonical_event_bytes(&entry);
        let sig: Signature = self.key.sign(&payload);
        entry.sig = format!(
            "ed25519:{}",
            base64::encode_standard_no_pad(sig.to_bytes().as_slice())
        );

        let line = serde_json::to_string(&entry)?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(entry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Canonical bytes of a v2 decision entry **without** the `sig` field.
fn canonical_decision_v2_bytes(e: &AuditEntry) -> Vec<u8> {
    let obj = serde_json::json!({
        "v": e.version,
        "id": e.id,
        "ts": e.ts,
        "tool": e.tool,
        "input_hash": e.input_hash,
        "capabilities": e.capabilities,
        "capability_provenance": e.capability_provenance,
        "decision": e.decision,
        "matched_rule": e.matched_rule,
        "policy_version": e.policy_version,
        "expedition": e.expedition,
    });
    canonical_render(&obj).into_bytes()
}

fn canonical_event_bytes(e: &AuditEventEntry) -> Vec<u8> {
    let obj = serde_json::json!({
        "v": e.version,
        "id": e.id,
        "ts": e.ts,
        "kind": e.kind,
        "event": e.event,
    });
    canonical_render(&obj).into_bytes()
}

fn canonical_render(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => if *b { "true" } else { "false" }.into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_render).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_render(&o[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// JSON value parser that rejects duplicate object keys at every depth before
/// `serde_json::Map` can collapse them with last-key-wins semantics.
struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> serde::de::Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(
            value.to_string(),
        )))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key `{key}`"
                )));
            }
            let StrictJsonValue(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictJsonValue(serde_json::Value::Object(object)))
    }
}

enum ParsedRecord {
    Decision {
        entry: AuditEntry,
        payload: Vec<u8>,
    },
    Event {
        entry: AuditEventEntry,
        payload: Vec<u8>,
    },
}

impl ParsedRecord {
    fn id(&self) -> &str {
        match self {
            ParsedRecord::Decision { entry, .. } => &entry.id,
            ParsedRecord::Event { entry, .. } => &entry.id,
        }
    }

    fn ts(&self) -> &str {
        match self {
            ParsedRecord::Decision { entry, .. } => &entry.ts,
            ParsedRecord::Event { entry, .. } => &entry.ts,
        }
    }

    fn policy_version(&self) -> Option<&str> {
        match self {
            ParsedRecord::Decision { entry, .. } => Some(&entry.policy_version),
            ParsedRecord::Event { .. } => None,
        }
    }

    fn expedition(&self) -> Option<&str> {
        match self {
            ParsedRecord::Decision { entry, .. } => entry.expedition.as_deref(),
            ParsedRecord::Event { .. } => None,
        }
    }

    fn sig(&self) -> &str {
        match self {
            ParsedRecord::Decision { entry, .. } => &entry.sig,
            ParsedRecord::Event { entry, .. } => &entry.sig,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            ParsedRecord::Decision { payload, .. } | ParsedRecord::Event { payload, .. } => payload,
        }
    }
}

fn parse_record(line: &str, line_number: usize) -> Result<ParsedRecord, AuditError> {
    let mut deserializer = serde_json::Deserializer::from_str(line);
    let StrictJsonValue(value) = StrictJsonValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    let object = value.as_object().ok_or_else(|| AuditError::InvalidSchema {
        line: line_number,
        record_kind: "record",
        reason: "the top-level JSON value must be an object".to_string(),
    })?;

    if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
        let version = schema_version(&value, line_number, "event")?;
        if version != u64::from(EVENT_SCHEMA_VERSION) {
            return Err(AuditError::UnsupportedSchema {
                line: line_number,
                record_kind: "event",
                version,
            });
        }
        validate_exact_top_level_fields(object, EVENT_V1_FIELDS, line_number, "event", version)?;
        let payload = canonical_unsigned_payload(&value);
        let entry = serde_json::from_value(value)?;
        return Ok(ParsedRecord::Event { entry, payload });
    }

    let version = schema_version(&value, line_number, "decision")?;
    let allowed_fields = match version {
        version if version == u64::from(LEGACY_DECISION_SCHEMA_VERSION) => {
            if value.get("capability_provenance").is_some() {
                return Err(AuditError::InvalidSchema {
                    line: line_number,
                    record_kind: "decision",
                    reason: "v1 must not contain capability_provenance".to_string(),
                });
            }
            DECISION_V1_FIELDS
        }
        version if version == u64::from(DECISION_SCHEMA_VERSION) => {
            if value.get("capability_provenance").is_none() {
                return Err(AuditError::InvalidSchema {
                    line: line_number,
                    record_kind: "decision",
                    reason: "v2 requires capability_provenance".to_string(),
                });
            }
            DECISION_V2_FIELDS
        }
        version => {
            return Err(AuditError::UnsupportedSchema {
                line: line_number,
                record_kind: "decision",
                version,
            });
        }
    };

    validate_exact_top_level_fields(object, allowed_fields, line_number, "decision", version)?;
    let payload = canonical_unsigned_payload(&value);
    let entry = serde_json::from_value(value)?;
    Ok(ParsedRecord::Decision { entry, payload })
}

fn validate_exact_top_level_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed_fields: &[&str],
    line: usize,
    record_kind: &'static str,
    version: u64,
) -> Result<(), AuditError> {
    if let Some(field) = object
        .keys()
        .filter(|field| !allowed_fields.contains(&field.as_str()))
        .min()
    {
        return Err(AuditError::InvalidSchema {
            line,
            record_kind,
            reason: format!("unexpected top-level field `{field}` in v{version}"),
        });
    }
    if let Some(field) = allowed_fields
        .iter()
        .find(|field| !object.contains_key(**field))
    {
        return Err(AuditError::InvalidSchema {
            line,
            record_kind,
            reason: format!("missing top-level field `{field}` in v{version}"),
        });
    }
    Ok(())
}

fn canonical_unsigned_payload(value: &serde_json::Value) -> Vec<u8> {
    // Preserve every nested field from the received record. Typed
    // deserialization is used for consumers, but never to reconstruct the
    // signed payload because doing so would silently drop unknown fields.
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("validated audit records are JSON objects")
        .remove("sig")
        .expect("validated audit records contain sig");
    canonical_render(&unsigned).into_bytes()
}

fn schema_version(
    value: &serde_json::Value,
    line: usize,
    record_kind: &'static str,
) -> Result<u64, AuditError> {
    value
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .ok_or(AuditError::InvalidSchema {
            line,
            record_kind,
            reason: "v must be a non-negative integer".to_string(),
        })
}

fn verify_record(record: &ParsedRecord, vk: &VerifyingKey, line: usize) -> Result<(), AuditError> {
    let sig_b64 = record
        .sig()
        .strip_prefix("ed25519:")
        .ok_or(AuditError::BadSignature { line })?;
    let sig_bytes =
        base64::decode_standard_no_pad(sig_b64).map_err(|_| AuditError::BadSignature { line })?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AuditError::BadSignature { line })?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(record.payload(), &sig)
        .map_err(|_| AuditError::BadSignature { line })
}

pub fn verify_log(path: &Path, vk: &VerifyingKey) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record = parse_record(&line, i + 1)?;
        verify_record(&record, vk, i + 1)?;
        count += 1;
    }
    Ok(count)
}

/// Diagnostic-level report for `gommage audit-verify --explain`. Walks every
/// entry, attempts per-line signature verification, records anomalies without
/// aborting on the first problem. Useful for forensic audits where you want
/// the full picture instead of "failed at line N".
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub entries_total: usize,
    pub entries_verified: usize,
    pub key_fingerprint: String,
    pub bypass_activations: usize,
    pub hard_stop_bypass_attempts: usize,
    pub anomalies: Vec<Anomaly>,
    #[serde(rename = "policy_versions")]
    pub policy_versions_seen: Vec<String>,
    #[serde(rename = "expeditions")]
    pub expeditions_seen: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anomaly {
    /// Line did not parse as a well-formed `AuditEntry`.
    MalformedEntry { line: usize, error: String },
    /// Entry parsed, but signature verification failed under the given key.
    /// This is the classic tamper / key-rotation flag.
    BadSignature { line: usize, entry_id: String },
    /// Timestamps should be monotonically non-decreasing. A reversal is either
    /// tampering or a clock rollback — both worth surfacing.
    TimestampOutOfOrder {
        line: usize,
        previous_ts: String,
        current_ts: String,
    },
    /// Policy version hash changed mid-log. Not an anomaly per se (reloads
    /// happen), but forensically useful to flag. First occurrence only.
    PolicyVersionChanged {
        line: usize,
        from: String,
        to: String,
    },
    HardStopBypassAttempt {
        line: usize,
        tool: String,
        original_reason: String,
    },
}

/// The ed25519 verifying key fingerprint is the hex SHA-256 of its raw 32
/// bytes, truncated to 16 chars. Stable, short, printable.
pub fn key_fingerprint(vk: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    let digest = hex::encode(h.finalize());
    digest[..16].to_string()
}

/// Append a signed `BypassActivated` event for a `GOMMAGE_BYPASS` decision.
///
/// Best-effort: a failure to load the signing key or open the audit log is
/// swallowed, because the bypass is a recovery path and must never be blocked by
/// an audit problem. Shared by the `gommage-mcp` hook binary and the
/// `gommage mcp` CLI adapter so both leave an identical, tamper-evident trail.
pub fn append_bypass_event_best_effort(
    layout: &gommage_core::runtime::HomeLayout,
    call: &ToolCall,
    eval: &EvalResult,
    bypass_decision: &str,
) {
    let Ok(sk) = layout.load_key() else {
        return;
    };
    let Ok(mut writer) = AuditWriter::open(&layout.audit_log, sk) else {
        return;
    };
    let (original_decision, original_reason, hard_stop) = match &eval.decision {
        Decision::Allow => (
            "allow".to_string(),
            "policy evaluation skipped".to_string(),
            false,
        ),
        Decision::Gommage { reason, hard_stop } => ("deny".to_string(), reason.clone(), *hard_stop),
        Decision::AskPicto { reason, .. } => ("ask".to_string(), reason.clone(), false),
    };
    let _ = writer.append_event(AuditEvent::BypassActivated {
        tool: call.tool.clone(),
        input_hash: call.input_hash(),
        capabilities: eval.capabilities.clone(),
        original_decision,
        original_reason,
        hard_stop,
        bypass_decision: bypass_decision.to_string(),
    });
}

/// Walk the log and produce a `VerifyReport`. Does NOT abort on the first
/// failure — continues recording anomalies. Returns `Ok(report)` as long as
/// the file can be opened and read; individual line errors are anomalies.
pub fn explain_log(path: &Path, vk: &VerifyingKey) -> Result<VerifyReport, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut total = 0usize;
    let mut verified = 0usize;
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let mut last_ts: Option<String> = None;
    let mut last_policy_version: Option<String> = None;
    let mut policy_versions: Vec<String> = Vec::new();
    let mut expeditions: Vec<String> = Vec::new();
    let mut bypass_activations = 0usize;
    let mut hard_stop_bypass_attempts = 0usize;

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let record = match parse_record(&line, i + 1) {
            Ok(e) => e,
            Err(e) => {
                anomalies.push(Anomaly::MalformedEntry {
                    line: i + 1,
                    error: e.to_string(),
                });
                continue;
            }
        };

        // Signature verification.
        let sig_ok = verify_record(&record, vk, i + 1).is_ok();
        if sig_ok {
            verified += 1;
        } else {
            anomalies.push(Anomaly::BadSignature {
                line: i + 1,
                entry_id: record.id().to_string(),
            });
        }

        // Timestamp ordering.
        if let Some(prev) = &last_ts
            && record.ts() < prev.as_str()
        {
            anomalies.push(Anomaly::TimestampOutOfOrder {
                line: i + 1,
                previous_ts: prev.clone(),
                current_ts: record.ts().to_string(),
            });
        }
        last_ts = Some(record.ts().to_string());

        // Policy version tracking.
        if let Some(policy_version) = record.policy_version() {
            if let Some(prev) = &last_policy_version
                && prev != policy_version
            {
                anomalies.push(Anomaly::PolicyVersionChanged {
                    line: i + 1,
                    from: prev.clone(),
                    to: policy_version.to_string(),
                });
            }
            last_policy_version = Some(policy_version.to_string());

            if !policy_versions.iter().any(|v| v == policy_version) {
                policy_versions.push(policy_version.to_string());
            }
        }

        if let Some(e) = record.expedition()
            && !expeditions.iter().any(|seen| seen == e)
        {
            expeditions.push(e.to_string());
        }

        if let ParsedRecord::Event { entry, .. } = &record
            && let AuditEvent::BypassActivated {
                tool,
                original_reason,
                hard_stop,
                bypass_decision,
                ..
            } = &entry.event
        {
            bypass_activations += 1;
            if *hard_stop {
                hard_stop_bypass_attempts += 1;
                if bypass_decision == "allow" {
                    anomalies.push(Anomaly::HardStopBypassAttempt {
                        line: i + 1,
                        tool: tool.clone(),
                        original_reason: original_reason.clone(),
                    });
                }
            }
        }
    }

    Ok(VerifyReport {
        entries_total: total,
        entries_verified: verified,
        key_fingerprint: key_fingerprint(vk),
        bypass_activations,
        hard_stop_bypass_attempts,
        anomalies,
        policy_versions_seen: policy_versions,
        expeditions_seen: expeditions,
    })
}

mod base64 {
    use base64::{Engine as _, engine::general_purpose};
    pub fn encode_standard_no_pad(bytes: &[u8]) -> String {
        general_purpose::STANDARD_NO_PAD.encode(bytes)
    }
    pub fn decode_standard_no_pad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD_NO_PAD.decode(s.as_bytes())
    }
}

#[cfg(test)]
mod tests;
