//! Append-only audit log for Gommage decisions.
//!
//! Each decision produces one JSONL line of the form:
//!
//! ```json
//! {"v":1,"id":"...","ts":"...","tool":"Bash","input_hash":"sha256:...",
//!  "capabilities":["git.push:refs/heads/main"],"decision":{...},
//!  "matched_rule":{"name":"gate-main-push","file":"...","index":0},
//!  "policy_version":"sha256:...","sig":"ed25519:..."}
//! ```
//!
//! The signature covers the canonical bytes of the object **minus the `sig`
//! field itself**, so verification is line-local: kill the daemon mid-write
//! and at most the last line is corrupt — everything before is still valid.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gommage_core::{Capability, Decision, EvalResult, MatchedRule, ToolCall};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed at line {line}")]
    BadSignature { line: usize },
    #[error("time: {0}")]
    Time(#[from] time::error::Format),
}

const AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    #[serde(rename = "v")]
    pub version: u32,
    pub id: String,
    pub ts: String,
    pub tool: String,
    pub input_hash: String,
    pub capabilities: Vec<Capability>,
    pub decision: Decision,
    pub matched_rule: Option<MatchedRule>,
    pub policy_version: String,
    pub expedition: Option<String>,
    /// `ed25519:<base64>` signature over everything above.
    pub sig: String,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<WebhookSignatureAudit>,
    },
    ApprovalWebhookFailed {
        id: String,
        url: String,
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
            version: AUDIT_SCHEMA_VERSION,
            id,
            ts,
            tool: call.tool.clone(),
            input_hash: call.input_hash(),
            capabilities: eval.capabilities.clone(),
            decision: eval.decision.clone(),
            matched_rule: eval.matched_rule.clone(),
            policy_version: eval.policy_version.clone(),
            expedition: expedition.map(str::to_string),
            sig: String::new(),
        };
        let payload = canonical_bytes(&entry);
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
            version: AUDIT_SCHEMA_VERSION,
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

/// Canonical bytes of an entry **without** the `sig` field. Used for signing
/// and verifying. We emit the fields in a fixed order so byte-output is stable
/// across serde versions.
fn canonical_bytes(e: &AuditEntry) -> Vec<u8> {
    let obj = serde_json::json!({
        "v": e.version,
        "id": e.id,
        "ts": e.ts,
        "tool": e.tool,
        "input_hash": e.input_hash,
        "capabilities": e.capabilities,
        "decision": e.decision,
        "matched_rule": e.matched_rule,
        "policy_version": e.policy_version,
        "expedition": e.expedition,
    });
    // Sorted key rendering.
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

enum ParsedRecord {
    Decision(AuditEntry),
    Event(AuditEventEntry),
}

impl ParsedRecord {
    fn id(&self) -> &str {
        match self {
            ParsedRecord::Decision(e) => &e.id,
            ParsedRecord::Event(e) => &e.id,
        }
    }

    fn ts(&self) -> &str {
        match self {
            ParsedRecord::Decision(e) => &e.ts,
            ParsedRecord::Event(e) => &e.ts,
        }
    }

    fn policy_version(&self) -> Option<&str> {
        match self {
            ParsedRecord::Decision(e) => Some(&e.policy_version),
            ParsedRecord::Event(_) => None,
        }
    }

    fn expedition(&self) -> Option<&str> {
        match self {
            ParsedRecord::Decision(e) => e.expedition.as_deref(),
            ParsedRecord::Event(_) => None,
        }
    }

    fn payload(&self) -> Vec<u8> {
        match self {
            ParsedRecord::Decision(e) => canonical_bytes(e),
            ParsedRecord::Event(e) => canonical_event_bytes(e),
        }
    }

    fn sig(&self) -> &str {
        match self {
            ParsedRecord::Decision(e) => &e.sig,
            ParsedRecord::Event(e) => &e.sig,
        }
    }
}

fn parse_record(line: &str) -> Result<ParsedRecord, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
        serde_json::from_value(value).map(ParsedRecord::Event)
    } else {
        serde_json::from_value(value).map(ParsedRecord::Decision)
    }
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
    let payload = record.payload();
    vk.verify(&payload, &sig)
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
        let record = parse_record(&line)?;
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
        let record = match parse_record(&line) {
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

        if let ParsedRecord::Event(entry) = &record
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
mod tests {
    use super::*;
    use gommage_core::Decision;
    use rand_core::OsRng;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn append_and_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![Capability::new("proc.exec:ls")],
            policy_version: "sha256:test".into(),
        };
        w.append(&call, &eval, Some("expedition-x")).unwrap();
        w.append(&call, &eval, Some("expedition-x")).unwrap();
        let n = verify_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn append_event_and_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        w.append_event(AuditEvent::PictoRevoked { id: "p1".into() })
            .unwrap();
        drop(w);

        let n = verify_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn explain_counts_bypass_events_and_flags_hard_stop_allows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        w.append_event(AuditEvent::BypassActivated {
            tool: "Bash".into(),
            input_hash: "sha256:test".into(),
            capabilities: vec![Capability::new("proc.exec:rm -rf /")],
            original_decision: "deny".into(),
            original_reason: "hard-stop hs.rm-rf-root".into(),
            hard_stop: true,
            bypass_decision: "allow".into(),
        })
        .unwrap();
        drop(w);

        let report = explain_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(report.entries_total, 1);
        assert_eq!(report.entries_verified, 1);
        assert_eq!(report.bypass_activations, 1);
        assert_eq!(report.hard_stop_bypass_attempts, 1);
        assert!(
            report
                .anomalies
                .iter()
                .any(|a| matches!(a, Anomaly::HardStopBypassAttempt { .. }))
        );
    }

    #[test]
    fn mixed_decision_and_event_log_verifies() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:v1".into(),
        };
        w.append(&call, &eval, Some("exp")).unwrap();
        w.append_event(AuditEvent::PictoRevoked { id: "p1".into() })
            .unwrap();
        drop(w);

        let report = explain_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(report.entries_total, 2);
        assert_eq!(report.entries_verified, 2);
        assert_eq!(report.policy_versions_seen, vec!["sha256:v1"]);
        assert_eq!(report.expeditions_seen, vec!["exp"]);
    }

    #[test]
    fn explain_reports_total_verified_and_no_anomalies_on_clean_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:v1".into(),
        };
        for _ in 0..3 {
            w.append(&call, &eval, Some("exp")).unwrap();
        }
        drop(w);

        let report = explain_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(report.entries_total, 3);
        assert_eq!(report.entries_verified, 3);
        assert_eq!(report.key_fingerprint.len(), 16);
        assert!(report.anomalies.is_empty());
        assert_eq!(report.policy_versions_seen, vec!["sha256:v1"]);
        assert_eq!(report.expeditions_seen, vec!["exp"]);
    }

    #[test]
    fn explain_flags_policy_version_change() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval_a = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:v1".into(),
        };
        let eval_b = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:v2".into(),
        };
        w.append(&call, &eval_a, None).unwrap();
        w.append(&call, &eval_b, None).unwrap();
        drop(w);

        let report = explain_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(report.entries_verified, 2);
        assert_eq!(report.policy_versions_seen.len(), 2);
        assert!(
            report
                .anomalies
                .iter()
                .any(|a| matches!(a, Anomaly::PolicyVersionChanged { .. }))
        );
    }

    #[test]
    fn explain_flags_bad_signature_but_keeps_walking() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:v1".into(),
        };
        w.append(&call, &eval, None).unwrap();
        w.append(&call, &eval, None).unwrap();
        drop(w);

        // Tamper one line in the middle.
        let content = std::fs::read_to_string(&path).unwrap();
        let corrupted = content.replacen("\"Bash\"", "\"Bashh\"", 1);
        std::fs::write(&path, corrupted).unwrap();

        let report = explain_log(&path, &sk.verifying_key()).unwrap();
        assert_eq!(report.entries_total, 2);
        assert_eq!(report.entries_verified, 1);
        assert!(
            report
                .anomalies
                .iter()
                .any(|a| matches!(a, Anomaly::BadSignature { .. }))
        );
    }

    #[test]
    fn tampered_line_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sk = SigningKey::generate(&mut OsRng);
        let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command":"ls"}),
        };
        let eval = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![],
            policy_version: "sha256:test".into(),
        };
        w.append(&call, &eval, None).unwrap();
        drop(w);
        // Corrupt a field
        let content = std::fs::read_to_string(&path).unwrap();
        let corrupted = content.replace("\"Bash\"", "\"Sneak\"");
        std::fs::write(&path, corrupted).unwrap();
        assert!(verify_log(&path, &sk.verifying_key()).is_err());
    }
}
