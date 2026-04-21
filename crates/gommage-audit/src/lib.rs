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

pub fn verify_log(path: &Path, vk: &VerifyingKey) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;
        let sig_b64 = entry
            .sig
            .strip_prefix("ed25519:")
            .ok_or(AuditError::BadSignature { line: i + 1 })?;
        let sig_bytes = base64::decode_standard_no_pad(sig_b64)
            .map_err(|_| AuditError::BadSignature { line: i + 1 })?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::BadSignature { line: i + 1 })?;
        let sig = Signature::from_bytes(&sig_arr);
        let payload = canonical_bytes(&entry);
        vk.verify(&payload, &sig)
            .map_err(|_| AuditError::BadSignature { line: i + 1 })?;
        count += 1;
    }
    Ok(count)
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
