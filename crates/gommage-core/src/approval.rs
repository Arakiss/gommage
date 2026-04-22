//! Local out-of-band approval inbox.
//!
//! Approval requests are operational state: they let a human review an
//! `ask_picto` decision and mint an exact-scope picto without editing policy.
//! Forensics live in the signed audit log; this store is append-only JSONL so
//! it remains easy for agents and humans to inspect.

use crate::{Capability, EvalResult, MatchedRule, ToolCall, error::GommageError};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub created_at: OffsetDateTime,
    pub tool: String,
    pub input_hash: String,
    pub required_scope: String,
    pub reason: String,
    pub capabilities: Vec<Capability>,
    pub matched_rule: Option<MatchedRule>,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolution {
    pub request_id: String,
    pub resolved_at: OffsetDateTime,
    pub status: ApprovalStatus,
    pub reason: String,
    pub picto_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalState {
    pub request: ApprovalRequest,
    pub status: ApprovalStatus,
    pub resolution: Option<ApprovalResolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ApprovalRecord {
    Requested { request: ApprovalRequest },
    Resolved { resolution: ApprovalResolution },
}

pub struct ApprovalStore {
    path: PathBuf,
}

impl ApprovalStore {
    pub fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn request_from_eval(
        tool: &str,
        input_hash: &str,
        required_scope: &str,
        reason: &str,
        eval: &EvalResult,
    ) -> ApprovalRequest {
        let id = request_id(input_hash, required_scope, &eval.policy_version);
        ApprovalRequest {
            id,
            created_at: OffsetDateTime::now_utc(),
            tool: tool.to_string(),
            input_hash: input_hash.to_string(),
            required_scope: required_scope.to_string(),
            reason: reason.to_string(),
            capabilities: eval.capabilities.clone(),
            matched_rule: eval.matched_rule.clone(),
            policy_version: eval.policy_version.clone(),
        }
    }

    pub fn record_request(
        &self,
        mut request: ApprovalRequest,
    ) -> Result<ApprovalRequest, GommageError> {
        let states = self.replay()?;
        if let Some(existing) = states.values().find(|state| {
            state.status == ApprovalStatus::Pending && same_request(&state.request, &request)
        }) {
            return Ok(existing.request.clone());
        }
        if states.contains_key(&request.id) {
            request.id = reopened_request_id(&request.id);
        }
        self.append(&ApprovalRecord::Requested {
            request: request.clone(),
        })?;
        Ok(request)
    }

    pub fn request_for_ask(
        &self,
        call: &ToolCall,
        eval: &EvalResult,
        required_scope: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, GommageError> {
        let request =
            Self::request_from_eval(&call.tool, &call.input_hash(), required_scope, reason, eval);
        self.record_request(request)
    }

    pub fn resolve(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        reason: &str,
        picto_id: Option<String>,
    ) -> Result<ApprovalResolution, GommageError> {
        let state = self.get(request_id)?.ok_or_else(|| {
            GommageError::Policy(format!("approval request {request_id:?} not found"))
        })?;
        if state.status != ApprovalStatus::Pending {
            return Err(GommageError::Policy(format!(
                "approval request {request_id:?} is already {}",
                state.status.as_str()
            )));
        }
        let resolution = ApprovalResolution {
            request_id: request_id.to_string(),
            resolved_at: OffsetDateTime::now_utc(),
            status,
            reason: reason.to_string(),
            picto_id,
        };
        self.append(&ApprovalRecord::Resolved {
            resolution: resolution.clone(),
        })?;
        Ok(resolution)
    }

    pub fn list(&self) -> Result<Vec<ApprovalState>, GommageError> {
        let states = self.replay()?;
        Ok(states.into_values().collect())
    }

    pub fn pending(&self) -> Result<Vec<ApprovalState>, GommageError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|state| state.status == ApprovalStatus::Pending)
            .collect())
    }

    pub fn get(&self, request_id: &str) -> Result<Option<ApprovalState>, GommageError> {
        Ok(self.replay()?.remove(request_id))
    }

    fn replay(&self) -> Result<BTreeMap<String, ApprovalState>, GommageError> {
        let mut states = BTreeMap::new();
        if !self.path.exists() {
            return Ok(states);
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: ApprovalRecord = serde_json::from_str(&line)?;
            match record {
                ApprovalRecord::Requested { request } => {
                    states.entry(request.id.clone()).or_insert(ApprovalState {
                        request,
                        status: ApprovalStatus::Pending,
                        resolution: None,
                    });
                }
                ApprovalRecord::Resolved { resolution } => {
                    if let Some(state) = states.get_mut(&resolution.request_id) {
                        state.status = resolution.status;
                        state.resolution = Some(resolution);
                    }
                }
            }
        }
        Ok(states)
    }

    fn append(&self, record: &ApprovalRecord) -> Result<(), GommageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(record)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }
}

fn request_id(input_hash: &str, required_scope: &str, policy_version: &str) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(input_hash.as_bytes());
    h.update(b"\0");
    h.update(required_scope.as_bytes());
    h.update(b"\0");
    h.update(policy_version.as_bytes());
    let digest = hex::encode(h.finalize());
    format!("apr_{}", &digest[..20])
}

fn reopened_request_id(base: &str) -> String {
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    format!("{base}_{}", &suffix[..8])
}

fn same_request(a: &ApprovalRequest, b: &ApprovalRequest) -> bool {
    a.input_hash == b.input_hash
        && a.required_scope == b.required_scope
        && a.policy_version == b.policy_version
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decision, EvalResult};
    use tempfile::tempdir;

    fn eval() -> EvalResult {
        EvalResult {
            decision: Decision::AskPicto {
                required_scope: "git.push:main".to_string(),
                reason: "main push requires approval".to_string(),
            },
            matched_rule: Some(MatchedRule {
                name: "gate-main".to_string(),
                file: "20-git.yaml".to_string(),
                index: 0,
            }),
            capabilities: vec![Capability::new("git.push:refs/heads/main")],
            policy_version: "sha256:test".to_string(),
        }
    }

    #[test]
    fn request_ids_are_deterministic_for_same_decision() {
        let a = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            "reason",
            &eval(),
        );
        let b = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            "reason",
            &eval(),
        );
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn repeated_pending_requests_do_not_duplicate_state() {
        let dir = tempdir().unwrap();
        let store = ApprovalStore::open(&dir.path().join("approvals.jsonl"));
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            "reason",
            &eval(),
        );
        let id = request.id.clone();

        store.record_request(request.clone()).unwrap();
        store.record_request(request).unwrap();

        let states = store.list().unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].request.id, id);
        assert_eq!(states[0].status, ApprovalStatus::Pending);
    }

    #[test]
    fn resolving_pending_request_updates_state() {
        let dir = tempdir().unwrap();
        let store = ApprovalStore::open(&dir.path().join("approvals.jsonl"));
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            "reason",
            &eval(),
        );
        let id = request.id.clone();

        store.record_request(request).unwrap();
        store
            .resolve(
                &id,
                ApprovalStatus::Approved,
                "looks correct",
                Some("picto_1".to_string()),
            )
            .unwrap();

        let state = store.get(&id).unwrap().unwrap();
        assert_eq!(state.status, ApprovalStatus::Approved);
        assert_eq!(
            state.resolution.unwrap().picto_id.as_deref(),
            Some("picto_1")
        );
    }

    #[test]
    fn resolved_requests_can_be_reopened_without_spamming_pending_requests() {
        let dir = tempdir().unwrap();
        let store = ApprovalStore::open(&dir.path().join("approvals.jsonl"));
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            "reason",
            &eval(),
        );
        let original_id = request.id.clone();

        store.record_request(request.clone()).unwrap();
        store
            .resolve(
                &original_id,
                ApprovalStatus::Denied,
                "not enough context",
                None,
            )
            .unwrap();
        let reopened = store.record_request(request.clone()).unwrap();
        let duplicate = store.record_request(request).unwrap();

        assert_ne!(reopened.id, original_id);
        assert_eq!(duplicate.id, reopened.id);
        let states = store.list().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(
            states
                .iter()
                .filter(|state| state.status == ApprovalStatus::Pending)
                .count(),
            1
        );
        assert_eq!(
            states
                .iter()
                .filter(|state| state.status == ApprovalStatus::Denied)
                .count(),
            1
        );
    }
}
