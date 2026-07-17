//! Local out-of-band approval inbox.
//!
//! Approval requests are operational state: they let a human review an
//! `ask_picto` decision and mint a scope- or input-bound picto without editing
//! policy.
//! The normal path also emits independently signed audit records. This inbox is
//! unsigned, append-oriented operational JSONL so it remains easy for agents
//! and humans to inspect; it is not a cryptographic completeness boundary.

use crate::{
    Capability, EvalResult, MatchedRule, ToolCall, error::GommageError, picto::PictoBinding,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use time::{
    Date, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset,
    format_description::well_known::Rfc3339,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    /// A matching call consumed a Picto while this request was pending.
    Satisfied,
    /// Current policy no longer matches the authority this request described.
    Superseded,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Satisfied => "satisfied",
            ApprovalStatus::Superseded => "superseded",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    #[serde(with = "approval_time")]
    pub created_at: OffsetDateTime,
    pub tool: String,
    pub input_hash: String,
    pub required_scope: String,
    #[serde(default)]
    pub bind_input: bool,
    pub reason: String,
    pub capabilities: Vec<Capability>,
    pub matched_rule: Option<MatchedRule>,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolution {
    pub request_id: String,
    #[serde(with = "approval_time")]
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
        bind_input: bool,
        reason: &str,
        eval: &EvalResult,
    ) -> ApprovalRequest {
        let id = request_id(input_hash, required_scope, bind_input, &eval.policy_version);
        ApprovalRequest {
            id,
            created_at: OffsetDateTime::now_utc(),
            tool: tool.to_string(),
            input_hash: input_hash.to_string(),
            required_scope: required_scope.to_string(),
            bind_input,
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
        self.with_exclusive_lock(|| {
            let states = self.replay_unlocked()?;
            if let Some(existing) = states.values().find(|state| {
                state.status == ApprovalStatus::Pending && same_request(&state.request, &request)
            }) {
                return Ok(existing.request.clone());
            }
            if states.contains_key(&request.id) {
                request.id = reopened_request_id(&request.id);
            }
            self.append_unlocked(&ApprovalRecord::Requested {
                request: request.clone(),
            })?;
            Ok(request)
        })
    }

    pub fn request_for_ask(
        &self,
        call: &ToolCall,
        eval: &EvalResult,
        required_scope: &str,
        bind_input: bool,
        reason: &str,
    ) -> Result<ApprovalRequest, GommageError> {
        let request = Self::request_from_eval(
            &call.tool,
            &call.input_hash(),
            required_scope,
            bind_input,
            reason,
            eval,
        );
        self.record_request(request)
    }

    pub fn resolve(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        reason: &str,
        picto_id: Option<String>,
    ) -> Result<ApprovalResolution, GommageError> {
        if status == ApprovalStatus::Pending {
            return Err(GommageError::Policy(
                "an approval resolution cannot remain pending".to_string(),
            ));
        }
        self.with_exclusive_lock(|| {
            let states = self.replay_unlocked()?;
            let state = states.get(request_id).ok_or_else(|| {
                GommageError::Policy(format!("approval request {request_id:?} not found"))
            })?;
            if state.status != ApprovalStatus::Pending {
                return Err(GommageError::Policy(format!(
                    "approval request {request_id:?} is already {}",
                    state.status.as_str()
                )));
            }
            self.append_resolution_unlocked(request_id, status, reason, picto_id)
        })
    }

    /// Resolve one exactly matching pending request when a Picto authorizes the
    /// call. This records successful use without mislabeling it as a human
    /// approval.
    #[allow(clippy::too_many_arguments)]
    pub fn satisfy_matching_call(
        &self,
        tool: &str,
        input_hash: &str,
        required_scope: &str,
        binding: &PictoBinding,
        policy_version: &str,
        picto_id: &str,
    ) -> Result<Option<ApprovalResolution>, GommageError> {
        let binding_matches_call = match binding {
            PictoBinding::ScopeOnly => true,
            PictoBinding::ExactInput {
                input_hash: bound_hash,
            } => bound_hash == input_hash,
        };
        if !binding_matches_call {
            return Ok(None);
        }
        self.with_exclusive_lock(|| {
            let states = self.replay_unlocked()?;
            let matching_id = states.values().find_map(|state| {
                let request = &state.request;
                (state.status == ApprovalStatus::Pending
                    && request.tool == tool
                    && request.input_hash == input_hash
                    && request.required_scope == required_scope
                    && request.bind_input == binding.is_exact_input()
                    && request.policy_version == policy_version)
                    .then(|| request.id.clone())
            });
            let Some(request_id) = matching_id else {
                return Ok(None);
            };
            self.append_resolution_unlocked(
                &request_id,
                ApprovalStatus::Satisfied,
                "matching call authorized by consumed Picto",
                Some(picto_id.to_string()),
            )
            .map(Some)
        })
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
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let lock = OpenOptions::new().read(true).open(&self.path)?;
        lock.lock_shared()?;
        let result = self.replay_unlocked();
        File::unlock(&lock)?;
        result
    }

    fn replay_unlocked(&self) -> Result<BTreeMap<String, ApprovalState>, GommageError> {
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

    fn append_resolution_unlocked(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        reason: &str,
        picto_id: Option<String>,
    ) -> Result<ApprovalResolution, GommageError> {
        let resolution = ApprovalResolution {
            request_id: request_id.to_string(),
            resolved_at: OffsetDateTime::now_utc(),
            status,
            reason: reason.to_string(),
            picto_id,
        };
        self.append_unlocked(&ApprovalRecord::Resolved {
            resolution: resolution.clone(),
        })?;
        Ok(resolution)
    }

    fn append_unlocked(&self, record: &ApprovalRecord) -> Result<(), GommageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }

    fn with_exclusive_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, GommageError>,
    ) -> Result<T, GommageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        lock.lock()?;
        let result = operation();
        File::unlock(&lock)?;
        result
    }
}

fn request_id(
    input_hash: &str,
    required_scope: &str,
    bind_input: bool,
    policy_version: &str,
) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(input_hash.as_bytes());
    h.update(b"\0");
    h.update(required_scope.as_bytes());
    h.update(b"\0");
    let binding: &[u8] = if bind_input {
        b"input-bound"
    } else {
        b"scope-only"
    };
    h.update(binding);
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
    a.tool == b.tool
        && a.input_hash == b.input_hash
        && a.required_scope == b.required_scope
        && a.bind_input == b.bind_input
        && a.policy_version == b.policy_version
}

mod approval_time {
    use super::*;
    use serde::{Deserializer, Serializer, de};

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = value.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ApprovalTimeVisitor)
    }

    struct ApprovalTimeVisitor;

    impl<'de> de::Visitor<'de> for ApprovalTimeVisitor {
        type Value = OffsetDateTime;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an RFC3339 timestamp or legacy time tuple")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            OffsetDateTime::parse(value, &Rfc3339).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let year = next::<i32, _>(&mut seq, "year")?;
            let ordinal = next::<u16, _>(&mut seq, "ordinal day")?;
            let hour = next::<u8, _>(&mut seq, "hour")?;
            let minute = next::<u8, _>(&mut seq, "minute")?;
            let second = next::<u8, _>(&mut seq, "second")?;
            let nanosecond = next::<u32, _>(&mut seq, "nanosecond")?;
            let offset_hour = next::<i8, _>(&mut seq, "offset hour")?;
            let offset_minute = next::<i8, _>(&mut seq, "offset minute")?;
            let offset_second = next::<i8, _>(&mut seq, "offset second")?;
            let date = Date::from_ordinal_date(year, ordinal).map_err(de::Error::custom)?;
            let time =
                Time::from_hms_nano(hour, minute, second, nanosecond).map_err(de::Error::custom)?;
            let offset = UtcOffset::from_hms(offset_hour, offset_minute, offset_second)
                .map_err(de::Error::custom)?;
            Ok(PrimitiveDateTime::new(date, time).assume_offset(offset))
        }
    }

    fn next<'de, T, A>(seq: &mut A, field: &'static str) -> Result<T, A::Error>
    where
        T: Deserialize<'de>,
        A: de::SeqAccess<'de>,
    {
        seq.next_element()?
            .ok_or_else(|| de::Error::missing_field(field))
    }
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
                bind_input: false,
            },
            matched_rule: Some(MatchedRule {
                name: "gate-main".to_string(),
                file: "20-git.yaml".to_string(),
                index: 0,
            }),
            capabilities: vec![Capability::new("git.push:refs/heads/main")],
            policy_version: "sha256:test".to_string(),
            capability_provenance: Vec::new(),
            authorization: None,
        }
    }

    #[test]
    fn request_ids_are_deterministic_for_same_decision() {
        let a = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
            "reason",
            &eval(),
        );
        let b = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
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
            false,
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
            false,
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
    fn consumed_picto_satisfies_only_the_exact_pending_call() {
        let dir = tempdir().unwrap();
        let store = ApprovalStore::open(&dir.path().join("approvals.jsonl"));
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
            "reason",
            &eval(),
        );
        let id = request.id.clone();
        store.record_request(request).unwrap();

        for (tool, input_hash, scope, binding, policy) in [
            (
                "Write",
                "sha256:input",
                "git.push:main",
                PictoBinding::ScopeOnly,
                "sha256:test",
            ),
            (
                "Bash",
                "sha256:other",
                "git.push:main",
                PictoBinding::ScopeOnly,
                "sha256:test",
            ),
            (
                "Bash",
                "sha256:input",
                "git.push:other",
                PictoBinding::ScopeOnly,
                "sha256:test",
            ),
            (
                "Bash",
                "sha256:input",
                "git.push:main",
                PictoBinding::ExactInput {
                    input_hash: "sha256:input".to_string(),
                },
                "sha256:test",
            ),
            (
                "Bash",
                "sha256:input",
                "git.push:main",
                PictoBinding::ScopeOnly,
                "sha256:changed",
            ),
        ] {
            assert!(
                store
                    .satisfy_matching_call(tool, input_hash, scope, &binding, policy, "picto_1",)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            store.get(&id).unwrap().unwrap().status,
            ApprovalStatus::Pending
        );

        let resolution = store
            .satisfy_matching_call(
                "Bash",
                "sha256:input",
                "git.push:main",
                &PictoBinding::ScopeOnly,
                "sha256:test",
                "picto_1",
            )
            .unwrap()
            .unwrap();

        assert_eq!(resolution.status, ApprovalStatus::Satisfied);
        assert_eq!(resolution.picto_id.as_deref(), Some("picto_1"));
        assert_eq!(
            store.get(&id).unwrap().unwrap().status,
            ApprovalStatus::Satisfied
        );
    }

    #[test]
    fn concurrent_duplicate_requests_remain_one_pending_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("approvals.jsonl");
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
            "reason",
            &eval(),
        );
        let threads = (0..8)
            .map(|_| {
                let path = path.clone();
                let request = request.clone();
                std::thread::spawn(move || {
                    ApprovalStore::open(&path).record_request(request).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }

        let states = ApprovalStore::open(&path).list().unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].status, ApprovalStatus::Pending);
    }

    #[test]
    fn resolved_requests_can_be_reopened_without_spamming_pending_requests() {
        let dir = tempdir().unwrap();
        let store = ApprovalStore::open(&dir.path().join("approvals.jsonl"));
        let request = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
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

    #[test]
    fn approval_timestamps_serialize_as_rfc3339_and_read_legacy_tuple() {
        let request = ApprovalRequest {
            id: "apr_test".to_string(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            tool: "Bash".to_string(),
            input_hash: "sha256:test".to_string(),
            required_scope: "proc.exec:echo".to_string(),
            bind_input: false,
            reason: "test".to_string(),
            capabilities: Vec::new(),
            matched_rule: None,
            policy_version: "sha256:test".to_string(),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["created_at"].as_str(), Some("1970-01-01T00:00:00Z"));

        let legacy = serde_json::json!({
            "id": "apr_legacy",
            "created_at": [2026, 113, 7, 40, 28, 811654143, 0, 0, 0],
            "tool": "Bash",
            "input_hash": "sha256:legacy",
            "required_scope": "proc.exec:echo",
            "reason": "legacy",
            "capabilities": [],
            "matched_rule": null,
            "policy_version": "sha256:legacy"
        });
        let decoded: ApprovalRequest = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.created_at.year(), 2026);
        assert_eq!(decoded.created_at.ordinal(), 113);
        assert_eq!(decoded.created_at.nanosecond(), 811_654_143);
        assert!(!decoded.bind_input);
    }

    #[test]
    fn input_bound_requests_have_a_distinct_identity() {
        let scope_only = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            false,
            "reason",
            &eval(),
        );
        let input_bound = ApprovalStore::request_from_eval(
            "Bash",
            "sha256:input",
            "git.push:main",
            true,
            "reason",
            &eval(),
        );
        assert_ne!(scope_only.id, input_bound.id);
        assert!(input_bound.bind_input);
    }
}
