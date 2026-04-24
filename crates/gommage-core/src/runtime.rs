//! Shared runtime wiring: home directory layout, keypair, expedition state.
//!
//! Keeps the CLI, daemon, and MCP adapter from diverging on how they open
//! `~/.gommage/`. This module deliberately does *not* do policy evaluation —
//! that stays pure in `evaluator.rs`.

use crate::{
    ApprovalStore, CapabilityMapper, PictoStore, Policy, error::GommageError, policy::PolicyLayer,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// The canonical location of the Gommage home directory.
/// Respects `$GOMMAGE_HOME`; falls back to `~/.gommage`.
pub fn home_dir() -> PathBuf {
    if let Ok(p) = std::env::var("GOMMAGE_HOME") {
        return PathBuf::from(p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gommage")
}

/// Base environment used for policy `${VAR}` substitution even when no
/// expedition is active.
pub fn default_policy_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    if let Ok(home) = std::env::var("HOME") {
        env.insert("HOME".into(), home);
    }
    env
}

const ORG_POLICY_DIR_ENV: &str = "GOMMAGE_ORG_POLICY_DIR";
const PROJECT_POLICY_DIR_ENV: &str = "GOMMAGE_PROJECT_POLICY_DIR";

pub fn active_policy_layers(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
) -> Result<Vec<PolicyLayer>, GommageError> {
    let mut layers = Vec::new();
    if let Some(dir) = explicit_policy_dir(ORG_POLICY_DIR_ENV)? {
        push_policy_layer(&mut layers, "org", dir);
    }
    if let Some(dir) = explicit_policy_dir(PROJECT_POLICY_DIR_ENV)? {
        push_policy_layer(&mut layers, "project", dir);
    } else if let Some(expedition) = expedition {
        let dir = expedition.root.join(".gommage").join("policy.d");
        if dir.is_dir() {
            push_policy_layer(&mut layers, "project", dir);
        }
    }
    push_policy_layer(&mut layers, "user", layout.policy_dir.clone());
    Ok(layers)
}

pub fn load_active_policy(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
    env: &HashMap<String, String>,
) -> Result<Policy, GommageError> {
    let layers = active_policy_layers(layout, expedition)?;
    Policy::load_from_layers(&layers, env)
}

fn explicit_policy_dir(var: &str) -> Result<Option<PathBuf>, GommageError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(trimmed);
    if !path.is_dir() {
        return Err(GommageError::Policy(format!(
            "{var} points to {}, but it is not a directory",
            path.display()
        )));
    }
    Ok(Some(path))
}

fn push_policy_layer(layers: &mut Vec<PolicyLayer>, name: &str, dir: PathBuf) {
    if layers.iter().any(|layer| layer.dir == dir) {
        return;
    }
    layers.push(PolicyLayer::new(name, dir));
}

pub struct HomeLayout {
    pub root: PathBuf,
    pub policy_dir: PathBuf,
    pub capabilities_dir: PathBuf,
    pub pictos_db: PathBuf,
    pub approvals_log: PathBuf,
    pub approval_webhook_dlq: PathBuf,
    pub audit_log: PathBuf,
    pub key_file: PathBuf,
    pub expedition_file: PathBuf,
    pub socket: PathBuf,
}

impl HomeLayout {
    pub fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            policy_dir: root.join("policy.d"),
            capabilities_dir: root.join("capabilities.d"),
            pictos_db: root.join("pictos.sqlite"),
            approvals_log: root.join("approvals.jsonl"),
            approval_webhook_dlq: root.join("approval-webhook-dlq.jsonl"),
            audit_log: root.join("audit.log"),
            key_file: root.join("key.ed25519"),
            expedition_file: root.join("expedition.json"),
            socket: root.join("gommage.sock"),
        }
    }

    /// Create missing directories with 0700, generate keypair if absent, seed
    /// empty policy.d + capabilities.d directories. Idempotent.
    pub fn ensure(&self) -> Result<(), GommageError> {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(&self.policy_dir)?;
        fs::create_dir_all(&self.capabilities_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&self.root, &self.policy_dir, &self.capabilities_dir] {
                let mut perms = fs::metadata(dir)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms)?;
            }
        }
        if !self.key_file.exists() {
            let sk = SigningKey::generate(&mut OsRng);
            fs::write(&self.key_file, sk.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&self.key_file)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&self.key_file, perms)?;
            }
        }
        Ok(())
    }

    pub fn load_key(&self) -> Result<SigningKey, GommageError> {
        let bytes = fs::read(&self.key_file)?;
        if bytes.len() != 32 {
            return Err(GommageError::BadSignature);
        }
        let arr: [u8; 32] = bytes.try_into().map_err(|_| GommageError::BadSignature)?;
        Ok(SigningKey::from_bytes(&arr))
    }

    pub fn load_verifying_key(&self) -> Result<VerifyingKey, GommageError> {
        Ok(self.load_key()?.verifying_key())
    }
}

impl Default for HomeLayout {
    fn default() -> Self {
        Self::at(&home_dir())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expedition {
    pub name: String,
    pub root: PathBuf,
    pub started_at: time::OffsetDateTime,
}

impl Expedition {
    pub fn save(&self, file: &Path) -> Result<(), GommageError> {
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(file, json)?;
        Ok(())
    }

    pub fn load(file: &Path) -> Result<Option<Self>, GommageError> {
        if !file.exists() {
            return Ok(None);
        }
        let bytes = fs::read(file)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn clear(file: &Path) -> Result<(), GommageError> {
        if file.exists() {
            fs::remove_file(file)?;
        }
        Ok(())
    }

    /// The env map used for ${VAR} substitution at policy load time.
    pub fn policy_env(&self) -> HashMap<String, String> {
        let mut env = default_policy_env();
        env.insert("EXPEDITION_NAME".into(), self.name.clone());
        env.insert(
            "EXPEDITION_ROOT".into(),
            self.root.to_string_lossy().to_string(),
        );
        env
    }
}

/// Everything needed to evaluate a tool call: policy + mapper + picto store.
///
/// Construct with `Runtime::open(layout)` after `layout.ensure()`.
pub struct Runtime {
    pub mapper: CapabilityMapper,
    pub policy: Policy,
    pub pictos: PictoStore,
    pub approvals: ApprovalStore,
    pub expedition: Option<Expedition>,
    pub layout: HomeLayout,
}

impl Runtime {
    pub fn open(layout: HomeLayout) -> Result<Self, GommageError> {
        layout.ensure()?;
        let expedition = Expedition::load(&layout.expedition_file)?;
        let env = expedition
            .as_ref()
            .map(Expedition::policy_env)
            .unwrap_or_else(default_policy_env);
        let mapper = CapabilityMapper::load_from_dir(&layout.capabilities_dir)?;
        let policy = load_active_policy(&layout, expedition.as_ref(), &env)?;
        let pictos = PictoStore::open(&layout.pictos_db)?;
        let approvals = ApprovalStore::open(&layout.approvals_log);
        Ok(Runtime {
            mapper,
            policy,
            pictos,
            approvals,
            expedition,
            layout,
        })
    }

    /// Reload policy + capability mappers from disk. Use on SIGHUP.
    pub fn reload_policy(&mut self) -> Result<(), GommageError> {
        let env = self
            .expedition
            .as_ref()
            .map(Expedition::policy_env)
            .unwrap_or_else(default_policy_env);
        self.mapper = CapabilityMapper::load_from_dir(&self.layout.capabilities_dir)?;
        self.policy = load_active_policy(&self.layout, self.expedition.as_ref(), &env)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ensure_creates_layout_and_key() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        assert!(layout.policy_dir.exists());
        assert!(layout.capabilities_dir.exists());
        assert!(layout.key_file.exists());
        let _ = layout.load_key().unwrap();
    }

    #[test]
    fn expedition_roundtrip() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        let exp = Expedition {
            name: "test".into(),
            root: PathBuf::from("/home/u/p"),
            started_at: time::OffsetDateTime::now_utc(),
        };
        exp.save(&layout.expedition_file).unwrap();
        let back = Expedition::load(&layout.expedition_file).unwrap().unwrap();
        assert_eq!(back.name, exp.name);
        Expedition::clear(&layout.expedition_file).unwrap();
        assert!(Expedition::load(&layout.expedition_file).unwrap().is_none());
    }

    #[test]
    fn active_policy_layers_include_project_before_user() {
        let td = tempdir().unwrap();
        let home = td.path().join("home");
        let project = td.path().join("project");
        let project_policy = project.join(".gommage/policy.d");
        fs::create_dir_all(&project_policy).unwrap();
        let layout = HomeLayout::at(&home);
        layout.ensure().unwrap();
        let expedition = Expedition {
            name: "project".into(),
            root: project.clone(),
            started_at: time::OffsetDateTime::now_utc(),
        };

        let layers = active_policy_layers(&layout, Some(&expedition)).unwrap();

        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].name, "project");
        assert_eq!(layers[0].dir, project_policy);
        assert_eq!(layers[1].name, "user");
        assert_eq!(layers[1].dir, layout.policy_dir);
    }
}
