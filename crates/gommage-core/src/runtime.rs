//! Shared runtime wiring: home directory layout, keypair, expedition state.
//!
//! Keeps the CLI, daemon, and MCP adapter from diverging on how they open
//! `~/.gommage/`. This module deliberately does *not* do policy evaluation —
//! that stays pure in `evaluator.rs`.

use crate::{CapabilityMapper, PictoStore, Policy, error::GommageError};
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

pub struct HomeLayout {
    pub root: PathBuf,
    pub policy_dir: PathBuf,
    pub capabilities_dir: PathBuf,
    pub pictos_db: PathBuf,
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
        let mut env = HashMap::new();
        env.insert("EXPEDITION_NAME".into(), self.name.clone());
        env.insert(
            "EXPEDITION_ROOT".into(),
            self.root.to_string_lossy().to_string(),
        );
        if let Ok(home) = std::env::var("HOME") {
            env.insert("HOME".into(), home);
        }
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
            .unwrap_or_default();
        let mapper = CapabilityMapper::load_from_dir(&layout.capabilities_dir)?;
        let policy = Policy::load_from_dir(&layout.policy_dir, &env)?;
        let pictos = PictoStore::open(&layout.pictos_db)?;
        Ok(Runtime {
            mapper,
            policy,
            pictos,
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
            .unwrap_or_default();
        self.mapper = CapabilityMapper::load_from_dir(&self.layout.capabilities_dir)?;
        self.policy = Policy::load_from_dir(&self.layout.policy_dir, &env)?;
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
}
