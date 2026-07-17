use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    rc::{Rc, Weak},
    thread,
    time::{Duration, Instant},
};
use time::OffsetDateTime;

use gommage_core::runtime::HomeLayout;

const INSTALL_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const INSTALL_LOCK_RETRY: Duration = Duration::from_millis(25);
const JOURNAL_VERSION: u32 = 1;

thread_local! {
    static ACTIVE_TRANSACTION: RefCell<Option<Weak<RefCell<TransactionState>>>> = const { RefCell::new(None) };
}

pub fn read_json_object(path: &Path) -> Result<serde_json::Value> {
    if !path.exists() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("{} must contain a JSON object", path.display());
    }
    Ok(value)
}

pub fn read_toml_document(path: &Path) -> Result<toml_edit::DocumentMut> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parsing {}", path.display()))
}

pub fn write_json(path: &Path, value: &serde_json::Value, dry_run: bool) -> Result<()> {
    let mut raw = serde_json::to_string_pretty(value)?;
    raw.push('\n');
    write_text(path, &raw, dry_run)
}

/// Write a regular text file through a same-directory, fsynced rename.
///
/// Existing modes are preserved. During an installation transaction, both the
/// intended bytes and every backup/temp artifact are written to the durable
/// journal before the corresponding filesystem mutation.
pub fn write_text(path: &Path, contents: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("plan write: {}", path.display());
        return Ok(());
    }
    with_active_transaction(|state| match state {
        Some(state) => state.write_regular(path, contents.as_bytes()),
        None => write_regular_untracked(path, contents.as_bytes()),
    })?;
    println!("ok wrote: {}", path.display());
    Ok(())
}

/// Back up and remove a regular file without following symbolic links.
pub(crate) fn backup_and_remove_file(path: &Path, dry_run: bool) -> Result<Option<PathBuf>> {
    if dry_run {
        println!("plan backup and remove: {}", path.display());
        return Ok(None);
    }
    let backup = with_active_transaction(|state| match state {
        Some(state) => state.remove_regular_with_backup(path),
        None => remove_regular_untracked(path),
    })?;
    if let Some(backup) = &backup {
        println!("ok backup: {} -> {}", path.display(), backup.display());
    }
    Ok(backup)
}

/// Restore already-snapshotted bytes without creating another user backup.
/// Used only by an enclosing transaction's compensation path.
pub(crate) fn restore_regular_bytes(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => anyhow::bail!(
            "refusing to restore over non-regular path {}",
            path.display()
        ),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
    if let Some(parent) = path.parent() {
        ensure_directory(parent, None)?;
    }
    with_active_transaction(|state| match state {
        Some(state) => state.atomic_write(path, contents, mode),
        None => atomic_write_raw(path, contents, mode, None),
    })
}

/// Create the Gommage home with secure modes and an atomic signing-key write.
/// This is the transactional CLI equivalent of `HomeLayout::ensure`.
pub(crate) fn ensure_home(layout: &HomeLayout) -> Result<()> {
    ensure_directory(&layout.root, Some(0o700))?;
    ensure_directory(&layout.policy_dir, Some(0o700))?;
    ensure_directory(&layout.capabilities_dir, Some(0o700))?;
    match std::fs::symlink_metadata(&layout.key_file) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "refusing to initialize signing key through symbolic link {}",
            layout.key_file.display()
        ),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!(
            "{} exists but is not a regular signing-key file",
            layout.key_file.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let signing_key = SigningKey::generate(&mut OsRng);
            write_bytes_with_mode(&layout.key_file, &signing_key.to_bytes(), 0o600)
        }
        Err(error) => Err(error)
            .with_context(|| format!("inspecting signing key {}", layout.key_file.display())),
    }
}

pub(crate) fn write_bytes_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    with_active_transaction(|state| match state {
        Some(state) => state.write_regular_with_mode(path, contents, mode),
        None => write_regular_untracked_with_mode(path, contents, mode),
    })
}

fn ensure_directory(path: &Path, mode: Option<u32>) -> Result<()> {
    with_active_transaction(|state| match state {
        Some(state) => state.ensure_directory(path, mode),
        None => ensure_directory_untracked(path, mode),
    })
}

pub(crate) fn transaction_is_active() -> bool {
    ACTIVE_TRANSACTION.with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade).is_some())
}

pub(crate) fn record_active_recovery_value<T: Serialize>(key: &str, value: &T) -> Result<()> {
    with_active_transaction(|state| {
        let state = state.ok_or_else(|| {
            anyhow::anyhow!("no active installation transaction for recovery state {key}")
        })?;
        state.record_recovery_value(key, value)
    })
}

pub(crate) fn clear_active_recovery_value(key: &str) -> Result<()> {
    with_active_transaction(|state| {
        let state = state.ok_or_else(|| {
            anyhow::anyhow!("no active installation transaction for recovery state {key}")
        })?;
        state.clear_recovery_value(key)
    })
}

mod filesystem;
mod transaction;

use filesystem::*;
use transaction::*;
pub(crate) use transaction::{InstallTransaction, TransactionFile};

pub fn env_path_or_home(env_var: &str, components: &[&str]) -> PathBuf {
    if let Ok(path) = std::env::var(env_var) {
        return PathBuf::from(path);
    }
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    for component in components {
        path.push(component);
    }
    path
}

pub fn path_details(path: &Path) -> serde_json::Value {
    serde_json::json!({ "path": path_display(path) })
}

pub fn path_display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests;
