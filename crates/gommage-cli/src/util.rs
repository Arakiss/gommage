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

#[derive(Debug, Clone)]
pub(crate) struct TransactionFile {
    path: PathBuf,
    preserve_existing: bool,
}

impl TransactionFile {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            preserve_existing: false,
        }
    }

    /// Existing bytes are operator/runtime evidence and are never rewritten by
    /// rollback. A file created during this transaction is still removed when
    /// its exact observed fingerprint matches the journal.
    pub(crate) fn preserve_existing(mut self) -> Self {
        self.preserve_existing = true;
        self
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// An interprocess-exclusive, crash-recoverable installation transaction.
///
/// The lock and journal live beside `GOMMAGE_HOME`, so taking a snapshot never
/// creates the home it is supposed to describe. If a prior process died, its
/// journal is rolled back deterministically; callers must then re-synchronize
/// the old live runtime and call [`Self::acknowledge_recovery`] before writing.
pub(crate) struct InstallTransaction {
    lock_files: Vec<File>,
    state: Option<Rc<RefCell<TransactionState>>>,
    recovered: Option<TransactionState>,
    pending_files: Vec<TransactionFile>,
    pending_directories: Vec<PathBuf>,
    journal_dir: PathBuf,
    finished: bool,
}

impl InstallTransaction {
    pub(crate) fn begin(
        layout: &HomeLayout,
        files: Vec<TransactionFile>,
        directories: Vec<PathBuf>,
    ) -> Result<Self> {
        if transaction_is_active() {
            anyhow::bail!("an installation transaction is already active in this process");
        }
        let (home_lock_path, journal_dir) = transaction_control_paths(&layout.root)?;
        let mut lock_paths = vec![home_lock_path];
        for path in files
            .iter()
            .map(TransactionFile::path)
            .chain(directories.iter().map(PathBuf::as_path))
        {
            lock_paths.push(transaction_target_lock_path(path)?);
        }
        lock_paths.sort();
        lock_paths.dedup();
        let mut lock_files = Vec::with_capacity(lock_paths.len());
        for lock_path in lock_paths {
            lock_files.push(acquire_install_lock(&lock_path)?);
        }
        let recovered = load_and_rollback_interrupted_journal(&journal_dir)?;
        let mut transaction = Self {
            lock_files,
            state: None,
            recovered,
            pending_files: files,
            pending_directories: directories,
            journal_dir,
            finished: false,
        };
        if transaction.recovered.is_none() {
            transaction.capture_current_state()?;
        }
        Ok(transaction)
    }

    pub(crate) fn recovered_previous(&self) -> bool {
        self.recovered.is_some()
    }

    /// Confirm that the prior live runtime has been restored, discard its
    /// journal, then durably capture the new operation before any mutation.
    pub(crate) fn acknowledge_recovery(&mut self) -> Result<()> {
        let Some(recovered) = self.recovered.take() else {
            return Ok(());
        };
        recovered.remove_journal()?;
        self.capture_current_state()
    }

    pub(crate) fn observe_paths<'a>(
        &mut self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> Result<()> {
        let state = self.state.as_ref().ok_or_else(|| {
            anyhow::anyhow!("transaction is waiting for recovery acknowledgement")
        })?;
        state.borrow_mut().observe_paths(paths)
    }

    pub(crate) fn recovered_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(recovered) = &self.recovered else {
            return Ok(None);
        };
        recovered.recovery_value(key)
    }

    pub(crate) fn current_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(state) = &self.state else {
            return Ok(None);
        };
        state.borrow().recovery_value(key)
    }

    /// Restore original bytes/modes and remove only artifacts whose current
    /// state still matches what this transaction wrote. The journal remains
    /// durable until the caller reloads the prior runtime and commits it.
    pub(crate) fn rollback(&mut self) -> Result<()> {
        let state = self.state.as_ref().ok_or_else(|| {
            anyhow::anyhow!("transaction is waiting for recovery acknowledgement")
        })?;
        state.borrow_mut().rollback()
    }

    pub(crate) fn has_mutations(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| state.borrow().has_mutations())
    }

    pub(crate) fn commit(&mut self) -> Result<()> {
        let state = self
            .state
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("transaction has no captured state to commit"))?;
        {
            let mut state = state.borrow_mut();
            state.journal.committed = true;
            if let Err(error) = state.persist() {
                state.journal.committed = false;
                return Err(error.context("durably committing installation transaction"));
            }
        }

        // The committed marker is the point of no return. Cleanup after it is
        // opportunistic: an interrupted cleanup is completed by the next
        // transaction without rolling back the successfully committed state.
        clear_active_transaction(&state);
        let cleanup = {
            let state = state.borrow();
            state
                .cleanup_commit_artifacts()
                .and_then(|()| state.remove_journal())
        };
        if let Err(error) = cleanup {
            eprintln!("warn installation committed but journal cleanup was deferred: {error:#}");
        }
        self.state = None;
        self.finished = true;
        for lock_file in &self.lock_files {
            if let Err(error) = File::unlock(lock_file) {
                eprintln!("warn installation committed but explicit lock release failed: {error}");
            }
        }
        Ok(())
    }

    fn capture_current_state(&mut self) -> Result<()> {
        let state = TransactionState::capture(
            &self.journal_dir,
            &self.pending_files,
            &self.pending_directories,
        )?;
        let state = Rc::new(RefCell::new(state));
        set_active_transaction(&state)?;
        self.state = Some(state);
        Ok(())
    }
}

impl Drop for InstallTransaction {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            clear_active_transaction(state);
        }
        if !self.finished {
            for lock_file in &self.lock_files {
                let _ = File::unlock(lock_file);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Fingerprint {
    Missing,
    Regular { sha256: String, mode: u32 },
    Directory { mode: u32 },
    Symlink { target: PathBuf },
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OriginalFileState {
    Missing,
    Regular {
        snapshot: String,
        sha256: String,
        mode: u32,
    },
    PreserveExisting {
        fingerprint: Fingerprint,
    },
}

impl OriginalFileState {
    fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Missing => Fingerprint::Missing,
            Self::Regular { sha256, mode, .. } => Fingerprint::Regular {
                sha256: sha256.clone(),
                mode: *mode,
            },
            Self::PreserveExisting { fingerprint } => fingerprint.clone(),
        }
    }

    fn is_preserved(&self) -> bool {
        matches!(self, Self::PreserveExisting { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalFile {
    path: PathBuf,
    original: OriginalFileState,
    expected: Option<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalDirectory {
    path: PathBuf,
    existed: bool,
    original_mode: Option<u32>,
    expected: Option<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalArtifact {
    path: PathBuf,
    expected: Fingerprint,
    cleanup_on_commit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableJournal {
    version: u32,
    #[serde(default)]
    committed: bool,
    files: Vec<JournalFile>,
    directories: Vec<JournalDirectory>,
    artifacts: Vec<JournalArtifact>,
    #[serde(default)]
    recovery: BTreeMap<String, serde_json::Value>,
}

struct TransactionState {
    journal_dir: PathBuf,
    manifest_path: PathBuf,
    journal: DurableJournal,
    sealed: bool,
}

impl TransactionState {
    fn capture(
        journal_dir: &Path,
        file_specs: &[TransactionFile],
        explicit_directories: &[PathBuf],
    ) -> Result<Self> {
        preflight_transaction_paths(file_specs, explicit_directories)?;
        if path_lexists(journal_dir)? {
            anyhow::bail!(
                "transaction journal {} already exists after recovery",
                journal_dir.display()
            );
        }
        create_secure_directory_raw(journal_dir, 0o700)?;
        let snapshots_dir = journal_dir.join("snapshots");
        create_secure_directory_raw(&snapshots_dir, 0o700)?;

        let capture_result = (|| {
            let mut specs = BTreeMap::<PathBuf, bool>::new();
            for spec in file_specs {
                specs
                    .entry(spec.path.clone())
                    .and_modify(|preserve| *preserve |= spec.preserve_existing)
                    .or_insert(spec.preserve_existing);
            }
            let mut files = Vec::with_capacity(specs.len());
            for (index, (path, preserve_existing)) in specs.into_iter().enumerate() {
                let original = capture_file_state(&path, preserve_existing, &snapshots_dir, index)?;
                files.push(JournalFile {
                    path,
                    original,
                    expected: None,
                });
            }

            let directory_paths = transaction_directory_paths(file_specs, explicit_directories)?;
            let mut directories = Vec::with_capacity(directory_paths.len());
            for path in directory_paths {
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
                        "refusing installation through symbolic-link directory {}",
                        path.display()
                    ),
                    Ok(metadata) if metadata.is_dir() => directories.push(JournalDirectory {
                        path,
                        existed: true,
                        original_mode: Some(metadata_mode(&metadata)),
                        expected: None,
                    }),
                    Ok(_) => anyhow::bail!(
                        "transaction directory path {} is not a directory",
                        path.display()
                    ),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        directories.push(JournalDirectory {
                            path,
                            existed: false,
                            original_mode: None,
                            expected: None,
                        });
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("inspecting transaction directory {}", path.display())
                        });
                    }
                }
            }
            directories.sort_by(|left, right| left.path.cmp(&right.path));

            let journal = DurableJournal {
                version: JOURNAL_VERSION,
                committed: false,
                files,
                directories,
                artifacts: Vec::new(),
                recovery: BTreeMap::new(),
            };
            let mut state = Self {
                journal_dir: journal_dir.to_path_buf(),
                manifest_path: journal_dir.join("manifest.json"),
                journal,
                sealed: false,
            };
            state.persist()?;
            Ok(state)
        })();

        if capture_result.is_err() {
            let _ = std::fs::remove_dir_all(journal_dir);
            if let Some(parent) = journal_dir.parent() {
                let _ = sync_directory(parent);
            }
        }
        capture_result
    }

    fn load(journal_dir: &Path) -> Result<Self> {
        let manifest_path = journal_dir.join("manifest.json");
        let raw = std::fs::read(&manifest_path).with_context(|| {
            format!(
                "reading interrupted transaction journal {}",
                manifest_path.display()
            )
        })?;
        let journal: DurableJournal = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "parsing interrupted transaction journal {}",
                manifest_path.display()
            )
        })?;
        if journal.version != JOURNAL_VERSION {
            anyhow::bail!(
                "unsupported installation journal version {} at {}",
                journal.version,
                manifest_path.display()
            );
        }
        Ok(Self {
            journal_dir: journal_dir.to_path_buf(),
            manifest_path,
            journal,
            sealed: false,
        })
    }

    fn persist(&mut self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.journal)?;
        atomic_write_raw(&self.manifest_path, &bytes, 0o600, None)
            .context("persisting installation journal")
    }

    fn has_mutations(&self) -> bool {
        self.journal
            .files
            .iter()
            .any(|entry| entry.expected.is_some())
            || self
                .journal
                .directories
                .iter()
                .any(|entry| entry.expected.is_some())
            || !self.journal.artifacts.is_empty()
            || !self.journal.recovery.is_empty()
    }

    fn record_recovery_value<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        if self.sealed {
            anyhow::bail!("installation transaction is sealed after rollback");
        }
        let value = serde_json::to_value(value)
            .with_context(|| format!("serializing transaction recovery value {key}"))?;
        self.journal.recovery.insert(key.to_string(), value);
        self.persist()
    }

    fn clear_recovery_value(&mut self, key: &str) -> Result<()> {
        if self.journal.recovery.remove(key).is_some() {
            self.persist()?;
        }
        Ok(())
    }

    fn recovery_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        self.journal
            .recovery
            .get(key)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .with_context(|| format!("parsing transaction recovery value {key}"))
    }

    fn ensure_directory(&mut self, path: &Path, requested_mode: Option<u32>) -> Result<()> {
        let mut missing = Vec::new();
        let mut cursor = path;
        loop {
            match std::fs::symlink_metadata(cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
                    "refusing installation through symbolic-link directory {}",
                    cursor.display()
                ),
                Ok(metadata) if metadata.is_dir() => break,
                Ok(_) => anyhow::bail!("{} is not a directory", cursor.display()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.push(cursor.to_path_buf());
                    cursor = cursor.parent().ok_or_else(|| {
                        anyhow::anyhow!("cannot create directory root for {}", path.display())
                    })?;
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("inspecting {}", cursor.display()));
                }
            }
        }
        for directory in missing.into_iter().rev() {
            self.prepare_directory(&directory, 0o700)?;
            std::fs::create_dir(&directory)
                .with_context(|| format!("creating directory {}", directory.display()))?;
            set_path_mode(&directory, 0o700)?;
            if let Some(parent) = directory.parent() {
                sync_directory(parent)?;
            }
        }
        if let Some(mode) = requested_mode {
            let current = std::fs::symlink_metadata(path)
                .with_context(|| format!("inspecting directory {}", path.display()))?;
            if metadata_mode(&current) != mode {
                self.prepare_directory(path, mode)?;
                set_path_mode(path, mode)?;
                sync_directory(path)?;
            }
        }
        Ok(())
    }

    fn write_regular(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        let mode = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!("refusing to replace symbolic link {}", path.display())
            }
            Ok(metadata) if metadata.is_file() => metadata_mode(&metadata),
            Ok(_) => anyhow::bail!("{} exists but is not a regular file", path.display()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0o600,
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        };
        self.write_regular_with_mode(path, contents, mode)
    }

    fn write_regular_with_mode(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        if self.sealed {
            anyhow::bail!("installation transaction is sealed after rollback");
        }
        if let Some(parent) = path.parent() {
            self.ensure_directory(parent, None)?;
        }
        let current = read_regular_or_missing(path)?;
        if current
            .as_ref()
            .is_some_and(|(bytes, current_mode)| bytes == contents && *current_mode == mode)
        {
            println!("ok unchanged: {}", path.display());
            return Ok(());
        }
        let desired = regular_fingerprint(contents, mode);
        self.prepare_file(path, desired)?;
        if let Some((bytes, current_mode)) = current {
            let backup = backup_path(path);
            self.register_artifact(&backup, regular_fingerprint(&bytes, current_mode), false)?;
            self.atomic_write(&backup, &bytes, current_mode)?;
            println!("ok backup: {} -> {}", path.display(), backup.display());
        }
        self.atomic_write(path, contents, mode)
    }

    fn remove_regular_with_backup(&mut self, path: &Path) -> Result<Option<PathBuf>> {
        if self.sealed {
            anyhow::bail!("installation transaction is sealed after rollback");
        }
        let Some((bytes, mode)) = read_regular_or_missing(path)? else {
            return Ok(None);
        };
        self.prepare_file(path, Fingerprint::Missing)?;
        let backup = backup_path(path);
        self.register_artifact(&backup, regular_fingerprint(&bytes, mode), false)?;
        self.atomic_write(&backup, &bytes, mode)?;
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(Some(backup))
    }

    fn prepare_file(&mut self, path: &Path, desired: Fingerprint) -> Result<()> {
        let current = fingerprint_path(path)?;
        let entry = self
            .journal
            .files
            .iter_mut()
            .find(|entry| entry.path == path)
            .ok_or_else(|| {
                anyhow::anyhow!("{} is outside the installation transaction", path.display())
            })?;
        if entry.original.is_preserved() {
            anyhow::bail!(
                "{} is protected runtime evidence and cannot be rewritten by this transaction",
                path.display()
            );
        }
        let original = entry.original.fingerprint();
        let allowed = entry.expected.as_ref().unwrap_or(&original);
        if &current != allowed && current != entry.original.fingerprint() {
            anyhow::bail!(
                "{} changed outside the installation transaction; refusing to overwrite it",
                path.display()
            );
        }
        entry.expected = Some(desired);
        self.persist()
    }

    fn prepare_directory(&mut self, path: &Path, mode: u32) -> Result<()> {
        let current = fingerprint_path(path)?;
        let entry = self
            .journal
            .directories
            .iter_mut()
            .find(|entry| entry.path == path)
            .ok_or_else(|| {
                anyhow::anyhow!("{} is outside the installation transaction", path.display())
            })?;
        let original = if entry.existed {
            Fingerprint::Directory {
                mode: entry.original_mode.unwrap_or(mode),
            }
        } else {
            Fingerprint::Missing
        };
        let allowed = entry.expected.as_ref().unwrap_or(&original);
        if &current != allowed && current != original {
            anyhow::bail!(
                "directory {} changed outside the installation transaction",
                path.display()
            );
        }
        entry.expected = Some(Fingerprint::Directory { mode });
        self.persist()
    }

    fn register_artifact(
        &mut self,
        path: &Path,
        expected: Fingerprint,
        cleanup_on_commit: bool,
    ) -> Result<()> {
        if fingerprint_path(path)? != Fingerprint::Missing {
            anyhow::bail!(
                "transaction artifact path already exists: {}",
                path.display()
            );
        }
        self.journal.artifacts.push(JournalArtifact {
            path: path.to_path_buf(),
            expected,
            cleanup_on_commit,
        });
        self.persist()
    }

    fn atomic_write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        let temp = unique_sibling(path, ".gommage-tmp-");
        self.register_artifact(&temp, regular_fingerprint(contents, mode), true)?;
        atomic_write_raw(path, contents, mode, Some(&temp))
    }

    fn observe_paths<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) -> Result<()> {
        for path in paths {
            let observed = fingerprint_path(path)?;
            let entry = self
                .journal
                .files
                .iter_mut()
                .find(|entry| entry.path == path)
                .ok_or_else(|| {
                    anyhow::anyhow!("{} is outside the installation transaction", path.display())
                })?;
            if entry.original.is_preserved() {
                if matches!(
                    entry.original,
                    OriginalFileState::PreserveExisting {
                        fingerprint: Fingerprint::Missing
                    }
                ) {
                    entry.expected = Some(observed);
                }
            } else if entry.expected.is_none() && observed != entry.original.fingerprint() {
                entry.expected = Some(observed);
            }
        }
        self.persist()
    }

    fn rollback(&mut self) -> Result<()> {
        let conflicts = self.rollback_conflicts()?;
        if !conflicts.is_empty() {
            anyhow::bail!(
                "installation rollback refused to overwrite unexpected changes: {}",
                conflicts.join("; ")
            );
        }
        self.sealed = true;

        for index in (0..self.journal.files.len()).rev() {
            let entry = self.journal.files[index].clone();
            if entry.original.is_preserved() || entry.expected.is_none() {
                continue;
            }
            let current = fingerprint_path(&entry.path)?;
            if current == entry.original.fingerprint() {
                continue;
            }
            match entry.original {
                OriginalFileState::Missing => remove_regular_raw(&entry.path)?,
                OriginalFileState::Regular {
                    snapshot,
                    sha256,
                    mode,
                } => {
                    let snapshot_path = self.journal_dir.join(snapshot);
                    let bytes = std::fs::read(&snapshot_path).with_context(|| {
                        format!("reading rollback snapshot {}", snapshot_path.display())
                    })?;
                    if hex::encode(Sha256::digest(&bytes)) != sha256 {
                        anyhow::bail!(
                            "rollback snapshot integrity check failed for {}",
                            entry.path.display()
                        );
                    }
                    self.atomic_write(&entry.path, &bytes, mode)?;
                }
                OriginalFileState::PreserveExisting { .. } => {}
            }
        }

        for artifact in self.journal.artifacts.clone() {
            let current = fingerprint_path(&artifact.path)?;
            if current == artifact.expected {
                remove_regular_raw(&artifact.path)?;
            }
        }

        let mut directories = self.journal.directories.clone();
        directories.sort_by_key(|entry| std::cmp::Reverse(entry.path.components().count()));
        for entry in directories {
            let Some(_) = entry.expected else {
                continue;
            };
            if entry.existed {
                if let Some(mode) = entry.original_mode {
                    set_path_mode(&entry.path, mode)?;
                    sync_directory(&entry.path)?;
                }
            } else {
                match std::fs::remove_dir(&entry.path) {
                    Ok(()) => {
                        if let Some(parent) = entry.path.parent() {
                            sync_directory(parent)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("removing transaction directory {}", entry.path.display())
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn rollback_conflicts(&self) -> Result<Vec<String>> {
        let mut conflicts = Vec::new();
        for entry in &self.journal.files {
            let Some(expected) = &entry.expected else {
                continue;
            };
            if entry.original.is_preserved() {
                continue;
            }
            let current = fingerprint_path(&entry.path)?;
            if current != *expected && current != entry.original.fingerprint() {
                conflicts.push(entry.path.display().to_string());
            }
        }
        for artifact in &self.journal.artifacts {
            let current = fingerprint_path(&artifact.path)?;
            if current != Fingerprint::Missing && current != artifact.expected {
                conflicts.push(artifact.path.display().to_string());
            }
        }
        for entry in &self.journal.directories {
            let Some(expected) = &entry.expected else {
                continue;
            };
            let original = if entry.existed {
                Fingerprint::Directory {
                    mode: entry.original_mode.unwrap_or_default(),
                }
            } else {
                Fingerprint::Missing
            };
            let current = fingerprint_path(&entry.path)?;
            if current != *expected && current != original {
                conflicts.push(entry.path.display().to_string());
            }
        }
        Ok(conflicts)
    }

    fn cleanup_commit_artifacts(&self) -> Result<()> {
        for artifact in &self.journal.artifacts {
            if !artifact.cleanup_on_commit {
                continue;
            }
            let current = fingerprint_path(&artifact.path)?;
            if current == Fingerprint::Missing {
                continue;
            }
            if current != artifact.expected {
                anyhow::bail!(
                    "temporary transaction artifact {} changed unexpectedly",
                    artifact.path.display()
                );
            }
            remove_regular_raw(&artifact.path)?;
        }
        Ok(())
    }

    fn remove_journal(&self) -> Result<()> {
        std::fs::remove_dir_all(&self.journal_dir).with_context(|| {
            format!(
                "removing transaction journal {}",
                self.journal_dir.display()
            )
        })?;
        if let Some(parent) = self.journal_dir.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }
}

fn load_and_rollback_interrupted_journal(journal_dir: &Path) -> Result<Option<TransactionState>> {
    match std::fs::symlink_metadata(journal_dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", journal_dir.display()));
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!(
                "installation journal path {} is not a regular directory",
                journal_dir.display()
            )
        }
        Ok(_) => {}
    }
    let manifest = journal_dir.join("manifest.json");
    if !path_lexists(&manifest)? {
        std::fs::remove_dir_all(journal_dir).with_context(|| {
            format!(
                "removing incomplete transaction journal {}",
                journal_dir.display()
            )
        })?;
        if let Some(parent) = journal_dir.parent() {
            sync_directory(parent)?;
        }
        return Ok(None);
    }
    let mut state = TransactionState::load(journal_dir)?;
    if state.journal.committed {
        state
            .cleanup_commit_artifacts()
            .context("finishing committed installation transaction cleanup")?;
        state.remove_journal()?;
        return Ok(None);
    }
    state
        .rollback()
        .context("recovering interrupted installation transaction")?;
    eprintln!(
        "warn recovered an interrupted installation transaction; restoring the prior runtime before continuing"
    );
    Ok(Some(state))
}

fn capture_file_state(
    path: &Path,
    preserve_existing: bool,
    snapshots_dir: &Path,
    index: usize,
) -> Result<OriginalFileState> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "refusing to mutate symbolic link {} (including dangling links)",
            path.display()
        ),
        Ok(metadata) if metadata.is_file() => {
            let bytes =
                std::fs::read(path).with_context(|| format!("snapshotting {}", path.display()))?;
            let fingerprint = regular_fingerprint(&bytes, metadata_mode(&metadata));
            if preserve_existing {
                return Ok(OriginalFileState::PreserveExisting { fingerprint });
            }
            let snapshot = format!("snapshots/{index:06}.bin");
            let snapshot_path = snapshots_dir
                .parent()
                .expect("snapshots directory has a parent")
                .join(&snapshot);
            write_new_synced_file(&snapshot_path, &bytes, 0o600)?;
            let Fingerprint::Regular { sha256, mode } = fingerprint else {
                unreachable!("regular fingerprint")
            };
            Ok(OriginalFileState::Regular {
                snapshot,
                sha256,
                mode,
            })
        }
        Ok(metadata) if preserve_existing && !metadata.is_dir() => {
            Ok(OriginalFileState::PreserveExisting {
                fingerprint: fingerprint_path(path)?,
            })
        }
        Ok(_) => anyhow::bail!("{} exists but is not a regular file", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(OriginalFileState::Missing),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn preflight_transaction_paths(
    files: &[TransactionFile],
    explicit_directories: &[PathBuf],
) -> Result<()> {
    for spec in files {
        match std::fs::symlink_metadata(&spec.path) {
            Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
                "refusing to mutate symbolic link {} (including dangling links)",
                spec.path.display()
            ),
            Ok(metadata) if !metadata.is_file() && !spec.preserve_existing => {
                anyhow::bail!("{} exists but is not a regular file", spec.path.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", spec.path.display()));
            }
        }
    }
    for path in transaction_directory_paths(files, explicit_directories)? {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
                "refusing installation through symbolic-link directory {}",
                path.display()
            ),
            Ok(metadata) if !metadata.is_dir() => {
                anyhow::bail!("{} exists but is not a directory", path.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        }
    }
    Ok(())
}

fn transaction_directory_paths(
    files: &[TransactionFile],
    explicit_directories: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let mut directories = BTreeSet::new();
    for directory in explicit_directories {
        collect_directory_chain(directory, &mut directories)?;
    }
    for file in files {
        if let Some(parent) = file.path.parent() {
            collect_directory_chain(parent, &mut directories)?;
        }
    }
    Ok(directories.into_iter().collect())
}

fn collect_directory_chain(path: &Path, directories: &mut BTreeSet<PathBuf>) -> Result<()> {
    let mut cursor = Some(path);
    while let Some(directory) = cursor {
        directories.insert(directory.to_path_buf());
        match std::fs::symlink_metadata(directory) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                cursor = directory.parent();
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", directory.display()));
            }
        }
    }
    Ok(())
}

fn acquire_install_lock(path: &Path) -> Result<File> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "installation lock {} has no parent directory",
            path.display()
        )
    })?;
    if !parent.is_dir() {
        anyhow::bail!(
            "GOMMAGE_HOME parent {} must exist before installation",
            parent.display()
        );
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!("installation lock {} is not a regular file", path.display())
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting lock {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening installation lock {}", path.display()))?;
    validate_open_lock_file(&file, path)?;
    set_file_mode(&file, 0o600)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= INSTALL_LOCK_TIMEOUT {
                    anyhow::bail!(
                        "another Gommage installation transaction still holds {} after {} ms",
                        path.display(),
                        INSTALL_LOCK_TIMEOUT.as_millis()
                    );
                }
                thread::sleep(INSTALL_LOCK_RETRY);
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("locking installation transaction");
            }
        }
    }
}

fn validate_open_lock_file(file: &File, path: &Path) -> Result<()> {
    let opened = file
        .metadata()
        .with_context(|| format!("inspecting opened installation lock {}", path.display()))?;
    if !opened.is_file() {
        anyhow::bail!("installation lock {} is not a regular file", path.display());
    }
    let linked = std::fs::symlink_metadata(path)
        .with_context(|| format!("re-inspecting installation lock {}", path.display()))?;
    if linked.file_type().is_symlink() || !linked.is_file() {
        anyhow::bail!(
            "installation lock {} changed while it was being opened",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
            anyhow::bail!(
                "installation lock {} was replaced while it was being opened",
                path.display()
            );
        }
    }
    Ok(())
}

fn transaction_control_paths(root: &Path) -> Result<(PathBuf, PathBuf)> {
    let parent = root.parent().ok_or_else(|| {
        anyhow::anyhow!("GOMMAGE_HOME {} has no parent directory", root.display())
    })?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("GOMMAGE_HOME name is not valid UTF-8"))?;
    let stem = if name.starts_with('.') {
        name.to_string()
    } else {
        format!(".{name}")
    };
    Ok((
        parent.join(format!("{stem}.gommage-install.lock")),
        parent.join(format!("{stem}.gommage-install-journal")),
    ))
}

fn transaction_target_lock_path(path: &Path) -> Result<PathBuf> {
    let identity = canonical_transaction_target(path)?;
    let digest = Sha256::digest(identity.as_os_str().as_encoded_bytes());
    let lock_root = std::fs::canonicalize(std::env::temp_dir())
        .context("canonicalizing the host installation lock directory")?;
    Ok(lock_root.join(format!(".gommage-target-{}.lock", hex::encode(digest))))
}

fn canonical_transaction_target(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving current directory for installation target")?
            .join(path)
    };
    let mut cursor = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                for component in missing.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot resolve installation target identity for {}",
                        path.display()
                    )
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot resolve installation target parent for {}",
                        path.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("canonicalizing installation target {}", path.display())
                });
            }
        }
    }
}

fn set_active_transaction(state: &Rc<RefCell<TransactionState>>) -> Result<()> {
    ACTIVE_TRANSACTION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().and_then(Weak::upgrade).is_some() {
            anyhow::bail!("an installation transaction is already active");
        }
        *slot = Some(Rc::downgrade(state));
        Ok(())
    })
}

fn clear_active_transaction(state: &Rc<RefCell<TransactionState>>) {
    ACTIVE_TRANSACTION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|active| Rc::ptr_eq(&active, state))
        {
            *slot = None;
        }
    });
}

fn with_active_transaction<T>(
    operation: impl FnOnce(Option<&mut TransactionState>) -> Result<T>,
) -> Result<T> {
    ACTIVE_TRANSACTION.with(|slot| {
        let active = slot.borrow().as_ref().and_then(Weak::upgrade);
        match active {
            Some(active) => operation(Some(&mut active.borrow_mut())),
            None => operation(None),
        }
    })
}

fn write_regular_untracked(path: &Path, contents: &[u8]) -> Result<()> {
    let mode = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("refusing to replace symbolic link {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => metadata_mode(&metadata),
        Ok(_) => anyhow::bail!("{} exists but is not a regular file", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0o600,
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    write_regular_untracked_with_mode(path, contents, mode)
}

fn write_regular_untracked_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_directory_untracked(parent, None)?;
    }
    let current = read_regular_or_missing(path)?;
    if current
        .as_ref()
        .is_some_and(|(bytes, current_mode)| bytes == contents && *current_mode == mode)
    {
        println!("ok unchanged: {}", path.display());
        return Ok(());
    }
    if let Some((bytes, current_mode)) = current {
        let backup = backup_path(path);
        atomic_write_raw(&backup, &bytes, current_mode, None)?;
        println!("ok backup: {} -> {}", path.display(), backup.display());
    }
    atomic_write_raw(path, contents, mode, None)
}

fn remove_regular_untracked(path: &Path) -> Result<Option<PathBuf>> {
    let Some((bytes, mode)) = read_regular_or_missing(path)? else {
        return Ok(None);
    };
    let backup = backup_path(path);
    atomic_write_raw(&backup, &bytes, mode, None)?;
    remove_regular_raw(path)?;
    Ok(Some(backup))
}

fn ensure_directory_untracked(path: &Path, requested_mode: Option<u32>) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "refusing installation through symbolic-link directory {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => {
            if let Some(mode) = requested_mode {
                set_path_mode(path, mode)?;
            }
            Ok(())
        }
        Ok(_) => anyhow::bail!("{} exists but is not a directory", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .with_context(|| format!("creating directory {}", path.display()))?;
            set_path_mode(path, requested_mode.unwrap_or(0o700))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn read_regular_or_missing(path: &Path) -> Result<Option<(Vec<u8>, u32)>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("refusing to mutate symbolic link {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => Ok(Some((
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
            metadata_mode(&metadata),
        ))),
        Ok(_) => anyhow::bail!("{} exists but is not a regular file", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn fingerprint_path(path: &Path) -> Result<Fingerprint> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(Fingerprint::Symlink {
            target: std::fs::read_link(path)
                .with_context(|| format!("reading symbolic link {}", path.display()))?,
        }),
        Ok(metadata) if metadata.is_file() => {
            let mut file = File::open(path)
                .with_context(|| format!("opening {} for fingerprint", path.display()))?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
            }
            Ok(Fingerprint::Regular {
                sha256: hex::encode(hash.finalize()),
                mode: metadata_mode(&metadata),
            })
        }
        Ok(metadata) if metadata.is_dir() => Ok(Fingerprint::Directory {
            mode: metadata_mode(&metadata),
        }),
        Ok(_) => Ok(Fingerprint::Other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Fingerprint::Missing),
        Err(error) => Err(error).with_context(|| format!("fingerprinting {}", path.display())),
    }
}

fn regular_fingerprint(contents: &[u8], mode: u32) -> Fingerprint {
    Fingerprint::Regular {
        sha256: hex::encode(Sha256::digest(contents)),
        mode,
    }
}

fn atomic_write_raw(
    path: &Path,
    contents: &[u8],
    mode: u32,
    prepared_temp: Option<&Path>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    let temp = prepared_temp
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unique_sibling(path, ".gommage-tmp-"));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options
            .open(&temp)
            .with_context(|| format!("creating temporary file for {}", path.display()))?;
        file.write_all(contents)?;
        set_file_mode(&file, mode)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path).with_context(|| {
            format!(
                "atomically replacing {} from {}",
                path.display(),
                temp.display()
            )
        })?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn write_new_synced_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating journal snapshot {}", path.display()))?;
    file.write_all(contents)?;
    set_file_mode(&file, mode)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn remove_regular_raw(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => anyhow::bail!(
            "refusing to remove non-regular transaction path {}",
            path.display()
        ),
        Ok(_) => {
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn create_secure_directory_raw(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir(path).with_context(|| format!("creating {}", path.display()))?;
    set_path_mode(path, mode)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn unique_sibling(path: &Path, marker: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let mut nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    loop {
        let candidate = path.with_file_name(format!(".{file_name}{marker}{nonce}"));
        if matches!(fingerprint_path(&candidate), Ok(Fingerprint::Missing)) {
            return candidate;
        }
        nonce += 1;
    }
}

pub(crate) fn backup_path(path: &Path) -> PathBuf {
    let mut ts = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    loop {
        let candidate = path.with_file_name(format!("{file_name}.gommage-bak-{ts}"));
        if matches!(fingerprint_path(&candidate), Ok(Fingerprint::Missing)) {
            return candidate;
        }
        ts += 1;
    }
}

fn path_lexists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

#[cfg(unix)]
fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn metadata_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_path_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_path_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

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
mod tests {
    use super::*;

    #[test]
    fn write_text_creates_unique_backups_for_repeated_writes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");

        write_text(&path, "one\n", false).unwrap();
        write_text(&path, "two\n", false).unwrap();
        write_text(&path, "three\n", false).unwrap();

        let mut backups = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with("settings.json.gommage-bak-"))
            .collect::<Vec<_>>();
        backups.sort();

        assert_eq!(backups.len(), 2);
        assert_ne!(backups[0], backups[1]);
    }

    #[test]
    fn atomic_write_preserves_existing_mode() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        std::fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        write_text(&path, "new", false).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }

    #[test]
    fn interrupted_transaction_is_recovered_before_the_next_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let settings = temp.path().join("claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, "original\n").unwrap();

        let transaction =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        write_text(&settings, "attempted\n", false).unwrap();
        let (_, journal_dir) = transaction_control_paths(&layout.root).unwrap();
        assert!(journal_dir.join("manifest.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&journal_dir)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(journal_dir.join("manifest.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(transaction);

        let mut recovered =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        assert!(recovered.recovered_previous());
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "original\n");
        recovered.acknowledge_recovery().unwrap();
        recovered.commit().unwrap();
        assert!(!journal_dir.exists());
    }

    #[test]
    fn recovery_handles_crash_after_intent_sync_but_before_replace() {
        let temp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let settings = temp.path().join("settings.json");
        std::fs::write(&settings, "original\n").unwrap();

        let transaction =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        transaction
            .state
            .as_ref()
            .unwrap()
            .borrow_mut()
            .prepare_file(&settings, regular_fingerprint(b"attempted\n", 0o644))
            .unwrap();
        drop(transaction);

        let mut recovered =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        assert!(recovered.recovered_previous());
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "original\n");
        recovered.acknowledge_recovery().unwrap();
        recovered.commit().unwrap();
    }

    #[test]
    fn recovery_finishes_cleanup_after_the_commit_marker() {
        let temp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let settings = temp.path().join("settings.json");
        std::fs::write(&settings, "original\n").unwrap();

        let transaction =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        let orphan = temp.path().join(".settings.json.gommage-tmp-orphan");
        #[cfg(unix)]
        let mode = 0o600;
        #[cfg(not(unix))]
        let mode = 0;
        {
            let mut state = transaction.state.as_ref().unwrap().borrow_mut();
            state
                .register_artifact(&orphan, regular_fingerprint(b"temporary\n", mode), true)
                .unwrap();
            atomic_write_raw(&orphan, b"temporary\n", mode, None).unwrap();
            state.journal.committed = true;
            state.persist().unwrap();
        }
        let (_, journal_dir) = transaction_control_paths(&layout.root).unwrap();
        assert!(orphan.is_file());
        assert!(journal_dir.is_dir());
        drop(transaction);

        let mut next =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        assert!(!next.recovered_previous());
        assert!(!orphan.exists());
        assert!(journal_dir.is_dir());
        next.commit().unwrap();
        assert!(!journal_dir.exists());
        assert_eq!(std::fs::read_to_string(settings).unwrap(), "original\n");
    }

    #[cfg(unix)]
    #[test]
    fn opened_lock_validation_rejects_a_symlink_swap() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.lock");
        let lock = temp.path().join("install.lock");
        std::fs::write(&target, "operator data\n").unwrap();
        symlink(&target, &lock).unwrap();
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .unwrap();

        let error = validate_open_lock_file(&opened, &lock).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being opened")
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), "operator data\n");
    }

    #[test]
    fn shared_target_lock_serializes_transactions_across_different_homes() {
        let temp = tempfile::tempdir().unwrap();
        let layout_a = HomeLayout::at(&temp.path().join("home-a"));
        let layout_b_root = temp.path().join("home-b");
        let settings = temp.path().join("shared-agent/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, "{}\n").unwrap();

        let mut transaction_a =
            InstallTransaction::begin(&layout_a, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        let settings_for_b = settings.clone();
        let started = Instant::now();
        let competing = std::thread::spawn(move || {
            let layout_b = HomeLayout::at(&layout_b_root);
            InstallTransaction::begin(
                &layout_b,
                vec![TransactionFile::new(settings_for_b)],
                Vec::new(),
            )
            .err()
            .expect("the shared target lock must reject the competing transaction")
        })
        .join()
        .unwrap();

        assert!(started.elapsed() >= Duration::from_millis(1_900));
        assert!(
            competing
                .to_string()
                .contains("another Gommage installation transaction")
        );
        transaction_a.commit().unwrap();

        let mut transaction_b = InstallTransaction::begin(
            &HomeLayout::at(&temp.path().join("home-b")),
            vec![TransactionFile::new(settings)],
            Vec::new(),
        )
        .unwrap();
        transaction_b.commit().unwrap();
    }

    #[test]
    fn rollback_refuses_to_overwrite_an_unexpected_external_change() {
        let temp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let settings = temp.path().join("settings.json");
        std::fs::write(&settings, "original\n").unwrap();

        let mut transaction =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .unwrap();
        write_text(&settings, "attempted\n", false).unwrap();
        std::fs::write(&settings, "external\n").unwrap();

        let error = transaction.rollback().unwrap_err();
        assert!(error.to_string().contains("unexpected changes"));
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "external\n");
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_preserved_and_its_target_is_never_created() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let target = temp.path().join("missing-target.json");
        let settings = temp.path().join("settings.json");
        symlink(&target, &settings).unwrap();

        let error =
            InstallTransaction::begin(&layout, vec![TransactionFile::new(&settings)], Vec::new())
                .err()
                .expect("dangling symlink must fail before capture");
        assert!(error.to_string().contains("symbolic link"));
        assert_eq!(std::fs::read_link(&settings).unwrap(), target);
        assert!(!target.exists());
        assert!(!layout.root.exists());
    }
}
