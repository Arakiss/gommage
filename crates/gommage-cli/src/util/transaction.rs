use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TransactionFile {
    pub(super) path: PathBuf,
    pub(super) preserve_existing: bool,
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
    pub(super) state: Option<Rc<RefCell<TransactionState>>>,
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
pub(super) enum Fingerprint {
    Missing,
    Regular { sha256: String, mode: u32 },
    Directory { mode: u32 },
    Symlink { target: PathBuf },
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum OriginalFileState {
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
pub(super) struct JournalFile {
    path: PathBuf,
    original: OriginalFileState,
    expected: Option<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct JournalDirectory {
    path: PathBuf,
    existed: bool,
    original_mode: Option<u32>,
    expected: Option<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct JournalArtifact {
    path: PathBuf,
    expected: Fingerprint,
    cleanup_on_commit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DurableJournal {
    version: u32,
    #[serde(default)]
    pub(super) committed: bool,
    files: Vec<JournalFile>,
    directories: Vec<JournalDirectory>,
    artifacts: Vec<JournalArtifact>,
    #[serde(default)]
    recovery: BTreeMap<String, serde_json::Value>,
}

pub(super) struct TransactionState {
    journal_dir: PathBuf,
    manifest_path: PathBuf,
    pub(super) journal: DurableJournal,
    sealed: bool,
}

impl TransactionState {
    pub(super) fn capture(
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

    pub(super) fn load(journal_dir: &Path) -> Result<Self> {
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

    pub(super) fn persist(&mut self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.journal)?;
        atomic_write_raw(&self.manifest_path, &bytes, 0o600, None)
            .context("persisting installation journal")
    }

    pub(super) fn has_mutations(&self) -> bool {
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

    pub(super) fn record_recovery_value<T: Serialize>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<()> {
        if self.sealed {
            anyhow::bail!("installation transaction is sealed after rollback");
        }
        let value = serde_json::to_value(value)
            .with_context(|| format!("serializing transaction recovery value {key}"))?;
        self.journal.recovery.insert(key.to_string(), value);
        self.persist()
    }

    pub(super) fn clear_recovery_value(&mut self, key: &str) -> Result<()> {
        if self.journal.recovery.remove(key).is_some() {
            self.persist()?;
        }
        Ok(())
    }

    pub(super) fn recovery_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        self.journal
            .recovery
            .get(key)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .with_context(|| format!("parsing transaction recovery value {key}"))
    }

    pub(super) fn ensure_directory(
        &mut self,
        path: &Path,
        requested_mode: Option<u32>,
    ) -> Result<()> {
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

    pub(super) fn write_regular(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
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

    pub(super) fn write_regular_with_mode(
        &mut self,
        path: &Path,
        contents: &[u8],
        mode: u32,
    ) -> Result<()> {
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

    pub(super) fn remove_regular_with_backup(&mut self, path: &Path) -> Result<Option<PathBuf>> {
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

    pub(super) fn prepare_file(&mut self, path: &Path, desired: Fingerprint) -> Result<()> {
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

    pub(super) fn register_artifact(
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

    pub(super) fn atomic_write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        let temp = unique_sibling(path, ".gommage-tmp-");
        self.register_artifact(&temp, regular_fingerprint(contents, mode), true)?;
        atomic_write_raw(path, contents, mode, Some(&temp))
    }

    pub(super) fn observe_paths<'a>(
        &mut self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> Result<()> {
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

    pub(super) fn rollback(&mut self) -> Result<()> {
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

    pub(super) fn cleanup_commit_artifacts(&self) -> Result<()> {
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

    pub(super) fn remove_journal(&self) -> Result<()> {
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
