use super::*;

pub(super) fn load_and_rollback_interrupted_journal(
    journal_dir: &Path,
) -> Result<Option<TransactionState>> {
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

pub(super) fn capture_file_state(
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

pub(super) fn preflight_transaction_paths(
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

pub(super) fn transaction_directory_paths(
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

pub(super) fn collect_directory_chain(
    path: &Path,
    directories: &mut BTreeSet<PathBuf>,
) -> Result<()> {
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

pub(super) fn acquire_install_lock(path: &Path) -> Result<File> {
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

pub(super) fn validate_open_lock_file(file: &File, path: &Path) -> Result<()> {
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

pub(super) fn transaction_control_paths(root: &Path) -> Result<(PathBuf, PathBuf)> {
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

pub(super) fn transaction_target_lock_path(path: &Path) -> Result<PathBuf> {
    let identity = canonical_transaction_target(path)?;
    let digest = Sha256::digest(identity.as_os_str().as_encoded_bytes());
    let lock_root = std::fs::canonicalize(std::env::temp_dir())
        .context("canonicalizing the host installation lock directory")?;
    Ok(lock_root.join(format!(".gommage-target-{}.lock", hex::encode(digest))))
}

pub(super) fn canonical_transaction_target(path: &Path) -> Result<PathBuf> {
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

pub(super) fn set_active_transaction(state: &Rc<RefCell<TransactionState>>) -> Result<()> {
    ACTIVE_TRANSACTION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().and_then(Weak::upgrade).is_some() {
            anyhow::bail!("an installation transaction is already active");
        }
        *slot = Some(Rc::downgrade(state));
        Ok(())
    })
}

pub(super) fn clear_active_transaction(state: &Rc<RefCell<TransactionState>>) {
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

pub(super) fn with_active_transaction<T>(
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

pub(super) fn write_regular_untracked(path: &Path, contents: &[u8]) -> Result<()> {
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

pub(super) fn write_regular_untracked_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
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

pub(super) fn remove_regular_untracked(path: &Path) -> Result<Option<PathBuf>> {
    let Some((bytes, mode)) = read_regular_or_missing(path)? else {
        return Ok(None);
    };
    let backup = backup_path(path);
    atomic_write_raw(&backup, &bytes, mode, None)?;
    remove_regular_raw(path)?;
    Ok(Some(backup))
}

pub(super) fn ensure_directory_untracked(path: &Path, requested_mode: Option<u32>) -> Result<()> {
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

pub(super) fn read_regular_or_missing(path: &Path) -> Result<Option<(Vec<u8>, u32)>> {
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

pub(super) fn fingerprint_path(path: &Path) -> Result<Fingerprint> {
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

pub(super) fn regular_fingerprint(contents: &[u8], mode: u32) -> Fingerprint {
    Fingerprint::Regular {
        sha256: hex::encode(Sha256::digest(contents)),
        mode,
    }
}

pub(super) fn atomic_write_raw(
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

pub(super) fn write_new_synced_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
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

pub(super) fn remove_regular_raw(path: &Path) -> Result<()> {
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

pub(super) fn create_secure_directory_raw(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir(path).with_context(|| format!("creating {}", path.display()))?;
    set_path_mode(path, mode)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

pub(super) fn unique_sibling(path: &Path, marker: &str) -> PathBuf {
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

pub(super) fn path_lexists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

#[cfg(unix)]
pub(super) fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
pub(super) fn metadata_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
pub(super) fn set_path_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))
}

#[cfg(not(unix))]
pub(super) fn set_path_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn set_file_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}
