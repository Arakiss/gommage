use super::*;
use std::{
    ffi::OsString,
    fs::{File, Metadata, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const PRIVATE_FILE_MODE: u32 = 0o600;

/// Stable process-local ownership acquired before retention or SQLite is read.
pub(super) struct AuthorityWriterGuard {
    directory_path: PathBuf,
    database_path: PathBuf,
    lock_path: PathBuf,
    directory: File,
    // Must remain last so every other retained descriptor drops before the lock.
    writer_lock: File,
}

/// Filesystem identity retained for the complete usable Authority lifetime.
pub(super) struct AuthorityStorageGuard {
    directory_path: PathBuf,
    database_path: PathBuf,
    lock_path: PathBuf,
    directory: File,
    database: File,
    // Must remain last. Never unlink the stable lock path on drop.
    writer_lock: File,
}

impl AuthorityWriterGuard {
    pub(super) fn acquire(path: &Path) -> Result<Self, AuthorityError> {
        let file_name = path.file_name().ok_or_else(|| {
            AuthorityError::Storage("authority database path has no file name".into())
        })?;
        let parent = path.parent().ok_or_else(|| {
            AuthorityError::Storage("authority database path has no parent directory".into())
        })?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let directory_path = std::fs::canonicalize(parent).map_err(|error| {
            storage_io("canonicalizing authority database directory", parent, error)
        })?;
        let directory = File::open(&directory_path).map_err(|error| {
            storage_io(
                "opening authority database directory",
                &directory_path,
                error,
            )
        })?;
        validate_directory(&directory, &directory_path)?;

        let database_path = directory_path.join(file_name);
        let lock_path = sibling_lock_path(&database_path)?;
        reject_unsafe_path_if_present(&lock_path, "writer lock")?;
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| storage_io("opening authority writer lock", &lock_path, error))?;
        validate_private_regular(&writer_lock, &lock_path, "writer lock")?;
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(AuthorityError::WriterBusy),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(storage_io(
                    "locking authority writer lock",
                    &lock_path,
                    error,
                ));
            }
        }
        validate_private_regular(&writer_lock, &lock_path, "writer lock")?;
        validate_directory(&directory, &directory_path)?;

        Ok(Self {
            directory_path,
            database_path,
            lock_path,
            directory,
            writer_lock,
        })
    }

    pub(super) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(super) fn ensure_database_absent(&self) -> Result<(), AuthorityError> {
        match std::fs::symlink_metadata(&self.database_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(storage_io(
                "inspecting authority database",
                &self.database_path,
                error,
            )),
            Ok(_) => Err(AuthorityError::InvalidInput(
                "bootstrap requires a new authority database path".into(),
            )),
        }
    }

    pub(super) fn prepare_bootstrap_database(&self) -> Result<(PathBuf, File), AuthorityError> {
        self.ensure_database_absent()?;
        let bootstrap_path = sibling_bootstrap_path(&self.database_path)?;
        reject_unsafe_path_if_present(&bootstrap_path, "bootstrap preparation")?;
        let bootstrap_exists = match std::fs::symlink_metadata(&bootstrap_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(storage_io(
                    "inspecting authority bootstrap preparation",
                    &bootstrap_path,
                    error,
                ));
            }
        };
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        if !bootstrap_exists {
            options.create_new(true);
        }
        let database = options.open(&bootstrap_path).map_err(|error| {
            storage_io(
                "opening authority bootstrap preparation",
                &bootstrap_path,
                error,
            )
        })?;
        validate_private_regular(&database, &bootstrap_path, "bootstrap preparation")?;
        Ok((bootstrap_path, database))
    }

    pub(super) fn sync_bootstrap_database(
        &self,
        bootstrap_path: &Path,
        database: &File,
    ) -> Result<(), AuthorityError> {
        self.verify_bootstrap_database(bootstrap_path, database, 1)?;
        sync_file(database, bootstrap_path)?;
        self.remove_bootstrap_sidecars(bootstrap_path)?;
        self.sync_directory()?;
        self.verify_bootstrap_database(bootstrap_path, database, 1)
    }

    pub(super) fn publish_bootstrap_database(
        &self,
        bootstrap_path: &Path,
        database: &File,
    ) -> Result<(), AuthorityError> {
        self.verify_bootstrap_database(bootstrap_path, database, 1)?;
        self.ensure_database_absent()?;
        std::fs::hard_link(bootstrap_path, &self.database_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                AuthorityError::InvalidInput(
                    "bootstrap requires a new authority database path".into(),
                )
            } else {
                storage_io(
                    "publishing authority database without replacement",
                    &self.database_path,
                    error,
                )
            }
        })?;
        self.sync_directory()?;

        self.verify_bootstrap_database(bootstrap_path, database, 2)?;
        let published = open_private_regular(&self.database_path, "database", 2)?;
        require_same_identity(
            &database.metadata().map_err(|error| {
                storage_io(
                    "inspecting authority bootstrap preparation",
                    bootstrap_path,
                    error,
                )
            })?,
            &published.metadata().map_err(|error| {
                storage_io(
                    "inspecting published authority database",
                    &self.database_path,
                    error,
                )
            })?,
            &self.database_path,
            "published database",
        )?;
        drop(published);

        std::fs::remove_file(bootstrap_path).map_err(|error| {
            storage_io(
                "removing published authority bootstrap link",
                bootstrap_path,
                error,
            )
        })?;
        self.sync_directory()?;
        validate_private_regular(database, &self.database_path, "database")
    }

    pub(super) fn recover_bootstrap_publication(
        &self,
        retained_state: &CheckpointRetentionStateV2,
    ) -> Result<(), AuthorityError> {
        let bootstrap_path = sibling_bootstrap_path(&self.database_path)?;
        let database_metadata =
            std::fs::symlink_metadata(&self.database_path).map_err(|error| {
                storage_io("inspecting authority database", &self.database_path, error)
            })?;
        if database_metadata.file_type().is_symlink() || !database_metadata.is_file() {
            return Err(AuthorityError::Storage(format!(
                "authority database path is not a regular file: {}",
                self.database_path.display()
            )));
        }
        let bootstrap_metadata = match std::fs::symlink_metadata(&bootstrap_path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(storage_io(
                    "inspecting authority bootstrap preparation",
                    &bootstrap_path,
                    error,
                ));
            }
        };

        if database_metadata.nlink() == 1 && bootstrap_metadata.is_none() {
            return Ok(());
        }
        let Some(bootstrap_metadata) = bootstrap_metadata else {
            return Err(AuthorityError::Storage(
                "published authority database has extra links but no recoverable bootstrap link"
                    .into(),
            ));
        };
        if !matches!(
            retained_state,
            CheckpointRetentionStateV2::BootstrapPending(_)
        ) {
            return Err(AuthorityError::RecoveryAmbiguous(
                "unexpected bootstrap publication links without BootstrapPending retention".into(),
            ));
        }
        if bootstrap_metadata.file_type().is_symlink()
            || !bootstrap_metadata.is_file()
            || database_metadata.nlink() != 2
            || bootstrap_metadata.nlink() != 2
        {
            return Err(AuthorityError::Storage(
                "authority bootstrap publication links are not the expected two regular links"
                    .into(),
            ));
        }
        let database = open_private_regular(&self.database_path, "database", 2)?;
        let bootstrap = open_private_regular(&bootstrap_path, "bootstrap preparation", 2)?;
        require_same_identity(
            &database.metadata().map_err(|error| {
                storage_io("inspecting authority database", &self.database_path, error)
            })?,
            &bootstrap.metadata().map_err(|error| {
                storage_io(
                    "inspecting authority bootstrap preparation",
                    &bootstrap_path,
                    error,
                )
            })?,
            &self.database_path,
            "bootstrap publication",
        )?;
        drop(bootstrap);
        std::fs::remove_file(&bootstrap_path).map_err(|error| {
            storage_io(
                "finishing authority bootstrap publication",
                &bootstrap_path,
                error,
            )
        })?;
        self.sync_directory()?;
        validate_private_regular(&database, &self.database_path, "database")
    }

    pub(super) fn open_database(&self) -> Result<File, AuthorityError> {
        reject_unsafe_path_if_present(&self.database_path, "database")?;
        open_private_regular(&self.database_path, "database", 1)
    }

    fn verify_bootstrap_database(
        &self,
        bootstrap_path: &Path,
        database: &File,
        expected_links: u64,
    ) -> Result<(), AuthorityError> {
        validate_directory(&self.directory, &self.directory_path)?;
        validate_private_regular(&self.writer_lock, &self.lock_path, "writer lock")?;
        validate_private_regular_with_links(
            database,
            bootstrap_path,
            "bootstrap preparation",
            expected_links,
        )
    }

    fn remove_bootstrap_sidecars(&self, bootstrap_path: &Path) -> Result<(), AuthorityError> {
        for suffix in ["-wal", "-shm"] {
            let sidecar = append_file_name_suffix(bootstrap_path, suffix)?;
            match std::fs::symlink_metadata(&sidecar) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(storage_io(
                        "inspecting authority bootstrap sidecar",
                        &sidecar,
                        error,
                    ));
                }
                Ok(_) => {
                    let file = open_private_regular(&sidecar, "bootstrap sidecar", 1)?;
                    drop(file);
                    std::fs::remove_file(&sidecar).map_err(|error| {
                        storage_io("removing authority bootstrap sidecar", &sidecar, error)
                    })?;
                }
            }
        }
        Ok(())
    }

    fn sync_directory(&self) -> Result<(), AuthorityError> {
        validate_directory(&self.directory, &self.directory_path)?;
        self.directory.sync_all().map_err(|error| {
            storage_io(
                "syncing authority database directory",
                &self.directory_path,
                error,
            )
        })?;
        validate_directory(&self.directory, &self.directory_path)
    }

    pub(super) fn verify_database(&self, database: &File) -> Result<(), AuthorityError> {
        validate_directory(&self.directory, &self.directory_path)?;
        validate_private_regular(&self.writer_lock, &self.lock_path, "writer lock")?;
        validate_private_regular(database, &self.database_path, "database")
    }

    pub(super) fn bind_database(
        self,
        database: File,
    ) -> Result<AuthorityStorageGuard, AuthorityError> {
        self.verify_database(&database)?;
        Ok(AuthorityStorageGuard {
            directory_path: self.directory_path,
            database_path: self.database_path,
            lock_path: self.lock_path,
            directory: self.directory,
            database,
            writer_lock: self.writer_lock,
        })
    }
}

impl AuthorityStorageGuard {
    pub(super) fn verify(&self) -> Result<(), AuthorityError> {
        validate_directory(&self.directory, &self.directory_path)?;
        validate_private_regular(&self.writer_lock, &self.lock_path, "writer lock")?;
        validate_private_regular(&self.database, &self.database_path, "database")
    }
}

fn sibling_lock_path(database_path: &Path) -> Result<PathBuf, AuthorityError> {
    let mut name = database_path
        .file_name()
        .ok_or_else(|| AuthorityError::Storage("authority database has no file name".into()))?
        .to_os_string();
    name.push(OsString::from(".gommage.lock"));
    Ok(database_path.with_file_name(name))
}

fn sibling_bootstrap_path(database_path: &Path) -> Result<PathBuf, AuthorityError> {
    let file_name = database_path
        .file_name()
        .ok_or_else(|| AuthorityError::Storage("authority database has no file name".into()))?;
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(OsString::from(".gommage-bootstrap"));
    Ok(database_path.with_file_name(name))
}

fn append_file_name_suffix(path: &Path, suffix: &str) -> Result<PathBuf, AuthorityError> {
    let mut name = path
        .file_name()
        .ok_or_else(|| AuthorityError::Storage("authority storage path has no file name".into()))?
        .to_os_string();
    name.push(OsString::from(suffix));
    Ok(path.with_file_name(name))
}

fn reject_unsafe_path_if_present(path: &Path, kind: &str) -> Result<(), AuthorityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AuthorityError::Storage(format!(
                "authority {kind} path is not a regular file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_io("inspecting authority storage path", path, error)),
    }
}

fn validate_directory(directory: &File, path: &Path) -> Result<(), AuthorityError> {
    let opened = directory
        .metadata()
        .map_err(|error| storage_io("inspecting opened authority directory", path, error))?;
    let linked = std::fs::symlink_metadata(path)
        .map_err(|error| storage_io("re-inspecting authority directory", path, error))?;
    if !opened.is_dir() || linked.file_type().is_symlink() || !linked.is_dir() {
        return Err(AuthorityError::Storage(format!(
            "authority database directory is not a stable directory: {}",
            path.display()
        )));
    }
    require_same_identity(&opened, &linked, path, "database directory")?;
    let expected_uid = effective_uid();
    if opened.uid() != expected_uid {
        return Err(AuthorityError::Storage(format!(
            "authority database directory must be owned by uid {expected_uid}: {}",
            path.display()
        )));
    }
    if opened.mode() & 0o022 != 0 {
        return Err(AuthorityError::Storage(format!(
            "authority database directory must not be group- or world-writable: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_private_regular(file: &File, path: &Path, kind: &str) -> Result<(), AuthorityError> {
    validate_private_regular_with_links(file, path, kind, 1)
}

fn validate_private_regular_with_links(
    file: &File,
    path: &Path,
    kind: &str,
    expected_links: u64,
) -> Result<(), AuthorityError> {
    let opened = file
        .metadata()
        .map_err(|error| storage_io("inspecting opened authority file", path, error))?;
    let linked = std::fs::symlink_metadata(path)
        .map_err(|error| storage_io("re-inspecting authority file", path, error))?;
    if !opened.is_file() || linked.file_type().is_symlink() || !linked.is_file() {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} is not a stable regular file: {}",
            path.display()
        )));
    }
    require_same_identity(&opened, &linked, path, kind)?;
    let expected_uid = effective_uid();
    if opened.uid() != expected_uid {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} must be owned by uid {expected_uid}: {}",
            path.display()
        )));
    }
    if opened.mode() & 0o777 != PRIVATE_FILE_MODE {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} must have mode 0600: {}",
            path.display()
        )));
    }
    if opened.nlink() != expected_links {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} must have exactly {expected_links} filesystem link(s): {}",
            path.display()
        )));
    }
    Ok(())
}

fn open_private_regular(
    path: &Path,
    kind: &str,
    expected_links: u64,
) -> Result<File, AuthorityError> {
    reject_unsafe_path_if_present(path, kind)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| storage_io("opening authority storage file", path, error))?;
    validate_private_regular_with_links(&file, path, kind, expected_links)?;
    Ok(file)
}

fn sync_file(file: &File, path: &Path) -> Result<(), AuthorityError> {
    file.sync_all()
        .map_err(|error| storage_io("syncing authority database", path, error))?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: fcntl receives a live descriptor and the argument-free
        // F_FULLFSYNC operation; it does not access Rust-managed memory.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
            return Err(storage_io(
                "fully syncing authority database",
                path,
                io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

fn require_same_identity(
    opened: &Metadata,
    linked: &Metadata,
    path: &Path,
    kind: &str,
) -> Result<(), AuthorityError> {
    if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} pathname changed identity: {}",
            path.display()
        )));
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions, reads process credentials, and
    // cannot invalidate Rust memory.
    unsafe { libc::geteuid() }
}

fn storage_io(operation: &str, path: &Path, error: io::Error) -> AuthorityError {
    AuthorityError::Storage(format!("{operation} {}: {error}", path.display()))
}
