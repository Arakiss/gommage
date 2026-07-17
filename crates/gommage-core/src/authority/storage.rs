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

    pub(super) fn create_database(&self) -> Result<File, AuthorityError> {
        reject_unsafe_path_if_present(&self.database_path, "database")?;
        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.database_path)
            .map_err(|error| {
                AuthorityError::InvalidInput(format!(
                    "bootstrap requires a new authority database path: {error}"
                ))
            })?;
        validate_private_regular(&database, &self.database_path, "database")?;
        Ok(database)
    }

    pub(super) fn open_database(&self) -> Result<File, AuthorityError> {
        reject_unsafe_path_if_present(&self.database_path, "database")?;
        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.database_path)
            .map_err(|error| {
                storage_io("opening authority database", &self.database_path, error)
            })?;
        validate_private_regular(&database, &self.database_path, "database")?;
        Ok(database)
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
    if opened.nlink() != 1 {
        return Err(AuthorityError::Storage(format!(
            "authority {kind} must have exactly one filesystem link: {}",
            path.display()
        )));
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
