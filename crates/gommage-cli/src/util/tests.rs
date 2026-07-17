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
