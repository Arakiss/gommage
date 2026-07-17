use super::*;

#[test]
fn daemon_install_launchd_writes_plist_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "launchd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plist = fs::read_to_string(launchd.join("dev.gommage.daemon.plist")).unwrap();
    assert!(plist.contains("<string>dev.gommage.daemon</string>"));
    assert!(plist.contains("<string>--foreground</string>"));
    assert!(plist.contains("<string>--home</string>"));
    assert!(plist.contains(&home.to_string_lossy().to_string()));
    let canonical_daemon = fs::canonicalize(&fake_daemon).unwrap();
    assert!(plist.contains(&canonical_daemon.to_string_lossy().to_string()));
    assert!(!home.exists());
}

#[test]
fn daemon_install_systemd_writes_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "systemd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("Description=Gommage policy daemon"));
    assert!(service.contains("Type=exec"));
    assert!(!service.contains("Type=simple"));
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    let canonical_daemon = fs::canonicalize(&fake_daemon).unwrap();
    assert!(service.contains(&canonical_daemon.to_string_lossy().to_string()));
    assert!(!home.exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_restores_loaded_service_after_bootstrap_failure() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let existing_backup = launchd.join("dev.gommage.daemon.plist.gommage-bak-existing");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    let first_bootstrap = temp.path().join("first-bootstrap-failed");
    let loaded_state = temp.path().join("launchd-loaded-state");
    let bootout_count = temp.path().join("launchd-bootout-count");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let original = owned_launchd_service(&home).into_bytes();
    fs::write(&service_file, &original).unwrap();
    let mut service_permissions = fs::metadata(&service_file).unwrap().permissions();
    service_permissions.set_mode(0o640);
    fs::set_permissions(&service_file, service_permissions).unwrap();
    fs::write(&existing_backup, b"older backup\n").unwrap();
    fs::write(&loaded_state, "1").unwrap();
    fs::write(&bootout_count, "0").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$1" in
  print)
    if [ "$(/bin/cat "$GOMMAGE_LAUNCHD_LOADED_STATE")" = "1" ]; then
      exit 0
    fi
    printf 'Could not find service\n' >&2
    exit 113
    ;;
  bootout)
    count="$(/bin/cat "$GOMMAGE_LAUNCHD_BOOTOUT_COUNT")"
    if [ "$count" = "1" ]; then
      case "$(/bin/cat "$GOMMAGE_LAUNCHD_SERVICE_FILE")" in
        *"<string>dev.gommage.daemon</string>"*) ;;
        *) exit 45 ;;
      esac
    fi
    printf '%s' "$((count + 1))" > "$GOMMAGE_LAUNCHD_BOOTOUT_COUNT"
    printf '0' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
    exit 0
    ;;
  bootstrap)
    if [ ! -e "$GOMMAGE_FIRST_BOOTSTRAP" ]; then
      : > "$GOMMAGE_FIRST_BOOTSTRAP"
      printf '1' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
      exit 42
    fi
    case "$(/bin/cat "$GOMMAGE_LAUNCHD_SERVICE_FILE")" in
      *"<string>--home</string>"*) ;;
      *) exit 46 ;;
    esac
    printf '1' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
    exit 0
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ready_daemon = start_fake_ready_daemon(&home);

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_FIRST_BOOTSTRAP", &first_bootstrap)
        .env("GOMMAGE_LAUNCHD_LOADED_STATE", &loaded_state)
        .env("GOMMAGE_LAUNCHD_BOOTOUT_COUNT", &bootout_count)
        .env("GOMMAGE_LAUNCHD_SERVICE_FILE", &service_file)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();
    ready_daemon.finish();
    fs::remove_dir(&home).unwrap();

    assert!(!output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("rollback also failed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("service command failed: launchctl bootstrap"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&service_file).unwrap(), original);
    assert_eq!(
        fs::metadata(&service_file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let backups = fs::read_dir(&launchd)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("dev.gommage.daemon.plist.gommage-bak-")
        })
        .collect::<Vec<_>>();
    assert_eq!(backups, vec![existing_backup]);
    assert_eq!(fs::read_to_string(loaded_state).unwrap(), "1");
    assert_eq!(fs::read_to_string(bootout_count).unwrap(), "2");
    assert!(!home.exists());

    let calls = fs::read_to_string(log).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 6, "{calls:?}");
    assert!(calls[0].starts_with("print gui/"), "{calls:?}");
    assert!(calls[1].starts_with("bootout gui/"), "{calls:?}");
    assert!(calls[2].starts_with("bootstrap gui/"), "{calls:?}");
    assert!(calls[3].starts_with("print gui/"), "{calls:?}");
    assert!(calls[4].starts_with("bootout gui/"), "{calls:?}");
    assert!(calls[5].starts_with("bootstrap gui/"), "{calls:?}");
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_accepts_not_loaded_during_rollback_probe() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    let loaded_state = temp.path().join("launchd-loaded-state");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let original = b"original unloaded launchd plist\n";
    fs::write(&service_file, original).unwrap();
    fs::write(&loaded_state, "0").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$1" in
  print)
    if [ "$(/bin/cat "$GOMMAGE_LAUNCHD_LOADED_STATE")" = "1" ]; then
      exit 0
    fi
    printf 'Could not find service\n' >&2
    exit 113
    ;;
  bootstrap)
    exit 42
    ;;
  bootout)
    exit 65
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_LAUNCHD_LOADED_STATE", &loaded_state)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("service command failed: launchctl bootstrap"),
        "{stderr}"
    );
    assert!(!stderr.contains("rollback also failed"), "{stderr}");
    assert_eq!(fs::read(&service_file).unwrap(), original);
    assert_eq!(fs::read_to_string(loaded_state).unwrap(), "0");
    assert!(!home.exists());
    let backups = fs::read_dir(&launchd)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("dev.gommage.daemon.plist.gommage-bak-")
        })
        .collect::<Vec<_>>();
    assert!(backups.is_empty(), "{backups:?}");

    let calls = fs::read_to_string(log).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].starts_with("print gui/"), "{calls:?}");
    assert!(calls[1].starts_with("bootstrap gui/"), "{calls:?}");
    assert!(calls[2].starts_with("print gui/"), "{calls:?}");
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_state_probe_error_is_not_treated_as_unloaded() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, "original plist\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        "#!/bin/sh\nprintf 'permission denied\\n' >&2\nexit 77\n",
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not determine"));
    assert_eq!(
        fs::read_to_string(&service_file).unwrap(),
        "original plist\n"
    );
    assert!(!home.exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_rejects_loaded_service_without_restorable_plist() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    fs::create_dir_all(&bin).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
if [ "$1" = "print" ]; then
  exit 0
fi
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("without a restorable plist"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(log).unwrap().lines().count(), 1);
    assert!(!launchd.join("dev.gommage.daemon.plist").exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restores_independent_runtime_states_after_enable_failure() {
    use std::os::unix::fs::PermissionsExt;

    for (was_enabled, was_active) in [(true, true), (true, false), (false, true), (false, false)] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let existing_backup = systemd.join("gommage-daemon.service.gommage-bak-existing");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        let enabled_state = temp.path().join("enabled-state");
        let active_state = temp.path().join("active-state");
        let first_enable = temp.path().join("first-enable-failed");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let original = owned_systemd_service(&home).into_bytes();
        fs::write(&service_file, &original).unwrap();
        let mut service_permissions = fs::metadata(&service_file).unwrap().permissions();
        service_permissions.set_mode(0o640);
        fs::set_permissions(&service_file, service_permissions).unwrap();
        fs::write(&existing_backup, b"older backup\n").unwrap();
        fs::write(&enabled_state, if was_enabled { "1" } else { "0" }).unwrap();
        fs::write(&active_state, if was_active { "1" } else { "0" }).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ "$(/bin/cat "$GOMMAGE_ACTIVE_STATE")" = "1" ]; then
      printf 'active\n'
      exit 0
    fi
    printf 'inactive\n'
    exit 3
    ;;
  is-enabled)
    if [ "$(/bin/cat "$GOMMAGE_ENABLED_STATE")" = "1" ]; then
      printf 'enabled\n'
      exit 0
    fi
    printf 'disabled\n'
    exit 1
    ;;
  daemon-reload)
    exit 0
    ;;
  enable)
    if [ ! -e "$GOMMAGE_FIRST_ENABLE" ]; then
      : > "$GOMMAGE_FIRST_ENABLE"
      exit 43
    fi
    printf '1' > "$GOMMAGE_ENABLED_STATE"
    ;;
  disable)
    printf '0' > "$GOMMAGE_ENABLED_STATE"
    if [ "$3" = "--now" ]; then
      printf '0' > "$GOMMAGE_ACTIVE_STATE"
    fi
    ;;
  start)
    printf '1' > "$GOMMAGE_ACTIVE_STATE"
    ;;
  stop)
    printf '0' > "$GOMMAGE_ACTIVE_STATE"
    ;;
  *)
    exit 64
    ;;
esac
"#,
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let ready_daemon = was_active.then(|| start_fake_ready_daemon(&home));

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("GOMMAGE_ENABLED_STATE", &enabled_state)
            .env("GOMMAGE_ACTIVE_STATE", &active_state)
            .env("GOMMAGE_FIRST_ENABLE", &first_enable)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();
        if let Some(ready_daemon) = ready_daemon {
            ready_daemon.finish();
            fs::remove_dir(&home).unwrap();
        }

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("service command failed: systemctl --user enable gommage-daemon.service"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&service_file).unwrap(), original);
        assert_eq!(
            fs::metadata(&service_file).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let backups = fs::read_dir(&systemd)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("gommage-daemon.service.gommage-bak-")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups, vec![existing_backup]);
        assert_eq!(
            fs::read_to_string(&enabled_state).unwrap(),
            if was_enabled { "1" } else { "0" }
        );
        assert_eq!(
            fs::read_to_string(&active_state).unwrap(),
            if was_active { "1" } else { "0" }
        );
        assert!(!home.exists());

        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.contains("--user is-active gommage-daemon.service\n"));
        assert!(calls.contains("--user is-enabled gommage-daemon.service\n"));
        assert!(calls.contains("--user daemon-reload\n"));
        assert!(calls.contains("--user enable gommage-daemon.service\n"));
        assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
        assert!(calls.contains(if was_enabled {
            "--user enable gommage-daemon.service\n"
        } else {
            "--user disable gommage-daemon.service\n"
        }));
        if was_active {
            assert!(calls.contains("--user stop gommage-daemon.service\n"));
            assert!(calls.contains("--user start gommage-daemon.service\n"));
        } else {
            assert!(!calls.contains("--user stop gommage-daemon.service\n"));
            assert!(!calls.contains("--user start gommage-daemon.service\n"));
        }
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restarts_an_already_active_service() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, owned_systemd_service(&home)).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'active\n'; exit 0 ;;
  is-enabled) printf 'enabled\n'; exit 0 ;;
  daemon-reload|enable|restart) exit 0 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ready_daemon = start_fake_ready_daemon(&home);

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd", "--force"])
        .output()
        .unwrap();
    ready_daemon.finish();
    fs::remove_dir(&home).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user daemon-reload\n"));
    assert!(calls.contains("--user enable gommage-daemon.service\n"));
    assert!(calls.contains("--user restart gommage-daemon.service\n"));
    assert!(!calls.contains("--user start gommage-daemon.service\n"));
    assert!(
        fs::read_to_string(&service_file)
            .unwrap()
            .contains("Type=exec")
    );
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_state_probe_error_is_not_treated_as_inactive() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, "original unit\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) exit 42 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not determine active state"));
    assert_eq!(
        fs::read_to_string(&service_file).unwrap(),
        "original unit\n"
    );
    assert!(!home.exists());
}
