use super::*;

#[test]
#[cfg(unix)]
fn daemon_install_readiness_failure_rolls_back_service_file_and_state() {
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
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf 'disabled\n'; exit 1 ;;
  daemon-reload|enable|start|disable|stop) exit 0 ;;
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

    let started = std::time::Instant::now();
    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd"])
        .output()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(!output.status.success());
    assert!(elapsed >= std::time::Duration::from_millis(4_900));
    assert!(elapsed < std::time::Duration::from_millis(7_000));
    assert!(String::from_utf8_lossy(&output.stderr).contains("daemon readiness failed"));
    assert!(!service_file.exists());
    assert!(!home.exists());
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user start gommage-daemon.service\n"));
    assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
    assert!(!calls.contains("--user stop gommage-daemon.service\n"));
}

#[test]
#[cfg(unix)]
fn daemon_install_rollback_preserves_static_and_indirect_enablement() {
    for enablement in ["static", "indirect"] {
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
        fs::write(&service_file, format!("original {enablement} unit\n")).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
  daemon-reload|disable|stop) exit 0 ;;
  enable) exit 43 ;;
esac
exit 64
"#
            ),
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
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            format!("original {enablement} unit\n")
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls
                .lines()
                .filter(|line| *line == "--user enable gommage-daemon.service")
                .count(),
            1
        );
        assert_eq!(
            calls
                .lines()
                .filter(|line| *line == "--user disable gommage-daemon.service")
                .count(),
            0
        );
        assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restores_runtime_and_mask_enablement_exactly() {
    for (enablement, restore_command) in [
        (
            "enabled-runtime",
            "--user enable --runtime gommage-daemon.service",
        ),
        (
            "disabled-runtime",
            "--user disable --runtime gommage-daemon.service",
        ),
        ("masked", "--user mask gommage-daemon.service"),
        (
            "masked-runtime",
            "--user mask --runtime gommage-daemon.service",
        ),
    ] {
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
        fs::write(&service_file, format!("original {enablement} unit\n")).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
  daemon-reload|disable|mask) exit 0 ;;
  enable)
    if [ "$3" = "--runtime" ]; then exit 0; fi
    exit 43
    ;;
esac
exit 64
"#
            ),
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
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            format!("original {enablement} unit\n")
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.lines().any(|line| line == restore_command), "{calls}");
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_rejects_unreconstructable_enablement_before_mutation() {
    for enablement in [
        "linked",
        "linked-runtime",
        "alias",
        "generated",
        "transient",
    ] {
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
        fs::write(&service_file, "original unit\n").unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
esac
exit 64
"#
            ),
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
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot reconstruct"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            "original unit\n"
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert!(!calls.contains("daemon-reload"), "{calls}");
        assert!(!calls.lines().any(|line| line.starts_with("--user enable ")));
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_rejects_transitional_activity_before_mutation() {
    for (activity, status) in [
        ("failed", 3),
        ("activating", 0),
        ("deactivating", 0),
        ("reloading", 0),
    ] {
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
        fs::write(&service_file, "original unit\n").unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GOMMAGE_SERVICE_MANAGER_LOG\"\nprintf '{activity}\\n'\nexit {status}\n"
            ),
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
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("non-restorable"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            "original unit\n"
        );
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_absent_inactive_rollback_never_stops_missing_unit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active|is-enabled) printf 'not-found\n'; exit 4 ;;
  daemon-reload) exit 0 ;;
  enable) exit 43 ;;
  stop) exit 99 ;;
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
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!systemd.join("gommage-daemon.service").exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("rollback also failed"), "{stderr}");
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        !calls.contains("--user stop gommage-daemon.service"),
        "{calls}"
    );
    assert!(!calls.contains("--user disable --now"), "{calls}");
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_suppresses_service_manager_output() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        systemd.join("gommage-daemon.service"),
        format!(
            "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
            home.display()
        ),
    )
    .unwrap();
    let runtime_state = temp.path().join("systemd-active");
    fs::write(&runtime_state, "active\n").unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_SERVICE_RUNTIME_STATE" ]; then printf 'active\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_SERVICE_RUNTIME_STATE" ]; then printf 'enabled\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  stop|disable)
    rm -f "$GOMMAGE_SERVICE_RUNTIME_STATE"
    echo "Removed '/tmp/raw.service'."
    echo 'raw stderr' >&2
    exit 0
    ;;
  daemon-reload) exit 0 ;;
esac
exit 64
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_systemctl).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_systemctl, perms).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_SERVICE_RUNTIME_STATE", &runtime_state)
        .env("PATH", path)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("ok daemon: removed"));
    assert!(!stdout.contains("Removed '/tmp/raw.service'"));
    assert!(!stderr.contains("raw stderr"));
    assert!(!systemd.join("gommage-daemon.service").exists());
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_preserves_service_file_when_stop_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    );
    fs::write(&service_file, &original).unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) printf 'active\n'; exit 0 ;;
  is-enabled) printf 'enabled\n'; exit 0 ;;
  stop) exit 42 ;;
  disable) exit 0 ;;
  daemon-reload) exit 0 ;;
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
        .env("PATH", path)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(String::from_utf8_lossy(&output.stderr).contains("stopping daemon before uninstall"));
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_restores_file_and_enablement_when_reload_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    let enablement = temp.path().join("enabled");
    let reload_count = temp.path().join("reload-count");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&enablement, "enabled\n").unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    );
    fs::write(&service_file, &original).unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLEMENT_STATE" ]; then printf 'enabled\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  disable) rm -f "$GOMMAGE_ENABLEMENT_STATE"; exit 0 ;;
  enable) : > "$GOMMAGE_ENABLEMENT_STATE"; exit 0 ;;
  daemon-reload)
    count=0
    if [ -e "$GOMMAGE_RELOAD_COUNT" ]; then count="$(cat "$GOMMAGE_RELOAD_COUNT")"; fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$GOMMAGE_RELOAD_COUNT"
    if [ "$count" -eq 1 ]; then exit 42; fi
    exit 0
    ;;
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
        .env("GOMMAGE_ENABLEMENT_STATE", &enablement)
        .env("GOMMAGE_RELOAD_COUNT", &reload_count)
        .env("PATH", path)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(enablement.exists());
    assert_eq!(fs::read_to_string(&reload_count).unwrap().trim(), "2");
    assert!(String::from_utf8_lossy(&output.stderr).contains("rolled back"));
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_refuses_a_service_bound_to_another_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("selected-home");
    let other_home = temp.path().join("other-home");
    let systemd = temp.path().join("systemd-user");
    fs::create_dir_all(&systemd).unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        other_home.display()
    );
    fs::write(&service_file, &original).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not select"));
}
