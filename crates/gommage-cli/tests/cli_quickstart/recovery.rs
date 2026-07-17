use super::*;

#[test]
#[cfg(unix)]
fn quickstart_recovers_service_manager_after_crash_between_start_and_commit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude/settings.json");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    let active_state = temp.path().join("active-state");
    let enabled_state = temp.path().join("enabled-state");
    let killed_once = temp.path().join("killed-once");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&settings, "{\n  \"language\": \"spanish\"\n}\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_ACTIVE_STATE" ]; then printf 'active\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'inactive\n'; exit 3
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLED_STATE" ]; then printf 'enabled\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'disabled\n'; exit 1
    ;;
  daemon-reload) exit 0 ;;
  enable) : > "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  disable) rm -f "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  stop) rm -f "$GOMMAGE_ACTIVE_STATE"; exit 0 ;;
  start)
    : > "$GOMMAGE_ACTIVE_STATE"
    if [ ! -e "$GOMMAGE_KILLED_ONCE" ]; then
      : > "$GOMMAGE_KILLED_ONCE"
      kill -9 "$PPID"
    fi
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
    let command = || {
        let mut command = gommage(&home);
        command
            .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("GOMMAGE_ACTIVE_STATE", &active_state)
            .env("GOMMAGE_ENABLED_STATE", &enabled_state)
            .env("GOMMAGE_KILLED_ONCE", &killed_once)
            .env("GOMMAGE_SERVICE_FILE", &service_file)
            .env("PATH", &path);
        command
    };

    let crashed = command()
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--no-self-test",
            "--daemon",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();
    assert!(!crashed.status.success());
    assert!(active_state.exists(), "fake service never reached start");
    assert!(enabled_state.exists(), "fake service was never enabled");
    assert!(
        temp.path()
            .join(".gommage.gommage-install-journal/manifest.json")
            .is_file(),
        "crash did not leave the durable journal"
    );

    let recovered = command()
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(
        !service_file.exists(),
        "recovery retained the attempted unit"
    );
    assert!(
        !active_state.exists(),
        "recovery retained the attempted process"
    );
    assert!(
        !enabled_state.exists(),
        "recovery retained attempted enablement"
    );
    assert!(
        !temp
            .path()
            .join(".gommage.gommage-install-journal")
            .exists(),
        "recovery did not close the interrupted journal"
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user stop gommage-daemon.service\n"));
    assert!(calls.contains("--user disable gommage-daemon.service\n"));
}

#[test]
#[cfg(unix)]
fn quickstart_compensates_service_when_journal_fails_after_start() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude/settings.json");
    let original_settings = "{\n  \"language\": \"spanish\"\n}\n";
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let journal = temp.path().join(".gommage.gommage-install-journal");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    let active_state = temp.path().join("active-state");
    let enabled_state = temp.path().join("enabled-state");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&settings, original_settings).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    let ready_daemon = start_fake_ready_daemon(&home);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_ACTIVE_STATE" ]; then printf 'active\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'inactive\n'; exit 3
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLED_STATE" ]; then printf 'enabled\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'disabled\n'; exit 1
    ;;
  daemon-reload) exit 0 ;;
  enable) : > "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  disable) rm -f "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  start)
    : > "$GOMMAGE_ACTIVE_STATE"
    chmod 0500 "$GOMMAGE_INSTALL_JOURNAL"
    exit 0
    ;;
  stop)
    rm -f "$GOMMAGE_ACTIVE_STATE"
    chmod 0700 "$GOMMAGE_INSTALL_JOURNAL"
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
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_ACTIVE_STATE", &active_state)
        .env("GOMMAGE_ENABLED_STATE", &enabled_state)
        .env("GOMMAGE_SERVICE_FILE", &service_file)
        .env("GOMMAGE_INSTALL_JOURNAL", &journal)
        .env("PATH", path)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--no-self-test",
            "--daemon",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();
    ready_daemon.finish();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("journaling daemon runtime activation"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), original_settings);
    assert!(
        !service_file.exists(),
        "rollback retained the attempted unit"
    );
    assert!(
        !active_state.exists(),
        "rollback retained the attempted process"
    );
    assert!(!enabled_state.exists(), "rollback retained enablement");
    assert!(!journal.exists(), "rollback did not close its journal");
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user stop gommage-daemon.service\n"));
    assert!(calls.contains("--user disable gommage-daemon.service\n"));
}
