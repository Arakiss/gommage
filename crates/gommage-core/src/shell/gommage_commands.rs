use super::*;

pub(super) fn classify_gommage_argv(
    raw: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    if raw.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-admin-command");
    }
    let argv = strip_gommage_home_options(raw, out);

    let help_requested = argv
        .iter()
        .flatten()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"));
    let version_requested = argv
        .first()
        .and_then(Option::as_deref)
        .is_some_and(|arg| matches!(arg, "-V" | "--version"));
    if help_requested || version_requested {
        return false;
    }

    // A bare `gommage` invocation only renders help and does not mutate.
    if argv.is_empty() {
        return false;
    }
    let Some(command) = static_gommage_subcommand(&argv, 0, out) else {
        return false;
    };
    let dry_run = has_exact_flag(&argv, "--dry-run");

    match command {
        "grant" | "g" | "confirm" | "revoke" => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "approval" => classify_approval_command(&argv, dry_run, out),
        "tui" => {
            let inspection_only = [
                "--snapshot",
                "--watch",
                "--watch-ticks",
                "--stream",
                "--stream-ticks",
            ]
            .iter()
            .any(|flag| has_exact_or_value_flag(&argv, flag));
            if !inspection_only {
                out.push(GommageAdminEffect::Authorize);
            }
            !inspection_only
        }
        "init" => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        "quickstart" | "upgrade" => {
            if !dry_run {
                out.push(GommageAdminEffect::Reconfigure);
            }
            !dry_run && command == "quickstart"
        }
        "policy" => classify_policy_command(&argv, out),
        "project" => classify_project_command(&argv, dry_run, out),
        "agent" => classify_agent_command(&argv, dry_run, out),
        "repair" => classify_repair_command(&argv, dry_run, out),
        "daemon" => classify_daemon_command(&argv, dry_run, out),
        "expedition" => classify_expedition_command(&argv, out),
        "harness" => classify_harness_command(&argv, dry_run, out),
        "state" => classify_state_command(&argv, dry_run, out),
        "uninstall" => {
            if !dry_run {
                out.push(GommageAdminEffect::Disable);
            }
            !dry_run
                && (has_exact_flag(&argv, "--purge-home")
                    || has_exact_flag(&argv, "--home-data")
                    || has_exact_flag(&argv, "--all"))
        }
        // Closed inventory of non-administrative top-level commands. Some can
        // have ordinary filesystem or network effects, which remain visible to
        // their dedicated typed effects and compatibility mapper rules.
        "list" | "beta" | "update" | "posture" | "tail" | "explain" | "audit-verify" | "replay"
        | "decide" | "map" | "doctor" | "verify" | "managed" | "release" | "report" | "run"
        | "smoke" | "stats" | "sandbox" | "session" | "mascot" | "logo" | "hook" | "mcp" => {
            validate_read_only_nested_command(command, &argv, out);
            false
        }
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

pub(super) fn strip_gommage_home_options(
    raw: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> Vec<Option<String>> {
    let mut argv = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_deref() {
            Some("--home") => {
                match raw.get(index + 1) {
                    Some(Some(value)) if !value.is_empty() => {}
                    Some(None) => out.ambiguity("dynamic-gommage-admin-command"),
                    _ => out.ambiguity("unknown-gommage-admin-command"),
                }
                index += 2;
            }
            Some(value) if value.starts_with("--home=") => {
                if value == "--home=" {
                    out.ambiguity("unknown-gommage-admin-command");
                }
                index += 1;
            }
            _ => {
                argv.push(raw[index].clone());
                index += 1;
            }
        }
    }
    argv
}

pub(super) fn static_gommage_subcommand<'a>(
    argv: &'a [Option<String>],
    index: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) -> Option<&'a str> {
    match argv.get(index) {
        Some(Some(command)) => Some(command),
        Some(None) => {
            out.ambiguity("dynamic-gommage-admin-command");
            None
        }
        None => {
            out.ambiguity("unknown-gommage-admin-command");
            None
        }
    }
}

pub(super) fn has_exact_flag(argv: &[Option<String>], flag: &str) -> bool {
    argv.iter().any(|arg| arg.as_deref() == Some(flag))
}

pub(super) fn has_exact_or_value_flag(argv: &[Option<String>], flag: &str) -> bool {
    argv.iter().flatten().any(|arg| {
        arg == flag
            || arg
                .strip_prefix(flag)
                .is_some_and(|suffix| suffix.starts_with('='))
    })
}

pub(super) fn classify_approval_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let Some(command) = static_gommage_subcommand(argv, 1, out) else {
        return false;
    };
    match command {
        "approve" | "deny" => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "webhook" | "callback" if !dry_run => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "deny-stale" if has_exact_flag(argv, "--apply") => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "webhook" | "callback" | "deny-stale" | "list" | "show" | "dlq" | "replay" | "evidence"
        | "template" => false,
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

pub(super) fn classify_policy_command(
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let Some(command) = static_gommage_subcommand(argv, 1, out) else {
        return false;
    };
    match command {
        "init" => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        "check" | "layers" | "lint" | "schema" | "test" | "diff" | "suggest" | "snapshot"
        | "capture" | "hash" => false,
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

pub(super) fn classify_project_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("init") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            false
        }
        Some("init") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_agent_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("install") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("uninstall") if !dry_run => {
            out.push(GommageAdminEffect::Disable);
            false
        }
        Some("install" | "uninstall" | "status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_repair_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("agent") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            !has_exact_flag(argv, "--restore-backup")
        }
        Some("agent") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_daemon_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("install") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("uninstall") if !dry_run => {
            out.push(GommageAdminEffect::Disable);
            false
        }
        Some("reload") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("install" | "uninstall" | "status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_expedition_command(
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("start" | "end") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_harness_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("write-context") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("write-context" | "diagnose" | "explain") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn classify_state_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("rebuild" | "vacuum") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("reset") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("reset" | "verify" | "stats") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

pub(super) fn validate_read_only_nested_command(
    command: &str,
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let known: &[&str] = match command {
        "beta" => &["check"],
        "managed" => &["status"],
        "release" => &["verify"],
        "report" => &["bundle"],
        "run" => &["codex"],
        "sandbox" => &["advise"],
        "session" => &["doctor"],
        _ => return,
    };
    let Some(nested) = static_gommage_subcommand(argv, 1, out) else {
        return;
    };
    if !known.contains(&nested) {
        out.ambiguity("unknown-gommage-admin-command");
    }
}

pub(super) fn classify_gommage_service_lifecycle(
    command: &ShellCommand,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Ok(head) = command.trusted_effective_head() else {
        return;
    };
    if head == "systemctl" {
        classify_systemctl_lifecycle(command.effective_args(), out);
        return;
    }
    if head == "pkill" {
        classify_pkill_lifecycle(command.effective_args(), out);
        return;
    }
    if head == "killall" {
        classify_killall_lifecycle(command.effective_args(), out);
        return;
    }
    if head == "launchctl" {
        classify_launchctl_lifecycle(command.effective_args(), out);
        return;
    }
    if head == "service" {
        classify_service_lifecycle(command.effective_args(), out);
        return;
    }
    if head != "kill" {
        return;
    }
    let tokens = shell_word_tokens(command.effective_args());
    if tokens.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-service-target");
    }
}
