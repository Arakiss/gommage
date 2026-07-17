use super::*;

pub(super) fn classify_service_lifecycle(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    if args.iter().any(|word| word.static_value().is_err()) {
        out.ambiguity("dynamic-gommage-service-target");
        return;
    }
    let tokens = args
        .iter()
        .map(|word| word.static_value().expect("checked above"))
        .collect::<Vec<_>>();
    let Some(service) = tokens.first().copied() else {
        return;
    };
    if matches!(service, "--status-all" | "--help" | "--version") {
        return;
    }
    let service_is_gommage = matches!(
        service.rsplit('/').next(),
        Some("gommage-daemon.service" | "gommage-daemon")
    );
    let trailing_mentions_gommage = tokens.iter().skip(2).any(|token| {
        matches!(
            token.rsplit('/').next(),
            Some("gommage-daemon.service" | "gommage-daemon")
        )
    });
    if tokens.len() > 2 && (service_is_gommage || trailing_mentions_gommage) {
        out.ambiguity("nonexclusive-service-targets");
    }
    if !service_is_gommage {
        if trailing_mentions_gommage {
            out.ambiguity("decoy-gommage-service-target");
        }
        return;
    }
    let Some(action) = tokens.get(1).copied() else {
        out.ambiguity("missing-gommage-service-action");
        return;
    };
    match action {
        "start" | "restart" | "reload" | "force-reload" => {
            out.push(GommageAdminEffect::Reconfigure);
        }
        "stop" => out.push(GommageAdminEffect::Disable),
        "status" => {}
        _ => out.ambiguity("unknown-gommage-service-action"),
    }
}

pub(super) fn classify_launchctl_lifecycle(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(action_word) = args.first() else {
        return;
    };
    let action = match action_word.static_value() {
        Ok(action) => action,
        Err(_) => {
            out.ambiguity("dynamic-gommage-service-action");
            return;
        }
    };
    let lifecycle = match action {
        "start" | "kickstart" | "bootstrap" | "load" | "enable" | "submit" => {
            Some(GommageAdminEffect::Reconfigure)
        }
        "stop" | "bootout" | "unload" | "disable" | "remove" | "kill" => {
            Some(GommageAdminEffect::Disable)
        }
        "list" | "print" | "print-disabled" | "blame" | "procinfo" | "dumpstate" | "getenv"
        | "help" | "managerpid" | "manageruid" | "managername" | "error" | "variant"
        | "version" => None,
        _ => {
            if args.iter().any(launchctl_word_targets_gommage) {
                out.ambiguity("unknown-gommage-service-action");
            }
            return;
        }
    };
    let Some(lifecycle) = lifecycle else {
        return;
    };

    if args.iter().skip(1).any(|word| word.static_value().is_err()) {
        out.ambiguity("dynamic-launchctl-option-value");
    }
    if !validate_launchctl_action(action, &args[1..], out) {
        return;
    }
    let targets_gommage = if action == "submit" {
        launchctl_submit_targets_gommage(&args[1..], out)
    } else {
        launchctl_action_targets_gommage(action, &args[1..], out)
    };
    if targets_gommage {
        out.push(lifecycle);
    }
}

pub(super) fn launchctl_action_targets_gommage(
    action: &str,
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let tokens = args
        .iter()
        .map(|word| {
            word.static_value()
                .expect("launchctl validation requires static arguments")
        })
        .collect::<Vec<_>>();
    let mut targets = Vec::new();
    match action {
        "load" | "unload" => {
            let mut index = 0;
            while index < tokens.len() {
                match tokens[index] {
                    "-S" | "-D" => index += 2,
                    "-w" | "-F" => index += 1,
                    target => {
                        targets.push(target);
                        index += 1;
                    }
                }
            }
        }
        "bootstrap" | "bootout" if tokens.len() > 1 => {
            targets.extend(tokens.iter().skip(1).copied());
        }
        "kill" if tokens.len() > 1 => targets.push(tokens[1]),
        "kickstart" => {
            targets.extend(
                tokens
                    .iter()
                    .copied()
                    .filter(|token| !token.starts_with('-')),
            );
        }
        _ => targets.extend(
            tokens
                .iter()
                .copied()
                .filter(|token| !token.starts_with('-')),
        ),
    }

    let gommage_targets = targets
        .iter()
        .filter(|target| launchctl_value_targets_gommage(target))
        .count();
    if gommage_targets > 0 && gommage_targets != targets.len() {
        out.ambiguity("nonexclusive-launchctl-targets");
    }
    gommage_targets > 0
}

pub(super) fn launchctl_value_targets_gommage(value: &str) -> bool {
    matches!(value, "dev.gommage.daemon" | "dev.gommage.daemon.plist")
        || value.ends_with("/dev.gommage.daemon")
        || value.ends_with("/dev.gommage.daemon.plist")
}

pub(super) fn launchctl_submit_targets_gommage(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let tokens = args
        .iter()
        .map(|word| {
            word.static_value()
                .expect("launchctl validation requires static arguments")
        })
        .collect::<Vec<_>>();
    let mut label = None;
    let mut program = None;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "-l" => {
                if label.replace(tokens[index + 1]).is_some() {
                    out.ambiguity("multiple-launchctl-submit-labels");
                }
                index += 2;
            }
            "-p" => {
                if program.replace(tokens[index + 1]).is_some() {
                    out.ambiguity("multiple-launchctl-submit-programs");
                }
                index += 2;
            }
            "-o" | "-e" => index += 2,
            "--" => {
                if tokens
                    .get(index + 1)
                    .is_some_and(|command| program.replace(command).is_some())
                {
                    out.ambiguity("multiple-launchctl-submit-programs");
                }
                break;
            }
            _ => index += 1,
        }
    }

    let label_is_gommage = label == Some("dev.gommage.daemon");
    let program_is_gommage = program.is_some_and(|program| {
        trusted_executable_basename(program).is_ok_and(|head| head == "gommage-daemon")
    });
    let mentions_gommage = tokens.iter().any(|value| value.contains("gommage"));
    if mentions_gommage && !(label_is_gommage && program_is_gommage) {
        out.ambiguity("nonexclusive-launchctl-submit");
    }
    label_is_gommage || program_is_gommage
}

pub(super) fn launchctl_word_targets_gommage(word: &ShellWord) -> bool {
    word.static_value()
        .is_ok_and(launchctl_value_targets_gommage)
}

pub(super) fn validate_launchctl_action(
    action: &str,
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    if args.iter().any(|word| word.static_value().is_err()) {
        return false;
    }
    let tokens = args
        .iter()
        .map(|word| word.static_value().expect("checked above"))
        .collect::<Vec<_>>();
    match action {
        "submit" => {
            let mut index = 0;
            while index < tokens.len() {
                match tokens[index] {
                    "--" => return true,
                    "-l" | "-p" | "-o" | "-e" => {
                        if tokens.get(index + 1).is_none() {
                            out.ambiguity("missing-launchctl-option-value");
                            return false;
                        }
                        index += 2;
                    }
                    value if value.starts_with('-') => {
                        out.ambiguity("unknown-launchctl-option");
                        return false;
                    }
                    _ => index += 1,
                }
            }
            true
        }
        "bootstrap" | "bootout" => {
            if tokens.is_empty() {
                out.ambiguity("missing-launchctl-domain");
                return false;
            }
            true
        }
        "load" | "unload" => {
            let mut index = 0;
            while index < tokens.len() {
                match tokens[index] {
                    "-w" | "-F" => index += 1,
                    "-S" | "-D" => {
                        if tokens.get(index + 1).is_none() {
                            out.ambiguity("missing-launchctl-option-value");
                            return false;
                        }
                        index += 2;
                    }
                    value if value.starts_with('-') => {
                        out.ambiguity("unknown-launchctl-option");
                        return false;
                    }
                    _ => index += 1,
                }
            }
            true
        }
        "kickstart" => {
            if tokens
                .iter()
                .any(|value| value.starts_with('-') && !matches!(*value, "-k" | "-p" | "-s"))
            {
                out.ambiguity("unknown-launchctl-option");
                return false;
            }
            true
        }
        "kill" => {
            if tokens.len() < 2 {
                out.ambiguity("missing-launchctl-option-value");
                return false;
            }
            true
        }
        _ => true,
    }
}

pub(super) fn classify_systemctl_lifecycle(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let known_actions = [
        "start",
        "restart",
        "try-restart",
        "reload",
        "reload-or-restart",
        "try-reload-or-restart",
        "enable",
        "edit",
        "link",
        "reenable",
        "preset",
        "revert",
        "unmask",
        "stop",
        "disable",
        "mask",
        "kill",
        "status",
        "show",
        "cat",
        "help",
        "is-active",
        "is-enabled",
        "is-failed",
        "list-dependencies",
        "daemon-reload",
    ];
    let action = args.iter().enumerate().find_map(|(index, word)| {
        word.static_value()
            .ok()
            .filter(|value| known_actions.contains(value))
            .map(|value| (index, value))
    });
    let Some((action_index, action)) = action else {
        if args
            .iter()
            .filter_map(|word| word.static_value().ok())
            .any(|value| systemctl_target_matches_gommage(value).unwrap_or(true))
        {
            out.ambiguity("unknown-gommage-service-action");
        } else if args.iter().any(|word| word.static_value().is_err()) {
            out.ambiguity("dynamic-gommage-service-action");
        }
        return;
    };
    if !validate_systemctl_options(args, action_index, out) {
        return;
    }
    if matches!(
        action,
        "status"
            | "show"
            | "cat"
            | "help"
            | "is-active"
            | "is-enabled"
            | "is-failed"
            | "list-dependencies"
            | "daemon-reload"
    ) {
        return;
    }
    let lifecycle = if matches!(action, "stop" | "disable" | "mask" | "kill") {
        GommageAdminEffect::Disable
    } else {
        GommageAdminEffect::Reconfigure
    };
    let mut targets_gommage = false;
    let mut targets_other_service = false;
    for target in systemctl_target_words(args, action_index) {
        match target.static_value() {
            Ok(value) => match systemctl_target_matches_gommage(value) {
                Ok(true) => targets_gommage = true,
                Ok(false) => targets_other_service = true,
                Err(reason) => out.ambiguity(reason),
            },
            Err(_) => out.ambiguity("dynamic-gommage-service-target"),
        }
    }
    if targets_gommage && targets_other_service {
        out.ambiguity("nonexclusive-systemctl-targets");
    }
    if targets_gommage {
        out.push(lifecycle);
    }
}

pub(super) fn systemctl_target_words(args: &[ShellWord], action_index: usize) -> Vec<&ShellWord> {
    let mut targets = Vec::new();
    let mut index = action_index + 1;
    let mut options = true;
    while index < args.len() {
        let Ok(value) = args[index].static_value() else {
            targets.push(&args[index]);
            index += 1;
            continue;
        };
        if value == "--" && options {
            options = false;
            index += 1;
            continue;
        }
        if options && systemctl_option_takes_value(value) {
            index += 2;
            continue;
        }
        if options && value.starts_with('-') {
            index += 1;
            continue;
        }
        targets.push(&args[index]);
        index += 1;
    }
    targets
}

pub(super) fn systemctl_option_takes_value(value: &str) -> bool {
    matches!(
        value,
        "-H" | "--host"
            | "-M"
            | "--machine"
            | "--root"
            | "--image"
            | "--type"
            | "--state"
            | "--property"
            | "--value"
            | "--job-mode"
            | "--kill-who"
            | "--signal"
            | "--output"
            | "--lines"
    )
}

pub(super) fn validate_systemctl_options(
    args: &[ShellWord],
    action_index: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let context_value_options = ["-H", "--host", "-M", "--machine", "--root", "--image"];
    let ordinary_value_options = [
        "--type",
        "--state",
        "--property",
        "--value",
        "--job-mode",
        "--kill-who",
        "--signal",
        "--output",
        "--lines",
    ];
    let mut index = 0;
    while index < args.len() {
        if index == action_index {
            index += 1;
            continue;
        }
        let value = match args[index].static_value() {
            Ok(value) => value,
            Err(_) => {
                out.ambiguity("dynamic-systemctl-option");
                return false;
            }
        };
        if value == "--" {
            index += 1;
            continue;
        }
        if context_value_options.contains(&value) || ordinary_value_options.contains(&value) {
            let Some(option_value) = args.get(index + 1) else {
                out.ambiguity("missing-systemctl-option-value");
                return false;
            };
            if option_value.static_value().is_err() {
                out.ambiguity("dynamic-systemctl-option");
                return false;
            }
            if context_value_options.contains(&value) {
                out.ambiguity("wrapper-execution-context-mutation");
            }
            index += 2;
            continue;
        }
        if context_value_options
            .iter()
            .filter(|option| option.starts_with("--"))
            .any(|option| value.starts_with(&format!("{option}=")))
        {
            if value.ends_with('=') {
                out.ambiguity("missing-systemctl-option-value");
                return false;
            }
            out.ambiguity("wrapper-execution-context-mutation");
            index += 1;
            continue;
        }
        if ordinary_value_options
            .iter()
            .any(|option| value.starts_with(&format!("{option}=")))
        {
            if value.ends_with('=') {
                out.ambiguity("missing-systemctl-option-value");
                return false;
            }
            index += 1;
            continue;
        }
        if matches!(
            value,
            "--system"
                | "--user"
                | "--global"
                | "--runtime"
                | "--force"
                | "--no-reload"
                | "--no-block"
                | "--no-wall"
                | "--dry-run"
                | "--quiet"
                | "-q"
                | "--full"
                | "--recursive"
                | "-r"
                | "--reverse"
                | "--after"
                | "--before"
                | "--all"
                | "-a"
                | "--failed"
                | "--legend"
                | "--plain"
                | "--no-pager"
                | "--no-ask-password"
                | "--wait"
                | "--show-transaction"
                | "--marked"
                | "--now"
        ) {
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            out.ambiguity("unknown-systemctl-option");
            return false;
        }
        if index < action_index {
            out.ambiguity("nonpositional-systemctl-action");
            return false;
        }
        index += 1;
    }
    true
}

pub(super) fn systemctl_target_matches_gommage(value: &str) -> Result<bool, Ambiguity> {
    let target = value.rsplit('/').next().unwrap_or(value);
    if matches!(target, "gommage-daemon.service" | "gommage-daemon") {
        return Ok(true);
    }
    if target.contains('{') || target.contains('}') {
        return Err("shell-brace-expansion");
    }
    let glob = globset::Glob::new(target).map_err(|_| "invalid-systemctl-unit-pattern")?;
    let matcher = glob.compile_matcher();
    if ["gommage-daemon.service", "gommage-daemon"]
        .iter()
        .any(|candidate| matcher.is_match(candidate))
    {
        return Err("broad-systemctl-unit-pattern");
    }
    Ok(false)
}

pub(super) fn classify_pkill_lifecycle(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(spec) = pkill_spec(args, out) else {
        return;
    };
    if spec.inverse {
        out.ambiguity("inverse-pkill-selection");
        out.push(GommageAdminEffect::Disable);
    }
    let pattern = match spec.pattern.static_value() {
        Ok(pattern) => pattern,
        Err(_) => {
            out.ambiguity("dynamic-gommage-service-target");
            return;
        }
    };
    let mut builder = regex::RegexBuilder::new(pattern);
    builder.case_insensitive(spec.ignore_case);
    match builder.build() {
        Ok(pattern)
            if pkill_candidates(spec.full)
                .iter()
                .any(|candidate| pattern.is_match(candidate)) =>
        {
            if !regex_selects_only_gommage_daemon(pattern.as_str(), spec.ignore_case) {
                out.ambiguity("broad-pkill-pattern");
            }
            out.push(GommageAdminEffect::Disable);
        }
        // `pkill -f` matches an arbitrary full command line, including custom
        // daemon paths selected through GOMMAGE_DAEMON_BIN. A finite candidate
        // list cannot prove that a regular expression is disjoint from every
        // possible Gommage daemon command, so unmatched full-mode patterns are
        // intentionally fail-closed.
        Ok(_) if spec.full => out.ambiguity("opaque-pkill-full-pattern"),
        Ok(_) => {}
        Err(_) => out.ambiguity("invalid-pkill-pattern"),
    }
}

pub(super) fn regex_selects_only_gommage_daemon(pattern: &str, ignore_case: bool) -> bool {
    let Some(literal) = literal_regex_value(pattern) else {
        return false;
    };
    let target = head_basename(&literal);
    if ignore_case {
        target.eq_ignore_ascii_case("gommage-daemon")
    } else {
        target == "gommage-daemon"
    }
}

pub(super) fn literal_regex_value(pattern: &str) -> Option<String> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut literal = String::new();
    let mut index = usize::from(chars.first() == Some(&'^'));
    while index < chars.len() {
        match chars[index] {
            '$' if index + 1 == chars.len() => break,
            '\\' => {
                let escaped = *chars.get(index + 1)?;
                literal.push(escaped);
                index += 2;
            }
            '[' => {
                let closing = chars[index + 1..]
                    .iter()
                    .position(|character| *character == ']')?
                    + index
                    + 1;
                let contents = &chars[index + 1..closing];
                let selected = match contents {
                    [single] => *single,
                    ['\\', escaped] => *escaped,
                    _ => return None,
                };
                literal.push(selected);
                index = closing + 1;
            }
            '.' | '*' | '+' | '?' | '|' | '(' | ')' | '{' | '}' | '^' | '$' => return None,
            character => {
                literal.push(character);
                index += 1;
            }
        }
    }
    Some(literal)
}

#[derive(Debug)]
pub(super) struct PkillSpec<'a> {
    pattern: &'a ShellWord,
    ignore_case: bool,
    full: bool,
    inverse: bool,
}

pub(super) fn pkill_candidates(full: bool) -> &'static [&'static str] {
    if full {
        &[
            "gommage-daemon",
            "/usr/local/bin/gommage-daemon",
            "/opt/homebrew/bin/gommage-daemon",
            "/home/user/.cargo/bin/gommage-daemon",
            "/Users/user/.cargo/bin/gommage-daemon",
            "/home/user/.local/bin/gommage-daemon",
            "/usr/local/bin/gommage-daemon --foreground",
        ]
    } else {
        &["gommage-daemon"]
    }
}

pub(super) fn pkill_spec<'a>(
    args: &'a [ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) -> Option<PkillSpec<'a>> {
    let value_options = [
        "-d",
        "--delimiter",
        "-g",
        "--pgroup",
        "-G",
        "--group",
        "-P",
        "--parent",
        "-s",
        "--session",
        "-t",
        "--terminal",
        "-u",
        "--euid",
        "-U",
        "--uid",
        "-F",
        "--pidfile",
        "-O",
        "--older",
        "-q",
        "--queue",
        "-r",
        "--runstates",
        "--cgroup",
        "--ns",
        "--nslist",
        "--env",
        "--signal",
    ];
    let mut index = 0;
    let mut pattern = None;
    let mut options = true;
    let mut ignore_case = false;
    let mut full = false;
    let mut inverse = false;
    while index < args.len() {
        match args[index].static_value() {
            Ok("--") if options => {
                options = false;
                index += 1;
            }
            Ok(value) if options && value_options.contains(&value) => {
                let Some(option_value) = args.get(index + 1) else {
                    out.ambiguity("missing-pkill-option-value");
                    return None;
                };
                if option_value.static_value().is_err() {
                    out.ambiguity("dynamic-pkill-option-value");
                    return None;
                }
                index += 2;
            }
            Ok("-i" | "--ignore-case") if options => {
                ignore_case = true;
                index += 1;
            }
            Ok("-f" | "--full") if options => {
                full = true;
                index += 1;
            }
            Ok("-v" | "--inverse") if options => {
                inverse = true;
                index += 1;
            }
            Ok(value) if options && value.starts_with('-') && !value.starts_with("--") => {
                // procps accepts compact boolean short options such as `-if`.
                let compact = value.trim_start_matches('-');
                if compact.chars().all(|flag| matches!(flag, 'i' | 'f' | 'v')) {
                    ignore_case |= compact.contains('i');
                    full |= compact.contains('f');
                    inverse |= compact.contains('v');
                } else if !is_signal_shorthand(value) {
                    out.ambiguity("unknown-pkill-option");
                    return None;
                }
                index += 1;
            }
            Ok(value) if options && value.starts_with("--") && value.contains('=') => {
                let (option, option_value) = value.split_once('=').expect("contains '='");
                if !value_options.contains(&option) || option_value.is_empty() {
                    out.ambiguity("unknown-pkill-option");
                    return None;
                }
                index += 1;
            }
            Ok(value) if options && value.starts_with('-') => {
                out.ambiguity("unknown-pkill-option");
                return None;
            }
            Ok(_) => {
                if pattern.replace(&args[index]).is_some() {
                    out.ambiguity("multiple-pkill-patterns");
                    return None;
                }
                index += 1;
            }
            Err(_) => {
                out.ambiguity("dynamic-gommage-service-target");
                return None;
            }
        }
    }
    pattern.map(|pattern| PkillSpec {
        pattern,
        ignore_case,
        full,
        inverse,
    })
}

pub(super) fn is_signal_shorthand(value: &str) -> bool {
    let signal = value.strip_prefix('-').unwrap_or(value);
    !signal.is_empty()
        && (signal.bytes().all(|byte| byte.is_ascii_digit())
            || matches!(
                signal,
                "HUP"
                    | "INT"
                    | "QUIT"
                    | "ILL"
                    | "TRAP"
                    | "ABRT"
                    | "BUS"
                    | "FPE"
                    | "KILL"
                    | "USR1"
                    | "SEGV"
                    | "USR2"
                    | "PIPE"
                    | "ALRM"
                    | "TERM"
                    | "CHLD"
                    | "CONT"
                    | "STOP"
                    | "TSTP"
                    | "TTIN"
                    | "TTOU"
            ))
}

pub(super) fn classify_killall_lifecycle(
    args: &[ShellWord],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let value_options = [
        "-s",
        "--signal",
        "-u",
        "--user",
        "-y",
        "--younger-than",
        "-o",
        "--older-than",
    ];
    let mut index = 0;
    let mut options = true;
    let mut regexp = false;
    let mut ignore_case = false;
    let mut targets_gommage = false;
    let mut target_count = 0;

    while index < args.len() {
        match args[index].static_value() {
            Ok("--") if options => {
                options = false;
                index += 1;
            }
            Ok(value) if options && value_options.contains(&value) => {
                let Some(option_value) = args.get(index + 1) else {
                    out.ambiguity("missing-killall-option-value");
                    return;
                };
                if option_value.static_value().is_err() {
                    out.ambiguity("dynamic-killall-option-value");
                    return;
                }
                index += 2;
            }
            Ok("-r" | "--regexp" | "-m") if options => {
                regexp = true;
                index += 1;
            }
            Ok("-I" | "--ignore-case") if options => {
                ignore_case = true;
                index += 1;
            }
            Ok("-g" | "--process-group") if options => {
                out.ambiguity("killall-process-group-selection");
                index += 1;
            }
            Ok(value) if options && value.starts_with("--") && value.contains('=') => {
                let (option, option_value) = value.split_once('=').expect("contains '='");
                if !value_options.contains(&option) || option_value.is_empty() {
                    out.ambiguity("unknown-killall-option");
                    return;
                }
                index += 1;
            }
            Ok(value) if options && value.starts_with('-') => {
                if is_signal_shorthand(value)
                    || matches!(
                        value,
                        "-e" | "--exact"
                            | "-i"
                            | "--interactive"
                            | "-l"
                            | "--list"
                            | "-q"
                            | "--quiet"
                            | "-v"
                            | "--verbose"
                            | "-w"
                            | "--wait"
                    )
                {
                    index += 1;
                } else {
                    out.ambiguity("unknown-killall-option");
                    return;
                }
            }
            Ok(value) => {
                target_count += 1;
                if regexp {
                    let mut builder = regex::RegexBuilder::new(value);
                    builder.case_insensitive(ignore_case);
                    match builder.build() {
                        Ok(pattern) if pattern.is_match("gommage-daemon") => {
                            targets_gommage = true;
                            if !regex_selects_only_gommage_daemon(value, ignore_case) {
                                out.ambiguity("broad-killall-pattern");
                            }
                        }
                        Ok(_) => {}
                        Err(_) => out.ambiguity("invalid-killall-pattern"),
                    }
                } else if if ignore_case {
                    value.eq_ignore_ascii_case("gommage-daemon")
                } else {
                    value == "gommage-daemon"
                } {
                    targets_gommage = true;
                }
                index += 1;
            }
            Err(_) => {
                out.ambiguity("dynamic-gommage-service-target");
                return;
            }
        }
    }

    if targets_gommage {
        if target_count != 1 {
            out.ambiguity("nonexclusive-killall-targets");
        }
        out.push(GommageAdminEffect::Disable);
    }
}
