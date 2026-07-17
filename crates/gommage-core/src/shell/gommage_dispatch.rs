use super::*;

/// Derive Gommage administration effects from parsed argv, not command text.
///
/// `effective_words` already unwraps transparent process wrappers and the AST
/// collector recursively adds static `sh -c` payloads. This function adds the
/// direct Gommage binaries. Cargo-selected binaries are deliberately not
/// treated as the installed authority: an arbitrary workspace may define the
/// same bin/package name and alter execution through runners or build scripts.
pub(crate) fn gommage_admin_effects(
    analysis: &ShellAnalysis,
    cwd: Option<&str>,
) -> EffectSet<GommageAdminEffect> {
    gommage_admin_effects_inner(analysis, cwd, 0)
}

pub(super) fn gommage_admin_effects_inner(
    analysis: &ShellAnalysis,
    cwd: Option<&str>,
    dispatcher_depth: usize,
) -> EffectSet<GommageAdminEffect> {
    let mut out = EffectSet::default();
    for reason in &analysis.ambiguities {
        out.ambiguity(reason);
    }
    let cwd = trusted_cwd(cwd);
    let mut cwd_may_have_changed = false;
    for command in &analysis.commands {
        let effect_cwd = (!cwd_may_have_changed).then_some(cwd.as_deref()).flatten();
        let first_effect = out.effects.len();
        classify_gommage_invocation(command, effect_cwd, &mut out);
        classify_gommage_daemon_invocation(command, effect_cwd, &mut out);
        if cwd_may_have_changed
            && out.effects[first_effect..].iter().any(|effect| {
                matches!(
                    effect,
                    GommageAdminEffect::HomeMutate(path) | GommageAdminEffect::PathWrite(path)
                        if path_is_cwd_relative(path)
                )
            })
        {
            out.ambiguity("shell-cwd-mutation");
        }
        classify_gommage_dispatcher(command, effect_cwd, dispatcher_depth, &mut out);
        classify_gommage_service_lifecycle(command, &mut out);
        cwd_may_have_changed |= command_changes_cwd(command);
    }
    if !out.effects.is_empty() && analysis.commands.len() != 1 {
        out.ambiguity("compound-gommage-admin-command");
    }
    out
}

pub(super) fn classify_gommage_daemon_invocation(
    command: &ShellCommand,
    cwd: Option<&str>,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(words) = gommage_daemon_invocation_words(command, out) else {
        return;
    };
    let tokens = shell_word_tokens(&words);
    if tokens.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-daemon-command");
        return;
    }
    let tokens = tokens.into_iter().flatten().collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| matches!(token.as_str(), "-h" | "--help" | "-V" | "--version"))
    {
        return;
    }

    let mut index = 0;
    let mut homes = Vec::new();
    let mut sockets = Vec::new();
    while index < words.len() {
        let value = words[index]
            .static_value()
            .expect("dynamic daemon words returned above");
        match value {
            "--foreground" => index += 1,
            "--home" | "--socket" => {
                let Some(path) = words.get(index + 1) else {
                    out.ambiguity("missing-gommage-daemon-option-value");
                    return;
                };
                if value == "--home" {
                    homes.push(path.clone());
                } else {
                    sockets.push(path.clone());
                }
                index += 2;
            }
            value if value.starts_with("--home=") => {
                homes.push(static_shell_word(&value["--home=".len()..]));
                index += 1;
            }
            value if value.starts_with("--socket=") => {
                sockets.push(static_shell_word(&value["--socket=".len()..]));
                index += 1;
            }
            value if value.starts_with("--foreground=") => index += 1,
            _ => {
                out.ambiguity("unknown-gommage-daemon-option");
                return;
            }
        }
    }

    out.push(GommageAdminEffect::Reconfigure);
    for home in homes {
        match static_path(&home, cwd) {
            Ok(path) => out.push(GommageAdminEffect::HomeMutate(path)),
            Err(reason) => out.ambiguity(reason),
        }
    }
    for socket in sockets {
        match static_path(&socket, cwd) {
            Ok(path) => out.push(GommageAdminEffect::PathWrite(path)),
            Err(reason) => out.ambiguity(reason),
        }
    }
}

pub(super) fn static_shell_word(value: &str) -> ShellWord {
    ShellWord {
        raw: value.to_string(),
        value: Some(value.to_string()),
        provenance: WordProvenance::default(),
        ambiguity: None,
    }
}

pub(super) fn classify_gommage_invocation(
    command: &ShellCommand,
    cwd: Option<&str>,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(words) = gommage_invocation_words(command, out) else {
        return;
    };
    if classify_gommage_argv(&shell_word_tokens(&words), out) {
        for home in gommage_path_option_words(&words, "--home", out) {
            match static_path(&home, cwd) {
                Ok(path) => out.push(GommageAdminEffect::HomeMutate(path)),
                Err(reason) => out.ambiguity(reason),
            }
        }
    }
}

pub(super) fn classify_gommage_dispatcher(
    command: &ShellCommand,
    cwd: Option<&str>,
    depth: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Ok(head) = command.trusted_effective_head() else {
        return;
    };
    match head {
        "eval" => classify_eval_dispatch(command.effective_args(), cwd, depth, out),
        "watch" => classify_watch_dispatch(command.effective_args(), cwd, depth, out),
        "xargs" => {
            if dispatcher_words_may_invoke_gommage(command.effective_args()) {
                out.ambiguity("xargs-gommage-command");
            } else if xargs_invokes_opaque_dispatcher(command.effective_args()) {
                out.ambiguity("xargs-opaque-command");
            }
        }
        "find" => classify_find_dispatch(command.effective_args(), out),
        _ => {}
    }
}

pub(super) fn classify_eval_dispatch(
    args: &[ShellWord],
    cwd: Option<&str>,
    depth: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(payload) = static_eval_payload(args, out) else {
        return;
    };
    classify_nested_shell_program(&payload, cwd, depth, out);
}

pub(super) fn static_eval_payload<T: PartialEq>(
    args: &[ShellWord],
    out: &mut EffectSet<T>,
) -> Option<String> {
    let mut start = 0;
    if let Some(first) = args.first() {
        match first.static_value() {
            Ok("--") => start = 1,
            Ok(value) if value.starts_with('-') => {
                out.ambiguity("unknown-eval-option");
                return None;
            }
            Ok(_) => {}
            Err(_) => {
                out.ambiguity("dynamic-eval-command");
                return None;
            }
        }
    }
    if start == args.len() {
        return None;
    }
    match args[start..]
        .iter()
        .map(ShellWord::static_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(words) => Some(words.join(" ")),
        Err(_) => {
            out.ambiguity("dynamic-eval-command");
            None
        }
    }
}

pub(super) fn classify_watch_dispatch(
    args: &[ShellWord],
    cwd: Option<&str>,
    depth: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some((start, exec_mode)) = watch_command_start(args, out) else {
        return;
    };
    let payload = &args[start..];
    if payload.is_empty() {
        return;
    }
    if exec_mode {
        classify_nested_argv(payload, cwd, depth, out);
        return;
    }
    let payload = match payload
        .iter()
        .map(ShellWord::static_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(words) => words.join(" "),
        Err(_) => {
            out.ambiguity("dynamic-watch-command");
            return;
        }
    };
    classify_nested_shell_program(&payload, cwd, depth, out);
}

pub(super) fn watch_command_start<T: PartialEq>(
    args: &[ShellWord],
    out: &mut EffectSet<T>,
) -> Option<(usize, bool)> {
    let mut index = 0;
    let mut exec_mode = false;
    while index < args.len() {
        let Ok(arg) = args[index].static_value() else {
            out.ambiguity("dynamic-watch-command");
            return None;
        };
        match arg {
            "--" => return Some((index + 1, exec_mode)),
            "-x" | "--exec" => {
                exec_mode = true;
                index += 1;
            }
            "-n" | "--interval" => {
                if args.get(index + 1).is_none() {
                    out.ambiguity("missing-watch-option-value");
                    return None;
                }
                index += 2;
            }
            value if value.starts_with("--interval=") || value.starts_with("--differences=") => {
                index += 1;
            }
            "-a" | "--beep" | "-b" | "--beep-errs" | "-c" | "--color" | "-C" | "--no-color"
            | "-d" | "--differences" | "-e" | "--errexit" | "-f" | "--follow" | "-g"
            | "--chgexit" | "-p" | "--precise" | "-q" | "--equexit" | "-r" | "--no-rerun"
            | "-t" | "--no-title" | "-w" | "--no-wrap" => index += 1,
            value if value.starts_with('-') => {
                if args[index..].iter().any(word_mentions_gommage) {
                    out.ambiguity("unknown-watch-option");
                }
                return None;
            }
            _ => return Some((index, exec_mode)),
        }
    }
    None
}

pub(super) fn classify_nested_shell_program(
    payload: &str,
    cwd: Option<&str>,
    depth: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    if depth >= 4 {
        out.ambiguity("gommage-dispatcher-depth");
        return;
    }
    let nested = gommage_admin_effects_inner(&analyze(payload), cwd, depth + 1);
    merge_effect_set(out, nested);
}

pub(super) fn classify_nested_argv(
    words: &[ShellWord],
    cwd: Option<&str>,
    depth: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let mut scratch = ShellAnalysis::default();
    let command = ShellCommand {
        words: words.to_vec(),
        effective_words: unwrap_words(words, &mut scratch),
        redirections: Vec::new(),
    };
    for reason in scratch.ambiguities {
        out.ambiguity(reason);
    }
    classify_gommage_invocation(&command, cwd, out);
    if let Some(payload) = shell_c_payload(&command.effective_words) {
        match payload {
            Ok(payload) => classify_nested_shell_program(&payload, cwd, depth, out),
            Err(reason) => out.ambiguity(reason),
        }
    }
}

pub(super) fn merge_effect_set<T: PartialEq>(out: &mut EffectSet<T>, nested: EffectSet<T>) {
    for effect in nested.effects {
        out.push(effect);
    }
    for reason in nested.ambiguities {
        out.ambiguity(reason);
    }
}

pub(super) fn classify_find_dispatch(args: &[ShellWord], out: &mut EffectSet<GommageAdminEffect>) {
    let mut index = 0;
    while index < args.len() {
        let Ok(arg) = args[index].static_value() else {
            index += 1;
            continue;
        };
        if !matches!(arg, "-exec" | "-execdir" | "-ok" | "-okdir") {
            index += 1;
            continue;
        }
        let start = index + 1;
        let end = args[start..]
            .iter()
            .position(|word| {
                word.static_value()
                    .is_ok_and(|value| matches!(value, ";" | "+"))
            })
            .map(|offset| start + offset)
            .unwrap_or(args.len());
        let payload = &args[start..end];
        if payload.iter().any(word_mentions_gommage) {
            out.ambiguity("find-exec-gommage-command");
        } else if payload.iter().any(|word| word.static_value().is_err()) {
            out.ambiguity("dynamic-find-exec-command");
        }
        index = end.saturating_add(1);
    }
}

pub(super) fn dispatcher_words_may_invoke_gommage(words: &[ShellWord]) -> bool {
    words.iter().any(word_mentions_gommage)
}

pub(super) fn xargs_invokes_opaque_dispatcher(words: &[ShellWord]) -> bool {
    words.iter().any(|word| {
        word.static_value().is_ok_and(|value| {
            matches!(
                head_basename(value),
                "bash" | "sh" | "zsh" | "python" | "python3" | "node" | "ruby" | "perl"
            )
        })
    })
}

pub(super) fn word_mentions_gommage(word: &ShellWord) -> bool {
    word.static_value().map_or_else(
        |_| word.raw.contains("gommage"),
        |value| value.contains("gommage"),
    )
}

pub(super) fn gommage_invocation_words<T: PartialEq>(
    command: &ShellCommand,
    out: &mut EffectSet<T>,
) -> Option<Vec<ShellWord>> {
    let Ok(head) = command.trusted_effective_head() else {
        return None;
    };
    match head {
        "gommage" => Some(command.effective_args().to_vec()),
        "cargo" => {
            let args = command.effective_args();
            let tokens = shell_word_tokens(args);
            if cargo_run_gommage_argv_start(&tokens, out).is_some() {
                out.ambiguity("untrusted-cargo-gommage-execution");
            }
            None
        }
        _ => None,
    }
}

pub(super) fn gommage_daemon_invocation_words<T: PartialEq>(
    command: &ShellCommand,
    out: &mut EffectSet<T>,
) -> Option<Vec<ShellWord>> {
    let Ok(head) = command.trusted_effective_head() else {
        return None;
    };
    match head {
        "gommage-daemon" => Some(command.effective_args().to_vec()),
        "cargo" => {
            let args = command.effective_args();
            let tokens = shell_word_tokens(args);
            if cargo_run_daemon_argv_start(&tokens, out).is_some() {
                out.ambiguity("untrusted-cargo-gommage-execution");
            }
            None
        }
        _ => None,
    }
}

pub(super) fn shell_word_tokens(words: &[ShellWord]) -> Vec<Option<String>> {
    words
        .iter()
        .map(|word| word.static_value().ok().map(str::to_string))
        .collect()
}

pub(super) fn cargo_run_gommage_argv_start<T: PartialEq>(
    tokens: &[Option<String>],
    out: &mut EffectSet<T>,
) -> Option<usize> {
    let may_target_gommage = tokens.iter().flatten().any(|token| {
        token == "gommage"
            || is_gommage_cli_package(token)
            || is_gommage_cli_manifest(token)
            || is_gommage_admin_command_name(token)
    });
    if may_target_gommage && tokens.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-admin-command");
    }
    let Some(run) = cargo_run_subcommand_index(tokens) else {
        let dynamic_subcommand_with_gommage_selector = tokens.iter().any(Option::is_none)
            && tokens.iter().flatten().any(|token| {
                token == "gommage"
                    || is_gommage_cli_package(token)
                    || is_gommage_cli_manifest(token)
            });
        if dynamic_subcommand_with_gommage_selector {
            out.ambiguity("dynamic-gommage-admin-command");
        }
        return None;
    };
    let mut bin: Option<Option<String>> = None;
    let mut package: Option<Option<String>> = None;
    let mut manifest: Option<Option<String>> = None;
    let mut example_selected = false;
    let mut argv_start = tokens.len();
    let mut index = run + 1;
    while index < tokens.len() {
        match tokens[index].as_deref() {
            Some("--") => {
                argv_start = index + 1;
                break;
            }
            Some("--bin") => {
                bin = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("-p" | "--package") => {
                package = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("--manifest-path") => {
                manifest = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some(value) if value.starts_with("--bin=") => {
                bin = Some(Some(value["--bin=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--package=") => {
                package = Some(Some(value["--package=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--manifest-path=") => {
                manifest = Some(Some(value["--manifest-path=".len()..].to_string()));
                index += 1;
            }
            Some("--example") => {
                example_selected = true;
                if !matches!(tokens.get(index + 1), Some(Some(_))) {
                    out.ambiguity("dynamic-gommage-admin-command");
                    return None;
                }
                index += 2;
            }
            Some(value) if value.starts_with("--example=") => {
                example_selected = true;
                index += 1;
            }
            Some(
                "--target" | "--target-dir" | "--features" | "-F" | "--jobs" | "-j" | "--profile"
                | "--color" | "--config" | "-Z" | "--message-format",
            ) => {
                if !matches!(tokens.get(index + 1), Some(Some(_))) {
                    out.ambiguity("dynamic-gommage-admin-command");
                    return None;
                }
                index += 2;
            }
            Some(value)
                if value.starts_with("--target=")
                    || value.starts_with("--target-dir=")
                    || value.starts_with("--features=")
                    || value.starts_with("--jobs=")
                    || value.starts_with("--profile=")
                    || value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--message-format=") =>
            {
                index += 1;
            }
            Some(
                "--release"
                | "--all-features"
                | "--no-default-features"
                | "--locked"
                | "--offline"
                | "--frozen"
                | "--ignore-rust-version"
                | "--unit-graph"
                | "--future-incompat-report"
                | "--timings"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v",
            ) => index += 1,
            Some(value) if value.starts_with('-') => {
                out.ambiguity("unknown-gommage-admin-command");
                return None;
            }
            Some(_) | None => {
                argv_start = index;
                break;
            }
        }
    }

    let dynamic_selector = [&bin, &package, &manifest]
        .into_iter()
        .flatten()
        .any(Option::is_none);
    if dynamic_selector {
        out.ambiguity("dynamic-gommage-admin-command");
    }
    let explicit_other_bin = bin
        .as_ref()
        .and_then(Option::as_deref)
        .is_some_and(|value| value != "gommage");
    let selected_gommage = !example_selected
        && !explicit_other_bin
        && (bin.as_ref().and_then(Option::as_deref) == Some("gommage")
            || package
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(is_gommage_cli_package)
            || manifest
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(is_gommage_cli_manifest));
    if selected_gommage {
        return Some(argv_start);
    }

    let has_static_selector = example_selected
        || [&bin, &package, &manifest]
            .into_iter()
            .flatten()
            .any(|selector| selector.is_some());
    if has_static_selector && !dynamic_selector {
        return None;
    }

    let possible_admin_argv = tokens[argv_start..]
        .first()
        .and_then(Option::as_deref)
        .is_some_and(is_gommage_admin_command_name);
    if dynamic_selector || possible_admin_argv {
        out.ambiguity("unknown-gommage-admin-command");
    }
    None
}

pub(super) fn cargo_run_daemon_argv_start<T: PartialEq>(
    tokens: &[Option<String>],
    out: &mut EffectSet<T>,
) -> Option<usize> {
    let may_target_daemon = tokens.iter().flatten().any(|token| {
        token == "gommage-daemon"
            || is_gommage_daemon_package(token)
            || is_gommage_daemon_manifest(token)
            || matches!(token.as_str(), "--foreground" | "--home" | "--socket")
            || token.starts_with("--home=")
            || token.starts_with("--socket=")
    });
    if may_target_daemon && tokens.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-daemon-command");
    }
    let run = cargo_run_subcommand_index(tokens)?;
    let mut bin: Option<Option<String>> = None;
    let mut package: Option<Option<String>> = None;
    let mut manifest: Option<Option<String>> = None;
    let mut example_selected = false;
    let mut argv_start = tokens.len();
    let mut index = run + 1;
    while index < tokens.len() {
        match tokens[index].as_deref() {
            Some("--") => {
                argv_start = index + 1;
                break;
            }
            Some("--bin") => {
                bin = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("-p" | "--package") => {
                package = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("--manifest-path") => {
                manifest = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some(value) if value.starts_with("--bin=") => {
                bin = Some(Some(value["--bin=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--package=") => {
                package = Some(Some(value["--package=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--manifest-path=") => {
                manifest = Some(Some(value["--manifest-path=".len()..].to_string()));
                index += 1;
            }
            Some("--example") => {
                example_selected = true;
                if !matches!(tokens.get(index + 1), Some(Some(_))) {
                    out.ambiguity("dynamic-gommage-daemon-command");
                    return None;
                }
                index += 2;
            }
            Some(value) if value.starts_with("--example=") => {
                example_selected = true;
                index += 1;
            }
            Some(
                "--target" | "--target-dir" | "--features" | "-F" | "--jobs" | "-j" | "--profile"
                | "--color" | "--config" | "-Z" | "--message-format",
            ) => {
                if !matches!(tokens.get(index + 1), Some(Some(_))) {
                    out.ambiguity("dynamic-gommage-daemon-command");
                    return None;
                }
                index += 2;
            }
            Some(value)
                if value.starts_with("--target=")
                    || value.starts_with("--target-dir=")
                    || value.starts_with("--features=")
                    || value.starts_with("--jobs=")
                    || value.starts_with("--profile=")
                    || value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--message-format=") =>
            {
                index += 1;
            }
            Some(
                "--release"
                | "--all-features"
                | "--no-default-features"
                | "--locked"
                | "--offline"
                | "--frozen"
                | "--ignore-rust-version"
                | "--unit-graph"
                | "--future-incompat-report"
                | "--timings"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v",
            ) => index += 1,
            Some(value) if value.starts_with('-') => {
                out.ambiguity("unknown-gommage-daemon-command");
                return None;
            }
            Some(_) | None => {
                argv_start = index;
                break;
            }
        }
    }

    let dynamic_selector = [&bin, &package, &manifest]
        .into_iter()
        .flatten()
        .any(Option::is_none);
    if dynamic_selector {
        out.ambiguity("dynamic-gommage-daemon-command");
    }
    let selected = !example_selected
        && (bin.as_ref().and_then(Option::as_deref) == Some("gommage-daemon")
            || package
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(is_gommage_daemon_package)
            || manifest
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(is_gommage_daemon_manifest));
    if selected { Some(argv_start) } else { None }
}

pub(super) fn cargo_run_subcommand_index(tokens: &[Option<String>]) -> Option<usize> {
    let mut index = 0;
    if tokens
        .first()
        .and_then(Option::as_deref)
        .is_some_and(|token| token.starts_with('+'))
    {
        index += 1;
    }
    while index < tokens.len() {
        match tokens[index].as_deref() {
            Some("run" | "r") => return Some(index),
            Some(
                "--verbose" | "-v" | "--quiet" | "-q" | "--frozen" | "--locked" | "--offline"
                | "--version" | "-V" | "--list" | "--help" | "-h",
            ) => index += 1,
            Some("--color" | "--config" | "-Z" | "--explain" | "-C") => index += 2,
            Some(value)
                if value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--explain=") =>
            {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn is_gommage_cli_manifest(value: &str) -> bool {
    is_gommage_manifest(value, "gommage-cli")
}

pub(super) fn is_gommage_daemon_manifest(value: &str) -> bool {
    is_gommage_manifest(value, "gommage-daemon")
}

pub(super) fn is_gommage_manifest(value: &str, crate_name: &str) -> bool {
    let mut components = Vec::new();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return false;
                }
            }
            component => components.push(component),
        }
    }
    components.ends_with(&["crates", crate_name, "Cargo.toml"])
}

pub(super) fn is_gommage_cli_package(value: &str) -> bool {
    is_gommage_package(value, "gommage-cli")
}

pub(super) fn is_gommage_daemon_package(value: &str) -> bool {
    is_gommage_package(value, "gommage-daemon")
}

pub(super) fn is_gommage_package(value: &str, package_name: &str) -> bool {
    value == package_name
        || value
            .strip_prefix(&format!("{package_name}@"))
            .is_some_and(|version| !version.is_empty())
        || value
            .strip_prefix(&format!("{package_name}:"))
            .is_some_and(|version| !version.is_empty())
        || value.split_once('#').is_some_and(|(source, fragment)| {
            source
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .is_some_and(|component| component == package_name)
                || fragment.split_once('@').map_or(fragment, |(name, _)| name) == package_name
        })
}

pub(super) fn is_gommage_admin_command_name(value: &str) -> bool {
    matches!(
        value,
        "grant"
            | "g"
            | "confirm"
            | "revoke"
            | "approval"
            | "tui"
            | "init"
            | "quickstart"
            | "upgrade"
            | "policy"
            | "project"
            | "agent"
            | "repair"
            | "daemon"
            | "expedition"
            | "uninstall"
            | "state"
            | "harness"
    )
}
