use super::*;

pub(super) fn collect_read_operands(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands(command, args) {
        Ok((operands, _)) => {
            for operand in operands {
                if operand.value.as_deref() != Some("-") {
                    add_path_effect(operand, cwd, FsEffectKind::Read, out);
                }
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn collect_copy_effects(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if command == "install"
        && args.iter().any(|arg| {
            arg.static_value()
                .is_ok_and(|arg| matches!(arg, "-d" | "--directory"))
        })
    {
        collect_all_operands("install", args, cwd, FsEffectKind::Write, out);
        return;
    }
    match parse_operands(command, args) {
        Ok((operands, target_directory)) => {
            if let Some(target) = target_directory {
                for source in operands {
                    add_path_effect(source, cwd, FsEffectKind::Read, out);
                }
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if let Some((destination, sources)) = operands.split_last() {
                if sources.is_empty() {
                    out.ambiguity("missing-copy-source");
                }
                for source in sources {
                    add_path_effect(source, cwd, FsEffectKind::Read, out);
                }
                add_path_effect(destination, cwd, FsEffectKind::Write, out);
            } else {
                out.ambiguity("missing-copy-operands");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn collect_move_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands("mv", args) {
        Ok((operands, target_directory)) => {
            for operand in &operands {
                add_path_effect(operand, cwd, FsEffectKind::Write, out);
            }
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if operands.len() < 2 {
                out.ambiguity("missing-move-operands");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn collect_all_operands(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands(command, args) {
        Ok((operands, target_directory)) => {
            for operand in operands {
                add_path_effect(operand, cwd, kind, out);
            }
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, kind, out);
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn collect_rsync_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let remove_sources = args.iter().any(|arg| {
        arg.static_value()
            .is_ok_and(|arg| arg == "--remove-source-files")
    });
    let Ok((operands, _)) = parse_operands("rsync", args) else {
        out.ambiguity("rsync-options");
        return;
    };
    let Some((destination, sources)) = operands.split_last() else {
        out.ambiguity("missing-rsync-operands");
        return;
    };
    for source in sources {
        match source.static_value() {
            Ok(value) if is_remote_endpoint(value) => {}
            Ok(_) => {
                add_path_effect(source, cwd, FsEffectKind::Read, out);
                if remove_sources {
                    add_path_effect(source, cwd, FsEffectKind::Write, out);
                }
            }
            Err(reason) => out.ambiguity(reason),
        }
    }
    match destination.static_value() {
        Ok(value) if is_remote_endpoint(value) => {}
        Ok(_) => add_path_effect(destination, cwd, FsEffectKind::Write, out),
        Err(reason) => out.ambiguity(reason),
    }
}

pub(crate) fn has_static_remote_rsync(analysis: &ShellAnalysis) -> bool {
    analysis.commands.iter().any(|command| {
        command.trusted_effective_head() == Ok("rsync")
            && parse_operands("rsync", command.effective_args()).is_ok_and(|(operands, _)| {
                operands
                    .iter()
                    .any(|operand| operand.static_value().is_ok_and(is_remote_endpoint))
            })
    })
}

pub(super) fn is_remote_endpoint(value: &str) -> bool {
    value.starts_with("rsync://")
        || value
            .split_once(':')
            .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'))
}

pub(super) fn collect_ln_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands("ln", args) {
        Ok((operands, target_directory)) => {
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if operands.len() >= 2 {
                if let Some(destination) = operands.last() {
                    add_path_effect(destination, cwd, FsEffectKind::Write, out);
                }
            } else {
                out.ambiguity("implicit-link-destination");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn collect_sed_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let mut i = 0;
    let mut in_place = false;
    let mut script_seen = false;
    let mut files = Vec::new();
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-sed-operand");
            return;
        };
        if arg == "--" {
            i += 1;
            break;
        }
        if arg == "-i"
            || arg == "--in-place"
            || (arg.starts_with("-i") && arg.len() > 2)
            || arg.starts_with("--in-place=")
        {
            in_place = true;
            i += 1;
            // BSD sed requires a separate extension after `-i`; the empty
            // spelling is unambiguous and is also harmless under GNU sed.
            if arg == "-i"
                && args
                    .get(i)
                    .and_then(|word| word.static_value().ok())
                    .is_some_and(str::is_empty)
            {
                i += 1;
            }
            continue;
        }
        if arg == "-I" {
            in_place = true;
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            i += 2;
            continue;
        }
        if matches!(arg, "-e" | "--expression") {
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            script_seen = true;
            i += 2;
            continue;
        }
        if (arg.starts_with("-e") && arg.len() > 2) || arg.starts_with("--expression=") {
            script_seen = true;
            i += 1;
            continue;
        }
        if matches!(arg, "-f" | "--file") {
            let Some(script) = args.get(i + 1) else {
                out.ambiguity("missing-option-value");
                return;
            };
            add_path_effect(script, cwd, FsEffectKind::Read, out);
            script_seen = true;
            i += 2;
            continue;
        }
        if let Some(script) = arg
            .strip_prefix("--file=")
            .or_else(|| arg.strip_prefix("-f").filter(|_| arg.len() > 2))
        {
            add_synthetic_path(script, cwd, FsEffectKind::Read, out);
            script_seen = true;
            i += 1;
            continue;
        }
        if matches!(arg, "-l" | "--line-length") {
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            i += 2;
            continue;
        }
        if arg.starts_with("--line-length=")
            || matches!(
                arg,
                "-n" | "--quiet"
                    | "--silent"
                    | "-E"
                    | "-r"
                    | "--regexp-extended"
                    | "-s"
                    | "--separate"
                    | "-u"
                    | "--unbuffered"
                    | "-z"
                    | "--null-data"
                    | "-a"
                    | "-b"
                    | "--sandbox"
                    | "--debug"
                    | "--posix"
                    | "--help"
                    | "--version"
            )
        {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            out.ambiguity("unknown-sed-option");
            return;
        }
        if !script_seen {
            script_seen = true;
        } else {
            files.push(&args[i]);
        }
        i += 1;
    }
    for arg in &args[i..] {
        if script_seen {
            files.push(arg);
        } else {
            script_seen = true;
        }
    }
    if in_place {
        if files.is_empty() {
            out.ambiguity("missing-sed-target");
        }
        for file in files {
            add_path_effect(file, cwd, FsEffectKind::Write, out);
        }
    }
}

pub(super) fn collect_dd_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    for arg in args {
        match arg.static_value() {
            Ok(value) => {
                if let Some(path) = value.strip_prefix("if=") {
                    add_synthetic_path(path, cwd, FsEffectKind::Read, out);
                } else if let Some(path) = value.strip_prefix("of=") {
                    add_synthetic_path(path, cwd, FsEffectKind::Write, out);
                }
            }
            Err(reason) => out.ambiguity(reason),
        }
    }
}

pub(super) fn add_synthetic_path(
    path: &str,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    let word = ShellWord {
        raw: path.to_string(),
        value: Some(path.to_string()),
        provenance: WordProvenance::default(),
        ambiguity: None,
    };
    add_path_effect(&word, cwd, kind, out);
}
