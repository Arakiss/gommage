use super::*;

/// Derive package installation and registry-publication effects from parsed
/// argv. Regex mappers cannot distinguish `cargo publish` from
/// `cargo publish --help`, and therefore cannot be the authority for these
/// operations.
pub(crate) fn package_manager_effects(analysis: &ShellAnalysis) -> EffectSet<PackageManagerEffect> {
    let mut out = EffectSet::default();
    for command in &analysis.commands {
        collect_package_manager_effect(command, &mut out);
    }
    out
}

pub(super) fn collect_package_manager_effect(
    command: &ShellCommand,
    out: &mut EffectSet<PackageManagerEffect>,
) {
    if publish_script_executes(command) {
        out.push(PackageManagerEffect::CargoPublish);
        return;
    }

    let Some(executable) = command.effective_words.first() else {
        return;
    };
    let Ok(executable) = executable.static_value() else {
        return;
    };
    let Ok(head) = trusted_executable_basename(executable) else {
        return;
    };
    let args = command.effective_args();

    match head {
        "cargo" => collect_cargo_effect(args, out),
        "bun" => collect_bun_effect(args, out),
        "npm" => collect_npm_effect(args, out),
        "twine" => {
            if static_package_word(args, 0) == Some("upload")
                && !selected_command_requests_info(args, 1)
            {
                out.push(PackageManagerEffect::PythonPublish);
            }
        }
        head if head == "pip" || pip_versioned_name(head) => {
            if static_package_word(args, 0) == Some("upload")
                && !selected_command_requests_info(args, 1)
            {
                out.push(PackageManagerEffect::PythonPublish);
            }
        }
        head if python_executable_name(head)
            && static_package_word(args, 0) == Some("-m")
            && static_package_word(args, 1) == Some("twine")
            && static_package_word(args, 2) == Some("upload")
            && !selected_command_requests_info(args, 3) =>
        {
            out.push(PackageManagerEffect::PythonPublish);
        }
        _ => {}
    }
}

pub(super) fn collect_cargo_effect(args: &[ShellWord], out: &mut EffectSet<PackageManagerEffect>) {
    let Some((command_index, command)) = cargo_subcommand(args, out) else {
        return;
    };
    let informational = selected_command_requests_info(args, command_index + 1);
    match command {
        "install" if !informational => out.push(PackageManagerEffect::CargoInstall),
        "publish" if !informational => out.push(PackageManagerEffect::CargoPublish),
        _ => {}
    }
}

pub(super) fn cargo_subcommand<'a>(
    args: &'a [ShellWord],
    out: &mut EffectSet<PackageManagerEffect>,
) -> Option<(usize, &'a str)> {
    let mut index = 0;
    if static_package_word(args, index).is_some_and(|value| value.starts_with('+')) {
        index += 1;
    }

    while index < args.len() {
        let Ok(argument) = args[index].static_value() else {
            out.ambiguity("dynamic-package-manager-command");
            return None;
        };
        match argument {
            "-h" | "--help" | "-V" | "--version" | "--list" => return None,
            "-v" | "-vv" | "-vvv" | "--verbose" | "-q" | "--quiet" | "--locked" | "--offline"
            | "--frozen" => index += 1,
            "--color" | "--config" | "--explain" | "-C" | "-Z" => {
                let Some(value) = args.get(index + 1) else {
                    out.ambiguity("missing-package-manager-option-value");
                    return None;
                };
                if value.static_value().is_err() {
                    out.ambiguity("dynamic-package-manager-option-value");
                    return None;
                }
                index += 2;
            }
            value
                if value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--explain=")
                    || (value.starts_with("-C") && value.len() > 2)
                    || (value.starts_with("-Z") && value.len() > 2) =>
            {
                index += 1;
            }
            "--" => {
                index += 1;
                let command = args.get(index)?;
                let Ok(command) = command.static_value() else {
                    out.ambiguity("dynamic-package-manager-command");
                    return None;
                };
                return Some((index, command));
            }
            value if value.starts_with('-') => {
                out.ambiguity("unknown-package-manager-global-option");
                return None;
            }
            value => return Some((index, value)),
        }
    }
    None
}

pub(super) fn collect_bun_effect(args: &[ShellWord], out: &mut EffectSet<PackageManagerEffect>) {
    let Some(command) = static_package_subcommand(args, out) else {
        return;
    };
    if selected_command_requests_info(args, 1) {
        return;
    }
    match command {
        "install" | "i" | "add" | "a" | "remove" | "rm" => {
            out.push(PackageManagerEffect::BunInstall);
        }
        "publish" => out.push(PackageManagerEffect::BunPublish),
        _ => {}
    }
}

pub(super) fn collect_npm_effect(args: &[ShellWord], out: &mut EffectSet<PackageManagerEffect>) {
    let Some(command) = static_package_subcommand(args, out) else {
        return;
    };
    if selected_command_requests_info(args, 1) {
        return;
    }
    match command {
        "install" | "i" | "add" | "remove" | "uninstall" => {
            out.push(PackageManagerEffect::NpmInstall);
        }
        "publish" => out.push(PackageManagerEffect::NpmPublish),
        _ => {}
    }
}

pub(super) fn static_package_subcommand<'a>(
    args: &'a [ShellWord],
    out: &mut EffectSet<PackageManagerEffect>,
) -> Option<&'a str> {
    let command = args.first()?;
    match command.static_value() {
        Ok("-h" | "--help" | "-V" | "--version") => None,
        Ok(value) if value.starts_with('-') => {
            out.ambiguity("unknown-package-manager-global-option");
            None
        }
        Ok(value) => Some(value),
        Err(_) => {
            out.ambiguity("dynamic-package-manager-command");
            None
        }
    }
}

pub(super) fn selected_command_requests_info(args: &[ShellWord], start: usize) -> bool {
    args.get(start..).is_some_and(|tail| {
        tail.iter().any(|word| {
            word.static_value()
                .is_ok_and(|value| matches!(value, "-h" | "--help" | "-V" | "--version"))
        })
    })
}

pub(super) fn static_package_word(words: &[ShellWord], index: usize) -> Option<&str> {
    words.get(index)?.static_value().ok()
}

pub(super) fn pip_versioned_name(name: &str) -> bool {
    name.strip_prefix("pip").is_some_and(|version| {
        !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
    })
}

pub(super) fn python_executable_name(name: &str) -> bool {
    name == "python"
        || name.strip_prefix("python").is_some_and(|version| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
}

pub(super) fn publish_script_executes(command: &ShellCommand) -> bool {
    let words = &command.effective_words;
    let Some(first) = static_package_word(words, 0) else {
        return false;
    };
    let argument_start = if publish_script_path(first) {
        1
    } else if matches!(trusted_executable_basename(first), Ok("sh" | "bash"))
        && static_package_word(words, 1).is_some_and(publish_script_path)
    {
        2
    } else {
        return false;
    };
    let Some(arguments) = words.get(argument_start..) else {
        return false;
    };
    let help = arguments.iter().any(|word| {
        word.static_value()
            .is_ok_and(|value| matches!(value, "-h" | "--help"))
    });
    let execute = arguments
        .iter()
        .any(|word| word.static_value().is_ok_and(|value| value == "--execute"));
    execute && !help
}

pub(super) fn publish_script_path(value: &str) -> bool {
    matches!(
        value,
        "scripts/publish-crates.sh" | "./scripts/publish-crates.sh"
    )
}
