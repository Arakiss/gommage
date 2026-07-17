use super::*;

pub(super) fn unwrap_words(words: &[ShellWord], analysis: &mut ShellAnalysis) -> Vec<ShellWord> {
    let mut current = words.to_vec();
    for _ in 0..MAX_NESTING_DEPTH {
        let Some(head) = current.first() else {
            return current;
        };
        let Ok(executable) = head.static_value() else {
            return current;
        };
        let basename = head_basename(executable);
        if privileged_executable_name(basename) && trusted_executable_basename(executable).is_err()
        {
            analysis.ambiguity("untrusted-executable-path");
            return current;
        }
        let head = trusted_executable_basename(executable).unwrap_or(basename);
        let step = match head {
            "builtin" => unwrap_builtin(&current),
            "command" => unwrap_command(&current),
            "exec" => unwrap_exec(&current),
            "env" => unwrap_env(&current),
            "sudo" => unwrap_sudo(&current),
            "doas" => unwrap_doas(&current),
            "timeout" => unwrap_timeout(&current),
            "time" => unwrap_time(&current),
            "nice" => unwrap_nice(&current),
            "nohup" => unwrap_nohup(&current),
            "noglob" => UnwrapStep::At(1),
            "stdbuf" => unwrap_stdbuf(&current),
            "setsid" => unwrap_setsid(&current),
            _ => return current,
        };
        match step {
            UnwrapStep::At(index) if index < current.len() => current = current[index..].to_vec(),
            UnwrapStep::AtWithAmbiguity(index, reason) if index < current.len() => {
                analysis.ambiguity(reason);
                current = current[index..].to_vec();
            }
            UnwrapStep::Stop => return current,
            UnwrapStep::Ambiguous(reason) => {
                analysis.ambiguity(reason);
                return current;
            }
            UnwrapStep::At(_) => {
                analysis.ambiguity("wrapper-missing-command");
                return current;
            }
            UnwrapStep::AtWithAmbiguity(_, reason) => {
                analysis.ambiguity(reason);
                analysis.ambiguity("wrapper-missing-command");
                return current;
            }
        }
    }
    analysis.ambiguity("wrapper-depth");
    current
}

pub(super) fn unwrap_builtin(words: &[ShellWord]) -> UnwrapStep {
    let mut index = 1;
    if words.get(index).and_then(|word| word.static_value().ok()) == Some("--") {
        index += 1;
    }
    let Some(command) = words.get(index) else {
        return UnwrapStep::Stop;
    };
    match command.static_value() {
        Ok(value) if value.starts_with('-') => UnwrapStep::Stop,
        Ok(_) => UnwrapStep::At(index),
        Err(_) => UnwrapStep::Ambiguous("dynamic-builtin-command"),
    }
}

pub(super) enum UnwrapStep {
    At(usize),
    AtWithAmbiguity(usize, Ambiguity),
    Stop,
    Ambiguous(Ambiguity),
}

pub(super) fn static_word(words: &[ShellWord], index: usize) -> Result<&str, Ambiguity> {
    words
        .get(index)
        .ok_or("wrapper-missing-value")?
        .static_value()
}

pub(super) fn unwrap_command(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-v" | "-V" => return UnwrapStep::Stop,
            "-p" => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-command-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

pub(super) fn unwrap_exec(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-a" => {
                if static_word(words, i + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                i += 2;
            }
            "-c" | "-l" => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-exec-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

pub(super) fn unwrap_env(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    let mut mutates_environment = false;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        if arg == "--" {
            return if mutates_environment {
                UnwrapStep::AtWithAmbiguity(i + 1, "wrapper-environment-mutation")
            } else {
                UnwrapStep::At(i + 1)
            };
        }
        if is_assignment(arg) {
            mutates_environment = true;
            i += 1;
            continue;
        }
        match arg {
            "-i" | "--ignore-environment" => {
                mutates_environment = true;
                i += 1;
            }
            "-u" | "--unset" => {
                mutates_environment = true;
                if static_word(words, i + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                i += 2;
            }
            "-0" | "--null" => i += 1,
            "-C" | "--chdir" => return UnwrapStep::Ambiguous("wrapper-changes-cwd"),
            "-S" | "--split-string" => return UnwrapStep::Ambiguous("env-split-string"),
            arg if arg.starts_with("--unset=") => {
                mutates_environment = true;
                i += 1;
            }
            arg if arg.starts_with("--chdir=") => {
                return UnwrapStep::Ambiguous("wrapper-changes-cwd");
            }
            arg if arg.starts_with("--split-string=") => {
                return UnwrapStep::Ambiguous("env-split-string");
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-env-option"),
            _ => {
                return if mutates_environment {
                    UnwrapStep::AtWithAmbiguity(i, "wrapper-environment-mutation")
                } else {
                    UnwrapStep::At(i)
                };
            }
        }
    }
    if mutates_environment {
        UnwrapStep::Ambiguous("wrapper-environment-mutation")
    } else {
        UnwrapStep::Stop
    }
}

pub(super) fn unwrap_sudo(words: &[ShellWord]) -> UnwrapStep {
    let mut index = 1;
    let mut parsing_options = true;
    let mut mutates_environment = false;
    let mut changes_execution_context = false;

    while index < words.len() {
        let Ok(argument) = static_word(words, index) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };

        if parsing_options {
            if argument == "--" {
                parsing_options = false;
                index += 1;
                continue;
            }

            if is_sudo_assignment(argument) {
                parsing_options = false;
                mutates_environment = true;
                index += 1;
                continue;
            }

            match argument {
                // These options deterministically consume one value, but also
                // change the identity, host, cwd, or filesystem namespace in
                // which sudo resolves the nested executable.
                "-u" | "--user" | "-g" | "--group" | "-h" | "--host" | "-R" | "--chroot" | "-D"
                | "--chdir" => {
                    if words
                        .get(index + 1)
                        .and_then(|word| word.static_value().ok())
                        .is_none()
                    {
                        return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                    }
                    changes_execution_context = true;
                    index += 2;
                }
                // These value-taking options do not change command lookup,
                // but their values must still be static: an unquoted dynamic
                // value can expand into additional argv entries.
                "-p" | "--prompt" | "-C" | "--close-from" | "-T" | "--command-timeout" => {
                    if words
                        .get(index + 1)
                        .and_then(|word| word.static_value().ok())
                        .is_none()
                    {
                        return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                    }
                    index += 2;
                }
                // Environment- and shell-selecting modes are not transparent
                // wrappers even though their command position is stable.
                "-E" | "--preserve-env" | "-H" | "--set-home" => {
                    mutates_environment = true;
                    index += 1;
                }
                "-i" | "--login" | "-s" | "--shell" | "-P" | "--preserve-groups" => {
                    changes_execution_context = true;
                    index += 1;
                }
                // These switches do not alter nested command lookup.
                "-A" | "--askpass" | "-b" | "--background" | "-B" | "--bell" | "-K"
                | "--remove-timestamp" | "-k" | "--reset-timestamp" | "-N" | "--no-update"
                | "-n" | "--non-interactive" | "-S" | "--stdin" => {
                    index += 1;
                }
                // These sudo modes do not transparently execute the remaining
                // argv as the command being classified.
                "-e" | "--edit" | "-l" | "--list" | "-v" | "--validate" | "-V" | "--version"
                | "--help" => {
                    return UnwrapStep::Ambiguous("unsupported-sudo-mode");
                }
                _ if argument.starts_with("--preserve-env=") => {
                    mutates_environment = true;
                    index += 1;
                }
                _ if ["--user=", "--group=", "--host=", "--chroot=", "--chdir="]
                    .iter()
                    .any(|prefix| argument.starts_with(prefix)) =>
                {
                    changes_execution_context = true;
                    index += 1;
                }
                _ if ["--prompt=", "--close-from=", "--command-timeout="]
                    .iter()
                    .any(|prefix| argument.starts_with(prefix)) =>
                {
                    index += 1;
                }
                _ if argument.starts_with('-') => {
                    return UnwrapStep::Ambiguous("unknown-sudo-option");
                }
                _ => return sudo_unwrap_at(index, mutates_environment, changes_execution_context),
            }
        } else if is_sudo_assignment(argument) {
            mutates_environment = true;
            index += 1;
        } else {
            return sudo_unwrap_at(index, mutates_environment, changes_execution_context);
        }
    }

    if mutates_environment {
        UnwrapStep::Ambiguous("wrapper-environment-mutation")
    } else if changes_execution_context {
        UnwrapStep::Ambiguous("wrapper-execution-context-mutation")
    } else {
        UnwrapStep::Stop
    }
}

pub(super) fn sudo_unwrap_at(
    index: usize,
    mutates_environment: bool,
    changes_execution_context: bool,
) -> UnwrapStep {
    if mutates_environment {
        UnwrapStep::AtWithAmbiguity(index, "wrapper-environment-mutation")
    } else if changes_execution_context {
        UnwrapStep::AtWithAmbiguity(index, "wrapper-execution-context-mutation")
    } else {
        UnwrapStep::At(index)
    }
}

pub(super) fn is_sudo_assignment(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(name, _)| !name.is_empty() && !name.starts_with('-'))
}

pub(super) fn unwrap_doas(words: &[ShellWord]) -> UnwrapStep {
    let mut index = 1;
    let mut changes_execution_context = false;
    while index < words.len() {
        let Ok(argument) = static_word(words, index) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match argument {
            "--" => {
                return if changes_execution_context {
                    UnwrapStep::AtWithAmbiguity(index + 1, "wrapper-execution-context-mutation")
                } else {
                    UnwrapStep::At(index + 1)
                };
            }
            "-u" => {
                if static_word(words, index + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                changes_execution_context = true;
                index += 2;
            }
            "-a" | "-C" => {
                if static_word(words, index + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                index += 2;
            }
            "-L" | "-n" => index += 1,
            argument if argument.starts_with('-') => {
                return UnwrapStep::Ambiguous("unknown-doas-option");
            }
            _ => {
                return if changes_execution_context {
                    UnwrapStep::AtWithAmbiguity(index, "wrapper-execution-context-mutation")
                } else {
                    UnwrapStep::At(index)
                };
            }
        }
    }
    if changes_execution_context {
        UnwrapStep::Ambiguous("wrapper-execution-context-mutation")
    } else {
        UnwrapStep::Stop
    }
}

pub(super) fn unwrap_timeout(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => {
                i += 1;
                break;
            }
            "-s" | "--signal" | "-k" | "--kill-after" => {
                if static_word(words, i + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                i += 2;
            }
            "--preserve-status" | "--foreground" | "-v" | "--verbose" => i += 1,
            arg if arg.starts_with("--signal=") || arg.starts_with("--kill-after=") => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-timeout-option"),
            _ => break,
        }
    }
    if i >= words.len() {
        return UnwrapStep::Stop;
    }
    if static_word(words, i).is_err() {
        return UnwrapStep::Ambiguous("dynamic-wrapper-option");
    }
    i += 1; // duration
    UnwrapStep::At(i)
}

pub(super) fn unwrap_time(words: &[ShellWord]) -> UnwrapStep {
    if words.iter().skip(1).any(|word| {
        word.static_value().is_ok_and(|value| {
            matches!(value, "-o" | "--output")
                || value.starts_with("--output=")
                || (value.starts_with("-o") && value.len() > 2)
        })
    }) {
        return UnwrapStep::Ambiguous("time-output-file");
    }
    unwrap_flag_wrapper(
        words,
        &["-f", "--format"],
        &["-a", "--append", "-p", "--portability", "-v", "--verbose"],
        "unknown-time-option",
    )
}

pub(super) fn unwrap_nice(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-n" | "--adjustment" => {
                if static_word(words, i + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                i += 2;
            }
            arg if arg.starts_with("--adjustment=") => i += 1,
            arg if arg.len() > 1
                && arg.starts_with('-')
                && arg[1..].chars().all(|ch| ch.is_ascii_digit()) =>
            {
                i += 1
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-nice-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

pub(super) fn unwrap_nohup(words: &[ShellWord]) -> UnwrapStep {
    if words.get(1).is_some_and(|word| word.raw == "--") {
        UnwrapStep::At(2)
    } else {
        UnwrapStep::At(1)
    }
}

pub(super) fn unwrap_stdbuf(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-i" | "-o" | "-e" | "--input" | "--output" | "--error" => {
                if static_word(words, i + 1).is_err() {
                    return UnwrapStep::Ambiguous("dynamic-wrapper-option");
                }
                i += 2;
            }
            arg if arg.starts_with("-i")
                || arg.starts_with("-o")
                || arg.starts_with("-e")
                || arg.starts_with("--input=")
                || arg.starts_with("--output=")
                || arg.starts_with("--error=") =>
            {
                i += 1
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-stdbuf-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

pub(super) fn unwrap_setsid(words: &[ShellWord]) -> UnwrapStep {
    unwrap_flag_wrapper(
        words,
        &[],
        &["-c", "--ctty", "-f", "--fork", "-w", "--wait"],
        "unknown-setsid-option",
    )
}

pub(super) fn unwrap_flag_wrapper(
    words: &[ShellWord],
    value_options: &[&str],
    boolean_options: &[&str],
    unknown: Ambiguity,
) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        if arg == "--" {
            return UnwrapStep::At(i + 1);
        }
        if value_options.contains(&arg) {
            if static_word(words, i + 1).is_err() {
                return UnwrapStep::Ambiguous("dynamic-wrapper-option");
            }
            i += 2;
        } else if boolean_options.contains(&arg)
            || value_options
                .iter()
                .any(|option| option.starts_with("--") && arg.starts_with(&format!("{option}=")))
        {
            i += 1;
        } else if arg.starts_with('-') {
            return UnwrapStep::Ambiguous(unknown);
        } else {
            return UnwrapStep::At(i);
        }
    }
    UnwrapStep::Stop
}

pub(super) fn shell_c_payload(words: &[ShellWord]) -> Option<Result<String, Ambiguity>> {
    let head = words
        .first()?
        .static_value()
        .ok()
        .and_then(|value| trusted_executable_basename(value).ok())?;
    if !matches!(head, "bash" | "sh" | "zsh") {
        return None;
    }
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = words[i].static_value() else {
            return Some(Err("dynamic-shell-option"));
        };
        if arg == "-c" {
            return Some(
                words
                    .get(i + 1)
                    .ok_or("missing-shell-payload")
                    .and_then(|word| word.static_value().map(str::to_string)),
            );
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c') {
            if arg[1..].contains(['i', 'l']) {
                return Some(Err("shell-startup-mode"));
            }
            return Some(
                words
                    .get(i + 1)
                    .ok_or("missing-shell-payload")
                    .and_then(|word| word.static_value().map(str::to_string)),
            );
        }
        match arg {
            "--" => return None,
            "--init-file" | "--rcfile" => return Some(Err("shell-startup-file")),
            "-O" | "-o" => {
                let Some(value) = words.get(i + 1) else {
                    return Some(Err("missing-shell-option-value"));
                };
                if value.static_value().is_err() {
                    return Some(Err("dynamic-shell-option"));
                }
                i += 2;
                continue;
            }
            "--login" => return Some(Err("shell-startup-mode")),
            "--noprofile" | "--norc" | "--posix" | "--restricted" | "--verbose" | "--noediting" => {
                i += 1;
                continue;
            }
            _ if arg.starts_with("-O") || arg.starts_with("-o") => {
                i += 1;
                continue;
            }
            _ if arg.starts_with("--init-file=") || arg.starts_with("--rcfile=") => {
                return Some(Err("shell-startup-file"));
            }
            _ if arg.starts_with('-') => return Some(Err("unknown-shell-option")),
            _ => return None,
        }
    }
    None
}
