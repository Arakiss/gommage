use super::*;

pub(super) fn trusted_cwd(cwd: Option<&str>) -> Option<String> {
    let cwd = cwd?;
    if !cwd.starts_with('/') || cwd.split('/').any(|part| part == "..") {
        return None;
    }
    normalize_lexical(cwd, false).ok()
}

pub(crate) fn static_path(word: &ShellWord, cwd: Option<&str>) -> Result<String, Ambiguity> {
    let raw = word.static_value()?;
    let mut path = raw.to_string();
    let literal_home_alias = !word.provenance.home_alias
        && (matches!(path.as_str(), "$HOME" | "${HOME}" | "~")
            || path.starts_with("$HOME/")
            || path.starts_with("${HOME}/")
            || path.starts_with("~/"));

    let absolute_or_home = path.starts_with('/') || path == "$HOME" || path.starts_with("$HOME/");
    if (!absolute_or_home || literal_home_alias)
        && let Some(cwd) = cwd
    {
        path = format!("{cwd}/{path}");
    }
    if path.split('/').any(|part| part == "..") {
        return Err("parent-component");
    }
    let normalized = normalize_lexical(&path, word.provenance.home_alias)?;
    if literal_home_alias && cwd.is_none() {
        Ok(format!("./{normalized}"))
    } else {
        Ok(normalized)
    }
}

pub(super) fn normalize_lexical(path: &str, home_alias: bool) -> Result<String, Ambiguity> {
    let (prefix, rest) = if home_alias && path == "$HOME" {
        ("$HOME", "")
    } else if home_alias {
        path.strip_prefix("$HOME/")
            .map_or(("", path), |rest| ("$HOME", rest))
    } else if let Some(rest) = path.strip_prefix('/') {
        ("/", rest)
    } else {
        ("", path)
    };

    let mut components = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." if components.last().is_some_and(|previous| *previous != "..") => {
                components.pop();
            }
            ".." if prefix.is_empty() => components.push(component),
            ".." => {}
            _ => components.push(component),
        }
    }
    let joined = components.join("/");
    match prefix {
        "/" if joined.is_empty() => Ok("/".to_string()),
        "/" => Ok(format!("/{joined}")),
        "$HOME" if joined.is_empty() => Ok("$HOME".to_string()),
        "$HOME" => Ok(format!("$HOME/{joined}")),
        _ if joined.is_empty() => Ok(".".to_string()),
        _ => Ok(joined),
    }
}

pub(super) fn add_path_effect(
    word: &ShellWord,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    match static_path(word, cwd) {
        Ok(path) => out.push(FsEffect { kind, path }),
        Err(reason) => out.ambiguity(reason),
    }
}

pub(super) fn parse_operands<'a>(
    command: &str,
    args: &'a [ShellWord],
) -> Result<(Vec<&'a ShellWord>, Option<ShellWord>), Ambiguity> {
    let mut operands = Vec::new();
    let mut target_directory = None;
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let value = args[i].static_value()?;
        if options && value == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options && value.starts_with('-') && value != "-" {
            if option_takes_value(command, value) {
                let option = value;
                let Some(next) = args.get(i + 1) else {
                    return Err("missing-option-value");
                };
                if matches!(option, "-t" | "--target-directory") {
                    target_directory = Some(next.clone());
                }
                i += 2;
                continue;
            }
            if let Some(value) = value.strip_prefix("--target-directory=") {
                if value.is_empty() {
                    return Err("missing-option-value");
                }
                target_directory = Some(ShellWord {
                    raw: value.to_string(),
                    value: Some(value.to_string()),
                    provenance: WordProvenance::default(),
                    ambiguity: None,
                });
                i += 1;
                continue;
            }
            if matches!(command, "cp" | "mv" | "install" | "ln")
                && value.starts_with("-t")
                && value.len() > 2
            {
                let target = &value[2..];
                target_directory = Some(ShellWord {
                    raw: target.to_string(),
                    value: Some(target.to_string()),
                    provenance: WordProvenance::default(),
                    ambiguity: None,
                });
                i += 1;
                continue;
            }
            if option_has_attached_value(command, value)
                || known_boolean_option(command, value)
                || is_known_short_option_cluster(command, value)
            {
                i += 1;
                continue;
            }
            return Err("unknown-command-option");
        }
        operands.push(&args[i]);
        i += 1;
    }
    Ok((operands, target_directory))
}

pub(super) fn option_takes_value(command: &str, option: &str) -> bool {
    match command {
        "cat" => false,
        "head" => matches!(option, "-n" | "--lines" | "-c" | "--bytes"),
        "tail" => matches!(
            option,
            "-n" | "--lines"
                | "-c"
                | "--bytes"
                | "--pid"
                | "-s"
                | "--sleep-interval"
                | "--max-unchanged-stats"
        ),
        "less" => matches!(
            option,
            "-D" | "-j" | "-k" | "-P" | "-t" | "-T" | "-x" | "-y" | "-z"
        ),
        "od" => matches!(
            option,
            "-A" | "--address-radix"
                | "-j"
                | "--skip-bytes"
                | "-N"
                | "--read-bytes"
                | "-t"
                | "--format"
                | "-w"
                | "--width"
                | "--endian"
        ),
        "xxd" => matches!(
            option,
            "-c" | "-cols" | "-g" | "-groupsize" | "-l" | "-len" | "-o" | "-seek" | "-s" | "-name"
        ),
        "base64" => matches!(option, "-w" | "--wrap"),
        "strings" => matches!(
            option,
            "-e" | "--encoding"
                | "-n"
                | "--bytes"
                | "-o"
                | "-t"
                | "--radix"
                | "-T"
                | "--target"
                | "-U"
                | "--unicode"
                | "--output-separator"
        ),
        "file" => matches!(
            option,
            "-e" | "--exclude"
                | "-f"
                | "--files-from"
                | "-m"
                | "--magic-file"
                | "-P"
                | "--parameter"
        ),
        "cp" | "mv" | "ln" => matches!(option, "-S" | "--suffix" | "-t" | "--target-directory"),
        "install" => matches!(
            option,
            "-g" | "--group"
                | "-m"
                | "--mode"
                | "-o"
                | "--owner"
                | "-S"
                | "--suffix"
                | "-t"
                | "--target-directory"
                | "--strip-program"
        ),
        "rsync" => matches!(
            option,
            "-e" | "--rsh"
                | "--exclude"
                | "--exclude-from"
                | "--include"
                | "--include-from"
                | "--filter"
                | "-f"
                | "--files-from"
                | "--rsync-path"
                | "--port"
                | "--password-file"
                | "--timeout"
                | "--contimeout"
                | "--max-size"
                | "--min-size"
                | "--bwlimit"
                | "--block-size"
                | "-B"
                | "--out-format"
                | "--log-file"
                | "--log-file-format"
                | "--remote-option"
                | "-M"
        ),
        "touch" => matches!(
            option,
            "-d" | "--date" | "-r" | "--reference" | "-t" | "--time"
        ),
        "mkdir" => matches!(option, "-m" | "--mode"),
        "rm" | "tee" => false,
        _ => false,
    }
}

pub(super) fn option_has_attached_value(command: &str, option: &str) -> bool {
    if let Some((name, value)) = option.split_once('=') {
        return !value.is_empty()
            && (option_takes_value(command, name) || optional_value_option(command, name));
    }

    let Some(short) = option
        .strip_prefix('-')
        .filter(|value| !value.starts_with('-'))
    else {
        return false;
    };
    let mut chars = short.chars();
    let Some(flag) = chars.next() else {
        return false;
    };
    if chars.as_str().is_empty() {
        return false;
    }
    let name = format!("-{flag}");
    option_takes_value(command, &name)
        || matches!((command, flag), ("mkdir", 'Z') | ("cp" | "mv" | "ln", 'b'))
}

pub(super) fn optional_value_option(command: &str, option: &str) -> bool {
    matches!(
        (command, option),
        ("cp" | "mv" | "ln", "--backup" | "--context")
            | ("install", "--backup" | "--context")
            | ("mkdir", "--context")
            | ("tail", "--follow")
    )
}

pub(super) fn known_boolean_option(command: &str, option: &str) -> bool {
    match command {
        "cat" => matches!(
            option,
            "--show-all"
                | "--number-nonblank"
                | "--show-ends"
                | "--number"
                | "--squeeze-blank"
                | "--show-tabs"
                | "--help"
                | "--version"
        ),
        "head" => matches!(
            option,
            "--quiet"
                | "--silent"
                | "--verbose"
                | "-z"
                | "--zero-terminated"
                | "--help"
                | "--version"
        ),
        "tail" => matches!(
            option,
            "-f" | "--follow"
                | "-F"
                | "--retry"
                | "--quiet"
                | "--silent"
                | "--verbose"
                | "-z"
                | "--zero-terminated"
                | "--help"
                | "--version"
        ),
        "less" => matches!(
            option,
            "--help"
                | "--version"
                | "--quit-at-eof"
                | "--QUIT-AT-EOF"
                | "--quit-if-one-screen"
                | "--ignore-case"
                | "--IGNORE-CASE"
                | "--status-column"
                | "--LONG-PROMPT"
                | "--clear-screen"
                | "--silent"
                | "--SILENT"
                | "--tilde"
                | "--underline-special"
                | "--chop-long-lines"
                | "--no-init"
                | "--RAW-CONTROL-CHARS"
                | "--raw-control-chars"
                | "--squeeze-blank-lines"
                | "--tabs"
                | "--window"
                | "--hilite-unread"
        ),
        "od" => matches!(option, "-a" | "--traditional" | "--help" | "--version"),
        "xxd" => matches!(
            option,
            "-a" | "-autoskip"
                | "-b"
                | "-bits"
                | "-C"
                | "-capitalize"
                | "-d"
                | "-decimal"
                | "-E"
                | "-EBCDIC"
                | "-e"
                | "-g1"
                | "-h"
                | "-help"
                | "-i"
                | "-include"
                | "-p"
                | "-ps"
                | "-postscript"
                | "-plain"
                | "-r"
                | "-revert"
                | "-u"
                | "-uppercase"
                | "-v"
                | "-version"
        ),
        "base64" => matches!(
            option,
            "-d" | "--decode" | "-i" | "--ignore-garbage" | "--help" | "--version"
        ),
        "strings" => matches!(
            option,
            "-a" | "--all"
                | "-f"
                | "--print-file-name"
                | "-w"
                | "--include-all-whitespace"
                | "-h"
                | "--help"
                | "-v"
                | "-V"
                | "--version"
        ),
        "file" => matches!(
            option,
            "-b" | "--brief"
                | "-C"
                | "--compile"
                | "-c"
                | "--checking-printout"
                | "-E"
                | "--no-sandbox"
                | "-F"
                | "--separator"
                | "-h"
                | "--no-dereference"
                | "-i"
                | "--mime"
                | "--mime-type"
                | "--mime-encoding"
                | "-k"
                | "--keep-going"
                | "-L"
                | "--dereference"
                | "-l"
                | "--list"
                | "-N"
                | "--no-pad"
                | "-n"
                | "--no-buffer"
                | "-p"
                | "--preserve-date"
                | "-r"
                | "--raw"
                | "-s"
                | "--special-files"
                | "-S"
                | "-v"
                | "--version"
                | "-z"
                | "--uncompress"
                | "-Z"
                | "--uncompress-noreport"
                | "--help"
        ),
        "cp" => matches!(
            option,
            "--archive"
                | "--attributes-only"
                | "--copy-contents"
                | "--dereference"
                | "--force"
                | "--interactive"
                | "--link"
                | "--no-clobber"
                | "--no-dereference"
                | "--no-preserve"
                | "--no-target-directory"
                | "--one-file-system"
                | "--parents"
                | "--preserve"
                | "--recursive"
                | "--reflink"
                | "--remove-destination"
                | "--sparse"
                | "--strip-trailing-slashes"
                | "--symbolic-link"
                | "--update"
                | "--verbose"
                | "--help"
                | "--version"
                | "--backup"
                | "--context"
        ),
        "mv" => matches!(
            option,
            "--force"
                | "--interactive"
                | "--no-clobber"
                | "--no-target-directory"
                | "--strip-trailing-slashes"
                | "--update"
                | "--verbose"
                | "--help"
                | "--version"
                | "--backup"
                | "--context"
        ),
        "install" => matches!(
            option,
            "--backup"
                | "-C"
                | "--compare"
                | "-d"
                | "--directory"
                | "-D"
                | "--create-leading"
                | "-p"
                | "--preserve-timestamps"
                | "-s"
                | "--strip"
                | "-T"
                | "--no-target-directory"
                | "-v"
                | "--verbose"
                | "--help"
                | "--version"
                | "--context"
        ),
        "ln" => matches!(
            option,
            "--backup"
                | "-d"
                | "-F"
                | "--directory"
                | "-f"
                | "--force"
                | "-i"
                | "--interactive"
                | "-L"
                | "--logical"
                | "-n"
                | "--no-dereference"
                | "-P"
                | "--physical"
                | "-r"
                | "--relative"
                | "-s"
                | "--symbolic"
                | "-T"
                | "--no-target-directory"
                | "-v"
                | "--verbose"
                | "--help"
                | "--version"
                | "--context"
        ),
        "rsync" => matches!(
            option,
            "--verbose"
                | "--info"
                | "--debug"
                | "--msgs2stderr"
                | "--quiet"
                | "--no-motd"
                | "--checksum"
                | "--archive"
                | "--recursive"
                | "--relative"
                | "--no-implied-dirs"
                | "--backup"
                | "--update"
                | "--inplace"
                | "--append"
                | "--append-verify"
                | "--dirs"
                | "--links"
                | "--copy-links"
                | "--copy-unsafe-links"
                | "--safe-links"
                | "--munge-links"
                | "--copy-dirlinks"
                | "--keep-dirlinks"
                | "--hard-links"
                | "--perms"
                | "--executability"
                | "--acls"
                | "--xattrs"
                | "--owner"
                | "--group"
                | "--devices"
                | "--copy-devices"
                | "--specials"
                | "--times"
                | "--omit-dir-times"
                | "--omit-link-times"
                | "--super"
                | "--fake-super"
                | "--sparse"
                | "--preallocate"
                | "--dry-run"
                | "--whole-file"
                | "--checksum-choice"
                | "--one-file-system"
                | "--existing"
                | "--ignore-existing"
                | "--remove-source-files"
                | "--delete"
                | "--delete-before"
                | "--delete-during"
                | "--delete-delay"
                | "--delete-after"
                | "--delete-excluded"
                | "--ignore-missing-args"
                | "--delete-missing-args"
                | "--ignore-errors"
                | "--force"
                | "--max-delete"
                | "--numeric-ids"
                | "--usermap"
                | "--groupmap"
                | "--chown"
                | "--ignore-times"
                | "--size-only"
                | "--modify-window"
                | "--temp-dir"
                | "--fuzzy"
                | "--compare-dest"
                | "--copy-dest"
                | "--link-dest"
                | "--compress"
                | "--compress-choice"
                | "--compress-level"
                | "--skip-compress"
                | "--partial"
                | "--partial-dir"
                | "--delay-updates"
                | "--prune-empty-dirs"
                | "--progress"
                | "--stats"
                | "--human-readable"
                | "--itemize-changes"
                | "--list-only"
                | "--protect-args"
                | "--old-args"
                | "--secluded-args"
                | "--iconv"
                | "--checksum-seed"
                | "--ipv4"
                | "--ipv6"
                | "--version"
                | "--help"
        ),
        "touch" => matches!(
            option,
            "-a" | "-c" | "--no-create" | "-m" | "-h" | "--no-dereference" | "--help" | "--version"
        ),
        "mkdir" => matches!(
            option,
            "-p" | "--parents" | "-v" | "--verbose" | "-Z" | "--context" | "--help" | "--version"
        ),
        "rm" => matches!(
            option,
            "--force"
                | "--interactive"
                | "--interactive=always"
                | "--interactive=once"
                | "--one-file-system"
                | "--no-preserve-root"
                | "--preserve-root"
                | "--recursive"
                | "--dir"
                | "--verbose"
                | "--help"
                | "--version"
        ),
        "tee" => matches!(
            option,
            "--append" | "--ignore-interrupts" | "--output-error" | "--help" | "--version"
        ),
        _ => false,
    }
}

pub(super) fn is_known_short_option_cluster(command: &str, value: &str) -> bool {
    let Some(flags) = value
        .strip_prefix('-')
        .filter(|value| !value.starts_with('-'))
    else {
        return false;
    };
    if flags.is_empty() {
        return false;
    }
    if matches!(command, "head" | "tail") && flags.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    let allowed = match command {
        "cat" => "AbEeEnstTuv",
        "head" => "qvzc",
        "tail" => "fFqvzc",
        "less" => "aAbBcCeEfFgGiILmMnNqQRsSuUVwWX",
        "od" => "abcdDfFhHiIlLoOsvxX",
        "xxd" => "abCdeEhipruv",
        "base64" => "di",
        "strings" => "afhwvV",
        "file" => "bCcEhikLlNnprsSvzZ",
        "cp" => "abdfHilLnPrRsTuvx",
        "mv" => "bfinTuv",
        "install" => "bCDdpsTv",
        "ln" => "bdfFiLnPrsTv",
        "rsync" => "avqcrRbuolHDptgxnSAXWNKydFhPsiz",
        "touch" => "acmh",
        "mkdir" => "pvZ",
        "rm" => "firdRv",
        "tee" => "ai",
        _ => return false,
    };
    flags.chars().all(|flag| allowed.contains(flag))
}
