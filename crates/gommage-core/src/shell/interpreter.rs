use super::*;

pub(super) fn items_supply_stdin(items: &[CommandPrefixOrSuffixItem]) -> bool {
    items.iter().any(|item| {
        matches!(
            item,
            CommandPrefixOrSuffixItem::IoRedirect(redirect) if redirect_supplies_stdin(redirect)
        )
    })
}

pub(super) fn redirect_supplies_stdin(redirect: &IoRedirect) -> bool {
    match redirect {
        IoRedirect::File(fd, kind, _) => {
            fd.unwrap_or(0) == 0
                && matches!(
                    kind,
                    IoFileRedirectKind::Read
                        | IoFileRedirectKind::ReadAndWrite
                        | IoFileRedirectKind::DuplicateInput
                )
        }
        IoRedirect::HereDocument(fd, _) | IoRedirect::HereString(fd, _) => fd.unwrap_or(0) == 0,
        IoRedirect::OutputAndError(_, _) => false,
    }
}

pub(super) fn interpreter_reads_stdin_program(command: &ShellCommand) -> bool {
    interpreter_words_read_stdin_program(&command.effective_words)
}

pub(super) fn interpreter_words_read_stdin_program(words: &[ShellWord]) -> bool {
    classify_interpreter_program(words).is_ok_and(|(_, source)| {
        matches!(
            source,
            InterpreterProgramSource::Stdin
                | InterpreterProgramSource::PseudoFd
                | InterpreterProgramSource::PseudoFdUrl
        )
    })
}

pub(super) fn opaque_interpreter_program_ambiguity(words: &[ShellWord]) -> Option<Ambiguity> {
    let (kind, source) = match classify_interpreter_program(words) {
        Ok(classification) => classification,
        Err("not-an-interpreter") => return None,
        Err(reason) => return Some(reason),
    };
    match source {
        InterpreterProgramSource::Inline if !kind.is_transparent_shell() => {
            Some("interpreter-inline-program")
        }
        InterpreterProgramSource::Stdin if !kind.is_transparent_shell() => {
            Some("interpreter-stdin-program")
        }
        InterpreterProgramSource::InlinePreload => Some("interpreter-inline-preload-program"),
        InterpreterProgramSource::PseudoFd => Some("interpreter-pseudo-fd-program"),
        InterpreterProgramSource::PseudoFdUrl => Some("interpreter-pseudo-fd-url-program"),
        InterpreterProgramSource::Inline
        | InterpreterProgramSource::Stdin
        | InterpreterProgramSource::StaticFile
        | InterpreterProgramSource::Informational => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InterpreterKind {
    TransparentShell,
    OpaqueShell,
    Python,
    Node,
    Perl,
    Ruby,
    Php,
}

impl InterpreterKind {
    fn is_transparent_shell(self) -> bool {
        self == Self::TransparentShell
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InterpreterProgramSource {
    Inline,
    InlinePreload,
    Stdin,
    PseudoFd,
    PseudoFdUrl,
    StaticFile,
    Informational,
}

pub(super) fn classify_interpreter_program(
    words: &[ShellWord],
) -> Result<(InterpreterKind, InterpreterProgramSource), Ambiguity> {
    let Some(executable) = words.first().and_then(|word| word.static_value().ok()) else {
        return Err("dynamic-interpreter-command");
    };
    let untrusted_head = head_basename(executable);
    if untrusted_head != "busybox" && interpreter_kind(untrusted_head).is_none() {
        return Err("not-an-interpreter");
    }
    let head = trusted_executable_basename(executable)?;
    if head == "busybox" {
        return classify_busybox_shell_program(words);
    }
    let Some(kind) = interpreter_kind(head) else {
        return Err("not-an-interpreter");
    };
    let source = match kind {
        InterpreterKind::TransparentShell | InterpreterKind::OpaqueShell => {
            classify_shell_program(words)?
        }
        InterpreterKind::Python => classify_python_program(words)?,
        InterpreterKind::Node => classify_node_program(words)?,
        InterpreterKind::Perl => classify_perl_or_ruby_program(words, false)?,
        InterpreterKind::Ruby => classify_perl_or_ruby_program(words, true)?,
        InterpreterKind::Php => classify_php_program(words)?,
    };
    Ok((kind, source))
}

pub(super) fn interpreter_kind(head: &str) -> Option<InterpreterKind> {
    if matches!(head, "bash" | "sh" | "zsh") {
        return Some(InterpreterKind::TransparentShell);
    }
    if matches!(head, "dash" | "ash" | "ksh" | "mksh" | "yash" | "fish") {
        return Some(InterpreterKind::OpaqueShell);
    }
    if versioned_interpreter_name(head, &["python", "python2", "python3"]) {
        return Some(InterpreterKind::Python);
    }
    if versioned_interpreter_name(head, &["node", "nodejs"]) {
        return Some(InterpreterKind::Node);
    }
    if versioned_interpreter_name(head, &["perl", "perl5"]) {
        return Some(InterpreterKind::Perl);
    }
    if versioned_interpreter_name(head, &["ruby"]) {
        return Some(InterpreterKind::Ruby);
    }
    versioned_interpreter_name(head, &["php"]).then_some(InterpreterKind::Php)
}

pub(super) fn versioned_interpreter_name(head: &str, stems: &[&str]) -> bool {
    stems.iter().any(|stem| {
        head.strip_prefix(stem).is_some_and(|suffix| {
            suffix.is_empty()
                || (suffix.bytes().any(|byte| byte.is_ascii_digit())
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.'))
        })
    })
}

pub(super) fn classify_busybox_shell_program(
    words: &[ShellWord],
) -> Result<(InterpreterKind, InterpreterProgramSource), Ambiguity> {
    let Some(applet) = words.get(1) else {
        return Ok((
            InterpreterKind::OpaqueShell,
            InterpreterProgramSource::Informational,
        ));
    };
    let applet = applet
        .static_value()
        .map_err(|_| "dynamic-busybox-applet")?;
    if !matches!(applet, "sh" | "ash" | "hush") {
        return Err("not-an-interpreter");
    }
    Ok((
        InterpreterKind::OpaqueShell,
        classify_shell_program(&words[1..])?,
    ))
}

pub(super) fn classify_shell_program(
    words: &[ShellWord],
) -> Result<InterpreterProgramSource, Ambiguity> {
    let mut index = 1;
    while index < words.len() {
        let argument = words[index]
            .static_value()
            .map_err(|_| "dynamic-interpreter-option")?;
        if matches!(argument, "-c" | "--command") || argument.starts_with("--command=") {
            return Ok(InterpreterProgramSource::Inline);
        }
        if matches!(argument, "-" | "-s") {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if argument.starts_with('-')
            && !argument.starts_with("--")
            && !argument.starts_with("-O")
            && !argument.starts_with("-o")
        {
            let flags = &argument[1..];
            if flags.contains('c') {
                return Ok(InterpreterProgramSource::Inline);
            }
            if flags.contains('s') {
                return Ok(InterpreterProgramSource::Stdin);
            }
        }
        match argument {
            "--" => return classify_optional_program_path(words.get(index + 1)),
            "-O" | "-o" | "+O" | "+o" => {
                static_interpreter_option_value(words, index + 1)?;
                index += 2;
            }
            "--init-file" | "--rcfile" => {
                let preload = static_interpreter_option_value(words, index + 1)?;
                if pseudo_fd_path(preload) {
                    return Ok(InterpreterProgramSource::PseudoFd);
                }
                index += 2;
            }
            "--noprofile" | "--norc" | "--posix" | "--restricted" | "--verbose" | "--noediting" => {
                index += 1
            }
            value if value.starts_with("--init-file=") || value.starts_with("--rcfile=") => {
                let preload = value
                    .split_once('=')
                    .map(|(_, preload)| preload)
                    .ok_or("missing-interpreter-option-value")?;
                if pseudo_fd_path(preload) {
                    return Ok(InterpreterProgramSource::PseudoFd);
                }
                index += 1;
            }
            value
                if value.starts_with("-O")
                    || value.starts_with("-o")
                    || value.starts_with("+O")
                    || value.starts_with("+o") =>
            {
                index += 1;
            }
            value if value.starts_with(['-', '+']) => index += 1,
            value => return Ok(classify_program_path(value)),
        }
    }
    Ok(InterpreterProgramSource::Stdin)
}

pub(super) fn classify_python_program(
    words: &[ShellWord],
) -> Result<InterpreterProgramSource, Ambiguity> {
    let mut interactive = false;
    let mut index = 1;
    while index < words.len() {
        let argument = words[index]
            .static_value()
            .map_err(|_| "dynamic-interpreter-option")?;
        if argument == "--" {
            let source = classify_optional_program_path(words.get(index + 1))?;
            return Ok(if interactive {
                InterpreterProgramSource::Stdin
            } else {
                source
            });
        }
        if matches!(argument, "-h" | "-V" | "--help" | "--version") {
            return Ok(InterpreterProgramSource::Informational);
        }
        if matches!(argument, "-W" | "-X" | "--check-hash-based-pycs") {
            static_interpreter_option_value(words, index + 1)?;
            index += 2;
            continue;
        }
        if argument.starts_with("-W") || argument.starts_with("-X") {
            index += 1;
            continue;
        }
        if argument == "-m" {
            static_interpreter_option_value(words, index + 1)?;
            return Ok(if interactive {
                InterpreterProgramSource::Stdin
            } else {
                InterpreterProgramSource::StaticFile
            });
        }
        if argument.starts_with("-m") && argument.len() > 2 {
            return Ok(if interactive {
                InterpreterProgramSource::Stdin
            } else {
                InterpreterProgramSource::StaticFile
            });
        }
        if argument == "-c"
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && argument[1..].contains('c'))
        {
            return Ok(InterpreterProgramSource::Inline);
        }
        if argument.starts_with('-') && !argument.starts_with("--") {
            if argument[1..].contains('i') {
                interactive = true;
            }
            if argument[1..].bytes().all(|flag| {
                matches!(
                    flag,
                    b'b' | b'B'
                        | b'd'
                        | b'E'
                        | b'i'
                        | b'I'
                        | b'O'
                        | b'q'
                        | b's'
                        | b'S'
                        | b'u'
                        | b'v'
                        | b'x'
                )
            }) {
                index += 1;
                continue;
            }
            return Err("unknown-interpreter-option");
        }
        if argument.starts_with("--") {
            return Err("unknown-interpreter-option");
        }
        let source = classify_program_path(argument);
        return Ok(if interactive {
            InterpreterProgramSource::Stdin
        } else {
            source
        });
    }
    Ok(InterpreterProgramSource::Stdin)
}

pub(super) fn classify_node_program(
    words: &[ShellWord],
) -> Result<InterpreterProgramSource, Ambiguity> {
    let mut index = 1;
    while index < words.len() {
        let argument = words[index]
            .static_value()
            .map_err(|_| "dynamic-interpreter-option")?;
        if argument == "--" {
            return classify_optional_program_path(words.get(index + 1));
        }
        if matches!(
            argument,
            "-h" | "-v" | "--help" | "--version" | "--v8-options"
        ) {
            return Ok(InterpreterProgramSource::Informational);
        }
        if matches!(argument, "-e" | "-p" | "--eval" | "--print")
            || argument.starts_with("--eval=")
            || argument.starts_with("--print=")
        {
            return Ok(InterpreterProgramSource::Inline);
        }
        if matches!(argument, "-i" | "--interactive") {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if matches!(
            argument,
            "-r" | "--require" | "--import" | "--loader" | "--experimental-loader"
        ) {
            let preload = static_interpreter_option_value(words, index + 1)?;
            let source = classify_node_preload(preload)?;
            if source != InterpreterProgramSource::StaticFile {
                return Ok(source);
            }
            index += 2;
            continue;
        }
        if let Some(preload) = [
            "--require=",
            "--import=",
            "--loader=",
            "--experimental-loader=",
        ]
        .iter()
        .find_map(|prefix| argument.strip_prefix(prefix))
        {
            let source = classify_node_preload(preload)?;
            if source != InterpreterProgramSource::StaticFile {
                return Ok(source);
            }
            index += 1;
            continue;
        }
        if matches!(argument, "-C" | "--conditions" | "--input-type") {
            static_interpreter_option_value(words, index + 1)?;
            index += 2;
            continue;
        }
        if argument == "-" {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if argument == "-c"
            || argument.starts_with("--conditions=")
            || argument.starts_with("--input-type=")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return Err("unknown-interpreter-option");
        }
        return Ok(classify_program_path(argument));
    }
    Ok(InterpreterProgramSource::Stdin)
}

pub(super) fn classify_node_preload(preload: &str) -> Result<InterpreterProgramSource, Ambiguity> {
    let scheme = preload
        .split_once(':')
        .filter(|(scheme, _)| valid_url_scheme(scheme));
    let Some((scheme, _)) = scheme else {
        return Ok(classify_program_path(preload));
    };
    if scheme.eq_ignore_ascii_case("data") {
        return Ok(InterpreterProgramSource::InlinePreload);
    }
    if scheme.eq_ignore_ascii_case("node") {
        return Ok(InterpreterProgramSource::StaticFile);
    }
    if !scheme.eq_ignore_ascii_case("file") {
        return Err("unsupported-interpreter-preload-url");
    }
    let path = node_file_url_path(preload)?;
    Ok(if pseudo_fd_path(&path) {
        InterpreterProgramSource::PseudoFdUrl
    } else {
        InterpreterProgramSource::StaticFile
    })
}

pub(super) fn valid_url_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

pub(super) fn node_file_url_path(url: &str) -> Result<String, Ambiguity> {
    let (_, rest) = url
        .split_once(':')
        .ok_or("invalid-interpreter-preload-url")?;
    let path = if let Some(authority_and_path) = rest.strip_prefix("//") {
        let (authority, path) = authority_and_path
            .split_once('/')
            .ok_or("invalid-interpreter-preload-url")?;
        if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
            return Err("nonlocal-interpreter-preload-url");
        }
        format!("/{path}")
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        return Err("invalid-interpreter-preload-url");
    };
    let path = path
        .split(['?', '#'])
        .next()
        .ok_or("invalid-interpreter-preload-url")?;
    percent_decode_url_path(path)
}

pub(super) fn percent_decode_url_path(path: &str) -> Result<String, Ambiguity> {
    let input = path.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte != b'%' {
            decoded.push(byte);
            index += 1;
            continue;
        }
        let Some((&high, remainder)) = input.get(index + 1).zip(input.get(index + 2..)) else {
            return Err("invalid-interpreter-preload-url");
        };
        let Some(&low) = remainder.first() else {
            return Err("invalid-interpreter-preload-url");
        };
        let Some(decoded_byte) = hex_value(high)
            .zip(hex_value(low))
            .map(|(high, low)| (high << 4) | low)
        else {
            return Err("invalid-interpreter-preload-url");
        };
        if decoded_byte == 0 {
            return Err("invalid-interpreter-preload-url");
        }
        decoded.push(decoded_byte);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| "invalid-interpreter-preload-url")
}

pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn classify_perl_or_ruby_program(
    words: &[ShellWord],
    ruby: bool,
) -> Result<InterpreterProgramSource, Ambiguity> {
    let mut index = 1;
    while index < words.len() {
        let argument = words[index]
            .static_value()
            .map_err(|_| "dynamic-interpreter-option")?;
        if argument == "--" {
            return classify_optional_program_path(words.get(index + 1));
        }
        if matches!(argument, "-h" | "--help" | "--version") || (!ruby && argument == "-v") {
            return Ok(InterpreterProgramSource::Informational);
        }
        if argument == "-" {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if argument.starts_with("--") {
            if ruby
                && (argument.starts_with("--encoding=")
                    || argument.starts_with("--external-encoding=")
                    || argument.starts_with("--internal-encoding=")
                    || argument.starts_with("--enable=")
                    || argument.starts_with("--disable=")
                    || argument.starts_with("--dump="))
            {
                index += 1;
                continue;
            }
            return Err("unknown-interpreter-option");
        }
        if let Some(flags) = argument.strip_prefix('-') {
            for (offset, flag) in flags.char_indices() {
                if ruby && flag == 'r' {
                    let value_start = offset + flag.len_utf8();
                    let preload = if value_start < flags.len() {
                        &flags[value_start..]
                    } else {
                        index += 1;
                        static_interpreter_option_value(words, index)?
                    };
                    if pseudo_fd_path(preload) {
                        return Ok(InterpreterProgramSource::PseudoFd);
                    }
                    break;
                }
                if flag == 'e' || (!ruby && flag == 'E') {
                    return Ok(InterpreterProgramSource::Inline);
                }
                let value_is_attached = offset + flag.len_utf8() < flags.len();
                let requires_value = if ruby {
                    matches!(flag, 'C' | 'E' | 'F' | 'I' | 'r')
                } else {
                    matches!(flag, 'F' | 'I' | 'M' | 'm')
                };
                if requires_value {
                    if !value_is_attached {
                        static_interpreter_option_value(words, index + 1)?;
                        index += 1;
                    }
                    break;
                }
                let accepts_attached_value = if ruby {
                    matches!(flag, '0' | 'T' | 'W' | 'i' | 'l' | 'x')
                } else {
                    matches!(flag, '0' | 'C' | 'D' | 'd' | 'i' | 'l' | 'x')
                };
                if accepts_attached_value && value_is_attached {
                    break;
                }
            }
            index += 1;
            continue;
        }
        return Ok(classify_program_path(argument));
    }
    Ok(InterpreterProgramSource::Stdin)
}

pub(super) fn classify_php_program(
    words: &[ShellWord],
) -> Result<InterpreterProgramSource, Ambiguity> {
    let mut index = 1;
    while index < words.len() {
        let argument = words[index]
            .static_value()
            .map_err(|_| "dynamic-interpreter-option")?;
        if argument == "--" {
            return classify_optional_program_path(words.get(index + 1));
        }
        if matches!(
            argument,
            "-h" | "-v" | "-i" | "-m" | "--help" | "--version" | "--info" | "--modules"
        ) {
            return Ok(InterpreterProgramSource::Informational);
        }
        if matches!(argument, "-a" | "--interactive") {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if matches!(
            argument,
            "-r" | "-B"
                | "-R"
                | "-E"
                | "--run"
                | "--process-begin"
                | "--process-code"
                | "--process-end"
        ) || ["-r", "-B", "-R", "-E"]
            .iter()
            .any(|flag| argument.starts_with(flag) && argument.len() > flag.len())
            || argument.starts_with("--run=")
            || argument.starts_with("--process-begin=")
            || argument.starts_with("--process-code=")
            || argument.starts_with("--process-end=")
        {
            return Ok(InterpreterProgramSource::Inline);
        }
        if matches!(argument, "-f" | "-F" | "--file" | "--process-file") {
            let path = static_interpreter_option_value(words, index + 1)?;
            return Ok(classify_program_path(path));
        }
        if (argument.starts_with("-f") || argument.starts_with("-F")) && argument.len() > 2 {
            return Ok(classify_program_path(&argument[2..]));
        }
        if let Some(path) = argument.strip_prefix("--process-file=") {
            return Ok(classify_program_path(path));
        }
        if matches!(argument, "-c" | "-z" | "--php-ini" | "--zend-extension") {
            let path = static_interpreter_option_value(words, index + 1)?;
            if pseudo_fd_path(path) {
                return Ok(InterpreterProgramSource::PseudoFd);
            }
            index += 2;
            continue;
        }
        if let Some(path) = ["-c", "-z"]
            .iter()
            .find_map(|flag| argument.strip_prefix(flag).filter(|path| !path.is_empty()))
        {
            if pseudo_fd_path(path) {
                return Ok(InterpreterProgramSource::PseudoFd);
            }
            index += 1;
            continue;
        }
        if let Some(path) = ["--php-ini=", "--zend-extension="]
            .iter()
            .find_map(|prefix| argument.strip_prefix(prefix))
        {
            if pseudo_fd_path(path) {
                return Ok(InterpreterProgramSource::PseudoFd);
            }
            index += 1;
            continue;
        }
        if matches!(argument, "-d" | "--define") {
            let definition = static_interpreter_option_value(words, index + 1)?;
            if php_definition_loads_pseudo_fd(definition) {
                return Ok(InterpreterProgramSource::PseudoFd);
            }
            index += 2;
            continue;
        }
        if let Some(definition) = argument
            .strip_prefix("-d")
            .filter(|definition| !definition.is_empty())
            .or_else(|| argument.strip_prefix("--define="))
        {
            if php_definition_loads_pseudo_fd(definition) {
                return Ok(InterpreterProgramSource::PseudoFd);
            }
            index += 1;
            continue;
        }
        if matches!(argument, "-e" | "-H" | "-l" | "-n" | "-s" | "-w") {
            index += 1;
            continue;
        }
        if argument == "-" {
            return Ok(InterpreterProgramSource::Stdin);
        }
        if argument.starts_with('-') {
            return Err("unknown-interpreter-option");
        }
        return Ok(classify_program_path(argument));
    }
    Ok(InterpreterProgramSource::Stdin)
}

pub(super) fn php_definition_loads_pseudo_fd(definition: &str) -> bool {
    let Some((name, value)) = definition.split_once('=') else {
        return false;
    };
    let name = name.trim();
    if ![
        "auto_prepend_file",
        "auto_append_file",
        "extension",
        "zend_extension",
        "opcache.preload",
        "ffi.preload",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        return false;
    }
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    pseudo_fd_path(value)
}

pub(super) fn static_interpreter_option_value(
    words: &[ShellWord],
    index: usize,
) -> Result<&str, Ambiguity> {
    words
        .get(index)
        .ok_or("missing-interpreter-option-value")?
        .static_value()
        .map_err(|_| "dynamic-interpreter-option-value")
}

pub(super) fn classify_optional_program_path(
    word: Option<&ShellWord>,
) -> Result<InterpreterProgramSource, Ambiguity> {
    let Some(word) = word else {
        return Ok(InterpreterProgramSource::Stdin);
    };
    Ok(classify_program_path(
        word.static_value()
            .map_err(|_| "dynamic-interpreter-program")?,
    ))
}

pub(super) fn classify_program_path(path: &str) -> InterpreterProgramSource {
    if matches!(path, "-" | "/dev/stdin") {
        InterpreterProgramSource::Stdin
    } else if pseudo_fd_path(path) {
        InterpreterProgramSource::PseudoFd
    } else {
        InterpreterProgramSource::StaticFile
    }
}

pub(super) fn pseudo_fd_path(path: &str) -> bool {
    let Ok(path) = normalize_lexical(path, false) else {
        return false;
    };
    ["/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"]
        .iter()
        .any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|fd| !fd.is_empty() && fd.bytes().all(|byte| byte.is_ascii_digit()))
        })
}
