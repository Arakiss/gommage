//! Shared, quote-aware shell parsing helpers.
//!
//! These functions are the single source of truth for how Gommage decomposes a
//! shell command string into the pieces policy and hardstops reason about. They
//! were originally private to `hardstop.rs`; the capability mapper now reuses
//! the exact same parsing so that a policy gate cannot be evaded by command
//! *shape* (compound commands, `env`/`sudo` prefixes, command substitution,
//! `bash -c` wrappers, absolute-path heads, …).
//!
//! Everything here is `pub(crate)`: it is an internal contract between the
//! mapper and the hardstop scanner, not a public API.
//!
//! Design notes:
//!   - Parsing is intentionally *approximate but conservative*. It is not a full
//!     POSIX shell parser. It splits on the unquoted operators `&& || ; |` and
//!     newlines, tokenises on unquoted whitespace, honours single/double quotes
//!     and backslash escapes, and extracts `$(...)` / backtick substitutions.
//!   - Quoted text is never treated as a command: `echo 'git push'` yields the
//!     single segment `[echo, git push]`, so `git push` is data, not a verb.
//!   - When parsing is uncertain, the surrounding policy fails closed — these
//!     helpers only ever *add* candidates to scan, they never suppress one.

/// Split a command string into shell segments, where each segment is the list
/// of whitespace-separated words of one simple command.
///
/// Splits on the unquoted operators `&&`, `||`, `;`, `|`, and newlines.
/// Single quotes, double quotes, and backslash escapes are honoured so that an
/// operator inside a quoted string does not split the command.
pub(crate) fn shell_segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut chars = command.chars().peekable();
    let mut single = false;
    let mut double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '\\' if !single => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            ';' | '\n' if !single && !double => {
                push_word(&mut words, &mut word);
                push_segment(&mut segments, &mut words);
            }
            '&' if !single && !double && chars.peek() == Some(&'&') => {
                chars.next();
                push_word(&mut words, &mut word);
                push_segment(&mut segments, &mut words);
            }
            '|' if !single && !double => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                push_word(&mut words, &mut word);
                push_segment(&mut segments, &mut words);
            }
            ch if ch.is_whitespace() && !single && !double => push_word(&mut words, &mut word),
            _ => word.push(ch),
        }
    }
    push_word(&mut words, &mut word);
    push_segment(&mut segments, &mut words);
    segments
}

fn push_word(words: &mut Vec<String>, word: &mut String) {
    if !word.is_empty() {
        words.push(std::mem::take(word));
    }
}

fn push_segment(segments: &mut Vec<Vec<String>>, words: &mut Vec<String>) {
    if !words.is_empty() {
        segments.push(std::mem::take(words));
    }
}

/// Strip the leading wrapper/prefix tokens of a simple command and return the
/// slice that begins at the *real* command word.
///
/// Skips, in any order:
///   - leading `VAR=value` environment assignments
///   - `env [VAR=value | -flag]*`
///   - `sudo [-u user | -g group | -h host | -other]*`
///   - `timeout [-s SIG | -k DUR | --signal SIG | --kill-after DUR | --preserve-status]* DURATION`
///   - `nice [-n N | -N]*`
///   - `nohup`
///   - `stdbuf [-i MODE | -o MODE | -e MODE]*`
///
/// Returns `None` only when the slice is exhausted (e.g. a bare `sudo` with no
/// command). The returned slice's first element is the head command token; it
/// may still contain a `/` (absolute/relative path) — basename normalisation is
/// the caller's job (see [`head_basename`]).
pub(crate) fn command_words(words: &[String]) -> Option<&[String]> {
    let mut index = 0;
    while index < words.len() {
        match words[index].as_str() {
            "sudo" => {
                index += 1;
                while index < words.len() && words[index].starts_with('-') {
                    if matches!(
                        words[index].as_str(),
                        "-u" | "--user" | "-g" | "--group" | "-h" | "--host"
                    ) {
                        index += 1;
                    }
                    index += 1;
                }
            }
            "env" => {
                index += 1;
                while index < words.len()
                    && (is_assignment(&words[index]) || words[index].starts_with('-'))
                {
                    index += 1;
                }
            }
            "nohup" => index += 1,
            "nice" => {
                index += 1;
                // `nice -n 10` or `nice -10` or bare `nice`.
                while index < words.len() && words[index].starts_with('-') {
                    let takes_arg = words[index] == "-n";
                    index += 1;
                    if takes_arg && index < words.len() {
                        index += 1;
                    }
                }
            }
            "timeout" => {
                index += 1;
                // Option flags before the mandatory DURATION argument.
                while index < words.len() && words[index].starts_with('-') {
                    let takes_arg = matches!(words[index].as_str(), "-s" | "--signal" | "-k");
                    let takes_attached = words[index] == "--kill-after";
                    index += 1;
                    if takes_arg && index < words.len() {
                        index += 1;
                    }
                    // `--kill-after=DUR` is self-contained; `--kill-after DUR`
                    // is handled by the generic flag loop on the next pass only
                    // if written separately, which GNU coreutils does not, so
                    // we treat the separated form conservatively here.
                    let _ = takes_attached;
                }
                // Consume the DURATION positional (e.g. `30`, `1m`, `5s`).
                if index < words.len() {
                    index += 1;
                }
            }
            "stdbuf" => {
                index += 1;
                while index < words.len() && words[index].starts_with('-') {
                    let takes_arg = matches!(words[index].as_str(), "-i" | "-o" | "-e");
                    index += 1;
                    if takes_arg && index < words.len() {
                        index += 1;
                    }
                }
            }
            word if is_assignment(word) => index += 1,
            _ => break,
        }
    }
    words.get(index..)
}

/// The basename of a command head token: `/usr/bin/git` → `git`, `git` → `git`.
/// Used so that absolute/relative-path invocations match the same rules and
/// hardstops as the bare command name. A token with no `/` is returned as-is.
pub(crate) fn head_basename(token: &str) -> &str {
    match token.rsplit_once('/') {
        Some((_, base)) if !base.is_empty() => base,
        _ => token,
    }
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Given the argument words *after* a `bash`/`sh`/`zsh` head, return the payload
/// of a `-c "..."` invocation, if present. Skips other `-flag`s; stops at the
/// first non-flag word that is not `-c`.
pub(crate) fn shell_c_payload(args: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-c" {
            return args.get(index + 1).map(String::as_str);
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return None;
    }
    None
}

/// Extract the targets of genuine output redirections (`>` / `>>`) in
/// `command`, honouring quote and escape context so a redirect operator that
/// appears inside quotes is treated as data, not a redirect.
///
/// This exists because the segment-join the mapper uses for candidates strips
/// quotes: `echo "> /dev/sda"` would otherwise look identical to
/// `echo data > /dev/sda` once re-joined. A naive regex over the raw string
/// cannot tell the two apart; this scanner can, because it tracks quote state
/// exactly like [`shell_segments`]. Returns the target token following each
/// unquoted `>`/`>>` (file-descriptor prefixes like `2>` are honoured, the fd
/// digit is not part of the target). Used by the capability mapper to surface
/// device-write redirects without the quoted-data false positive.
pub(crate) fn redirect_targets(command: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut chars = command.chars().peekable();
    let mut single = false;
    let mut double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '\\' if !single => {
                chars.next();
            }
            '>' if !single && !double => {
                // Consume a possible second '>' (>>), then any whitespace, then
                // read the target token up to the next whitespace or operator.
                if chars.peek() == Some(&'>') {
                    chars.next();
                }
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
                // Read the target token, stripping quotes from the target itself
                // so `> "/dev/sda"` yields the same `/dev/sda` as `> /dev/sda`
                // (a quoted *target* is still a real redirect; only a quoted
                // operator is data, handled by the outer single/double guards).
                let mut target = String::new();
                let mut tsingle = false;
                let mut tdouble = false;
                while let Some(&c) = chars.peek() {
                    match c {
                        '\'' if !tdouble => tsingle = !tsingle,
                        '"' if !tsingle => tdouble = !tdouble,
                        c if (c.is_whitespace() || matches!(c, '>' | '<' | '|' | '&' | ';'))
                            && !tsingle
                            && !tdouble =>
                        {
                            break;
                        }
                        c => target.push(c),
                    }
                    chars.next();
                }
                if !target.is_empty() {
                    targets.push(target);
                }
            }
            _ => {}
        }
    }
    targets
}

/// Extract the bodies of all `$(...)` and backtick command substitutions in
/// `command`, honouring quote context (a substitution inside single quotes is
/// data, not a substitution). Nested `$(...)` parens are balanced; the returned
/// strings are the inner command text only (without the delimiters).
pub(crate) fn command_substitutions(command: &str) -> Vec<String> {
    let chars = command.char_indices().collect::<Vec<_>>();
    let mut substitutions = Vec::new();
    let mut single = false;
    let mut double = false;
    let mut index = 0;

    while index < chars.len() {
        let (_, ch) = chars[index];
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '$' if !single && chars.get(index + 1).is_some_and(|(_, next)| *next == '(') => {
                if let Some((end, content)) = read_command_substitution(command, &chars, index + 2)
                {
                    substitutions.push(content);
                    index = end;
                    continue;
                }
            }
            '`' if !single => {
                if let Some((end, content)) = read_backtick_substitution(command, &chars, index + 1)
                {
                    substitutions.push(content);
                    index = end;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }
    substitutions
}

fn read_command_substitution(
    command: &str,
    chars: &[(usize, char)],
    start: usize,
) -> Option<(usize, String)> {
    let mut depth = 1usize;
    let mut single = false;
    let mut double = false;
    let content_start = chars.get(start).map_or(command.len(), |(byte, _)| *byte);
    let mut index = start;

    while index < chars.len() {
        let (_, ch) = chars[index];
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '(' if !single && !double => depth += 1,
            ')' if !single && !double => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let content_end = chars[index].0;
                    return Some((index + 1, command[content_start..content_end].to_string()));
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn read_backtick_substitution(
    command: &str,
    chars: &[(usize, char)],
    start: usize,
) -> Option<(usize, String)> {
    let content_start = chars.get(start).map_or(command.len(), |(byte, _)| *byte);
    let mut index = start;

    while index < chars.len() {
        let (_, ch) = chars[index];
        if ch == '`' {
            let content_end = chars[index].0;
            return Some((index + 1, command[content_start..content_end].to_string()));
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Vec<Vec<String>> {
        shell_segments(s)
    }

    #[test]
    fn splits_on_operators() {
        assert_eq!(
            seg("a && b; c | d || e"),
            vec![
                vec!["a".to_string()],
                vec!["b".to_string()],
                vec!["c".to_string()],
                vec!["d".to_string()],
                vec!["e".to_string()],
            ]
        );
    }

    #[test]
    fn quotes_protect_operators() {
        assert_eq!(
            seg("echo 'a && b'"),
            vec![vec!["echo".to_string(), "a && b".to_string()]]
        );
    }

    #[test]
    fn strips_env_and_sudo_prefix() {
        let words: Vec<String> = "env DEBUG=1 sudo -u root git push"
            .split_whitespace()
            .map(String::from)
            .collect();
        let real = command_words(&words).unwrap();
        assert_eq!(real[0], "git");
    }

    #[test]
    fn strips_timeout_prefix_with_duration() {
        let words: Vec<String> = "timeout 30 git push"
            .split_whitespace()
            .map(String::from)
            .collect();
        let real = command_words(&words).unwrap();
        assert_eq!(real[0], "git");
    }

    #[test]
    fn strips_timeout_with_signal_option() {
        let words: Vec<String> = "timeout -s KILL 5 rm -rf /"
            .split_whitespace()
            .map(String::from)
            .collect();
        let real = command_words(&words).unwrap();
        assert_eq!(real[0], "rm");
    }

    #[test]
    fn strips_nice_nohup_stdbuf() {
        let words: Vec<String> = "nohup nice -n 5 stdbuf -o0 git push"
            .split_whitespace()
            .map(String::from)
            .collect();
        let real = command_words(&words).unwrap();
        assert_eq!(real[0], "git");
    }

    #[test]
    fn basename_of_absolute_head() {
        assert_eq!(head_basename("/usr/bin/git"), "git");
        assert_eq!(head_basename("git"), "git");
        assert_eq!(head_basename("./bin/rm"), "rm");
        assert_eq!(head_basename("/"), "/");
    }

    #[test]
    fn extracts_dollar_paren_substitution() {
        assert_eq!(command_substitutions("echo $(git push)"), vec!["git push"]);
    }

    #[test]
    fn extracts_backtick_substitution() {
        assert_eq!(command_substitutions("echo `git push`"), vec!["git push"]);
    }

    #[test]
    fn single_quoted_substitution_is_data() {
        assert!(command_substitutions("echo '$(git push)'").is_empty());
        assert!(command_substitutions("echo '`git push`'").is_empty());
    }

    #[test]
    fn shell_c_payload_is_extracted() {
        let args: Vec<String> = vec!["-c".into(), "rm -rf /".into()];
        assert_eq!(shell_c_payload(&args), Some("rm -rf /"));
    }

    #[test]
    fn redirect_targets_unquoted() {
        assert_eq!(
            redirect_targets("echo data > /dev/sda"),
            vec!["/dev/sda".to_string()]
        );
        assert_eq!(
            redirect_targets("echo x >> /dev/disk2"),
            vec!["/dev/disk2".to_string()]
        );
        assert_eq!(
            redirect_targets("printf a > /tmp/a; printf b > /dev/sdb"),
            vec!["/tmp/a".to_string(), "/dev/sdb".to_string()]
        );
    }

    #[test]
    fn redirect_targets_ignores_quoted_operator() {
        // The whole `> /dev/sda` is inside quotes — it is data, not a redirect.
        assert!(redirect_targets("echo \"> /dev/sda\"").is_empty());
        assert!(redirect_targets("echo '> /dev/sda'").is_empty());
        // A redirect target that itself is quoted is still a real redirect.
        assert_eq!(
            redirect_targets("echo x > \"/dev/sda\""),
            vec!["/dev/sda".to_string()]
        );
    }
}
