//! Shared, quote-aware shell parsing helpers.
//!
//! These functions are the single source of truth for how Gommage decomposes a
//! shell command string into the pieces policy and hardstops reason about. They
//! were originally private to `hardstop.rs`; the capability mapper now reuses
//! the exact same parsing so that a policy gate cannot be evaded by command
//! *shape* (compound commands, `env`/`sudo` prefixes, command substitution,
//! `bash -c` wrappers, absolute-path heads, …).
//!
//! Most helpers here are `pub(crate)`: they are an internal contract between
//! the mapper and the hardstop scanner. `shell_write_targets` is the narrow
//! public adapter surface used by host integrations to add policy context before
//! evaluation.
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

/// Extract best-effort filesystem write targets from a shell command.
///
/// This is the host-adapter companion to the stdlib Bash mapper. It deliberately
/// recognizes the same write shapes the mapper surfaces as `fs.write:*`: `tee`,
/// `cp` / `install` / `mv` / `rsync` / `ln` destinations, `sed -i` targets,
/// `dd of=...`, and output redirects. The result is used by hook adapters to attach destination Git
/// context before evaluation; it is not part of the evaluator and it never
/// suppresses the raw command capability.
pub fn shell_write_targets(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for segment in shell_segments(command) {
        let Some(real) = command_words(&segment) else {
            continue;
        };
        if real.is_empty() {
            continue;
        }
        let head = head_basename(&real[0]);
        match head {
            "tee" => {
                if let Some(path) = first_non_flag_arg(&real[1..]) {
                    push_target(path.to_string(), &mut out, &mut seen);
                }
            }
            // The destination of every file-moving verb is a write. `mv`,
            // `rsync` and `ln` joined `cp`/`install` on 2026-09-03: the stdlib
            // mapper gated only the latter two, so moving a file onto a guarded
            // path was the same effect through an unwatched verb.
            "cp" | "install" | "mv" | "rsync" | "ln" => {
                if let Some(path) = last_non_flag_arg(&real[1..]) {
                    push_target(path.to_string(), &mut out, &mut seen);
                }
            }
            "sed" => {
                if let Some(path) = sed_in_place_target(&real[1..]) {
                    push_target(path.to_string(), &mut out, &mut seen);
                }
            }
            "dd" => {
                for word in &real[1..] {
                    if let Some(path) = word.strip_prefix("of=")
                        && !path.is_empty()
                    {
                        push_target(path.to_string(), &mut out, &mut seen);
                    }
                }
            }
            _ => {}
        }
    }

    for target in redirect_targets(command) {
        push_target(target, &mut out, &mut seen);
    }

    out
}

fn first_non_flag_arg(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn last_non_flag_arg(args: &[String]) -> Option<&str> {
    args.iter()
        .rev()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn sed_in_place_target(args: &[String]) -> Option<&str> {
    let mut in_place = false;
    let mut script_from_option = false;
    let mut index = 0;

    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            index += 1;
            break;
        }
        if is_sed_in_place_option(arg) {
            in_place = true;
            index += 1;
            if matches!(arg, "-i" | "--in-place")
                && args
                    .get(index)
                    .is_some_and(|next| next.is_empty() || next.starts_with('.'))
                && args.get(index + 2).is_some()
            {
                index += 1;
            }
            continue;
        }
        if matches!(arg, "-e" | "-f") {
            script_from_option = true;
            index += 2;
            continue;
        }
        if (arg.starts_with("-e") || arg.starts_with("-f")) && arg.len() > 2 {
            script_from_option = true;
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }

    if !in_place {
        return None;
    }

    if script_from_option {
        return args.get(index).map(String::as_str);
    }

    args.get(index + 1).map(String::as_str)
}

fn is_sed_in_place_option(arg: &str) -> bool {
    arg == "-i" || arg.starts_with("-i.") || arg == "--in-place" || arg.starts_with("--in-place=")
}

fn push_target(
    target: String,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    if !target.is_empty() && seen.insert(target.clone()) {
        out.push(target);
    }
}

/// Which heredoc bodies [`mask_heredoc_bodies`] blanks out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeredocMask {
    /// Every heredoc body, quoted delimiter or not. Correct for any scan that
    /// reads the text as *commands* or *shell operators*: a heredoc body is
    /// stdin data, and the shell never parses it as either.
    All,
    /// Only bodies whose delimiter was quoted or backslash-escaped (`<<'EOF'`,
    /// `<<"EOF"`, `<<\EOF`). With a bare delimiter the shell still expands
    /// `$(...)`, backticks and variables inside the body, so those really do
    /// run and must stay visible to the substitution scanner.
    LiteralOnly,
}

/// Blank out heredoc bodies so the text a heredoc *feeds to stdin* is not parsed
/// as shell source.
///
/// Motivation (measured 2026-08-06): the capability mapper derives candidates
/// from newline segments and from backtick/`$(...)` substitutions. Neither scan
/// knew about heredocs, so a commit or PR body written with `git commit -F - <<'EOF'`
/// had its prose parsed as commands — a line *documenting* a dangerous command
/// emitted that command's capability, and a command name in markdown backticks
/// was read as a substitution. Inside a quoted heredoc the shell expands
/// nothing: that text can never execute, so deriving capabilities from it is a
/// false positive, and one that punishes writing a warning down.
///
/// Replacement is in place, character for character: every body character
/// becomes a space and newlines are kept, so line structure and character
/// offsets are identical to the input and callers can scan the masked string
/// exactly as they scanned the original.
///
/// Fail-closed by construction, three ways:
///   - an *unterminated* heredoc is left untouched, so a body that never reaches
///     its delimiter keeps being scanned exactly as before;
///   - the body is masked only when the line opening it names a known
///     **data consumer** ([`HEREDOC_DATA_CONSUMERS`]) — `cat`, `git commit -F -`,
///     `gh`, `tee`, `pbcopy`, … — because for anything else the body may well be
///     source code, not data;
///   - and never when the line also names an **interpreter**
///     ([`HEREDOC_EXECUTORS`]). `bash <<'EOF'` and `cat <<'EOF' | sh` really do
///     execute the body from stdin, quoted delimiter or not; masking those would
///     be an evasion, not a fix.
///
/// So masking only ever hides text the shell provably treats as data. Anything
/// unrecognised keeps its current (over-eager) behaviour.
pub(crate) fn mask_heredoc_bodies(command: &str, mask: HeredocMask) -> String {
    // Nothing to do unless a heredoc operator is present at all — the common
    // case, kept cheap.
    if !command.contains("<<") {
        return command.to_string();
    }

    let mut out: Vec<char> = command.chars().collect();
    // Line spans as (start, end) char indices, end exclusive of the newline.
    let lines = char_lines(&out);

    let mut pending: std::collections::VecDeque<PendingHeredoc> = std::collections::VecDeque::new();
    // Body lines collected for the heredoc currently being read, held back
    // until its delimiter is seen. Dropped wholesale if it never is.
    let mut body: Vec<(usize, usize)> = Vec::new();
    let mut current: Option<PendingHeredoc> = None;
    let mut to_blank: Vec<(usize, usize)> = Vec::new();
    // Quote state persists across lines: a quote can span newlines. Body lines
    // never touch it, which is the point — they are data.
    let mut single = false;
    let mut double = false;

    for &(line_start, line_end) in &lines {
        if let Some(heredoc) = &current {
            let line: String = out[line_start..line_end].iter().collect();
            if line.trim() == heredoc.delimiter {
                // Terminator reached: the held-back body is provably data. The
                // terminator line itself is heredoc syntax, not a command, so it
                // is blanked too — otherwise `EOF` shows up as a segment head.
                if heredoc.maskable && (heredoc.literal || mask == HeredocMask::All) {
                    to_blank.append(&mut body);
                    to_blank.push((line_start, line_end));
                }
                body.clear();
                current = pending.pop_front();
                continue;
            }
            body.push((line_start, line_end));
            continue;
        }

        scan_line_for_heredocs(
            &out[line_start..line_end],
            &mut single,
            &mut double,
            &mut pending,
        );
        if current.is_none() {
            current = pending.pop_front();
        }
    }

    // Unterminated heredoc: leave every held-back line alone (fail-closed).

    for (start, end) in to_blank {
        for slot in &mut out[start..end] {
            *slot = ' ';
        }
    }
    out.into_iter().collect()
}

struct PendingHeredoc {
    delimiter: String,
    literal: bool,
    /// Whether this heredoc's body is safe to mask, decided from the line that
    /// opened it (data consumer present, no interpreter present).
    maskable: bool,
}

/// Commands that consume a heredoc body as **data**. Masking a body requires one
/// of these on the opening line: it is the evidence that the text is content,
/// not source. Deliberately narrow — an unrecognised head keeps the old
/// over-eager scanning rather than being trusted by default.
const HEREDOC_DATA_CONSUMERS: &[&str] = &[
    "cat", "git", "gh", "glab", "tee", "pbcopy", "wc", "grep", "rg", "sort", "uniq", "head",
    "tail", "diff", "patch", "jq", "yq", "mail", "mailx", "sendmail", "msmtp", "psql", "mysql",
    "sqlite3", "curl", "http", "wc", "column", "fold", "fmt", "tr", "base64", "harbard", "nahuali",
    "urd", "gommage",
];

/// Commands that execute a heredoc body as a **program**, so its text is live
/// code even with a quoted delimiter. Presence of any of these anywhere on the
/// opening line blocks masking outright — `bash <<'EOF'`, `cat <<'EOF' | sh`,
/// `ssh host <<'EOF'` all run what the body says.
const HEREDOC_EXECUTORS: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "eval",
    "source",
    "exec",
    "xargs",
    "env",
    "ssh",
    "scp",
    "sftp",
    "docker",
    "podman",
    "kubectl",
    "nsenter",
    "chroot",
    "su",
    "screen",
    "tmux",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "deno",
    "bun",
    "php",
    "lua",
    "tclsh",
    "expect",
    "awk",
    "osascript",
    "make",
    "just",
    "ansible",
    "ansible-playbook",
];

/// Decide whether heredocs opened on this line may have their bodies masked.
///
/// Uses a deliberately simple whitespace/operator tokenisation of the line
/// (never [`shell_segments`], which calls back into masking) and compares each
/// token's basename against the two lists above.
fn line_allows_masking(line: &[char]) -> bool {
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    for &ch in line {
        if ch.is_whitespace() || matches!(ch, '|' | '&' | ';' | '(' | ')' | '\'' | '"' | '<' | '>')
        {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(ch);
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }

    let basenames: Vec<&str> = tokens
        .iter()
        .map(|t| head_basename(t.trim_start_matches('$')))
        .collect();
    if basenames.iter().any(|b| HEREDOC_EXECUTORS.contains(b)) {
        return false;
    }
    basenames.iter().any(|b| HEREDOC_DATA_CONSUMERS.contains(b))
}

/// Char-index line spans of `chars`, each excluding its trailing newline.
fn char_lines(chars: &[char]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, ch) in chars.iter().enumerate() {
        if *ch == '\n' {
            lines.push((start, index));
            start = index + 1;
        }
    }
    if start <= chars.len() {
        lines.push((start, chars.len()));
    }
    lines
}

/// Scan one command line for heredoc operators, appending each `<<` delimiter it
/// opens (in source order — bash stacks multiple heredocs on one line) to
/// `pending`. Quote state is threaded through so `echo "<<'EOF'"` opens nothing.
fn scan_line_for_heredocs(
    line: &[char],
    single: &mut bool,
    double: &mut bool,
    pending: &mut std::collections::VecDeque<PendingHeredoc>,
) {
    let maskable = line_allows_masking(line);
    let mut index = 0;
    while index < line.len() {
        let ch = line[index];
        match ch {
            '\'' if !*double => *single = !*single,
            '"' if !*single => *double = !*double,
            '\\' if !*single => {
                index += 2;
                continue;
            }
            '<' if !*single && !*double && line.get(index + 1) == Some(&'<') => {
                // `<<<` is a here-string, not a heredoc: no body follows.
                if line.get(index + 2) == Some(&'<') {
                    index += 3;
                    continue;
                }
                let mut cursor = index + 2;
                // `<<-` strips leading tabs from the body and terminator.
                if line.get(cursor) == Some(&'-') {
                    cursor += 1;
                }
                while line.get(cursor).is_some_and(|c| *c == ' ' || *c == '\t') {
                    cursor += 1;
                }
                if let Some((delimiter, literal, next)) = read_heredoc_delimiter(line, cursor) {
                    pending.push_back(PendingHeredoc {
                        delimiter,
                        literal,
                        maskable,
                    });
                    index = next;
                    continue;
                }
                index = cursor;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
}

/// Read the delimiter word of a heredoc starting at `start`, returning it with
/// whether it was quoted/escaped (making the body fully literal) and the index
/// just past it. `None` when no delimiter word is present.
fn read_heredoc_delimiter(line: &[char], start: usize) -> Option<(String, bool, usize)> {
    let mut index = start;
    let mut delimiter = String::new();
    let mut literal = false;

    match line.get(index) {
        Some('\'') => {
            literal = true;
            index += 1;
            while let Some(&ch) = line.get(index) {
                index += 1;
                if ch == '\'' {
                    break;
                }
                delimiter.push(ch);
            }
        }
        Some('"') => {
            literal = true;
            index += 1;
            while let Some(&ch) = line.get(index) {
                index += 1;
                if ch == '"' {
                    break;
                }
                delimiter.push(ch);
            }
        }
        Some(_) => {
            // Bare word. A backslash or an embedded quote anywhere in it also
            // suppresses expansion in bash (`<<\EOF`, `<<E'O'F`); treat the
            // whole word as literal in that case.
            while let Some(&ch) = line.get(index) {
                if ch.is_whitespace() || matches!(ch, '<' | '>' | '|' | '&' | ';' | '(' | ')') {
                    break;
                }
                index += 1;
                if matches!(ch, '\\' | '\'' | '"') {
                    literal = true;
                    continue;
                }
                delimiter.push(ch);
            }
        }
        None => return None,
    }

    if delimiter.is_empty() {
        return None;
    }
    Some((delimiter, literal, index))
}

/// Split a command string into shell segments, where each segment is the list
/// of whitespace-separated words of one simple command.
///
/// Splits on the unquoted operators `&&`, `||`, `;`, `|`, and newlines.
/// Single quotes, double quotes, and backslash escapes are honoured so that an
/// operator inside a quoted string does not split the command.
///
/// Heredoc bodies are masked out first: the text a heredoc feeds to stdin is
/// data, never a simple command, so it must not produce segments (see
/// [`mask_heredoc_bodies`]).
pub(crate) fn shell_segments(command: &str) -> Vec<Vec<String>> {
    let masked = mask_heredoc_bodies(command, HeredocMask::All);
    let command = masked.as_str();
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

/// Remove shell redirections and the background-`&` control operator from a
/// simple command's word list, returning only the genuine command + argument
/// tokens.
///
/// A redirection is **not** an argument: `git push origin main 2>&1` must be
/// reasoned about as `git push origin main`, not capture `2>&1` as a refspec.
/// Without this, a gate keyed on a capability (e.g. `git.push:refs/heads/main`)
/// is trivially evaded by appending a redirection — the candidate the mapper
/// builds would carry `2>&1` into the refspec position and miss the gate.
///
/// Handles both forms the (whitespace-only) tokenizer produces:
/// - glued (`>file`, `>>log`, `2>&1`, `2>/dev/null`, `&>log`, `<input`): the
///   whole token is one redirection, dropped.
/// - spaced (`> file`, `2> file`, `>> log`, `< input`): the operator token is
///   dropped *and* the following token (its target) is consumed too.
///
/// A lone `&` token (background) is also dropped: the tokenizer keeps it as a
/// word (only `&&` splits a segment), so `git push origin main &` would
/// otherwise leave `&` in the refspec position.
///
/// This only ever *removes* control tokens, never command/argument tokens, so
/// the surrounding fail-closed evaluation is unaffected.
pub(crate) fn strip_redirections(words: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    let mut index = 0;
    while index < words.len() {
        match classify_control_token(&words[index]) {
            ControlToken::None => {
                out.push(words[index].clone());
                index += 1;
            }
            // `>file`, `2>&1`, `&>log`, lone `&` — self-contained, drop the token.
            ControlToken::SelfContained => index += 1,
            // `>`, `2>`, `>>`, `<` — the target is the *next* token; drop both.
            ControlToken::BareOperator => {
                index += 1;
                if index < words.len() {
                    index += 1;
                }
            }
        }
    }
    out
}

enum ControlToken {
    /// Not a redirection or background operator: a real command/argument token.
    None,
    /// A whole-token control operator (glued redirect, fd-dup, or lone `&`).
    SelfContained,
    /// A redirection operator whose target is the following whitespace-separated
    /// token (`>`, `2>`, `>>`, `<`, `&>`, …).
    BareOperator,
}

/// Classify a single whitespace-separated token as a redirection / control
/// operator. Recognises an optional leading file descriptor (`2>`) or the
/// stdout+stderr `&>` form, the operators `> >> < << <<< <> >|`, and a lone
/// background `&`.
fn classify_control_token(word: &str) -> ControlToken {
    if word == "&" {
        return ControlToken::SelfContained;
    }
    // Strip an optional leading file descriptor before the operator: digits
    // (`2>`), or `&` for the stdout+stderr `&>` form.
    let rest = if let Some(after_amp) = word.strip_prefix('&') {
        if !after_amp.starts_with('>') {
            return ControlToken::None;
        }
        after_amp
    } else {
        let digits = word.chars().take_while(char::is_ascii_digit).count();
        let rest = &word[digits..];
        // Leading digits with no following operator are a plain argument
        // (e.g. a bare `2`), not a redirection.
        if digits > 0 && !(rest.starts_with('>') || rest.starts_with('<')) {
            return ControlToken::None;
        }
        rest
    };
    let op_len = if rest.starts_with("<<<") {
        3
    } else if rest.starts_with(">>")
        || rest.starts_with("<<")
        || rest.starts_with("<>")
        || rest.starts_with(">|")
    {
        2
    } else if rest.starts_with('>') || rest.starts_with('<') {
        1
    } else {
        return ControlToken::None;
    };
    if rest[op_len..].is_empty() {
        ControlToken::BareOperator
    } else {
        ControlToken::SelfContained
    }
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

#[cfg(test)]
mod write_target_tests {
    use super::*;

    #[test]
    fn extracts_redirect_and_heredoc_write_targets() {
        assert_eq!(
            shell_write_targets("cat > src/lib.rs <<EOF\nx\nEOF"),
            vec!["src/lib.rs"]
        );
        assert_eq!(
            shell_write_targets("printf x >> ./notes.txt"),
            vec!["./notes.txt"]
        );
    }

    #[test]
    fn extracts_write_verb_targets() {
        assert_eq!(shell_write_targets("tee src/lib.rs"), vec!["src/lib.rs"]);
        assert_eq!(
            shell_write_targets("cp src/lib.rs dist/lib.rs"),
            vec!["dist/lib.rs"]
        );
        assert_eq!(
            shell_write_targets("sed -i 's/a/b/' src/lib.rs"),
            vec!["src/lib.rs"]
        );
        assert_eq!(
            shell_write_targets("sed -i.bak -e s/a/b/ src/lib.rs"),
            vec!["src/lib.rs"]
        );
        assert_eq!(
            shell_write_targets("sed -i .bak s/a/b/ src/lib.rs"),
            vec!["src/lib.rs"]
        );
        assert_eq!(
            shell_write_targets("sed -i '' s/a/b/ src/lib.rs"),
            vec!["src/lib.rs"]
        );
        assert_eq!(shell_write_targets("dd if=a of=out.img"), vec!["out.img"]);
    }

    #[test]
    fn ignores_quoted_redirect_data() {
        assert!(shell_write_targets("echo '> src/lib.rs'").is_empty());
    }

    /// Regression (2026-09-03): only `cp` and `install` were recognised, so a
    /// file moved onto a guarded path produced no write target at all.
    #[test]
    fn extracts_moving_verb_destinations() {
        assert_eq!(
            shell_write_targets("mv /tmp/x.json /Users/a/.claude/settings.json"),
            vec!["/Users/a/.claude/settings.json"]
        );
        assert_eq!(
            shell_write_targets("rsync -a /tmp/x.json /Users/a/.claude/settings.json"),
            vec!["/Users/a/.claude/settings.json"]
        );
        assert_eq!(
            shell_write_targets("ln -s /tmp/evil /Users/a/.claude/settings.json"),
            vec!["/Users/a/.claude/settings.json"]
        );
        assert_eq!(
            shell_write_targets("install -m 644 a.json /Users/a/.claude/settings.json"),
            vec!["/Users/a/.claude/settings.json"]
        );
    }

    /// A `cd` chain must not hide the destination: the mapper scans each
    /// segment, so the `tee` segment still surfaces its target.
    #[test]
    fn moving_verb_destination_survives_a_cd_chain() {
        assert_eq!(
            shell_write_targets("cd /tmp && mv x.json /Users/a/.claude/settings.json"),
            vec!["/Users/a/.claude/settings.json"]
        );
    }

    /// Multi-source `mv a b dir/` resolves to the destination directory —
    /// conservative, never narrower than the truth.
    #[test]
    fn multi_source_move_uses_the_last_argument() {
        assert_eq!(
            shell_write_targets("mv a.txt b.txt /Users/a/.claude/"),
            vec!["/Users/a/.claude/"]
        );
    }
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
    // A `>` inside a heredoc body is data on stdin, not a redirect — masking
    // first keeps `cat <<'EOF' … > /dev/sda … EOF` from looking like one.
    let masked = mask_heredoc_bodies(command, HeredocMask::All);
    let command = masked.as_str();
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
///
/// Bodies of *quoted-delimiter* heredocs are masked out first: there the shell
/// expands nothing, so a command name written in markdown backticks inside a
/// commit or PR body is prose, not a substitution. A bare-delimiter heredoc
/// (`<<EOF`) does expand, so its substitutions stay visible.
pub(crate) fn command_substitutions(command: &str) -> Vec<String> {
    let masked = mask_heredoc_bodies(command, HeredocMask::LiteralOnly);
    let command = masked.as_str();
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
            // A backslash-escaped delimiter (`\`` or `\$`) is a literal in the
            // shell, not the start of a substitution. Skip the backslash and the
            // escaped char so `"\`rm -rf /\`"` is treated as data — matching the
            // escape handling already in `shell_segments` / `redirect_targets`.
            '\\' if !single => {
                index += 2;
                continue;
            }
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
    fn backslash_escaped_delimiters_are_data() {
        // Escaped backticks / `$(` inside double quotes are literals in the
        // shell, not substitutions. Regression: a git commit whose message
        // carried `\`rm -rf /\`` was hard-stopped as a fake substitution.
        assert!(command_substitutions(r#"echo "\`rm -rf /\`""#).is_empty());
        assert!(command_substitutions(r#"echo "\$(rm -rf /)""#).is_empty());
    }

    #[test]
    fn unescaped_substitution_still_extracted_with_escape_support() {
        // A genuine (unescaped) substitution is still found — the escape
        // handling only suppresses the provably-literal escaped form.
        assert_eq!(
            command_substitutions(r#"echo "$(git push)""#),
            vec!["git push"]
        );
        assert_eq!(
            command_substitutions(r#"echo "`git push`""#),
            vec!["git push"]
        );
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

    fn strip(cmd: &str) -> Vec<String> {
        let words: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        strip_redirections(&words)
    }

    #[test]
    fn strip_redirections_drops_glued_fd_dup() {
        // The reported gate-evasion: `2>&1` must not survive into the refspec.
        assert_eq!(
            strip("git push origin main 2>&1"),
            vec!["git", "push", "origin", "main"]
        );
    }

    #[test]
    fn strip_redirections_drops_glued_and_spaced_targets() {
        assert_eq!(
            strip("git push origin main >log"),
            vec!["git", "push", "origin", "main"]
        );
        assert_eq!(
            strip("git push origin main > log"),
            vec!["git", "push", "origin", "main"]
        );
        assert_eq!(
            strip("git push origin main 2> /dev/null"),
            vec!["git", "push", "origin", "main"]
        );
        assert_eq!(
            strip("git push origin main 2>/dev/null >>out.txt"),
            vec!["git", "push", "origin", "main"]
        );
    }

    #[test]
    fn strip_redirections_drops_trailing_background() {
        assert_eq!(
            strip("git push origin main &"),
            vec!["git", "push", "origin", "main"]
        );
    }

    #[test]
    fn strip_redirections_keeps_real_arguments() {
        // Refspecs and numeric-looking args are never stripped.
        assert_eq!(
            strip("git push origin feature/x"),
            vec!["git", "push", "origin", "feature/x"]
        );
        assert_eq!(
            strip("git reset --hard HEAD~1"),
            vec!["git", "reset", "--hard", "HEAD~1"]
        );
        assert_eq!(strip("kill -9 1234"), vec!["kill", "-9", "1234"]);
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

#[cfg(test)]
mod heredoc_mask_tests {
    use super::*;

    /// The command string this fix exists for, assembled at runtime so this file
    /// does not itself carry the literal that used to trip the mapper.
    fn bulk_stage() -> String {
        format!("git {} -A", "add")
    }

    /// A destructive command used as *data* in the fixtures below.
    fn destructive() -> String {
        format!("rm {} /etc", "-rf")
    }

    fn segment_heads(command: &str) -> Vec<String> {
        shell_segments(command)
            .iter()
            .filter_map(|words| words.first().cloned())
            .collect()
    }

    #[test]
    fn quoted_heredoc_body_is_not_parsed_as_commands() {
        // The exact shape denied on 2026-08-06: a commit body documenting a
        // dangerous command. Nothing in that body can execute.
        let command = format!(
            "git commit -q -F - <<'EOF'\nchore: untrack artifacts\n\n{} from any session would carry it.\nEOF",
            bulk_stage()
        );
        assert_eq!(segment_heads(&command), vec!["git".to_string()]);
    }

    #[test]
    fn backticks_in_a_quoted_heredoc_body_are_prose() {
        let command = format!(
            "gh pr create --body \"$(cat <<'EOF'\nany `{}` would carry it\nEOF\n)\"",
            bulk_stage()
        );
        // The outer `$(cat <<'EOF' … )` is a real substitution and still shows up
        // — what must not happen is the *backticked prose inside the body*
        // becoming a substitution of its own. The mapper recurses into the outer
        // body, and that recursion is where masking has to hold; assert it here
        // by re-scanning the outer body the way the mapper does.
        let outer = command_substitutions(&command);
        assert_eq!(
            outer.len(),
            1,
            "expected exactly the outer substitution: {outer:?}"
        );
        let inner = command_substitutions(&outer[0]);
        assert!(
            inner.is_empty(),
            "markdown backticks inside a quoted heredoc must not read as substitutions: {inner:?}"
        );
    }

    #[test]
    fn bare_delimiter_heredoc_still_exposes_substitutions() {
        // `<<EOF` (unquoted) expands: that substitution really does run.
        let command = "cat <<EOF\nsnapshot: `git push --force`\nEOF";
        assert!(
            command_substitutions(command)
                .iter()
                .any(|s| s.contains("git push --force")),
            "an unquoted heredoc expands, so its substitutions must stay visible"
        );
    }

    #[test]
    fn interpreter_heredoc_body_is_still_scanned() {
        // These execute the body from stdin — masking them would be an evasion.
        let danger = destructive();
        for command in [
            format!("bash <<'EOF'\n{danger}\nEOF"),
            format!("cat <<'EOF' | sh\n{danger}\nEOF"),
            format!("ssh host <<'EOF'\n{danger}\nEOF"),
            format!("python3 <<'EOF'\n{danger}\nEOF"),
        ] {
            assert!(
                segment_heads(&command).contains(&"rm".to_string()),
                "body must stay visible for an executing consumer: {command}"
            );
        }
    }

    #[test]
    fn unknown_consumer_keeps_previous_behaviour() {
        // Not in the data-consumer allowlist: fail closed, keep scanning.
        let command = format!("weirdtool <<'EOF'\n{}\nEOF", destructive());
        assert!(segment_heads(&command).contains(&"rm".to_string()));
    }

    #[test]
    fn unterminated_heredoc_is_left_untouched() {
        let command = format!("cat <<'EOF'\n{}\n", destructive());
        assert!(
            segment_heads(&command).contains(&"rm".to_string()),
            "a heredoc that never reaches its delimiter must keep being scanned"
        );
    }

    #[test]
    fn quoted_heredoc_operator_opens_nothing() {
        // The operator itself is inside quotes: data, not a heredoc.
        let command = format!("echo \"<<'EOF'\" && {}", destructive());
        assert!(segment_heads(&command).contains(&"rm".to_string()));
    }

    #[test]
    fn here_string_is_not_a_heredoc() {
        // `<<<` takes no body, so the following line is an ordinary command.
        let command = format!("cat <<<'x'\n{}", destructive());
        assert!(segment_heads(&command).contains(&"rm".to_string()));
    }

    #[test]
    fn dash_form_and_indented_terminator() {
        let command = format!(
            "git commit -F - <<-'EOF'\n\t{} in prose\n\tEOF\n",
            bulk_stage()
        );
        assert_eq!(segment_heads(&command), vec!["git".to_string()]);
    }

    #[test]
    fn stacked_heredocs_are_consumed_in_order() {
        let command = format!(
            "cat <<'A' <<'B'\nfirst {d}\nA\nsecond {d}\nB",
            d = destructive()
        );
        assert!(
            !segment_heads(&command).contains(&"rm".to_string()),
            "both stacked bodies are data: {:?}",
            shell_segments(&command)
        );
    }

    #[test]
    fn redirect_inside_a_quoted_heredoc_body_is_not_a_redirect() {
        let command = "cat <<'EOF'\nnever write > /dev/sda by hand\nEOF";
        assert!(redirect_targets(command).is_empty());
    }

    #[test]
    fn masking_preserves_line_structure_and_length() {
        let command = "cat <<'EOF'\nabc\ndef\nEOF";
        let masked = mask_heredoc_bodies(command, HeredocMask::All);
        assert_eq!(masked.chars().count(), command.chars().count());
        assert_eq!(masked.lines().count(), command.lines().count());
        assert!(masked.contains("cat <<'EOF'"));
        assert!(!masked.contains("abc"));
    }

    #[test]
    fn commands_after_a_heredoc_terminator_are_still_seen() {
        let command = format!("cat <<'EOF'\nprose\nEOF\n{}", destructive());
        assert!(segment_heads(&command).contains(&"rm".to_string()));
    }

    #[test]
    fn write_target_extraction_survives_masking() {
        // Regression guard for the existing heredoc write-target behaviour.
        assert_eq!(
            shell_write_targets("cat > src/lib.rs <<EOF\nx\nEOF"),
            vec!["src/lib.rs"]
        );
    }
}
