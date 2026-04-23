use crate::Capability;
use globset::{GlobBuilder, GlobMatcher};
use std::sync::OnceLock;

/// The list of hardcoded, always-on capability patterns that Gommage will
/// gommage regardless of policy, picto, or expedition. Keep this list **finite**,
/// **documented**, and **hard to grow**: anything here must be universally
/// destructive.
///
/// Editing this list requires a PR. Do not source it from configuration.
///
/// Patterns are compiled with `literal_separator=false` because these entries
/// target `proc.exec:<command>` which is a flat command string, not a path —
/// `*` should match `/` freely here.
pub const HARD_STOPS: &[(&str, &str)] = &[
    // --- Direct destructive invocations ---
    ("hs.rm-rf-root", "proc.exec:rm -rf /*"),
    ("hs.rm-rf-root-strict", "proc.exec:rm -rf /"),
    ("hs.sudo-rm-rf", "proc.exec:sudo rm -rf *"),
    ("hs.mkfs", "proc.exec:mkfs*"),
    ("hs.dd-to-device", "proc.exec:dd if=* of=/dev/*"),
    ("hs.fork-bomb", "proc.exec:*:|:&*"),
    ("hs.wipe-disk", "proc.exec:shred /dev/*"),
    ("hs.chmod-system", "proc.exec:chmod -R * /"),
    // Compound commands, shell wrappers, `env`/`sudo` prefixes, `xargs`, and
    // command substitution are handled by the semantic scanner below. Keep glob
    // entries for single-command shapes only; broad substring globs create
    // false positives for quoted fixture data.
];

const SEMANTIC_RM_RF_ROOT_PATTERN: &str = "proc.exec:<shell-semantic rm -rf absolute>";
const SEMANTIC_DD_DEVICE_PATTERN: &str = "proc.exec:<shell-semantic dd of=/dev/*>";

fn compiled() -> &'static [(&'static str, GlobMatcher)] {
    static CELL: OnceLock<Vec<(&'static str, GlobMatcher)>> = OnceLock::new();
    CELL.get_or_init(|| {
        HARD_STOPS
            .iter()
            .map(|(name, pat)| {
                let g = GlobBuilder::new(pat)
                    .literal_separator(false)
                    .backslash_escape(true)
                    .build()
                    .unwrap_or_else(|_| {
                        panic!("hardstop pattern {pat:?} failed to compile — this is a bug")
                    })
                    .compile_matcher();
                (*name, g)
            })
            .collect()
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardStopHit {
    pub name: &'static str,
    pub pattern: &'static str,
    pub capability: Capability,
}

/// Scan `caps` for anything matching the hardcoded hard-stop set.
/// Returns the **first** hit (deterministic, insertion-order).
pub fn check(caps: &[Capability]) -> Option<HardStopHit> {
    for (name, matcher) in compiled() {
        for cap in caps {
            if matcher.is_match(cap.as_str()) {
                let pattern = HARD_STOPS
                    .iter()
                    .find_map(|(n, p)| if n == name { Some(*p) } else { None })
                    .unwrap_or("");
                return Some(HardStopHit {
                    name,
                    pattern,
                    capability: cap.clone(),
                });
            }
        }
    }
    for cap in caps {
        if cap.namespace() == "proc.exec"
            && let Some((name, pattern)) = semantic_proc_exec_hit(cap.payload())
        {
            return Some(HardStopHit {
                name,
                pattern,
                capability: cap.clone(),
            });
        }
    }
    None
}

fn semantic_proc_exec_hit(command: &str) -> Option<(&'static str, &'static str)> {
    for substitution in command_substitutions(command) {
        if let Some(hit) = semantic_proc_exec_hit(&substitution) {
            return Some(hit);
        }
    }

    for segment in shell_segments(command) {
        if let Some(hit) = semantic_segment_hit(&segment) {
            return Some(hit);
        }
    }
    None
}

fn semantic_segment_hit(words: &[String]) -> Option<(&'static str, &'static str)> {
    let words = command_words(words)?;
    let (cmd, args) = words.split_first()?;

    if matches!(cmd.as_str(), "bash" | "sh" | "zsh")
        && let Some(script) = shell_c_payload(args)
    {
        return semantic_proc_exec_hit(script);
    }

    if cmd == "xargs" && xargs_invokes_rm_rf(args) {
        return Some(("hs.xargs-rm-rf", "proc.exec:*xargs rm -rf*"));
    }

    if cmd == "rm" && rm_rf_absolute(args) {
        return Some(("hs.rm-rf-root", SEMANTIC_RM_RF_ROOT_PATTERN));
    }

    if cmd == "dd" && dd_writes_device(args) {
        return Some(("hs.dd-to-device", SEMANTIC_DD_DEVICE_PATTERN));
    }

    None
}

fn command_words(words: &[String]) -> Option<&[String]> {
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
            word if is_assignment(word) => index += 1,
            _ => break,
        }
    }
    words.get(index..)
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

fn shell_c_payload(args: &[String]) -> Option<&str> {
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

fn rm_rf_absolute(args: &[String]) -> bool {
    let mut recursive = false;
    let mut force = false;
    let mut absolute = false;

    for arg in args {
        if arg == "--" {
            continue;
        }
        if arg == "--recursive" {
            recursive = true;
            continue;
        }
        if arg == "--force" {
            force = true;
            continue;
        }
        if let Some(flags) = arg.strip_prefix('-')
            && !flags.is_empty()
            && flags.chars().all(|ch| ch.is_ascii_alphabetic())
        {
            recursive |= flags.contains('r') || flags.contains('R');
            force |= flags.contains('f');
            continue;
        }
        absolute |= arg == "/" || arg.starts_with('/');
    }

    recursive && force && absolute
}

fn dd_writes_device(args: &[String]) -> bool {
    args.iter().any(|arg| arg.starts_with("of=/dev/"))
}

fn xargs_invokes_rm_rf(args: &[String]) -> bool {
    args.windows(3)
        .any(|window| window[0] == "rm" && rm_rf_flags(&window[1..]))
        || args
            .windows(2)
            .any(|window| window[0] == "rm" && rm_rf_flags(&window[1..]))
}

fn rm_rf_flags(args: &[String]) -> bool {
    let mut recursive = false;
    let mut force = false;
    for arg in args {
        if let Some(flags) = arg.strip_prefix('-') {
            recursive |= flags.contains('r') || flags.contains('R');
            force |= flags.contains('f');
        }
    }
    recursive && force
}

fn shell_segments(command: &str) -> Vec<Vec<String>> {
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

fn command_substitutions(command: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rm_rf_root_is_caught() {
        let caps = vec![Capability::new("proc.exec:rm -rf /")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn benign_ls_is_not_caught() {
        let caps = vec![Capability::new("proc.exec:ls -la")];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn dd_of_device_is_caught() {
        let caps = vec![Capability::new("proc.exec:dd if=/dev/zero of=/dev/sda")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn fork_bomb_caught() {
        let caps = vec![Capability::new("proc.exec::(){ :|:& };:")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn bash_c_wrapper_rm_rf_root_caught() {
        let caps = vec![Capability::new("proc.exec:bash -c 'rm -rf /'")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn sh_c_wrapper_rm_rf_root_caught() {
        let caps = vec![Capability::new("proc.exec:sh -c \"rm -rf /home\"")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn env_prefix_rm_rf_caught() {
        let caps = vec![Capability::new("proc.exec:env DEBUG=1 rm -rf /var")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn sudo_wrapper_rm_rf_caught() {
        let caps = vec![Capability::new("proc.exec:sudo bash -c 'rm -rf /var/log'")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn xargs_rm_rf_caught() {
        let caps = vec![Capability::new("proc.exec:xargs rm -rf --no-preserve-root")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn relative_rm_rf_is_not_hardstopped() {
        // Relative paths (no leading `/`) are out of hardstop scope —
        // they're covered by policy rules at the project layer.
        let caps = vec![Capability::new("proc.exec:rm -rf ./build")];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn bash_c_legitimate_non_rm_passes() {
        // bash -c wrapping a non-destructive command must not be
        // caught by the wrapper hardstops.
        let caps = vec![Capability::new("proc.exec:bash -c 'ls -la /tmp'")];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn quoted_fixture_data_is_not_hardstopped() {
        let caps = vec![Capability::new(
            r#"proc.exec:echo '{"tool_input":{"command":"rm -rf /"}}' | gommage-mcp"#,
        )];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn bash_c_echoing_fixture_data_is_not_hardstopped() {
        let caps = vec![Capability::new(
            r#"proc.exec:bash -c 'echo {"command":"rm -rf /"}'"#,
        )];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn compound_rm_rf_root_is_caught() {
        let caps = vec![Capability::new("proc.exec:echo ok; rm -rf /")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn newline_rm_rf_root_is_caught() {
        let caps = vec![Capability::new("proc.exec:echo ok\nrm -rf /")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn command_substitution_rm_rf_root_is_caught() {
        let caps = vec![Capability::new(r#"proc.exec:echo "$(rm -rf /)""#)];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn quoted_dd_fixture_data_is_not_hardstopped() {
        let caps = vec![Capability::new(
            r#"proc.exec:echo '{"command":"dd if=/dev/zero of=/dev/sda"}'"#,
        )];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn compound_dd_to_device_is_caught() {
        let caps = vec![Capability::new(
            "proc.exec:printf ok; dd if=/dev/zero of=/dev/sda",
        )];
        assert!(check(&caps).is_some());
    }
}
