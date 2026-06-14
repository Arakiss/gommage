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
    for substitution in crate::shell::command_substitutions(command) {
        if let Some(hit) = semantic_proc_exec_hit(&substitution) {
            return Some(hit);
        }
    }

    for segment in crate::shell::shell_segments(command) {
        if let Some(hit) = semantic_segment_hit(&segment) {
            return Some(hit);
        }
    }
    None
}

fn semantic_segment_hit(words: &[String]) -> Option<(&'static str, &'static str)> {
    let words = crate::shell::command_words(words)?;
    let (cmd_token, args) = words.split_first()?;
    // Normalise an absolute/relative path head (`/bin/rm`, `./bin/rm`) to its
    // basename so a fully-pathed invocation hits the same hardstops.
    let cmd = crate::shell::head_basename(cmd_token);

    if matches!(cmd, "bash" | "sh" | "zsh")
        && let Some(script) = crate::shell::shell_c_payload(args)
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
    fn escaped_backtick_in_double_quotes_is_not_hardstopped() {
        // `\`rm -rf /\`` inside double quotes is a literal string, not a
        // command substitution — so a commit message documenting it must pass.
        let caps = vec![Capability::new(
            r#"proc.exec:git commit -m "deny scope: \`rm -rf /\`""#,
        )];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn unescaped_command_substitution_rm_rf_still_caught() {
        // The fix must not regress detection of a real substitution.
        let caps = vec![Capability::new(r#"proc.exec:git commit -m "$(rm -rf /)""#)];
        assert!(check(&caps).is_some());
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
