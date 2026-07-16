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
    // command substitution are handled by the AST-backed semantic analysis
    // below. Keep glob entries for single-command shapes only; broad substring
    // globs create false positives for quoted fixture data.
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
    let analysis = crate::shell::analyze(command);
    for command in &analysis.commands {
        if let Some(hit) = semantic_command_hit(command) {
            return Some(hit);
        }
    }
    None
}

fn semantic_command_hit(
    command: &crate::shell::ShellCommand,
) -> Option<(&'static str, &'static str)> {
    let cmd = command.effective_head().ok()?;
    let args = command.effective_args();

    if cmd == "xargs" && xargs_invokes_rm_rf(args) {
        return Some(("hs.xargs-rm-rf", "proc.exec:*xargs rm -rf*"));
    }

    if cmd == "rm" && rm_rf_absolute(args) {
        return Some(("hs.rm-rf-root", SEMANTIC_RM_RF_ROOT_PATTERN));
    }

    if cmd == "dd" && dd_writes_device(args) {
        return Some(("hs.dd-to-device", SEMANTIC_DD_DEVICE_PATTERN));
    }

    if cmd.starts_with("mkfs") {
        return Some(("hs.mkfs", "proc.exec:mkfs*"));
    }

    if cmd == "shred" && args.iter().any(is_device_path) {
        return Some(("hs.wipe-disk", "proc.exec:shred /dev/*"));
    }

    if cmd == "chmod" && chmod_recursively_targets_root(args) {
        return Some(("hs.chmod-system", "proc.exec:chmod -R * /"));
    }

    None
}

fn rm_rf_absolute(args: &[crate::shell::ShellWord]) -> bool {
    let mut recursive = false;
    let mut force = false;
    let mut absolute = false;
    let mut options = true;

    for arg in args {
        let Ok(value) = arg.static_value() else {
            continue;
        };
        if options && value == "--" {
            options = false;
            continue;
        }
        if options && value == "--recursive" {
            recursive = true;
            continue;
        }
        if options && value == "--force" {
            force = true;
            continue;
        }
        if options
            && let Some(flags) = value.strip_prefix('-')
            && !flags.is_empty()
            && flags.chars().all(|ch| ch.is_ascii_alphabetic())
        {
            recursive |= flags.contains('r') || flags.contains('R');
            force |= flags.contains('f');
            continue;
        }
        absolute |= crate::shell::static_path(arg, None).is_ok_and(|path| {
            path.starts_with('/') || path == "$HOME" || path.starts_with("$HOME/")
        });
    }

    recursive && force && absolute
}

fn dd_writes_device(args: &[crate::shell::ShellWord]) -> bool {
    args.iter().any(|arg| {
        arg.static_value().is_ok_and(|arg| {
            arg.strip_prefix("of=").is_some_and(|path| {
                let target = crate::shell::ShellWord {
                    raw: path.to_string(),
                    value: Some(path.to_string()),
                    provenance: crate::shell::WordProvenance::default(),
                    ambiguity: None,
                };
                crate::shell::static_path(&target, None).is_ok_and(|path| path.starts_with("/dev/"))
            })
        })
    })
}

fn xargs_invokes_rm_rf(args: &[crate::shell::ShellWord]) -> bool {
    let static_args: Vec<&str> = args
        .iter()
        .filter_map(|arg| arg.static_value().ok())
        .collect();
    static_args.iter().enumerate().any(|(index, arg)| {
        crate::shell::head_basename(arg) == "rm" && rm_rf_flags(&static_args[index + 1..])
    })
}

fn rm_rf_flags(args: &[&str]) -> bool {
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

fn is_device_path(arg: &crate::shell::ShellWord) -> bool {
    crate::shell::static_path(arg, None).is_ok_and(|path| path.starts_with("/dev/"))
}

fn chmod_recursively_targets_root(args: &[crate::shell::ShellWord]) -> bool {
    let recursive = args.iter().any(|arg| {
        arg.static_value().is_ok_and(|arg| {
            arg == "--recursive"
                || arg
                    .strip_prefix('-')
                    .is_some_and(|flags| flags.contains('R'))
        })
    });
    recursive
        && args
            .iter()
            .any(|arg| crate::shell::static_path(arg, None).is_ok_and(|path| path == "/"))
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
        for command in [
            "printf ok; dd if=/dev/zero of=/dev/sda",
            "dd of=//dev/./disk2",
        ] {
            let caps = vec![Capability::new(format!("proc.exec:{command}"))];
            assert!(check(&caps).is_some(), "must hard-stop {command:?}");
        }
    }

    #[test]
    fn home_aliases_and_lexical_variants_are_caught() {
        for command in [
            "rm -rf $HOME",
            r#"rm -rf "${HOME}//.""#,
            "rm --recursive --force ~/./cache",
            "rm -fr ////var//./tmp",
        ] {
            let caps = vec![Capability::new(format!("proc.exec:{command}"))];
            assert!(check(&caps).is_some(), "must hard-stop {command:?}");
        }
    }

    #[test]
    fn recursively_unwrapped_rm_is_caught() {
        for command in [
            "command rm -rf /",
            "exec env X=1 /bin/rm --recursive --force /var",
            "sudo -- timeout 2 sh -c 'rm -rf /home'",
            "env -i HOME=/tmp command rm -rf $HOME",
        ] {
            let caps = vec![Capability::new(format!("proc.exec:{command}"))];
            assert!(check(&caps).is_some(), "must hard-stop {command:?}");
        }
    }

    #[test]
    fn quoted_and_relative_rm_operands_are_not_hardstopped() {
        for command in [
            "echo 'rm -rf /'",
            "printf '%s' '$HOME'",
            "rm -rf '$HOME'",
            r"rm -rf \$HOME",
            "rm -rf ./target",
            "command -v rm",
            r#"sh -c 'printf "%s" "rm -rf /"'"#,
        ] {
            let caps = vec![Capability::new(format!("proc.exec:{command}"))];
            assert!(check(&caps).is_none(), "must not hard-stop {command:?}");
        }
    }

    #[test]
    fn wrappers_cannot_hide_other_compiled_invariants() {
        for command in [
            "command mkfs.ext4 /dev/sda",
            "exec env X=1 dd if=/dev/zero of=/dev/disk2",
            "sudo -- shred /dev/nvme0n1",
            "timeout 2 chmod -R 000 /",
        ] {
            let caps = vec![Capability::new(format!("proc.exec:{command}"))];
            assert!(check(&caps).is_some(), "must hard-stop {command:?}");
        }
    }
}
