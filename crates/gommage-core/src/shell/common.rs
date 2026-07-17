use super::*;

pub(crate) fn head_basename(token: &str) -> &str {
    token.rsplit_once('/').map_or(
        token,
        |(_, base)| if base.is_empty() { token } else { base },
    )
}

/// Normalize an executable token only when its origin is deterministic enough
/// to inherit typed authority. Bare names deliberately retain PATH semantics;
/// explicit paths are accepted only from conventional installation roots.
pub(crate) fn trusted_executable_basename(token: &str) -> Result<&str, Ambiguity> {
    if !token.contains('/') {
        return Ok(token);
    }
    let Some((directory, basename)) = token.rsplit_once('/') else {
        return Err("untrusted-executable-path");
    };
    if basename.is_empty() || !trusted_executable_directory(directory) {
        return Err("untrusted-executable-path");
    }
    Ok(basename)
}

pub(super) fn trusted_executable_directory(directory: &str) -> bool {
    matches!(
        directory,
        "/bin" | "/usr/bin" | "/usr/local/bin" | "/opt/homebrew/bin" | "/opt/local/bin"
    ) || matches!(directory, "$HOME/.cargo/bin" | "$HOME/.local/bin")
}

pub(super) fn privileged_executable_name(name: &str) -> bool {
    name == "busybox"
        || interpreter_kind(name).is_some()
        || matches!(
            name,
            "gommage"
                | "gommage-daemon"
                | "gh"
                | "git"
                | "cargo"
                | "builtin"
                | "command"
                | "exec"
                | "env"
                | "sudo"
                | "doas"
                | "timeout"
                | "time"
                | "nice"
                | "nohup"
                | "noglob"
                | "stdbuf"
                | "setsid"
                | "bash"
                | "sh"
                | "zsh"
                | "eval"
                | "watch"
                | "xargs"
                | "find"
                | "systemctl"
                | "launchctl"
                | "service"
                | "pkill"
                | "killall"
        )
}

pub(super) fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}
