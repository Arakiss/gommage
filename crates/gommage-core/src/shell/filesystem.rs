use super::*;

/// Convert parsed commands into deterministic filesystem effects.
pub(crate) fn filesystem_effects(
    analysis: &ShellAnalysis,
    cwd: Option<&str>,
) -> EffectSet<FsEffect> {
    let mut out = EffectSet::default();
    let supplied_cwd = cwd.is_some();
    let cwd = trusted_cwd(cwd);
    if supplied_cwd && cwd.is_none() {
        out.ambiguity("invalid-cwd");
    }
    let mut cwd_may_have_changed = false;
    for command in &analysis.commands {
        let effect_cwd = (!cwd_may_have_changed).then_some(cwd.as_deref()).flatten();
        let first_effect = out.effects.len();
        for redirect in &command.redirections {
            match static_path(&redirect.target, effect_cwd) {
                Ok(path) => out.push(FsEffect {
                    kind: match redirect.kind {
                        RedirectionKind::Read => FsEffectKind::Read,
                        RedirectionKind::Write => FsEffectKind::Write,
                    },
                    path,
                }),
                Err(reason) => out.ambiguity(reason),
            }
        }

        if let Ok(head) = command.trusted_effective_head() {
            let args = command.effective_args();
            collect_gommage_cli_filesystem_effects(
                command,
                effect_cwd,
                cwd_may_have_changed,
                &mut out,
            );
            match head {
                "cat" | "head" | "tail" | "less" | "od" | "xxd" | "base64" | "strings" | "file" => {
                    collect_read_operands(head, args, effect_cwd, &mut out)
                }
                "cp" | "install" => collect_copy_effects(head, args, effect_cwd, &mut out),
                "mv" => collect_move_effects(args, effect_cwd, &mut out),
                "rsync" => collect_rsync_effects(args, effect_cwd, &mut out),
                "ln" => collect_ln_effects(args, effect_cwd, &mut out),
                "touch" | "mkdir" | "rm" => {
                    collect_all_operands(head, args, effect_cwd, FsEffectKind::Write, &mut out)
                }
                "tee" => {
                    collect_all_operands("tee", args, effect_cwd, FsEffectKind::Write, &mut out)
                }
                "sed" => collect_sed_effects(args, effect_cwd, &mut out),
                "dd" => collect_dd_effects(args, effect_cwd, &mut out),
                "gh" => collect_gh_pr_merge_filesystem_effects(args, effect_cwd, &mut out),
                _ => {}
            }
        }
        if cwd_may_have_changed
            && out.effects[first_effect..]
                .iter()
                .any(|effect| path_is_cwd_relative(&effect.path))
        {
            out.ambiguity("shell-cwd-mutation");
        }
        cwd_may_have_changed |= command_changes_cwd(command);
    }
    out
}

pub(super) fn collect_gh_pr_merge_filesystem_effects(
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let Some(merge_index) = args
        .iter()
        .position(|word| word.static_value().ok() == Some("merge"))
    else {
        return;
    };
    if !args[..merge_index]
        .iter()
        .any(|word| word.static_value().ok() == Some("pr"))
    {
        return;
    }

    let mut index = merge_index + 1;
    while index < args.len() {
        let word = &args[index];
        match word.static_value() {
            Ok("-F" | "--body-file") => {
                let Some(path) = args.get(index + 1) else {
                    out.ambiguity("missing-gh-pr-merge-body-file");
                    return;
                };
                collect_gh_pr_merge_body_file(path, cwd, out);
                index += 2;
            }
            Ok(value) if value.starts_with("--body-file=") => {
                let path = static_suffix_word(word, "--body-file=");
                collect_gh_pr_merge_body_file(&path, cwd, out);
                index += 1;
            }
            Ok(value) if value.starts_with("-F") && value.len() > 2 => {
                let path = static_suffix_word(word, "-F");
                collect_gh_pr_merge_body_file(&path, cwd, out);
                index += 1;
            }
            Err(_)
                if word.raw.starts_with("--body-file=")
                    || (word.raw.starts_with("-F") && word.raw.len() > 2) =>
            {
                out.ambiguity(word.ambiguity.unwrap_or("dynamic-path"));
                index += 1;
            }
            Ok(
                "-A"
                | "--author-email"
                | "-b"
                | "--body"
                | "--match-head-commit"
                | "-t"
                | "--subject",
            ) => index += 2,
            _ => index += 1,
        }
    }
}

pub(super) fn collect_gh_pr_merge_body_file(
    word: &ShellWord,
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if word.static_value().ok() == Some("-") {
        return;
    }
    add_path_effect(word, cwd, FsEffectKind::Read, out);
}

pub(super) fn static_suffix_word(word: &ShellWord, prefix: &str) -> ShellWord {
    let value = word
        .static_value()
        .expect("suffix extraction requires a static word")[prefix.len()..]
        .to_string();
    ShellWord {
        raw: value.clone(),
        value: Some(value),
        provenance: word.provenance.clone(),
        ambiguity: None,
    }
}

pub(super) fn collect_gommage_cli_filesystem_effects(
    command: &ShellCommand,
    cwd: Option<&str>,
    cwd_may_have_changed: bool,
    out: &mut EffectSet<FsEffect>,
) {
    let Some(raw) = gommage_invocation_words(command, out) else {
        return;
    };
    let argv = strip_gommage_home_word_options(&raw);
    if argv.iter().any(|word| {
        word.static_value()
            .is_ok_and(|value| matches!(value, "-h" | "--help"))
    }) {
        return;
    }
    let Some(top) = argv.first().and_then(|word| word.static_value().ok()) else {
        return;
    };

    match top {
        "approval" => match gommage_static_word(&argv, 1) {
            Some("callback") => {
                collect_gommage_path_options(&argv, "--body", cwd, FsEffectKind::Read, out)
            }
            Some("evidence") => {
                collect_gommage_path_options(&argv, "--output", cwd, FsEffectKind::Write, out)
            }
            _ => {}
        },
        "report" if gommage_static_word(&argv, 1) == Some("bundle") => {
            collect_gommage_path_options(&argv, "--output", cwd, FsEffectKind::Write, out);
        }
        "upgrade" => collect_gommage_upgrade_paths(&argv, cwd, out),
        "project" if gommage_static_word(&argv, 1) == Some("init") => {
            if cwd_may_have_changed
                && !gommage_has_flag(&argv, "--dry-run")
                && gommage_path_option_words(&argv, "--root", out).is_empty()
            {
                out.ambiguity("shell-cwd-mutation");
            }
            collect_gommage_project_paths(&argv, cwd, out);
        }
        "release" if gommage_static_word(&argv, 1) == Some("verify") => {
            collect_gommage_release_paths(&argv, cwd, out);
        }
        "replay" => {
            collect_gommage_path_options(&argv, "--audit", cwd, FsEffectKind::Read, out);
            collect_gommage_path_options(&argv, "--policy", cwd, FsEffectKind::Read, out);
        }
        "policy" => collect_gommage_policy_read_paths(&argv, cwd, out),
        "beta" if gommage_static_word(&argv, 1) == Some("check") => {
            collect_gommage_path_options(&argv, "--policy-test", cwd, FsEffectKind::Read, out);
        }
        "verify" => {
            collect_gommage_path_options(&argv, "--policy-test", cwd, FsEffectKind::Read, out)
        }
        _ => {}
    }
}

pub(super) fn strip_gommage_home_word_options(raw: &[ShellWord]) -> Vec<ShellWord> {
    let mut argv = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let value = raw[index].static_value().ok();
        if value == Some("--home") {
            index += 2;
        } else if value.is_some_and(|value| value.starts_with("--home="))
            || raw[index].raw.starts_with("--home=")
        {
            index += 1;
        } else {
            argv.push(raw[index].clone());
            index += 1;
        }
    }
    argv
}

pub(super) fn gommage_static_word(argv: &[ShellWord], index: usize) -> Option<&str> {
    argv.get(index)?.static_value().ok()
}

pub(super) fn gommage_path_option_words<T: PartialEq>(
    argv: &[ShellWord],
    flag: &str,
    out: &mut EffectSet<T>,
) -> Vec<ShellWord> {
    let attached_prefix = format!("{flag}=");
    let mut paths = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        match argv[index].static_value() {
            Ok(value) if value == flag => {
                let Some(path) = argv.get(index + 1) else {
                    out.ambiguity("missing-gommage-path-option-value");
                    break;
                };
                paths.push(path.clone());
                index += 2;
            }
            Ok(value) if value.starts_with(&attached_prefix) => {
                let path = &value[attached_prefix.len()..];
                if path.is_empty() {
                    out.ambiguity("missing-gommage-path-option-value");
                } else {
                    let mut word = argv[index].clone();
                    word.raw = word
                        .raw
                        .split_once('=')
                        .map_or_else(|| path.to_string(), |(_, raw)| raw.to_string());
                    word.value = Some(path.to_string());
                    paths.push(word);
                }
                index += 1;
            }
            Err(reason) if argv[index].raw.starts_with(&attached_prefix) => {
                out.ambiguity(reason);
                index += 1;
            }
            _ => index += 1,
        }
    }
    paths
}

pub(super) fn collect_gommage_path_options(
    argv: &[ShellWord],
    flag: &str,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    for path in gommage_path_option_words(argv, flag, out) {
        add_path_effect(&path, cwd, kind, out);
    }
}

pub(super) fn collect_gommage_upgrade_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if gommage_has_flag(argv, "--dry-run") {
        return;
    }

    for installer in gommage_path_option_words(argv, "--installer", out) {
        match installer.static_value() {
            Ok(value) if value.starts_with("https://") || value.starts_with("http://") => {}
            Ok(value) if value.starts_with("file://") => {
                add_synthetic_path(
                    value.trim_start_matches("file://"),
                    cwd,
                    FsEffectKind::Read,
                    out,
                );
            }
            Ok(_) => add_path_effect(&installer, cwd, FsEffectKind::Read, out),
            Err(reason) => out.ambiguity(reason),
        }
    }

    if gommage_has_flag(argv, "--skill-only") {
        return;
    }
    for bin_dir in gommage_path_option_words(argv, "--bin-dir", out) {
        let Some(dir) = normalized_effect_path(&bin_dir, cwd, out) else {
            continue;
        };
        out.push(FsEffect {
            kind: FsEffectKind::Write,
            path: dir.clone(),
        });
        for binary in ["gommage", "gommage-daemon", "gommage-mcp"] {
            out.push(FsEffect {
                kind: FsEffectKind::Write,
                path: child_effect_path(&dir, binary),
            });
        }
    }
}

pub(super) fn collect_gommage_project_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if gommage_has_flag(argv, "--dry-run") {
        return;
    }
    let roots = gommage_path_option_words(argv, "--root", out);
    let roots = if roots.is_empty() {
        cwd.map(|cwd| {
            vec![ShellWord {
                raw: cwd.to_string(),
                value: Some(cwd.to_string()),
                provenance: WordProvenance::default(),
                ambiguity: None,
            }]
        })
        .unwrap_or_default()
    } else {
        roots
    };
    for root in roots {
        let Some(root) = normalized_effect_path(&root, cwd, out) else {
            continue;
        };
        for relative in [
            ".gommage/policy.d/20-project.yaml",
            ".gommage/policy-fixtures.yaml",
            ".gommage/README.md",
        ] {
            out.push(FsEffect {
                kind: FsEffectKind::Write,
                path: child_effect_path(&root, relative),
            });
        }
    }
}

pub(super) fn collect_gommage_release_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let dirs = gommage_path_option_words(argv, "--dir", out);
    if dirs.is_empty() {
        return;
    }
    let assets: Vec<String> = if gommage_has_flag(argv, "--all-assets") {
        gommage_release_assets()
            .iter()
            .map(|asset| (*asset).to_string())
            .collect()
    } else {
        let selected = gommage_static_option(argv, "--asset", out);
        match selected.as_deref() {
            None | Some("auto") => default_gommage_release_asset()
                .into_iter()
                .map(str::to_string)
                .collect(),
            Some(asset) if gommage_release_assets().contains(&asset) => {
                vec![asset.to_string()]
            }
            Some(_) => {
                out.ambiguity("unknown-gommage-release-asset");
                Vec::new()
            }
        }
    };
    for dir in dirs {
        let Some(dir) = normalized_effect_path(&dir, cwd, out) else {
            continue;
        };
        out.push(FsEffect {
            kind: FsEffectKind::Write,
            path: dir.clone(),
        });
        for asset in &assets {
            for name in [
                asset.to_string(),
                format!("{asset}.sha256"),
                format!("{asset}.sigstore.json"),
            ] {
                out.push(FsEffect {
                    kind: FsEffectKind::Write,
                    path: child_effect_path(&dir, &name),
                });
            }
        }
    }
}

pub(super) fn collect_gommage_policy_read_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match gommage_static_word(argv, 1) {
        Some("lint") => collect_gommage_positional_path(
            argv,
            2,
            &["--strict", "--json"],
            cwd,
            FsEffectKind::Read,
            out,
        ),
        Some("test") => {
            collect_gommage_positional_path(argv, 2, &["--json"], cwd, FsEffectKind::Read, out)
        }
        Some("diff") => {
            for flag in ["--from", "--to", "--against"] {
                collect_gommage_path_options(argv, flag, cwd, FsEffectKind::Read, out);
            }
        }
        Some("suggest") => {
            collect_gommage_path_options(argv, "--audit", cwd, FsEffectKind::Read, out)
        }
        _ => {}
    }
}

pub(super) fn collect_gommage_positional_path(
    argv: &[ShellWord],
    start: usize,
    boolean_options: &[&str],
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    for word in &argv[start..] {
        match word.static_value() {
            Ok("--") => continue,
            Ok(value) if boolean_options.contains(&value) => continue,
            Ok(value) if value.starts_with('-') => continue,
            Ok(_) => {
                add_path_effect(word, cwd, kind, out);
                return;
            }
            Err(reason) => {
                out.ambiguity(reason);
                return;
            }
        }
    }
}

pub(super) fn gommage_static_option(
    argv: &[ShellWord],
    flag: &str,
    out: &mut EffectSet<FsEffect>,
) -> Option<String> {
    gommage_path_option_words(argv, flag, out)
        .last()
        .and_then(|word| word.static_value().ok().map(str::to_string))
}

pub(super) fn gommage_has_flag(argv: &[ShellWord], flag: &str) -> bool {
    argv.iter()
        .any(|word| word.static_value().ok() == Some(flag))
}

pub(super) fn normalized_effect_path(
    word: &ShellWord,
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) -> Option<String> {
    match static_path(word, cwd) {
        Ok(path) => Some(path),
        Err(reason) => {
            out.ambiguity(reason);
            None
        }
    }
}

pub(super) fn child_effect_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{child}", parent.trim_end_matches('/'))
    }
}

pub(super) fn gommage_release_assets() -> &'static [&'static str] {
    &[
        "gommage-aarch64-darwin.tar.gz",
        "gommage-aarch64-linux.tar.gz",
        "gommage-x86_64-darwin.tar.gz",
        "gommage-x86_64-linux.tar.gz",
    ]
}

pub(super) fn default_gommage_release_asset() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("gommage-aarch64-darwin.tar.gz"),
        ("macos", "x86_64") => Some("gommage-x86_64-darwin.tar.gz"),
        ("linux", "aarch64") => Some("gommage-aarch64-linux.tar.gz"),
        ("linux", "x86_64") => Some("gommage-x86_64-linux.tar.gz"),
        _ => None,
    }
}

pub(super) fn command_changes_cwd(command: &ShellCommand) -> bool {
    match command.trusted_effective_head() {
        Ok("cd" | "chdir" | "pushd" | "popd") => true,
        Ok("builtin") => command
            .effective_args()
            .first()
            .and_then(|word| word.static_value().ok())
            .is_some_and(|command| matches!(command, "cd" | "chdir" | "pushd" | "popd")),
        _ => false,
    }
}

pub(super) fn path_is_cwd_relative(path: &str) -> bool {
    !path.starts_with('/') && path != "$HOME" && !path.starts_with("$HOME/")
}
