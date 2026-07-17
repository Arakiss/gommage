use super::*;

/// Parse Git push destination semantics from AST-backed argv.
pub(crate) fn git_push_effects(analysis: &ShellAnalysis) -> EffectSet<GitPushEffect> {
    let mut out = EffectSet::default();
    for reason in &analysis.ambiguities {
        out.ambiguity(reason);
    }
    for command in &analysis.commands {
        let Ok(head) = command.trusted_effective_head() else {
            continue;
        };
        if head != "git" {
            continue;
        }
        let Some(push_args) = git_push_args(command.effective_args(), &mut out) else {
            continue;
        };
        parse_git_push(push_args, &mut out);
        out.push(GitPushEffect::Network);
    }
    out
}

pub(super) fn git_push_args<'a>(
    args: &'a [ShellWord],
    out: &mut EffectSet<GitPushEffect>,
) -> Option<&'a [ShellWord]> {
    let mut i = 0;
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-git-subcommand");
            return None;
        };
        if arg == "push" {
            return Some(&args[i + 1..]);
        }
        if arg == "--" {
            return None;
        }
        if matches!(
            arg,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            let Some(value) = args.get(i + 1) else {
                out.ambiguity("missing-git-global-option-value");
                return None;
            };
            if value.static_value().is_err() {
                out.ambiguity("dynamic-git-global-option-value");
                return None;
            }
            i += 2;
        } else if arg.starts_with("--git-dir=")
            || arg.starts_with("--work-tree=")
            || arg.starts_with("--namespace=")
            || arg.starts_with("--config-env=")
            || matches!(
                arg,
                "--bare"
                    | "--no-pager"
                    | "--literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
            )
        {
            i += 1;
        } else if arg.starts_with('-') {
            out.ambiguity("unknown-git-global-option");
            return None;
        } else {
            return None;
        }
    }
    None
}

pub(super) fn parse_git_push(args: &[ShellWord], out: &mut EffectSet<GitPushEffect>) {
    let mut positionals = Vec::new();
    let mut delete = false;
    let mut wide_all = false;
    let mut wide_tags = false;
    let mut follow_tags = false;
    let mut repository_from_option: Option<&ShellWord> = None;
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-git-push-argument");
            return;
        };
        if options && arg == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options && arg.starts_with('-') && arg != "-" {
            match arg {
                "-f" | "--force" => out.push(GitPushEffect::Force),
                "-d" | "--delete" => delete = true,
                "--all" => wide_all = true,
                "--tags" => wide_tags = true,
                "--follow-tags" => follow_tags = true,
                "--prune" => out.ambiguity("git-prune-destination"),
                "--mirror" => {
                    out.push(GitPushEffect::Force);
                    out.ambiguity("git-mirror-destination");
                }
                "--force-with-lease" | "--force-if-includes" => out.push(GitPushEffect::Force),
                "--repo" => {
                    let Some(repository) = args.get(i + 1) else {
                        out.ambiguity("missing-git-repository");
                        return;
                    };
                    repository_from_option = Some(repository);
                    i += 1;
                }
                "--receive-pack"
                | "--exec"
                | "-o"
                | "--push-option"
                | "--server-option"
                | "--recurse-submodules" => {
                    let Some(value) = args.get(i + 1) else {
                        out.ambiguity("missing-git-push-option-value");
                        return;
                    };
                    if value.static_value().is_err() {
                        out.ambiguity("dynamic-git-push-option-value");
                        return;
                    }
                    i += 1;
                }
                "-q" | "--quiet" | "-v" | "--verbose" | "-n" | "--dry-run" | "--porcelain"
                | "-u" | "--set-upstream" | "--atomic" | "--no-verify" | "--signed" => {}
                arg if arg.starts_with("--force-with-lease=") => out.push(GitPushEffect::Force),
                arg if arg.starts_with("--repo=") => {
                    let repository = arg.trim_start_matches("--repo=");
                    if repository.is_empty() {
                        out.ambiguity("missing-git-repository");
                        return;
                    }
                    repository_from_option = Some(&args[i]);
                }
                arg if arg.starts_with("--receive-pack=")
                    || arg.starts_with("--exec=")
                    || arg.starts_with("--push-option=")
                    || arg.starts_with("--server-option=")
                    || arg.starts_with("--recurse-submodules=")
                    || arg.starts_with("--signed=") => {}
                arg if arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..]
                        .chars()
                        .all(|flag| matches!(flag, 'f' | 'd' | 'q' | 'v' | 'n' | 'u')) =>
                {
                    if arg[1..].contains('f') {
                        out.push(GitPushEffect::Force);
                    }
                    if arg[1..].contains('d') {
                        delete = true;
                    }
                }
                _ => {
                    out.ambiguity("unknown-git-push-option");
                    return;
                }
            }
            i += 1;
            continue;
        }
        positionals.push(&args[i]);
        i += 1;
    }

    if wide_all {
        out.push(GitPushEffect::Destination("refs/heads/<all>".to_string()));
    }
    if wide_tags {
        out.push(GitPushEffect::Destination("refs/tags/<all>".to_string()));
    }
    if follow_tags {
        out.push(GitPushEffect::Destination(
            "refs/tags/<followed>".to_string(),
        ));
    }

    if let Some(repository) = repository_from_option {
        if repository.static_value().is_err() {
            out.ambiguity("dynamic-git-repository");
        }
    } else if let Some(repository) = positionals.first()
        && repository.static_value().is_err()
    {
        out.ambiguity("dynamic-git-repository");
    }

    // The first positional is the optional remote. With no positionals at all,
    // Git pushes the configured current branch.
    if positionals.is_empty() {
        if !wide_all && !wide_tags && !follow_tags {
            out.push(GitPushEffect::CurrentBranch);
        }
        return;
    }
    let refspecs = if repository_from_option.is_some() {
        positionals.as_slice()
    } else {
        &positionals[1..]
    };
    if refspecs.is_empty() {
        if !wide_all && !wide_tags && !follow_tags {
            out.push(GitPushEffect::CurrentBranch);
        }
        return;
    }

    let mut index = 0;
    while index < refspecs.len() {
        let Ok(spec) = refspecs[index].static_value() else {
            out.ambiguity("dynamic-git-refspec");
            index += 1;
            continue;
        };
        if spec == "tag" {
            if let Some(tag) = refspecs
                .get(index + 1)
                .and_then(|word| word.static_value().ok())
            {
                let destination = format!("refs/tags/{}", tag.trim_start_matches("refs/tags/"));
                if delete {
                    out.push(GitPushEffect::Delete(destination.clone()));
                }
                out.push(GitPushEffect::Destination(destination));
                index += 2;
                continue;
            }
            out.ambiguity("missing-tag-refspec");
            break;
        }
        parse_refspec(spec, delete, out);
        index += 1;
    }
}

pub(super) fn parse_refspec(spec: &str, delete_option: bool, out: &mut EffectSet<GitPushEffect>) {
    let (forced, spec) = spec
        .strip_prefix('+')
        .map_or((false, spec), |stripped| (true, stripped));
    if forced {
        out.push(GitPushEffect::Force);
    }
    let (source, destination) = spec.split_once(':').map_or((spec, spec), |parts| parts);
    let deleting = delete_option || source.is_empty();
    let Some(destination) = canonical_git_destination(destination, source) else {
        out.ambiguity("ambiguous-git-destination");
        return;
    };
    if deleting {
        out.push(GitPushEffect::Delete(destination.clone()));
    }
    out.push(GitPushEffect::Destination(destination));
}

pub(super) fn canonical_git_destination(destination: &str, source: &str) -> Option<String> {
    if destination.is_empty() {
        return None;
    }
    if destination.starts_with("refs/") {
        return Some(destination.to_string());
    }
    if destination.contains("..")
        || destination.contains(['~', '^', ':', '?', '*', '[', '\\'])
        || destination.ends_with('.')
        || destination.starts_with('.')
    {
        return None;
    }
    if matches!(destination, "HEAD" | "@") && destination == source {
        return None;
    }
    if source.starts_with("refs/") && destination == source {
        return None;
    }
    if source.starts_with("refs/tags/") {
        return Some(format!("refs/tags/{destination}"));
    }
    Some(format!("refs/heads/{destination}"))
}
