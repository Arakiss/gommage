use super::*;

/// Parse `gh pr merge` into a repository-and-PR-bound effect.
///
/// Repository context is accepted only when it is explicit in argv or carried
/// by a full pull-request URL. The analyzer deliberately does not consult the
/// process environment, Git remotes, the current directory, or the network.
pub(crate) fn gh_pr_merge_effects(analysis: &ShellAnalysis) -> EffectSet<GhPrMergeEffect> {
    gh_pr_merge_effects_inner(analysis, 0)
}

pub(super) fn gh_pr_merge_effects_inner(
    analysis: &ShellAnalysis,
    dispatcher_depth: usize,
) -> EffectSet<GhPrMergeEffect> {
    let mut out = EffectSet::default();
    for reason in &analysis.ambiguities {
        out.ambiguity(reason);
    }
    for command in &analysis.commands {
        let Ok(head) = command.trusted_effective_head() else {
            continue;
        };
        match head {
            "gh" => parse_gh_pr_merge(command.effective_args(), &mut out),
            "eval" => {
                classify_gh_eval_dispatch(command.effective_args(), dispatcher_depth, &mut out)
            }
            "watch" => classify_repeated_gh_dispatch(
                "watch-gh-pr-merge-command",
                command.effective_args(),
                &mut out,
            ),
            "xargs" => classify_repeated_gh_dispatch(
                "xargs-gh-pr-merge-command",
                command.effective_args(),
                &mut out,
            ),
            "find" => classify_find_gh_dispatch(command.effective_args(), &mut out),
            _ => {}
        }
    }
    if !out.effects.is_empty() && analysis.commands.len() != 1 {
        out.effects.clear();
        out.ambiguity("compound-gh-pr-merge-command");
    }
    out
}

pub(super) fn classify_gh_eval_dispatch(
    args: &[ShellWord],
    depth: usize,
    out: &mut EffectSet<GhPrMergeEffect>,
) {
    if depth >= 4 {
        out.ambiguity("gh-pr-merge-dispatcher-depth");
        return;
    }
    let Some(payload) = static_eval_payload(args, out) else {
        return;
    };
    merge_effect_set(
        out,
        gh_pr_merge_effects_inner(&analyze(&payload), depth + 1),
    );
}

pub(super) fn classify_repeated_gh_dispatch(
    ambiguity: Ambiguity,
    args: &[ShellWord],
    out: &mut EffectSet<GhPrMergeEffect>,
) {
    if dispatcher_words_may_invoke_gh_pr_merge(args) {
        out.ambiguity(ambiguity);
    }
}

pub(super) fn classify_find_gh_dispatch(args: &[ShellWord], out: &mut EffectSet<GhPrMergeEffect>) {
    let mut index = 0;
    while index < args.len() {
        let Ok(arg) = args[index].static_value() else {
            index += 1;
            continue;
        };
        if !matches!(arg, "-exec" | "-execdir" | "-ok" | "-okdir") {
            index += 1;
            continue;
        }
        let start = index + 1;
        let end = args[start..]
            .iter()
            .position(|word| {
                word.static_value()
                    .is_ok_and(|value| matches!(value, ";" | "+"))
            })
            .map(|offset| start + offset)
            .unwrap_or(args.len());
        if dispatcher_words_may_invoke_gh_pr_merge(&args[start..end]) {
            out.ambiguity("find-exec-gh-pr-merge-command");
        }
        index = end.saturating_add(1);
    }
}

pub(super) fn dispatcher_words_may_invoke_gh_pr_merge(words: &[ShellWord]) -> bool {
    let rendered = words
        .iter()
        .map(|word| word.static_value().unwrap_or(&word.raw))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let mentions_gh = words.iter().any(|word| {
        word.static_value()
            .is_ok_and(|value| head_basename(value).eq_ignore_ascii_case("gh"))
    }) || rendered.contains("gh pr");
    mentions_gh && rendered.contains("merge")
}

pub(super) fn parse_gh_pr_merge(args: &[ShellWord], out: &mut EffectSet<GhPrMergeEffect>) {
    let mut residual = Vec::with_capacity(args.len());
    let mut repository = None;
    let mut repository_error = None;
    let option_value_indices = gh_pr_merge_option_value_indices(args);
    let mut index = 0;

    while index < args.len() {
        if option_value_indices.contains(&index) {
            residual.push(&args[index]);
            index += 1;
            continue;
        }
        let word = &args[index];
        match word.static_value() {
            Ok("-R" | "--repo") => {
                let Some(value) = args.get(index + 1) else {
                    repository_error = Some("missing-gh-pr-merge-repository");
                    index += 1;
                    continue;
                };
                match value.static_value() {
                    Ok(value) => merge_gh_repository(
                        &mut repository,
                        canonical_gh_repository(value),
                        &mut repository_error,
                    ),
                    Err(_) => repository_error = Some("dynamic-gh-pr-merge-repository"),
                }
                index += 2;
            }
            Ok(value) if value.starts_with("--repo=") => {
                let value = &value["--repo=".len()..];
                merge_gh_repository(
                    &mut repository,
                    canonical_gh_repository(value),
                    &mut repository_error,
                );
                index += 1;
            }
            Ok(value) if value.starts_with("-R") && value.len() > 2 => {
                merge_gh_repository(
                    &mut repository,
                    canonical_gh_repository(&value[2..]),
                    &mut repository_error,
                );
                index += 1;
            }
            Err(_)
                if word.raw.starts_with("--repo=")
                    || (word.raw.starts_with("-R") && word.raw.len() > 2) =>
            {
                repository_error = Some("dynamic-gh-pr-merge-repository");
                index += 1;
            }
            _ => {
                residual.push(word);
                index += 1;
            }
        }
    }

    let Some(pr_word) = residual.first() else {
        return;
    };
    match pr_word.static_value() {
        Ok("pr") => {}
        Err(_) if residual.get(1).and_then(|word| word.static_value().ok()) == Some("merge") => {
            out.ambiguity("dynamic-gh-command");
            return;
        }
        _ => {
            if gh_words_contain_pr_merge(&residual) {
                out.ambiguity("unsupported-gh-pr-merge-shape");
            }
            return;
        }
    }
    match residual.get(1).map(|word| word.static_value()) {
        Some(Ok("merge")) => {}
        Some(Err(_)) => {
            out.ambiguity("dynamic-gh-pr-command");
            return;
        }
        _ => {
            if gh_words_contain_pr_merge(&residual) {
                out.ambiguity("unsupported-gh-pr-merge-shape");
            }
            return;
        }
    }

    if let Some(reason) = repository_error {
        out.ambiguity(reason);
        return;
    }

    let mut admin = false;
    let mut delete_branch = false;
    let mut body_file = false;
    let mut matched_head_commit = None;
    let mut target: Option<&ShellWord> = None;
    let mut index = 2;
    while index < residual.len() {
        let word = residual[index];
        match word.static_value() {
            Ok("--admin") => {
                admin = true;
                index += 1;
            }
            Ok(value) if value.starts_with("--admin=") => {
                match &value["--admin=".len()..] {
                    "true" => admin = true,
                    "false" => admin = false,
                    _ => {
                        out.ambiguity("invalid-gh-pr-merge-admin-value");
                        return;
                    }
                }
                index += 1;
            }
            Ok("-d" | "--delete-branch") => {
                delete_branch = true;
                index += 1;
            }
            Ok(value) if value.starts_with("--delete-branch=") => {
                match &value["--delete-branch=".len()..] {
                    "true" => delete_branch = true,
                    "false" => delete_branch = false,
                    _ => {
                        out.ambiguity("invalid-gh-pr-merge-boolean-value");
                        return;
                    }
                }
                index += 1;
            }
            Ok(
                "--auto" | "--disable-auto" | "-m" | "--merge" | "-r" | "--rebase" | "-s"
                | "--squash",
            ) => index += 1,
            Ok(value)
                if [
                    "--auto=",
                    "--disable-auto=",
                    "--merge=",
                    "--rebase=",
                    "--squash=",
                ]
                .iter()
                .any(|prefix| value.starts_with(prefix)) =>
            {
                let Some((_, boolean)) = value.split_once('=') else {
                    unreachable!("matched option prefix contains equals")
                };
                if !matches!(boolean, "true" | "false") {
                    out.ambiguity("invalid-gh-pr-merge-boolean-value");
                    return;
                }
                index += 1;
            }
            Ok("--match-head-commit") => {
                let Some(value) = residual.get(index + 1) else {
                    out.ambiguity("missing-gh-pr-merge-head-commit");
                    return;
                };
                let Ok(value) = value.static_value() else {
                    out.ambiguity(value.ambiguity.unwrap_or("dynamic-gh-pr-merge-head-commit"));
                    return;
                };
                if !valid_git_object_id(value) {
                    out.ambiguity("invalid-gh-pr-merge-head-commit");
                    return;
                }
                if matched_head_commit.replace(value).is_some() {
                    out.ambiguity("multiple-gh-pr-merge-head-commits");
                    return;
                }
                index += 2;
            }
            Ok(value) if value.starts_with("--match-head-commit=") => {
                let value = &value["--match-head-commit=".len()..];
                if !valid_git_object_id(value) {
                    out.ambiguity("invalid-gh-pr-merge-head-commit");
                    return;
                }
                if matched_head_commit.replace(value).is_some() {
                    out.ambiguity("multiple-gh-pr-merge-head-commits");
                    return;
                }
                index += 1;
            }
            Ok("-A" | "--author-email" | "-b" | "--body" | "-t" | "--subject") => {
                let Some(value) = residual.get(index + 1) else {
                    out.ambiguity("missing-gh-pr-merge-option-value");
                    return;
                };
                if value.static_value().is_err() {
                    out.ambiguity(
                        value
                            .ambiguity
                            .unwrap_or("dynamic-gh-pr-merge-option-value"),
                    );
                    return;
                }
                index += 2;
            }
            Ok("-F" | "--body-file") => {
                let Some(value) = residual.get(index + 1) else {
                    out.ambiguity("missing-gh-pr-merge-option-value");
                    return;
                };
                if value.static_value().is_err() {
                    out.ambiguity(
                        value
                            .ambiguity
                            .unwrap_or("dynamic-gh-pr-merge-option-value"),
                    );
                    return;
                }
                body_file = true;
                index += 2;
            }
            Ok(value)
                if ["--author-email=", "--body=", "--subject="]
                    .iter()
                    .any(|prefix| value.starts_with(prefix)) =>
            {
                index += 1;
            }
            Ok(value) if value.starts_with("--body-file=") => {
                body_file = true;
                index += 1;
            }
            Ok(value)
                if ["-A", "-b", "-t"]
                    .iter()
                    .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len()) =>
            {
                index += 1;
            }
            Ok(value) if value.starts_with("-F") && value.len() > 2 => {
                body_file = true;
                index += 1;
            }
            Err(_)
                if [
                    "--author-email=",
                    "--body=",
                    "--body-file=",
                    "--subject=",
                    "-A",
                    "-b",
                    "-F",
                    "-t",
                ]
                .iter()
                .any(|prefix| word.raw.starts_with(prefix) && word.raw.len() > prefix.len()) =>
            {
                out.ambiguity(word.ambiguity.unwrap_or("dynamic-gh-pr-merge-option-value"));
                return;
            }
            Ok("--help") => return,
            Ok(value) if value.starts_with('-') => {
                out.ambiguity("unknown-gh-pr-merge-option");
                return;
            }
            Ok(_) | Err(_) => {
                if target.replace(word).is_some() {
                    out.ambiguity("multiple-gh-pr-merge-targets");
                    return;
                }
                index += 1;
            }
        }
    }

    let Some(target) = target else {
        out.ambiguity("missing-gh-pr-merge-target");
        return;
    };
    let Ok(target) = target.static_value() else {
        out.ambiguity("dynamic-gh-pr-merge-target");
        return;
    };
    let identity = match canonical_gh_pr_url(target) {
        Ok(Some((url_repository, number))) => {
            if repository
                .as_ref()
                .is_some_and(|selected| selected != &url_repository)
            {
                out.ambiguity("conflicting-gh-pr-merge-repository");
                return;
            }
            format!("{url_repository}#{number}")
        }
        Ok(None) => {
            let Some(number) = canonical_gh_pr_number(target) else {
                out.ambiguity("unsupported-gh-pr-merge-target");
                return;
            };
            let Some(repository) = repository else {
                out.ambiguity("missing-gh-pr-merge-repository");
                return;
            };
            format!("{repository}#{number}")
        }
        Err(reason) => {
            out.ambiguity(reason);
            return;
        }
    };

    if admin && matched_head_commit.is_none() {
        out.ambiguity("admin-gh-pr-merge-missing-head-commit");
        return;
    }

    out.push(GhPrMergeEffect::Merge(identity.clone()));
    if body_file {
        out.push(GhPrMergeEffect::BodyFile(identity.clone()));
    }
    if admin {
        out.push(GhPrMergeEffect::Admin(identity.clone()));
    }
    if delete_branch {
        out.push(GhPrMergeEffect::DeleteBranch(identity));
    }
}

pub(super) fn valid_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn gh_words_contain_pr_merge(words: &[&ShellWord]) -> bool {
    let mut saw_pr = false;
    for word in words {
        match word.static_value() {
            Ok("pr") => saw_pr = true,
            Ok("merge") if saw_pr => return true,
            _ => {}
        }
    }
    false
}

pub(super) fn gh_pr_merge_option_value_indices(
    args: &[ShellWord],
) -> std::collections::HashSet<usize> {
    let Some(merge_index) = args
        .iter()
        .position(|word| word.static_value().ok() == Some("merge"))
    else {
        return std::collections::HashSet::new();
    };
    let mut values = std::collections::HashSet::new();
    let mut index = merge_index + 1;
    while index < args.len() {
        if args[index].static_value().is_ok_and(|value| {
            matches!(
                value,
                "-A" | "--author-email"
                    | "-b"
                    | "--body"
                    | "-F"
                    | "--body-file"
                    | "--match-head-commit"
                    | "-t"
                    | "--subject"
            )
        }) && args.get(index + 1).is_some()
        {
            values.insert(index + 1);
            index += 2;
        } else {
            index += 1;
        }
    }
    values
}

pub(super) fn merge_gh_repository(
    selected: &mut Option<String>,
    candidate: Result<String, Ambiguity>,
    error: &mut Option<Ambiguity>,
) {
    let Ok(candidate) = candidate else {
        *error = Some("invalid-gh-pr-merge-repository");
        return;
    };
    match selected {
        Some(existing) if existing != &candidate => {
            *error = Some("conflicting-gh-pr-merge-repository")
        }
        Some(_) => {}
        None => *selected = Some(candidate),
    }
}

pub(super) fn canonical_gh_repository(value: &str) -> Result<String, Ambiguity> {
    let parts: Vec<&str> = value.split('/').collect();
    let (host, owner, repository) = match parts.as_slice() {
        [host, owner, repository] => (*host, *owner, *repository),
        _ => return Err("invalid-gh-pr-merge-repository"),
    };
    if !valid_gh_host(host)
        || !valid_gh_repository_component(owner)
        || !valid_gh_repository_component(repository)
    {
        return Err("invalid-gh-pr-merge-repository");
    }
    Ok(format!(
        "{}/{}/{}",
        host.to_ascii_lowercase(),
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase()
    ))
}

pub(super) fn canonical_gh_pr_url(value: &str) -> Result<Option<(String, u64)>, Ambiguity> {
    let Some(rest) = value.strip_prefix("https://") else {
        return if value.contains("://") {
            Err("invalid-gh-pr-merge-url")
        } else {
            Ok(None)
        };
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let parts: Vec<&str> = rest.split('/').collect();
    let [host, owner, repository, "pull", number] = parts.as_slice() else {
        return Err("invalid-gh-pr-merge-url");
    };
    let repository = canonical_gh_repository(&format!("{host}/{owner}/{repository}"))?;
    let Some(number) = canonical_gh_pr_number(number) else {
        return Err("invalid-gh-pr-merge-url");
    };
    Ok(Some((repository, number)))
}

pub(super) fn canonical_gh_pr_number(value: &str) -> Option<u64> {
    let number = value.parse::<u64>().ok()?;
    (number > 0 && number <= i64::MAX as u64).then_some(number)
}

pub(super) fn valid_gh_host(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

pub(super) fn valid_gh_repository_component(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}
