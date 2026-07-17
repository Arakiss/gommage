use crate::{Capability, ToolCall, error::GommageError};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const MAPPER_REGEX_SIZE_LIMIT_BYTES: usize = 256 * 1024;
const MAPPER_REGEX_NEST_LIMIT: u32 = 128;

/// The YAML shape of a capability mapper rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMapperRule {
    pub name: String,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub tool_pattern: Option<String>,
    /// `field_path` → regex that the field's string value must match.
    /// `field_path` supports dot notation for nested JSON: `"options.flag"`.
    ///
    /// A rule with an empty `match_input` fires for every call matching
    /// `tool` or `tool_pattern`.
    #[serde(default)]
    pub match_input: HashMap<String, String>,
    /// Templates to render into capabilities when the rule fires.
    /// Templates support `${capture_name}` (from the regexes above) and
    /// `${input.field.sub}` (dot-path into the tool call's input JSON), plus
    /// `${tool}` for the actual tool name.
    pub emit: Vec<String>,
}

#[derive(Debug)]
#[allow(dead_code)] // name/source/index are surfaced by `gommage explain` (v0.1 final)
struct CompiledRule {
    name: String,
    tool_match: ToolMatch,
    match_input: Vec<(String, Regex)>,
    emit: Vec<Template>,
    source: PathBuf,
    index: usize,
}

#[derive(Debug)]
enum ToolMatch {
    Exact(String),
    Pattern(Regex),
}

#[derive(Debug)]
struct Template {
    parts: Vec<TemplatePart>,
}

#[derive(Debug)]
enum TemplatePart {
    Literal(String),
    ToolName,
    Capture(String),
    InputPath(Vec<String>),
}

/// The capability mapper. Deterministic by construction: rules are tried in
/// load order (lexicographic filenames, then declaration order within each
/// file), and every rule whose conditions hold emits its capabilities.
#[derive(Debug, Default)]
pub struct CapabilityMapper {
    rules: Vec<CompiledRule>,
}

impl CapabilityMapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn load_from_dir(dir: &Path) -> Result<Self, GommageError> {
        let mut files: Vec<PathBuf> = Vec::new();
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == "yaml" || e == "yml")
                {
                    files.push(path);
                }
            }
        }
        files.sort();

        let mut rules = Vec::new();
        for file in &files {
            let raw = fs::read_to_string(file)?;
            let parsed: Vec<RawMapperRule> = serde_yaml::from_str(&raw)?;
            for (index, r) in parsed.into_iter().enumerate() {
                rules.push(compile(r, file.clone(), index)?);
            }
        }
        Ok(Self { rules })
    }

    pub fn from_yaml_string(s: &str, label: &str) -> Result<Self, GommageError> {
        let parsed: Vec<RawMapperRule> = serde_yaml::from_str(s)?;
        let path = PathBuf::from(label);
        let mut rules = Vec::new();
        for (index, r) in parsed.into_iter().enumerate() {
            rules.push(compile(r, path.clone(), index)?);
        }
        Ok(Self { rules })
    }

    /// Map a single tool call into the list of capabilities it implies.
    ///
    /// Deterministic: same `ToolCall` + same loaded rules → identical output
    /// (order included).
    ///
    /// For shell tool calls (`Bash` with a string `command` field) the mapper is
    /// **shape-aware**: it does not only match each `match_input` rule against
    /// the whole command string, it also matches against a deterministic list of
    /// *candidate* command strings derived from the command's shell structure —
    /// each `&&`/`||`/`;`/`|`/newline segment with its leading `env`/`sudo`/
    /// wrapper prefixes stripped, the body of each `$(...)`/backtick command
    /// substitution, and the payload of each `bash -c "..."`. This closes the
    /// gap where a policy gate keyed on a capability (e.g. `git.push:…`) could be
    /// evaded purely by command *shape* (`true; git push`, `$(git push)`,
    /// `bash -c 'git push'`, `/usr/bin/git push`).
    ///
    /// Capture groups in `emit` templates (`${ref}`, …) resolve against the
    /// matched **candidate**; `${input.*}` and `${tool}` always resolve against
    /// the **original** tool input. Emissions are unioned across rules and
    /// candidates, deduplicated, and ordered stably by `(rule-index,
    /// candidate-index)` so the result is invariant under the determinism
    /// shuffle.
    pub fn map(&self, call: &ToolCall) -> Vec<Capability> {
        // Candidate index 0 is always the original input. Additional candidates
        // (shell segments / substitutions / `-c` payloads) only exist for shell
        // tool calls and are applied only to rules that match on the shell
        // command field. Non-shell rules and non-shell tools see candidate 0
        // alone, preserving prior behavior exactly.
        let (candidates, has_multiple_executions) = shell_candidates(call);

        let mut out: Vec<Capability> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Security-relevant Bash effects are derived from the quote-preserving
        // AST before compatibility regex rules. The raw proc.exec rule remains
        // authoritative and is appended below; typed effects never replace it.
        for capability in typed_shell_capabilities(call) {
            if seen.insert(capability.as_str().to_string()) {
                out.push(capability);
            }
        }
        // Every statically recovered shell execution carries independent
        // authority. The original `proc.exec` capability remains below for
        // audit fidelity, while these derived executions prevent a permissive
        // prefix match on the first command from authorizing siblings or
        // command substitutions that policy has not resolved.
        if has_multiple_executions {
            for candidate in &candidates {
                let capability = format!("proc.exec:{candidate}");
                if seen.insert(capability.clone()) {
                    out.push(Capability::new(capability));
                }
            }
        }
        for rule in &self.rules {
            let Some(tool_captures) = match_tool(&rule.tool_match, &call.tool) else {
                continue;
            };

            // A rule participates in candidate expansion only if it actually
            // constrains the shell command field; otherwise it sees the original
            // input alone (candidate 0).
            let expand = !candidates.is_empty() && rule_matches_shell_field(rule);

            // Iterate candidates in stable order. Candidate 0 is the original
            // input; candidates 1.. are the shell-derived command strings.
            let candidate_count = if expand { candidates.len() + 1 } else { 1 };
            for cand_idx in 0..candidate_count {
                let candidate_input: Option<Value> = if cand_idx == 0 {
                    None
                } else {
                    Some(with_shell_command(&call.input, &candidates[cand_idx - 1]))
                };
                let match_input_value = candidate_input.as_ref().unwrap_or(&call.input);

                let Some(input_captures) = match_all_inputs(rule, match_input_value) else {
                    continue;
                };
                let mut captures = tool_captures.clone();
                captures.extend(input_captures);
                for tpl in &rule.emit {
                    // Capture groups come from the matched candidate; ${input.*}
                    // and ${tool} always refer to the original tool input.
                    let rendered = render(tpl, &captures, &call.tool, &call.input);
                    if shadowed_relative_filesystem_capability(call, &rendered) {
                        continue;
                    }
                    if seen.insert(rendered.clone()) {
                        out.push(Capability::new(rendered));
                    }
                }
            }
        }
        out
    }
}

fn shadowed_relative_filesystem_capability(call: &ToolCall, capability: &str) -> bool {
    let (raw_field, resolved_field) = if call.tool == "NotebookEdit" {
        ("notebook_path", "__gommage_notebook_path")
    } else if matches!(call.tool.as_str(), "Read" | "Write" | "Edit" | "MultiEdit") {
        ("file_path", "__gommage_file_path")
    } else {
        return false;
    };
    let Some(raw) = call.input.get(raw_field).and_then(Value::as_str) else {
        return false;
    };
    if call
        .input
        .get(resolved_field)
        .and_then(Value::as_str)
        .is_none()
    {
        return false;
    }
    capability == format!("fs.read:{raw}") || capability == format!("fs.write:{raw}")
}

/// The name of the field on a shell tool call that carries the command string.
const SHELL_COMMAND_FIELD: &str = "command";

/// Build the deterministic list of *derived* candidate command strings for a
/// shell tool call (everything except candidate 0, the whole command). Returns
/// an empty vec for non-shell calls so the mapper short-circuits to legacy
/// behavior.
///
/// Order: for each shell segment (in source order) the prefix-stripped segment
/// text; then, recursing one level, the body of each command substitution; then
/// each `bash -c` payload. The list is de-duplicated while preserving first-seen
/// order so identical candidates do not multiply work or perturb ordering.
fn shell_candidates(call: &ToolCall) -> (Vec<String>, bool) {
    if call.tool != "Bash" {
        return (Vec::new(), false);
    }
    let Some(command) = call.input.get(SHELL_COMMAND_FIELD).and_then(Value::as_str) else {
        return (Vec::new(), false);
    };

    let analysis = crate::shell::analyze(command);
    let has_multiple_executions = analysis.commands.len() > 1;
    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for parsed in &analysis.commands {
        if parsed.static_argv().is_none() {
            continue;
        }
        let mut argv = parsed
            .effective_words
            .iter()
            .map(|word| word.raw.clone())
            .collect::<Vec<_>>();
        if argv.is_empty() {
            continue;
        }
        let executable = parsed.effective_words[0]
            .static_value()
            .expect("static argv checked above");
        if let Ok(head) = crate::shell::trusted_executable_basename(executable) {
            argv[0] = head.to_string();
        }
        let candidate = argv.join(" ");
        if candidate != command && seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    }
    (candidates, has_multiple_executions)
}

fn typed_shell_capabilities(call: &ToolCall) -> Vec<Capability> {
    if call.tool != "Bash" {
        return Vec::new();
    }
    let Some(command) = call.input.get(SHELL_COMMAND_FIELD).and_then(Value::as_str) else {
        return vec![Capability::new("proc.exec.ambiguous:missing-command")];
    };
    let cwd = call.input.get("__gommage_cwd").and_then(Value::as_str);
    let analysis = crate::shell::analyze(command);
    let mut rendered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut emit = |value: String| {
        if seen.insert(value.clone()) {
            rendered.push(Capability::new(value));
        }
    };

    for reason in &analysis.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }

    let filesystem = crate::shell::filesystem_effects(&analysis, cwd);
    for effect in filesystem.effects {
        let namespace = match effect.kind {
            crate::shell::FsEffectKind::Read => "fs.read",
            crate::shell::FsEffectKind::Write => "fs.write",
        };
        if effect.kind == crate::shell::FsEffectKind::Write && is_raw_device_path(&effect.path) {
            emit("disk.device:write".to_string());
        }
        emit(format!("{namespace}:{}", effect.path));
    }
    for reason in &filesystem.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }
    if crate::shell::has_static_remote_rsync(&analysis) {
        emit("net.rsync:out".to_string());
    }

    let packages = crate::shell::package_manager_effects(&analysis);
    for effect in packages.effects {
        use crate::shell::PackageManagerEffect;
        let (capability, registry) = match effect {
            PackageManagerEffect::BunInstall => ("pkg.bun:install", "registry.npmjs.org"),
            PackageManagerEffect::BunPublish => ("pkg.bun:publish", "registry.npmjs.org"),
            PackageManagerEffect::NpmInstall => ("pkg.npm:install", "registry.npmjs.org"),
            PackageManagerEffect::NpmPublish => ("pkg.npm:publish", "registry.npmjs.org"),
            PackageManagerEffect::CargoInstall => ("pkg.cargo:install", "crates.io"),
            PackageManagerEffect::CargoPublish => ("pkg.cargo:publish", "crates.io"),
            PackageManagerEffect::PythonPublish => ("pkg.python:publish", "pypi.org"),
        };
        emit(capability.to_string());
        emit(format!("net.out:{registry}"));
    }
    for reason in &packages.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }

    let git = crate::shell::git_push_effects(&analysis);
    for effect in git.effects {
        match effect {
            crate::shell::GitPushEffect::Destination(destination) => {
                emit(format!("git.push:{destination}"));
            }
            crate::shell::GitPushEffect::CurrentBranch => {
                emit("git.push:<current-branch>".to_string());
            }
            crate::shell::GitPushEffect::Force => emit("git.push.force:<any>".to_string()),
            crate::shell::GitPushEffect::Delete(destination) => {
                emit(format!("git.push.delete:{destination}"));
            }
            crate::shell::GitPushEffect::Network => emit("net.out:github.com".to_string()),
        }
    }
    for reason in &git.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }

    let github = crate::shell::gh_pr_merge_effects(&analysis);
    for effect in github.effects {
        match effect {
            crate::shell::GhPrMergeEffect::Merge(identity) => {
                emit(format!("gh.pr.merge:{identity}"));
            }
            crate::shell::GhPrMergeEffect::Admin(identity) => {
                emit(format!("gh.pr.merge.admin:{identity}"));
            }
            crate::shell::GhPrMergeEffect::DeleteBranch(identity) => {
                emit(format!("gh.pr.merge.delete-branch:{identity}"));
            }
            crate::shell::GhPrMergeEffect::BodyFile(identity) => {
                let host = identity
                    .split('/')
                    .next()
                    .expect("canonical gh PR identities always contain a host");
                emit(format!("gh.pr.merge.body-file:{identity}"));
                emit(format!("net.out.post:{host}"));
            }
        }
    }
    for reason in &github.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }

    let administration = crate::shell::gommage_admin_effects(&analysis, cwd);
    for effect in administration.effects {
        emit(match effect {
            crate::shell::GommageAdminEffect::Authorize => "gommage.authorize".to_string(),
            crate::shell::GommageAdminEffect::Reconfigure => "gommage.reconfigure".to_string(),
            crate::shell::GommageAdminEffect::Disable => "gommage.disable".to_string(),
            crate::shell::GommageAdminEffect::HomeMutate(path) => {
                format!("gommage.home.mutate:{path}")
            }
            crate::shell::GommageAdminEffect::PathWrite(path) => {
                format!("fs.write:{path}")
            }
        });
    }
    for reason in &administration.ambiguities {
        emit(format!("proc.exec.ambiguous:{reason}"));
    }
    rendered
}

fn is_raw_device_path(path: &str) -> bool {
    ["/dev/sd", "/dev/disk", "/dev/nvme", "/dev/rdisk"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Does this rule constrain the shell command field? Only such rules take part
/// in candidate expansion; rules that ignore `command` (or constrain only other
/// fields) see the original input alone.
fn rule_matches_shell_field(rule: &CompiledRule) -> bool {
    rule.match_input
        .iter()
        .any(|(path, _)| path == SHELL_COMMAND_FIELD)
}

/// Clone the original input JSON object and replace the shell command field with
/// a derived candidate string. Other fields are preserved so multi-field rules
/// keep matching their non-command constraints against the real input.
fn with_shell_command(input: &Value, candidate: &str) -> Value {
    let mut cloned = input.clone();
    if let Value::Object(map) = &mut cloned {
        map.insert(
            SHELL_COMMAND_FIELD.to_string(),
            Value::String(candidate.to_string()),
        );
    }
    cloned
}

fn compile(
    raw: RawMapperRule,
    source: PathBuf,
    index: usize,
) -> Result<CompiledRule, GommageError> {
    let tool_match = compile_tool_match(&raw)?;
    let match_input = raw
        .match_input
        .into_iter()
        .map(|(path, pat)| {
            RegexBuilder::new(&pat)
                .size_limit(MAPPER_REGEX_SIZE_LIMIT_BYTES)
                .nest_limit(MAPPER_REGEX_NEST_LIMIT)
                .build()
                .map(|re| (path, re))
                .map_err(|e| GommageError::Regex {
                    pattern: pat,
                    source: e,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sort by field path so rule evaluation order over match_input is stable
    // regardless of HashMap iteration order.
    let mut match_input = match_input;
    match_input.sort_by(|a, b| a.0.cmp(&b.0));

    let emit = raw.emit.into_iter().map(parse_template).collect();

    Ok(CompiledRule {
        name: raw.name,
        tool_match,
        match_input,
        emit,
        source,
        index,
    })
}

fn compile_tool_match(raw: &RawMapperRule) -> Result<ToolMatch, GommageError> {
    match (&raw.tool, &raw.tool_pattern) {
        (Some(tool), None) => Ok(ToolMatch::Exact(tool.clone())),
        (None, Some(pattern)) => RegexBuilder::new(pattern)
            .size_limit(MAPPER_REGEX_SIZE_LIMIT_BYTES)
            .nest_limit(MAPPER_REGEX_NEST_LIMIT)
            .build()
            .map(ToolMatch::Pattern)
            .map_err(|e| GommageError::Regex {
                pattern: pattern.clone(),
                source: e,
            }),
        (Some(_), Some(_)) => Err(GommageError::Policy(format!(
            "mapper rule {:?}: use either tool or tool_pattern, not both",
            raw.name
        ))),
        (None, None) => Err(GommageError::Policy(format!(
            "mapper rule {:?}: missing tool or tool_pattern",
            raw.name
        ))),
    }
}

fn parse_template(s: String) -> Template {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut literal_start = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            if literal_start < i {
                parts.push(TemplatePart::Literal(s[literal_start..i].to_string()));
            }
            let start = i + 2;
            let end = s[start..].find('}').map(|p| start + p).unwrap_or(s.len());
            let token = &s[start..end];
            if token == "tool" {
                parts.push(TemplatePart::ToolName);
            } else if let Some(rest) = token.strip_prefix("input.") {
                parts.push(TemplatePart::InputPath(
                    rest.split('.').map(str::to_string).collect(),
                ));
            } else {
                parts.push(TemplatePart::Capture(token.to_string()));
            }
            i = end + 1;
            literal_start = i;
        } else {
            i += 1;
        }
    }
    if literal_start < s.len() {
        parts.push(TemplatePart::Literal(s[literal_start..].to_string()));
    }
    Template { parts }
}

fn match_tool(tool_match: &ToolMatch, tool: &str) -> Option<HashMap<String, String>> {
    match tool_match {
        ToolMatch::Exact(expected) if expected == tool => Some(HashMap::new()),
        ToolMatch::Exact(_) => None,
        ToolMatch::Pattern(re) => {
            let caps = re.captures(tool)?;
            let mut captures = HashMap::new();
            for name in re.capture_names().flatten() {
                if let Some(m) = caps.name(name) {
                    captures.insert(name.to_string(), m.as_str().to_string());
                }
            }
            Some(captures)
        }
    }
}

fn match_all_inputs(rule: &CompiledRule, input: &Value) -> Option<HashMap<String, String>> {
    let mut captures: HashMap<String, String> = HashMap::new();
    for (path, re) in &rule.match_input {
        let text = extract_string(input, path)?;
        let caps = re.captures(&text)?;
        for name in re.capture_names().flatten() {
            if let Some(m) = caps.name(name) {
                captures.insert(name.to_string(), m.as_str().to_string());
            }
        }
    }
    Some(captures)
}

fn extract_string(input: &Value, path: &str) -> Option<String> {
    let mut cur = input;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn render(tpl: &Template, captures: &HashMap<String, String>, tool: &str, input: &Value) -> String {
    let mut out = String::new();
    for part in &tpl.parts {
        match part {
            TemplatePart::Literal(s) => out.push_str(s),
            TemplatePart::ToolName => out.push_str(tool),
            TemplatePart::Capture(name) => {
                if let Some(v) = captures.get(name) {
                    out.push_str(v);
                }
            }
            TemplatePart::InputPath(path) => {
                let mut cur = input;
                let mut ok = true;
                for p in path {
                    match cur.get(p) {
                        Some(v) => cur = v,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    match cur {
                        Value::String(s) => out.push_str(s),
                        Value::Number(n) => out.push_str(&n.to_string()),
                        Value::Bool(b) => out.push_str(&b.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
