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
        let candidates = shell_candidates(call);

        let mut out: Vec<Capability> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                    if seen.insert(rendered.clone()) {
                        out.push(Capability::new(rendered));
                    }
                }
            }
        }
        out
    }
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
fn shell_candidates(call: &ToolCall) -> Vec<String> {
    if call.tool != "Bash" {
        return Vec::new();
    }
    let Some(command) = call.input.get(SHELL_COMMAND_FIELD).and_then(Value::as_str) else {
        return Vec::new();
    };

    let mut candidates: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    collect_candidates(command, &mut candidates, &mut seen, 0);
    // The whole command (candidate 0) is handled separately by the caller; drop
    // it here if the recursion re-derived it identically.
    candidates.retain(|c| c != command);
    candidates
}

/// Recursion depth cap for command-substitution nesting. One level of recursion
/// is required by spec; we allow a small bounded depth so `$( $( … ) )` and
/// `bash -c '$(…)'` still surface their inner verbs without unbounded work.
const MAX_CANDIDATE_DEPTH: usize = 3;

fn collect_candidates(
    command: &str,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
    depth: usize,
) {
    if depth > MAX_CANDIDATE_DEPTH {
        return;
    }

    // 1. Each shell segment, with leading env/sudo/wrapper prefixes stripped and
    //    the head reduced to its basename so `/usr/bin/git push` matches `git`.
    for segment in crate::shell::shell_segments(command) {
        if let Some(real) = crate::shell::command_words(&segment) {
            if real.is_empty() {
                continue;
            }
            // Drop redirections / background `&` before joining: they are not
            // arguments, and leaving them in lets a gate keyed on a refspec
            // (e.g. `git.push:refs/heads/main`) be evaded by appending `2>&1`
            // or `&`, which would otherwise land in the refspec position.
            let mut normalized = crate::shell::strip_redirections(real);
            if normalized.is_empty() {
                continue;
            }
            normalized[0] = crate::shell::head_basename(&normalized[0]).to_string();
            let joined = normalized.join(" ");
            push_candidate(joined, out, seen);

            // 1b. If this segment is a `bash/sh/zsh -c "<payload>"`, recurse into
            //     the payload one level deeper.
            let head = crate::shell::head_basename(&real[0]);
            if matches!(head, "bash" | "sh" | "zsh")
                && let Some(payload) = crate::shell::shell_c_payload(&real[1..])
            {
                collect_candidates(payload, out, seen, depth + 1);
            }
        }
    }

    // 2. The body of each command substitution, recursing one level deeper.
    for sub in crate::shell::command_substitutions(command) {
        collect_candidates(&sub, out, seen, depth + 1);
    }

    // 3. Genuine (quote-aware) output-redirection targets, surfaced as a small
    //    synthetic candidate of the form `> <target>`. A YAML rule anchored at
    //    `^>` matches these but never matches quoted data (whose segment join
    //    and raw candidate never *begin* with `>`), so a device-write redirect
    //    is caught while `echo "> /dev/sda"` is left as inert data. The leading
    //    operator is preserved verbatim so the existing fs.write redirect rule's
    //    semantics are untouched (it keeps matching segments/candidate 0).
    for target in crate::shell::redirect_targets(command) {
        push_candidate(format!("> {target}"), out, seen);
    }
}

fn push_candidate(
    candidate: String,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    if !candidate.is_empty() && seen.insert(candidate.clone()) {
        out.push(candidate);
    }
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
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn git_push_to_main() {
        let yaml = r#"
- name: bash-git-push
  tool: Bash
  match_input:
    command: "^git push(?:\\s+origin)?\\s+(?P<ref>\\S+)"
  emit:
    - "git.push:refs/heads/${ref}"
    - "net.out:github.com"
"#;
        let m = CapabilityMapper::from_yaml_string(yaml, "git.yaml").unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command": "git push origin main"}),
        };
        let caps = m.map(&call);
        assert_eq!(
            caps,
            vec![
                Capability::new("git.push:refs/heads/main"),
                Capability::new("net.out:github.com")
            ]
        );
    }

    #[test]
    fn fs_write_template_from_input() {
        let yaml = r#"
- name: fs-write
  tool: Write
  emit:
    - "fs.write:${input.file_path}"
"#;
        let m = CapabilityMapper::from_yaml_string(yaml, "fs.yaml").unwrap();
        let call = ToolCall {
            tool: "Write".into(),
            input: json!({"file_path": "/tmp/x.txt", "content": "hi"}),
        };
        assert_eq!(m.map(&call), vec![Capability::new("fs.write:/tmp/x.txt")]);
    }

    #[test]
    fn non_matching_tool_emits_nothing() {
        let yaml = r#"
- name: only-bash
  tool: Bash
  emit: ["proc.exec:${input.command}"]
"#;
        let m = CapabilityMapper::from_yaml_string(yaml, "x.yaml").unwrap();
        let call = ToolCall {
            tool: "Read".into(),
            input: json!({"file_path": "/tmp/x"}),
        };
        assert!(m.map(&call).is_empty());
    }

    #[test]
    fn multiple_rules_fire_in_order() {
        let yaml = r#"
- name: a
  tool: Bash
  match_input: { command: "^echo" }
  emit: ["proc.exec:echo"]
- name: b
  tool: Bash
  match_input: { command: "^echo" }
  emit: ["net.out:unknown"]
"#;
        let m = CapabilityMapper::from_yaml_string(yaml, "x.yaml").unwrap();
        let call = ToolCall {
            tool: "Bash".into(),
            input: json!({"command": "echo hi"}),
        };
        assert_eq!(
            m.map(&call),
            vec![
                Capability::new("proc.exec:echo"),
                Capability::new("net.out:unknown")
            ]
        );
    }

    #[test]
    fn tool_pattern_emits_actual_tool_name_and_captures() {
        let yaml = r#"
- name: mcp-read
  tool_pattern: "^mcp__(?P<server>.+)__read_.*$"
  emit:
    - "mcp.read:${tool}"
    - "mcp.server:${server}"
"#;
        let m = CapabilityMapper::from_yaml_string(yaml, "mcp.yaml").unwrap();
        let call = ToolCall {
            tool: "mcp__filesystem__read_file".into(),
            input: json!({"path": "/tmp/x"}),
        };
        assert_eq!(
            m.map(&call),
            vec![
                Capability::new("mcp.read:mcp__filesystem__read_file"),
                Capability::new("mcp.server:filesystem")
            ]
        );
    }

    #[test]
    fn mapper_rule_requires_one_tool_matcher() {
        let yaml = r#"
- name: bad
  emit: ["x"]
"#;
        assert!(CapabilityMapper::from_yaml_string(yaml, "bad.yaml").is_err());
    }

    // --- Shell-aware (shape) mapping (R1 / R3) ------------------------------

    /// A minimal mapper mirroring the shipped bash.yaml shapes relevant to the
    /// shell-aware tests: whole-command proc.exec for audit + a per-segment
    /// git.push rule.
    fn shell_mapper() -> CapabilityMapper {
        let yaml = r#"
- name: bash-proc-exec
  tool: Bash
  emit:
    - "proc.exec:${input.command}"
- name: bash-git-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push(?:\\s+[-\\w]+)*\\s+(?P<remote>[\\w.-]+)\\s+(?P<ref>\\S+)"
  emit:
    - "git.push:refs/heads/${ref}"
    - "net.out:github.com"
- name: bash-git-force-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push[^#]*--force\\b"
  emit:
    - "git.push.force:<any>"
- name: bash-git-reset-hard
  tool: Bash
  match_input:
    command: "^\\s*git\\s+reset\\s+--hard\\b"
  emit:
    - "git.reset.hard:<any>"
"#;
        CapabilityMapper::from_yaml_string(yaml, "bash.yaml").unwrap()
    }

    fn bash(cmd: &str) -> ToolCall {
        ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": cmd }),
        }
    }

    fn caps_of(m: &CapabilityMapper, cmd: &str) -> Vec<String> {
        m.map(&bash(cmd))
            .into_iter()
            .map(|c| c.as_str().to_string())
            .collect()
    }

    #[test]
    fn compound_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "true; git push origin main");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
        // Whole-command audit fidelity preserved.
        assert!(
            caps.iter()
                .any(|c| c == "proc.exec:true; git push origin main")
        );
    }

    #[test]
    fn cd_prefix_compound_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "cd /r && git push origin main");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn command_substitution_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "$(git push origin main)");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn bash_c_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "bash -c 'git push origin main'");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn quoted_git_push_does_not_emit_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "echo 'git push origin main'");
        assert!(
            !caps.iter().any(|c| c.starts_with("git.push")),
            "quoted string must not be treated as a command; caps: {caps:?}"
        );
    }

    #[test]
    fn env_sudo_prefix_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "env GIT_TRACE=1 sudo git push origin main");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn absolute_path_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "/usr/bin/git push origin main");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn timeout_wrapper_git_push_main_emits_git_push() {
        let m = shell_mapper();
        let caps = caps_of(&m, "timeout 30 git push origin main");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn redirected_git_push_main_still_emits_real_refspec() {
        // Gate-evasion regression: appending a redirection must not knock the
        // real branch out of the refspec. The derived segment candidate is
        // redirection-stripped, so `git.push:refs/heads/main` is still emitted
        // and the main-push gate can fire.
        let m = shell_mapper();
        for cmd in [
            "git push origin main 2>&1",
            "git push origin main >/tmp/log",
            "git push origin main 2> /dev/null",
            "git push origin main >out.txt 2>&1",
            "git push origin main &",
        ] {
            let caps = caps_of(&m, cmd);
            assert!(
                caps.iter().any(|c| c == "git.push:refs/heads/main"),
                "redirected `{cmd}` must still surface the real refspec; caps: {caps:?}"
            );
        }
    }

    #[test]
    fn compound_redirected_git_push_main_emits_real_refspec() {
        let m = shell_mapper();
        let caps = caps_of(&m, "cd /r && git push origin main 2>&1 | tee log");
        assert!(
            caps.iter().any(|c| c == "git.push:refs/heads/main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn compound_git_force_push_emits_force() {
        let m = shell_mapper();
        let caps = caps_of(&m, "true && git push --force origin feature/x");
        assert!(
            caps.iter().any(|c| c == "git.push.force:<any>"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn compound_git_reset_hard_emits_reset() {
        let m = shell_mapper();
        let caps = caps_of(&m, "echo ok; git reset --hard HEAD~1");
        assert!(
            caps.iter().any(|c| c == "git.reset.hard:<any>"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn whole_command_proc_exec_uses_original_input_not_candidate() {
        // ${input.command} must always be the ORIGINAL whole command, even
        // though the git.push capture comes from a candidate segment.
        let m = shell_mapper();
        let caps = caps_of(&m, "cd /r && git push origin main");
        assert!(
            caps.iter()
                .any(|c| c == "proc.exec:cd /r && git push origin main"),
            "caps: {caps:?}"
        );
    }

    #[test]
    fn non_shell_tool_is_unaffected_by_candidate_expansion() {
        // A Write call has no shell decomposition; behavior is identical to
        // before. The git-push rule must not fire on a file_path field.
        let m = shell_mapper();
        let call = ToolCall {
            tool: "Write".into(),
            input: json!({ "file_path": "/tmp/git push origin main" }),
        };
        assert!(m.map(&call).is_empty());
    }

    #[test]
    fn emissions_are_order_stable_and_deduped() {
        let m = shell_mapper();
        // git push appears both as whole command (candidate 0) and as the only
        // segment (candidate 1) — must emit exactly once, in rule order.
        let caps = caps_of(&m, "git push origin main");
        let push_count = caps
            .iter()
            .filter(|c| c.as_str() == "git.push:refs/heads/main")
            .count();
        assert_eq!(push_count, 1, "deduped; caps: {caps:?}");
        // proc.exec (rule 0) precedes git.push (rule 1).
        let proc_idx = caps
            .iter()
            .position(|c| c.starts_with("proc.exec:"))
            .unwrap();
        let push_idx = caps
            .iter()
            .position(|c| c.starts_with("git.push:"))
            .unwrap();
        assert!(proc_idx < push_idx, "rule order; caps: {caps:?}");
    }
}
