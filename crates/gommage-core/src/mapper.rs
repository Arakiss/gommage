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
    pub fn map(&self, call: &ToolCall) -> Vec<Capability> {
        let mut out: Vec<Capability> = Vec::new();
        for rule in &self.rules {
            let Some(mut captures) = match_tool(&rule.tool_match, &call.tool) else {
                continue;
            };
            let Some(input_captures) = match_all_inputs(rule, &call.input) else {
                continue;
            };
            captures.extend(input_captures);
            for tpl in &rule.emit {
                let rendered = render(tpl, &captures, &call.tool, &call.input);
                out.push(Capability::new(rendered));
            }
        }
        out
    }
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
}
