use crate::error::GommageError;
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// The raw YAML shape of a decision. Kept flat to make policy files read well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    Allow,
    Gommage,
    AskPicto,
}

/// A raw rule as it appears in YAML. Not yet compiled: glob patterns are still strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRule {
    pub name: String,
    pub decision: RuleDecision,
    #[serde(default)]
    pub hard_stop: bool,
    #[serde(default)]
    pub required_scope: Option<String>,
    #[serde(default = "default_match")]
    pub r#match: RawMatch,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawMatch {
    #[serde(default)]
    pub any_capability: Vec<String>,
    #[serde(default)]
    pub all_capability: Vec<String>,
    #[serde(default)]
    pub none_capability: Vec<String>,
}

fn default_match() -> RawMatch {
    RawMatch::default()
}

/// A rule after compilation: globs are compiled, env vars substituted.
#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub decision: RuleDecision,
    pub hard_stop: bool,
    pub required_scope: Option<String>,
    pub r#match: Match,
    pub reason: String,
    /// Source file + index, so `gommage explain` can point at exactly
    /// which rule fired.
    pub source: RuleSource,
}

#[derive(Debug, Clone)]
pub struct RuleSource {
    pub file: PathBuf,
    pub index: usize,
}

#[derive(Debug)]
pub struct Match {
    pub any_capability: Vec<GlobMatcher>,
    pub all_capability: Vec<GlobMatcher>,
    pub none_capability: Vec<GlobMatcher>,
}

impl Match {
    /// Returns `true` iff the rule's match clause passes for the given set of capabilities.
    ///
    /// Semantics:
    /// - `any_capability`: at least one pattern matches at least one cap (or empty → pass).
    /// - `all_capability`: every pattern matches at least one cap (or empty → pass).
    /// - `none_capability`: no pattern matches any cap (or empty → pass).
    pub fn matches(&self, caps: &[crate::Capability]) -> bool {
        let any_ok = self.any_capability.is_empty()
            || self
                .any_capability
                .iter()
                .any(|p| caps.iter().any(|c| p.is_match(c.as_str())));
        if !any_ok {
            return false;
        }

        let all_ok = self
            .all_capability
            .iter()
            .all(|p| caps.iter().any(|c| p.is_match(c.as_str())));
        if !all_ok {
            return false;
        }

        self.none_capability
            .iter()
            .all(|p| !caps.iter().any(|c| p.is_match(c.as_str())))
    }
}

/// A canvas is the active compiled policy for the current expedition. It is
/// an ordered list of rules and a hash identifying exactly which source files
/// were used to build it (so the hash can be embedded in the audit log).
#[derive(Debug)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub version_hash: String,
}

impl Policy {
    /// Load every `*.yaml` / `*.yml` file under `dir` in lexicographic filename order,
    /// substituting `${VAR}` references from `env` at load time.
    pub fn load_from_dir(dir: &Path, env: &HashMap<String, String>) -> Result<Self, GommageError> {
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

        let mut rules: Vec<Rule> = Vec::new();
        let mut version = sha2::Sha256::new();
        use sha2::Digest as _;

        for file in &files {
            let raw = fs::read_to_string(file)?;
            let substituted = substitute_env(&raw, env);
            update_policy_hash(&mut version, dir, file, &substituted);
            let raw_rules: Vec<RawRule> = serde_yaml::from_str(&substituted)?;
            for (index, raw) in raw_rules.into_iter().enumerate() {
                rules.push(compile_rule(raw, file.clone(), index)?);
            }
        }

        let version_hash = format!("sha256:{}", hex::encode(version.finalize()));
        Ok(Policy {
            rules,
            version_hash,
        })
    }

    /// Same as `load_from_dir` but from an already-parsed string (handy for tests).
    pub fn from_yaml_string(
        s: &str,
        env: &HashMap<String, String>,
        source_label: &str,
    ) -> Result<Self, GommageError> {
        let substituted = substitute_env(s, env);
        let raw_rules: Vec<RawRule> = serde_yaml::from_str(&substituted)?;
        let path = PathBuf::from(source_label);
        let mut rules = Vec::new();
        for (index, raw) in raw_rules.into_iter().enumerate() {
            rules.push(compile_rule(raw, path.clone(), index)?);
        }
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(b"file\0");
        h.update(source_label.as_bytes());
        h.update(b"\0content\0");
        h.update(substituted.as_bytes());
        Ok(Policy {
            rules,
            version_hash: format!("sha256:{}", hex::encode(h.finalize())),
        })
    }
}

fn update_policy_hash(
    hash: &mut sha2::Sha256,
    root: &Path,
    file: &Path,
    substituted_contents: &str,
) {
    use sha2::Digest as _;
    let rel = file.strip_prefix(root).unwrap_or(file);
    let rel = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    hash.update(b"file\0");
    hash.update(rel.as_bytes());
    hash.update(b"\0content\0");
    hash.update(substituted_contents.as_bytes());
    hash.update(b"\0");
}

fn compile_rule(raw: RawRule, file: PathBuf, index: usize) -> Result<Rule, GommageError> {
    // Validate decision/field combinations early — a policy with inconsistent
    // fields should fail at load, not at evaluation.
    if raw.decision == RuleDecision::AskPicto && raw.required_scope.is_none() {
        return Err(GommageError::Policy(format!(
            "rule {:?}: decision=ask_picto requires required_scope",
            raw.name
        )));
    }
    if raw.decision != RuleDecision::Gommage && raw.hard_stop {
        return Err(GommageError::Policy(format!(
            "rule {:?}: hard_stop=true only valid with decision=gommage",
            raw.name
        )));
    }

    let r#match = Match {
        any_capability: compile_globs(&raw.r#match.any_capability)?,
        all_capability: compile_globs(&raw.r#match.all_capability)?,
        none_capability: compile_globs(&raw.r#match.none_capability)?,
    };

    Ok(Rule {
        name: raw.name,
        decision: raw.decision,
        hard_stop: raw.hard_stop,
        required_scope: raw.required_scope,
        r#match,
        reason: raw.reason,
        source: RuleSource { file, index },
    })
}

fn compile_globs(pats: &[String]) -> Result<Vec<GlobMatcher>, GommageError> {
    pats.iter()
        .map(|p| {
            Glob::new(p)
                .map(|g| g.compile_matcher())
                .map_err(|e| GommageError::Glob {
                    pattern: p.clone(),
                    source: e,
                })
        })
        .collect()
}

/// Substitute `${NAME}` and `${NAME:-default}` references in `input` using `env`.
/// Unknown vars with no default become empty string and log a warning — the
/// policy loader catches mistyped names via the downstream glob that ends up
/// being nonsensical, but we don't hard-fail (otherwise policy files with
/// `${PROJECT_NAME}` would fail on hosts where that isn't set).
pub fn substitute_env(input: &str, env: &HashMap<String, String>) -> String {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap();
    re.replace_all(input, |caps: &regex::Captures<'_>| {
        let name = &caps[1];
        let default = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        env.get(name)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;

    fn env() -> HashMap<String, String> {
        let mut e = HashMap::new();
        e.insert("EXPEDITION_ROOT".into(), "/home/user/project".into());
        e
    }

    #[test]
    fn env_substitution() {
        let out = substitute_env("allow fs.read:${EXPEDITION_ROOT}/**", &env());
        assert_eq!(out, "allow fs.read:/home/user/project/**");
    }

    #[test]
    fn env_substitution_with_default() {
        let out = substitute_env("x ${NONEXISTENT:-fallback} y", &HashMap::new());
        assert_eq!(out, "x fallback y");
    }

    #[test]
    fn match_semantics() {
        let yaml = r#"
- name: t
  decision: gommage
  match:
    any_capability:
      - "fs.write:**/node_modules/**"
      - "fs.write:**/.git/**"
  reason: "no"
"#;
        let p = Policy::from_yaml_string(yaml, &HashMap::new(), "test.yaml").unwrap();
        let r = &p.rules[0];
        assert!(
            r.r#match
                .matches(&[Capability::new("fs.write:/a/node_modules/b.js")])
        );
        assert!(!r.r#match.matches(&[Capability::new("fs.write:/src/a.js")]));
    }

    #[test]
    fn policy_hash_is_independent_of_root_path() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let yaml = r#"
- name: allow-read
  decision: allow
  match:
    any_capability: ["fs.read:/project/**"]
"#;
        std::fs::write(a.path().join("10-default.yaml"), yaml).unwrap();
        std::fs::write(b.path().join("10-default.yaml"), yaml).unwrap();

        let pa = Policy::load_from_dir(a.path(), &HashMap::new()).unwrap();
        let pb = Policy::load_from_dir(b.path(), &HashMap::new()).unwrap();
        assert_eq!(pa.version_hash, pb.version_hash);
    }

    #[test]
    fn policy_hash_changes_when_substituted_policy_changes() {
        let yaml = r#"
- name: allow-root
  decision: allow
  match:
    any_capability: ["fs.read:${EXPEDITION_ROOT}/**"]
"#;
        let mut env_a = HashMap::new();
        env_a.insert("EXPEDITION_ROOT".into(), "/a".into());
        let mut env_b = HashMap::new();
        env_b.insert("EXPEDITION_ROOT".into(), "/b".into());

        let pa = Policy::from_yaml_string(yaml, &env_a, "10-default.yaml").unwrap();
        let pb = Policy::from_yaml_string(yaml, &env_b, "10-default.yaml").unwrap();
        assert_ne!(pa.version_hash, pb.version_hash);
    }

    #[test]
    fn ask_picto_requires_scope() {
        let yaml = r#"
- name: bad
  decision: ask_picto
  match: { any_capability: ["git.push:*"] }
  reason: "bad"
"#;
        let err = Policy::from_yaml_string(yaml, &HashMap::new(), "t").unwrap_err();
        assert!(matches!(err, GommageError::Policy(_)));
    }
}
