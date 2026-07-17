use crate::{Capability, error::GommageError, picto::validate_picto_scope};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const POLICY_HASH_SCHEMA: &[u8] = b"gommage-policy-v2\0";
const PATH_NORMALIZER_SCHEMA: &[u8] = b"home-alias-v1\0";

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
    /// Derive the Picto scope from the single normalized capability matching
    /// this selector. The selector must also appear verbatim in
    /// `match.all_capability`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope_from_capability: Option<String>,
    /// Require a Picto signed for the exact canonical tool-call input hash.
    /// Scope-only direct grants remain valid only when this is false.
    #[serde(default)]
    pub bind_input: bool,
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
    /// Canonical selector used to derive the Picto scope from one capability.
    pub required_scope_from_capability: Option<String>,
    pub(crate) required_scope_from_capability_matcher: Option<GlobMatcher>,
    pub bind_input: bool,
    pub r#match: Match,
    pub reason: String,
    /// Source file + index, so `gommage explain` can point at exactly
    /// which rule fired.
    pub source: RuleSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSource {
    /// Stable name supplied for the policy layer (`org`, `project`, `user`,
    /// or `inline` for policies compiled from a string).
    pub layer: String,
    /// Position of the layer in the load request. This remains distinct from
    /// the name so repeated layer names still have deterministic ordering.
    pub layer_index: usize,
    /// Source policy file for compatibility provenance and operator tooling.
    pub file: PathBuf,
    /// Lexicographic position of the file inside its layer.
    pub file_index: usize,
    /// Declaration position of the rule inside its source file.
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

    /// Returns `true` when this match clause positively covers `capability`.
    ///
    /// Whole-set matching decides whether a rule is eligible. Coverage is
    /// narrower: only a positive `any_capability` or `all_capability` pattern
    /// can authorize or restrict an individual capability. Negative patterns
    /// are conditions and never provide coverage by themselves.
    pub fn covers(&self, capability: &crate::Capability) -> bool {
        self.any_capability
            .iter()
            .chain(&self.all_capability)
            .any(|pattern| pattern.is_match(capability.as_str()))
    }
}

/// A canvas is the active compiled policy for the current expedition. It is
/// an ordered list of rules and a hash identifying exactly which source files
/// were used to build it (so the hash can be embedded in the audit log).
#[derive(Debug)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub version_hash: String,
    pub(crate) path_normalizer: PathNormalizer,
}

/// Binding modes used by `ask_picto` rules that can require one concrete scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PictoScopeRequirements {
    /// At least one matching rule can consume a scope-only Picto.
    pub has_scope_only_rule: bool,
    /// At least one matching rule requires an exact canonical input hash.
    pub has_input_bound_rule: bool,
}

/// Closed policy-layer roles in their only valid load order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayerKind {
    /// Organization-controlled policy loaded first.
    #[serde(rename = "org")]
    Organization,
    /// Operator-controlled policy loaded after organization policy.
    User,
    /// Repository-controlled, tightening-only policy loaded last.
    Project,
}

impl PolicyLayerKind {
    /// Stable public label used in provenance and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Organization => "org",
            Self::User => "user",
            Self::Project => "project",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Organization => 0,
            Self::User => 1,
            Self::Project => 2,
        }
    }
}

/// One canonical policy layer and its source directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLayer {
    /// Security role that determines ordering and allowed decisions.
    pub kind: PolicyLayerKind,
    /// Directory containing this layer's ordered YAML policy files.
    pub dir: PathBuf,
}

impl PolicyLayer {
    /// Construct an organization-controlled layer.
    pub fn organization(dir: impl Into<PathBuf>) -> Self {
        Self {
            kind: PolicyLayerKind::Organization,
            dir: dir.into(),
        }
    }

    /// Construct an operator-controlled user layer.
    pub fn user(dir: impl Into<PathBuf>) -> Self {
        Self {
            kind: PolicyLayerKind::User,
            dir: dir.into(),
        }
    }

    /// Construct a repository-controlled, tightening-only project layer.
    pub fn project(dir: impl Into<PathBuf>) -> Self {
        Self {
            kind: PolicyLayerKind::Project,
            dir: dir.into(),
        }
    }

    /// Return the stable public layer label.
    pub const fn name(&self) -> &'static str {
        self.kind.as_str()
    }
}

fn validate_policy_layers(layers: &[PolicyLayer]) -> Result<(), GommageError> {
    let mut previous: Option<PolicyLayerKind> = None;
    for layer in layers {
        if let Some(previous) = previous
            && previous.rank() >= layer.kind.rank()
        {
            return Err(GommageError::Policy(format!(
                "policy layers must be unique and ordered org, user, project; found {} after {}",
                layer.name(),
                previous.as_str()
            )));
        }
        previous = Some(layer.kind);
    }
    Ok(())
}

impl Policy {
    /// Load every `*.yaml` / `*.yml` file under `dir` in lexicographic filename order,
    /// substituting `${VAR}` references from `env` at load time.
    pub fn load_from_dir(dir: &Path, env: &HashMap<String, String>) -> Result<Self, GommageError> {
        load_policy_files(
            &collect_policy_files(dir)?,
            env,
            HashMode::Legacy { root: dir },
        )
    }

    /// Load policy files from ordered layers. Evaluation preserves first-match
    /// ordering inside each layer while aggregating contributions from all
    /// layers conservatively.
    pub fn load_from_layers(
        layers: &[PolicyLayer],
        env: &HashMap<String, String>,
    ) -> Result<Self, GommageError> {
        validate_policy_layers(layers)?;
        if layers.len() == 1 && layers[0].kind == PolicyLayerKind::User {
            return Self::load_from_dir(&layers[0].dir, env);
        }

        let mut files = Vec::new();
        for (layer_index, layer) in layers.iter().enumerate() {
            for (file_index, file) in collect_policy_files(&layer.dir)?.into_iter().enumerate() {
                files.push(LayeredPolicyFile {
                    layer_name: layer.name().to_string(),
                    layer_index,
                    layer_root: layer.dir.clone(),
                    file_index,
                    path: file.path,
                });
            }
        }
        load_policy_files(&files, env, HashMode::Layered)
    }

    /// Same as `load_from_dir` but from an already-parsed string (handy for tests).
    pub fn from_yaml_string(
        s: &str,
        env: &HashMap<String, String>,
        source_label: &str,
    ) -> Result<Self, GommageError> {
        let substituted = substitute_env(s, env)?;
        let path_normalizer = PathNormalizer::from_env(env);
        let raw_rules: Vec<RawRule> = serde_yaml::from_str(&substituted)?;
        let path = PathBuf::from(source_label);
        let mut rules = Vec::new();
        for (index, raw) in raw_rules.into_iter().enumerate() {
            rules.push(compile_rule(
                raw,
                RuleSource {
                    layer: "inline".to_string(),
                    layer_index: 0,
                    file: path.clone(),
                    file_index: 0,
                    index,
                },
                &path_normalizer,
            )?);
        }
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        update_policy_hash_context(&mut h, &path_normalizer);
        h.update(b"file\0");
        h.update(source_label.as_bytes());
        h.update(b"\0content\0");
        h.update(substituted.as_bytes());
        Ok(Policy {
            rules,
            version_hash: format!("sha256:{}", hex::encode(h.finalize())),
            path_normalizer,
        })
    }

    /// Return the canonical capability form policy evaluation should use.
    ///
    /// The mapper deliberately stays pure and preserves the tool-call string it
    /// saw. Policy loading, however, already has the `${HOME}` substitution
    /// environment, so this is the single place where home aliases can be
    /// compared safely: `~/x`, `$HOME/x`, `${HOME}/x`, and `/abs/home/x`
    /// become the same filesystem capability while relative paths stay
    /// relative.
    pub fn normalize_capabilities(&self, caps: &[Capability]) -> Vec<Capability> {
        self.path_normalizer.normalize_capabilities(caps)
    }

    /// Return the binding modes of all `ask_picto` rules that can require
    /// `scope`.
    ///
    /// Static scopes use exact equality. Capability-derived scopes use their
    /// compiled selector. Invalid Picto scopes can never be required and return
    /// `None` even when a permissive selector would otherwise match them.
    pub fn picto_scope_requirements(&self, scope: &str) -> Option<PictoScopeRequirements> {
        if validate_picto_scope(scope).is_err() {
            return None;
        }

        let mut requirements: Option<PictoScopeRequirements> = None;
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.decision == RuleDecision::AskPicto)
        {
            let static_match = rule.required_scope.as_deref() == Some(scope);
            let derived_match = rule
                .required_scope_from_capability_matcher
                .as_ref()
                .is_some_and(|selector| selector.is_match(scope));
            if !static_match && !derived_match {
                continue;
            }

            let requirements = requirements.get_or_insert(PictoScopeRequirements {
                has_scope_only_rule: false,
                has_input_bound_rule: false,
            });
            if rule.bind_input {
                requirements.has_input_bound_rule = true;
            } else {
                requirements.has_scope_only_rule = true;
            }
        }
        requirements
    }

    /// Return whether any `ask_picto` rule can require `scope`.
    pub fn can_require_picto_scope(&self, scope: &str) -> bool {
        self.picto_scope_requirements(scope).is_some()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PathNormalizer {
    home: Option<String>,
}

impl PathNormalizer {
    fn from_env(env: &HashMap<String, String>) -> Self {
        Self {
            home: env.get("HOME").and_then(|home| normalize_home_value(home)),
        }
    }

    fn normalize_capabilities(&self, caps: &[Capability]) -> Vec<Capability> {
        let mut out: Vec<Capability> = caps
            .iter()
            .map(|cap| Capability::new(self.normalize_capability_str(cap.as_str())))
            .collect();
        out.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        out.dedup_by(|left, right| left.as_str() == right.as_str());
        out
    }

    fn normalize_capability_str(&self, capability: &str) -> String {
        let Some((namespace, payload)) = capability.split_once(':') else {
            return capability.to_string();
        };
        if !is_path_capability_namespace(namespace) {
            return capability.to_string();
        }
        let Some(path) = self.normalize_home_path(payload) else {
            return capability.to_string();
        };
        format!("{namespace}:{path}")
    }

    fn normalize_home_path(&self, path: &str) -> Option<String> {
        let home = self.home.as_deref()?;
        if path == "~" || path == "$HOME" || path == "${HOME}" {
            return Some(home.to_string());
        }
        for prefix in ["~/", "$HOME/", "${HOME}/"] {
            if let Some(rest) = path.strip_prefix(prefix) {
                return Some(join_home(home, rest));
            }
        }
        None
    }
}

fn normalize_home_value(home: &str) -> Option<String> {
    if home.is_empty() {
        return None;
    }
    let trimmed = home.trim_end_matches('/');
    if trimmed.is_empty() {
        return Some("/".to_string());
    }
    Some(trimmed.to_string())
}

fn join_home(home: &str, rest: &str) -> String {
    if home == "/" {
        format!("/{rest}")
    } else {
        format!("{home}/{rest}")
    }
}

fn is_path_capability_namespace(namespace: &str) -> bool {
    matches!(namespace, "fs.read" | "fs.search" | "fs.write")
}

#[derive(Debug)]
struct LayeredPolicyFile {
    layer_name: String,
    layer_index: usize,
    layer_root: PathBuf,
    file_index: usize,
    path: PathBuf,
}

enum HashMode<'a> {
    Legacy { root: &'a Path },
    Layered,
}

fn collect_policy_files(dir: &Path) -> Result<Vec<LayeredPolicyFile>, GommageError> {
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

    Ok(files
        .into_iter()
        .enumerate()
        .map(|(file_index, path)| LayeredPolicyFile {
            layer_name: "user".to_string(),
            layer_index: 0,
            layer_root: dir.to_path_buf(),
            file_index,
            path,
        })
        .collect())
}

fn load_policy_files(
    files: &[LayeredPolicyFile],
    env: &HashMap<String, String>,
    hash_mode: HashMode<'_>,
) -> Result<Policy, GommageError> {
    let mut rules: Vec<Rule> = Vec::new();
    let mut version = sha2::Sha256::new();
    let path_normalizer = PathNormalizer::from_env(env);
    use sha2::Digest as _;
    update_policy_hash_context(&mut version, &path_normalizer);

    for file in files {
        let raw = fs::read_to_string(&file.path)?;
        let substituted = substitute_env(&raw, env).map_err(|error| {
            GommageError::Policy(format!(
                "policy variable substitution failed in {}: {error}",
                file.path.display()
            ))
        })?;
        match hash_mode {
            HashMode::Legacy { root } => {
                update_policy_hash(&mut version, root, &file.path, &substituted);
            }
            HashMode::Layered => {
                update_layered_policy_hash(
                    &mut version,
                    &file.layer_name,
                    &file.layer_root,
                    &file.path,
                    &substituted,
                );
            }
        }
        let raw_rules: Vec<RawRule> = serde_yaml::from_str(&substituted)?;
        for (index, raw) in raw_rules.into_iter().enumerate() {
            if file.layer_name == "project" && raw.decision == RuleDecision::Allow {
                return Err(GommageError::Policy(format!(
                    "project policy {} rule {index} ({}) uses decision=allow; project layers may only tighten operator policy with ask_picto or gommage",
                    file.path.display(),
                    raw.name
                )));
            }
            rules.push(compile_rule(
                raw,
                RuleSource {
                    layer: file.layer_name.clone(),
                    layer_index: file.layer_index,
                    file: file.path.clone(),
                    file_index: file.file_index,
                    index,
                },
                &path_normalizer,
            )?);
        }
    }

    let version_hash = format!("sha256:{}", hex::encode(version.finalize()));
    Ok(Policy {
        rules,
        version_hash,
        path_normalizer,
    })
}

fn update_policy_hash_context(hash: &mut sha2::Sha256, normalizer: &PathNormalizer) {
    use sha2::Digest as _;
    hash.update(POLICY_HASH_SCHEMA);
    hash.update(PATH_NORMALIZER_SCHEMA);
    match normalizer.home.as_deref() {
        Some(home) => {
            hash.update(b"home\0some\0");
            hash.update(home.as_bytes());
            hash.update(b"\0");
        }
        None => hash.update(b"home\0none\0"),
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

fn update_layered_policy_hash(
    hash: &mut sha2::Sha256,
    layer_name: &str,
    layer_root: &Path,
    file: &Path,
    substituted_contents: &str,
) {
    use sha2::Digest as _;
    let rel = file.strip_prefix(layer_root).unwrap_or(file);
    let rel = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    hash.update(b"layer\0");
    hash.update(layer_name.as_bytes());
    hash.update(b"\0file\0");
    hash.update(rel.as_bytes());
    hash.update(b"\0content\0");
    hash.update(substituted_contents.as_bytes());
    hash.update(b"\0");
}

fn compile_rule(
    raw: RawRule,
    source: RuleSource,
    path_normalizer: &PathNormalizer,
) -> Result<Rule, GommageError> {
    // Validate decision/field combinations early — a policy with inconsistent
    // fields should fail at load, not at evaluation.
    if raw.required_scope.is_some() && raw.required_scope_from_capability.is_some() {
        return Err(GommageError::Policy(format!(
            "rule {:?}: required_scope and required_scope_from_capability are mutually exclusive",
            raw.name
        )));
    }
    if raw.decision == RuleDecision::AskPicto {
        match (
            raw.required_scope.as_deref(),
            raw.required_scope_from_capability.as_deref(),
        ) {
            (Some(scope), None) => validate_picto_scope(scope).map_err(|reason| {
                GommageError::Policy(format!(
                    "rule {:?}: invalid required_scope: {reason}",
                    raw.name
                ))
            })?,
            (None, Some(selector)) => {
                if !raw
                    .r#match
                    .all_capability
                    .iter()
                    .any(|pattern| pattern == selector)
                {
                    return Err(GommageError::Policy(format!(
                        "rule {:?}: required_scope_from_capability must exactly match a pattern in match.all_capability",
                        raw.name
                    )));
                }
            }
            (None, None) => {
                return Err(GommageError::Policy(format!(
                    "rule {:?}: decision=ask_picto requires exactly one of required_scope or required_scope_from_capability",
                    raw.name
                )));
            }
            (Some(_), Some(_)) => {
                return Err(GommageError::Policy(format!(
                    "rule {:?}: required_scope and required_scope_from_capability are mutually exclusive",
                    raw.name
                )));
            }
        }
    } else if raw.required_scope_from_capability.is_some() {
        return Err(GommageError::Policy(format!(
            "rule {:?}: required_scope_from_capability is only valid with decision=ask_picto",
            raw.name
        )));
    }
    if raw.decision != RuleDecision::Gommage && raw.hard_stop {
        return Err(GommageError::Policy(format!(
            "rule {:?}: hard_stop=true only valid with decision=gommage",
            raw.name
        )));
    }
    if raw.decision != RuleDecision::AskPicto && raw.bind_input {
        return Err(GommageError::Policy(format!(
            "rule {:?}: bind_input=true only valid with decision=ask_picto",
            raw.name
        )));
    }
    if raw.r#match.any_capability.is_empty() && raw.r#match.all_capability.is_empty() {
        return Err(GommageError::Policy(format!(
            "rule {:?}: at least one positive any_capability or all_capability pattern is required",
            raw.name
        )));
    }
    if raw.decision != RuleDecision::Allow && !raw.r#match.none_capability.is_empty() {
        return Err(GommageError::Policy(format!(
            "rule {:?}: none_capability is only valid with decision=allow",
            raw.name
        )));
    }

    let required_scope_from_capability_matcher = raw
        .required_scope_from_capability
        .as_deref()
        .map(|selector| compile_glob(selector, path_normalizer))
        .transpose()?;
    let required_scope_from_capability = raw
        .required_scope_from_capability
        .as_deref()
        .map(|selector| path_normalizer.normalize_capability_str(selector));
    let r#match = Match {
        any_capability: compile_globs(&raw.r#match.any_capability, path_normalizer)?,
        all_capability: compile_globs(&raw.r#match.all_capability, path_normalizer)?,
        none_capability: compile_globs(&raw.r#match.none_capability, path_normalizer)?,
    };

    Ok(Rule {
        name: raw.name,
        decision: raw.decision,
        hard_stop: raw.hard_stop,
        required_scope: raw.required_scope,
        required_scope_from_capability,
        required_scope_from_capability_matcher,
        bind_input: raw.bind_input,
        r#match,
        reason: raw.reason,
        source,
    })
}

fn compile_globs(
    pats: &[String],
    path_normalizer: &PathNormalizer,
) -> Result<Vec<GlobMatcher>, GommageError> {
    pats.iter()
        .map(|pattern| compile_glob(pattern, path_normalizer))
        .collect()
}

fn compile_glob(
    pattern: &str,
    path_normalizer: &PathNormalizer,
) -> Result<GlobMatcher, GommageError> {
    let normalized = path_normalizer.normalize_capability_str(pattern);
    Glob::new(&normalized)
        .map(|glob| glob.compile_matcher())
        .map_err(|source| GommageError::Glob {
            pattern: normalized,
            source,
        })
}

/// Substitute `${NAME}` and `${NAME:-default}` references in `input` using `env`.
///
/// Missing and empty values fail closed unless the expression supplies a
/// non-empty default. This prevents a path policy such as
/// `fs.write:${EXPEDITION_ROOT}/**` from silently broadening to `fs.write:/**`.
pub fn substitute_env(input: &str, env: &HashMap<String, String>) -> Result<String, GommageError> {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap();
    let mut output = String::with_capacity(input.len());
    let mut previous_end = 0;

    for captures in re.captures_iter(input) {
        let expression = captures
            .get(0)
            .expect("the complete substitution expression is always captured");
        output.push_str(&input[previous_end..expression.start()]);

        let name = &captures[1];
        let configured = env.get(name).filter(|value| !value.trim().is_empty());
        let fallback = captures
            .get(2)
            .map(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let replacement = configured.map(String::as_str).or(fallback).ok_or_else(|| {
            GommageError::Policy(format!(
                "policy variable {name} is unset or empty and has no non-empty default"
            ))
        })?;
        output.push_str(replacement);
        previous_end = expression.end();
    }

    output.push_str(&input[previous_end..]);
    if output.contains("${") {
        return Err(GommageError::Policy(
            "policy contains an unsupported or unterminated variable expression".to_string(),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
