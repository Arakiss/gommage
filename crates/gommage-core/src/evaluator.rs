use crate::{Capability, Policy, Rule, RuleDecision, hardstop};
use serde::{Deserialize, Serialize};

/// The final decision the daemon will return to the agent.
///
/// `Allow` and `Gommage` are self-explanatory. `AskPicto` is returned to the
/// daemon, not to the agent directly — the daemon consults the picto store and
/// (if no matching picto) escalates out-of-band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Decision {
    Allow,
    /// Denied by policy. `hard_stop` is true when the rule said so OR when the
    /// hit came from the hardcoded hardstop set.
    Gommage {
        reason: String,
        hard_stop: bool,
    },
    /// Rule matched with `decision=ask_picto`. Daemon must consult the picto store.
    /// A matching, valid picto causes this to become `Allow`; otherwise the daemon
    /// escalates out-of-band.
    AskPicto {
        required_scope: String,
        reason: String,
    },
}

/// A summary of which rule produced the decision. Written to the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRule {
    pub name: String,
    pub file: String,
    pub index: usize,
}

/// The full result of evaluation: decision + provenance + the capabilities that
/// were in play at the time. Stored in audit so `gommage explain` can be exact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub decision: Decision,
    pub matched_rule: Option<MatchedRule>,
    pub capabilities: Vec<Capability>,
    pub policy_version: String,
}

/// Pure evaluation. Given the set of capabilities produced by the mapper and a
/// compiled policy, produce a decision.
///
/// Ordering rules (**do not change without updating the determinism suite**):
///   1. Hardcoded hardstop check (always first, cannot be bypassed by policy).
///   2. Iterate `policy.rules` in declared order. First rule whose match clause
///      accepts the capabilities wins.
///   3. If no rule matches, fail closed: `Gommage { reason: "no rule matched (fail-closed)" }`.
pub fn evaluate(caps: &[Capability], policy: &Policy) -> EvalResult {
    if let Some(hit) = hardstop::check(caps) {
        return EvalResult {
            decision: Decision::Gommage {
                reason: format!(
                    "hard-stop {}: pattern {:?} matched {}",
                    hit.name, hit.pattern, hit.capability
                ),
                hard_stop: true,
            },
            matched_rule: Some(MatchedRule {
                name: format!("<hardcoded:{}>", hit.name),
                file: "<compiled-in>".to_string(),
                index: 0,
            }),
            capabilities: caps.to_vec(),
            policy_version: policy.version_hash.clone(),
        };
    }

    for rule in &policy.rules {
        if rule.r#match.matches(caps) {
            return EvalResult {
                decision: decision_from_rule(rule),
                matched_rule: Some(MatchedRule {
                    name: rule.name.clone(),
                    file: rule.source.file.to_string_lossy().to_string(),
                    index: rule.source.index,
                }),
                capabilities: caps.to_vec(),
                policy_version: policy.version_hash.clone(),
            };
        }
    }

    EvalResult {
        decision: Decision::Gommage {
            reason: "no rule matched (fail-closed)".to_string(),
            hard_stop: false,
        },
        matched_rule: None,
        capabilities: caps.to_vec(),
        policy_version: policy.version_hash.clone(),
    }
}

fn decision_from_rule(rule: &Rule) -> Decision {
    match rule.decision {
        RuleDecision::Allow => Decision::Allow,
        RuleDecision::Gommage => Decision::Gommage {
            reason: rule.reason.clone(),
            hard_stop: rule.hard_stop,
        },
        RuleDecision::AskPicto => Decision::AskPicto {
            required_scope: rule
                .required_scope
                .clone()
                .expect("ask_picto rule without required_scope survived compilation; bug"),
            reason: rule.reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn p(yaml: &str) -> Policy {
        Policy::from_yaml_string(yaml, &HashMap::new(), "test.yaml").unwrap()
    }

    #[test]
    fn first_match_wins() {
        let pol = p(r#"
- name: first
  decision: allow
  match: { any_capability: ["fs.read:*"] }
  reason: ""
- name: second
  decision: gommage
  match: { any_capability: ["fs.read:*"] }
  reason: "never fires"
"#);
        let res = evaluate(&[Capability::new("fs.read:/tmp/x")], &pol);
        assert_eq!(res.decision, Decision::Allow);
    }

    #[test]
    fn fail_closed_on_no_match() {
        let pol = p(r#"
- name: only-git
  decision: allow
  match: { any_capability: ["git.push:*"] }
  reason: ""
"#);
        let res = evaluate(&[Capability::new("fs.read:/tmp/x")], &pol);
        assert!(matches!(res.decision, Decision::Gommage { .. }));
    }

    #[test]
    fn hardstop_wins_over_allow() {
        let pol = p(r#"
- name: allow-all
  decision: allow
  match: { any_capability: ["**"] }
  reason: ""
"#);
        let res = evaluate(&[Capability::new("proc.exec:rm -rf /")], &pol);
        let Decision::Gommage { hard_stop, .. } = res.decision else {
            panic!("expected gommage");
        };
        assert!(hard_stop);
    }

    #[test]
    fn ask_picto_surfaces_scope() {
        let pol = p(r#"
- name: gate-main
  decision: ask_picto
  required_scope: "git.push:main"
  match: { any_capability: ["git.push:refs/heads/main"] }
  reason: "main requires picto"
"#);
        let res = evaluate(&[Capability::new("git.push:refs/heads/main")], &pol);
        let Decision::AskPicto { required_scope, .. } = res.decision else {
            panic!("expected ask_picto");
        };
        assert_eq!(required_scope, "git.push:main");
    }
}
