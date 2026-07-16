use gommage_core::{
    Capability, CapabilityProvenanceStatus, Decision, EvalResult, Policy, PolicyLayer, evaluate,
};
use std::{collections::HashMap, fs};

fn policy(yaml: &str) -> Policy {
    Policy::from_yaml_string(yaml, &HashMap::new(), "inline-test.yaml").unwrap()
}

fn capability(value: &str) -> Capability {
    Capability::new(value)
}

fn provenance<'a>(result: &'a EvalResult, value: &str) -> &'a gommage_core::CapabilityProvenance {
    result
        .capability_provenance
        .iter()
        .find(|entry| entry.capability.as_str() == value)
        .unwrap_or_else(|| panic!("missing provenance for {value}"))
}

#[test]
fn one_allow_rule_covers_its_capability() {
    let policy = policy(
        r#"
- name: allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    );

    let result = evaluate(&[capability("cap:A")], &policy);

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("allow-a")
    );
}

#[test]
fn uncovered_sibling_fails_closed() {
    let policy = policy(
        r#"
- name: allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    assert!(matches!(
        result.decision,
        Decision::Gommage {
            hard_stop: false,
            ..
        }
    ));
    assert_eq!(
        provenance(&result, "cap:A").status,
        CapabilityProvenanceStatus::Resolved
    );
    assert_eq!(
        provenance(&result, "cap:B").status,
        CapabilityProvenanceStatus::Unresolved
    );
    assert!(result.matched_rule.is_none());
}

#[test]
fn deny_beats_allow_across_capabilities() {
    let policy = policy(
        r#"
- name: allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
- name: deny-b
  decision: gommage
  match: { any_capability: ["cap:B"] }
  reason: "B is denied"
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    assert_eq!(
        result.decision,
        Decision::Gommage {
            reason: "B is denied".to_string(),
            hard_stop: false,
        }
    );
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("deny-b")
    );
}

#[test]
fn one_ask_scope_beats_complete_allow_coverage() {
    let policy = policy(
        r#"
- name: allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
- name: ask-b
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:B"] }
  reason: "B needs approval"
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    assert_eq!(
        result.decision,
        Decision::AskPicto {
            required_scope: "scope:X".to_string(),
            reason: "B needs approval".to_string(),
            bind_input: false,
        }
    );
}

#[test]
fn same_ask_scope_ors_exact_input_binding() {
    let policy = policy(
        r#"
- name: ask-a
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:A"] }
  reason: "A needs approval"
- name: ask-b-exact
  decision: ask_picto
  required_scope: "scope:X"
  bind_input: true
  match: { any_capability: ["cap:B"] }
  reason: "B needs exact approval"
"#,
    );

    let result = evaluate(&[capability("cap:B"), capability("cap:A")], &policy);

    assert_eq!(
        result.decision,
        Decision::AskPicto {
            required_scope: "scope:X".to_string(),
            reason: "A needs approval".to_string(),
            bind_input: true,
        }
    );
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("ask-a")
    );
}

#[test]
fn distinct_ask_scopes_require_the_call_to_be_split() {
    let policy = policy(
        r#"
- name: ask-a
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:A"] }
  reason: "A needs approval"
- name: ask-b
  decision: ask_picto
  required_scope: "scope:Y"
  match: { any_capability: ["cap:B"] }
  reason: "B needs approval"
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    let Decision::Gommage { reason, hard_stop } = result.decision else {
        panic!("distinct scopes must synthesize a deny");
    };
    assert!(!hard_stop);
    assert!(reason.contains("scope:X, scope:Y"));
    assert!(reason.contains("split the call"));
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("ask-a")
    );
}

#[test]
fn all_patterns_cover_only_capabilities_that_match_a_positive_pattern() {
    let policy = policy(
        r#"
- name: allow-pair
  decision: allow
  match:
    all_capability: ["cap:A", "cap:B"]
"#,
    );

    let pair = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);
    assert_eq!(pair.decision, Decision::Allow);

    let with_sibling = evaluate(
        &[
            capability("cap:C"),
            capability("cap:B"),
            capability("cap:A"),
        ],
        &policy,
    );
    assert!(matches!(with_sibling.decision, Decision::Gommage { .. }));
    assert_eq!(
        provenance(&with_sibling, "cap:C").status,
        CapabilityProvenanceStatus::Unresolved
    );
}

#[test]
fn rules_require_positive_coverage_and_explicit_wildcards_remain_valid() {
    let empty = r#"
- name: empty
  decision: allow
"#;
    assert!(Policy::from_yaml_string(empty, &HashMap::new(), "empty.yaml").is_err());

    let negative_only = r#"
- name: negative-only
  decision: allow
  match: { none_capability: ["cap:B"] }
"#;
    assert!(Policy::from_yaml_string(negative_only, &HashMap::new(), "negative.yaml").is_err());

    let wildcard = policy(
        r#"
- name: explicit-wildcard
  decision: allow
  match: { any_capability: ["**"] }
"#,
    );
    assert_eq!(
        evaluate(&[capability("cap:anything")], &wildcard).decision,
        Decision::Allow
    );
}

#[test]
fn negative_conditions_are_rejected_for_deny_and_ask_rules() {
    let deny = r#"
- name: conditional-deny
  decision: gommage
  match:
    any_capability: ["cap:A"]
    none_capability: ["cap:B"]
"#;
    assert!(Policy::from_yaml_string(deny, &HashMap::new(), "deny.yaml").is_err());

    let ask = r#"
- name: conditional-ask
  decision: ask_picto
  required_scope: "scope:X"
  match:
    any_capability: ["cap:A"]
    none_capability: ["cap:B"]
"#;
    assert!(Policy::from_yaml_string(ask, &HashMap::new(), "ask.yaml").is_err());
}

#[test]
fn negative_allow_condition_can_only_withdraw_a_grant() {
    let policy = policy(
        r#"
- name: allow-a-without-b
  decision: allow
  match:
    any_capability: ["cap:A"]
    none_capability: ["cap:B"]
- name: ask-a
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:A"] }
  reason: "A needs approval when B is present"
- name: allow-b
  decision: allow
  match: { any_capability: ["cap:B"] }
"#,
    );

    assert_eq!(
        evaluate(&[capability("cap:A")], &policy).decision,
        Decision::Allow
    );
    assert!(matches!(
        evaluate(&[capability("cap:A"), capability("cap:B")], &policy).decision,
        Decision::AskPicto { .. }
    ));
}

#[test]
fn lower_layers_can_tighten_but_never_relax() {
    let project = tempfile::tempdir().unwrap();
    let user = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("10-project.yaml"),
        r#"
- name: project-allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    )
    .unwrap();
    fs::write(
        user.path().join("10-user.yaml"),
        r#"
- name: user-deny-a
  decision: gommage
  match: { any_capability: ["cap:A"] }
  reason: "user policy denies A"
"#,
    )
    .unwrap();

    let policy = Policy::load_from_layers(
        &[
            PolicyLayer::new("project", project.path()),
            PolicyLayer::new("user", user.path()),
        ],
        &HashMap::new(),
    )
    .unwrap();
    let result = evaluate(&[capability("cap:A")], &policy);

    assert_eq!(
        result.decision,
        Decision::Gommage {
            reason: "user policy denies A".to_string(),
            hard_stop: false,
        }
    );
    let contributions = &provenance(&result, "cap:A").contributions;
    assert_eq!(
        contributions
            .iter()
            .map(|entry| (entry.layer.as_str(), entry.layer_index))
            .collect::<Vec<_>>(),
        vec![("project", 0), ("user", 1)]
    );
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("user-deny-a")
    );
}

#[test]
fn project_deny_tightens_an_earlier_allow() {
    let user = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        user.path().join("10-user.yaml"),
        r#"
- name: user-allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    )
    .unwrap();
    fs::write(
        project.path().join("10-project.yaml"),
        r#"
- name: project-deny-a
  decision: gommage
  match: { any_capability: ["cap:A"] }
  reason: "project policy denies A"
"#,
    )
    .unwrap();

    let policy = Policy::load_from_layers(
        &[
            PolicyLayer::new("user", user.path()),
            PolicyLayer::new("project", project.path()),
        ],
        &HashMap::new(),
    )
    .unwrap();

    assert!(matches!(
        evaluate(&[capability("cap:A")], &policy).decision,
        Decision::Gommage { .. }
    ));
}

#[test]
fn benign_siblings_cannot_turn_deny_or_ask_into_allow() {
    let deny_policy = policy(
        r#"
- name: deny-a
  decision: gommage
  match: { any_capability: ["cap:A"] }
  reason: "A denied"
- name: allow-c
  decision: allow
  match: { any_capability: ["cap:C"] }
"#,
    );
    assert!(matches!(
        evaluate(&[capability("cap:A")], &deny_policy).decision,
        Decision::Gommage { .. }
    ));
    assert!(matches!(
        evaluate(&[capability("cap:A"), capability("cap:C")], &deny_policy).decision,
        Decision::Gommage { .. }
    ));

    let ask_policy = policy(
        r#"
- name: ask-a
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:A"] }
  reason: "A needs approval"
- name: allow-c
  decision: allow
  match: { any_capability: ["cap:C"] }
"#,
    );
    assert!(matches!(
        evaluate(&[capability("cap:A")], &ask_policy).decision,
        Decision::AskPicto { .. }
    ));
    assert!(matches!(
        evaluate(&[capability("cap:C"), capability("cap:A")], &ask_policy).decision,
        Decision::AskPicto { .. }
    ));
}

#[test]
fn capability_permutations_and_duplicates_serialize_identically() {
    let policy = policy(
        r#"
- name: allow-a
  decision: allow
  match: { any_capability: ["cap:A"] }
- name: ask-b
  decision: ask_picto
  required_scope: "scope:X"
  match: { any_capability: ["cap:B"] }
  reason: "B needs approval"
"#,
    );

    let first = evaluate(
        &[
            capability("cap:B"),
            capability("cap:A"),
            capability("cap:B"),
        ],
        &policy,
    );
    let second = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(
        first.capabilities,
        vec![capability("cap:A"), capability("cap:B")]
    );
}

#[test]
fn primary_provenance_uses_rule_order_not_capability_order() {
    let policy = policy(
        r#"
- name: first-rule-for-z
  decision: allow
  match: { any_capability: ["cap:Z"] }
- name: second-rule-for-a
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:Z")], &policy);

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("first-rule-for-z")
    );
    assert_eq!(provenance(&result, "cap:Z").contributions[0].rule.index, 0);
    assert_eq!(provenance(&result, "cap:A").contributions[0].rule.index, 1);
}

#[test]
fn first_match_is_scoped_to_one_layer_and_one_capability() {
    let policy = policy(
        r#"
- name: allow-a-first
  decision: allow
  match: { any_capability: ["cap:A"] }
- name: deny-b-first
  decision: gommage
  match: { any_capability: ["cap:B"] }
  reason: "B denied"
- name: deny-a-later
  decision: gommage
  match: { any_capability: ["cap:A"] }
  reason: "must not replace A's first match"
"#,
    );

    let result = evaluate(&[capability("cap:A"), capability("cap:B")], &policy);

    assert_eq!(
        provenance(&result, "cap:A").contributions[0].rule.name,
        "allow-a-first"
    );
    assert_eq!(
        provenance(&result, "cap:B").contributions[0].rule.name,
        "deny-b-first"
    );
    assert_eq!(
        result.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("deny-b-first")
    );
}

#[test]
fn compiled_hard_stop_marks_siblings_as_skipped() {
    let policy = policy(
        r#"
- name: allow-all
  decision: allow
  match: { any_capability: ["**"] }
"#,
    );

    let result = evaluate(
        &[
            capability("proc.exec:rm -rf /"),
            capability("proc.exec:echo safe"),
        ],
        &policy,
    );

    assert_eq!(
        provenance(&result, "proc.exec:rm -rf /").status,
        CapabilityProvenanceStatus::HardStop
    );
    assert_eq!(
        provenance(&result, "proc.exec:echo safe").status,
        CapabilityProvenanceStatus::SkippedDueToHardStop
    );
    assert!(
        provenance(&result, "proc.exec:echo safe")
            .contributions
            .is_empty()
    );
}

#[test]
fn inline_and_directory_policies_have_stable_layer_identity() {
    let inline = policy(
        r#"
- name: inline-allow
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    );
    assert_eq!(inline.rules[0].source.layer, "inline");
    assert_eq!(inline.rules[0].source.layer_index, 0);

    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("10-user.yaml"),
        r#"
- name: directory-allow
  decision: allow
  match: { any_capability: ["cap:A"] }
"#,
    )
    .unwrap();
    let loaded = Policy::load_from_dir(directory.path(), &HashMap::new()).unwrap();
    assert_eq!(loaded.rules[0].source.layer, "user");
    assert_eq!(loaded.rules[0].source.layer_index, 0);
    assert_eq!(loaded.rules[0].source.file_index, 0);
}

#[test]
fn older_evaluation_results_deserialize_with_empty_provenance() {
    let json = r#"{
        "decision": {"kind": "allow"},
        "matched_rule": null,
        "capabilities": ["cap:A"],
        "policy_version": "sha256:legacy"
    }"#;

    let result: EvalResult = serde_json::from_str(json).unwrap();

    assert!(result.capability_provenance.is_empty());
}
