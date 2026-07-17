use super::*;
use crate::{Capability, Decision, evaluate};

fn env() -> HashMap<String, String> {
    let mut e = HashMap::new();
    e.insert("EXPEDITION_ROOT".into(), "/home/user/project".into());
    e
}

#[test]
fn env_substitution() {
    let out = substitute_env("allow fs.read:${EXPEDITION_ROOT}/**", &env()).unwrap();
    assert_eq!(out, "allow fs.read:/home/user/project/**");
}

#[test]
fn env_substitution_with_default() {
    let out = substitute_env("x ${NONEXISTENT:-fallback} y", &HashMap::new()).unwrap();
    assert_eq!(out, "x fallback y");
}

#[test]
fn env_substitution_uses_default_for_empty_values() {
    let mut env = HashMap::new();
    env.insert("EMPTY".to_string(), String::new());

    let out = substitute_env("x ${EMPTY:-fallback} y", &env).unwrap();

    assert_eq!(out, "x fallback y");
}

#[test]
fn env_substitution_rejects_missing_empty_and_malformed_values() {
    let mut env = HashMap::new();
    env.insert("EMPTY".to_string(), "   ".to_string());

    for input in ["${MISSING}", "${EMPTY}", "${MISSING:-}", "${lowercase}"] {
        assert!(substitute_env(input, &env).is_err(), "accepted {input:?}");
    }
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
fn dotdot_glob_matches_shell_verb_write_paths() {
    // Locks the contract the shell-aware bash.yaml verb rules rely on: a
    // `tee`/`cp`/redirect target that escapes via `..` must hit
    // deny-dotdot-escape exactly like a Write tool call would.
    let yaml = r#"
- name: deny-dotdot
  decision: gommage
  match:
    any_capability:
      - "fs.write:**/../**"
      - "fs.read:**/../**"
  reason: "no dotdot"
"#;
    let p = Policy::from_yaml_string(yaml, &HashMap::new(), "test.yaml").unwrap();
    let r = &p.rules[0];
    assert!(
        r.r#match
            .matches(&[Capability::new("fs.write:/tmp/proj/../../etc/passwd")])
    );
    assert!(
        !r.r#match
            .matches(&[Capability::new("fs.write:/tmp/proj/src/lib.rs")])
    );
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
fn policy_hash_binds_path_normalizer_configuration() {
    let yaml = r#"
- name: allow-home-a
  decision: allow
  match:
    any_capability: ["fs.read:/home/a/**"]
"#;
    let mut env_a = HashMap::new();
    env_a.insert("HOME".into(), "/home/a".into());
    let mut env_b = HashMap::new();
    env_b.insert("HOME".into(), "/home/b".into());

    let policy_a = Policy::from_yaml_string(yaml, &env_a, "10-default.yaml").unwrap();
    let policy_b = Policy::from_yaml_string(yaml, &env_b, "10-default.yaml").unwrap();

    assert_eq!(
        evaluate(&[Capability::new("fs.read:~/x")], &policy_a).decision,
        Decision::Allow
    );
    assert_ne!(
        evaluate(&[Capability::new("fs.read:~/x")], &policy_b).decision,
        Decision::Allow
    );
    assert_ne!(policy_a.version_hash, policy_b.version_hash);
}

#[test]
fn layered_policy_preserves_layer_order() {
    let org = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let user = tempfile::tempdir().unwrap();
    std::fs::write(
        org.path().join("10-org.yaml"),
        r#"
- name: org-deny-secret
  decision: gommage
  match: { any_capability: ["fs.write:/repo/secret"] }
  reason: "org wins"
"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("10-project.yaml"),
        r#"
- name: project-ask-secret
  decision: ask_picto
  required_scope: "project:secret"
  match: { any_capability: ["fs.write:/repo/secret"] }
"#,
    )
    .unwrap();
    std::fs::write(
        user.path().join("10-user.yaml"),
        r#"
- name: user-allow-all
  decision: allow
  match: { any_capability: ["fs.write:*"] }
"#,
    )
    .unwrap();

    let policy = Policy::load_from_layers(
        &[
            PolicyLayer::organization(org.path()),
            PolicyLayer::user(user.path()),
            PolicyLayer::project(project.path()),
        ],
        &HashMap::new(),
    )
    .unwrap();

    assert_eq!(policy.rules[0].name, "org-deny-secret");
    assert_eq!(policy.rules[1].name, "user-allow-all");
    assert_eq!(policy.rules[2].name, "project-ask-secret");
}

#[test]
fn layered_policy_hash_includes_layer_name() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let yaml = r#"
- name: deny-read
  decision: gommage
  match:
    any_capability: ["fs.read:/repo/**"]
  reason: "test policy"
"#;
    std::fs::write(a.path().join("10-default.yaml"), yaml).unwrap();
    std::fs::write(b.path().join("10-default.yaml"), yaml).unwrap();

    let org_user = Policy::load_from_layers(
        &[
            PolicyLayer::organization(a.path()),
            PolicyLayer::user(b.path()),
        ],
        &HashMap::new(),
    )
    .unwrap();
    let project_user = Policy::load_from_layers(
        &[PolicyLayer::user(b.path()), PolicyLayer::project(a.path())],
        &HashMap::new(),
    )
    .unwrap();

    assert_ne!(org_user.version_hash, project_user.version_hash);
}

#[test]
fn layered_policy_rejects_noncanonical_or_duplicate_order() {
    let user = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();

    for layers in [
        vec![
            PolicyLayer::project(project.path()),
            PolicyLayer::user(user.path()),
        ],
        vec![
            PolicyLayer::user(user.path()),
            PolicyLayer::user(user.path()),
        ],
    ] {
        let error = Policy::load_from_layers(&layers, &HashMap::new()).unwrap_err();
        assert!(
            error.to_string().contains("ordered org, user, project"),
            "{error}"
        );
    }
}

#[test]
fn policy_loader_rejects_unresolved_variables_before_yaml_parsing() {
    for value in [None, Some(""), Some("   ")] {
        let mut env = HashMap::new();
        if let Some(value) = value {
            env.insert("EXPEDITION_ROOT".to_string(), value.to_string());
        }
        let error = Policy::from_yaml_string(
            r#"
- name: unsafe-root
  decision: allow
  match: { any_capability: ["fs.write:${EXPEDITION_ROOT}/**"] }
"#,
            &env,
            "unsafe.yaml",
        )
        .unwrap_err();
        assert!(error.to_string().contains("EXPEDITION_ROOT"), "{error}");
    }
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

#[test]
fn ask_picto_scope_must_fit_the_picto_signing_domain() {
    for scope in [
        String::new(),
        "safe\u{202e}evil".to_string(),
        "safe\u{2066}evil".to_string(),
        "s".repeat(513),
    ] {
        let yaml = serde_yaml::to_string(&vec![RawRule {
            name: "invalid-scope".to_string(),
            decision: RuleDecision::AskPicto,
            hard_stop: false,
            required_scope: Some(scope),
            required_scope_from_capability: None,
            bind_input: false,
            r#match: RawMatch {
                any_capability: vec!["mcp.write:*".to_string()],
                ..RawMatch::default()
            },
            reason: "must be approvable".to_string(),
        }])
        .unwrap();
        let error = Policy::from_yaml_string(&yaml, &HashMap::new(), "invalid.yaml").unwrap_err();
        assert!(
            error.to_string().contains("invalid required_scope"),
            "{error}"
        );
    }
}

#[test]
fn ask_picto_can_require_an_exact_input_binding() {
    let yaml = r#"
- name: exact-deployment
  decision: ask_picto
  required_scope: "deploy.production"
  bind_input: true
  match: { any_capability: ["deploy.production"] }
  reason: "exact reviewed deployment required"
"#;
    let policy = Policy::from_yaml_string(yaml, &HashMap::new(), "t").unwrap();
    assert!(policy.rules[0].bind_input);
}

#[test]
fn ask_picto_can_compile_scope_from_an_exact_all_capability_pattern() {
    let yaml = r#"
- name: scoped-mcp-write
  decision: ask_picto
  required_scope_from_capability: "mcp.write:*"
  match:
    all_capability: ["mcp.call:*", "mcp.write:*"]
  reason: "write requires approval"
"#;
    let policy = Policy::from_yaml_string(yaml, &HashMap::new(), "dynamic.yaml").unwrap();

    assert!(policy.rules[0].required_scope.is_none());
    assert_eq!(
        policy.rules[0].required_scope_from_capability.as_deref(),
        Some("mcp.write:*")
    );
    assert!(
        policy.rules[0]
            .required_scope_from_capability_matcher
            .is_some()
    );
}

#[test]
fn policy_reports_static_and_derived_picto_scope_binding_modes() {
    let yaml = r#"
- name: dynamic-input-bound
  decision: ask_picto
  required_scope_from_capability: "mcp.write:*"
  bind_input: true
  match:
    all_capability: ["mcp.write:*"]
- name: shared-scope-only
  decision: ask_picto
  required_scope: "shared.scope"
  match:
    all_capability: ["task.scope-only:*"]
- name: shared-input-bound
  decision: ask_picto
  required_scope: "shared.scope"
  bind_input: true
  match:
    all_capability: ["task.input-bound:*"]
"#;
    let policy = Policy::from_yaml_string(yaml, &HashMap::new(), "requirements.yaml").unwrap();

    assert_eq!(
        policy.picto_scope_requirements("mcp.write:server/tool"),
        Some(PictoScopeRequirements {
            has_scope_only_rule: false,
            has_input_bound_rule: true,
        })
    );
    assert_eq!(
        policy.picto_scope_requirements("shared.scope"),
        Some(PictoScopeRequirements {
            has_scope_only_rule: true,
            has_input_bound_rule: true,
        })
    );
    assert!(policy.can_require_picto_scope("mcp.write:server/tool"));
    assert!(!policy.can_require_picto_scope("unknown.scope"));
    assert!(
        policy
            .picto_scope_requirements(&format!("mcp.write:safe{}evil", '\u{202e}'))
            .is_none()
    );
}

#[test]
fn ask_picto_scope_sources_are_mutually_exclusive() {
    let yaml = r#"
- name: ambiguous-scope
  decision: ask_picto
  required_scope: "mcp.write:server"
  required_scope_from_capability: "mcp.write:*"
  match:
    all_capability: ["mcp.write:*"]
"#;
    let error = Policy::from_yaml_string(yaml, &HashMap::new(), "invalid.yaml").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("required_scope and required_scope_from_capability are mutually exclusive"),
        "{error}"
    );
}

#[test]
fn capability_derived_scope_is_only_valid_for_ask_picto() {
    for decision in ["allow", "gommage"] {
        let yaml = format!(
            r#"
- name: invalid-decision
  decision: {decision}
  required_scope_from_capability: "mcp.write:*"
  match:
    all_capability: ["mcp.write:*"]
"#
        );
        let error = Policy::from_yaml_string(&yaml, &HashMap::new(), "invalid.yaml").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("required_scope_from_capability is only valid with decision=ask_picto"),
            "{error}"
        );
    }
}

#[test]
fn capability_derived_scope_must_exactly_match_an_all_capability_pattern() {
    for (selector, match_clause) in [
        ("mcp.write:*", "any_capability: [\"mcp.write:*\"]"),
        ("mcp.write:**", "all_capability: [\"mcp.write:*\"]"),
    ] {
        let yaml = format!(
            r#"
- name: invalid-selector
  decision: ask_picto
  required_scope_from_capability: "{selector}"
  match:
    {match_clause}
"#
        );
        let error = Policy::from_yaml_string(&yaml, &HashMap::new(), "invalid.yaml").unwrap_err();

        assert!(
                error.to_string().contains(
                    "required_scope_from_capability must exactly match a pattern in match.all_capability"
                ),
                "{error}"
            );
    }
}

#[test]
fn input_binding_is_rejected_for_non_picto_rules() {
    let yaml = r#"
- name: invalid
  decision: allow
  bind_input: true
  match: { any_capability: ["fs.read:*"] }
"#;
    let err = Policy::from_yaml_string(yaml, &HashMap::new(), "t").unwrap_err();
    assert!(matches!(err, GommageError::Policy(_)));
}

#[test]
fn home_alias_capability_hits_home_rule_before_broad_allow() {
    let yaml = r#"
- name: deny-gommage-home-tamper
  decision: gommage
  match:
    any_capability: ["fs.write:${HOME}/.gommage/policy.d/**"]
  reason: "protected"
- name: broad-home-allow
  decision: allow
  match:
    any_capability: ["fs.write:~/.gommage/**"]
"#;
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/home/operator".to_string());
    let policy = Policy::from_yaml_string(yaml, &env, "test.yaml").unwrap();

    let eval = evaluate(
        &[Capability::new("fs.write:~/.gommage/policy.d/x.yaml")],
        &policy,
    );

    assert_eq!(
        eval.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("deny-gommage-home-tamper")
    );
    assert!(matches!(eval.decision, Decision::Gommage { .. }));
    assert_eq!(
        eval.capabilities,
        vec![Capability::new(
            "fs.write:/home/operator/.gommage/policy.d/x.yaml"
        )]
    );
}

#[test]
fn tilde_policy_pattern_matches_absolute_capability() {
    let yaml = r#"
- name: deny-shell-rc-write
  decision: gommage
  match:
    any_capability: ["fs.write:~/.zshrc"]
  reason: "protected"
"#;
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/home/operator".to_string());
    let policy = Policy::from_yaml_string(yaml, &env, "test.yaml").unwrap();

    let eval = evaluate(
        &[Capability::new("fs.write:/home/operator/.zshrc")],
        &policy,
    );

    assert_eq!(
        eval.matched_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("deny-shell-rc-write")
    );
}

#[test]
fn home_alias_normalization_is_prefix_bounded_and_stable() {
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/home/operator/".to_string());
    let policy = Policy::from_yaml_string("[]", &env, "test.yaml").unwrap();

    let normalized = policy.normalize_capabilities(&[
        Capability::new("fs.write:~/.gommage/policy.d/x.yaml"),
        Capability::new("fs.write:/home/operator/.gommage/policy.d/x.yaml"),
        Capability::new("fs.read:$HOME"),
        Capability::new("fs.search:${HOME}/src"),
        Capability::new("fs.write:~other/.gommage/policy.d/x.yaml"),
        Capability::new("fs.write:/home/operator2/settings.json"),
        Capability::new("fs.write:relative/path"),
        Capability::new("proc.exec:$HOME/bin/tool"),
    ]);

    assert_eq!(
        normalized,
        vec![
            Capability::new("fs.read:/home/operator"),
            Capability::new("fs.search:/home/operator/src"),
            Capability::new("fs.write:/home/operator/.gommage/policy.d/x.yaml"),
            Capability::new("fs.write:/home/operator2/settings.json"),
            Capability::new("fs.write:relative/path"),
            Capability::new("fs.write:~other/.gommage/policy.d/x.yaml"),
            Capability::new("proc.exec:$HOME/bin/tool"),
        ]
    );
}

#[test]
fn root_home_alias_does_not_introduce_a_double_slash() {
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/".to_string());
    let policy = Policy::from_yaml_string("[]", &env, "test.yaml").unwrap();

    assert_eq!(
        policy.normalize_capabilities(&[Capability::new("fs.write:~/config")]),
        vec![Capability::new("fs.write:/config")]
    );
}
