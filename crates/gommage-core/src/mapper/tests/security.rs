use super::*;

#[test]
fn opaque_interpreter_programs_are_terminal_before_raw_execution_allows() {
    let mapper = typed_mapper();
    let policy = crate::Policy::from_yaml_string(
        r#"
- name: deny-opaque-interpreter
  decision: gommage
  hard_stop: true
  match:
    any_capability: ["proc.exec.ambiguous:*"]
  reason: "opaque interpreter execution is unresolved"
- name: allow-all-raw-execution
  decision: allow
  match:
    any_capability: ["proc.exec:*"]
  reason: "compatibility guard"
"#,
        &HashMap::new(),
        "opaque-interpreter-test.yaml",
    )
    .unwrap();

    for command in [
        "python -c 'print(1)'",
        "python3 <<'EOF'\nprint(1)\nEOF",
        "node -e 'console.log(1)'",
        "printf '%s\\n' 'console.log(1)' | node",
        "perl -e 'print 1'",
        "ruby -e 'puts 1'",
        "php -r 'echo 1;'",
        "dash -c 'echo ok'",
        "busybox sh -c 'echo ok'",
        "bash /dev/fd/9 9<<< 'echo ok'",
        "node --require /dev/fd/3 /dev/null 3<<< \"console.error('executed')\"",
        "node --require=/dev/fd/../fd/3 /dev/null",
        "node --import=file:///dev/fd/3 /dev/null 3<<< \"console.error('executed')\"",
        "node --import=file:///dev/%66d/3 /dev/null",
        "node '--import=data:text/javascript,console.error(1)' /dev/null",
        "node '--loader=data:text/javascript,export async function resolve(s,c,n){return n(s,c)}' /dev/null",
        "ruby -r/dev/fd/4 ./script.rb",
        "php -d auto_prepend_file=/dev/fd/5 ./script.php",
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.as_str().starts_with("proc.exec.ambiguous:")),
            "{command}: {capabilities:?}"
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.as_str().starts_with("proc.exec:")),
            "{command}: {capabilities:?}"
        );

        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-opaque-interpreter"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn every_derived_shell_execution_requires_its_own_policy_resolution() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();

    for command in [
        "gommage doctor && python3 -c 'print(1)'",
        "ls $(python3 -c 'print(1)')",
        "pwd $(python3 -c 'print(1)')",
        "command -v gommage $(python3 -c 'print(1)')",
        r#"sh -c "gommage doctor && python3 -c 'print(1)'""#,
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.as_str().starts_with("proc.exec:python3 -c")),
            "{command}: {capabilities:?}"
        );
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert_ne!(
            evaluated.decision,
            crate::Decision::Allow,
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn untrusted_explicit_executables_never_acquire_privileged_typed_effects() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    let head_commit = "0123456789abcdef0123456789abcdef01234567";
    let cases = [
        ("/tmp/gommage --help".to_string(), "gommage."),
        (
            format!(
                "/tmp/gh pr merge 79 -R github.com/Arakiss/galdr --admin --match-head-commit {head_commit}"
            ),
            "gh.pr.merge",
        ),
        ("/tmp/git push origin main".to_string(), "git.push"),
        (
            "/tmp/cargo run -p gommage-cli -- grant --scope git.push:main".to_string(),
            "gommage.",
        ),
    ];

    for (command, forbidden_prefix) in cases {
        let capabilities = mapper.map(&bash(&command));
        assert!(
            capabilities.iter().any(|capability| {
                capability.as_str() == "proc.exec.ambiguous:untrusted-executable-path"
            }),
            "{command}: {capabilities:?}"
        );
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.as_str().starts_with(forbidden_prefix)),
            "{command}: {capabilities:?}"
        );
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn dynamic_wrapper_options_and_static_identity_switches_fail_closed() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    for command in [
        "timeout -s \"$SIG\" 30 gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "nice -n \"$N\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "stdbuf -o \"$MODE\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "doas -u \"$USER\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "exec -a \"$ARGV0\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "/usr/bin/time -f \"$FORMAT\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "doas -u root gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "bash -O \"$OPT\" -c 'gommage daemon reload'",
        "bash -lc 'gommage daemon reload'",
        "bash -ic 'gommage daemon reload'",
        "bash --rcfile /tmp/mutable.bashrc -c 'gommage daemon reload'",
        "BASH_ENV=/tmp/mutable.bashenv bash -c 'gommage daemon reload'",
    ] {
        let evaluated = crate::evaluate(&mapper.map(&bash(command)), &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn dynamic_cargo_selector_values_fail_closed_before_gommage_authority() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    for command in [
        "cargo --config \"$CFG\" run --bin gommage -- approval approve apr_1",
        "cargo run --target \"$TARGET\" --bin gommage-daemon -- --foreground",
        "cargo run --features \"$FEATURES\" --bin gommage -- approval approve apr_1",
        "cargo run --bin gommage-daemon --target \"$TARGET\" -- --foreground",
    ] {
        let evaluated = crate::evaluate(&mapper.map(&bash(command)), &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn dynamic_service_killer_options_and_inverse_selection_fail_closed() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    for command in [
        "systemctl --host \"$HOST\" --user stop gommage-daemon.service",
        "systemctl --root \"$ROOT\" --user stop gommage-daemon.service",
        "pkill -u \"$USER\" gommage-daemon",
        "pkill --signal \"$SIGNAL\" gommage-daemon",
        "killall -u \"$USER\" gommage-daemon",
        "killall --signal \"$SIGNAL\" gommage-daemon",
        "pkill -v gommage-daemon",
        "pkill --inverse gommage-daemon",
        "launchctl submit -l dev.gommage.daemon -- \"$BIN\"",
        "launchctl bootstrap \"$DOMAIN\" ~/Library/LaunchAgents/dev.gommage.daemon.plist",
        "killall -g gommage-daemon",
        "killall --process-group gommage-daemon",
        "pkill -f '.*'",
        "pkill -f 'gommage-daemon|postgres'",
        "killall -r '.*'",
        "killall -r '^gommage.*'",
        "killall gommage-daemon postgres",
        "systemctl --user stop '*'",
        "systemctl --user stop '*.service'",
        "systemctl --user stop gommage-daemon.service postgresql.service",
        "service postgresql stop gommage-daemon",
        "launchctl submit -l dev.gommage.daemon -- /bin/sh -c evil",
        "launchctl load /tmp/dev.gommage.daemon.plist /tmp/evil.plist",
    ] {
        let capabilities = mapper.map(&bash(command));
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {capabilities:?}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {capabilities:?}: {evaluated:?}"
        );
    }
}

#[test]
fn compound_gommage_authority_cannot_cover_sibling_processes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();

    for command in [
        "python3 -c 'print(1)' ; gommage approval approve apr_1",
        "python3 -c 'print(1)' && gommage daemon reload",
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities.iter().any(|capability| {
                capability.as_str() == "proc.exec.ambiguous:compound-gommage-admin-command"
            }),
            "{command}: {capabilities:?}"
        );
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn compound_gh_body_file_authority_cannot_cover_sibling_reads_or_processes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();

    for command in [
        "cat /secret; gh pr merge 1 -R evil.example/attacker/repo --squash --body-file /safe",
        "python3 -c 'print(1)'; gh pr merge 1 -R evil.example/attacker/repo --squash --body-file /safe",
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities.iter().any(|capability| {
                capability.as_str() == "proc.exec.ambiguous:compound-gh-pr-merge-command"
            }),
            "{command}: {capabilities:?}"
        );
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn shell_resolution_mutators_cannot_share_gommage_authority() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    for command in [
        "export PATH=/tmp:$PATH; gommage approval approve apr_1",
        "export HOME=/tmp; $HOME/.cargo/bin/gommage approval approve apr_1",
        ". /tmp/mutable.sh; gommage daemon reload",
        "source /tmp/mutable.sh; gommage daemon reload",
        "alias gommage=/tmp/gommage; gommage daemon reload",
        "unalias gommage; gommage daemon reload",
        "hash -p /tmp/gommage gommage; gommage daemon reload",
        "enable -f /tmp/mutable.so gommage; gommage daemon reload",
        "typeset PATH=/tmp; gommage daemon reload",
        "declare HOME=/tmp; gommage daemon reload",
        "set PATH=/tmp; gommage daemon reload",
        "unset PATH; gommage daemon reload",
    ] {
        let evaluated = crate::evaluate(&mapper.map(&bash(command)), &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            ),
            "{command}: {evaluated:?}"
        );
        assert_eq!(
            evaluated
                .matched_rule
                .as_ref()
                .map(|rule| rule.name.as_str()),
            Some("deny-ambiguous-shell-effects"),
            "{command}: {evaluated:?}"
        );
    }
}

#[test]
fn compound_gommage_admin_command_cannot_cover_arbitrary_filesystem_writes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    let call = bash("gommage --home /authority/one init; touch /outside/authority");
    let capabilities = mapper.map(&call);

    assert!(
        capabilities
            .iter()
            .any(|capability| capability.as_str() == "gommage.home.mutate:/authority/one")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.as_str() == "fs.write:/outside/authority")
    );
    let evaluated = crate::evaluate(&capabilities, &policy);
    assert!(
        matches!(
            evaluated.decision,
            crate::Decision::Gommage {
                hard_stop: true,
                ..
            }
        ),
        "{evaluated:?}"
    );
    assert_eq!(
        evaluated
            .matched_rule
            .as_ref()
            .map(|rule| rule.name.as_str()),
        Some("deny-ambiguous-shell-effects"),
        "the arbitrary write must not inherit the Gommage home gate: {evaluated:?}"
    );
}

#[test]
fn shipped_gommage_home_gate_is_bound_to_each_exact_home_input() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();
    let first = bash("gommage --home /authority/one init");
    let second = bash("gommage --home /authority/two init");

    for call in [&first, &second] {
        let evaluated = crate::evaluate(&mapper.map(call), &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::AskPicto {
                    ref required_scope,
                    bind_input: true,
                    ..
                } if required_scope == "gommage.reconfigure"
            ),
            "{evaluated:?}"
        );
    }
    assert_ne!(
        first.input_hash(),
        second.input_hash(),
        "different selected homes must require different input-bound pictos"
    );
}

#[test]
fn shipped_force_policy_keeps_force_scope_without_affecting_normal_pushes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mapper = CapabilityMapper::load_from_dir(&root.join("capabilities")).unwrap();
    let mut env = HashMap::new();
    env.insert("HOME".to_string(), "/__home__".to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    let policy = crate::Policy::load_from_dir(&root.join("policies"), &env).unwrap();

    let normal = crate::evaluate(&mapper.map(&bash("git push origin main")), &policy);
    assert!(matches!(
        normal.decision,
        crate::Decision::AskPicto {
            ref required_scope,
            ..
        } if required_scope == "git.push:main"
    ));

    for command in [
        "git push --force origin main",
        "git push --force origin HEAD:main 2>&1",
        "git push origin +main > /tmp/push.log",
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == "git.push:refs/heads/main"),
            "{command}: {capabilities:?}"
        );
        assert!(!capabilities.iter().any(|cap| {
            cap.as_str().contains("refs/heads/2") || cap.as_str().contains("refs/heads/origin")
        }));
        let evaluated = crate::evaluate(&capabilities, &policy);
        assert!(
            matches!(
                evaluated.decision,
                crate::Decision::AskPicto {
                    ref required_scope,
                    ..
                } if required_scope == "git.push.force"
            ),
            "{command}: {evaluated:?}"
        );
    }
}
