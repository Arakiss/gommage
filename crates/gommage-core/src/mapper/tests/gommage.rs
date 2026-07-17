use super::*;

#[test]
fn typed_gommage_admin_inventory_is_closed_and_order_independent() {
    let mapper = typed_mapper();
    let cases: &[(&str, &str)] = &[
        ("gommage grant --scope git.push:main", "gommage.authorize"),
        ("/opt/homebrew/bin/gommage g --scope x", "gommage.authorize"),
        (
            "env LANG=C gommage --home /tmp/g grant --scope x",
            "gommage.authorize",
        ),
        ("gommage grant --home /tmp/g --scope x", "gommage.authorize"),
        ("command gommage revoke picto_1", "gommage.authorize"),
        ("bash -c 'gommage confirm picto_1'", "gommage.authorize"),
        (
            "gommage approval deny apr_1 --reason no",
            "gommage.authorize",
        ),
        (
            "gommage approval callback --signature x --timestamp t --signing-secret s",
            "gommage.authorize",
        ),
        (
            "gommage approval webhook --url https://approvals.example.test/hook",
            "gommage.authorize",
        ),
        ("gommage approval deny-stale --apply", "gommage.authorize"),
        ("gommage tui --view approvals", "gommage.authorize"),
        ("gommage init", "gommage.reconfigure"),
        (
            "gommage quickstart --home /tmp/g --agent codex",
            "gommage.reconfigure",
        ),
        (
            "gommage quickstart --home=/tmp/g --agent codex",
            "gommage.reconfigure",
        ),
        ("gommage policy init --stdlib", "gommage.reconfigure"),
        ("gommage project init", "gommage.reconfigure"),
        ("gommage agent install codex", "gommage.reconfigure"),
        ("gommage repair agent codex", "gommage.reconfigure"),
        ("gommage daemon install", "gommage.reconfigure"),
        ("gommage daemon reload", "gommage.reconfigure"),
        ("gommage upgrade --version latest", "gommage.reconfigure"),
        ("gommage expedition start audit", "gommage.reconfigure"),
        ("gommage expedition end", "gommage.reconfigure"),
        ("gommage harness write-context", "gommage.reconfigure"),
        ("gommage state rebuild", "gommage.reconfigure"),
        ("gommage state vacuum", "gommage.reconfigure"),
        ("gommage state reset", "gommage.reconfigure"),
        (
            "systemctl --user restart gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user try-reload-or-restart gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user edit gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user link /tmp/gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user reenable gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user preset gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user revert gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "systemctl --user unmask gommage-daemon.service",
            "gommage.reconfigure",
        ),
        (
            "launchctl kickstart gui/501/dev.gommage.daemon",
            "gommage.reconfigure",
        ),
        (
            "launchctl bootstrap gui/501 ~/Library/LaunchAgents/dev.gommage.daemon.plist",
            "gommage.reconfigure",
        ),
        (
            "launchctl submit -l dev.gommage.daemon -- /usr/local/bin/gommage-daemon",
            "gommage.reconfigure",
        ),
        ("gommage-daemon --foreground", "gommage.reconfigure"),
        (
            "/usr/local/bin/gommage-daemon --foreground",
            "gommage.reconfigure",
        ),
        ("gommage uninstall --all", "gommage.disable"),
        ("gommage agent uninstall all", "gommage.disable"),
        ("gommage daemon uninstall", "gommage.disable"),
        (
            "systemctl disable --now --user gommage-daemon.service",
            "gommage.disable",
        ),
        (
            "systemctl --user kill gommage-daemon.service",
            "gommage.disable",
        ),
        (
            "launchctl bootout gui/501/dev.gommage.daemon",
            "gommage.disable",
        ),
        (
            "launchctl kill SIGTERM gui/501/dev.gommage.daemon",
            "gommage.disable",
        ),
        ("launchctl remove dev.gommage.daemon", "gommage.disable"),
        ("pkill -f gommage-daemon", "gommage.disable"),
        ("pkill -f '[g]ommage-daemon'", "gommage.disable"),
        ("pkill -f 'gommage-daemo[n]'", "gommage.disable"),
        ("pkill -f 'gommage[-]daemon'", "gommage.disable"),
        ("pkill -i -f GOMMAGE-DAEMON", "gommage.disable"),
        ("pkill --signal TERM gommage-daemon", "gommage.disable"),
        ("killall gommage-daemon", "gommage.disable"),
        ("killall -r '^gommage-daemon$'", "gommage.disable"),
        ("killall --signal TERM gommage-daemon", "gommage.disable"),
    ];

    for (command, expected) in cases {
        let capabilities = caps_of(&mapper, command);
        assert!(
            capabilities.iter().any(|capability| capability == expected),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn typed_gommage_read_only_inventory_has_no_admin_effect() {
    let mapper = typed_mapper();
    let commands = [
        "gommage --help",
        "gommage --version",
        "gommage list --json",
        "gommage approval list --json",
        "gommage approval show apr_1",
        "gommage approval deny-stale",
        "gommage approval callback --dry-run --signature x --timestamp t --signing-secret s",
        "gommage approval webhook --dry-run --url https://approvals.example.test/hook",
        "gommage policy check",
        "gommage policy layers",
        "gommage agent status codex",
        "gommage daemon status",
        "gommage expedition status",
        "gommage harness diagnose",
        "gommage harness explain",
        "gommage state verify",
        "gommage state stats",
        "gommage explain audit_1",
        "gommage doctor --json",
        "gommage --home /tmp/g doctor --json",
        "gommage verify --json",
        "gommage tui --snapshot",
        "gommage tui --watch-ticks 1",
        "gommage tui --stream",
        "gommage quickstart --help",
        "gommage quickstart --dry-run --json",
        "gommage upgrade --dry-run",
        "gommage uninstall --all --dry-run",
        "gommage harness write-context --dry-run",
        "gommage state reset --dry-run",
        "systemctl --user status gommage-daemon.service",
        "systemctl --user status gommage-daemon.service stop",
        "launchctl print gui/501/dev.gommage.daemon",
        "launchctl print gui/501/dev.gommage.daemon remove",
        "service gommage-daemon status",
    ];

    for command in commands {
        let capabilities = caps_of(&mapper, command);
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.starts_with("gommage.")),
            "{command}: {capabilities:?}"
        );
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.starts_with("proc.exec.ambiguous:")),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn typed_gommage_home_mutations_name_the_exact_selected_authority_root() {
    let mapper = typed_mapper();
    let cases: &[(&str, &str)] = &[
        (
            "gommage --home /tmp/authorize grant --scope x",
            "gommage.home.mutate:/tmp/authorize",
        ),
        (
            "gommage init --home=/tmp/reconfigure",
            "gommage.home.mutate:/tmp/reconfigure",
        ),
        (
            "gommage uninstall --home /tmp/remove --purge-home --yes",
            "gommage.home.mutate:/tmp/remove",
        ),
        (
            "gommage --home ~/.gommage-alt daemon reload",
            "gommage.home.mutate:$HOME/.gommage-alt",
        ),
    ];

    for (command, expected) in cases {
        let capabilities = caps_of(&mapper, command);
        assert!(
            capabilities.iter().any(|capability| capability == expected),
            "{command}: missing {expected} in {capabilities:?}"
        );
    }

    let relative = caps_of_call(
        &mapper,
        ToolCall {
            tool: "Bash".into(),
            input: json!({
                "command": "gommage --home authority init",
                "__gommage_cwd": "/repo/work"
            }),
        },
    );
    assert!(
        relative
            .iter()
            .any(|capability| capability == "gommage.home.mutate:/repo/work/authority"),
        "{relative:?}"
    );
}

#[test]
fn direct_daemon_start_binds_home_and_socket_mutations() {
    let mapper = typed_mapper();
    for command in [
        "gommage-daemon --foreground --home /tmp/gommage-direct --socket /tmp/gommage-direct.sock",
        "/usr/local/bin/gommage-daemon --home=/tmp/gommage-direct --socket=/tmp/gommage-direct.sock",
    ] {
        let capabilities = caps_of(&mapper, command);
        for expected in [
            "gommage.reconfigure",
            "gommage.home.mutate:/tmp/gommage-direct",
            "fs.write:/tmp/gommage-direct.sock",
        ] {
            assert!(
                capabilities.iter().any(|capability| capability == expected),
                "{command}: missing {expected}: {capabilities:?}"
            );
        }
    }
}

#[test]
fn typed_gommage_non_home_mutations_do_not_invent_home_authority() {
    let mapper = typed_mapper();
    for command in [
        "gommage --home /tmp/g doctor --json",
        "gommage --home /tmp/g project init --root /repo/project",
        "gommage --home /tmp/g agent uninstall codex",
        "gommage --home /tmp/g daemon uninstall",
        "gommage --home /tmp/g repair agent codex --restore-backup",
        "gommage --home /tmp/g upgrade --force",
        "gommage --home /tmp/g uninstall --binaries --yes",
        "gommage --home /tmp/g quickstart --dry-run",
        "gommage --home /tmp/g uninstall --all --dry-run",
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.starts_with("gommage.home.mutate:")),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn unknown_or_dynamic_gommage_admin_forms_fail_closed() {
    let mapper = typed_mapper();
    for command in [
        "gommage mystery",
        "gommage approval maybe apr_1",
        "gommage --bogus doctor",
        "gommage \"$COMMAND\"",
        "gommage --home \"$TARGET\" doctor",
        "cargo run --bin gommage -- \"$COMMAND\"",
        "systemctl --user \"$ACTION\" gommage-daemon.service",
        "launchctl \"$ACTION\" gui/501/dev.gommage.daemon",
        "systemctl --user frobnicate gommage-daemon.service",
        "launchctl frobnicate gui/501/dev.gommage.daemon",
        "service gommage-daemon frobnicate",
        "systemctl --user stop \"$UNIT\"",
        "systemctl --user stop gommage-{daemon,daemon}.service",
        "printf '%s\\n' apr_1 | xargs gommage approval approve",
        "find . -maxdepth 0 -exec gommage daemon uninstall ';'",
        "find . -maxdepth 0 -execdir gommage approval approve '{}' ';'",
        "eval \"$COMMAND\"",
        "gommage-daemon --home",
        "gommage-daemon \"$OPTION\"",
        "cargo run --bin gommage-daemon --target",
        "cargo run --bin gommage-daemon --example",
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.starts_with("proc.exec.ambiguous:")),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn static_eval_and_watch_dispatchers_preserve_gommage_authority() {
    let mapper = typed_mapper();
    for (command, expected) in [
        ("eval 'gommage approval approve apr_1'", "gommage.authorize"),
        ("watch -n 1 gommage daemon uninstall", "gommage.disable"),
        (
            "watch --exec gommage approval approve apr_1",
            "gommage.authorize",
        ),
        (
            "watch -x sh -c 'gommage daemon uninstall'",
            "gommage.disable",
        ),
        (
            "builtin eval 'gommage approval approve apr_1'",
            "gommage.authorize",
        ),
        (
            "builtin command gommage approval approve apr_1",
            "gommage.authorize",
        ),
        ("builtin exec gommage daemon uninstall", "gommage.disable"),
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            capabilities.iter().any(|capability| capability == expected),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn unrelated_cargo_targets_and_services_have_no_gommage_admin_effect() {
    let mapper = typed_mapper();
    for command in [
        "cargo run -p other-cli -- grant --scope x",
        "cargo run --bin other-tool -- uninstall --all",
        "cargo run --bin gommage-daemon -- --help",
        "gommage-daemon --help",
        "/usr/local/bin/gommage-daemon --version",
        "cargo test -- run --bin gommage -- grant --scope x",
        "cargo run --example gommage -- grant --scope x",
        "systemctl --user restart postgresql.service",
        "systemctl --user stop docker.service",
        "launchctl kickstart gui/501/com.example.worker",
        "launchctl bootout gui/501/com.example.worker",
        "pkill -f other-daemon",
        "killall other-daemon",
        "kill -TERM 1234",
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.starts_with("gommage.")),
            "{command}: {capabilities:?}"
        );
        assert!(
            !capabilities.iter().any(|capability| capability
                .starts_with("proc.exec.ambiguous:unknown-gommage-admin-command")),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn cargo_homonyms_never_acquire_installed_gommage_authority() {
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
        "cargo run --locked --bin gommage -- approval approve apr_1",
        "cargo run -p gommage-cli -- grant --scope x",
        "cargo +stable --quiet r --package=gommage-cli@0.50.0-beta.1 -- daemon uninstall",
        "cargo run --manifest-path crates/gommage-cli/Cargo.toml -- grant --scope x",
        "cargo run --bin gommage-daemon -- --foreground --home /tmp/g --socket /tmp/g.sock",
        "cargo run -p gommage-daemon -- --foreground",
    ] {
        let capabilities = mapper.map(&bash(command));
        assert!(
            capabilities.iter().any(|capability| {
                capability.as_str() == "proc.exec.ambiguous:untrusted-cargo-gommage-execution"
            }),
            "{command}: {capabilities:?}"
        );
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.as_str().starts_with("gommage.")),
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
fn typed_gommage_caller_selected_paths_emit_exact_filesystem_effects() {
    let mapper = typed_mapper();
    let cases: &[(&str, &[&str])] = &[
        (
            "gommage approval evidence apr_1 --redact --output ~/.gommage/key.ed25519 --force",
            &["fs.write:$HOME/.gommage/key.ed25519"],
        ),
        (
            "gommage report bundle --redact --output=/repo/policy.d/05-harness-integrity.yaml --force",
            &["fs.write:/repo/policy.d/05-harness-integrity.yaml"],
        ),
        (
            "gommage approval callback --body ~/.gommage/key.ed25519 --signature x --timestamp t --signing-secret s",
            &["fs.read:$HOME/.gommage/key.ed25519"],
        ),
        (
            "gommage replay --audit /repo/audit.jsonl --policy /repo/policy.d",
            &["fs.read:/repo/audit.jsonl", "fs.read:/repo/policy.d"],
        ),
        (
            "gommage policy lint /repo/policy.yaml --strict",
            &["fs.read:/repo/policy.yaml"],
        ),
        (
            "gommage policy test --json /repo/fixtures.yaml",
            &["fs.read:/repo/fixtures.yaml"],
        ),
        (
            "gommage policy diff --from /repo/base --to /repo/candidate --against /repo/audit.jsonl",
            &[
                "fs.read:/repo/base",
                "fs.read:/repo/candidate",
                "fs.read:/repo/audit.jsonl",
            ],
        ),
        (
            "gommage policy suggest --audit /repo/audit.jsonl",
            &["fs.read:/repo/audit.jsonl"],
        ),
        (
            "gommage beta check --policy-test /repo/beta.yaml --policy-test=/repo/extra.yaml",
            &["fs.read:/repo/beta.yaml", "fs.read:/repo/extra.yaml"],
        ),
        (
            "gommage verify --policy-test /repo/verify.yaml",
            &["fs.read:/repo/verify.yaml"],
        ),
        (
            "gommage upgrade --bin-dir ~/.cargo/bin --force",
            &[
                "fs.write:$HOME/.cargo/bin",
                "fs.write:$HOME/.cargo/bin/gommage",
                "fs.write:$HOME/.cargo/bin/gommage-daemon",
                "fs.write:$HOME/.cargo/bin/gommage-mcp",
            ],
        ),
        (
            "gommage upgrade --installer /repo/install.sh --bin-dir /repo/bin --force",
            &["fs.read:/repo/install.sh", "fs.write:/repo/bin/gommage"],
        ),
        (
            "gommage project init --root /repo/project --force",
            &[
                "fs.write:/repo/project/.gommage/policy.d/20-project.yaml",
                "fs.write:/repo/project/.gommage/policy-fixtures.yaml",
                "fs.write:/repo/project/.gommage/README.md",
            ],
        ),
        (
            "gommage release verify --asset gommage-aarch64-darwin.tar.gz --dir /repo/release",
            &[
                "fs.write:/repo/release",
                "fs.write:/repo/release/gommage-aarch64-darwin.tar.gz",
                "fs.write:/repo/release/gommage-aarch64-darwin.tar.gz.sha256",
                "fs.write:/repo/release/gommage-aarch64-darwin.tar.gz.sigstore.json",
            ],
        ),
    ];

    for (command, expected) in cases {
        let capabilities = caps_of(&mapper, command);
        for expected in *expected {
            assert!(
                capabilities.iter().any(|capability| capability == expected),
                "{command}: missing {expected} in {capabilities:?}"
            );
        }
    }
}

#[test]
fn typed_gommage_dynamic_or_parent_paths_fail_closed() {
    let mapper = typed_mapper();
    for command in [
        "gommage report bundle --redact --output \"$TARGET\" --force",
        "gommage approval evidence apr_1 --output=\"$TARGET\" --force",
        "gommage report bundle --redact --output ../key.ed25519 --force",
        "gommage approval callback --body \"$BODY\" --signature x --timestamp t --signing-secret s",
        "gommage policy test \"$FIXTURE\"",
        "gommage project init --root ../authority --force",
        "gommage upgrade --bin-dir ../bin --force",
        "gommage release verify --dir \"$DIR\"",
        "gommage --home ../authority init",
        "gommage --home \"$HOME_ROOT\" grant --scope x",
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.starts_with("proc.exec.ambiguous:")),
            "{command}: {capabilities:?}"
        );
    }
}

#[test]
fn cwd_mutation_before_relative_effects_fails_closed() {
    let mapper = typed_mapper();
    for command in [
        "cd \"$HOME/.gommage\"; gommage report bundle --redact --output key.ed25519 --force",
        "cd \"$HOME/.gommage\" && gommage approval evidence apr_1 --output=key.ed25519 --force",
        "pushd /tmp; gommage --home authority init",
        "cd /tmp; touch relative-file",
        "(cd /tmp; gommage report bundle --output key.ed25519 --force)",
        "builtin -- cd /tmp; gommage report bundle --output key.ed25519 --force",
    ] {
        let capabilities = caps_of_call(
            &mapper,
            ToolCall {
                tool: "Bash".into(),
                input: json!({
                    "command": command,
                    "__gommage_cwd": "/repo"
                }),
            },
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability == "proc.exec.ambiguous:shell-cwd-mutation"),
            "{command}: {capabilities:?}"
        );
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.as_str().contains("/repo/key.ed25519")),
            "{command}: {capabilities:?}"
        );
    }

    let absolute = caps_of_call(
        &mapper,
        ToolCall {
            tool: "Bash".into(),
            input: json!({
                "command": "cd /tmp; gommage report bundle --output /safe/report.json",
                "__gommage_cwd": "/repo"
            }),
        },
    );
    assert!(
        !absolute
            .iter()
            .any(|capability| capability == "proc.exec.ambiguous:shell-cwd-mutation"),
        "{absolute:?}"
    );
    assert!(
        absolute
            .iter()
            .any(|capability| capability == "fs.write:/safe/report.json"),
        "{absolute:?}"
    );
}

#[test]
fn typed_gommage_non_writing_forms_do_not_invent_filesystem_effects() {
    let mapper = typed_mapper();
    for command in [
        "gommage approval evidence apr_1 --redact",
        "gommage approval callback --signature x --timestamp t --signing-secret s",
        "gommage upgrade --dry-run --bin-dir ~/.cargo/bin",
        "gommage project init --dry-run --root /repo/project",
        "gommage release verify",
    ] {
        let capabilities = caps_of(&mapper, command);
        assert!(
            !capabilities
                .iter()
                .any(|capability| capability.starts_with("fs.read:")
                    || capability.starts_with("fs.write:")),
            "{command}: {capabilities:?}"
        );
    }
}
