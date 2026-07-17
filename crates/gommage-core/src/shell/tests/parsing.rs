use super::*;

#[test]
fn parses_compounds_substitutions_and_static_shell_payloads() {
    let parsed = argv("echo $(touch a); command -- bash -c 'mkdir b && rm -rf /'");
    assert!(parsed.contains(&vec!["touch".into(), "a".into()]));
    assert!(!parsed.contains(&vec!["echo".into(), "$(touch a)".into()]));
    assert!(parsed.contains(&vec![
        "bash".into(),
        "-c".into(),
        "mkdir b && rm -rf /".into()
    ]));
    assert!(parsed.contains(&vec!["mkdir".into(), "b".into()]));
    assert!(parsed.contains(&vec!["rm".into(), "-rf".into(), "/".into()]));
}

#[test]
fn recursively_unwraps_transparent_wrappers() {
    let analysis = analyze(
        "exec env X=1 sudo -- timeout 2 nohup nice -n 3 stdbuf -o0 setsid command -- /bin/rm -rf /",
    );
    let command = analysis.commands.first().unwrap();
    assert_eq!(command.effective_head(), Ok("rm"));
    assert_eq!(command.static_argv().unwrap(), ["/bin/rm", "-rf", "/"]);
}

#[test]
fn package_mutations_are_derived_from_static_argv() {
    for (command, expected) in [
        (
            "cargo publish -p gommage-core",
            PackageManagerEffect::CargoPublish,
        ),
        (
            "cargo +stable --quiet publish",
            PackageManagerEffect::CargoPublish,
        ),
        (
            "env cargo install cargo-deny",
            PackageManagerEffect::CargoInstall,
        ),
        ("bun publish", PackageManagerEffect::BunPublish),
        ("bun add zod", PackageManagerEffect::BunInstall),
        (
            "npm publish --access public",
            PackageManagerEffect::NpmPublish,
        ),
        ("npm install zod", PackageManagerEffect::NpmInstall),
        ("twine upload dist/*", PackageManagerEffect::PythonPublish),
        ("pip3 upload dist/*", PackageManagerEffect::PythonPublish),
        (
            "python3 -m twine upload dist/*",
            PackageManagerEffect::PythonPublish,
        ),
        (
            "./scripts/publish-crates.sh --execute",
            PackageManagerEffect::CargoPublish,
        ),
        (
            "sh scripts/publish-crates.sh --execute",
            PackageManagerEffect::CargoPublish,
        ),
    ] {
        let effects = package_manager_effects(&analyze(command));
        assert!(
            effects.effects.contains(&expected),
            "{command}: {effects:?}"
        );
    }
}

#[test]
fn package_help_and_version_forms_are_not_mutations() {
    for command in [
        "cargo publish --help",
        "cargo publish -h",
        "cargo install --help",
        "cargo help publish",
        "cargo --help publish",
        "cargo publish --version",
        "npm publish --help",
        "npm install -h",
        "bun publish --help",
        "bun add --help",
        "twine upload --help",
        "pip upload --help",
        "python3 -m twine upload --help",
        "./scripts/publish-crates.sh --execute --help",
        "sh scripts/publish-crates.sh --help --execute",
    ] {
        let effects = package_manager_effects(&analyze(command));
        assert!(effects.effects.is_empty(), "{command}: {effects:?}");
        assert!(effects.ambiguities.is_empty(), "{command}: {effects:?}");
    }
}

#[test]
fn informational_segments_cannot_hide_a_real_publish() {
    for command in [
        "cargo publish --help && cargo publish",
        "cargo publish --help; sh scripts/publish-crates.sh --execute",
        "npm publish --help || bun publish",
    ] {
        let effects = package_manager_effects(&analyze(command));
        assert!(
            effects.effects.iter().any(|effect| matches!(
                effect,
                PackageManagerEffect::CargoPublish
                    | PackageManagerEffect::BunPublish
                    | PackageManagerEffect::NpmPublish
            )),
            "{command}: {effects:?}"
        );
    }
}

#[test]
fn dynamic_or_unknown_package_subcommands_fail_closed() {
    for command in [
        "cargo \"$VERB\"",
        "npm \"$VERB\"",
        "bun --future-option publish",
    ] {
        let effects = package_manager_effects(&analyze(command));
        assert!(!effects.ambiguities.is_empty(), "{command}: {effects:?}");
    }
}

#[test]
fn sudo_environment_assignments_preserve_nested_effects_but_fail_closed() {
    let head = "0123456789abcdef0123456789abcdef01234567";
    for command in [
        format!(
            "sudo FOO=bar gh pr merge 79 -R github.com/Arakiss/galdr --admin --match-head-commit {head}"
        ),
        format!(
            "sudo -- FOO=bar BAR=baz gh pr merge 79 -R github.com/Arakiss/galdr --admin --match-head-commit {head}"
        ),
        format!(
            "sudo A-B=bar gh pr merge 79 -R github.com/Arakiss/galdr --admin --match-head-commit {head}"
        ),
    ] {
        let analysis = analyze(&command);
        assert!(
            analysis
                .ambiguities
                .contains(&"wrapper-environment-mutation"),
            "{command}: {analysis:?}"
        );
        assert_eq!(analysis.commands[0].effective_head(), Ok("gh"));

        let effects = gh_pr_merge_effects(&analysis);
        assert!(
            effects.effects.contains(&GhPrMergeEffect::Merge(
                "github.com/arakiss/galdr#79".into()
            )),
            "{command}: {effects:?}"
        );
        assert!(
            effects.effects.contains(&GhPrMergeEffect::Admin(
                "github.com/arakiss/galdr#79".into()
            )),
            "{command}: {effects:?}"
        );
    }
}

#[test]
fn sudo_context_switches_are_ambiguous_without_hiding_nested_effects() {
    for prefix in [
        "sudo -E",
        "sudo --preserve-env",
        "sudo --preserve-env=FOO",
        "sudo -H",
        "sudo -R /tmp/root",
        "sudo --chroot=/tmp/root",
        "sudo -D /tmp",
        "sudo --chdir=/tmp",
        "sudo -i",
        "sudo -s",
    ] {
        let command = format!("{prefix} gh pr merge 79 -R github.com/Arakiss/galdr --squash");
        let analysis = analyze(&command);
        assert!(
            analysis.ambiguities.iter().any(|reason| matches!(
                *reason,
                "wrapper-environment-mutation" | "wrapper-execution-context-mutation"
            )),
            "{command}: {analysis:?}"
        );
        assert_eq!(analysis.commands[0].effective_head(), Ok("gh"));
        assert!(
            gh_pr_merge_effects(&analysis)
                .effects
                .contains(&GhPrMergeEffect::Merge(
                    "github.com/arakiss/galdr#79".into()
                )),
            "{command}: {analysis:?}"
        );
    }

    let transparent = analyze("sudo -n gh pr merge 79 -R github.com/Arakiss/galdr --squash");
    assert!(transparent.ambiguities.is_empty(), "{transparent:?}");
    assert_eq!(transparent.commands[0].effective_head(), Ok("gh"));

    for command in [
        "sudo \"$OPTION\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "sudo -R \"$ROOT\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
    ] {
        let analysis = analyze(command);
        assert!(
            analysis.ambiguities.contains(&"dynamic-wrapper-option"),
            "{command}: {analysis:?}"
        );
    }
}

#[test]
fn dynamic_wrapper_values_never_reposition_a_privileged_command() {
    let commands = [
        "timeout -s \"$SIG\" 30 gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "nice -n \"$N\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "stdbuf -o \"$MODE\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "doas -u \"$USER\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "exec -a \"$ARGV0\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
        "/usr/bin/time -f \"$FORMAT\" gh pr merge 79 -R github.com/Arakiss/galdr --squash",
    ];

    for command in commands {
        let analysis = analyze(command);
        assert!(
            analysis.ambiguities.contains(&"dynamic-wrapper-option"),
            "{command}: {analysis:?}"
        );
        assert!(
            !gh_pr_merge_effects(&analysis)
                .effects
                .iter()
                .any(|effect| matches!(effect, GhPrMergeEffect::Merge(_))),
            "{command}: {analysis:?}"
        );
    }
}

#[test]
fn doas_user_switch_preserves_the_nested_effect_but_fails_closed() {
    let command = "doas -u root gh pr merge 79 -R github.com/Arakiss/galdr --squash";
    let analysis = analyze(command);
    assert!(
        analysis
            .ambiguities
            .contains(&"wrapper-execution-context-mutation"),
        "{analysis:?}"
    );
    assert_eq!(analysis.commands[0].effective_head(), Ok("gh"));
    assert!(
        gh_pr_merge_effects(&analysis)
            .effects
            .contains(&GhPrMergeEffect::Merge(
                "github.com/arakiss/galdr#79".into()
            )),
        "{analysis:?}"
    );
}

#[test]
fn explicit_executables_require_a_trusted_installation_root() {
    for trusted in [
        "git",
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
        "$HOME/.cargo/bin/git",
        "$HOME/.local/bin/git",
    ] {
        assert_eq!(trusted_executable_basename(trusted), Ok("git"), "{trusted}");
    }
    for untrusted in [
        "./git",
        "/tmp/git",
        "/Users/other/.cargo/bin/git",
        "/usr/bin/../tmp/git",
    ] {
        assert_eq!(
            trusted_executable_basename(untrusted),
            Err("untrusted-executable-path"),
            "{untrusted}"
        );
    }
}

#[test]
fn command_query_is_not_unwrapped_as_execution() {
    let analysis = analyze("command -v rm");
    assert_eq!(analysis.commands[0].effective_head(), Ok("command"));
}

#[test]
fn home_and_quote_provenance_are_distinct() {
    let expanded = analyze(r#"rm -rf "$HOME//.""#);
    let literal = analyze("rm -rf '$HOME'");
    assert!(
        expanded.commands[0].effective_args()[1]
            .provenance
            .home_alias
    );
    assert!(
        !literal.commands[0].effective_args()[1]
            .provenance
            .home_alias
    );
    assert_eq!(
        static_path(&expanded.commands[0].effective_args()[1], None),
        Ok("$HOME".into())
    );
    assert_eq!(
        static_path(&literal.commands[0].effective_args()[1], None),
        Ok("./$HOME".into())
    );
}

#[test]
fn filesystem_effects_cover_all_operands_and_redirects() {
    let analysis = analyze("cp a b out && mv x y dest; cat one two < input > output");
    let effects = filesystem_effects(&analysis, Some("/repo//./"));
    let as_pairs: Vec<_> = effects
        .effects
        .iter()
        .map(|effect| (effect.kind, effect.path.as_str()))
        .collect();
    assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/a")));
    assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/b")));
    assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/out")));
    assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/x")));
    assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/y")));
    assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/dest")));
    assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/one")));
    assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/two")));
    assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/input")));
    assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/output")));
}

#[test]
fn option_schemas_do_not_consume_files_as_option_values() {
    let analysis = analyze(
        "cat -A first second; rm --one-file-system old cache; cp -tdest one two; install -d nested; rsync --remove-source-files sync-source sync-dest",
    );
    let effects = filesystem_effects(&analysis, Some("/repo"));
    let as_pairs: Vec<_> = effects
        .effects
        .iter()
        .map(|effect| (effect.kind, effect.path.as_str()))
        .collect();
    for expected in [
        "/repo/first",
        "/repo/second",
        "/repo/one",
        "/repo/two",
        "/repo/sync-source",
    ] {
        assert!(
            as_pairs.contains(&(FsEffectKind::Read, expected)),
            "missing read {expected}: {as_pairs:?}"
        );
    }
    for expected in [
        "/repo/old",
        "/repo/cache",
        "/repo/dest",
        "/repo/nested",
        "/repo/sync-source",
        "/repo/sync-dest",
    ] {
        assert!(
            as_pairs.contains(&(FsEffectKind::Write, expected)),
            "missing write {expected}: {as_pairs:?}"
        );
    }
}

#[test]
fn cwd_changing_and_split_string_wrappers_are_ambiguous() {
    for command in ["env -C /tmp touch x", "env -S 'touch x'"] {
        let analysis = analyze(command);
        assert!(!analysis.ambiguities.is_empty(), "{command}: {analysis:?}");
    }
}

#[test]
fn static_shell_payload_after_value_options_is_collected() {
    let parsed = argv("bash -O extglob --noprofile -c 'touch payload'");
    assert!(parsed.contains(&vec!["touch".into(), "payload".into()]));
}

#[test]
fn shell_interpreters_with_executable_stdin_are_ambiguous() {
    for command in [
        "bash <<'EOF'\ngommage approval approve apr_1\nEOF",
        "bash <<'EOF'\ngh pr merge 79 -R github.com/Arakiss/galdr --admin --match-head-commit 0123456789abcdef0123456789abcdef01234567\nEOF",
        "bash <<< 'gommage daemon reload'",
        "printf '%s\\n' 'gommage daemon reload' | bash",
        "/bin/bash <<'EOF'\ngommage daemon reload\nEOF",
        "printf '%s\\n' 'gommage daemon reload' | /usr/bin/sh",
        "command -- /bin/zsh <<< 'gommage daemon reload'",
        "printf '%s\\n' 'gommage daemon reload' | env /bin/bash",
        "bash /dev/stdin <<'EOF'\ngommage daemon reload\nEOF",
        "bash - <<'EOF'\ngommage daemon reload\nEOF",
        "bash -s <<'EOF'\ngommage daemon reload\nEOF",
        "sh -s <<'EOF'\ngommage daemon reload\nEOF",
        "zsh -se <<'EOF'\ngommage daemon reload\nEOF",
        "bash -x <<'EOF'\ngommage daemon reload\nEOF",
        "sh -eu <<'EOF'\ngommage daemon reload\nEOF",
        "zsh -f <<'EOF'\ngommage daemon reload\nEOF",
        "bash +x <<'EOF'\ngommage daemon reload\nEOF",
        "bash +O extglob <<'EOF'\ngommage daemon reload\nEOF",
        "printf '%s\\n' 'gommage daemon reload' | bash -s -- arg",
        "{ bash; } <<'EOF'\ngommage daemon reload\nEOF",
        "printf '%s\\n' 'gommage daemon reload' | ( /bin/bash )",
    ] {
        let analysis = analyze(command);
        assert!(
            analysis.ambiguities.contains(&"shell-stdin-program"),
            "{command}: {analysis:?}"
        );
    }
}

#[test]
fn opaque_interpreter_inline_and_stdin_programs_are_ambiguous() {
    for command in [
        "python -c 'print(1)'",
        "python3 -ic 'print(1)'",
        "python3.13 -c 'print(1)'",
        "python3 -X dev -c 'print(1)'",
        "node -e 'console.log(1)'",
        "node --eval='console.log(1)'",
        "node --input-type module -e 'console.log(1)'",
        "perl -we 'print 1'",
        "perl -M strict -e 'print 1'",
        "ruby -we 'puts 1'",
        "ruby -E UTF-8 -e 'puts 1'",
        "php -r 'echo 1;'",
        "php -r'echo 1;'",
        "php -H -r 'echo 1;'",
        "dash -c 'gommage daemon reload'",
        "busybox sh -c 'gommage daemon reload'",
    ] {
        let analysis = analyze(command);
        assert!(
            analysis.ambiguities.contains(&"interpreter-inline-program"),
            "{command}: {analysis:?}"
        );
    }

    for command in [
        "python <<'EOF'\nprint(1)\nEOF",
        "printf '%s\\n' 'console.log(1)' | node",
        "perl - <<'EOF'\nprint 1\nEOF",
        "ruby <<'EOF'\nputs 1\nEOF",
        "php <<'EOF'\n<?php echo 1; ?>\nEOF",
        "dash <<'EOF'\ngommage daemon reload\nEOF",
        "busybox ash <<'EOF'\ngommage daemon reload\nEOF",
    ] {
        let analysis = analyze(command);
        assert!(
            analysis.ambiguities.contains(&"interpreter-stdin-program"),
            "{command}: {analysis:?}"
        );
    }
}

#[test]
fn interpreter_pseudo_fd_programs_are_ambiguous_for_every_numeric_descriptor() {
    for command in [
        "bash /dev/fd/9 9<<'EOF'\ngommage daemon reload\nEOF",
        "sh /proc/self/fd/42 42<<< 'gommage daemon reload'",
        "zsh /proc/thread-self/fd/7 7<<'EOF'\ngommage daemon reload\nEOF",
        "python3 /dev/fd/11 11<<'EOF'\nprint(1)\nEOF",
        "node /proc/self/fd/3 3<<< 'console.log(1)'",
        "perl /proc/thread-self/fd/17 17<<'EOF'\nprint 1\nEOF",
        "ruby /dev/fd/5 5<<< 'puts 1'",
        "php -f /proc/self/fd/8 8<<'EOF'\n<?php echo 1; ?>\nEOF",
        "php --process-file=/dev/fd/18 18<<'EOF'\n<?php echo 1; ?>\nEOF",
        "dash /dev/fd/12 12<<< 'gommage daemon reload'",
        "busybox sh /proc/thread-self/fd/6 6<<'EOF'\ngommage daemon reload\nEOF",
    ] {
        let analysis = analyze(command);
        assert!(
            analysis
                .ambiguities
                .contains(&"interpreter-pseudo-fd-program"),
            "{command}: {analysis:?}"
        );
    }
}
