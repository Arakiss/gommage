use gommage_core::{CapabilityMapper, Policy};
use std::collections::HashMap;

#[test]
fn valid_policy_seeds_parse() {
    for (name, source) in [
        (
            "allow-policy.yaml",
            include_str!("../seeds/configuration_parsers/allow-policy.yaml"),
        ),
        (
            "exact-ask-policy.yaml",
            include_str!("../seeds/configuration_parsers/exact-ask-policy.yaml"),
        ),
    ] {
        Policy::from_yaml_string(source, &HashMap::new(), name)
            .unwrap_or_else(|error| panic!("policy seed {name} must parse: {error}"));
    }
}

#[test]
fn valid_mapper_seed_parses() {
    CapabilityMapper::from_yaml_string(
        include_str!("../seeds/configuration_parsers/mapper.yaml"),
        "mapper.yaml",
    )
    .expect("mapper seed must parse");
}

#[test]
fn duplicate_key_seed_remains_rejected() {
    let source = include_str!("../seeds/configuration_parsers/invalid-duplicate.yaml");
    assert!(Policy::from_yaml_string(source, &HashMap::new(), "invalid-duplicate.yaml").is_err());
    assert!(CapabilityMapper::from_yaml_string(source, "invalid-duplicate.yaml").is_err());
}

#[test]
fn command_seeds_are_bounded_and_nonempty() {
    for (name, source) in [
        (
            "command-substitution",
            include_bytes!("../seeds/mapper_and_evaluator/command-substitution").as_slice(),
        ),
        (
            "git-delete-main",
            include_bytes!("../seeds/mapper_and_evaluator/git-delete-main").as_slice(),
        ),
        (
            "git-force-with-lease",
            include_bytes!("../seeds/mapper_and_evaluator/git-force-with-lease").as_slice(),
        ),
        (
            "git-main-refspec",
            include_bytes!("../seeds/mapper_and_evaluator/git-main-refspec").as_slice(),
        ),
        (
            "mixed-write",
            include_bytes!("../seeds/mapper_and_evaluator/mixed-write").as_slice(),
        ),
        (
            "quoted-data",
            include_bytes!("../seeds/mapper_and_evaluator/quoted-data").as_slice(),
        ),
        (
            "wrapped-hard-stop",
            include_bytes!("../seeds/mapper_and_evaluator/wrapped-hard-stop").as_slice(),
        ),
    ] {
        assert!(!source.is_empty(), "command seed {name} must not be empty");
        assert!(
            source.len() <= 64 * 1024,
            "command seed {name} must stay within the fuzz target bound"
        );
    }
}
