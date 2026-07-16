#![no_main]

use gommage_core::{CapabilityMapper, Policy, ToolCall, evaluate};
use libfuzzer_sys::fuzz_target;
use std::{collections::HashMap, sync::OnceLock};

fn engine() -> &'static (CapabilityMapper, Policy) {
    static ENGINE: OnceLock<(CapabilityMapper, Policy)> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mapper_yaml = gommage_stdlib::CAPABILITIES
            .iter()
            .map(|file| file.contents)
            .collect::<Vec<_>>()
            .join("\n");
        let mapper =
            CapabilityMapper::from_yaml_string(&mapper_yaml, "<fuzz-compiled-stdlib-capabilities>")
                .expect("compiled stdlib capability mapper must parse");

        let policy_yaml = gommage_stdlib::POLICIES
            .iter()
            .map(|file| file.contents)
            .collect::<Vec<_>>()
            .join("\n");
        let env = HashMap::from([
            ("HOME".to_string(), "/fuzz/home".to_string()),
            (
                "EXPEDITION_ROOT".to_string(),
                "/fuzz/expedition".to_string(),
            ),
        ]);
        let policy = Policy::from_yaml_string(&policy_yaml, &env, "<fuzz-compiled-stdlib-policy>")
            .expect("compiled stdlib policy must parse");

        (mapper, policy)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }

    let command = String::from_utf8_lossy(data).into_owned();
    let call = ToolCall {
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": command }),
    };
    let (mapper, policy) = engine();

    let first_capabilities = mapper.map(&call);
    let second_capabilities = mapper.map(&call);
    assert_eq!(first_capabilities, second_capabilities);

    let first = evaluate(&first_capabilities, policy);
    let second = evaluate(&second_capabilities, policy);
    assert_eq!(first.decision, second.decision);
    assert_eq!(first.matched_rule, second.matched_rule);
    assert_eq!(first.capabilities, second.capabilities);
    assert_eq!(first.policy_version, second.policy_version);
});
