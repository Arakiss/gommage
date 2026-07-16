#![no_main]

use gommage_core::{Capability, CapabilityMapper, Policy, ToolCall, evaluate};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let source = String::from_utf8_lossy(data);
    let env = HashMap::from([
        ("HOME".to_string(), "/fuzz/home".to_string()),
        (
            "EXPEDITION_ROOT".to_string(),
            "/fuzz/expedition".to_string(),
        ),
    ]);

    if let Ok(first_policy) = Policy::from_yaml_string(&source, &env, "<fuzz-policy>") {
        let second_policy = Policy::from_yaml_string(&source, &env, "<fuzz-policy>")
            .expect("a deterministic parser must accept the same source twice");
        let capabilities = data
            .chunks(32)
            .take(16)
            .map(|chunk| Capability::new(format!("fuzz:{}", encode_hex(chunk))))
            .collect::<Vec<_>>();
        let first = evaluate(&capabilities, &first_policy);
        let second = evaluate(&capabilities, &second_policy);
        assert_eq!(first.decision, second.decision);
        assert_eq!(first.matched_rule, second.matched_rule);
        assert_eq!(first.capabilities, second.capabilities);
        assert_eq!(first.policy_version, second.policy_version);
    }

    if let Ok(first_mapper) = CapabilityMapper::from_yaml_string(&source, "<fuzz-mapper>") {
        let second_mapper = CapabilityMapper::from_yaml_string(&source, "<fuzz-mapper>")
            .expect("a deterministic parser must accept the same source twice");
        let call = ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({ "command": source }),
        };
        assert_eq!(first_mapper.map(&call), second_mapper.map(&call));
    }
});

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
