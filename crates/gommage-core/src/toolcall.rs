use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum canonical bytes Authority will hash for one complete tool call.
pub const MAX_CANONICAL_TOOL_CALL_BYTES: usize = 256 * 1_024;
/// Maximum JSON nesting Authority will traverse inside one tool call.
pub const MAX_TOOL_CALL_JSON_DEPTH: usize = 64;
/// Maximum JSON values and object keys Authority will traverse in one tool call.
pub const MAX_TOOL_CALL_JSON_NODES: usize = 65_536;

/// A single tool call from an agent, as it appears on the wire.
///
/// We keep `input` as arbitrary JSON so the same type serves Bash, Read, Write,
/// Edit, or any tool a future agent might ship. The mapper is responsible for
/// interpreting the shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCall {
    pub tool: String,
    pub input: serde_json::Value,
}

impl ToolCall {
    /// SHA-256 commitment for an external host session identifier.
    ///
    /// The encoding is deliberately independent from [`ToolCall`] canonical
    /// JSON so adapter parity cannot drift if tool-call hashing evolves. It is
    /// `gommage.host-session.v1\0`, followed by the identifier's UTF-8 byte
    /// length as an unsigned 64-bit big-endian integer, followed by the UTF-8
    /// bytes themselves. Only this digest, never the raw identifier, should be
    /// inserted into canonical tool input.
    pub fn host_session_hash(session_id: &str) -> String {
        let session_bytes = session_id.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"gommage.host-session.v1\0");
        hasher.update((session_bytes.len() as u64).to_be_bytes());
        hasher.update(session_bytes);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Stable SHA-256 of the canonical JSON encoding. Used as the input_hash
    /// field in audit entries so `gommage explain` can reproduce decisions.
    pub fn input_hash(&self) -> String {
        // serde_json::to_vec is *not* canonical; for determinism we sort keys.
        let canonical = canonical_json::to_string(
            &serde_json::json!({ "tool": self.tool, "input": self.input }),
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub(crate) fn bounded_input_hash(&self) -> Result<String, String> {
        canonical_json::bounded_hash(self)
    }
}

mod canonical_json {
    use super::{
        MAX_CANONICAL_TOOL_CALL_BYTES, MAX_TOOL_CALL_JSON_DEPTH, MAX_TOOL_CALL_JSON_NODES, ToolCall,
    };
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::fmt::{self, Write};

    struct Budget {
        bytes: usize,
        nodes: usize,
    }

    impl Budget {
        fn add_bytes(&mut self, bytes: usize) -> Result<(), String> {
            self.bytes = self
                .bytes
                .checked_add(bytes)
                .ok_or_else(|| "canonical tool call size overflow".to_string())?;
            if self.bytes > MAX_CANONICAL_TOOL_CALL_BYTES {
                return Err(format!(
                    "canonical tool call exceeds {MAX_CANONICAL_TOOL_CALL_BYTES} bytes"
                ));
            }
            Ok(())
        }

        fn add_node(&mut self) -> Result<(), String> {
            self.nodes = self
                .nodes
                .checked_add(1)
                .ok_or_else(|| "tool call JSON node count overflow".to_string())?;
            if self.nodes > MAX_TOOL_CALL_JSON_NODES {
                return Err(format!(
                    "tool call JSON exceeds {MAX_TOOL_CALL_JSON_NODES} nodes"
                ));
            }
            Ok(())
        }

        fn add_encoded_string(&mut self, value: &str) -> Result<(), String> {
            self.add_bytes(2)?;
            for character in value.chars() {
                let encoded_len = match character {
                    '"' | '\\' | '\n' | '\r' | '\t' => 2,
                    character if (character as u32) < 0x20 => 6,
                    character => character.len_utf8(),
                };
                self.add_bytes(encoded_len)?;
            }
            Ok(())
        }

        fn add_display(&mut self, value: &impl fmt::Display) -> Result<(), String> {
            let mut writer = BudgetWriter {
                budget: self,
                error: None,
            };
            if write!(&mut writer, "{value}").is_err() {
                return Err(writer
                    .error
                    .unwrap_or_else(|| "canonical tool call formatting failed".into()));
            }
            Ok(())
        }
    }

    struct BudgetWriter<'a> {
        budget: &'a mut Budget,
        error: Option<String>,
    }

    impl fmt::Write for BudgetWriter<'_> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if let Err(error) = self.budget.add_bytes(value.len()) {
                self.error = Some(error);
                return Err(fmt::Error);
            }
            Ok(())
        }
    }

    pub fn to_string(v: &Value) -> String {
        let mut out = String::new();
        write_value(&mut out, v);
        out
    }

    pub fn bounded_hash(call: &ToolCall) -> Result<String, String> {
        let mut budget = Budget { bytes: 0, nodes: 0 };
        budget.add_bytes(18)?;
        for _ in 0..4 {
            budget.add_node()?;
        }
        budget.add_encoded_string(&call.tool)?;
        preflight_value(&call.input, 1, &mut budget)?;

        let mut hasher = Sha256::new();
        hasher.update(b"{\"input\":");
        hash_value(&mut hasher, &call.input);
        hasher.update(b",\"tool\":");
        hash_string(&mut hasher, &call.tool);
        hasher.update(b"}");
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    fn preflight_value(value: &Value, depth: usize, budget: &mut Budget) -> Result<(), String> {
        if depth > MAX_TOOL_CALL_JSON_DEPTH {
            return Err(format!(
                "tool call JSON exceeds depth {MAX_TOOL_CALL_JSON_DEPTH}"
            ));
        }
        budget.add_node()?;
        match value {
            Value::Null => budget.add_bytes(4),
            Value::Bool(true) => budget.add_bytes(4),
            Value::Bool(false) => budget.add_bytes(5),
            Value::Number(number) => budget.add_display(number),
            Value::String(value) => budget.add_encoded_string(value),
            Value::Array(values) => {
                budget.add_bytes(container_punctuation_bytes(values.len())?)?;
                for value in values {
                    preflight_value(value, depth + 1, budget)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                budget.add_bytes(container_punctuation_bytes(values.len())?)?;
                for (key, value) in values {
                    budget.add_node()?;
                    budget.add_encoded_string(key)?;
                    budget.add_bytes(1)?;
                    preflight_value(value, depth + 1, budget)?;
                }
                Ok(())
            }
        }
    }

    fn container_punctuation_bytes(len: usize) -> Result<usize, String> {
        if len == 0 {
            Ok(2)
        } else {
            len.checked_add(1)
                .ok_or_else(|| "canonical tool call size overflow".to_string())
        }
    }

    fn hash_value(hasher: &mut Sha256, value: &Value) {
        match value {
            Value::Null => hasher.update(b"null"),
            Value::Bool(value) => {
                hasher.update(if *value { &b"true"[..] } else { &b"false"[..] });
            }
            Value::Number(value) => hasher.update(value.to_string().as_bytes()),
            Value::String(value) => hash_string(hasher, value),
            Value::Array(values) => {
                hasher.update(b"[");
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        hasher.update(b",");
                    }
                    hash_value(hasher, value);
                }
                hasher.update(b"]");
            }
            Value::Object(values) => {
                hasher.update(b"{");
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort();
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        hasher.update(b",");
                    }
                    hash_string(hasher, key);
                    hasher.update(b":");
                    hash_value(hasher, &values[*key]);
                }
                hasher.update(b"}");
            }
        }
    }

    fn hash_string(hasher: &mut Sha256, value: &str) {
        hasher.update(b"\"");
        for character in value.chars() {
            match character {
                '"' => hasher.update(b"\\\""),
                '\\' => hasher.update(b"\\\\"),
                '\n' => hasher.update(b"\\n"),
                '\r' => hasher.update(b"\\r"),
                '\t' => hasher.update(b"\\t"),
                character if (character as u32) < 0x20 => {
                    hasher.update(format!("\\u{:04x}", character as u32).as_bytes());
                }
                character => {
                    let mut encoded = [0; 4];
                    hasher.update(character.encode_utf8(&mut encoded).as_bytes());
                }
            }
        }
        hasher.update(b"\"");
    }

    fn write_value(out: &mut String, v: &Value) {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            write!(out, "\\u{:04x}", c as u32).unwrap();
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, item) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_value(out, item);
                }
                out.push(']');
            }
            Value::Object(o) => {
                out.push('{');
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_value(out, &Value::String((*k).clone()));
                    out.push(':');
                    write_value(out, &o[*k]);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    fn arbitrary_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|value| json!(value)),
            ".{0,32}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                prop::collection::btree_map("[a-z]{0,8}", inner, 0..8)
                    .prop_map(|values| Value::Object(values.into_iter().collect())),
            ]
        })
    }

    fn nested_array(layers: usize) -> Value {
        (0..layers).fold(Value::Null, |value, _| Value::Array(vec![value]))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

        #[test]
        fn bounded_hash_matches_legacy_hash_for_arbitrary_accepted_json(
            tool in ".{1,32}",
            input in arbitrary_json(),
        ) {
            let call = ToolCall { tool, input };
            prop_assert_eq!(call.bounded_input_hash().unwrap(), call.input_hash());
        }
    }

    #[test]
    fn input_hash_is_key_order_independent() {
        let a = ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": "ls", "timeout": 5000 }),
        };
        let b = ToolCall {
            tool: "Bash".into(),
            input: json!({ "timeout": 5000, "command": "ls" }),
        };
        assert_eq!(a.input_hash(), b.input_hash());
    }

    #[test]
    fn input_hash_differs_for_different_content() {
        let a = ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": "ls" }),
        };
        let b = ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": "ls -la" }),
        };
        assert_ne!(a.input_hash(), b.input_hash());
    }

    #[test]
    fn bounded_hash_is_byte_identical_to_the_legacy_canonical_hash() {
        let call = ToolCall {
            tool: "MCP \"tool\"".into(),
            input: json!({
                "z": [null, true, false, 1.25, "line\nemoji 🧭"],
                "a": {"control": "\u{0001}", "slash": "\\"},
            }),
        };
        assert_eq!(call.bounded_input_hash().unwrap(), call.input_hash());
    }

    #[test]
    fn bounded_hash_rejects_oversized_and_overdeep_json() {
        let oversized = ToolCall {
            tool: "Bash".into(),
            input: json!({"command": "x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES)}),
        };
        assert!(oversized.bounded_input_hash().is_err());

        let mut nested = Value::Null;
        for _ in 0..=MAX_TOOL_CALL_JSON_DEPTH {
            nested = Value::Array(vec![nested]);
        }
        let overdeep = ToolCall {
            tool: "Bash".into(),
            input: nested,
        };
        assert!(overdeep.bounded_input_hash().is_err());
    }

    #[test]
    fn bounded_hash_limits_are_exact_at_bytes_depth_and_nodes() {
        let string_overhead = 18 + r#""Bash""#.len() + 2;
        let at_byte_limit = ToolCall {
            tool: "Bash".into(),
            input: Value::String("x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES - string_overhead)),
        };
        assert_eq!(
            canonical_json::to_string(&serde_json::to_value(&at_byte_limit).unwrap()).len(),
            MAX_CANONICAL_TOOL_CALL_BYTES
        );
        assert!(at_byte_limit.bounded_input_hash().is_ok());
        let over_byte_limit = ToolCall {
            tool: "Bash".into(),
            input: Value::String("x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES - string_overhead + 1)),
        };
        assert_eq!(
            canonical_json::to_string(&serde_json::to_value(&over_byte_limit).unwrap()).len(),
            MAX_CANONICAL_TOOL_CALL_BYTES + 1
        );
        assert!(over_byte_limit.bounded_input_hash().is_err());

        let at_depth_limit = ToolCall {
            tool: "Bash".into(),
            input: nested_array(MAX_TOOL_CALL_JSON_DEPTH - 1),
        };
        assert!(at_depth_limit.bounded_input_hash().is_ok());
        let over_depth_limit = ToolCall {
            tool: "Bash".into(),
            input: nested_array(MAX_TOOL_CALL_JSON_DEPTH),
        };
        assert!(over_depth_limit.bounded_input_hash().is_err());

        let at_node_limit = ToolCall {
            tool: "Bash".into(),
            input: Value::Array(vec![json!(0); MAX_TOOL_CALL_JSON_NODES - 5]),
        };
        assert!(at_node_limit.bounded_input_hash().is_ok());
        let over_node_limit = ToolCall {
            tool: "Bash".into(),
            input: Value::Array(vec![json!(0); MAX_TOOL_CALL_JSON_NODES - 4]),
        };
        assert!(over_node_limit.bounded_input_hash().is_err());
    }

    #[test]
    fn host_session_hash_has_a_stable_domain_separated_vector() {
        assert_eq!(
            ToolCall::host_session_hash("session-a"),
            "sha256:8e6c26332d7de24bc6270326afe3a44f35f04c297a9759a147898d9777f94961"
        );
        assert_ne!(
            ToolCall::host_session_hash("session-a"),
            ToolCall::host_session_hash("session-b")
        );
    }
}
