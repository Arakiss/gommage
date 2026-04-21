use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
}

mod canonical_json {
    use serde_json::Value;
    use std::fmt::Write;

    pub fn to_string(v: &Value) -> String {
        let mut out = String::new();
        write_value(&mut out, v);
        out
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
    use serde_json::json;

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
}
