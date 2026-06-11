//! Bundled policy and capability mapper stdlib assets.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdlibFile {
    pub name: &'static str,
    pub contents: &'static str,
}

pub const POLICIES: &[StdlibFile] = &[
    StdlibFile {
        name: "00-hard-stops.yaml",
        contents: include_str!("../policies/00-hard-stops.yaml"),
    },
    StdlibFile {
        name: "03-recovery.yaml",
        contents: include_str!("../policies/03-recovery.yaml"),
    },
    StdlibFile {
        name: "10-filesystem.yaml",
        contents: include_str!("../policies/10-filesystem.yaml"),
    },
    StdlibFile {
        name: "15-agent-tools.yaml",
        contents: include_str!("../policies/15-agent-tools.yaml"),
    },
    StdlibFile {
        name: "20-git.yaml",
        contents: include_str!("../policies/20-git.yaml"),
    },
    StdlibFile {
        name: "30-package-managers.yaml",
        contents: include_str!("../policies/30-package-managers.yaml"),
    },
    StdlibFile {
        name: "35-system.yaml",
        contents: include_str!("../policies/35-system.yaml"),
    },
    StdlibFile {
        name: "40-cloud.yaml",
        contents: include_str!("../policies/40-cloud.yaml"),
    },
    StdlibFile {
        name: "45-egress-and-perms.yaml",
        contents: include_str!("../policies/45-egress-and-perms.yaml"),
    },
    StdlibFile {
        name: "50-cloud-tools.yaml",
        contents: include_str!("../policies/50-cloud-tools.yaml"),
    },
];

pub const CAPABILITIES: &[StdlibFile] = &[
    StdlibFile {
        name: "bash.yaml",
        contents: include_str!("../capabilities/bash.yaml"),
    },
    StdlibFile {
        name: "cloud-tools.yaml",
        contents: include_str!("../capabilities/cloud-tools.yaml"),
    },
    StdlibFile {
        name: "filesystem.yaml",
        contents: include_str!("../capabilities/filesystem.yaml"),
    },
    StdlibFile {
        name: "mcp.yaml",
        contents: include_str!("../capabilities/mcp.yaml"),
    },
    StdlibFile {
        name: "web.yaml",
        contents: include_str!("../capabilities/web.yaml"),
    },
];

/// Map a tool call to capabilities using the **bundled** stdlib capability
/// mappers (not the user's on-disk files). Falls back to a bare
/// `proc.exec:<command>` for a Bash call if the bundled mappers fail to compile,
/// so a compiled hard-stop on the raw command is still surfaced.
///
/// This is the capability source for the `GOMMAGE_BYPASS` kill-switch: it must
/// not read on-disk policy/capabilities, because the whole point of the
/// kill-switch is to keep working when those are broken.
pub fn bypass_capabilities(call: &gommage_core::ToolCall) -> Vec<gommage_core::Capability> {
    use gommage_core::{Capability, CapabilityMapper};
    let yaml = CAPABILITIES
        .iter()
        .map(|file| file.contents)
        .collect::<Vec<_>>()
        .join("\n");
    match CapabilityMapper::from_yaml_string(&yaml, "<compiled-stdlib-capabilities>") {
        Ok(mapper) => mapper.map(call),
        Err(_) => {
            if call.tool == "Bash"
                && let Some(command) = call.input.get("command").and_then(|value| value.as_str())
            {
                return vec![Capability::new(format!("proc.exec:{command}"))];
            }
            Vec::new()
        }
    }
}

/// Full `GOMMAGE_BYPASS` evaluation: map capabilities from the bundled stdlib,
/// then apply the bypass decision (compiled hard-stops still deny; everything
/// else is allowed with policy skipped). Single entry point shared by the
/// `gommage-mcp` hook binary and the `gommage mcp` CLI adapter so both behave
/// identically under the kill-switch.
pub fn evaluate_bypass(call: &gommage_core::ToolCall) -> gommage_core::EvalResult {
    gommage_core::evaluate_bypass(bypass_capabilities(call))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_policy_has_unambiguous_early_prefix() {
        assert!(POLICIES.iter().any(|file| file.name == "03-recovery.yaml"));
        assert!(!POLICIES.iter().any(|file| file.name == "05-recovery.yaml"));
    }

    #[test]
    fn bypass_evaluation_denies_hardstop_but_allows_normal() {
        use gommage_core::{Decision, ToolCall};
        let bash = |cmd: &str| ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({ "command": cmd }),
        };
        assert_eq!(evaluate_bypass(&bash("ls -la")).decision, Decision::Allow);
        let denied = evaluate_bypass(&bash("rm -rf /"));
        assert!(matches!(
            denied.decision,
            Decision::Gommage {
                hard_stop: true,
                ..
            }
        ));
    }
}
