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
        name: "40-cloud.yaml",
        contents: include_str!("../policies/40-cloud.yaml"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_policy_has_unambiguous_early_prefix() {
        assert!(POLICIES.iter().any(|file| file.name == "03-recovery.yaml"));
        assert!(!POLICIES.iter().any(|file| file.name == "05-recovery.yaml"));
    }
}
