use serde::{Deserialize, Serialize};
use std::fmt;

/// A capability is an abstract, string-encoded claim about what a tool call
/// does. Policies match on capabilities; they do not read tool inputs directly.
///
/// Examples:
///   - `fs.read:/Users/dolores/Projects/foo/README.md`
///   - `fs.write:**/node_modules/**`
///   - `git.push:refs/heads/main`
///   - `net.out:api.stripe.com`
///   - `proc.exec:rm -rf /`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(s: impl Into<String>) -> Self {
        Capability(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The namespace is the substring up to the first colon.
    /// `git.push:refs/heads/main` → `git.push`.
    pub fn namespace(&self) -> &str {
        self.0.split_once(':').map_or(self.0.as_str(), |(ns, _)| ns)
    }

    /// The payload is everything after the first colon.
    pub fn payload(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, p)| p)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_string())
    }
}

impl From<String> for Capability {
    fn from(s: String) -> Self {
        Capability(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_and_payload() {
        let c = Capability::new("git.push:refs/heads/main");
        assert_eq!(c.namespace(), "git.push");
        assert_eq!(c.payload(), "refs/heads/main");
    }

    #[test]
    fn namespace_without_colon() {
        let c = Capability::new("proc.exec");
        assert_eq!(c.namespace(), "proc.exec");
        assert_eq!(c.payload(), "");
    }
}
