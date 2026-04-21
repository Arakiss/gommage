use crate::Capability;
use globset::{GlobBuilder, GlobMatcher};
use std::sync::OnceLock;

/// The list of hardcoded, always-on capability patterns that Gommage will
/// gommage regardless of policy, picto, or expedition. Keep this list **finite**,
/// **documented**, and **hard to grow**: anything here must be universally
/// destructive.
///
/// Editing this list requires a PR. Do not source it from configuration.
///
/// Patterns are compiled with `literal_separator=false` because these entries
/// target `proc.exec:<command>` which is a flat command string, not a path —
/// `*` should match `/` freely here.
pub const HARD_STOPS: &[(&str, &str)] = &[
    ("hs.rm-rf-root", "proc.exec:rm -rf /*"),
    ("hs.rm-rf-root-strict", "proc.exec:rm -rf /"),
    ("hs.sudo-rm-rf", "proc.exec:sudo rm -rf *"),
    ("hs.mkfs", "proc.exec:mkfs*"),
    ("hs.dd-to-device", "proc.exec:dd if=* of=/dev/*"),
    ("hs.fork-bomb", "proc.exec:*:|:&*"),
    ("hs.wipe-disk", "proc.exec:shred /dev/*"),
    ("hs.chmod-system", "proc.exec:chmod -R * /"),
];

fn compiled() -> &'static [(&'static str, GlobMatcher)] {
    static CELL: OnceLock<Vec<(&'static str, GlobMatcher)>> = OnceLock::new();
    CELL.get_or_init(|| {
        HARD_STOPS
            .iter()
            .map(|(name, pat)| {
                let g = GlobBuilder::new(pat)
                    .literal_separator(false)
                    .backslash_escape(true)
                    .build()
                    .unwrap_or_else(|_| {
                        panic!("hardstop pattern {pat:?} failed to compile — this is a bug")
                    })
                    .compile_matcher();
                (*name, g)
            })
            .collect()
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardStopHit {
    pub name: &'static str,
    pub pattern: &'static str,
    pub capability: Capability,
}

/// Scan `caps` for anything matching the hardcoded hard-stop set.
/// Returns the **first** hit (deterministic, insertion-order).
pub fn check(caps: &[Capability]) -> Option<HardStopHit> {
    for (name, matcher) in compiled() {
        for cap in caps {
            if matcher.is_match(cap.as_str()) {
                let pattern = HARD_STOPS
                    .iter()
                    .find_map(|(n, p)| if n == name { Some(*p) } else { None })
                    .unwrap_or("");
                return Some(HardStopHit {
                    name,
                    pattern,
                    capability: cap.clone(),
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rm_rf_root_is_caught() {
        let caps = vec![Capability::new("proc.exec:rm -rf /")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn benign_ls_is_not_caught() {
        let caps = vec![Capability::new("proc.exec:ls -la")];
        assert!(check(&caps).is_none());
    }

    #[test]
    fn dd_of_device_is_caught() {
        let caps = vec![Capability::new("proc.exec:dd if=/dev/zero of=/dev/sda")];
        assert!(check(&caps).is_some());
    }

    #[test]
    fn fork_bomb_caught() {
        let caps = vec![Capability::new("proc.exec::(){ :|:& };:")];
        assert!(check(&caps).is_some());
    }
}
