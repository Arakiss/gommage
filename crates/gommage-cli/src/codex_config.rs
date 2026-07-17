use toml_edit::{DocumentMut, value};

pub(crate) const CODEX_HOOKS_FEATURE_KEY: &str = "hooks";
pub(crate) const CODEX_LEGACY_HOOKS_FEATURE_KEY: &str = "codex_hooks";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CodexHooksFeatureState {
    pub(crate) hooks: Option<bool>,
    pub(crate) legacy_codex_hooks: Option<bool>,
}

impl CodexHooksFeatureState {
    pub(crate) fn canonical_enabled(self) -> bool {
        self.hooks == Some(true)
    }

    pub(crate) fn legacy_only_enabled(self) -> bool {
        self.hooks != Some(true) && self.legacy_codex_hooks == Some(true)
    }
}

pub(crate) fn codex_hooks_feature_state(config: &DocumentMut) -> CodexHooksFeatureState {
    let hooks = codex_feature_bool(config, CODEX_HOOKS_FEATURE_KEY);
    let legacy_codex_hooks = codex_feature_bool(config, CODEX_LEGACY_HOOKS_FEATURE_KEY);
    CodexHooksFeatureState {
        hooks,
        legacy_codex_hooks,
    }
}

pub(crate) fn enable_codex_hooks_feature(config: &mut DocumentMut) {
    config["features"][CODEX_HOOKS_FEATURE_KEY] = value(true);
}

fn codex_feature_bool(config: &DocumentMut, key: &str) -> Option<bool> {
    config
        .get("features")
        .and_then(|features| features.get(key))
        .and_then(|value| value.as_bool())
}
