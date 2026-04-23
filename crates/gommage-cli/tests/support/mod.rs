use std::process::Command;

pub fn gommage(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gommage"));
    cmd.env("GOMMAGE_HOME", home);
    cmd
}

#[allow(dead_code)]
pub fn workspace_path(relative: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[allow(dead_code)]
pub fn doctor_check<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report
        .get("checks")
        .and_then(|checks| checks.as_array())
        .unwrap()
        .iter()
        .find(|check| check.get("name").and_then(|value| value.as_str()) == Some(name))
        .unwrap()
}
