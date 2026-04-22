use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub fn read_json_object(path: &Path) -> Result<serde_json::Value> {
    if !path.exists() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("{} must contain a JSON object", path.display());
    }
    Ok(value)
}

pub fn read_toml_document(path: &Path) -> Result<toml_edit::DocumentMut> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parsing {}", path.display()))
}

pub fn write_json(path: &Path, value: &serde_json::Value, dry_run: bool) -> Result<()> {
    let mut raw = serde_json::to_string_pretty(value)?;
    raw.push('\n');
    write_text(path, &raw, dry_run)
}

pub fn write_text(path: &Path, contents: &str, dry_run: bool) -> Result<()> {
    if path.exists() && std::fs::read_to_string(path)? == contents {
        println!("ok unchanged: {}", path.display());
        return Ok(());
    }
    if dry_run {
        println!("plan write: {}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let backup = backup_path(path);
        std::fs::copy(path, &backup)?;
        println!("ok backup: {} -> {}", path.display(), backup.display());
    }
    std::fs::write(path, contents)?;
    println!("ok wrote: {}", path.display());
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let ts = OffsetDateTime::now_utc().unix_timestamp();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    path.with_file_name(format!("{file_name}.gommage-bak-{ts}"))
}

pub fn env_path_or_home(env_var: &str, components: &[&str]) -> PathBuf {
    if let Ok(path) = std::env::var(env_var) {
        return PathBuf::from(path);
    }
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    for component in components {
        path.push(component);
    }
    path
}

pub fn path_details(path: &Path) -> serde_json::Value {
    serde_json::json!({ "path": path_display(path) })
}

pub fn path_display(path: &Path) -> String {
    path.display().to_string()
}
