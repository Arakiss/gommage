//! Throttled, cached new-version check.
//!
//! `gommage update` / `gommage upgrade` already hit GitHub to compare the
//! installed binary against the latest installable release. This module
//! persists the *result* of that comparison to `~/.gommage/update-check.json`
//! so that `gommage doctor` can surface "an upgrade is available" with no
//! network I/O of its own.
//!
//! Two contracts hold everywhere in this module:
//!   * **Read does no network.** `read_cache` only touches one local file.
//!   * **Fail-open.** Any error (missing file, bad JSON, network down, GitHub
//!     5xx, no matching release, disk full) leaves the caller unaffected: no
//!     panic, no propagated error, no change to exit codes. A failed refresh
//!     leaves the existing cache exactly as it was.

use std::{
    fs,
    path::{Path, PathBuf},
};

use gommage_core::runtime::HomeLayout;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::self_update::{self, UpdateReport, UpdateStatus};

/// How long a cached check stays fresh before a refresh is allowed.
///
/// Used by the throttled [`refresh_if_stale`] entry point. The `update` /
/// `upgrade` commands persist their freshly-fetched report directly via
/// [`persist_report`] (the user explicitly asked, so no throttle applies);
/// `refresh_if_stale` is the gated path reserved for opportunistic callers
/// (and the deferred daemon refresh).
#[cfg_attr(not(test), allow(dead_code))]
const DEFAULT_TTL: Duration = Duration::hours(24);

/// Snapshot of the most recent new-version check, persisted between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UpdateCheckCache {
    #[serde(with = "rfc3339")]
    pub(crate) checked_at: OffsetDateTime,
    pub(crate) current_version: String,
    pub(crate) latest_tag: String,
    pub(crate) latest_version: String,
    pub(crate) status: UpdateStatus,
}

/// The canonical cache path inside the Gommage home.
pub(crate) fn cache_path(layout: &HomeLayout) -> PathBuf {
    layout.update_check.clone()
}

/// Read the cached check. Returns `None` on ANY error (missing file,
/// unreadable, malformed JSON, bad timestamp). Never touches the network.
pub(crate) fn read_cache(path: &Path) -> Option<UpdateCheckCache> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// True when the cache is older than `ttl` relative to `now`. A timestamp in
/// the future (clock skew, a file copied from another machine) is treated as
/// FRESH so a negative duration never triggers a refresh or panics.
pub(crate) fn is_stale(cache: &UpdateCheckCache, ttl: Duration, now: OffsetDateTime) -> bool {
    let age = now - cache.checked_at;
    age >= ttl
}

/// Persist a freshly-built [`UpdateReport`] as the cache. Best-effort: any
/// failure is swallowed so it can never affect the caller's exit code.
pub(crate) fn persist_report(layout: &HomeLayout, report: &UpdateReport) {
    let cache = UpdateCheckCache {
        checked_at: OffsetDateTime::now_utc(),
        current_version: report.current_version.clone(),
        latest_tag: report.latest_tag.clone(),
        latest_version: report.latest_version.clone(),
        status: report.status,
    };
    let _ = write_cache(&cache_path(layout), &cache);
}

/// Refresh the cache only when it is missing or older than `ttl`.
///
/// Throttle gate first: a fresh cache short-circuits BEFORE any network call.
/// Otherwise `build_update_report` is invoked (the same machinery `gommage
/// update` uses, so no version-parse or GitHub-fetch logic is duplicated). On
/// any error this returns silently and leaves the existing cache untouched.
pub(crate) fn refresh_if_stale(layout: &HomeLayout, repo: &str, ttl: Duration) {
    let path = cache_path(layout);
    if let Some(cache) = read_cache(&path)
        && !is_stale(&cache, ttl, OffsetDateTime::now_utc())
    {
        return; // throttle: still fresh, do not fetch.
    }
    // Cache missing or stale: fetch. Any error -> leave the cache as-is.
    match self_update::build_update_report(repo, "auto") {
        Ok(report) => persist_report(layout, &report),
        Err(_) => {
            // Fail-open: network down, GitHub error, no matching release, or a
            // JSON parse failure all leave the prior cache exactly as it was.
        }
    }
}

/// Refresh the cached check using the default 24h TTL. Thin wrapper so callers
/// (the `--if-stale` CLI mode, opportunistic hooks) do not need the const.
pub(crate) fn refresh(layout: &HomeLayout, repo: &str) {
    refresh_if_stale(layout, repo, DEFAULT_TTL);
}

/// A human-facing one-line upgrade notice if the cached status says a newer
/// version exists, else `None`. Pure read — never touches the network.
pub(crate) fn notice_line(layout: &HomeLayout) -> Option<String> {
    let cache = read_cache(&cache_path(layout))?;
    if cache.status == UpdateStatus::UpgradeAvailable {
        Some(format!(
            "\u{2b06} gommage {} is available (you have {}) \u{2014} run `gommage upgrade`",
            cache.latest_version, cache.current_version
        ))
    } else {
        None
    }
}

/// Atomic cache write: serialize to a sibling `.tmp` file then rename, so a
/// partial or failed write never truncates a live cache.
fn write_cache(path: &Path, cache: &UpdateCheckCache) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(cache)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// RFC3339 (string) serde for the `checked_at` timestamp. The cache file is
/// always written by us, so only the string form is needed; this mirrors the
/// `approval_time` module in `gommage-core::approval`.
mod rfc3339 {
    use serde::{Deserializer, Serializer, de};
    use std::fmt;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = value.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Rfc3339Visitor)
    }

    struct Rfc3339Visitor;

    impl de::Visitor<'_> for Rfc3339Visitor {
        type Value = OffsetDateTime;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an RFC3339 timestamp")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            OffsetDateTime::parse(value, &Rfc3339).map_err(E::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_update::TAG_PREFIX;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::tempdir;

    /// `GOMMAGE_RELEASES_JSON` is process-global; serialize tests that touch it.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn sample_cache(status: UpdateStatus) -> UpdateCheckCache {
        UpdateCheckCache {
            checked_at: OffsetDateTime::now_utc(),
            current_version: "0.39.0-beta.1".to_string(),
            latest_tag: "gommage-cli-v0.40.0-beta.1".to_string(),
            latest_version: "0.40.0-beta.1".to_string(),
            status,
        }
    }

    fn current_asset() -> &'static str {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "gommage-aarch64-darwin.tar.gz",
            ("macos", "x86_64") => "gommage-x86_64-darwin.tar.gz",
            ("linux", "aarch64") => "gommage-aarch64-linux.tar.gz",
            ("linux", "x86_64") => "gommage-x86_64-linux.tar.gz",
            _ => "gommage-aarch64-darwin.tar.gz",
        }
    }

    fn releases_fixture(version: &str) -> String {
        format!(
            r#"[{{"tag_name":"{TAG_PREFIX}{version}","assets":[{{"name":"{}"}}]}}]"#,
            current_asset()
        )
    }

    #[test]
    fn read_cache_missing_file_returns_none() {
        let td = tempdir().unwrap();
        let path = td.path().join("update-check.json");
        assert!(read_cache(&path).is_none());
    }

    #[test]
    fn read_cache_malformed_json_returns_none() {
        let td = tempdir().unwrap();
        let path = td.path().join("update-check.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(read_cache(&path).is_none());
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let td = tempdir().unwrap();
        let path = td.path().join("update-check.json");
        let cache = sample_cache(UpdateStatus::UpgradeAvailable);
        write_cache(&path, &cache).unwrap();

        // The on-disk status string must be the snake_case form.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("upgrade_available"));

        let back = read_cache(&path).expect("cache must read back");
        assert_eq!(back.current_version, cache.current_version);
        assert_eq!(back.latest_tag, cache.latest_tag);
        assert_eq!(back.latest_version, cache.latest_version);
        assert_eq!(back.status, UpdateStatus::UpgradeAvailable);
        assert_eq!(back.checked_at, cache.checked_at);
    }

    #[test]
    fn is_stale_true_when_older_than_ttl() {
        let mut cache = sample_cache(UpdateStatus::UpToDate);
        let now = OffsetDateTime::now_utc();
        cache.checked_at = now - Duration::hours(25);
        assert!(is_stale(&cache, Duration::hours(24), now));
    }

    #[test]
    fn is_stale_false_when_fresh() {
        let mut cache = sample_cache(UpdateStatus::UpToDate);
        let now = OffsetDateTime::now_utc();
        cache.checked_at = now - Duration::hours(1);
        assert!(!is_stale(&cache, Duration::hours(24), now));
    }

    #[test]
    fn is_stale_false_on_future_timestamp() {
        let mut cache = sample_cache(UpdateStatus::UpToDate);
        let now = OffsetDateTime::now_utc();
        cache.checked_at = now + Duration::hours(1);
        assert!(!is_stale(&cache, Duration::hours(24), now));
    }

    #[test]
    fn refresh_if_stale_fail_open_on_fetch_error() {
        let _guard = env_lock();
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        // Force fetch_releases -> build_update_report to Err with an unreadable path.
        let missing = td.path().join("does-not-exist.json");
        unsafe { std::env::set_var("GOMMAGE_RELEASES_JSON", &missing) };

        refresh_if_stale(&layout, "Arakiss/gommage", DEFAULT_TTL);

        unsafe { std::env::remove_var("GOMMAGE_RELEASES_JSON") };
        assert!(
            !cache_path(&layout).exists(),
            "a failed fetch must not write a cache file"
        );
    }

    #[test]
    fn refresh_if_stale_honors_throttle() {
        let _guard = env_lock();
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        let path = cache_path(&layout);
        // Pre-write a FRESH cache; refresh must NOT fetch.
        let fresh = sample_cache(UpdateStatus::UpToDate);
        write_cache(&path, &fresh).unwrap();
        let before = fs::read_to_string(&path).unwrap();

        // Point at a path that WOULD error if a fetch happened.
        let missing = td.path().join("does-not-exist.json");
        unsafe { std::env::set_var("GOMMAGE_RELEASES_JSON", &missing) };

        refresh_if_stale(&layout, "Arakiss/gommage", DEFAULT_TTL);

        unsafe { std::env::remove_var("GOMMAGE_RELEASES_JSON") };
        let after = fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "fresh cache must be left untouched (throttle)"
        );
    }

    #[test]
    fn refresh_writes_cache_from_fixture() {
        let _guard = env_lock();
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        let fixture = td.path().join("releases.json");
        fs::write(&fixture, releases_fixture("999.0.0")).unwrap();
        unsafe { std::env::set_var("GOMMAGE_RELEASES_JSON", &fixture) };

        refresh_if_stale(&layout, "Arakiss/gommage", DEFAULT_TTL);

        unsafe { std::env::remove_var("GOMMAGE_RELEASES_JSON") };
        let cache = read_cache(&cache_path(&layout)).expect("refresh must write a cache");
        assert_eq!(cache.status, UpdateStatus::UpgradeAvailable);
        assert_eq!(cache.latest_version, "999.0.0");
    }
    #[test]
    fn notice_line_present_only_when_upgrade_available() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        write_cache(
            &cache_path(&layout),
            &sample_cache(UpdateStatus::UpgradeAvailable),
        )
        .unwrap();
        let line = notice_line(&layout).expect("notice when an upgrade is available");
        assert!(line.contains("gommage"));
        assert!(line.contains("gommage upgrade"));
        write_cache(&cache_path(&layout), &sample_cache(UpdateStatus::UpToDate)).unwrap();
        assert!(notice_line(&layout).is_none());
    }
}
