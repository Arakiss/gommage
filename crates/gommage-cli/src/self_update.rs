use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use crate::release::resolve_asset;

const DEFAULT_REPO: &str = "Arakiss/gommage";
const INSTALLER_BRANCH: &str = "main";
const TAG_PREFIX: &str = "gommage-cli-v";

#[derive(Args)]
pub(crate) struct UpdateOptions {
    /// GitHub repository in OWNER/NAME form.
    #[arg(long, default_value = DEFAULT_REPO)]
    repo: String,
    /// Archive asset to require when resolving latest. Defaults to the current OS/arch.
    #[arg(long, default_value = "auto")]
    asset: String,
    /// Emit a stable machine-readable update report.
    #[arg(long)]
    json: bool,
    /// Exit 1 when a newer installable release exists.
    #[arg(long)]
    check: bool,
}

#[derive(Args)]
pub(crate) struct UpgradeOptions {
    /// Release tag to install. Defaults to the latest gommage-cli release.
    #[arg(long, alias = "tag", default_value = "latest")]
    version: String,
    /// GitHub repository in OWNER/NAME form.
    #[arg(long, default_value = DEFAULT_REPO)]
    repo: String,
    /// Install directory. Defaults to the current gommage executable directory.
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    /// cosign executable passed to the installer.
    #[arg(long)]
    cosign: Option<String>,
    /// Install or update the Gommage agent skill after binary upgrade.
    #[arg(long, conflicts_with = "no_skill")]
    with_skill: bool,
    /// Do not prompt for or install the Gommage agent skill.
    #[arg(long, conflicts_with = "with_skill")]
    no_skill: bool,
    /// Install or update only the Gommage agent skill; do not install binaries.
    #[arg(long)]
    skill_only: bool,
    /// Agent skill target. May be repeated.
    #[arg(long = "skill-agent", value_enum)]
    skill_agents: Vec<UpgradeSkillAgent>,
    /// Git ref for remote skill files.
    #[arg(long, default_value = INSTALLER_BRANCH)]
    skill_ref: String,
    /// Never prompt during installer execution.
    #[arg(long)]
    no_prompt: bool,
    /// Run `gommage verify` after installing binaries.
    #[arg(long)]
    verify: bool,
    /// Reinstall even when `gommage update` reports the current release is already latest.
    #[arg(long)]
    force: bool,
    /// Print the installer command without downloading or installing.
    #[arg(long)]
    dry_run: bool,
    /// Override installer script URL or local path.
    #[arg(long, hide = true, env = "GOMMAGE_INSTALLER_URL")]
    installer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum UpgradeSkillAgent {
    Codex,
    Claude,
    All,
}

impl UpgradeSkillAgent {
    fn as_installer_arg(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Serialize)]
struct UpdateReport {
    status: UpdateStatus,
    current_version: String,
    current_tag: String,
    latest_version: String,
    latest_tag: String,
    repo: String,
    asset: String,
    upgrade_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpdateStatus {
    UpToDate,
    UpgradeAvailable,
    AheadOfRelease,
}

impl UpdateStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::UpgradeAvailable => "upgrade_available",
            Self::AheadOfRelease => "ahead_of_release",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseVersion {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Vec<PrereleasePart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleasePart {
    Numeric(u64),
    Text(String),
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
}

pub(crate) fn cmd_update(options: UpdateOptions) -> Result<ExitCode> {
    let report = build_update_report(&options.repo, &options.asset)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_update_report(&report);
    }
    Ok(
        if options.check && report.status == UpdateStatus::UpgradeAvailable {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        },
    )
}

pub(crate) fn cmd_upgrade(options: UpgradeOptions) -> Result<ExitCode> {
    let installer = options.installer_url();
    let args = options.installer_args();

    if options.dry_run {
        print_upgrade_plan(&options, &installer, &args);
        return Ok(ExitCode::SUCCESS);
    }

    if should_skip_latest_upgrade(&options)? {
        return Ok(ExitCode::SUCCESS);
    }

    require_tool("curl")?;
    let tmp = std::env::temp_dir().join(format!("gommage-upgrade-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let script = tmp.join("install.sh");
    fetch_installer(&installer, &script)?;
    run_installer(&tmp, &script, &args)
}

impl UpgradeOptions {
    fn installer_url(&self) -> String {
        self.installer
            .clone()
            .unwrap_or_else(|| default_installer_url(&self.repo))
    }

    fn installer_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("--repo".to_string());
        args.push(self.repo.clone());

        if self.skill_only {
            args.push("--skill-only".to_string());
            args.push("--skill-ref".to_string());
            args.push(self.skill_ref.clone());
        } else {
            args.push("--version".to_string());
            args.push(self.version.clone());
            args.push("--bin-dir".to_string());
            args.push(
                self.bin_dir
                    .clone()
                    .or_else(default_bin_dir)
                    .unwrap_or_else(default_home_bin_dir)
                    .display()
                    .to_string(),
            );
            if let Some(cosign) = &self.cosign {
                args.push("--cosign".to_string());
                args.push(cosign.clone());
            }
            if self.with_skill {
                args.push("--with-skill".to_string());
                args.push("--skill-ref".to_string());
                args.push(self.skill_ref.clone());
            }
            if self.no_skill {
                args.push("--no-skill".to_string());
            }
            if self.verify {
                args.push("--verify".to_string());
            }
        }

        for agent in &self.skill_agents {
            args.push("--skill-agent".to_string());
            args.push(agent.as_installer_arg().to_string());
        }
        if self.no_prompt {
            args.push("--no-prompt".to_string());
        }
        args
    }
}

fn build_update_report(repo: &str, raw_asset: &str) -> Result<UpdateReport> {
    let asset = resolve_asset(raw_asset)?;
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let current_tag = format!("{TAG_PREFIX}{current_version}");
    let current = ReleaseVersion::parse(&current_version)
        .with_context(|| format!("parsing current version {current_version}"))?;
    let latest = latest_installable_release(repo, &asset)?;
    let latest_version = latest
        .tag
        .strip_prefix(TAG_PREFIX)
        .unwrap_or(&latest.tag)
        .to_string();
    let status = match latest.version.cmp(&current) {
        Ordering::Greater => UpdateStatus::UpgradeAvailable,
        Ordering::Equal => UpdateStatus::UpToDate,
        Ordering::Less => UpdateStatus::AheadOfRelease,
    };
    let upgrade_command = if status == UpdateStatus::UpgradeAvailable {
        "gommage upgrade".to_string()
    } else {
        "gommage upgrade --force".to_string()
    };

    Ok(UpdateReport {
        status,
        current_version,
        current_tag,
        latest_version,
        latest_tag: latest.tag,
        repo: repo.to_string(),
        asset,
        upgrade_command,
    })
}

fn print_update_report(report: &UpdateReport) {
    println!("Gommage update check");
    println!("status: {}", report.status.as_str());
    println!("current: {}", report.current_tag);
    println!("latest: {}", report.latest_tag);
    println!("repo: {}", report.repo);
    println!("asset: {}", report.asset);
    match report.status {
        UpdateStatus::UpgradeAvailable => {
            println!("next: {}", report.upgrade_command);
        }
        UpdateStatus::UpToDate => {
            println!("next: no binary upgrade needed");
            println!(
                "skills: gommage upgrade --skill-only --skill-agent codex --skill-agent claude"
            );
        }
        UpdateStatus::AheadOfRelease => {
            println!("next: current binary is newer than the latest published release");
            println!("repair: {}", report.upgrade_command);
        }
    }
}

fn print_upgrade_plan(options: &UpgradeOptions, installer: &str, args: &[String]) {
    println!("plan upgrade: run the Gommage installer");
    println!("repo: {}", options.repo);
    if options.skill_only {
        println!("mode: skill_only");
    } else {
        println!("target: {}", options.version);
        if let Some(bin_dir) = options
            .bin_dir
            .clone()
            .or_else(default_bin_dir)
            .or_else(|| Some(default_home_bin_dir()))
        {
            println!("bin_dir: {}", bin_dir.display());
        }
    }
    println!("installer: {installer}");
    println!("command: {}", display_installer_command(installer, args));
}

fn should_skip_latest_upgrade(options: &UpgradeOptions) -> Result<bool> {
    if options.force || options.skill_only || options.with_skill || options.version != "latest" {
        return Ok(false);
    }
    let report = build_update_report(&options.repo, "auto")?;
    match report.status {
        UpdateStatus::UpgradeAvailable => Ok(false),
        UpdateStatus::UpToDate => {
            println!(
                "ok gommage: already at latest installable release ({})",
                report.latest_tag
            );
            println!("repair: use `gommage upgrade --force` to reinstall the current release");
            Ok(true)
        }
        UpdateStatus::AheadOfRelease => {
            println!(
                "ok gommage: current binary ({}) is newer than latest published release ({})",
                report.current_tag, report.latest_tag
            );
            println!("repair: use `gommage upgrade --force` to reinstall the latest release");
            Ok(true)
        }
    }
}

struct LatestRelease {
    tag: String,
    version: ReleaseVersion,
}

fn latest_installable_release(repo: &str, asset: &str) -> Result<LatestRelease> {
    let releases = fetch_releases(repo)?;
    releases
        .into_iter()
        .filter_map(|release| {
            if !release.tag_name.starts_with(TAG_PREFIX) {
                return None;
            }
            if !release
                .assets
                .iter()
                .any(|candidate| candidate.name == asset)
            {
                return None;
            }
            let version = ReleaseVersion::parse(release.tag_name.strip_prefix(TAG_PREFIX)?).ok()?;
            Some(LatestRelease {
                tag: release.tag_name,
                version,
            })
        })
        .max_by(|left, right| left.version.cmp(&right.version))
        .ok_or_else(|| anyhow!("no installable gommage-cli release found in {repo} for {asset}"))
}

fn fetch_releases(repo: &str) -> Result<Vec<GithubRelease>> {
    let raw = if let Ok(path) = std::env::var("GOMMAGE_RELEASES_JSON") {
        std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?
    } else {
        require_tool("curl")?;
        let url = format!("https://api.github.com/repos/{repo}/releases?per_page=100");
        let mut command = authenticated_curl(&url);
        command_output(&mut command).with_context(|| format!("fetching {url}"))?
    };
    serde_json::from_str(&raw).context("parsing GitHub releases JSON")
}

fn fetch_installer(installer: &str, script: &Path) -> Result<()> {
    if let Some(path) = installer.strip_prefix("file://") {
        std::fs::copy(path, script)
            .with_context(|| format!("copying installer {} -> {}", path, script.display()))?;
        return Ok(());
    }
    let local_path = Path::new(installer);
    if local_path.exists() {
        std::fs::copy(local_path, script).with_context(|| {
            format!(
                "copying installer {} -> {}",
                local_path.display(),
                script.display()
            )
        })?;
        return Ok(());
    }
    command_status(authenticated_curl(installer).arg("-o").arg(script))
        .with_context(|| format!("downloading installer from {installer}"))
}

fn authenticated_curl(url: &str) -> Command {
    let mut command = Command::new("curl");
    command
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("-sSfL");
    if let Some(token) = github_token() {
        command
            .arg("-H")
            .arg(format!("Authorization: Bearer {token}"))
            .arg("-H")
            .arg("X-GitHub-Api-Version: 2022-11-28");
    }
    command.arg(url);
    command
}

fn github_token() -> Option<String> {
    ["GOMMAGE_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
}

fn run_installer(tmp: &Path, script: &Path, args: &[String]) -> Result<ExitCode> {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(
            "set -e; trap 'rm -rf \"$GOMMAGE_UPGRADE_TMP\"' EXIT INT TERM; sh \"$GOMMAGE_UPGRADE_SCRIPT\" \"$@\"",
        )
        .arg("gommage-upgrade")
        .args(args)
        .env("GOMMAGE_UPGRADE_TMP", tmp)
        .env("GOMMAGE_UPGRADE_SCRIPT", script);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        Err(err).context("executing installer")
    }

    #[cfg(not(unix))]
    {
        let status = command.status().context("running installer")?;
        Ok(status.code().map_or(ExitCode::from(1), |code| {
            ExitCode::from(code.clamp(0, 255) as u8)
        }))
    }
}

fn default_installer_url(repo: &str) -> String {
    format!("https://raw.githubusercontent.com/{repo}/{INSTALLER_BRANCH}/scripts/install.sh")
}

fn default_bin_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

fn default_home_bin_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("bin")
}

fn display_installer_command(installer: &str, args: &[String]) -> String {
    let mut parts = vec![
        "curl".to_string(),
        "--proto".to_string(),
        "'=https'".to_string(),
        "--tlsv1.2".to_string(),
        "-sSfL".to_string(),
        shell_quote(installer),
        "-o".to_string(),
        "<tmp>/install.sh".to_string(),
        "&&".to_string(),
        "sh".to_string(),
        "<tmp>/install.sh".to_string(),
    ];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '='))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl ReleaseVersion {
    fn parse(raw: &str) -> Result<Self> {
        let (core, prerelease) = raw.split_once('-').unwrap_or((raw, ""));
        let mut core_parts = core.split('.');
        let major = parse_core_part(core_parts.next(), raw, "major")?;
        let minor = parse_core_part(core_parts.next(), raw, "minor")?;
        let patch = parse_core_part(core_parts.next(), raw, "patch")?;
        if core_parts.next().is_some() {
            bail!("invalid semantic version {raw}");
        }
        let prerelease = if prerelease.is_empty() {
            Vec::new()
        } else {
            prerelease
                .split('.')
                .map(PrereleasePart::parse)
                .collect::<Result<Vec<_>>>()?
        };
        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| compare_prerelease(&self.prerelease, &other.prerelease))
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PrereleasePart {
    fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() {
            bail!("empty prerelease identifier");
        }
        if raw.chars().all(|ch| ch.is_ascii_digit()) {
            Ok(Self::Numeric(raw.parse()?))
        } else {
            Ok(Self::Text(raw.to_string()))
        }
    }
}

impl Ord for PrereleasePart {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => left.cmp(right),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for PrereleasePart {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_core_part(value: Option<&str>, raw: &str, label: &str) -> Result<u64> {
    value
        .ok_or_else(|| anyhow!("invalid semantic version {raw}: missing {label}"))?
        .parse()
        .with_context(|| format!("invalid semantic version {raw}: bad {label}"))
}

fn compare_prerelease(left: &[PrereleasePart], right: &[PrereleasePart]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    for (left, right) in left.iter().zip(right.iter()) {
        let ordering = left.cmp(right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn require_tool(name: &str) -> Result<()> {
    if command_exists(name) {
        Ok(())
    } else {
        Err(anyhow!("required tool not found: {name}"))
    }
}

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_status(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(command_error(command, &output))
}

fn command_output(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(command_error(command, &output))
}

fn command_error(command: &Command, output: &std::process::Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    if detail.is_empty() {
        anyhow!("command failed: {:?}", command)
    } else {
        anyhow!("command failed: {:?}: {detail}", command)
    }
}
