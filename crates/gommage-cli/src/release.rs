use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use crate::util::path_display;

#[derive(Subcommand)]
pub(crate) enum ReleaseCmd {
    /// Verify an installable GitHub Release archive.
    Verify(ReleaseVerifyOptions),
}

#[derive(Args)]
pub(crate) struct ReleaseVerifyOptions {
    /// Release tag to verify. Defaults to the latest gommage-cli release.
    #[arg(long, alias = "version", default_value = "latest")]
    tag: String,
    /// GitHub repository in OWNER/NAME form.
    #[arg(long, default_value = "Arakiss/gommage")]
    repo: String,
    /// Archive asset to verify. Defaults to the current OS/arch.
    #[arg(long, default_value = "auto")]
    asset: String,
    /// Download assets into this directory instead of a temporary directory.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Emit a stable machine-readable verification report.
    #[arg(long)]
    json: bool,
    /// Fail if the CycloneDX SBOM release asset is missing.
    #[arg(long)]
    require_sbom: bool,
    /// Fail if GitHub artifact attestation verification is missing.
    #[arg(long = "require-provenance", alias = "require-attestation")]
    require_provenance: bool,
}

pub(crate) fn cmd_release(cmd: ReleaseCmd) -> Result<ExitCode> {
    match cmd {
        ReleaseCmd::Verify(options) => cmd_release_verify(options),
    }
}

fn cmd_release_verify(options: ReleaseVerifyOptions) -> Result<ExitCode> {
    require_tool("gh")?;
    require_tool("cosign")?;
    let checksum_tool = if command_exists("shasum") {
        ChecksumTool::Shasum
    } else if command_exists("sha256sum") {
        ChecksumTool::Sha256sum
    } else {
        bail!("required tool not found: shasum or sha256sum");
    };

    let tag = resolve_tag(&options.repo, &options.tag)?;
    let asset = resolve_asset(&options.asset)?;
    let download = DownloadDir::create(options.dir.as_ref())?;
    let asset_names = release_asset_names(&options.repo, &tag)?;
    let sbom_asset = format!("gommage-{tag}.cdx.json");
    let sbom_present = asset_names.iter().any(|name| name == &sbom_asset);

    download_release_assets(&options.repo, &tag, &download.path, &asset)?;
    if sbom_present {
        download_release_asset(&options.repo, &tag, &download.path, &sbom_asset)?;
    }

    let checksum_status = if verify_checksum(checksum_tool, &download.path, &asset) {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let identity = format!(
        "https://github.com/{}/.github/workflows/release.yml@refs/tags/{}",
        options.repo, tag
    );
    let sigstore_status = if verify_sigstore(&download.path, &asset, &identity) {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let sbom_status = if sbom_present {
        CheckStatus::Pass
    } else {
        CheckStatus::Missing
    };
    let provenance_status =
        if verify_attestation(&options.repo, &tag, &download.path, &asset, &identity) {
            CheckStatus::Pass
        } else {
            CheckStatus::Missing
        };

    let status = overall_status(
        checksum_status,
        sigstore_status,
        sbom_status,
        provenance_status,
        options.require_sbom,
        options.require_provenance,
    );
    let report = ReleaseVerifyReport {
        status,
        repo: options.repo,
        tag,
        asset,
        download_dir: path_display(&download.path),
        checks: ReleaseVerifyChecks {
            sha256: checksum_status,
            sigstore_bundle: sigstore_status,
            cyclonedx_sbom: sbom_status,
            github_artifact_attestation: provenance_status,
        },
        expected_identity: identity,
    };

    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_release_verify_report(&report);
    }

    Ok(if report.status == ReleaseVerifyStatus::Fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseVerifyStatus {
    Pass,
    Warn,
    Fail,
}

impl ReleaseVerifyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Pass,
    Missing,
    Fail,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Missing => "missing",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
struct ReleaseVerifyReport {
    status: ReleaseVerifyStatus,
    repo: String,
    tag: String,
    asset: String,
    download_dir: String,
    checks: ReleaseVerifyChecks,
    expected_identity: String,
}

#[derive(Debug, Serialize)]
struct ReleaseVerifyChecks {
    sha256: CheckStatus,
    sigstore_bundle: CheckStatus,
    cyclonedx_sbom: CheckStatus,
    github_artifact_attestation: CheckStatus,
}

#[derive(Clone, Copy)]
enum ChecksumTool {
    Shasum,
    Sha256sum,
}

struct DownloadDir {
    path: PathBuf,
    cleanup: bool,
}

impl DownloadDir {
    fn create(dir: Option<&PathBuf>) -> Result<Self> {
        match dir {
            Some(path) => {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("creating {}", path.display()))?;
                Ok(Self {
                    path: path.clone(),
                    cleanup: false,
                })
            }
            None => {
                let path =
                    std::env::temp_dir().join(format!("gommage-release-{}", uuid::Uuid::now_v7()));
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("creating {}", path.display()))?;
                Ok(Self {
                    path,
                    cleanup: true,
                })
            }
        }
    }
}

impl Drop for DownloadDir {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn overall_status(
    checksum: CheckStatus,
    sigstore: CheckStatus,
    sbom: CheckStatus,
    provenance: CheckStatus,
    require_sbom: bool,
    require_provenance: bool,
) -> ReleaseVerifyStatus {
    let missing_required_evidence = checksum != CheckStatus::Pass
        || sigstore != CheckStatus::Pass
        || (require_sbom && sbom != CheckStatus::Pass)
        || (require_provenance && provenance != CheckStatus::Pass);
    if missing_required_evidence {
        ReleaseVerifyStatus::Fail
    } else if sbom != CheckStatus::Pass || provenance != CheckStatus::Pass {
        ReleaseVerifyStatus::Warn
    } else {
        ReleaseVerifyStatus::Pass
    }
}

fn print_release_verify_report(report: &ReleaseVerifyReport) {
    println!("Gommage release verify");
    println!("status: {}", report.status.as_str());
    println!("repo: {}", report.repo);
    println!("tag: {}", report.tag);
    println!("asset: {}", report.asset);
    println!("sha256: {}", report.checks.sha256.as_str());
    println!(
        "sigstore bundle: {}",
        report.checks.sigstore_bundle.as_str()
    );
    println!("CycloneDX SBOM: {}", report.checks.cyclonedx_sbom.as_str());
    println!(
        "GitHub artifact attestation: {}",
        report.checks.github_artifact_attestation.as_str()
    );
    println!("expected identity: {}", report.expected_identity);
    println!("download dir: {}", report.download_dir);
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

fn resolve_tag(repo: &str, raw: &str) -> Result<String> {
    if raw != "latest" {
        if raw.is_empty() {
            bail!("release tag cannot be empty");
        }
        return Ok(raw.to_string());
    }

    let output = command_output(
        Command::new("gh")
            .arg("release")
            .arg("list")
            .arg("--repo")
            .arg(repo)
            .arg("--limit")
            .arg("50")
            .arg("--json")
            .arg("tagName,publishedAt")
            .arg("--jq")
            .arg(
                r#"[.[] | select(.tagName | startswith("gommage-cli-v"))] | sort_by(.publishedAt) | last | .tagName"#,
            ),
    )
    .context("resolving latest gommage-cli release")?;
    let tag = output.trim();
    if tag.is_empty() || tag == "null" {
        bail!("no gommage-cli release found in {repo}");
    }
    Ok(tag.to_string())
}

fn resolve_asset(raw: &str) -> Result<String> {
    let asset = if raw == "auto" {
        detect_asset().ok_or_else(|| {
            anyhow!(
                "unsupported current platform for automatic asset selection: {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?
    } else {
        raw.to_string()
    };

    match asset.as_str() {
        "gommage-aarch64-darwin.tar.gz"
        | "gommage-aarch64-linux.tar.gz"
        | "gommage-x86_64-darwin.tar.gz"
        | "gommage-x86_64-linux.tar.gz" => Ok(asset),
        _ => bail!("unsupported release archive asset: {asset}"),
    }
}

fn detect_asset() -> Option<String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("gommage-aarch64-darwin.tar.gz".to_string()),
        ("macos", "x86_64") => Some("gommage-x86_64-darwin.tar.gz".to_string()),
        ("linux", "aarch64") => Some("gommage-aarch64-linux.tar.gz".to_string()),
        ("linux", "x86_64") => Some("gommage-x86_64-linux.tar.gz".to_string()),
        _ => None,
    }
}

fn release_asset_names(repo: &str, tag: &str) -> Result<Vec<String>> {
    let output = command_output(
        Command::new("gh")
            .arg("release")
            .arg("view")
            .arg(tag)
            .arg("--repo")
            .arg(repo)
            .arg("--json")
            .arg("assets")
            .arg("--jq")
            .arg(".assets[].name"),
    )
    .with_context(|| format!("listing assets for {tag}"))?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn download_release_assets(repo: &str, tag: &str, dir: &Path, asset: &str) -> Result<()> {
    command_status(
        Command::new("gh")
            .arg("release")
            .arg("download")
            .arg(tag)
            .arg("--repo")
            .arg(repo)
            .arg("--dir")
            .arg(dir)
            .arg("--clobber")
            .arg("--pattern")
            .arg(asset)
            .arg("--pattern")
            .arg(format!("{asset}.sha256"))
            .arg("--pattern")
            .arg(format!("{asset}.sigstore.json")),
    )
    .with_context(|| format!("downloading release assets for {asset}"))
}

fn download_release_asset(repo: &str, tag: &str, dir: &Path, asset: &str) -> Result<()> {
    command_status(
        Command::new("gh")
            .arg("release")
            .arg("download")
            .arg(tag)
            .arg("--repo")
            .arg(repo)
            .arg("--dir")
            .arg(dir)
            .arg("--clobber")
            .arg("--pattern")
            .arg(asset),
    )
    .with_context(|| format!("downloading release asset {asset}"))
}

fn verify_checksum(tool: ChecksumTool, dir: &Path, asset: &str) -> bool {
    let mut command = match tool {
        ChecksumTool::Shasum => {
            let mut command = Command::new("shasum");
            command.arg("-a").arg("256").arg("-c");
            command
        }
        ChecksumTool::Sha256sum => Command::new("sha256sum"),
    };
    command
        .arg(format!("{asset}.sha256"))
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn verify_sigstore(dir: &Path, asset: &str, identity: &str) -> bool {
    Command::new("cosign")
        .arg("verify-blob")
        .arg(dir.join(asset))
        .arg("--bundle")
        .arg(dir.join(format!("{asset}.sigstore.json")))
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn verify_attestation(repo: &str, tag: &str, dir: &Path, asset: &str, identity: &str) -> bool {
    Command::new("gh")
        .arg("attestation")
        .arg("verify")
        .arg(dir.join(asset))
        .arg("--repo")
        .arg(repo)
        .arg("--cert-identity")
        .arg(identity)
        .arg("--cert-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg("--source-ref")
        .arg(format!("refs/tags/{tag}"))
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
