use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::util::path_display;

#[derive(Subcommand)]
pub(crate) enum ProjectCmd {
    /// Create a reviewed project-local policy and fixture starter pack.
    Init {
        /// Project root. Defaults to the current directory.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Overwrite existing Gommage project files.
        #[arg(long)]
        force: bool,
        /// Show planned files without writing.
        #[arg(long)]
        dry_run: bool,
        /// Emit a stable machine-readable init report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct ProjectInitReport {
    status: ProjectInitStatus,
    root: String,
    dry_run: bool,
    force: bool,
    files: Vec<ProjectInitFile>,
}

impl ProjectInitReport {
    fn exit_code(&self) -> ExitCode {
        if self.status == ProjectInitStatus::Fail {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProjectInitStatus {
    Pass,
    Warn,
    Fail,
}

impl ProjectInitStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
struct ProjectInitFile {
    path: String,
    kind: &'static str,
    action: ProjectInitAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProjectInitAction {
    Create,
    Overwrite,
    SkipExisting,
}

pub(crate) fn cmd_project(cmd: ProjectCmd) -> Result<ExitCode> {
    match cmd {
        ProjectCmd::Init {
            root,
            force,
            dry_run,
            json,
        } => {
            let root = absolute_project_root(root)?;
            let report = build_project_init_report(&root, force, dry_run);
            if !dry_run && report.status != ProjectInitStatus::Fail {
                write_project_files(&root, force)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_project_init_report(&report);
            }
            Ok(report.exit_code())
        }
    }
}

fn absolute_project_root(root: Option<PathBuf>) -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    let root = root.unwrap_or_else(|| cwd.clone());
    if root.is_absolute() {
        Ok(root)
    } else {
        Ok(cwd.join(root))
    }
}

fn build_project_init_report(root: &Path, force: bool, dry_run: bool) -> ProjectInitReport {
    let specs = project_file_specs(root);
    let files = specs
        .iter()
        .map(|spec| {
            let exists = spec.path.exists();
            ProjectInitFile {
                path: path_display(&spec.path),
                kind: spec.kind,
                action: if exists && force {
                    ProjectInitAction::Overwrite
                } else if exists {
                    ProjectInitAction::SkipExisting
                } else {
                    ProjectInitAction::Create
                },
            }
        })
        .collect::<Vec<_>>();
    let status = if files
        .iter()
        .any(|file| file.action == ProjectInitAction::SkipExisting && !force)
    {
        if dry_run {
            ProjectInitStatus::Warn
        } else {
            ProjectInitStatus::Fail
        }
    } else {
        ProjectInitStatus::Pass
    };
    ProjectInitReport {
        status,
        root: path_display(root),
        dry_run,
        force,
        files,
    }
}

fn write_project_files(root: &Path, force: bool) -> Result<()> {
    for spec in project_file_specs(root) {
        if spec.path.exists() && !force {
            anyhow::bail!(
                "{} already exists; rerun with --force to overwrite",
                spec.path.display()
            );
        }
        if let Some(parent) = spec.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&spec.path, spec.contents)
            .with_context(|| format!("writing {}", spec.path.display()))?;
    }
    Ok(())
}

struct ProjectFileSpec {
    path: PathBuf,
    kind: &'static str,
    contents: String,
}

fn project_file_specs(root: &Path) -> Vec<ProjectFileSpec> {
    let root = path_display(root);
    vec![
        ProjectFileSpec {
            path: PathBuf::from(&root).join(".gommage/policy.d/20-project.yaml"),
            kind: "policy",
            contents: project_policy(&root),
        },
        ProjectFileSpec {
            path: PathBuf::from(&root).join(".gommage/policy-fixtures.yaml"),
            kind: "fixture",
            contents: project_fixtures(&root),
        },
        ProjectFileSpec {
            path: PathBuf::from(&root).join(".gommage/README.md"),
            kind: "readme",
            contents: PROJECT_README.to_string(),
        },
    ]
}

fn project_policy(root: &str) -> String {
    format!(
        r#"# Project-local Gommage policy starter.
#
# This layer is loaded when:
# - an expedition is active from this project root; or
# - GOMMAGE_PROJECT_POLICY_DIR points at this policy.d directory.
#
# Keep this file reviewed like code. Add fixtures in ../policy-fixtures.yaml
# before trusting a new allow/ask/deny behavior.

- name: project-allow-expedition-writes
  decision: allow
  match:
    any_capability:
      - "fs.write:{root}/**"
  reason: "project policy allows writes inside the active expedition root"
"#
    )
}

fn project_fixtures(root: &str) -> String {
    format!(
        r#"version: 1
cases:
  - name: project_allows_expedition_write
    description: Project policy permits writes inside the active expedition root.
    tool: Write
    input:
      file_path: "{root}/README.md"
    expect:
      decision: allow
      matched_rule: project-allow-expedition-writes
"#
    )
}

const PROJECT_README: &str = r#"# Gommage Project Policy

This directory contains project-local Gommage policy and fixtures.

Use it as a reviewed project layer, not as hidden runtime state:

```sh
gommage expedition start "<task-name>" --root "$PWD"
gommage policy test .gommage/policy-fixtures.yaml --json
gommage policy layers --json
```

The policy engine remains deterministic. Do not add transcript-aware or
heuristic behavior here; encode concrete capabilities and test them with
fixtures.
"#;

fn print_project_init_report(report: &ProjectInitReport) {
    println!("project init: {}", report.status.as_str());
    println!("root: {}", report.root);
    if report.dry_run {
        println!("dry-run: no files written");
    }
    for file in &report.files {
        println!("{} {}: {}", file.kind, action_label(file.action), file.path);
    }
}

fn action_label(action: ProjectInitAction) -> &'static str {
    match action {
        ProjectInitAction::Create => "create",
        ProjectInitAction::Overwrite => "overwrite",
        ProjectInitAction::SkipExisting => "skip-existing",
    }
}
