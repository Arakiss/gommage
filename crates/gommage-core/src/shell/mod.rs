//! Deterministic, AST-backed shell effect analysis.
//!
//! Security decisions must not depend on a lossy whitespace scanner. This
//! module adapts `brush-parser` behind an internal contract that preserves raw
//! words, quote and expansion provenance, nested commands, and typed
//! redirections. It never executes input, expands the ambient environment, or
//! inspects the filesystem.

use brush_parser::{
    Parser, ParserOptions,
    ast::{
        self, Command, CommandPrefixOrSuffixItem, CompoundCommand, CompoundList,
        IoFileRedirectKind, IoFileRedirectTarget, IoRedirect, SimpleCommand,
    },
    word::{self, Parameter, ParameterExpr, TildeExpr, WordPiece, WordPieceWithSource},
};
use std::io::Cursor;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_NESTING_DEPTH: usize = 16;
const MAX_COMMANDS: usize = 512;

/// A bounded, non-input-bearing reason suitable for a fail-closed capability.
pub(crate) type Ambiguity = &'static str;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WordProvenance {
    pub(crate) single_quoted: bool,
    pub(crate) double_quoted: bool,
    pub(crate) escaped: bool,
    pub(crate) expanded: bool,
    pub(crate) home_alias: bool,
    pub(crate) unquoted_glob: bool,
}

/// A raw shell word together with its static interpretation, when one exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellWord {
    pub(crate) raw: String,
    pub(crate) value: Option<String>,
    pub(crate) provenance: WordProvenance,
    pub(crate) ambiguity: Option<Ambiguity>,
}

impl ShellWord {
    pub(crate) fn static_value(&self) -> Result<&str, Ambiguity> {
        if self.provenance.unquoted_glob {
            return Err("dynamic-glob");
        }
        self.value
            .as_deref()
            .ok_or(self.ambiguity.unwrap_or("dynamic-word"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectionKind {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellRedirection {
    pub(crate) kind: RedirectionKind,
    pub(crate) target: ShellWord,
}

/// One parsed simple command, including its recursively unwrapped executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellCommand {
    pub(crate) words: Vec<ShellWord>,
    pub(crate) effective_words: Vec<ShellWord>,
    pub(crate) redirections: Vec<ShellRedirection>,
}

impl ShellCommand {
    pub(crate) fn effective_head(&self) -> Result<&str, Ambiguity> {
        self.effective_words
            .first()
            .ok_or("missing-command")?
            .static_value()
            .map(head_basename)
    }

    pub(crate) fn effective_args(&self) -> &[ShellWord] {
        self.effective_words.get(1..).unwrap_or_default()
    }

    pub(crate) fn trusted_effective_head(&self) -> Result<&str, Ambiguity> {
        let executable = self
            .effective_words
            .first()
            .ok_or("missing-command")?
            .static_value()?;
        trusted_executable_basename(executable)
    }

    pub(crate) fn static_argv(&self) -> Option<Vec<String>> {
        self.effective_words
            .iter()
            .map(|word| word.static_value().map(str::to_string))
            .collect::<Result<Vec<_>, _>>()
            .ok()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ShellAnalysis {
    pub(crate) commands: Vec<ShellCommand>,
    pub(crate) ambiguities: Vec<Ambiguity>,
}

impl ShellAnalysis {
    fn ambiguity(&mut self, reason: Ambiguity) {
        if !self.ambiguities.contains(&reason) {
            self.ambiguities.push(reason);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsEffectKind {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FsEffect {
    pub(crate) kind: FsEffectKind,
    pub(crate) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GitPushEffect {
    Destination(String),
    CurrentBranch,
    Force,
    Delete(String),
    Network,
}

/// A GitHub pull-request merge bound to one canonical repository and PR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GhPrMergeEffect {
    Merge(String),
    Admin(String),
    DeleteBranch(String),
    BodyFile(String),
}

/// Security-sensitive mutations exposed by the Gommage operator CLI.
///
/// The operation classes are deliberately closed and payload-free. A selected
/// home mutation carries only its normalized path, so policy can bind approval
/// to the exact authority root without treating the whole tree as a generic
/// filesystem write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GommageAdminEffect {
    Authorize,
    Reconfigure,
    Disable,
    HomeMutate(String),
    PathWrite(String),
}

/// Package-manager operations whose authority must be derived from parsed
/// argv rather than a text regex. Help and version invocations deliberately do
/// not produce effects because the selected command exits before mutating a
/// package installation or registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageManagerEffect {
    BunInstall,
    BunPublish,
    NpmInstall,
    NpmPublish,
    CargoInstall,
    CargoPublish,
    PythonPublish,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectSet<T> {
    pub(crate) effects: Vec<T>,
    pub(crate) ambiguities: Vec<Ambiguity>,
}

impl<T> Default for EffectSet<T> {
    fn default() -> Self {
        Self {
            effects: Vec::new(),
            ambiguities: Vec::new(),
        }
    }
}

impl<T: PartialEq> EffectSet<T> {
    fn push(&mut self, effect: T) {
        if !self.effects.contains(&effect) {
            self.effects.push(effect);
        }
    }

    fn ambiguity(&mut self, reason: Ambiguity) {
        if !self.ambiguities.contains(&reason) {
            self.ambiguities.push(reason);
        }
    }
}

mod common;
mod filesystem;
mod filesystem_commands;
mod gh_merge;
mod git_push;
mod gommage_commands;
mod gommage_dispatch;
mod interpreter;
mod package_manager;
mod parser;
mod paths;
mod service_lifecycle;
mod wrappers;

use common::*;
use filesystem::*;
use filesystem_commands::*;
use gommage_commands::*;
use gommage_dispatch::*;
use interpreter::*;
use paths::*;
use service_lifecycle::*;
use wrappers::*;

pub(crate) use common::{head_basename, trusted_executable_basename};
pub(crate) use filesystem::filesystem_effects;
pub(crate) use filesystem_commands::has_static_remote_rsync;
pub(crate) use gh_merge::gh_pr_merge_effects;
pub(crate) use git_push::git_push_effects;
pub(crate) use gommage_dispatch::gommage_admin_effects;
pub(crate) use package_manager::package_manager_effects;
pub(crate) use parser::analyze;
pub(crate) use paths::static_path;

/// Extract filesystem write targets through the same typed analysis used by
/// policy mapping. This adapter intentionally has no trusted cwd context.
pub fn shell_write_targets(command: &str) -> Vec<String> {
    filesystem_effects(&analyze(command), None)
        .effects
        .into_iter()
        .filter_map(|effect| (effect.kind == FsEffectKind::Write).then_some(effect.path))
        .collect()
}

#[cfg(test)]
mod tests;
