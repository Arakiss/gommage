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

/// Parse a shell program without executing it or consulting machine state.
pub(crate) fn analyze(command: &str) -> ShellAnalysis {
    if command.len() > MAX_INPUT_BYTES {
        return ShellAnalysis {
            commands: Vec::new(),
            ambiguities: vec!["input-too-large"],
        };
    }

    let options = ParserOptions::default();
    let mut parser = Parser::new(Cursor::new(command.as_bytes()), &options);
    let Ok(program) = parser.parse_program() else {
        return ShellAnalysis {
            commands: Vec::new(),
            ambiguities: vec!["parse-error"],
        };
    };

    let mut state = AnalysisState {
        analysis: ShellAnalysis::default(),
        options,
    };
    state.collect_program(&program, 0);
    state.analysis
}

struct AnalysisState {
    analysis: ShellAnalysis,
    options: ParserOptions,
}

impl AnalysisState {
    fn collect_program(&mut self, program: &ast::Program, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        for command in &program.complete_commands {
            self.collect_list(command, depth);
        }
    }

    fn collect_list(&mut self, list: &CompoundList, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        for item in &list.0 {
            self.collect_pipeline(&item.0.first, depth);
            for additional in &item.0.additional {
                match additional {
                    ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => {
                        self.collect_pipeline(pipeline, depth)
                    }
                }
            }
        }
    }

    fn collect_pipeline(&mut self, pipeline: &ast::Pipeline, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        for command in &pipeline.seq {
            self.collect_command(command, depth);
        }
    }

    fn collect_command(&mut self, command: &Command, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        match command {
            Command::Simple(simple) => self.collect_simple(simple, depth),
            Command::Compound(compound, redirects) => {
                self.collect_compound(compound, depth + 1);
                if let Some(redirects) = redirects {
                    self.collect_redirect_list(&redirects.0, depth + 1);
                }
            }
            Command::Function(function) => {
                // Defining a function does not execute its body. Its syntax can
                // contain arbitrary future effects, so reference posture does
                // not pretend the definition is an execution request.
                self.analysis.ambiguity("function-definition");
                if let Some(redirects) = &function.body.1 {
                    self.collect_redirect_list(&redirects.0, depth + 1);
                }
            }
            Command::ExtendedTest(_, redirects) => {
                if let Some(redirects) = redirects {
                    self.collect_redirect_list(&redirects.0, depth + 1);
                }
            }
        }
    }

    fn collect_compound(&mut self, command: &CompoundCommand, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        match command {
            CompoundCommand::Arithmetic(_) => self.analysis.ambiguity("arithmetic-command"),
            CompoundCommand::ArithmeticForClause(command) => {
                self.analysis.ambiguity("arithmetic-loop");
                self.collect_list(&command.body.list, depth + 1);
            }
            CompoundCommand::BraceGroup(command) => self.collect_list(&command.list, depth + 1),
            CompoundCommand::Subshell(command) => self.collect_list(&command.list, depth + 1),
            CompoundCommand::ForClause(command) => {
                if let Some(values) = &command.values {
                    for value in values {
                        self.collect_word_substitutions(value, depth + 1);
                    }
                } else {
                    self.analysis.ambiguity("implicit-loop-input");
                }
                self.collect_list(&command.body.list, depth + 1);
            }
            CompoundCommand::CaseClause(command) => {
                self.collect_word_substitutions(&command.value, depth + 1);
                for case in &command.cases {
                    for pattern in &case.patterns {
                        self.collect_word_substitutions(pattern, depth + 1);
                    }
                    if let Some(list) = &case.cmd {
                        self.collect_list(list, depth + 1);
                    }
                }
            }
            CompoundCommand::IfClause(command) => {
                self.collect_list(&command.condition, depth + 1);
                self.collect_list(&command.then, depth + 1);
                if let Some(elses) = &command.elses {
                    for clause in elses {
                        if let Some(condition) = &clause.condition {
                            self.collect_list(condition, depth + 1);
                        }
                        self.collect_list(&clause.body, depth + 1);
                    }
                }
            }
            CompoundCommand::WhileClause(command) | CompoundCommand::UntilClause(command) => {
                self.collect_list(&command.0, depth + 1);
                self.collect_list(&command.1.list, depth + 1);
            }
            CompoundCommand::Coprocess(command) => self.collect_command(&command.body, depth + 1),
        }
    }

    fn collect_simple(&mut self, command: &SimpleCommand, depth: usize) {
        if !self.enter(depth) || self.analysis.commands.len() >= MAX_COMMANDS {
            self.analysis.ambiguity("command-limit");
            return;
        }

        let mut words = Vec::new();
        let mut redirects = Vec::new();
        if let Some(prefix) = &command.prefix {
            self.collect_items(&prefix.0, &mut words, &mut redirects, false, depth + 1);
        }
        if let Some(word) = &command.word_or_name {
            self.collect_word_substitutions(word, depth + 1);
            words.push(analyze_word(word, &self.options));
        }
        if let Some(suffix) = &command.suffix {
            self.collect_items(&suffix.0, &mut words, &mut redirects, true, depth + 1);
        }

        if words.is_empty() {
            return;
        }

        let effective_words = unwrap_words(&words, &mut self.analysis);
        if effective_words
            .first()
            .is_some_and(|head| head.static_value().is_err())
        {
            self.analysis.ambiguity("dynamic-command");
        }
        if effective_words
            .first()
            .and_then(|head| head.static_value().ok())
            .is_some_and(|head| head_basename(head) == "xargs")
            && effective_words
                .get(1..)
                .is_some_and(|args| args.iter().any(|arg| arg.static_value().is_err()))
        {
            self.analysis.ambiguity("dynamic-xargs-command");
        }

        let nested_payload = shell_c_payload(&effective_words);
        self.analysis.commands.push(ShellCommand {
            words,
            effective_words,
            redirections: redirects,
        });

        if let Some(payload) = nested_payload {
            match payload {
                Ok(payload) => self.collect_nested_program(&payload, depth + 1),
                Err(reason) => self.analysis.ambiguity(reason),
            }
        }
    }

    fn collect_items(
        &mut self,
        items: &[CommandPrefixOrSuffixItem],
        words: &mut Vec<ShellWord>,
        redirects: &mut Vec<ShellRedirection>,
        include_words: bool,
        depth: usize,
    ) {
        for item in items {
            match item {
                CommandPrefixOrSuffixItem::Word(word) => {
                    self.collect_word_substitutions(word, depth + 1);
                    if include_words {
                        words.push(analyze_word(word, &self.options));
                    }
                }
                CommandPrefixOrSuffixItem::AssignmentWord(_, raw) => {
                    self.collect_word_substitutions(raw, depth + 1);
                    if include_words {
                        words.push(analyze_word(raw, &self.options));
                    }
                }
                CommandPrefixOrSuffixItem::IoRedirect(redirect) => {
                    self.collect_redirect(redirect, redirects, depth + 1)
                }
                CommandPrefixOrSuffixItem::ProcessSubstitution(_, subshell) => {
                    self.collect_list(&subshell.list, depth + 1);
                    if include_words {
                        self.analysis.ambiguity("process-substitution-path");
                    }
                }
            }
        }
    }

    fn collect_redirect_list(&mut self, redirects: &[IoRedirect], depth: usize) {
        let mut collected = Vec::new();
        for redirect in redirects {
            self.collect_redirect(redirect, &mut collected, depth + 1);
        }
        if !collected.is_empty() {
            self.analysis.commands.push(ShellCommand {
                words: Vec::new(),
                effective_words: Vec::new(),
                redirections: collected,
            });
        }
    }

    fn collect_redirect(
        &mut self,
        redirect: &IoRedirect,
        out: &mut Vec<ShellRedirection>,
        depth: usize,
    ) {
        match redirect {
            IoRedirect::File(_, kind, target) => match target {
                IoFileRedirectTarget::Filename(word) => {
                    self.collect_word_substitutions(word, depth + 1);
                    let word = analyze_word(word, &self.options);
                    match kind {
                        IoFileRedirectKind::Read => out.push(ShellRedirection {
                            kind: RedirectionKind::Read,
                            target: word,
                        }),
                        IoFileRedirectKind::Write
                        | IoFileRedirectKind::Append
                        | IoFileRedirectKind::Clobber => out.push(ShellRedirection {
                            kind: RedirectionKind::Write,
                            target: word,
                        }),
                        IoFileRedirectKind::ReadAndWrite => {
                            out.push(ShellRedirection {
                                kind: RedirectionKind::Read,
                                target: word.clone(),
                            });
                            out.push(ShellRedirection {
                                kind: RedirectionKind::Write,
                                target: word,
                            });
                        }
                        IoFileRedirectKind::DuplicateInput
                        | IoFileRedirectKind::DuplicateOutput => {}
                    }
                }
                IoFileRedirectTarget::ProcessSubstitution(_, subshell) => {
                    self.collect_list(&subshell.list, depth + 1)
                }
                IoFileRedirectTarget::Fd(_) | IoFileRedirectTarget::Duplicate(_) => {}
            },
            IoRedirect::OutputAndError(word, _) => {
                self.collect_word_substitutions(word, depth + 1);
                out.push(ShellRedirection {
                    kind: RedirectionKind::Write,
                    target: analyze_word(word, &self.options),
                });
            }
            IoRedirect::HereDocument(_, document) => {
                if document.requires_expansion {
                    self.collect_word_substitutions(&document.doc, depth + 1);
                }
            }
            IoRedirect::HereString(_, word) => self.collect_word_substitutions(word, depth + 1),
        }
    }

    fn collect_word_substitutions(&mut self, raw: &ast::Word, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        let Ok(pieces) = word::parse(&raw.value, &self.options) else {
            self.analysis.ambiguity("word-parse-error");
            return;
        };
        let mut substitutions = Vec::new();
        collect_substitutions(&pieces, &mut substitutions);
        for payload in substitutions {
            self.collect_nested_program(&payload, depth + 1);
        }
    }

    fn collect_nested_program(&mut self, payload: &str, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        if payload.len() > MAX_INPUT_BYTES {
            self.analysis.ambiguity("nested-input-too-large");
            return;
        }
        let mut parser = Parser::new(Cursor::new(payload.as_bytes()), &self.options);
        match parser.parse_program() {
            Ok(program) => self.collect_program(&program, depth + 1),
            Err(_) => self.analysis.ambiguity("nested-parse-error"),
        }
    }

    fn enter(&mut self, depth: usize) -> bool {
        if depth > MAX_NESTING_DEPTH {
            self.analysis.ambiguity("nesting-limit");
            false
        } else {
            true
        }
    }
}

fn analyze_word(raw: &ast::Word, options: &ParserOptions) -> ShellWord {
    let mut provenance = WordProvenance::default();
    let mut value = String::new();
    let mut ambiguity = None;
    match word::parse(&raw.value, options) {
        Ok(pieces) => render_pieces(&pieces, false, &mut value, &mut provenance, &mut ambiguity),
        Err(_) => ambiguity = Some("word-parse-error"),
    }
    ShellWord {
        raw: raw.value.clone(),
        value: ambiguity.is_none().then_some(value),
        provenance,
        ambiguity,
    }
}

fn render_pieces(
    pieces: &[WordPieceWithSource],
    quoted: bool,
    out: &mut String,
    provenance: &mut WordProvenance,
    ambiguity: &mut Option<Ambiguity>,
) {
    for piece in pieces {
        match &piece.piece {
            WordPiece::Text(text) => {
                if !quoted && text.chars().any(|ch| matches!(ch, '*' | '?' | '[')) {
                    provenance.unquoted_glob = true;
                }
                out.push_str(text);
            }
            WordPiece::SingleQuotedText(text) | WordPiece::AnsiCQuotedText(text) => {
                provenance.single_quoted = true;
                out.push_str(text);
            }
            WordPiece::DoubleQuotedSequence(inner)
            | WordPiece::GettextDoubleQuotedSequence(inner) => {
                provenance.double_quoted = true;
                render_pieces(inner, true, out, provenance, ambiguity);
            }
            WordPiece::TildeExpansion(TildeExpr::Home) if out.is_empty() && !quoted => {
                provenance.expanded = true;
                provenance.home_alias = true;
                out.push_str("$HOME");
            }
            WordPiece::TildeExpansion(_) => *ambiguity = Some("dynamic-tilde"),
            WordPiece::ParameterExpansion(ParameterExpr::Parameter {
                parameter: Parameter::Named(name),
                indirect: false,
            }) if name == "HOME" && out.is_empty() => {
                provenance.expanded = true;
                provenance.home_alias = true;
                out.push_str("$HOME");
            }
            WordPiece::ParameterExpansion(_) => *ambiguity = Some("dynamic-parameter"),
            WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_) => {
                provenance.expanded = true;
                *ambiguity = Some("dynamic-command-substitution");
            }
            WordPiece::EscapeSequence(text) => {
                provenance.escaped = true;
                out.push_str(text);
            }
            WordPiece::ArithmeticExpression(_) => {
                provenance.expanded = true;
                *ambiguity = Some("dynamic-arithmetic");
            }
        }
    }
}

fn collect_substitutions(pieces: &[WordPieceWithSource], out: &mut Vec<String>) {
    for piece in pieces {
        match &piece.piece {
            WordPiece::CommandSubstitution(payload)
            | WordPiece::BackquotedCommandSubstitution(payload) => out.push(payload.clone()),
            WordPiece::DoubleQuotedSequence(inner)
            | WordPiece::GettextDoubleQuotedSequence(inner) => collect_substitutions(inner, out),
            _ => {}
        }
    }
}

fn unwrap_words(words: &[ShellWord], analysis: &mut ShellAnalysis) -> Vec<ShellWord> {
    let mut current = words.to_vec();
    for _ in 0..MAX_NESTING_DEPTH {
        let Some(head) = current.first() else {
            return current;
        };
        let Ok(head) = head.static_value() else {
            return current;
        };
        let head = head_basename(head);
        let step = match head {
            "command" => unwrap_command(&current),
            "exec" => unwrap_exec(&current),
            "env" => unwrap_env(&current),
            "sudo" => unwrap_sudo(&current),
            "doas" => unwrap_doas(&current),
            "timeout" => unwrap_timeout(&current),
            "time" => unwrap_time(&current),
            "nice" => unwrap_nice(&current),
            "nohup" => unwrap_nohup(&current),
            "stdbuf" => unwrap_stdbuf(&current),
            "setsid" => unwrap_setsid(&current),
            _ => return current,
        };
        match step {
            UnwrapStep::At(index) if index < current.len() => current = current[index..].to_vec(),
            UnwrapStep::Stop => return current,
            UnwrapStep::Ambiguous(reason) => {
                analysis.ambiguity(reason);
                return current;
            }
            UnwrapStep::At(_) => {
                analysis.ambiguity("wrapper-missing-command");
                return current;
            }
        }
    }
    analysis.ambiguity("wrapper-depth");
    current
}

enum UnwrapStep {
    At(usize),
    Stop,
    Ambiguous(Ambiguity),
}

fn static_word(words: &[ShellWord], index: usize) -> Result<&str, Ambiguity> {
    words
        .get(index)
        .ok_or("wrapper-missing-value")?
        .static_value()
}

fn unwrap_command(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-v" | "-V" => return UnwrapStep::Stop,
            "-p" => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-command-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

fn unwrap_exec(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-a" => i += 2,
            "-c" | "-l" => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-exec-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

fn unwrap_env(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        if arg == "--" {
            return UnwrapStep::At(i + 1);
        }
        if is_assignment(arg) {
            i += 1;
            continue;
        }
        match arg {
            "-i" | "--ignore-environment" | "-0" | "--null" => i += 1,
            "-u" | "--unset" => i += 2,
            "-C" | "--chdir" => return UnwrapStep::Ambiguous("wrapper-changes-cwd"),
            "-S" | "--split-string" => return UnwrapStep::Ambiguous("env-split-string"),
            arg if arg.starts_with("--unset=") => i += 1,
            arg if arg.starts_with("--chdir=") => {
                return UnwrapStep::Ambiguous("wrapper-changes-cwd");
            }
            arg if arg.starts_with("--split-string=") => {
                return UnwrapStep::Ambiguous("env-split-string");
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-env-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

fn unwrap_sudo(words: &[ShellWord]) -> UnwrapStep {
    unwrap_flag_wrapper(
        words,
        &[
            "-u",
            "--user",
            "-g",
            "--group",
            "-h",
            "--host",
            "-p",
            "--prompt",
            "-C",
            "--close-from",
            "-R",
            "--chroot",
            "-T",
            "--command-timeout",
        ],
        &[
            "-A",
            "--askpass",
            "-b",
            "--background",
            "-E",
            "--preserve-env",
            "-H",
            "--set-home",
            "-K",
            "--remove-timestamp",
            "-k",
            "--reset-timestamp",
            "-n",
            "--non-interactive",
            "-P",
            "--preserve-groups",
            "-S",
            "--stdin",
        ],
        "unknown-sudo-option",
    )
}

fn unwrap_doas(words: &[ShellWord]) -> UnwrapStep {
    unwrap_flag_wrapper(
        words,
        &["-a", "-C", "-u"],
        &["-L", "-n"],
        "unknown-doas-option",
    )
}

fn unwrap_timeout(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => {
                i += 1;
                break;
            }
            "-s" | "--signal" | "-k" | "--kill-after" => i += 2,
            "--preserve-status" | "--foreground" | "-v" | "--verbose" => i += 1,
            arg if arg.starts_with("--signal=") || arg.starts_with("--kill-after=") => i += 1,
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-timeout-option"),
            _ => break,
        }
    }
    if i >= words.len() {
        return UnwrapStep::Stop;
    }
    i += 1; // duration
    UnwrapStep::At(i)
}

fn unwrap_time(words: &[ShellWord]) -> UnwrapStep {
    unwrap_flag_wrapper(
        words,
        &["-o", "--output", "-f", "--format"],
        &["-a", "--append", "-p", "--portability", "-v", "--verbose"],
        "unknown-time-option",
    )
}

fn unwrap_nice(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-n" | "--adjustment" => i += 2,
            arg if arg.starts_with("--adjustment=") => i += 1,
            arg if arg.len() > 1
                && arg.starts_with('-')
                && arg[1..].chars().all(|ch| ch.is_ascii_digit()) =>
            {
                i += 1
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-nice-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

fn unwrap_nohup(words: &[ShellWord]) -> UnwrapStep {
    if words.get(1).is_some_and(|word| word.raw == "--") {
        UnwrapStep::At(2)
    } else {
        UnwrapStep::At(1)
    }
}

fn unwrap_stdbuf(words: &[ShellWord]) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        match arg {
            "--" => return UnwrapStep::At(i + 1),
            "-i" | "-o" | "-e" | "--input" | "--output" | "--error" => i += 2,
            arg if arg.starts_with("-i")
                || arg.starts_with("-o")
                || arg.starts_with("-e")
                || arg.starts_with("--input=")
                || arg.starts_with("--output=")
                || arg.starts_with("--error=") =>
            {
                i += 1
            }
            arg if arg.starts_with('-') => return UnwrapStep::Ambiguous("unknown-stdbuf-option"),
            _ => return UnwrapStep::At(i),
        }
    }
    UnwrapStep::Stop
}

fn unwrap_setsid(words: &[ShellWord]) -> UnwrapStep {
    unwrap_flag_wrapper(
        words,
        &[],
        &["-c", "--ctty", "-f", "--fork", "-w", "--wait"],
        "unknown-setsid-option",
    )
}

fn unwrap_flag_wrapper(
    words: &[ShellWord],
    value_options: &[&str],
    boolean_options: &[&str],
    unknown: Ambiguity,
) -> UnwrapStep {
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = static_word(words, i) else {
            return UnwrapStep::Ambiguous("dynamic-wrapper-option");
        };
        if arg == "--" {
            return UnwrapStep::At(i + 1);
        }
        if value_options.contains(&arg) {
            i += 2;
        } else if boolean_options.contains(&arg)
            || value_options
                .iter()
                .any(|option| option.starts_with("--") && arg.starts_with(&format!("{option}=")))
        {
            i += 1;
        } else if arg.starts_with('-') {
            return UnwrapStep::Ambiguous(unknown);
        } else {
            return UnwrapStep::At(i);
        }
    }
    UnwrapStep::Stop
}

fn shell_c_payload(words: &[ShellWord]) -> Option<Result<String, Ambiguity>> {
    let head = words.first()?.static_value().ok().map(head_basename)?;
    if !matches!(head, "bash" | "sh" | "zsh") {
        return None;
    }
    let mut i = 1;
    while i < words.len() {
        let Ok(arg) = words[i].static_value() else {
            return Some(Err("dynamic-shell-option"));
        };
        if arg == "-c" || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c'))
        {
            return Some(
                words
                    .get(i + 1)
                    .ok_or("missing-shell-payload")
                    .and_then(|word| word.static_value().map(str::to_string)),
            );
        }
        match arg {
            "--" => return None,
            "-O" | "-o" | "--init-file" | "--rcfile" => {
                if words.get(i + 1).is_none() {
                    return Some(Err("missing-shell-option-value"));
                }
                i += 2;
                continue;
            }
            "--noprofile" | "--norc" | "--posix" | "--restricted" | "--verbose" | "--login"
            | "--noediting" => {
                i += 1;
                continue;
            }
            _ if arg.starts_with("-O")
                || arg.starts_with("-o")
                || arg.starts_with("--init-file=")
                || arg.starts_with("--rcfile=") =>
            {
                i += 1;
                continue;
            }
            _ if arg.starts_with('-') => return Some(Err("unknown-shell-option")),
            _ => return None,
        }
    }
    None
}

/// Derive Gommage administration effects from parsed argv, not command text.
///
/// `effective_words` already unwraps transparent process wrappers and the AST
/// collector recursively adds static `sh -c` payloads. This function adds the
/// two invocation forms that are specific to Gommage: the binary itself and
/// `cargo run --bin gommage -- ...` during local development.
pub(crate) fn gommage_admin_effects(
    analysis: &ShellAnalysis,
    cwd: Option<&str>,
) -> EffectSet<GommageAdminEffect> {
    let mut out = EffectSet::default();
    let cwd = trusted_cwd(cwd);
    for command in &analysis.commands {
        classify_gommage_invocation(command, cwd.as_deref(), &mut out);
        classify_gommage_service_lifecycle(command, &mut out);
    }
    out
}

fn classify_gommage_invocation(
    command: &ShellCommand,
    cwd: Option<&str>,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Some(words) = gommage_invocation_words(command, out) else {
        return;
    };
    if classify_gommage_argv(&shell_word_tokens(&words), out) {
        for home in gommage_path_option_words(&words, "--home", out) {
            match static_path(&home, cwd) {
                Ok(path) => out.push(GommageAdminEffect::HomeMutate(path)),
                Err(reason) => out.ambiguity(reason),
            }
        }
    }
}

fn gommage_invocation_words<T: PartialEq>(
    command: &ShellCommand,
    out: &mut EffectSet<T>,
) -> Option<Vec<ShellWord>> {
    let Ok(head) = command.effective_head() else {
        return None;
    };
    match head {
        "gommage" => Some(command.effective_args().to_vec()),
        "cargo" => {
            let args = command.effective_args();
            let tokens = shell_word_tokens(args);
            let argv_start = cargo_run_gommage_argv_start(&tokens, out)?;
            Some(args[argv_start..].to_vec())
        }
        _ => None,
    }
}

fn shell_word_tokens(words: &[ShellWord]) -> Vec<Option<String>> {
    words
        .iter()
        .map(|word| word.static_value().ok().map(str::to_string))
        .collect()
}

fn cargo_run_gommage_argv_start<T: PartialEq>(
    tokens: &[Option<String>],
    out: &mut EffectSet<T>,
) -> Option<usize> {
    let Some(run) = cargo_run_subcommand_index(tokens) else {
        let dynamic_subcommand_with_gommage_selector = tokens.iter().any(Option::is_none)
            && tokens.iter().flatten().any(|token| {
                token == "gommage" || token == "gommage-cli" || is_gommage_cli_manifest(token)
            });
        if dynamic_subcommand_with_gommage_selector {
            out.ambiguity("dynamic-gommage-admin-command");
        }
        return None;
    };
    let mut bin: Option<Option<String>> = None;
    let mut package: Option<Option<String>> = None;
    let mut manifest: Option<Option<String>> = None;
    let mut example_selected = false;
    let mut argv_start = tokens.len();
    let mut index = run + 1;
    while index < tokens.len() {
        match tokens[index].as_deref() {
            Some("--") => {
                argv_start = index + 1;
                break;
            }
            Some("--bin") => {
                bin = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("-p" | "--package") => {
                package = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some("--manifest-path") => {
                manifest = Some(tokens.get(index + 1).cloned().unwrap_or(None));
                index += 2;
            }
            Some(value) if value.starts_with("--bin=") => {
                bin = Some(Some(value["--bin=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--package=") => {
                package = Some(Some(value["--package=".len()..].to_string()));
                index += 1;
            }
            Some(value) if value.starts_with("--manifest-path=") => {
                manifest = Some(Some(value["--manifest-path=".len()..].to_string()));
                index += 1;
            }
            Some("--example") => {
                example_selected = true;
                if tokens.get(index + 1).is_none() {
                    out.ambiguity("unknown-gommage-admin-command");
                    return None;
                }
                index += 2;
            }
            Some(value) if value.starts_with("--example=") => {
                example_selected = true;
                index += 1;
            }
            Some(
                "--target" | "--target-dir" | "--features" | "-F" | "--jobs" | "-j" | "--profile"
                | "--color" | "--config" | "-Z" | "--message-format",
            ) => {
                if tokens.get(index + 1).is_none() {
                    out.ambiguity("unknown-gommage-admin-command");
                    return None;
                }
                index += 2;
            }
            Some(value)
                if value.starts_with("--target=")
                    || value.starts_with("--target-dir=")
                    || value.starts_with("--features=")
                    || value.starts_with("--jobs=")
                    || value.starts_with("--profile=")
                    || value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--message-format=") =>
            {
                index += 1;
            }
            Some(
                "--release"
                | "--all-features"
                | "--no-default-features"
                | "--locked"
                | "--offline"
                | "--frozen"
                | "--ignore-rust-version"
                | "--unit-graph"
                | "--future-incompat-report"
                | "--timings"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v",
            ) => index += 1,
            Some(value) if value.starts_with('-') => {
                out.ambiguity("unknown-gommage-admin-command");
                return None;
            }
            Some(_) | None => {
                argv_start = index;
                break;
            }
        }
    }

    let dynamic_selector = [&bin, &package, &manifest]
        .into_iter()
        .flatten()
        .any(Option::is_none);
    if dynamic_selector {
        out.ambiguity("dynamic-gommage-admin-command");
    }
    let explicit_other_bin = bin
        .as_ref()
        .and_then(Option::as_deref)
        .is_some_and(|value| value != "gommage");
    let selected_gommage = !example_selected
        && !explicit_other_bin
        && (bin.as_ref().and_then(Option::as_deref) == Some("gommage")
            || package.as_ref().and_then(Option::as_deref) == Some("gommage-cli")
            || manifest
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(is_gommage_cli_manifest));
    if selected_gommage {
        return Some(argv_start);
    }

    let has_static_selector = example_selected
        || [&bin, &package, &manifest]
            .into_iter()
            .flatten()
            .any(|selector| selector.is_some());
    if has_static_selector && !dynamic_selector {
        return None;
    }

    let possible_admin_argv = tokens[argv_start..]
        .first()
        .and_then(Option::as_deref)
        .is_some_and(is_gommage_admin_command_name);
    if dynamic_selector || possible_admin_argv {
        out.ambiguity("unknown-gommage-admin-command");
    }
    None
}

fn cargo_run_subcommand_index(tokens: &[Option<String>]) -> Option<usize> {
    let mut index = 0;
    if tokens
        .first()
        .and_then(Option::as_deref)
        .is_some_and(|token| token.starts_with('+'))
    {
        index += 1;
    }
    while index < tokens.len() {
        match tokens[index].as_deref() {
            Some("run" | "r") => return Some(index),
            Some(
                "--verbose" | "-v" | "--quiet" | "-q" | "--frozen" | "--locked" | "--offline"
                | "--version" | "-V" | "--list" | "--help" | "-h",
            ) => index += 1,
            Some("--color" | "--config" | "-Z" | "--explain" | "-C") => index += 2,
            Some(value)
                if value.starts_with("--color=")
                    || value.starts_with("--config=")
                    || value.starts_with("--explain=") =>
            {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

fn is_gommage_cli_manifest(value: &str) -> bool {
    value == "crates/gommage-cli/Cargo.toml"
        || value == "./crates/gommage-cli/Cargo.toml"
        || value.ends_with("/crates/gommage-cli/Cargo.toml")
}

fn is_gommage_admin_command_name(value: &str) -> bool {
    matches!(
        value,
        "grant"
            | "g"
            | "confirm"
            | "revoke"
            | "approval"
            | "tui"
            | "init"
            | "quickstart"
            | "upgrade"
            | "policy"
            | "project"
            | "agent"
            | "repair"
            | "daemon"
            | "expedition"
            | "uninstall"
            | "state"
            | "harness"
    )
}

fn classify_gommage_argv(raw: &[Option<String>], out: &mut EffectSet<GommageAdminEffect>) -> bool {
    if raw.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-admin-command");
    }
    let argv = strip_gommage_home_options(raw, out);

    let help_requested = argv
        .iter()
        .flatten()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"));
    let version_requested = argv
        .first()
        .and_then(Option::as_deref)
        .is_some_and(|arg| matches!(arg, "-V" | "--version"));
    if help_requested || version_requested {
        return false;
    }

    // A bare `gommage` invocation only renders help and does not mutate.
    if argv.is_empty() {
        return false;
    }
    let Some(command) = static_gommage_subcommand(&argv, 0, out) else {
        return false;
    };
    let dry_run = has_exact_flag(&argv, "--dry-run");

    match command {
        "grant" | "g" | "confirm" | "revoke" => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "approval" => classify_approval_command(&argv, dry_run, out),
        "tui" => {
            let inspection_only = [
                "--snapshot",
                "--watch",
                "--watch-ticks",
                "--stream",
                "--stream-ticks",
            ]
            .iter()
            .any(|flag| has_exact_or_value_flag(&argv, flag));
            if !inspection_only {
                out.push(GommageAdminEffect::Authorize);
            }
            !inspection_only
        }
        "init" => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        "quickstart" | "upgrade" => {
            if !dry_run {
                out.push(GommageAdminEffect::Reconfigure);
            }
            !dry_run && command == "quickstart"
        }
        "policy" => classify_policy_command(&argv, out),
        "project" => classify_project_command(&argv, dry_run, out),
        "agent" => classify_agent_command(&argv, dry_run, out),
        "repair" => classify_repair_command(&argv, dry_run, out),
        "daemon" => classify_daemon_command(&argv, dry_run, out),
        "expedition" => classify_expedition_command(&argv, out),
        "harness" => classify_harness_command(&argv, dry_run, out),
        "state" => classify_state_command(&argv, dry_run, out),
        "uninstall" => {
            if !dry_run {
                out.push(GommageAdminEffect::Disable);
            }
            !dry_run
                && (has_exact_flag(&argv, "--purge-home")
                    || has_exact_flag(&argv, "--home-data")
                    || has_exact_flag(&argv, "--all"))
        }
        // Closed inventory of non-administrative top-level commands. Some can
        // have ordinary filesystem or network effects, which remain visible to
        // their dedicated typed effects and compatibility mapper rules.
        "list" | "beta" | "update" | "posture" | "tail" | "explain" | "audit-verify" | "replay"
        | "decide" | "map" | "doctor" | "verify" | "managed" | "release" | "report" | "run"
        | "smoke" | "stats" | "sandbox" | "session" | "mascot" | "logo" | "hook" | "mcp" => {
            validate_read_only_nested_command(command, &argv, out);
            false
        }
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

fn strip_gommage_home_options(
    raw: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> Vec<Option<String>> {
    let mut argv = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_deref() {
            Some("--home") => {
                match raw.get(index + 1) {
                    Some(Some(value)) if !value.is_empty() => {}
                    Some(None) => out.ambiguity("dynamic-gommage-admin-command"),
                    _ => out.ambiguity("unknown-gommage-admin-command"),
                }
                index += 2;
            }
            Some(value) if value.starts_with("--home=") => {
                if value == "--home=" {
                    out.ambiguity("unknown-gommage-admin-command");
                }
                index += 1;
            }
            _ => {
                argv.push(raw[index].clone());
                index += 1;
            }
        }
    }
    argv
}

fn static_gommage_subcommand<'a>(
    argv: &'a [Option<String>],
    index: usize,
    out: &mut EffectSet<GommageAdminEffect>,
) -> Option<&'a str> {
    match argv.get(index) {
        Some(Some(command)) => Some(command),
        Some(None) => {
            out.ambiguity("dynamic-gommage-admin-command");
            None
        }
        None => {
            out.ambiguity("unknown-gommage-admin-command");
            None
        }
    }
}

fn has_exact_flag(argv: &[Option<String>], flag: &str) -> bool {
    argv.iter().any(|arg| arg.as_deref() == Some(flag))
}

fn has_exact_or_value_flag(argv: &[Option<String>], flag: &str) -> bool {
    argv.iter().flatten().any(|arg| {
        arg == flag
            || arg
                .strip_prefix(flag)
                .is_some_and(|suffix| suffix.starts_with('='))
    })
}

fn classify_approval_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let Some(command) = static_gommage_subcommand(argv, 1, out) else {
        return false;
    };
    match command {
        "approve" | "deny" => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "webhook" | "callback" if !dry_run => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "deny-stale" if has_exact_flag(argv, "--apply") => {
            out.push(GommageAdminEffect::Authorize);
            true
        }
        "webhook" | "callback" | "deny-stale" | "list" | "show" | "dlq" | "replay" | "evidence"
        | "template" => false,
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

fn classify_policy_command(
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    let Some(command) = static_gommage_subcommand(argv, 1, out) else {
        return false;
    };
    match command {
        "init" => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        "check" | "layers" | "lint" | "schema" | "test" | "diff" | "suggest" | "snapshot"
        | "capture" | "hash" => false,
        _ => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
    }
}

fn classify_project_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("init") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            false
        }
        Some("init") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_agent_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("install") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("uninstall") if !dry_run => {
            out.push(GommageAdminEffect::Disable);
            false
        }
        Some("install" | "uninstall" | "status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_repair_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("agent") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            !has_exact_flag(argv, "--restore-backup")
        }
        Some("agent") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_daemon_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("install") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("uninstall") if !dry_run => {
            out.push(GommageAdminEffect::Disable);
            false
        }
        Some("reload") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("install" | "uninstall" | "status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_expedition_command(
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("start" | "end") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("status") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_harness_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("write-context") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("write-context" | "diagnose" | "explain") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn classify_state_command(
    argv: &[Option<String>],
    dry_run: bool,
    out: &mut EffectSet<GommageAdminEffect>,
) -> bool {
    match static_gommage_subcommand(argv, 1, out) {
        Some("rebuild" | "vacuum") => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("reset") if !dry_run => {
            out.push(GommageAdminEffect::Reconfigure);
            true
        }
        Some("reset" | "verify" | "stats") => false,
        Some(_) => {
            out.ambiguity("unknown-gommage-admin-command");
            false
        }
        None => false,
    }
}

fn validate_read_only_nested_command(
    command: &str,
    argv: &[Option<String>],
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let known: &[&str] = match command {
        "beta" => &["check"],
        "managed" => &["status"],
        "release" => &["verify"],
        "report" => &["bundle"],
        "run" => &["codex"],
        "sandbox" => &["advise"],
        "session" => &["doctor"],
        _ => return,
    };
    let Some(nested) = static_gommage_subcommand(argv, 1, out) else {
        return;
    };
    if !known.contains(&nested) {
        out.ambiguity("unknown-gommage-admin-command");
    }
}

fn classify_gommage_service_lifecycle(
    command: &ShellCommand,
    out: &mut EffectSet<GommageAdminEffect>,
) {
    let Ok(head) = command.effective_head() else {
        return;
    };
    if !matches!(
        head,
        "systemctl" | "launchctl" | "service" | "pkill" | "killall" | "kill"
    ) {
        return;
    }
    let tokens = shell_word_tokens(command.effective_args());
    let targets_gommage = tokens.iter().flatten().any(|arg| match head {
        "systemctl" | "service" => {
            matches!(
                arg.rsplit('/').next(),
                Some("gommage-daemon.service" | "gommage-daemon")
            )
        }
        "launchctl" => {
            matches!(
                arg.as_str(),
                "dev.gommage.daemon" | "dev.gommage.daemon.plist"
            ) || arg.ends_with("/dev.gommage.daemon")
                || arg.ends_with("/dev.gommage.daemon.plist")
        }
        "pkill" | "killall" => arg.contains("gommage-daemon"),
        _ => false,
    });
    let lifecycle = match head {
        "systemctl" => tokens.iter().flatten().find_map(|arg| match arg.as_str() {
            "start" | "restart" | "try-restart" | "reload" | "reload-or-restart" | "enable"
            | "edit" | "link" | "reenable" | "preset" | "revert" | "unmask" => {
                Some(GommageAdminEffect::Reconfigure)
            }
            "stop" | "disable" | "mask" | "kill" => Some(GommageAdminEffect::Disable),
            _ => None,
        }),
        "launchctl" => tokens.iter().flatten().find_map(|arg| match arg.as_str() {
            "start" | "kickstart" | "bootstrap" | "load" | "enable" | "submit" => {
                Some(GommageAdminEffect::Reconfigure)
            }
            "stop" | "bootout" | "unload" | "disable" | "remove" | "kill" => {
                Some(GommageAdminEffect::Disable)
            }
            _ => None,
        }),
        "service" => tokens.iter().flatten().find_map(|arg| match arg.as_str() {
            "start" | "restart" | "reload" => Some(GommageAdminEffect::Reconfigure),
            "stop" => Some(GommageAdminEffect::Disable),
            _ => None,
        }),
        "pkill" | "killall" => Some(GommageAdminEffect::Disable),
        "kill" if tokens.iter().any(Option::is_none) => {
            out.ambiguity("dynamic-gommage-service-target");
            return;
        }
        _ => None,
    };
    let Some(lifecycle) = lifecycle else {
        if targets_gommage && tokens.iter().any(Option::is_none) {
            out.ambiguity("dynamic-gommage-service-action");
        } else if targets_gommage && !known_gommage_service_inspection(head, &tokens) {
            out.ambiguity("unknown-gommage-service-action");
        }
        return;
    };

    if targets_gommage {
        out.push(lifecycle);
    } else if tokens.iter().any(Option::is_none) {
        out.ambiguity("dynamic-gommage-service-target");
    }
}

fn known_gommage_service_inspection(head: &str, tokens: &[Option<String>]) -> bool {
    tokens.iter().flatten().any(|arg| match head {
        "systemctl" => matches!(
            arg.as_str(),
            "status"
                | "show"
                | "cat"
                | "help"
                | "is-active"
                | "is-enabled"
                | "is-failed"
                | "list-dependencies"
        ),
        "launchctl" => matches!(
            arg.as_str(),
            "list"
                | "print"
                | "print-disabled"
                | "blame"
                | "procinfo"
                | "dumpstate"
                | "getenv"
                | "help"
                | "managerpid"
                | "manageruid"
                | "managername"
                | "error"
                | "variant"
                | "version"
        ),
        "service" => arg == "status",
        _ => false,
    })
}

/// Convert parsed commands into deterministic filesystem effects.
pub(crate) fn filesystem_effects(
    analysis: &ShellAnalysis,
    cwd: Option<&str>,
) -> EffectSet<FsEffect> {
    let mut out = EffectSet::default();
    let supplied_cwd = cwd.is_some();
    let cwd = trusted_cwd(cwd);
    if supplied_cwd && cwd.is_none() {
        out.ambiguity("invalid-cwd");
    }
    for command in &analysis.commands {
        for redirect in &command.redirections {
            match static_path(&redirect.target, cwd.as_deref()) {
                Ok(path) => out.push(FsEffect {
                    kind: match redirect.kind {
                        RedirectionKind::Read => FsEffectKind::Read,
                        RedirectionKind::Write => FsEffectKind::Write,
                    },
                    path,
                }),
                Err(reason) => out.ambiguity(reason),
            }
        }

        let Ok(head) = command.effective_head() else {
            continue;
        };
        let args = command.effective_args();
        collect_gommage_cli_filesystem_effects(command, cwd.as_deref(), &mut out);
        match head {
            "cat" | "head" | "tail" | "less" | "od" | "xxd" | "base64" | "strings" | "file" => {
                collect_read_operands(head, args, cwd.as_deref(), &mut out)
            }
            "cp" | "install" => collect_copy_effects(head, args, cwd.as_deref(), &mut out),
            "mv" => collect_move_effects(args, cwd.as_deref(), &mut out),
            "rsync" => collect_rsync_effects(args, cwd.as_deref(), &mut out),
            "ln" => collect_ln_effects(args, cwd.as_deref(), &mut out),
            "touch" | "mkdir" | "rm" => {
                collect_all_operands(head, args, cwd.as_deref(), FsEffectKind::Write, &mut out)
            }
            "tee" => {
                collect_all_operands("tee", args, cwd.as_deref(), FsEffectKind::Write, &mut out)
            }
            "sed" => collect_sed_effects(args, cwd.as_deref(), &mut out),
            "dd" => collect_dd_effects(args, cwd.as_deref(), &mut out),
            _ => {}
        }
    }
    out
}

fn collect_gommage_cli_filesystem_effects(
    command: &ShellCommand,
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let Some(raw) = gommage_invocation_words(command, out) else {
        return;
    };
    let argv = strip_gommage_home_word_options(&raw);
    if argv.iter().any(|word| {
        word.static_value()
            .is_ok_and(|value| matches!(value, "-h" | "--help"))
    }) {
        return;
    }
    let Some(top) = argv.first().and_then(|word| word.static_value().ok()) else {
        return;
    };

    match top {
        "approval" => match gommage_static_word(&argv, 1) {
            Some("callback") => {
                collect_gommage_path_options(&argv, "--body", cwd, FsEffectKind::Read, out)
            }
            Some("evidence") => {
                collect_gommage_path_options(&argv, "--output", cwd, FsEffectKind::Write, out)
            }
            _ => {}
        },
        "report" if gommage_static_word(&argv, 1) == Some("bundle") => {
            collect_gommage_path_options(&argv, "--output", cwd, FsEffectKind::Write, out);
        }
        "upgrade" => collect_gommage_upgrade_paths(&argv, cwd, out),
        "project" if gommage_static_word(&argv, 1) == Some("init") => {
            collect_gommage_project_paths(&argv, cwd, out);
        }
        "release" if gommage_static_word(&argv, 1) == Some("verify") => {
            collect_gommage_release_paths(&argv, cwd, out);
        }
        "replay" => {
            collect_gommage_path_options(&argv, "--audit", cwd, FsEffectKind::Read, out);
            collect_gommage_path_options(&argv, "--policy", cwd, FsEffectKind::Read, out);
        }
        "policy" => collect_gommage_policy_read_paths(&argv, cwd, out),
        "beta" if gommage_static_word(&argv, 1) == Some("check") => {
            collect_gommage_path_options(&argv, "--policy-test", cwd, FsEffectKind::Read, out);
        }
        "verify" => {
            collect_gommage_path_options(&argv, "--policy-test", cwd, FsEffectKind::Read, out)
        }
        _ => {}
    }
}

fn strip_gommage_home_word_options(raw: &[ShellWord]) -> Vec<ShellWord> {
    let mut argv = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let value = raw[index].static_value().ok();
        if value == Some("--home") {
            index += 2;
        } else if value.is_some_and(|value| value.starts_with("--home="))
            || raw[index].raw.starts_with("--home=")
        {
            index += 1;
        } else {
            argv.push(raw[index].clone());
            index += 1;
        }
    }
    argv
}

fn gommage_static_word(argv: &[ShellWord], index: usize) -> Option<&str> {
    argv.get(index)?.static_value().ok()
}

fn gommage_path_option_words<T: PartialEq>(
    argv: &[ShellWord],
    flag: &str,
    out: &mut EffectSet<T>,
) -> Vec<ShellWord> {
    let attached_prefix = format!("{flag}=");
    let mut paths = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        match argv[index].static_value() {
            Ok(value) if value == flag => {
                let Some(path) = argv.get(index + 1) else {
                    out.ambiguity("missing-gommage-path-option-value");
                    break;
                };
                paths.push(path.clone());
                index += 2;
            }
            Ok(value) if value.starts_with(&attached_prefix) => {
                let path = &value[attached_prefix.len()..];
                if path.is_empty() {
                    out.ambiguity("missing-gommage-path-option-value");
                } else {
                    let mut word = argv[index].clone();
                    word.raw = word
                        .raw
                        .split_once('=')
                        .map_or_else(|| path.to_string(), |(_, raw)| raw.to_string());
                    word.value = Some(path.to_string());
                    paths.push(word);
                }
                index += 1;
            }
            Err(reason) if argv[index].raw.starts_with(&attached_prefix) => {
                out.ambiguity(reason);
                index += 1;
            }
            _ => index += 1,
        }
    }
    paths
}

fn collect_gommage_path_options(
    argv: &[ShellWord],
    flag: &str,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    for path in gommage_path_option_words(argv, flag, out) {
        add_path_effect(&path, cwd, kind, out);
    }
}

fn collect_gommage_upgrade_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if gommage_has_flag(argv, "--dry-run") {
        return;
    }

    for installer in gommage_path_option_words(argv, "--installer", out) {
        match installer.static_value() {
            Ok(value) if value.starts_with("https://") || value.starts_with("http://") => {}
            Ok(value) if value.starts_with("file://") => {
                add_synthetic_path(
                    value.trim_start_matches("file://"),
                    cwd,
                    FsEffectKind::Read,
                    out,
                );
            }
            Ok(_) => add_path_effect(&installer, cwd, FsEffectKind::Read, out),
            Err(reason) => out.ambiguity(reason),
        }
    }

    if gommage_has_flag(argv, "--skill-only") {
        return;
    }
    for bin_dir in gommage_path_option_words(argv, "--bin-dir", out) {
        let Some(dir) = normalized_effect_path(&bin_dir, cwd, out) else {
            continue;
        };
        out.push(FsEffect {
            kind: FsEffectKind::Write,
            path: dir.clone(),
        });
        for binary in ["gommage", "gommage-daemon", "gommage-mcp"] {
            out.push(FsEffect {
                kind: FsEffectKind::Write,
                path: child_effect_path(&dir, binary),
            });
        }
    }
}

fn collect_gommage_project_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if gommage_has_flag(argv, "--dry-run") {
        return;
    }
    let roots = gommage_path_option_words(argv, "--root", out);
    let roots = if roots.is_empty() {
        cwd.map(|cwd| {
            vec![ShellWord {
                raw: cwd.to_string(),
                value: Some(cwd.to_string()),
                provenance: WordProvenance::default(),
                ambiguity: None,
            }]
        })
        .unwrap_or_default()
    } else {
        roots
    };
    for root in roots {
        let Some(root) = normalized_effect_path(&root, cwd, out) else {
            continue;
        };
        for relative in [
            ".gommage/policy.d/20-project.yaml",
            ".gommage/policy-fixtures.yaml",
            ".gommage/README.md",
        ] {
            out.push(FsEffect {
                kind: FsEffectKind::Write,
                path: child_effect_path(&root, relative),
            });
        }
    }
}

fn collect_gommage_release_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    let dirs = gommage_path_option_words(argv, "--dir", out);
    if dirs.is_empty() {
        return;
    }
    let assets: Vec<String> = if gommage_has_flag(argv, "--all-assets") {
        gommage_release_assets()
            .iter()
            .map(|asset| (*asset).to_string())
            .collect()
    } else {
        let selected = gommage_static_option(argv, "--asset", out);
        match selected.as_deref() {
            None | Some("auto") => default_gommage_release_asset()
                .into_iter()
                .map(str::to_string)
                .collect(),
            Some(asset) if gommage_release_assets().contains(&asset) => {
                vec![asset.to_string()]
            }
            Some(_) => {
                out.ambiguity("unknown-gommage-release-asset");
                Vec::new()
            }
        }
    };
    for dir in dirs {
        let Some(dir) = normalized_effect_path(&dir, cwd, out) else {
            continue;
        };
        out.push(FsEffect {
            kind: FsEffectKind::Write,
            path: dir.clone(),
        });
        for asset in &assets {
            for name in [
                asset.to_string(),
                format!("{asset}.sha256"),
                format!("{asset}.sigstore.json"),
            ] {
                out.push(FsEffect {
                    kind: FsEffectKind::Write,
                    path: child_effect_path(&dir, &name),
                });
            }
        }
    }
}

fn collect_gommage_policy_read_paths(
    argv: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match gommage_static_word(argv, 1) {
        Some("lint") => collect_gommage_positional_path(
            argv,
            2,
            &["--strict", "--json"],
            cwd,
            FsEffectKind::Read,
            out,
        ),
        Some("test") => {
            collect_gommage_positional_path(argv, 2, &["--json"], cwd, FsEffectKind::Read, out)
        }
        Some("diff") => {
            for flag in ["--from", "--to", "--against"] {
                collect_gommage_path_options(argv, flag, cwd, FsEffectKind::Read, out);
            }
        }
        Some("suggest") => {
            collect_gommage_path_options(argv, "--audit", cwd, FsEffectKind::Read, out)
        }
        _ => {}
    }
}

fn collect_gommage_positional_path(
    argv: &[ShellWord],
    start: usize,
    boolean_options: &[&str],
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    for word in &argv[start..] {
        match word.static_value() {
            Ok("--") => continue,
            Ok(value) if boolean_options.contains(&value) => continue,
            Ok(value) if value.starts_with('-') => continue,
            Ok(_) => {
                add_path_effect(word, cwd, kind, out);
                return;
            }
            Err(reason) => {
                out.ambiguity(reason);
                return;
            }
        }
    }
}

fn gommage_static_option(
    argv: &[ShellWord],
    flag: &str,
    out: &mut EffectSet<FsEffect>,
) -> Option<String> {
    gommage_path_option_words(argv, flag, out)
        .last()
        .and_then(|word| word.static_value().ok().map(str::to_string))
}

fn gommage_has_flag(argv: &[ShellWord], flag: &str) -> bool {
    argv.iter()
        .any(|word| word.static_value().ok() == Some(flag))
}

fn normalized_effect_path(
    word: &ShellWord,
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) -> Option<String> {
    match static_path(word, cwd) {
        Ok(path) => Some(path),
        Err(reason) => {
            out.ambiguity(reason);
            None
        }
    }
}

fn child_effect_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{child}", parent.trim_end_matches('/'))
    }
}

fn gommage_release_assets() -> &'static [&'static str] {
    &[
        "gommage-aarch64-darwin.tar.gz",
        "gommage-aarch64-linux.tar.gz",
        "gommage-x86_64-darwin.tar.gz",
        "gommage-x86_64-linux.tar.gz",
    ]
}

fn default_gommage_release_asset() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("gommage-aarch64-darwin.tar.gz"),
        ("macos", "x86_64") => Some("gommage-x86_64-darwin.tar.gz"),
        ("linux", "aarch64") => Some("gommage-aarch64-linux.tar.gz"),
        ("linux", "x86_64") => Some("gommage-x86_64-linux.tar.gz"),
        _ => None,
    }
}

fn trusted_cwd(cwd: Option<&str>) -> Option<String> {
    let cwd = cwd?;
    if !cwd.starts_with('/') || cwd.split('/').any(|part| part == "..") {
        return None;
    }
    normalize_lexical(cwd, false).ok()
}

pub(crate) fn static_path(word: &ShellWord, cwd: Option<&str>) -> Result<String, Ambiguity> {
    let raw = word.static_value()?;
    let mut path = raw.to_string();
    let literal_home_alias = !word.provenance.home_alias
        && (matches!(path.as_str(), "$HOME" | "${HOME}" | "~")
            || path.starts_with("$HOME/")
            || path.starts_with("${HOME}/")
            || path.starts_with("~/"));

    let absolute_or_home = path.starts_with('/') || path == "$HOME" || path.starts_with("$HOME/");
    if (!absolute_or_home || literal_home_alias)
        && let Some(cwd) = cwd
    {
        path = format!("{cwd}/{path}");
    }
    let normalized = normalize_lexical(&path, word.provenance.home_alias)?;
    if literal_home_alias && cwd.is_none() {
        Ok(format!("./{normalized}"))
    } else {
        Ok(normalized)
    }
}

fn normalize_lexical(path: &str, home_alias: bool) -> Result<String, Ambiguity> {
    if path.split('/').any(|part| part == "..") {
        return Err("parent-component");
    }
    let (prefix, rest) = if home_alias && path == "$HOME" {
        ("$HOME", "")
    } else if home_alias {
        path.strip_prefix("$HOME/")
            .map_or(("", path), |rest| ("$HOME", rest))
    } else if let Some(rest) = path.strip_prefix('/') {
        ("/", rest)
    } else {
        ("", path)
    };

    let components: Vec<&str> = rest
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = components.join("/");
    match prefix {
        "/" if joined.is_empty() => Ok("/".to_string()),
        "/" => Ok(format!("/{joined}")),
        "$HOME" if joined.is_empty() => Ok("$HOME".to_string()),
        "$HOME" => Ok(format!("$HOME/{joined}")),
        _ if joined.is_empty() => Ok(".".to_string()),
        _ => Ok(joined),
    }
}

fn add_path_effect(
    word: &ShellWord,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    match static_path(word, cwd) {
        Ok(path) => out.push(FsEffect { kind, path }),
        Err(reason) => out.ambiguity(reason),
    }
}

fn parse_operands<'a>(
    command: &str,
    args: &'a [ShellWord],
) -> Result<(Vec<&'a ShellWord>, Option<ShellWord>), Ambiguity> {
    let mut operands = Vec::new();
    let mut target_directory = None;
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let value = args[i].static_value()?;
        if options && value == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options && value.starts_with('-') && value != "-" {
            if option_takes_value(command, value) {
                let option = value;
                let Some(next) = args.get(i + 1) else {
                    return Err("missing-option-value");
                };
                if matches!(option, "-t" | "--target-directory") {
                    target_directory = Some(next.clone());
                }
                i += 2;
                continue;
            }
            if let Some(value) = value.strip_prefix("--target-directory=") {
                if value.is_empty() {
                    return Err("missing-option-value");
                }
                target_directory = Some(ShellWord {
                    raw: value.to_string(),
                    value: Some(value.to_string()),
                    provenance: WordProvenance::default(),
                    ambiguity: None,
                });
                i += 1;
                continue;
            }
            if matches!(command, "cp" | "mv" | "install" | "ln")
                && value.starts_with("-t")
                && value.len() > 2
            {
                let target = &value[2..];
                target_directory = Some(ShellWord {
                    raw: target.to_string(),
                    value: Some(target.to_string()),
                    provenance: WordProvenance::default(),
                    ambiguity: None,
                });
                i += 1;
                continue;
            }
            if option_has_attached_value(command, value)
                || known_boolean_option(command, value)
                || is_known_short_option_cluster(command, value)
            {
                i += 1;
                continue;
            }
            return Err("unknown-command-option");
        }
        operands.push(&args[i]);
        i += 1;
    }
    Ok((operands, target_directory))
}

fn option_takes_value(command: &str, option: &str) -> bool {
    match command {
        "cat" => false,
        "head" => matches!(option, "-n" | "--lines" | "-c" | "--bytes"),
        "tail" => matches!(
            option,
            "-n" | "--lines"
                | "-c"
                | "--bytes"
                | "--pid"
                | "-s"
                | "--sleep-interval"
                | "--max-unchanged-stats"
        ),
        "less" => matches!(
            option,
            "-D" | "-j" | "-k" | "-P" | "-t" | "-T" | "-x" | "-y" | "-z"
        ),
        "od" => matches!(
            option,
            "-A" | "--address-radix"
                | "-j"
                | "--skip-bytes"
                | "-N"
                | "--read-bytes"
                | "-t"
                | "--format"
                | "-w"
                | "--width"
                | "--endian"
        ),
        "xxd" => matches!(
            option,
            "-c" | "-cols" | "-g" | "-groupsize" | "-l" | "-len" | "-o" | "-seek" | "-s" | "-name"
        ),
        "base64" => matches!(option, "-w" | "--wrap"),
        "strings" => matches!(
            option,
            "-e" | "--encoding"
                | "-n"
                | "--bytes"
                | "-o"
                | "-t"
                | "--radix"
                | "-T"
                | "--target"
                | "-U"
                | "--unicode"
                | "--output-separator"
        ),
        "file" => matches!(
            option,
            "-e" | "--exclude"
                | "-f"
                | "--files-from"
                | "-m"
                | "--magic-file"
                | "-P"
                | "--parameter"
        ),
        "cp" | "mv" | "ln" => matches!(option, "-S" | "--suffix" | "-t" | "--target-directory"),
        "install" => matches!(
            option,
            "-g" | "--group"
                | "-m"
                | "--mode"
                | "-o"
                | "--owner"
                | "-S"
                | "--suffix"
                | "-t"
                | "--target-directory"
                | "--strip-program"
        ),
        "rsync" => matches!(
            option,
            "-e" | "--rsh"
                | "--exclude"
                | "--exclude-from"
                | "--include"
                | "--include-from"
                | "--filter"
                | "-f"
                | "--files-from"
                | "--rsync-path"
                | "--port"
                | "--password-file"
                | "--timeout"
                | "--contimeout"
                | "--max-size"
                | "--min-size"
                | "--bwlimit"
                | "--block-size"
                | "-B"
                | "--out-format"
                | "--log-file"
                | "--log-file-format"
                | "--remote-option"
                | "-M"
        ),
        "touch" => matches!(
            option,
            "-d" | "--date" | "-r" | "--reference" | "-t" | "--time"
        ),
        "mkdir" => matches!(option, "-m" | "--mode"),
        "rm" | "tee" => false,
        _ => false,
    }
}

fn option_has_attached_value(command: &str, option: &str) -> bool {
    if let Some((name, value)) = option.split_once('=') {
        return !value.is_empty()
            && (option_takes_value(command, name) || optional_value_option(command, name));
    }

    let Some(short) = option
        .strip_prefix('-')
        .filter(|value| !value.starts_with('-'))
    else {
        return false;
    };
    let mut chars = short.chars();
    let Some(flag) = chars.next() else {
        return false;
    };
    if chars.as_str().is_empty() {
        return false;
    }
    let name = format!("-{flag}");
    option_takes_value(command, &name)
        || matches!((command, flag), ("mkdir", 'Z') | ("cp" | "mv" | "ln", 'b'))
}

fn optional_value_option(command: &str, option: &str) -> bool {
    matches!(
        (command, option),
        ("cp" | "mv" | "ln", "--backup" | "--context")
            | ("install", "--backup" | "--context")
            | ("mkdir", "--context")
            | ("tail", "--follow")
    )
}

fn known_boolean_option(command: &str, option: &str) -> bool {
    match command {
        "cat" => matches!(
            option,
            "--show-all"
                | "--number-nonblank"
                | "--show-ends"
                | "--number"
                | "--squeeze-blank"
                | "--show-tabs"
                | "--help"
                | "--version"
        ),
        "head" => matches!(
            option,
            "--quiet"
                | "--silent"
                | "--verbose"
                | "-z"
                | "--zero-terminated"
                | "--help"
                | "--version"
        ),
        "tail" => matches!(
            option,
            "-f" | "--follow"
                | "-F"
                | "--retry"
                | "--quiet"
                | "--silent"
                | "--verbose"
                | "-z"
                | "--zero-terminated"
                | "--help"
                | "--version"
        ),
        "less" => matches!(
            option,
            "--help"
                | "--version"
                | "--quit-at-eof"
                | "--QUIT-AT-EOF"
                | "--quit-if-one-screen"
                | "--ignore-case"
                | "--IGNORE-CASE"
                | "--status-column"
                | "--LONG-PROMPT"
                | "--clear-screen"
                | "--silent"
                | "--SILENT"
                | "--tilde"
                | "--underline-special"
                | "--chop-long-lines"
                | "--no-init"
                | "--RAW-CONTROL-CHARS"
                | "--raw-control-chars"
                | "--squeeze-blank-lines"
                | "--tabs"
                | "--window"
                | "--hilite-unread"
        ),
        "od" => matches!(option, "-a" | "--traditional" | "--help" | "--version"),
        "xxd" => matches!(
            option,
            "-a" | "-autoskip"
                | "-b"
                | "-bits"
                | "-C"
                | "-capitalize"
                | "-d"
                | "-decimal"
                | "-E"
                | "-EBCDIC"
                | "-e"
                | "-g1"
                | "-h"
                | "-help"
                | "-i"
                | "-include"
                | "-p"
                | "-ps"
                | "-postscript"
                | "-plain"
                | "-r"
                | "-revert"
                | "-u"
                | "-uppercase"
                | "-v"
                | "-version"
        ),
        "base64" => matches!(
            option,
            "-d" | "--decode" | "-i" | "--ignore-garbage" | "--help" | "--version"
        ),
        "strings" => matches!(
            option,
            "-a" | "--all"
                | "-f"
                | "--print-file-name"
                | "-w"
                | "--include-all-whitespace"
                | "-h"
                | "--help"
                | "-v"
                | "-V"
                | "--version"
        ),
        "file" => matches!(
            option,
            "-b" | "--brief"
                | "-C"
                | "--compile"
                | "-c"
                | "--checking-printout"
                | "-E"
                | "--no-sandbox"
                | "-F"
                | "--separator"
                | "-h"
                | "--no-dereference"
                | "-i"
                | "--mime"
                | "--mime-type"
                | "--mime-encoding"
                | "-k"
                | "--keep-going"
                | "-L"
                | "--dereference"
                | "-l"
                | "--list"
                | "-N"
                | "--no-pad"
                | "-n"
                | "--no-buffer"
                | "-p"
                | "--preserve-date"
                | "-r"
                | "--raw"
                | "-s"
                | "--special-files"
                | "-S"
                | "-v"
                | "--version"
                | "-z"
                | "--uncompress"
                | "-Z"
                | "--uncompress-noreport"
                | "--help"
        ),
        "cp" => matches!(
            option,
            "--archive"
                | "--attributes-only"
                | "--copy-contents"
                | "--dereference"
                | "--force"
                | "--interactive"
                | "--link"
                | "--no-clobber"
                | "--no-dereference"
                | "--no-preserve"
                | "--no-target-directory"
                | "--one-file-system"
                | "--parents"
                | "--preserve"
                | "--recursive"
                | "--reflink"
                | "--remove-destination"
                | "--sparse"
                | "--strip-trailing-slashes"
                | "--symbolic-link"
                | "--update"
                | "--verbose"
                | "--help"
                | "--version"
                | "--backup"
                | "--context"
        ),
        "mv" => matches!(
            option,
            "--force"
                | "--interactive"
                | "--no-clobber"
                | "--no-target-directory"
                | "--strip-trailing-slashes"
                | "--update"
                | "--verbose"
                | "--help"
                | "--version"
                | "--backup"
                | "--context"
        ),
        "install" => matches!(
            option,
            "--backup"
                | "-C"
                | "--compare"
                | "-d"
                | "--directory"
                | "-D"
                | "--create-leading"
                | "-p"
                | "--preserve-timestamps"
                | "-s"
                | "--strip"
                | "-T"
                | "--no-target-directory"
                | "-v"
                | "--verbose"
                | "--help"
                | "--version"
                | "--context"
        ),
        "ln" => matches!(
            option,
            "--backup"
                | "-d"
                | "-F"
                | "--directory"
                | "-f"
                | "--force"
                | "-i"
                | "--interactive"
                | "-L"
                | "--logical"
                | "-n"
                | "--no-dereference"
                | "-P"
                | "--physical"
                | "-r"
                | "--relative"
                | "-s"
                | "--symbolic"
                | "-T"
                | "--no-target-directory"
                | "-v"
                | "--verbose"
                | "--help"
                | "--version"
                | "--context"
        ),
        "rsync" => matches!(
            option,
            "--verbose"
                | "--info"
                | "--debug"
                | "--msgs2stderr"
                | "--quiet"
                | "--no-motd"
                | "--checksum"
                | "--archive"
                | "--recursive"
                | "--relative"
                | "--no-implied-dirs"
                | "--backup"
                | "--update"
                | "--inplace"
                | "--append"
                | "--append-verify"
                | "--dirs"
                | "--links"
                | "--copy-links"
                | "--copy-unsafe-links"
                | "--safe-links"
                | "--munge-links"
                | "--copy-dirlinks"
                | "--keep-dirlinks"
                | "--hard-links"
                | "--perms"
                | "--executability"
                | "--acls"
                | "--xattrs"
                | "--owner"
                | "--group"
                | "--devices"
                | "--copy-devices"
                | "--specials"
                | "--times"
                | "--omit-dir-times"
                | "--omit-link-times"
                | "--super"
                | "--fake-super"
                | "--sparse"
                | "--preallocate"
                | "--dry-run"
                | "--whole-file"
                | "--checksum-choice"
                | "--one-file-system"
                | "--existing"
                | "--ignore-existing"
                | "--remove-source-files"
                | "--delete"
                | "--delete-before"
                | "--delete-during"
                | "--delete-delay"
                | "--delete-after"
                | "--delete-excluded"
                | "--ignore-missing-args"
                | "--delete-missing-args"
                | "--ignore-errors"
                | "--force"
                | "--max-delete"
                | "--numeric-ids"
                | "--usermap"
                | "--groupmap"
                | "--chown"
                | "--ignore-times"
                | "--size-only"
                | "--modify-window"
                | "--temp-dir"
                | "--fuzzy"
                | "--compare-dest"
                | "--copy-dest"
                | "--link-dest"
                | "--compress"
                | "--compress-choice"
                | "--compress-level"
                | "--skip-compress"
                | "--partial"
                | "--partial-dir"
                | "--delay-updates"
                | "--prune-empty-dirs"
                | "--progress"
                | "--stats"
                | "--human-readable"
                | "--itemize-changes"
                | "--list-only"
                | "--protect-args"
                | "--old-args"
                | "--secluded-args"
                | "--iconv"
                | "--checksum-seed"
                | "--ipv4"
                | "--ipv6"
                | "--version"
                | "--help"
        ),
        "touch" => matches!(
            option,
            "-a" | "-c" | "--no-create" | "-m" | "-h" | "--no-dereference" | "--help" | "--version"
        ),
        "mkdir" => matches!(
            option,
            "-p" | "--parents" | "-v" | "--verbose" | "-Z" | "--context" | "--help" | "--version"
        ),
        "rm" => matches!(
            option,
            "--force"
                | "--interactive"
                | "--interactive=always"
                | "--interactive=once"
                | "--one-file-system"
                | "--no-preserve-root"
                | "--preserve-root"
                | "--recursive"
                | "--dir"
                | "--verbose"
                | "--help"
                | "--version"
        ),
        "tee" => matches!(
            option,
            "--append" | "--ignore-interrupts" | "--output-error" | "--help" | "--version"
        ),
        _ => false,
    }
}

fn is_known_short_option_cluster(command: &str, value: &str) -> bool {
    let Some(flags) = value
        .strip_prefix('-')
        .filter(|value| !value.starts_with('-'))
    else {
        return false;
    };
    if flags.is_empty() {
        return false;
    }
    if matches!(command, "head" | "tail") && flags.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    let allowed = match command {
        "cat" => "AbEeEnstTuv",
        "head" => "qvzc",
        "tail" => "fFqvzc",
        "less" => "aAbBcCeEfFgGiILmMnNqQRsSuUVwWX",
        "od" => "abcdDfFhHiIlLoOsvxX",
        "xxd" => "abCdeEhipruv",
        "base64" => "di",
        "strings" => "afhwvV",
        "file" => "bCcEhikLlNnprsSvzZ",
        "cp" => "abdfHilLnPrRsTuvx",
        "mv" => "bfinTuv",
        "install" => "bCDdpsTv",
        "ln" => "bdfFiLnPrsTv",
        "rsync" => "avqcrRbuolHDptgxnSAXWNKydFhPsiz",
        "touch" => "acmh",
        "mkdir" => "pvZ",
        "rm" => "firdRv",
        "tee" => "ai",
        _ => return false,
    };
    flags.chars().all(|flag| allowed.contains(flag))
}

fn collect_read_operands(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands(command, args) {
        Ok((operands, _)) => {
            for operand in operands {
                if operand.value.as_deref() != Some("-") {
                    add_path_effect(operand, cwd, FsEffectKind::Read, out);
                }
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

fn collect_copy_effects(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    out: &mut EffectSet<FsEffect>,
) {
    if command == "install"
        && args.iter().any(|arg| {
            arg.static_value()
                .is_ok_and(|arg| matches!(arg, "-d" | "--directory"))
        })
    {
        collect_all_operands("install", args, cwd, FsEffectKind::Write, out);
        return;
    }
    match parse_operands(command, args) {
        Ok((operands, target_directory)) => {
            if let Some(target) = target_directory {
                for source in operands {
                    add_path_effect(source, cwd, FsEffectKind::Read, out);
                }
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if let Some((destination, sources)) = operands.split_last() {
                if sources.is_empty() {
                    out.ambiguity("missing-copy-source");
                }
                for source in sources {
                    add_path_effect(source, cwd, FsEffectKind::Read, out);
                }
                add_path_effect(destination, cwd, FsEffectKind::Write, out);
            } else {
                out.ambiguity("missing-copy-operands");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

fn collect_move_effects(args: &[ShellWord], cwd: Option<&str>, out: &mut EffectSet<FsEffect>) {
    match parse_operands("mv", args) {
        Ok((operands, target_directory)) => {
            for operand in &operands {
                add_path_effect(operand, cwd, FsEffectKind::Write, out);
            }
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if operands.len() < 2 {
                out.ambiguity("missing-move-operands");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

fn collect_all_operands(
    command: &str,
    args: &[ShellWord],
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    match parse_operands(command, args) {
        Ok((operands, target_directory)) => {
            for operand in operands {
                add_path_effect(operand, cwd, kind, out);
            }
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, kind, out);
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

fn collect_rsync_effects(args: &[ShellWord], cwd: Option<&str>, out: &mut EffectSet<FsEffect>) {
    let remove_sources = args.iter().any(|arg| {
        arg.static_value()
            .is_ok_and(|arg| arg == "--remove-source-files")
    });
    let Ok((operands, _)) = parse_operands("rsync", args) else {
        out.ambiguity("rsync-options");
        return;
    };
    let Some((destination, sources)) = operands.split_last() else {
        out.ambiguity("missing-rsync-operands");
        return;
    };
    for source in sources {
        match source.static_value() {
            Ok(value) if is_remote_endpoint(value) => {}
            Ok(_) => {
                add_path_effect(source, cwd, FsEffectKind::Read, out);
                if remove_sources {
                    add_path_effect(source, cwd, FsEffectKind::Write, out);
                }
            }
            Err(reason) => out.ambiguity(reason),
        }
    }
    match destination.static_value() {
        Ok(value) if is_remote_endpoint(value) => {}
        Ok(_) => add_path_effect(destination, cwd, FsEffectKind::Write, out),
        Err(reason) => out.ambiguity(reason),
    }
}

pub(crate) fn has_static_remote_rsync(analysis: &ShellAnalysis) -> bool {
    analysis.commands.iter().any(|command| {
        command.effective_head() == Ok("rsync")
            && parse_operands("rsync", command.effective_args()).is_ok_and(|(operands, _)| {
                operands
                    .iter()
                    .any(|operand| operand.static_value().is_ok_and(is_remote_endpoint))
            })
    })
}

fn is_remote_endpoint(value: &str) -> bool {
    value.starts_with("rsync://")
        || value
            .split_once(':')
            .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'))
}

fn collect_ln_effects(args: &[ShellWord], cwd: Option<&str>, out: &mut EffectSet<FsEffect>) {
    match parse_operands("ln", args) {
        Ok((operands, target_directory)) => {
            if let Some(target) = target_directory {
                add_path_effect(&target, cwd, FsEffectKind::Write, out);
            } else if operands.len() >= 2 {
                if let Some(destination) = operands.last() {
                    add_path_effect(destination, cwd, FsEffectKind::Write, out);
                }
            } else {
                out.ambiguity("implicit-link-destination");
            }
        }
        Err(reason) => out.ambiguity(reason),
    }
}

fn collect_sed_effects(args: &[ShellWord], cwd: Option<&str>, out: &mut EffectSet<FsEffect>) {
    let mut i = 0;
    let mut in_place = false;
    let mut script_seen = false;
    let mut files = Vec::new();
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-sed-operand");
            return;
        };
        if arg == "--" {
            i += 1;
            break;
        }
        if arg == "-i"
            || arg == "--in-place"
            || (arg.starts_with("-i") && arg.len() > 2)
            || arg.starts_with("--in-place=")
        {
            in_place = true;
            i += 1;
            // BSD sed requires a separate extension after `-i`; the empty
            // spelling is unambiguous and is also harmless under GNU sed.
            if arg == "-i"
                && args
                    .get(i)
                    .and_then(|word| word.static_value().ok())
                    .is_some_and(str::is_empty)
            {
                i += 1;
            }
            continue;
        }
        if arg == "-I" {
            in_place = true;
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            i += 2;
            continue;
        }
        if matches!(arg, "-e" | "--expression") {
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            script_seen = true;
            i += 2;
            continue;
        }
        if (arg.starts_with("-e") && arg.len() > 2) || arg.starts_with("--expression=") {
            script_seen = true;
            i += 1;
            continue;
        }
        if matches!(arg, "-f" | "--file") {
            let Some(script) = args.get(i + 1) else {
                out.ambiguity("missing-option-value");
                return;
            };
            add_path_effect(script, cwd, FsEffectKind::Read, out);
            script_seen = true;
            i += 2;
            continue;
        }
        if let Some(script) = arg
            .strip_prefix("--file=")
            .or_else(|| arg.strip_prefix("-f").filter(|_| arg.len() > 2))
        {
            add_synthetic_path(script, cwd, FsEffectKind::Read, out);
            script_seen = true;
            i += 1;
            continue;
        }
        if matches!(arg, "-l" | "--line-length") {
            if args.get(i + 1).is_none() {
                out.ambiguity("missing-option-value");
                return;
            }
            i += 2;
            continue;
        }
        if arg.starts_with("--line-length=")
            || matches!(
                arg,
                "-n" | "--quiet"
                    | "--silent"
                    | "-E"
                    | "-r"
                    | "--regexp-extended"
                    | "-s"
                    | "--separate"
                    | "-u"
                    | "--unbuffered"
                    | "-z"
                    | "--null-data"
                    | "-a"
                    | "-b"
                    | "--sandbox"
                    | "--debug"
                    | "--posix"
                    | "--help"
                    | "--version"
            )
        {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            out.ambiguity("unknown-sed-option");
            return;
        }
        if !script_seen {
            script_seen = true;
        } else {
            files.push(&args[i]);
        }
        i += 1;
    }
    for arg in &args[i..] {
        if script_seen {
            files.push(arg);
        } else {
            script_seen = true;
        }
    }
    if in_place {
        if files.is_empty() {
            out.ambiguity("missing-sed-target");
        }
        for file in files {
            add_path_effect(file, cwd, FsEffectKind::Write, out);
        }
    }
}

fn collect_dd_effects(args: &[ShellWord], cwd: Option<&str>, out: &mut EffectSet<FsEffect>) {
    for arg in args {
        match arg.static_value() {
            Ok(value) => {
                if let Some(path) = value.strip_prefix("if=") {
                    add_synthetic_path(path, cwd, FsEffectKind::Read, out);
                } else if let Some(path) = value.strip_prefix("of=") {
                    add_synthetic_path(path, cwd, FsEffectKind::Write, out);
                }
            }
            Err(reason) => out.ambiguity(reason),
        }
    }
}

fn add_synthetic_path(
    path: &str,
    cwd: Option<&str>,
    kind: FsEffectKind,
    out: &mut EffectSet<FsEffect>,
) {
    let word = ShellWord {
        raw: path.to_string(),
        value: Some(path.to_string()),
        provenance: WordProvenance::default(),
        ambiguity: None,
    };
    add_path_effect(&word, cwd, kind, out);
}

/// Parse `gh pr merge` into a repository-and-PR-bound effect.
///
/// Repository context is accepted only when it is explicit in argv or carried
/// by a full pull-request URL. The analyzer deliberately does not consult the
/// process environment, Git remotes, the current directory, or the network.
pub(crate) fn gh_pr_merge_effects(analysis: &ShellAnalysis) -> EffectSet<GhPrMergeEffect> {
    let mut out = EffectSet::default();
    for command in &analysis.commands {
        if command.effective_head() == Ok("gh") {
            parse_gh_pr_merge(command.effective_args(), &mut out);
        }
    }
    out
}

fn parse_gh_pr_merge(args: &[ShellWord], out: &mut EffectSet<GhPrMergeEffect>) {
    let mut residual = Vec::with_capacity(args.len());
    let mut repository = None;
    let mut repository_error = None;
    let mut index = 0;

    while index < args.len() {
        let word = &args[index];
        match word.static_value() {
            Ok("-R" | "--repo") => {
                let Some(value) = args.get(index + 1) else {
                    repository_error = Some("missing-gh-pr-merge-repository");
                    index += 1;
                    continue;
                };
                match value.static_value() {
                    Ok(value) => merge_gh_repository(
                        &mut repository,
                        canonical_gh_repository(value),
                        &mut repository_error,
                    ),
                    Err(_) => repository_error = Some("dynamic-gh-pr-merge-repository"),
                }
                index += 2;
            }
            Ok(value) if value.starts_with("--repo=") => {
                let value = &value["--repo=".len()..];
                merge_gh_repository(
                    &mut repository,
                    canonical_gh_repository(value),
                    &mut repository_error,
                );
                index += 1;
            }
            Ok(value) if value.starts_with("-R") && value.len() > 2 => {
                merge_gh_repository(
                    &mut repository,
                    canonical_gh_repository(&value[2..]),
                    &mut repository_error,
                );
                index += 1;
            }
            Err(_)
                if word.raw.starts_with("--repo=")
                    || (word.raw.starts_with("-R") && word.raw.len() > 2) =>
            {
                repository_error = Some("dynamic-gh-pr-merge-repository");
                index += 1;
            }
            _ => {
                residual.push(word);
                index += 1;
            }
        }
    }

    let Some(pr_word) = residual.first() else {
        return;
    };
    match pr_word.static_value() {
        Ok("pr") => {}
        Err(_) if residual.get(1).and_then(|word| word.static_value().ok()) == Some("merge") => {
            out.ambiguity("dynamic-gh-command");
            return;
        }
        _ => return,
    }
    match residual.get(1).map(|word| word.static_value()) {
        Some(Ok("merge")) => {}
        Some(Err(_)) => {
            out.ambiguity("dynamic-gh-pr-command");
            return;
        }
        _ => return,
    }

    if let Some(reason) = repository_error {
        out.ambiguity(reason);
        return;
    }

    let mut admin = false;
    let mut target: Option<&ShellWord> = None;
    let mut index = 2;
    while index < residual.len() {
        let word = residual[index];
        match word.static_value() {
            Ok("--admin") => {
                admin = true;
                index += 1;
            }
            Ok(value) if value.starts_with("--admin=") => {
                match &value["--admin=".len()..] {
                    "true" => admin = true,
                    "false" => admin = false,
                    _ => {
                        out.ambiguity("invalid-gh-pr-merge-admin-value");
                        return;
                    }
                }
                index += 1;
            }
            Ok(
                "--auto" | "-d" | "--delete-branch" | "--disable-auto" | "-m" | "--merge" | "-r"
                | "--rebase" | "-s" | "--squash",
            ) => index += 1,
            Ok(value)
                if [
                    "--auto=",
                    "--delete-branch=",
                    "--disable-auto=",
                    "--merge=",
                    "--rebase=",
                    "--squash=",
                ]
                .iter()
                .any(|prefix| value.starts_with(prefix)) =>
            {
                let Some((_, boolean)) = value.split_once('=') else {
                    unreachable!("matched option prefix contains equals")
                };
                if !matches!(boolean, "true" | "false") {
                    out.ambiguity("invalid-gh-pr-merge-boolean-value");
                    return;
                }
                index += 1;
            }
            Ok(
                "-A"
                | "--author-email"
                | "-b"
                | "--body"
                | "-F"
                | "--body-file"
                | "--match-head-commit"
                | "-t"
                | "--subject",
            ) => {
                if residual.get(index + 1).is_none() {
                    out.ambiguity("missing-gh-pr-merge-option-value");
                    return;
                }
                index += 2;
            }
            Ok(value)
                if [
                    "--author-email=",
                    "--body=",
                    "--body-file=",
                    "--match-head-commit=",
                    "--subject=",
                ]
                .iter()
                .any(|prefix| value.starts_with(prefix)) =>
            {
                index += 1;
            }
            Ok(value)
                if ["-A", "-b", "-F", "-t"]
                    .iter()
                    .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len()) =>
            {
                index += 1;
            }
            Err(_)
                if [
                    "--author-email=",
                    "--body=",
                    "--body-file=",
                    "--match-head-commit=",
                    "--subject=",
                    "-A",
                    "-b",
                    "-F",
                    "-t",
                ]
                .iter()
                .any(|prefix| word.raw.starts_with(prefix) && word.raw.len() > prefix.len()) =>
            {
                index += 1;
            }
            Ok("--help") => return,
            Ok(value) if value.starts_with('-') => {
                out.ambiguity("unknown-gh-pr-merge-option");
                return;
            }
            Ok(_) | Err(_) => {
                if target.replace(word).is_some() {
                    out.ambiguity("multiple-gh-pr-merge-targets");
                    return;
                }
                index += 1;
            }
        }
    }

    let Some(target) = target else {
        out.ambiguity("missing-gh-pr-merge-target");
        return;
    };
    let Ok(target) = target.static_value() else {
        out.ambiguity("dynamic-gh-pr-merge-target");
        return;
    };
    let identity = match canonical_gh_pr_url(target) {
        Ok(Some((url_repository, number))) => {
            if repository
                .as_ref()
                .is_some_and(|selected| selected != &url_repository)
            {
                out.ambiguity("conflicting-gh-pr-merge-repository");
                return;
            }
            format!("{url_repository}#{number}")
        }
        Ok(None) => {
            let Some(number) = canonical_gh_pr_number(target) else {
                out.ambiguity("unsupported-gh-pr-merge-target");
                return;
            };
            let Some(repository) = repository else {
                out.ambiguity("missing-gh-pr-merge-repository");
                return;
            };
            format!("{repository}#{number}")
        }
        Err(reason) => {
            out.ambiguity(reason);
            return;
        }
    };

    out.push(GhPrMergeEffect::Merge(identity.clone()));
    if admin {
        out.push(GhPrMergeEffect::Admin(identity));
    }
}

fn merge_gh_repository(
    selected: &mut Option<String>,
    candidate: Result<String, Ambiguity>,
    error: &mut Option<Ambiguity>,
) {
    let Ok(candidate) = candidate else {
        *error = Some("invalid-gh-pr-merge-repository");
        return;
    };
    match selected {
        Some(existing) if existing != &candidate => {
            *error = Some("conflicting-gh-pr-merge-repository")
        }
        Some(_) => {}
        None => *selected = Some(candidate),
    }
}

fn canonical_gh_repository(value: &str) -> Result<String, Ambiguity> {
    let parts: Vec<&str> = value.split('/').collect();
    let (host, owner, repository) = match parts.as_slice() {
        [owner, repository] => ("github.com", *owner, *repository),
        [host, owner, repository] => (*host, *owner, *repository),
        _ => return Err("invalid-gh-pr-merge-repository"),
    };
    if !valid_gh_host(host)
        || !valid_gh_repository_component(owner)
        || !valid_gh_repository_component(repository)
    {
        return Err("invalid-gh-pr-merge-repository");
    }
    Ok(format!(
        "{}/{}/{}",
        host.to_ascii_lowercase(),
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase()
    ))
}

fn canonical_gh_pr_url(value: &str) -> Result<Option<(String, u64)>, Ambiguity> {
    let Some(rest) = value.strip_prefix("https://") else {
        return if value.contains("://") {
            Err("invalid-gh-pr-merge-url")
        } else {
            Ok(None)
        };
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let parts: Vec<&str> = rest.split('/').collect();
    let [host, owner, repository, "pull", number] = parts.as_slice() else {
        return Err("invalid-gh-pr-merge-url");
    };
    let repository = canonical_gh_repository(&format!("{host}/{owner}/{repository}"))?;
    let Some(number) = canonical_gh_pr_number(number) else {
        return Err("invalid-gh-pr-merge-url");
    };
    Ok(Some((repository, number)))
}

fn canonical_gh_pr_number(value: &str) -> Option<u64> {
    let number = value.parse::<u64>().ok()?;
    (number > 0).then_some(number)
}

fn valid_gh_host(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}

fn valid_gh_repository_component(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Parse Git push destination semantics from AST-backed argv.
pub(crate) fn git_push_effects(analysis: &ShellAnalysis) -> EffectSet<GitPushEffect> {
    let mut out = EffectSet::default();
    for command in &analysis.commands {
        let Ok(head) = command.effective_head() else {
            continue;
        };
        if head != "git" {
            continue;
        }
        let Some(push_args) = git_push_args(command.effective_args(), &mut out) else {
            continue;
        };
        parse_git_push(push_args, &mut out);
        out.push(GitPushEffect::Network);
    }
    out
}

fn git_push_args<'a>(
    args: &'a [ShellWord],
    out: &mut EffectSet<GitPushEffect>,
) -> Option<&'a [ShellWord]> {
    let mut i = 0;
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-git-subcommand");
            return None;
        };
        if arg == "push" {
            return Some(&args[i + 1..]);
        }
        if arg == "--" {
            return None;
        }
        if matches!(
            arg,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            let Some(value) = args.get(i + 1) else {
                out.ambiguity("missing-git-global-option-value");
                return None;
            };
            if value.static_value().is_err() {
                out.ambiguity("dynamic-git-global-option-value");
                return None;
            }
            i += 2;
        } else if arg.starts_with("--git-dir=")
            || arg.starts_with("--work-tree=")
            || arg.starts_with("--namespace=")
            || arg.starts_with("--config-env=")
            || matches!(
                arg,
                "--bare"
                    | "--no-pager"
                    | "--literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
            )
        {
            i += 1;
        } else if arg.starts_with('-') {
            out.ambiguity("unknown-git-global-option");
            return None;
        } else {
            return None;
        }
    }
    None
}

fn parse_git_push(args: &[ShellWord], out: &mut EffectSet<GitPushEffect>) {
    let mut positionals = Vec::new();
    let mut delete = false;
    let mut wide_all = false;
    let mut wide_tags = false;
    let mut follow_tags = false;
    let mut repository_from_option: Option<&ShellWord> = None;
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let Ok(arg) = args[i].static_value() else {
            out.ambiguity("dynamic-git-push-argument");
            return;
        };
        if options && arg == "--" {
            options = false;
            i += 1;
            continue;
        }
        if options && arg.starts_with('-') && arg != "-" {
            match arg {
                "-f" | "--force" => out.push(GitPushEffect::Force),
                "-d" | "--delete" => delete = true,
                "--all" => wide_all = true,
                "--tags" => wide_tags = true,
                "--follow-tags" => follow_tags = true,
                "--prune" => out.ambiguity("git-prune-destination"),
                "--mirror" => {
                    out.push(GitPushEffect::Force);
                    out.ambiguity("git-mirror-destination");
                }
                "--force-with-lease" | "--force-if-includes" => out.push(GitPushEffect::Force),
                "--repo" => {
                    let Some(repository) = args.get(i + 1) else {
                        out.ambiguity("missing-git-repository");
                        return;
                    };
                    repository_from_option = Some(repository);
                    i += 1;
                }
                "--receive-pack"
                | "--exec"
                | "-o"
                | "--push-option"
                | "--server-option"
                | "--recurse-submodules" => {
                    let Some(value) = args.get(i + 1) else {
                        out.ambiguity("missing-git-push-option-value");
                        return;
                    };
                    if value.static_value().is_err() {
                        out.ambiguity("dynamic-git-push-option-value");
                        return;
                    }
                    i += 1;
                }
                "-q" | "--quiet" | "-v" | "--verbose" | "-n" | "--dry-run" | "--porcelain"
                | "-u" | "--set-upstream" | "--atomic" | "--no-verify" | "--signed" => {}
                arg if arg.starts_with("--force-with-lease=") => out.push(GitPushEffect::Force),
                arg if arg.starts_with("--repo=") => {
                    let repository = arg.trim_start_matches("--repo=");
                    if repository.is_empty() {
                        out.ambiguity("missing-git-repository");
                        return;
                    }
                    repository_from_option = Some(&args[i]);
                }
                arg if arg.starts_with("--receive-pack=")
                    || arg.starts_with("--exec=")
                    || arg.starts_with("--push-option=")
                    || arg.starts_with("--server-option=")
                    || arg.starts_with("--recurse-submodules=")
                    || arg.starts_with("--signed=") => {}
                arg if arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..]
                        .chars()
                        .all(|flag| matches!(flag, 'f' | 'd' | 'q' | 'v' | 'n' | 'u')) =>
                {
                    if arg[1..].contains('f') {
                        out.push(GitPushEffect::Force);
                    }
                    if arg[1..].contains('d') {
                        delete = true;
                    }
                }
                _ => {
                    out.ambiguity("unknown-git-push-option");
                    return;
                }
            }
            i += 1;
            continue;
        }
        positionals.push(&args[i]);
        i += 1;
    }

    if wide_all {
        out.push(GitPushEffect::Destination("refs/heads/<all>".to_string()));
    }
    if wide_tags {
        out.push(GitPushEffect::Destination("refs/tags/<all>".to_string()));
    }
    if follow_tags {
        out.push(GitPushEffect::Destination(
            "refs/tags/<followed>".to_string(),
        ));
    }

    if let Some(repository) = repository_from_option {
        if repository.static_value().is_err() {
            out.ambiguity("dynamic-git-repository");
        }
    } else if let Some(repository) = positionals.first()
        && repository.static_value().is_err()
    {
        out.ambiguity("dynamic-git-repository");
    }

    // The first positional is the optional remote. With no positionals at all,
    // Git pushes the configured current branch.
    if positionals.is_empty() {
        if !wide_all && !wide_tags && !follow_tags {
            out.push(GitPushEffect::CurrentBranch);
        }
        return;
    }
    let refspecs = if repository_from_option.is_some() {
        positionals.as_slice()
    } else {
        &positionals[1..]
    };
    if refspecs.is_empty() {
        if !wide_all && !wide_tags && !follow_tags {
            out.push(GitPushEffect::CurrentBranch);
        }
        return;
    }

    let mut index = 0;
    while index < refspecs.len() {
        let Ok(spec) = refspecs[index].static_value() else {
            out.ambiguity("dynamic-git-refspec");
            index += 1;
            continue;
        };
        if spec == "tag" {
            if let Some(tag) = refspecs
                .get(index + 1)
                .and_then(|word| word.static_value().ok())
            {
                let destination = format!("refs/tags/{}", tag.trim_start_matches("refs/tags/"));
                if delete {
                    out.push(GitPushEffect::Delete(destination.clone()));
                }
                out.push(GitPushEffect::Destination(destination));
                index += 2;
                continue;
            }
            out.ambiguity("missing-tag-refspec");
            break;
        }
        parse_refspec(spec, delete, out);
        index += 1;
    }
}

fn parse_refspec(spec: &str, delete_option: bool, out: &mut EffectSet<GitPushEffect>) {
    let (forced, spec) = spec
        .strip_prefix('+')
        .map_or((false, spec), |stripped| (true, stripped));
    if forced {
        out.push(GitPushEffect::Force);
    }
    let (source, destination) = spec.split_once(':').map_or((spec, spec), |parts| parts);
    let deleting = delete_option || source.is_empty();
    let Some(destination) = canonical_git_destination(destination, source) else {
        out.ambiguity("ambiguous-git-destination");
        return;
    };
    if deleting {
        out.push(GitPushEffect::Delete(destination.clone()));
    }
    out.push(GitPushEffect::Destination(destination));
}

fn canonical_git_destination(destination: &str, source: &str) -> Option<String> {
    if destination.is_empty() {
        return None;
    }
    if destination.starts_with("refs/") {
        return Some(destination.to_string());
    }
    if destination.contains("..")
        || destination.contains(['~', '^', ':', '?', '*', '[', '\\'])
        || destination.ends_with('.')
        || destination.starts_with('.')
    {
        return None;
    }
    if matches!(destination, "HEAD" | "@") && destination == source {
        return None;
    }
    if source.starts_with("refs/") && destination == source {
        return None;
    }
    if source.starts_with("refs/tags/") {
        return Some(format!("refs/tags/{destination}"));
    }
    Some(format!("refs/heads/{destination}"))
}

/// Extract filesystem write targets through the same typed analysis used by
/// policy mapping. This adapter intentionally has no trusted cwd context.
pub fn shell_write_targets(command: &str) -> Vec<String> {
    filesystem_effects(&analyze(command), None)
        .effects
        .into_iter()
        .filter_map(|effect| (effect.kind == FsEffectKind::Write).then_some(effect.path))
        .collect()
}

pub(crate) fn head_basename(token: &str) -> &str {
    token.rsplit_once('/').map_or(
        token,
        |(_, base)| if base.is_empty() { token } else { base },
    )
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn argv(command: &str) -> Vec<Vec<String>> {
        analyze(command)
            .commands
            .iter()
            .filter_map(ShellCommand::static_argv)
            .collect()
    }

    #[test]
    fn parses_compounds_substitutions_and_static_shell_payloads() {
        let parsed = argv("echo $(touch a); command -- bash -c 'mkdir b && rm -rf /'");
        assert!(parsed.contains(&vec!["touch".into(), "a".into()]));
        assert!(!parsed.contains(&vec!["echo".into(), "$(touch a)".into()]));
        assert!(parsed.contains(&vec![
            "bash".into(),
            "-c".into(),
            "mkdir b && rm -rf /".into()
        ]));
        assert!(parsed.contains(&vec!["mkdir".into(), "b".into()]));
        assert!(parsed.contains(&vec!["rm".into(), "-rf".into(), "/".into()]));
    }

    #[test]
    fn recursively_unwraps_transparent_wrappers() {
        let analysis = analyze(
            "exec env X=1 sudo -- timeout 2 nohup nice -n 3 stdbuf -o0 setsid command -- /bin/rm -rf /",
        );
        let command = analysis.commands.first().unwrap();
        assert_eq!(command.effective_head(), Ok("rm"));
        assert_eq!(command.static_argv().unwrap(), ["/bin/rm", "-rf", "/"]);
    }

    #[test]
    fn command_query_is_not_unwrapped_as_execution() {
        let analysis = analyze("command -v rm");
        assert_eq!(analysis.commands[0].effective_head(), Ok("command"));
    }

    #[test]
    fn home_and_quote_provenance_are_distinct() {
        let expanded = analyze(r#"rm -rf "$HOME//.""#);
        let literal = analyze("rm -rf '$HOME'");
        assert!(
            expanded.commands[0].effective_args()[1]
                .provenance
                .home_alias
        );
        assert!(
            !literal.commands[0].effective_args()[1]
                .provenance
                .home_alias
        );
        assert_eq!(
            static_path(&expanded.commands[0].effective_args()[1], None),
            Ok("$HOME".into())
        );
        assert_eq!(
            static_path(&literal.commands[0].effective_args()[1], None),
            Ok("./$HOME".into())
        );
    }

    #[test]
    fn filesystem_effects_cover_all_operands_and_redirects() {
        let analysis = analyze("cp a b out && mv x y dest; cat one two < input > output");
        let effects = filesystem_effects(&analysis, Some("/repo//./"));
        let as_pairs: Vec<_> = effects
            .effects
            .iter()
            .map(|effect| (effect.kind, effect.path.as_str()))
            .collect();
        assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/a")));
        assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/b")));
        assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/out")));
        assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/x")));
        assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/y")));
        assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/dest")));
        assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/one")));
        assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/two")));
        assert!(as_pairs.contains(&(FsEffectKind::Read, "/repo/input")));
        assert!(as_pairs.contains(&(FsEffectKind::Write, "/repo/output")));
    }

    #[test]
    fn option_schemas_do_not_consume_files_as_option_values() {
        let analysis = analyze(
            "cat -A first second; rm --one-file-system old cache; cp -tdest one two; install -d nested; rsync --remove-source-files sync-source sync-dest",
        );
        let effects = filesystem_effects(&analysis, Some("/repo"));
        let as_pairs: Vec<_> = effects
            .effects
            .iter()
            .map(|effect| (effect.kind, effect.path.as_str()))
            .collect();
        for expected in [
            "/repo/first",
            "/repo/second",
            "/repo/one",
            "/repo/two",
            "/repo/sync-source",
        ] {
            assert!(
                as_pairs.contains(&(FsEffectKind::Read, expected)),
                "missing read {expected}: {as_pairs:?}"
            );
        }
        for expected in [
            "/repo/old",
            "/repo/cache",
            "/repo/dest",
            "/repo/nested",
            "/repo/sync-source",
            "/repo/sync-dest",
        ] {
            assert!(
                as_pairs.contains(&(FsEffectKind::Write, expected)),
                "missing write {expected}: {as_pairs:?}"
            );
        }
    }

    #[test]
    fn cwd_changing_and_split_string_wrappers_are_ambiguous() {
        for command in ["env -C /tmp touch x", "env -S 'touch x'"] {
            let analysis = analyze(command);
            assert!(!analysis.ambiguities.is_empty(), "{command}: {analysis:?}");
        }
    }

    #[test]
    fn static_shell_payload_after_value_options_is_collected() {
        let parsed = argv("bash -O extglob --noprofile -c 'touch payload'");
        assert!(parsed.contains(&vec!["touch".into(), "payload".into()]));
    }

    #[test]
    fn shell_write_targets_uses_typed_analysis() {
        assert_eq!(
            shell_write_targets("tee a b; cp x y dest; dd if=in of=out"),
            vec!["a", "b", "dest", "out"]
        );
        assert!(shell_write_targets("echo '> ignored'").is_empty());
    }

    #[test]
    fn git_push_destinations_are_typed() {
        let analysis = analyze(
            "/usr/bin/git -C repo push --force-with-lease origin HEAD:main feature/x:release/x refs/tags/v1",
        );
        let effects = git_push_effects(&analysis);
        assert!(effects.effects.contains(&GitPushEffect::Force));
        assert!(
            effects
                .effects
                .contains(&GitPushEffect::Destination("refs/heads/main".into()))
        );
        assert!(
            effects
                .effects
                .contains(&GitPushEffect::Destination("refs/heads/release/x".into()))
        );
        assert!(
            effects
                .effects
                .contains(&GitPushEffect::Destination("refs/tags/v1".into()))
        );
    }

    #[test]
    fn gh_pr_merge_identity_is_stable_across_supported_repo_positions() {
        let expected = GhPrMergeEffect::Merge("github.com/arakiss/galdr#79".into());
        for command in [
            "gh pr merge 79 --repo Arakiss/galdr",
            "gh pr --repo Arakiss/galdr merge 79",
            "gh -R Arakiss/galdr pr merge 79",
            "gh pr merge -RArakiss/galdr 79",
            "gh pr merge --repo=Arakiss/galdr 079",
            "gh pr merge https://github.com/Arakiss/galdr/pull/79",
        ] {
            let effects = gh_pr_merge_effects(&analyze(command));
            assert_eq!(effects.effects, [expected.clone()], "{command}");
            assert!(effects.ambiguities.is_empty(), "{command}: {effects:?}");
        }
    }

    #[test]
    fn gh_pr_merge_admin_boolean_is_not_presence_only() {
        let normal = gh_pr_merge_effects(&analyze(
            "gh pr merge 79 -R Arakiss/galdr --admin=false --squash",
        ));
        assert_eq!(
            normal.effects,
            [GhPrMergeEffect::Merge("github.com/arakiss/galdr#79".into())]
        );

        let admin = gh_pr_merge_effects(&analyze(
            "gh pr merge 79 -R Arakiss/galdr --admin=true --body \"$BODY\"",
        ));
        assert_eq!(
            admin.effects,
            [
                GhPrMergeEffect::Merge("github.com/arakiss/galdr#79".into()),
                GhPrMergeEffect::Admin("github.com/arakiss/galdr#79".into()),
            ]
        );
        assert!(admin.ambiguities.is_empty(), "{admin:?}");
    }

    #[test]
    fn gh_pr_merge_ambiguous_authority_never_emits_a_target() {
        for (command, reason) in [
            (
                "gh pr merge \"$PR\" --repo Arakiss/galdr",
                "dynamic-gh-pr-merge-target",
            ),
            (
                "gh pr merge 79 --repo \"$REPO\"",
                "dynamic-gh-pr-merge-repository",
            ),
            ("gh pr merge 79", "missing-gh-pr-merge-repository"),
            (
                "gh pr merge current-branch --repo Arakiss/galdr",
                "unsupported-gh-pr-merge-target",
            ),
            (
                "gh pr merge https://github.com/Arakiss/galdr/pull/79 -R Arakiss/gommage",
                "conflicting-gh-pr-merge-repository",
            ),
        ] {
            let effects = gh_pr_merge_effects(&analyze(command));
            assert!(effects.effects.is_empty(), "{command}: {effects:?}");
            assert_eq!(effects.ambiguities, [reason], "{command}: {effects:?}");
        }
    }

    #[test]
    fn git_delete_and_plus_refspecs_are_typed() {
        let delete = git_push_effects(&analyze("git push origin :main"));
        assert!(
            delete
                .effects
                .contains(&GitPushEffect::Delete("refs/heads/main".into()))
        );
        let forced = git_push_effects(&analyze("git push origin +main"));
        assert!(forced.effects.contains(&GitPushEffect::Force));
        assert!(
            forced
                .effects
                .contains(&GitPushEffect::Destination("refs/heads/main".into()))
        );
    }

    #[test]
    fn git_tags_and_dynamic_destinations_are_never_mislabeled() {
        let deleted_tag = git_push_effects(&analyze("git push --delete origin tag v1"));
        assert!(
            deleted_tag
                .effects
                .contains(&GitPushEffect::Delete("refs/tags/v1".into()))
        );
        assert!(
            deleted_tag
                .effects
                .contains(&GitPushEffect::Destination("refs/tags/v1".into()))
        );
        assert!(!deleted_tag.effects.iter().any(
            |effect| matches!(effect, GitPushEffect::Destination(path) if path.starts_with("refs/heads/"))
        ));

        let dynamic = git_push_effects(&analyze("git push \"$REMOTE\" HEAD:main"));
        assert!(dynamic.ambiguities.contains(&"dynamic-git-push-argument"));

        let unresolved_head = git_push_effects(&analyze("git push origin HEAD"));
        assert!(
            unresolved_head
                .ambiguities
                .contains(&"ambiguous-git-destination")
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_utf8_is_total(input in ".{0,4096}") {
            let analysis = analyze(&input);
            let _ = filesystem_effects(&analysis, Some("/repo"));
            let _ = git_push_effects(&analysis);
        }
    }
}
