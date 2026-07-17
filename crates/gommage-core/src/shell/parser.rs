use super::*;

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

pub(super) struct AnalysisState {
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
        for (index, command) in pipeline.seq.iter().enumerate() {
            let first_collected = self.analysis.commands.len();
            self.collect_command(command, depth);
            if index > 0
                && self.analysis.commands[first_collected..]
                    .iter()
                    .any(interpreter_reads_stdin_program)
            {
                self.analysis.ambiguity("shell-stdin-program");
            }
        }
    }

    fn collect_command(&mut self, command: &Command, depth: usize) {
        if !self.enter(depth) {
            return;
        }
        match command {
            Command::Simple(simple) => self.collect_simple(simple, depth),
            Command::Compound(compound, redirects) => {
                let first_collected = self.analysis.commands.len();
                self.collect_compound(compound, depth + 1);
                if let Some(redirects) = redirects {
                    if redirects.0.iter().any(redirect_supplies_stdin)
                        && self.analysis.commands[first_collected..]
                            .iter()
                            .any(interpreter_reads_stdin_program)
                    {
                        self.analysis.ambiguity("shell-stdin-program");
                    }
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
                // zsh extended-test expressions may perform assignments via
                // parameter expansion (`${name::=value}`). Until the full
                // expression AST is proven pure, treat the construct as
                // stateful rather than certifying commands that follow it.
                self.analysis.ambiguity("extended-test-command");
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
                // A shell `for` loop assigns its iteration variable before
                // every body execution. That mutation can redirect later
                // path and repository resolution (for example, `for HOME in
                // ...`), so the body cannot be certified in isolation.
                self.analysis.ambiguity("shell-environment-mutation");
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
                // Case selectors and patterns can contain stateful zsh
                // parameter expansion, including `${name::=value}`.
                self.analysis.ambiguity("case-command");
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
                self.analysis.ambiguity("shell-loop");
                self.collect_list(&command.0, depth + 1);
                self.collect_list(&command.1.list, depth + 1);
            }
            CompoundCommand::Coprocess(command) => {
                self.analysis.ambiguity("coprocess-command");
                self.collect_command(&command.body, depth + 1);
            }
        }
    }

    fn collect_simple(&mut self, command: &SimpleCommand, depth: usize) {
        if !self.enter(depth) || self.analysis.commands.len() >= MAX_COMMANDS {
            self.analysis.ambiguity("command-limit");
            return;
        }

        let mut words = Vec::new();
        let mut redirects = Vec::new();
        let executable_stdin_redirect = command
            .prefix
            .as_ref()
            .is_some_and(|prefix| items_supply_stdin(&prefix.0))
            || command
                .suffix
                .as_ref()
                .is_some_and(|suffix| items_supply_stdin(&suffix.0));
        let has_environment_assignment = command.prefix.as_ref().is_some_and(|prefix| {
            prefix
                .0
                .iter()
                .any(|item| matches!(item, CommandPrefixOrSuffixItem::AssignmentWord(_, _)))
        });
        if has_environment_assignment {
            self.analysis.ambiguity("shell-environment-mutation");
        }
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
            if !redirects.is_empty() || has_environment_assignment {
                self.analysis.commands.push(ShellCommand {
                    words: Vec::new(),
                    effective_words: Vec::new(),
                    redirections: redirects,
                });
            }
            return;
        }

        let effective_words = unwrap_words(&words, &mut self.analysis);
        if let Some(reason) = opaque_interpreter_program_ambiguity(&effective_words) {
            self.analysis.ambiguity(reason);
        }
        if executable_stdin_redirect && interpreter_words_read_stdin_program(&effective_words) {
            self.analysis.ambiguity("shell-stdin-program");
        }
        if let Some(executable) = effective_words
            .first()
            .and_then(|word| word.static_value().ok())
        {
            let basename = head_basename(executable);
            if privileged_executable_name(basename)
                && trusted_executable_basename(executable).is_err()
            {
                self.analysis.ambiguity("untrusted-executable-path");
            }
        }
        if effective_words
            .first()
            .is_some_and(|head| head.static_value().is_err())
        {
            self.analysis.ambiguity("dynamic-command");
        }
        if let Some(head) = effective_words
            .first()
            .and_then(|word| word.static_value().ok())
            .map(head_basename)
        {
            match head {
                "export" | "typeset" | "declare" | "set" | "unset" | "local" | "readonly" => {
                    self.analysis.ambiguity("shell-environment-mutation")
                }
                "source" | "." => self.analysis.ambiguity("shell-source-command"),
                "alias" | "unalias" | "hash" | "enable" => {
                    self.analysis.ambiguity("shell-command-resolution-mutation")
                }
                "eval" => self.analysis.ambiguity("eval-command"),
                "watch" => self.analysis.ambiguity("repeating-watch-command"),
                "xargs" => self.analysis.ambiguity("generated-xargs-command"),
                "find"
                    if effective_words.get(1..).is_some_and(|args| {
                        args.iter().any(|word| {
                            word.static_value().is_ok_and(|value| {
                                matches!(value, "-exec" | "-execdir" | "-ok" | "-okdir")
                            })
                        })
                    }) =>
                {
                    self.analysis.ambiguity("find-exec-command")
                }
                _ => {}
            }
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
                        | IoFileRedirectKind::DuplicateOutput => match word.static_value() {
                            Ok("-") => {}
                            Ok(value)
                                if value.chars().all(|character| character.is_ascii_digit()) => {}
                            Ok(_) => self.analysis.ambiguity("invalid-fd-redirect"),
                            Err(_) => self.analysis.ambiguity("dynamic-fd-redirect"),
                        },
                    }
                }
                IoFileRedirectTarget::ProcessSubstitution(_, subshell) => {
                    self.collect_list(&subshell.list, depth + 1)
                }
                IoFileRedirectTarget::Duplicate(word) => {
                    self.collect_word_substitutions(word, depth + 1);
                    let word = analyze_word(word, &self.options);
                    match word.static_value() {
                        Ok("-") => {}
                        Ok(value)
                            if value
                                .strip_suffix('-')
                                .unwrap_or(value)
                                .chars()
                                .all(|character| character.is_ascii_digit()) => {}
                        Ok(_) => self.analysis.ambiguity("invalid-fd-redirect"),
                        Err(_) => self.analysis.ambiguity("dynamic-fd-redirect"),
                    }
                }
                IoFileRedirectTarget::Fd(_) => {}
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
                    let word = analyze_word(&document.doc, &self.options);
                    if word.static_value().is_err() {
                        self.analysis
                            .ambiguity(word.ambiguity.unwrap_or("dynamic-here-document"));
                    }
                }
            }
            IoRedirect::HereString(_, word) => {
                self.collect_word_substitutions(word, depth + 1);
                let word = analyze_word(word, &self.options);
                if word.static_value().is_err() {
                    self.analysis
                        .ambiguity(word.ambiguity.unwrap_or("dynamic-here-string"));
                }
            }
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

pub(super) fn analyze_word(raw: &ast::Word, options: &ParserOptions) -> ShellWord {
    let mut provenance = WordProvenance::default();
    let mut value = String::new();
    let mut ambiguity = None;
    match word::parse(&raw.value, options) {
        Ok(pieces) => render_pieces(&pieces, false, &mut value, &mut provenance, &mut ambiguity),
        Err(_) => ambiguity = Some("word-parse-error"),
    }
    if word::parse_brace_expansions(&raw.value, options).is_ok_and(|parsed| {
        parsed.is_some_and(|parts| {
            parts
                .iter()
                .any(|part| matches!(part, word::BraceExpressionOrText::Expr(_)))
        })
    }) {
        ambiguity = Some("dynamic-brace-expansion");
    }
    ShellWord {
        raw: raw.value.clone(),
        value: ambiguity.is_none().then_some(value),
        provenance,
        ambiguity,
    }
}

pub(super) fn render_pieces(
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

pub(super) fn collect_substitutions(pieces: &[WordPieceWithSource], out: &mut Vec<String>) {
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
