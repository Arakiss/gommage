use super::*;
use proptest::prelude::*;

fn argv(command: &str) -> Vec<Vec<String>> {
    analyze(command)
        .commands
        .iter()
        .filter_map(ShellCommand::static_argv)
        .collect()
}

mod parsing;
mod security;
