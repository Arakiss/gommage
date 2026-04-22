use anyhow::{Context, Result};
use gommage_core::{Capability, ToolCall, runtime::HomeLayout};
use serde::Serialize;
use std::process::ExitCode;

use crate::{input::read_tool_call_from_stdin, util::path_display};

#[derive(Debug, Serialize)]
struct MapReport {
    input_hash: String,
    tool: String,
    capabilities_dir: String,
    mapper_rules: usize,
    capabilities: Vec<Capability>,
}

fn build_map_report(layout: &HomeLayout, call: ToolCall) -> Result<MapReport> {
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers")?;
    let capabilities = mapper.map(&call);
    Ok(MapReport {
        input_hash: call.input_hash(),
        tool: call.tool,
        capabilities_dir: path_display(&layout.capabilities_dir),
        mapper_rules: mapper.rule_count(),
        capabilities,
    })
}

pub(crate) fn cmd_map(layout: HomeLayout, json: bool, hook: bool) -> Result<ExitCode> {
    let call = read_tool_call_from_stdin(hook)?;
    let report = build_map_report(&layout, call)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_map_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_map_report(report: &MapReport) {
    println!("input_hash: {}", report.input_hash);
    println!("tool: {}", report.tool);
    println!("capabilities_dir: {}", report.capabilities_dir);
    println!("mapper_rules: {}", report.mapper_rules);
    if report.capabilities.is_empty() {
        println!("capabilities: none");
    } else {
        println!("capabilities:");
        for capability in &report.capabilities {
            println!("- {capability}");
        }
    }
}
