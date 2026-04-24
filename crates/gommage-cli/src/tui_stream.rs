use anyhow::Result;
use gommage_audit::{AuditStreamItem, recent_stream_items};
use gommage_core::runtime::HomeLayout;
use serde::Deserialize;
use std::{
    io::{self, BufRead, BufReader, Write},
    thread,
    time::Duration,
};

use crate::operator_metrics::build_operator_telemetry;

pub(crate) fn print_stream(
    layout: &HomeLayout,
    refresh: Duration,
    ticks: Option<u32>,
    limit: usize,
) -> Result<()> {
    let refresh = refresh.clamp(Duration::from_millis(250), Duration::from_millis(10_000));
    let limit = limit.clamp(1, 100);
    let frame_limit = ticks.unwrap_or(u32::MAX);
    let mut stdout = io::stdout();
    for frame in 0..frame_limit {
        if frame > 0 {
            thread::sleep(refresh);
            writeln!(stdout)?;
        }
        let snapshot = load_stream_snapshot(layout, limit);
        writeln!(
            stdout,
            "--- gommage tui stream frame {} at {} ---",
            frame + 1,
            time::OffsetDateTime::now_utc()
        )?;
        writeln!(stdout, "Gommage live decision stream")?;
        writeln!(stdout, "home: {}", layout.root.display())?;
        writeln!(stdout, "source: {}", snapshot.source)?;
        let telemetry = build_operator_telemetry(layout);
        for line in telemetry.snapshot_lines() {
            writeln!(stdout, "{line}")?;
        }
        writeln!(stdout, "events:")?;
        if snapshot.items.is_empty() {
            writeln!(stdout, "- no recent audit entries")?;
        } else {
            for item in snapshot.items {
                writeln!(
                    stdout,
                    "- line {} {} [{}] {} - {}",
                    item.line, item.ts, item.kind, item.summary, item.detail
                )?;
            }
        }
        writeln!(stdout, "next:")?;
        writeln!(stdout, "1. gommage audit-verify --explain")?;
        writeln!(
            stdout,
            "2. gommage tui --stream --stream-ticks {}",
            frame_limit.min(5)
        )?;
        stdout.flush()?;
    }
    Ok(())
}

struct StreamSnapshot {
    source: &'static str,
    items: Vec<AuditStreamItem>,
}

fn load_stream_snapshot(layout: &HomeLayout, limit: usize) -> StreamSnapshot {
    if let Some(items) = daemon_recent_audit(layout, limit) {
        return StreamSnapshot {
            source: "daemon-ipc",
            items,
        };
    }
    StreamSnapshot {
        source: "audit-log",
        items: recent_stream_items(&layout.audit_log, limit).unwrap_or_default(),
    }
}

#[cfg(unix)]
fn daemon_recent_audit(layout: &HomeLayout, limit: usize) -> Option<Vec<AuditStreamItem>> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&layout.socket).ok()?;
    let timeout = Some(Duration::from_millis(500));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;
    let request = serde_json::json!({"op": "recent_audit", "limit": limit});
    writeln!(stream, "{}", serde_json::to_string(&request).ok()?).ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    let response: DaemonResponse<Vec<AuditStreamItem>> = serde_json::from_str(&line).ok()?;
    if response.ok { response.result } else { None }
}

#[cfg(not(unix))]
fn daemon_recent_audit(_layout: &HomeLayout, _limit: usize) -> Option<Vec<AuditStreamItem>> {
    None
}

#[derive(Debug, Deserialize)]
struct DaemonResponse<T> {
    ok: bool,
    result: Option<T>,
}
