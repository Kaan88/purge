//! `xtask broker-timings`: the broker's timing lines of a run turned into the numbers of gate G12
//! (M3_DESIGN.md §9.1, §12; the lines are `purge_rpc::timing::TimingLine`, collected from the Application
//! log by `vm/guest/broker-timings.ps1`).
//!
//! ```text
//! cargo xtask broker-timings <file.jsonl | dir>... [--out <file.json>]
//! ```
//!
//! A directory is searched (not recursively) for `*.jsonl`. Every line that is not a timing line is
//! skipped; text before the first `{` of a line is ignored (an exported event text). Lines are grouped
//! by broker process (pid and creation time), then by request. The output (`purge.broker-timings/1`, to
//! `--out` or stdout) has, per broker:
//!
//! | Field | Metric (design 9.1) | Gate |
//! |---|---|---|
//! | `harvests[].after_uac_ms` | `harvest_complete` of `uninstall.prepare`, ms since the broker process was created: the UAC click starts the process, so this is "harvest complete after the UAC click" (start checks, the client's connect and hello, and the harvest) | for VS Code: 2x the walk floor of the same run (the scorer, with `walk-floor.json`), and 20,000 (`within_cap`) |
//! | `harvests[].duration_ms` | `harvest_complete` - `harvest_start` | reported |
//! | `scans[].duration_ms` | `scan_complete` - `scan_start` of `leftovers.scan`; `cold` is the broker's first scan | 10,000 cold |
//! | `scans[].first_progress_ms` | `first_progress` - `scan_start`: the first `scan.progress` line was written | 100 |
//! | `pipe_connected_ms` | client checked and hello answered, ms since creation | reported |
//! | `executes[]` | consent shown to answered (the user's time), executor start to complete | reported |
//!
//! `within_gate` is set for the metrics that have an absolute gate, `within_cap` for a harvest (its gate
//! is relative to the walk floor, `purge-engine walk-floor`, which this command does not read; the cap is
//! the absolute part); which run is the VS Code one, and whether a scan is a post-uninstall scan of a cold
//! broker, the scorer knows. `problems` lists marks that go back in
//! time within a request, a complete mark without its start, and lines that are not readable.
//! The command fails only when an input cannot be read or no timing line is found.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use purge_rpc::timing::{TIMING_LINE_KIND, TimingLine, TimingName};
use serde_json::{Value, json};

/// The output schema id.
pub const SCHEMA: &str = "purge.broker-timings/1";
/// Gate: harvest complete after the UAC click (VS Code), the absolute sanity cap, ms. The gate itself
/// is [`HARVEST_FLOOR_FACTOR`] times the walk floor of the same run (M3_DESIGN.md §9.1).
pub const HARVEST_CAP_MS: u64 = 20_000;
/// Gate: harvest complete after the UAC click, as a multiple of the walk floor measured on the same
/// machine in the same run (`purge-engine walk-floor`); judged by the scorer.
pub const HARVEST_FLOOR_FACTOR: u64 = 2;
/// Gate: post-uninstall scan, cold broker, ms.
pub const SCAN_GATE_MS: u64 = 10_000;
/// Gate: first progress of the scan, ms.
pub const FIRST_PROGRESS_GATE_MS: u64 = 100;

pub fn run(args: &[String]) -> Result<bool> {
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out" => out = Some(it.next().context("--out needs a file")?.into()),
            other if other.starts_with("--") => bail!("broker-timings: unknown argument {other}"),
            other => inputs.push(other.into()),
        }
    }
    if inputs.is_empty() {
        bail!("usage: cargo xtask broker-timings <file.jsonl | dir>... [--out <file.json>]");
    }
    let mut files = Vec::new();
    for input in &inputs {
        if input.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(input)
                .with_context(|| format!("reading {}", input.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect();
            found.sort();
            files.extend(found);
        } else {
            files.push(input.clone());
        }
    }
    let mut texts = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        texts.push((file.display().to_string(), text));
    }
    let report = summarize(&texts);
    if report["brokers"].as_array().is_none_or(Vec::is_empty) {
        bail!("broker-timings: no timing line in {} file(s)", files.len());
    }
    let text = serde_json::to_string_pretty(&report)? + "\n";
    match out {
        Some(path) => {
            std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
            println!("broker-timings: {}", path.display());
        }
        None => print!("{text}"),
    }
    Ok(true)
}

/// One request's marks, in the order they were read.
#[derive(Default)]
struct Request {
    method: Option<String>,
    marks: Vec<(TimingName, u64)>,
}

impl Request {
    fn at(&self, name: TimingName) -> Option<u64> {
        self.marks
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, ms)| *ms)
    }
}

#[derive(Default)]
struct Broker {
    process: Vec<(TimingName, u64)>,
    requests: BTreeMap<u64, Request>,
}

/// Reads one line: the JSON object from its first `{`, if it is a timing line.
fn parse_line(line: &str) -> Option<Result<TimingLine, String>> {
    let start = line.find('{')?;
    let text = &line[start..];
    let value: Value = serde_json::from_str(text).ok()?;
    if value.get("kind").and_then(Value::as_str) != Some(TIMING_LINE_KIND) {
        return None;
    }
    Some(serde_json::from_value(value).map_err(|e| e.to_string()))
}

/// The report over the given (name, text) inputs.
pub fn summarize(inputs: &[(String, String)]) -> Value {
    let mut problems: Vec<String> = Vec::new();
    let mut brokers: BTreeMap<(u32, Option<u64>), Broker> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for (name, text) in inputs {
        for (number, line) in text.lines().enumerate() {
            let parsed = match parse_line(line) {
                None => continue,
                Some(Err(why)) => {
                    problems.push(format!("{name}:{}: not a timing line: {why}", number + 1));
                    continue;
                }
                Some(Ok(parsed)) => parsed,
            };
            // The same line collected twice (overlapping exports) counts once.
            let key = (
                parsed.pid,
                parsed.process_created_unix_ms,
                parsed.request.map(|r| r.0),
                parsed.mark.mark,
            );
            if !seen.insert(key) {
                continue;
            }
            let broker = brokers
                .entry((parsed.pid, parsed.process_created_unix_ms))
                .or_default();
            match parsed.request {
                None => broker.process.push((parsed.mark.mark, parsed.mark.ms)),
                Some(request) => {
                    let entry = broker.requests.entry(request.0).or_default();
                    if entry.method.is_none() {
                        entry.method = parsed.method.clone();
                    }
                    entry.marks.push((parsed.mark.mark, parsed.mark.ms));
                }
            }
        }
    }
    let brokers: Vec<Value> = brokers
        .into_iter()
        .map(|((pid, created), broker)| broker_report(pid, created, &broker, &mut problems))
        .collect();
    json!({
        "schema": SCHEMA,
        "gates": {
            "harvest_floor_factor": HARVEST_FLOOR_FACTOR,
            "harvest_cap_ms": HARVEST_CAP_MS,
            "scan_ms": SCAN_GATE_MS,
            "first_progress_ms": FIRST_PROGRESS_GATE_MS,
        },
        "sources": inputs.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>(),
        "brokers": brokers,
        "problems": problems,
    })
}

fn names(marks: &[(TimingName, u64)]) -> Value {
    Value::Array(
        marks
            .iter()
            .map(|(name, ms)| json!({ "mark": name, "ms": ms }))
            .collect(),
    )
}

fn broker_report(
    pid: u32,
    created: Option<u64>,
    broker: &Broker,
    problems: &mut Vec<String>,
) -> Value {
    let process_at = |name| {
        broker
            .process
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, ms)| *ms)
    };
    let mut harvests = Vec::new();
    let mut scans = Vec::new();
    let mut plans = Vec::new();
    let mut executes = Vec::new();
    let mut cold = true;
    for (id, request) in &broker.requests {
        if request.marks.windows(2).any(|w| w[1].1 < w[0].1) {
            problems.push(format!(
                "broker {pid}: request {id}: the marks go back: {:?}",
                request.marks
            ));
        }
        let mut span = |start: TimingName, end: TimingName| {
            let (s, e) = (request.at(start), request.at(end));
            if e.is_some() && s.is_none() {
                problems.push(format!(
                    "broker {pid}: request {id}: {end:?} without {start:?}"
                ));
            }
            s.zip(e).map(|(s, e)| e.saturating_sub(s))
        };
        let method = request.method.clone().unwrap_or_default();
        if let Some(start) = request.at(TimingName::HarvestStart) {
            let complete = request.at(TimingName::HarvestComplete);
            harvests.push(json!({
                "request": id,
                "method": method,
                "start_ms": start,
                "complete_ms": complete,
                "after_uac_ms": complete,
                "duration_ms": span(TimingName::HarvestStart, TimingName::HarvestComplete),
                "within_cap": complete.map(|ms| ms <= HARVEST_CAP_MS),
            }));
        } else if request.at(TimingName::HarvestComplete).is_some() {
            span(TimingName::HarvestStart, TimingName::HarvestComplete);
        }
        if let Some(start) = request.at(TimingName::ScanStart) {
            let duration = span(TimingName::ScanStart, TimingName::ScanComplete);
            let first = request
                .at(TimingName::FirstProgress)
                .map(|ms| ms.saturating_sub(start));
            scans.push(json!({
                "request": id,
                "method": method,
                "cold": cold,
                "start_ms": start,
                "complete_ms": request.at(TimingName::ScanComplete),
                "duration_ms": duration,
                "first_progress_ms": first,
                "within_gate": duration.map(|d| d <= SCAN_GATE_MS),
                "first_progress_within_gate": first.map(|f| f <= FIRST_PROGRESS_GATE_MS),
            }));
            cold = false;
        } else if request.at(TimingName::ScanComplete).is_some() {
            span(TimingName::ScanStart, TimingName::ScanComplete);
        }
        if let Some(ready) = request.at(TimingName::PlanReady) {
            plans.push(json!({ "request": id, "ready_ms": ready }));
        }
        if request.at(TimingName::ExecuteStart).is_some()
            || request.at(TimingName::ConsentShown).is_some()
            || request.at(TimingName::ExecuteComplete).is_some()
        {
            executes.push(json!({
                "request": id,
                "method": method,
                "consent_shown_ms": request.at(TimingName::ConsentShown),
                "consent_answered_ms": request.at(TimingName::ConsentAnswered),
                "consent_wait_ms": span(TimingName::ConsentShown, TimingName::ConsentAnswered),
                "start_ms": request.at(TimingName::ExecuteStart),
                "complete_ms": request.at(TimingName::ExecuteComplete),
                "duration_ms": span(TimingName::ExecuteStart, TimingName::ExecuteComplete),
            }));
        }
    }
    let requests: BTreeMap<String, Value> = broker
        .requests
        .iter()
        .map(|(id, r)| {
            (
                id.to_string(),
                json!({ "method": r.method, "marks": names(&r.marks) }),
            )
        })
        .collect();
    json!({
        "pid": pid,
        "process_created_unix_ms": created,
        "broker_start_ms": process_at(TimingName::BrokerStart),
        "pipe_connected_ms": process_at(TimingName::PipeConnected),
        "harvests": harvests,
        "scans": scans,
        "plans": plans,
        "executes": executes,
        "process_marks": names(&broker.process),
        "requests": requests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(pid: u32, request: Option<(u64, &str)>, mark: &str, ms: u64) -> String {
        let mut v = json!({
            "kind": TIMING_LINE_KIND, "pid": pid, "process_created_unix_ms": 1_000,
            "mark": mark, "ms": ms, "wall_unix_ms": 1_000 + ms,
        });
        if let Some((id, method)) = request {
            v["request"] = json!(id);
            v["method"] = json!(method);
        }
        v.to_string()
    }

    fn flow(pid: u32, scan_ms: u64, first_ms: u64) -> String {
        [
            line(pid, None, "broker_start", 40),
            line(pid, None, "pipe_connected", 300),
            line(pid, Some((2, "uninstall.prepare")), "harvest_start", 320),
            line(pid, Some((2, "uninstall.prepare")), "first_progress", 330),
            line(
                pid,
                Some((2, "uninstall.prepare")),
                "harvest_complete",
                2_100,
            ),
            line(pid, Some((5, "leftovers.scan")), "scan_start", 9_000),
            line(
                pid,
                Some((5, "leftovers.scan")),
                "first_progress",
                9_000 + first_ms,
            ),
            line(
                pid,
                Some((5, "leftovers.scan")),
                "scan_complete",
                9_000 + scan_ms,
            ),
            line(pid, Some((6, "leftovers.scan")), "scan_start", 30_000),
            line(pid, Some((6, "leftovers.scan")), "scan_complete", 31_000),
            line(pid, Some((7, "plan.create")), "plan_ready", 31_500),
            line(pid, Some((8, "plan.execute")), "consent_shown", 32_000),
            line(pid, Some((8, "plan.execute")), "consent_answered", 35_000),
            line(pid, Some((8, "plan.execute")), "execute_start", 35_001),
            line(pid, Some((8, "plan.execute")), "execute_complete", 36_000),
        ]
        .join("\n")
    }

    #[test]
    fn the_gate_numbers_come_from_the_marks() {
        let text = format!(
            "noise line\nInformation 100 Purge {}\n",
            flow(11, 4_000, 12)
        );
        let report = summarize(&[("a.jsonl".into(), text)]);
        assert_eq!(report["schema"], SCHEMA);
        assert_eq!(report["problems"], json!([]));
        let b = &report["brokers"][0];
        assert_eq!(b["pid"], 11);
        assert_eq!(b["pipe_connected_ms"], 300);
        assert_eq!(b["harvests"][0]["after_uac_ms"], 2_100);
        assert_eq!(b["harvests"][0]["duration_ms"], 1_780);
        assert_eq!(b["harvests"][0]["within_cap"], true);
        assert_eq!(b["harvests"][0]["within_gate"], Value::Null);
        assert_eq!(report["gates"]["harvest_floor_factor"], 2);
        assert_eq!(report["gates"]["harvest_cap_ms"], 20_000);
        assert_eq!(b["scans"][0]["cold"], true);
        assert_eq!(b["scans"][0]["duration_ms"], 4_000);
        assert_eq!(b["scans"][0]["first_progress_ms"], 12);
        assert_eq!(b["scans"][0]["first_progress_within_gate"], true);
        assert_eq!(b["scans"][1]["cold"], false);
        assert_eq!(b["scans"][1]["first_progress_ms"], Value::Null);
        assert_eq!(b["plans"][0]["ready_ms"], 31_500);
        assert_eq!(b["executes"][0]["consent_wait_ms"], 3_000);
        assert_eq!(b["executes"][0]["duration_ms"], 999);
    }

    #[test]
    fn brokers_are_kept_apart_duplicates_count_once_and_breaches_show() {
        let one = flow(11, 4_000, 12);
        let two = flow(12, 12_000, 150);
        let report = summarize(&[
            ("a.jsonl".into(), one.clone()),
            ("b.jsonl".into(), format!("{one}\n{two}")),
        ]);
        let brokers = report["brokers"].as_array().unwrap();
        assert_eq!(brokers.len(), 2);
        assert_eq!(
            brokers[0]["requests"]["5"]["marks"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(brokers[1]["scans"][0]["within_gate"], false);
        assert_eq!(brokers[1]["scans"][0]["first_progress_within_gate"], false);
    }

    #[test]
    fn marks_out_of_order_or_without_a_start_are_problems() {
        let text = [
            line(3, Some((2, "uninstall.prepare")), "harvest_start", 500),
            line(3, Some((2, "uninstall.prepare")), "harvest_complete", 400),
            line(3, Some((4, "leftovers.scan")), "scan_complete", 900),
            format!(
                "{{\"kind\":\"{TIMING_LINE_KIND}\",\"pid\":3,\"mark\":\"later_mark\",\"ms\":1,\"wall_unix_ms\":1}}"
            ),
        ]
        .join("\n");
        let report = summarize(&[("c.jsonl".into(), text)]);
        let problems: Vec<String> = report["problems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("not a timing line"), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("go back")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("ScanComplete without ScanStart")),
            "{problems:?}"
        );
    }
}
