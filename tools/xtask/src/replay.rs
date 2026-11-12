//! `replay` and `replay-all`: the engine pipeline run offline over a frozen rig run (vm/RIG.md §2, §3).
//!
//! A rig run directory holds `run.json`, the snapshots `snap-<run>-<phase>.tsv.gz` and their lists
//! `lists-<run>-<phase>.json` (phase 1 = installed and used, phase 2 = after the uninstaller). The replay:
//!
//! 1. builds `Fixture::from_snap` for phase 1 and phase 2 (with their lists, and an optional overlay of
//!    file contents in the drive-letter layout `<overlay>\C\Program Files\…`);
//! 2. finds the app's inventory entry at phase 1 from `run.json` `main.key` and harvests it there;
//! 3. stands in for the uninstall step: the window is `run.json` `uninstall.t0`/`t1`, verify-gone is
//!    checked against the phase-2 fixture, and the co-removed products are the harvest's co-product
//!    candidates whose Uninstall key is absent at phase 2;
//! 4. scans the phase-2 fixture in `post` mode and writes the `purge.plan/0` document.
//!
//! What a snapshot cannot give limits the result (printed with every replay): file contents, version
//! resources and signers are unknown unless overlaid (so no Inno log without `unins000.dat` in the
//! overlay), REG_BINARY and other non-string data are unknown, and string previews are cut at 1024
//! characters.
//!
//! `replay-all` replays the frozen M0 runs [`M0_RUNS`] into `vm/runs/<id>/plans/purge-replay.json` (the
//! runs directory is git-ignored; the plan is a new file next to the other tools' plans) and then, when
//! `vm/rigtool/target/release/rigtool(.exe)` exists, prints `rigtool score --set …` over them.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use purge_engine::cli::output;
use purge_engine::pipeline::{self, Settings, Sources};
use purge_guard::prefix;
use purge_harvest::coproducts;
use purge_identity::kbdata::Kb;
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{Band, FileTime, InventoryEntry, ScanMode};
use purge_source::fixture::Fixture;
use purge_source::snapfixture::parse_iso8601;
use serde::Deserialize;

/// The frozen M0 runs `replay-all` replays (directory name = truth id).
pub const M0_RUNS: &[&str] = &["vscode", "git", "firefox", "npp"];

/// The plan file `replay-all` writes inside each run's `plans` directory.
pub const REPLAY_PLAN: &str = "purge-replay.json";

/// The environment variable naming the runs directory (also used by the ignored test).
pub const RUNS_DIR_VAR: &str = "PURGE_RUNS_DIR";

const REPLAY_USAGE: &str = "usage: cargo xtask replay --run <vm/runs/<id>> --app <truth id> -o <plan.json> \
                            [--overlay <dir>] [--baselines <dir>]";
const REPLAY_ALL_USAGE: &str = "usage: cargo xtask replay-all [--runs <vm/runs>] [--overlay-root <dir>] [--if-present] [--no-score]";

// ---------------------------------------------------------------------------------------------------------
// run.json
// ---------------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RunJson {
    id: Option<String>,
    run: Option<String>,
    user_sid: Option<String>,
    sid: Option<String>,
    main: Option<RunMain>,
    uninstall: Option<RunUninstall>,
}

#[derive(Debug, Deserialize)]
struct RunMain {
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RunUninstall {
    t0: Option<String>,
    t1: Option<String>,
}

/// What the replay needs from `run.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInfo {
    /// The run name used in the snapshot file names (`snap-<run>-<phase>.tsv.gz`).
    pub run: String,
    /// The app's Uninstall key, with `HKCU\` resolved to `HKU\<user SID>\`.
    pub main_key: String,
    /// Start of the uninstall window.
    pub t_start: FileTime,
    /// End of the uninstall window.
    pub t_end: FileTime,
}

/// Parses a rig `run.json` (`purge.rig.run/1`; a leading byte-order mark is accepted, as PowerShell
/// writes one).
pub fn parse_run_json(text: &str) -> Result<RunInfo> {
    let doc: RunJson = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .context("run.json is not valid JSON of the expected shape")?;
    let run = doc
        .run
        .or(doc.id)
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| anyhow!("run.json has neither `run` nor `id`"))?;
    let key = doc
        .main
        .and_then(|m| m.key)
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| anyhow!("run.json has no `main.key` (no app entry was recorded)"))?;
    let main_key = match prefix::strip_prefix(&key, "HKCU") {
        Some(rest) => {
            let sid = doc
                .user_sid
                .or(doc.sid)
                .ok_or_else(|| anyhow!("run.json `main.key` is under HKCU but no `user_sid`"))?;
            format!(r"HKU\{sid}\{}", rest.trim_start_matches('\\'))
        }
        None => key,
    };
    let un = doc
        .uninstall
        .ok_or_else(|| anyhow!("run.json has no `uninstall` section"))?;
    let time = |name: &str, v: Option<String>| -> Result<FileTime> {
        let s = v.ok_or_else(|| anyhow!("run.json has no `uninstall.{name}`"))?;
        parse_iso8601(&s)
            .ok_or_else(|| anyhow!("run.json `uninstall.{name}` {s:?} is not ISO 8601"))
    };
    let t_start = time("t0", un.t0)?;
    let t_end = time("t1", un.t1)?;
    if t_end < t_start {
        bail!("run.json `uninstall.t1` is before `uninstall.t0`");
    }
    Ok(RunInfo {
        run,
        main_key,
        t_start,
        t_end,
    })
}

// ---------------------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------------------

/// One replay's inputs.
#[derive(Debug, Clone)]
pub struct ReplayOpts {
    /// The rig run directory (`vm/runs/<id>`).
    pub run_dir: PathBuf,
    /// The plan's `app` field (the truth id).
    pub app: String,
    /// Where the plan is written.
    pub out: PathBuf,
    /// Overlay of file contents in the drive-letter layout, if any.
    pub overlay: Option<PathBuf>,
    /// The baseline directory (`kb/baselines`).
    pub baselines: Option<PathBuf>,
}

/// A replay's result, for the summary.
#[derive(Debug, Clone)]
pub struct Replayed {
    /// The plan as written.
    pub plan: purge_model::Plan,
    /// Pipeline and harvest warnings.
    pub warnings: Vec<String>,
    /// One line per limit of the snapshot data.
    pub limits: Vec<String>,
    /// Whether verify-gone passed at phase 2.
    pub verify_passed: bool,
    /// Co-removed products recorded.
    pub co_removed: usize,
}

fn load_phase(dir: &Path, run: &str, phase: u32, overlay: Option<&Path>) -> Result<Fixture> {
    let snap = dir.join(format!("snap-{run}-{phase}.tsv.gz"));
    let lists = dir.join(format!("lists-{run}-{phase}.json"));
    if !snap.is_file() {
        bail!("{} is missing", snap.display());
    }
    eprintln!("replay: loading {}", snap.display());
    Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), overlay)
        .map_err(|e| anyhow!("cannot load {}: {e}", snap.display()))
}

/// The inventory entry of `key` at phase 1: the same Uninstall key, else the only entry with its key name.
fn entry_for<'d>(entries: &'d [InventoryEntry], key: &str) -> Result<&'d InventoryEntry> {
    if let Some(e) = entries.iter().find(|e| prefix::is_same(&e.key_path, key)) {
        return Ok(e);
    }
    let name = key.rsplit('\\').next().unwrap_or(key);
    let hits: Vec<&InventoryEntry> = entries
        .iter()
        .filter(|e| e.program_id.key_name().eq_ignore_ascii_case(name))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => bail!("no inventory entry at phase 1 has the Uninstall key {key}"),
        _ => bail!("{} phase-1 entries have the key name {name:?}", hits.len()),
    }
}

fn limits(before: &Fixture, after: &Fixture, overlay: Option<&Path>) -> Vec<String> {
    let mut out = vec![match overlay {
        Some(o) => format!(
            "file contents, version info and signers come only from the overlay {} (no Inno log unless \
             unins000.dat is in it)",
            o.display()
        ),
        None => {
            "no overlay: file contents, version info and signers are unknown (no Inno log)".into()
        }
    }];
    for (phase, f) in [(1, before), (2, after)] {
        if let Some(st) = f.snap_stats() {
            out.push(format!(
                "phase {phase}: {} keys, {} values ({} with unknown data such as REG_BINARY, {} previews \
                 cut at 1024 characters), {} dirs, {} files, {} denied, {} errors",
                st.keys,
                st.values,
                st.unknown_values,
                st.truncated_values,
                st.dirs,
                st.files,
                st.denied,
                st.errors
            ));
        }
    }
    out
}

/// Replays one rig run and writes its plan.
pub fn replay(opts: &ReplayOpts) -> Result<Replayed> {
    let run_json = opts.run_dir.join("run.json");
    let text = std::fs::read_to_string(&run_json)
        .with_context(|| format!("reading {}", run_json.display()))?;
    let info = parse_run_json(&text).with_context(|| format!("in {}", run_json.display()))?;
    let overlay = opts.overlay.as_deref();
    let settings = Settings {
        baseline_dir: opts.baselines.clone(),
        purge_dirs: Vec::new(),
    };
    let mut progress = |line: &str| eprintln!("replay: {line}");

    let before = load_phase(&opts.run_dir, &info.run, 1, overlay)?;
    let inv1 = pipeline::inventory(Sources::of(&before));
    let entry = entry_for(&inv1.doc.entries, &info.main_key)?;
    let program_id = entry.program_id.to_string();
    let harvested = pipeline::harvest(
        Sources::of(&before),
        &program_id,
        Kb::shipped(),
        &settings,
        &mut progress,
    )
    .map_err(|e| anyhow!("harvest at phase 1: {e}"))?;
    let mut warnings = harvested.warnings;
    let report = harvested.report;
    let mut fp = report.fingerprint;

    let after = load_phase(&opts.run_dir, &info.run, 2, overlay)?;
    let verify = verify_gone::check(
        &after,
        &after,
        &after,
        &VerifyTarget {
            arp_key: entry.key_path.clone(),
            product_code: entry.product_code.clone(),
            main_exes: fp.main_exes().map(|e| e.path.clone()).collect(),
        },
    )
    .result;
    let disappeared = verify_gone::disappeared(&after, &inv1.doc.entries, &entry.program_id);
    fp.window.t_start = Some(info.t_start);
    fp.window.t_end = Some(info.t_end);
    fp.verify_gone = Some(verify);
    fp.co_removed = coproducts::co_removed(&report.co_candidates, &disappeared);
    progress(&format!(
        "uninstall window from run.json; verify-gone at phase 2 {} (ARP key gone: {}, MSI unknown: {}, \
         main exes gone: {}); {} co-removed of {} candidate(s)",
        if verify.is_passed() {
            "passed"
        } else {
            "failed"
        },
        verify.arp_gone,
        verify.msi_unknown_all_ctx,
        verify.main_exes_gone,
        fp.co_removed.len(),
        report.co_candidates.len()
    ));

    let scanned = pipeline::scan(
        Sources::of(&after),
        &fp,
        ScanMode::Post,
        Some(&opts.app),
        &settings,
        &mut progress,
    )
    .map_err(|e| anyhow!("scan at phase 2: {e}"))?;
    warnings.extend(scanned.warnings);

    if let Some(parent) = opts.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    output::write_atomic(&opts.out, &output::json_text(&scanned.built.plan))
        .with_context(|| format!("writing {}", opts.out.display()))?;
    Ok(Replayed {
        plan: scanned.built.plan,
        warnings,
        limits: limits(&before, &after, overlay),
        verify_passed: verify.is_passed(),
        co_removed: fp.co_removed.len(),
    })
}

fn summary(r: &Replayed) -> String {
    let count = |band| r.plan.items.iter().filter(|i| i.band == band).count();
    format!(
        "{} item(s): {} Safe ({} preselected), {} Likely, {} Weak, {} Blocked; verify-gone {}; {} co-removed",
        r.plan.items.len(),
        count(Band::Safe),
        r.plan.items.iter().filter(|i| i.preselected).count(),
        count(Band::Likely),
        count(Band::Weak),
        count(Band::Blocked),
        if r.verify_passed { "passed" } else { "failed" },
        r.co_removed
    )
}

fn report(app: &str, out: &Path, r: &Replayed) {
    for w in &r.warnings {
        eprintln!("replay: {app}: warning: {w}");
    }
    for l in &r.limits {
        println!("replay: {app}: limit: {l}");
    }
    println!("replay: {app}: {} -> {}", summary(r), out.display());
}

// ---------------------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------------------

/// Minimal flag parser: `--name value` pairs and bare switches.
struct Flags {
    pairs: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], valued: &[&str], switches: &[&str], usage: &str) -> Result<Self> {
        let mut out = Flags {
            pairs: Vec::new(),
            switches: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                let v = it
                    .next()
                    .with_context(|| format!("{a} needs a value\n{usage}"))?;
                out.pairs.push((a.clone(), v.clone()));
            } else if switches.contains(&a.as_str()) {
                out.switches.push(a.clone());
            } else {
                bail!("unknown argument {a:?}\n{usage}");
            }
        }
        Ok(out)
    }

    fn get(&self, names: &[&str]) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(k, _)| names.contains(&k.as_str()))
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
}

fn default_baselines(root: &Path) -> Option<PathBuf> {
    let dir = root.join("kb").join("baselines");
    dir.is_dir().then_some(dir)
}

/// `cargo xtask replay …`.
pub fn run_one(root: &Path, args: &[String]) -> Result<bool> {
    let f = Flags::parse(
        args,
        &[
            "--run",
            "--run-dir",
            "--app",
            "-o",
            "--out",
            "--overlay",
            "--baselines",
        ],
        &[],
        REPLAY_USAGE,
    )?;
    let run_dir = f
        .get(&["--run", "--run-dir"])
        .with_context(|| format!("--run is required\n{REPLAY_USAGE}"))?;
    let app = f
        .get(&["--app"])
        .with_context(|| format!("--app is required\n{REPLAY_USAGE}"))?;
    let out = f
        .get(&["-o", "--out"])
        .with_context(|| format!("-o is required\n{REPLAY_USAGE}"))?;
    let opts = ReplayOpts {
        run_dir: PathBuf::from(run_dir),
        app: app.to_owned(),
        out: PathBuf::from(out),
        overlay: f.get(&["--overlay"]).map(PathBuf::from),
        baselines: f
            .get(&["--baselines"])
            .map(PathBuf::from)
            .or_else(|| default_baselines(root)),
    };
    let r = replay(&opts)?;
    report(app, &opts.out, &r);
    Ok(true)
}

/// `cargo xtask replay-all …`.
pub fn run_all(root: &Path, args: &[String]) -> Result<bool> {
    let f = Flags::parse(
        args,
        &["--runs", "--overlay-root"],
        &["--if-present", "--no-score"],
        REPLAY_ALL_USAGE,
    )?;
    let runs = f
        .get(&["--runs"])
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(RUNS_DIR_VAR).map(PathBuf::from))
        .unwrap_or_else(|| root.join("vm").join("runs"));
    if !runs.is_dir() {
        let msg = format!(
            "replay-all: no runs directory {} (the frozen rig runs are git-ignored; pass --runs or set \
             {RUNS_DIR_VAR})",
            runs.display()
        );
        if f.has("--if-present") {
            println!("{msg}; nothing to do");
            return Ok(true);
        }
        bail!(msg);
    }
    let mut ok = true;
    let mut dirs = Vec::new();
    for id in M0_RUNS {
        let dir = runs.join(id);
        if !dir.join("run.json").is_file() {
            eprintln!("replay-all: {id}: no run.json in {}", dir.display());
            ok = false;
            continue;
        }
        let opts = ReplayOpts {
            run_dir: dir.clone(),
            app: (*id).to_owned(),
            out: dir.join("plans").join(REPLAY_PLAN),
            overlay: f
                .get(&["--overlay-root"])
                .map(|o| Path::new(o).join(id))
                .filter(|o| o.is_dir()),
            baselines: default_baselines(root),
        };
        match replay(&opts) {
            Ok(r) => {
                report(id, &opts.out, &r);
                dirs.push(dir);
            }
            Err(e) => {
                eprintln!("replay-all: {id}: {e:#}");
                ok = false;
            }
        }
    }
    if f.has("--no-score") || dirs.is_empty() {
        return Ok(ok);
    }
    let rigtool_dir = root
        .join("vm")
        .join("rigtool")
        .join("target")
        .join("release");
    let rigtool = ["rigtool.exe", "rigtool"]
        .iter()
        .map(|n| rigtool_dir.join(n))
        .find(|p| p.is_file());
    match rigtool {
        None => println!(
            "replay-all: {} has no rigtool binary; build it (cargo build --release in vm/rigtool) to \
             score the plans",
            rigtool_dir.display()
        ),
        Some(exe) => {
            let mut cmd = Command::new(&exe);
            cmd.arg("score").arg("--set").args(&dirs);
            println!("replay-all: {} score --set …", exe.display());
            let status = cmd
                .status()
                .with_context(|| format!("running {}", exe.display()))?;
            if !status.success() {
                eprintln!("replay-all: rigtool score failed ({status})");
                ok = false;
            }
        }
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\u{feff}{
        \"schema\": \"purge.rig.run/1\",
        \"id\": \"git\",
        \"run\": \"git\",
        \"user_sid\": \"S-1-5-21-1-2-3-1000\",
        \"main\": {
            \"key\": \"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Git_is1\",
            \"name\": \"Git\"
        },
        \"uninstall\": {
            \"cmd\": \"x\",
            \"t0\": \"2026-11-11T08:09:43.1776380-08:00\",
            \"t1\": \"2026-11-11T08:09:49.0887115-08:00\",
            \"exit\": 0
        }
    }";

    #[test]
    fn parses_a_run_json_with_a_bom() {
        let info = parse_run_json(SAMPLE).unwrap();
        assert_eq!(info.run, "git");
        assert_eq!(
            info.main_key,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
        );
        assert_eq!(
            Some(info.t_start),
            parse_iso8601("2026-11-11T16:09:43.1776380Z")
        );
        // 5.9110735 s later, in 100 ns ticks.
        assert_eq!(info.t_end.0 - info.t_start.0, 59_110_735);
    }

    #[test]
    fn resolves_hkcu_to_the_user_hive() {
        let text = SAMPLE.replace(r"HKLM\\SOFTWARE", r"HKCU\\Software");
        let info = parse_run_json(&text).unwrap();
        assert_eq!(
            info.main_key,
            r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
        );
    }

    #[test]
    fn rejects_runs_without_an_app_or_a_window() {
        let no_main = SAMPLE.replace("\"main\"", "\"other\"");
        assert!(parse_run_json(&no_main).is_err());
        let no_t1 = SAMPLE.replace("\"t1\"", "\"t9\"");
        assert!(parse_run_json(&no_t1).is_err());
        let bad_t0 = SAMPLE.replace("2026-11-11T08:09:43", "yesterday");
        assert!(parse_run_json(&bad_t0).is_err());
        let swapped = SAMPLE
            .replace("08:09:43.1776380", "XX")
            .replace("08:09:49.0887115", "08:09:43.1776380")
            .replace("XX", "08:09:49.0887115");
        assert!(parse_run_json(&swapped).is_err());
    }

    #[test]
    fn flags_parse_values_and_switches() {
        let args: Vec<String> = ["--runs", "x", "--if-present"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let f = Flags::parse(&args, &["--runs"], &["--if-present"], "u").unwrap();
        assert_eq!(f.get(&["--runs"]), Some("x"));
        assert!(f.has("--if-present"));
        assert!(Flags::parse(&args, &[], &[], "u").is_err());
        assert!(Flags::parse(&["--runs".to_owned()], &["--runs"], &[], "u").is_err());
    }

    /// Replays the frozen git run into the temp directory (never into vm/runs).
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the frozen rig runs"]
    fn replays_the_git_run() {
        let Some(runs) = std::env::var_os(RUNS_DIR_VAR) else {
            eprintln!("{RUNS_DIR_VAR} not set; skipping");
            return;
        };
        let out = std::env::temp_dir().join("purge-xtask-replay-git.json");
        let r = replay(&ReplayOpts {
            run_dir: Path::new(&runs).join("git"),
            app: "git".into(),
            out: out.clone(),
            overlay: None,
            baselines: default_baselines(&crate::workspace_root()),
        })
        .unwrap();
        assert!(r.verify_passed, "{:?}", r.warnings);
        assert!(!r.plan.items.is_empty());
        let text = std::fs::read_to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], "purge.plan/0");
        assert_eq!(v["app"], "git");
        assert_eq!(v["tool"], "purge");
        assert_eq!(v["mode"], "post");
        let _ = std::fs::remove_file(&out);
    }
}
