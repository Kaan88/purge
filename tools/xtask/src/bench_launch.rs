//! `bench-launch`: the launch bench of M3 design 9.2 (package M3-BENCH).
//!
//! ```text
//! cargo xtask bench-launch --purge <publish dir of Purge.exe> --bare <publish dir of BareWinUI.exe>
//!     [-n 21] [--out bench/launch] [--power <text>] [--purge-args "<switches>"] [--no-write]
//! cargo xtask bench-launch --first-launch --purge <dir> [--out bench/launch]
//! cargo xtask bench-launch --cold [--reset] --purge <dir> [--out bench/launch]
//! cargo xtask bench-launch --real-engine --purge <dir> [--engine <purge-engine.exe>] [-n 21] [--no-write]
//! cargo xtask bench-launch --s3-open --purge <dir> [-n 21] [--no-write]
//! ```
//!
//! Runs `Purge.exe --bench-exit --bench-stub` and `BareWinUI.exe --bench-exit` in turn (the order
//! alternates), `-n` times each (default 21), the first run of each dropped. Every launch gets its own
//! `PURGE_BENCH_OUT` file; the app appends one line of `marker=milliseconds` pairs (milliseconds since
//! process creation) once the first frame has been presented. The run writes
//! `bench/launch/<local date>-<local time>-<host>.json` with p50 and p90 per marker and the gate
//! verdicts, and fails on a gate breach or when a p50 is more than 10 % over the last file of the
//! same host.
//!
//! `--first-launch` copies the publish folder to 5 fresh directories and times launches 1 to 5 in each
//! (`<date>-<time>-<host>-first-launch.json`). The gated number is launch 1 of each copy.
//!
//! `--cold` (9.2(e)) is one launch after a reboot: it waits for 120 s of uptime, warns when the CPU is
//! not mostly idle, and appends the run (timestamp, uptime, markers) to `bench/launch/cold-<host>.json`.
//! With 5 runs it gates `presented` at 1.0 s p50; `--reset` starts a new series. Five reboots are the
//! documented procedure (docs/M3_BENCH.md).
//!
//! The modes above all run the stub engine (`--bench-stub`). Two more measure the rows of 9.1 the
//! stub cannot, each into a file of its own so stub and engine numbers never mix:
//!
//! - `--real-engine` (`<date>-<time>-<host>-real-engine.json`) runs `Purge.exe --bench-exit
//!   --bench-until icons_visible` without the stub: the real `purge-engine --stdio` (next to
//!   `Purge.exe`, or `--engine`) and this host's ARP data. It gates `names_visible` (the presented
//!   frame with rows: `presented` when the rows were in the first frame, else the frame after the
//!   first row) at 400 ms p50 / 460 ms p90 and `icons_visible` (the first screenful of rows with its
//!   icons settled) at 1 s p50 with a warm icon cache. The app gets an icon atlas of the run's own
//!   (`PURGE_BENCH_ICON_ATLAS`), empty at launch 1: that launch is the reported cold-cache number and,
//!   as in every mode, dropped from the warm ones. A launch that fell back to the sample data
//!   (`engine_fallback`) fails the run. Regression is checked against the last real-engine file.
//! - `--s3-open` (`<date>-<time>-<host>-s3-open.json`) runs `Purge.exe --bench-stub --bench-s3 2000
//!   --bench-until s3_open`: after the first frame the app opens the Leftovers page (S3) on a
//!   2,000-item sample fixture; the time is `s3_open - s3_start`. Reported, no gate (9.1).
//!
//! Not part of `xtask ci`: it needs published builds and a quiet machine.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(not(windows))]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Markers of the bench, in launch order (the spelling of `LaunchMarkers.Mark` in the app).
const MARKERS: &[&str] = &[
    "module_init",
    "main",
    "engine_ready",
    "list_reply",
    "on_launched",
    "window_ctor",
    "w_backdrop",
    "w_titlebar",
    "w_icon",
    "w_size",
    "programs_enter",
    "programs_xaml",
    "programs_ctor",
    "rows_set",
    "first_row",
    "first_tick",
    "presented",
    "names_visible",
    "icons_visible",
    "s3_start",
    "s3_open",
];

/// Gate rows (M3_DESIGN.json "budgets").
const REL_MARGIN_MS: f64 = 60.0;
const TICK_P50_MS: f64 = 360.0;
const TICK_P90_MS: f64 = 420.0;
const NAMES_P50_MS: f64 = 400.0;
const NAMES_P90_MS: f64 = 460.0;
const FIRST_LAUNCH_P50_MS: f64 = 1200.0;
const COLD_P50_MS: f64 = 1000.0;
/// "Icons visible, warm icon cache: 1 s" (9.1), applied to the p50 of `--real-engine`.
const ICONS_WARM_P50_MS: f64 = 1000.0;
/// "S3 page open, 2,000-item fixture" (9.1): reported, no gate yet.
const S3_ITEMS: u32 = 2000;
/// A p50 this much over the last file of the same host fails the run.
const REGRESSION: f64 = 1.10;
/// Longer than the app's own bench timeout (20 s after the first frame) plus its wait for a live
/// engine's icon load (at most 10 s), so the app's `bench_timeout` line is what a stall reports.
const RUN_TIMEOUT: Duration = Duration::from_secs(45);

/// Cold-after-reboot protocol (ENGINE_PLAN.md 9.2(e)): 120 s of uptime, mostly idle, 5 reboots.
const COLD_UPTIME_S: f64 = 120.0;
const COLD_MIN_RUNS: usize = 5;
const COLD_IDLE_FRACTION: f64 = 0.8;

type Markers = BTreeMap<String, f64>;

/// Parses one marker line, `name=1.5 other=2.0`. Unknown, malformed or non-finite pairs are skipped.
fn parse_markers(line: &str) -> Markers {
    line.split_whitespace()
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            Some((
                name.to_owned(),
                value.parse::<f64>().ok().filter(|v| v.is_finite())?,
            ))
        })
        .collect()
}

/// Nearest-rank percentile of `values` (not necessarily sorted), `p` in 1..=100.
fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let rank = ((p / 100.0) * v.len() as f64).ceil().max(1.0) as usize;
    Some(v[rank.min(v.len()) - 1])
}

/// True when `now` is more than 10 % above `before`.
fn regressed(before: f64, now: f64) -> bool {
    before > 0.0 && now > before * REGRESSION
}

#[derive(Default)]
struct Series {
    runs: Vec<Markers>,
}

impl Series {
    fn values(&self, marker: &str) -> Vec<f64> {
        self.runs
            .iter()
            .filter_map(|m| m.get(marker).copied())
            .collect()
    }
    fn p(&self, marker: &str, p: f64) -> Option<f64> {
        let v = self.values(marker);
        // A marker counts only when every run has it.
        (v.len() == self.runs.len())
            .then(|| percentile(&v, p))
            .flatten()
    }
    fn json(&self) -> Value {
        let mut out = serde_json::Map::new();
        for &name in MARKERS {
            if let (Some(p50), Some(p90)) = (self.p(name, 50.0), self.p(name, 90.0)) {
                out.insert(
                    name.to_owned(),
                    json!({"p50": round1(p50), "p90": round1(p90),
                           "min": round1(percentile(&self.values(name), 1.0).unwrap_or(0.0)),
                           "max": round1(percentile(&self.values(name), 100.0).unwrap_or(0.0))}),
                );
            }
        }
        json!({"runs": self.runs.len(), "markers": out})
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The time from marker `from` to marker `to` in one launch (the S3 page open is `s3_open - s3_start`).
fn span(m: &Markers, from: &str, to: &str) -> Option<f64> {
    let (a, b) = (m.get(from)?, m.get(to)?);
    (b >= a).then_some(b - a)
}

/// Refuses a launch line that does not measure what the mode asks: the app gave up waiting for
/// `until` (`bench_timeout`), never wrote it, or (with `real_engine`) showed the sample data because
/// the engine could not be used (`engine_fallback`).
fn check_line(m: &Markers, until: &str, real_engine: bool) -> Result<()> {
    if m.contains_key("bench_timeout") {
        bail!("the app did not reach '{until}' within its 20 s bench timeout");
    }
    if real_engine && m.contains_key("engine_fallback") {
        bail!(
            "the app fell back to the sample data (purge-engine missing, failing or slow): not a real-engine run"
        );
    }
    if !m.contains_key(until) {
        bail!("no '{until}' marker in the line");
    }
    Ok(())
}

/// One launch: starts `exe`, waits for exit, returns the marker line it wrote.
fn launch(exe: &Path, args: &[&str], out_file: &Path) -> Result<Markers> {
    launch_with(exe, args, out_file, &[], "presented", false)
}

/// [`launch`] with extra environment variables, waiting for the line to carry `until`.
fn launch_with(
    exe: &Path,
    args: &[&str],
    out_file: &Path,
    env: &[(&str, &Path)],
    until: &str,
    real_engine: bool,
) -> Result<Markers> {
    let _ = std::fs::remove_file(out_file);
    let mut child = Command::new(exe)
        .args(args)
        .envs(env.iter().copied())
        .env("PURGE_BENCH_OUT", out_file)
        .current_dir(exe.parent().unwrap_or(Path::new(".")))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > RUN_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} did not exit within {RUN_TIMEOUT:?}", exe.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let text = std::fs::read_to_string(out_file)
        .with_context(|| format!("{} wrote no marker file", exe.display()))?;
    let line = text.lines().last().unwrap_or("");
    let m = parse_markers(line);
    check_line(&m, until, real_engine).with_context(|| format!("{}: {line:?}", exe.display()))?;
    if !m.contains_key("presented") {
        bail!("{}: no 'presented' marker in {line:?}", exe.display());
    }
    Ok(m)
}

struct Opts {
    purge: PathBuf,
    bare: Option<PathBuf>,
    n: usize,
    out: PathBuf,
    first_launch: bool,
    cold: bool,
    reset: bool,
    power: Option<String>,
    write: bool,
    /// Extra switches for `Purge.exe` only (`--purge-args "--xaml-changes IconNoGridOptimization"`).
    purge_args: Vec<String>,
    /// `--real-engine`: the real medium engine and ARP data, no `--bench-stub` (names and icons visible).
    real_engine: bool,
    /// `--engine <purge-engine.exe>` for `--real-engine` (default: next to `Purge.exe`).
    engine: Option<PathBuf>,
    /// `--s3-open`: the S3 page open timer on the 2,000-item fixture.
    s3_open: bool,
}

fn parse_opts(root: &Path, args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        purge: PathBuf::new(),
        bare: None,
        n: 21,
        out: root.join("bench").join("launch"),
        first_launch: false,
        cold: false,
        reset: false,
        power: None,
        write: true,
        purge_args: Vec::new(),
        real_engine: false,
        engine: None,
        s3_open: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |what: &str| {
            it.next()
                .cloned()
                .with_context(|| format!("{what} needs a value"))
        };
        match a.as_str() {
            "--purge" => o.purge = PathBuf::from(val("--purge")?),
            "--bare" => o.bare = Some(PathBuf::from(val("--bare")?)),
            "-n" => o.n = val("-n")?.parse().context("-n")?,
            "--out" => o.out = PathBuf::from(val("--out")?),
            "--power" => o.power = Some(val("--power")?),
            "--first-launch" => o.first_launch = true,
            "--cold" => o.cold = true,
            "--reset" => o.reset = true,
            "--purge-args" => {
                o.purge_args = val("--purge-args")?
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
            }
            "--no-write" => o.write = false,
            "--real-engine" => o.real_engine = true,
            "--engine" => o.engine = Some(PathBuf::from(val("--engine")?)),
            "--s3-open" => o.s3_open = true,
            other => bail!("unknown option {other}"),
        }
    }
    if o.purge.as_os_str().is_empty() {
        bail!("--purge <publish dir of Purge.exe> is required");
    }
    let modes = [o.first_launch, o.cold, o.real_engine, o.s3_open];
    if modes.iter().filter(|&&m| m).count() > 1 {
        bail!("--first-launch, --cold, --real-engine and --s3-open are separate runs");
    }
    if o.reset && !o.cold {
        bail!("--reset only applies to --cold");
    }
    if o.engine.is_some() && !o.real_engine {
        bail!("--engine only applies to --real-engine");
    }
    // The stub and the bench-end switches belong to the mode; a stray one would mix stub and engine numbers.
    let owned = [
        "--bench-stub",
        "--sample",
        "--bench-until",
        "--bench-s3",
        "--bench-exit",
    ];
    if let Some(bad) = o.purge_args.iter().find(|a| owned.contains(&a.as_str())) {
        bail!("--purge-args may not carry {bad}: the bench mode sets it");
    }
    let warm = !modes.iter().any(|&m| m);
    if warm && o.bare.is_none() {
        bail!("--bare <publish dir of BareWinUI.exe> is required");
    }
    if o.n < 2 && (warm || o.real_engine || o.s3_open) {
        bail!("-n must be at least 2 (the first run is dropped)");
    }
    Ok(o)
}

/// Runs the command; the bench host facts are best effort.
pub fn run(root: &Path, args: &[String]) -> Result<bool> {
    let o = parse_opts(root, args)?;
    if !cfg!(windows) {
        bail!("bench-launch runs on Windows");
    }
    let tmp = std::env::temp_dir().join(format!("purge-bench-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let result = if o.cold {
        cold(&o, &tmp)
    } else if o.real_engine {
        real_engine(&o, &tmp)
    } else if o.s3_open {
        s3_open(&o, &tmp)
    } else if o.first_launch {
        first_launch(&o, &tmp)
    } else {
        warm(&o, &tmp)
    };
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

fn host_json(o: &Opts) -> Value {
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let shell = |script: &str| {
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .ok()
            .map(|r| String::from_utf8_lossy(&r.stdout).trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    let power = o.power.clone().or_else(|| {
        shell(
            "$b=Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue; \
             $p=(powercfg /getactivescheme) -replace '^.*\\(|\\).*$',''; \
             if($b){\"battery status=$($b.BatteryStatus) charge=$($b.EstimatedChargeRemaining)%; plan=$p\"} else {\"no battery; plan=$p\"}",
        )
    });
    let hw = shell(
        "$c=Get-CimInstance Win32_Processor|select -First 1; $v=Get-CimInstance Win32_VideoController|select -First 1; \
         \"$($c.Name.Trim()); $($v.Name)\"",
    );
    let os = shell(
        "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).BuildNumber",
    );
    json!({"host": host, "os": os, "hardware": hw, "power": power,
           "note": "a shared dev host: other work on the machine invalidates a run (docs/M3_BENCH.md)"})
}

fn flavour() -> Value {
    json!({"deploy": "unpackaged, self-contained, Native AOT, x64, custom Main",
           "winappsdk": "2.6.5", "stub_engine": "engine.hello + 300 rows after 20 ms (--bench-stub)"})
}

/// Civil date and time (UTC) from seconds since 1970-01-01, the algorithm of H. Hinnant.
/// Used for the non-Windows fallback and by the date test.
#[cfg_attr(windows, allow(dead_code))]
fn civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m as u32,
        d as u32,
        (rem / 3_600) as u32,
        ((rem % 3_600) / 60) as u32,
        (rem % 60) as u32,
    )
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct RawSystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawFileTime {
    low: u32,
    high: u32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetLocalTime(out: *mut RawSystemTime);
    fn GetTickCount64() -> u64;
    fn GetSystemTimes(
        idle: *mut RawFileTime,
        kernel: *mut RawFileTime,
        user: *mut RawFileTime,
    ) -> i32;
}

/// The local date and time; the file name must say when the run happened on this machine.
#[cfg(windows)]
fn local_parts() -> (i64, u32, u32, u32, u32, u32) {
    let mut t = RawSystemTime {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        milliseconds: 0,
    };
    // SAFETY: `GetLocalTime` writes the whole struct.
    unsafe { GetLocalTime(&mut t) };
    (
        i64::from(t.year),
        u32::from(t.month),
        u32::from(t.day),
        u32::from(t.hour),
        u32::from(t.minute),
        u32::from(t.second),
    )
}

#[cfg(not(windows))]
fn local_parts() -> (i64, u32, u32, u32, u32, u32) {
    civil(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

fn today() -> String {
    let (y, m, d, _, _, _) = local_parts();
    format!("{y:04}-{m:02}-{d:02}")
}

/// The local clock time, `<HHMMSS>` for the result file name.
fn clock() -> String {
    let (_, _, _, hh, mm, ss) = local_parts();
    format!("{hh:02}{mm:02}{ss:02}")
}

/// The local date and time, `YYYY-MM-DDTHH:MM:SS`, for a cold run's record.
fn stamp() -> String {
    let (y, m, d, hh, mm, ss) = local_parts();
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}")
}

/// Seconds since boot (`GetTickCount64`), or `None` off Windows.
#[cfg(windows)]
fn uptime_secs() -> Option<f64> {
    // SAFETY: no arguments, no pointer access.
    Some(unsafe { GetTickCount64() } as f64 / 1000.0)
}

#[cfg(not(windows))]
fn uptime_secs() -> Option<f64> {
    None
}

/// The idle share of the CPU over `sample` (kernel time already includes idle time).
#[cfg(windows)]
fn cpu_idle_fraction(sample: Duration) -> Option<f64> {
    fn ticks(t: RawFileTime) -> u64 {
        (u64::from(t.high) << 32) | u64::from(t.low)
    }
    fn read() -> Option<(u64, u64, u64)> {
        let (mut idle, mut kernel, mut user) = (
            RawFileTime::default(),
            RawFileTime::default(),
            RawFileTime::default(),
        );
        // SAFETY: `GetSystemTimes` writes all three structs.
        let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } != 0;
        ok.then(|| (ticks(idle), ticks(kernel), ticks(user)))
    }
    let (i0, k0, u0) = read()?;
    std::thread::sleep(sample);
    let (i1, k1, u1) = read()?;
    let idle = i1.saturating_sub(i0) as f64;
    let total = k1.saturating_sub(k0) as f64 + u1.saturating_sub(u0) as f64;
    (total > 0.0).then(|| idle / total)
}

#[cfg(not(windows))]
fn cpu_idle_fraction(_sample: Duration) -> Option<f64> {
    None
}

fn gate(
    name: &str,
    p50: Option<f64>,
    p90: Option<f64>,
    l50: f64,
    l90: Option<f64>,
) -> (Value, bool) {
    let pass = match (p50, p90) {
        (Some(a), b) => a <= l50 && l90.is_none_or(|l| b.is_some_and(|b| b <= l)),
        _ => false,
    };
    (
        json!({"gate": name, "p50": p50.map(round1), "p90": p90.map(round1),
               "limit_p50": l50, "limit_p90": l90, "pass": pass}),
        pass,
    )
}

/// The `--xaml-changes` list in the extra switches (the app validates it; this records it).
fn xaml_changes(args: &[String]) -> Vec<String> {
    args.iter()
        .position(|a| a == "--xaml-changes")
        .and_then(|i| args.get(i + 1))
        .map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn warm(o: &Opts, tmp: &Path) -> Result<bool> {
    let purge_exe = o.purge.join("Purge.exe");
    let bare_exe = o.bare.as_ref().expect("checked").join("BareWinUI.exe");
    let out_file = tmp.join("markers.txt");
    let mut purge_args = vec!["--bench-exit", "--bench-stub"];
    purge_args.extend(o.purge_args.iter().map(String::as_str));
    let bare_args = ["--bench-exit"];
    let at = |m: &Markers, name: &str| m.get(name).copied().unwrap_or(f64::NAN);
    let (mut purge, mut bare) = (Series::default(), Series::default());
    for i in 0..o.n {
        // Alternate the order so neither app always runs into the cache the other just warmed.
        let (p, b) = if i % 2 == 0 {
            (
                launch(&purge_exe, &purge_args, &out_file)?,
                launch(&bare_exe, &bare_args, &out_file)?,
            )
        } else {
            let b = launch(&bare_exe, &bare_args, &out_file)?;
            let p = launch(&purge_exe, &purge_args, &out_file)?;
            (p, b)
        };
        eprintln!(
            "run {:2}/{}{}  purge tick {:6.1} presented {:6.1} | bare tick {:6.1} presented {:6.1}",
            i + 1,
            o.n,
            if i == 0 { " (dropped)" } else { "" },
            at(&p, "first_tick"),
            at(&p, "presented"),
            at(&b, "first_tick"),
            at(&b, "presented")
        );
        if i > 0 {
            purge.runs.push(p);
            bare.runs.push(b);
        }
    }

    let mut gates = Vec::new();
    let mut ok = true;
    let tick50 = purge.p("first_tick", 50.0);
    let tick90 = purge.p("first_tick", 90.0);
    let bare50 = bare.p("first_tick", 50.0);
    let rel = tick50.zip(bare50).map(|(a, b)| a - b);
    let (g, p) = gate(
        "first Rendering tick vs bare control (relative, ms over control)",
        rel,
        None,
        REL_MARGIN_MS,
        None,
    );
    gates.push(g);
    ok &= p;
    let (g, p) = gate(
        "first Rendering tick, absolute guard",
        tick50,
        tick90,
        TICK_P50_MS,
        Some(TICK_P90_MS),
    );
    gates.push(g);
    ok &= p;
    let rows_in_frame = purge.runs.iter().all(|m| {
        m.get("first_row")
            .zip(m.get("presented"))
            .is_some_and(|(r, p)| r <= p)
    });
    let (mut g, p) = gate(
        "names visible (presented frame with rows)",
        purge.p("presented", 50.0),
        purge.p("presented", 90.0),
        NAMES_P50_MS,
        Some(NAMES_P90_MS),
    );
    g["rows_before_presented_in_every_run"] = json!(rows_in_frame);
    gates.push(g);
    ok &= p && rows_in_frame;

    // Regression against the last file of the same host.
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let name = format!("{}-{}-{host}.json", today(), clock());
    let regressions = regressions_since(
        &o.out,
        &format!("-{host}.json"),
        &name,
        &purge,
        &["first_tick", "presented"],
    );
    ok &= regressions.is_empty();

    let doc = json!({
        "schema": "purge.bench-launch/0",
        "date": today(),
        "host": host_json(o),
        "flavour": flavour(),
        "purge_args": purge_args,
        "xaml_changes": xaml_changes(&o.purge_args),
        "n": o.n, "dropped_first": 1,
        "percentile_rule": "nearest rank",
        "apps": {"purge": purge.json(), "bare": bare.json()},
        "gates": gates,
        "regressions_over_10_percent": regressions,
        "icons_visible_warm_cache": "not in this file: the stub sends no icons; cargo xtask bench-launch --real-engine measures it",
        "names_visible_real_engine": "not in this file: this run is the stub (300 rows after 20 ms); see --real-engine",
        "cold_after_reboot": "not in this file: cargo xtask bench-launch --cold appends to cold-<host>.json",
        "pass": ok,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    if o.write {
        std::fs::create_dir_all(&o.out)?;
        let path = o.out.join(&name);
        std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")?;
        eprintln!("wrote {}", path.display());
    }
    Ok(ok)
}

/// The latest `*<suffix>` under `dir` other than `exclude` (names start with the date and time;
/// `-<host>.json` for the stub warm runs, `-<host>-real-engine.json` for the real-engine runs).
fn last_file(dir: &Path, suffix: &str, exclude: &str) -> Option<(String, Value)> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.ends_with(suffix)
                && n != exclude
                && n.as_str() < exclude
                && n.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .collect();
    names.sort();
    let name = names.pop()?;
    let v = serde_json::from_str(&std::fs::read_to_string(dir.join(&name)).ok()?).ok()?;
    Some((name, v))
}

/// The p50 regressions of `markers` against the last `*<suffix>` file under `dir` (other than `name`).
fn regressions_since(
    dir: &Path,
    suffix: &str,
    name: &str,
    purge: &Series,
    markers: &[&str],
) -> Vec<String> {
    let mut regressions = Vec::new();
    if let Some((prev_name, prev)) = last_file(dir, suffix, name) {
        for &marker in markers {
            let before = prev["apps"]["purge"]["markers"][marker]["p50"].as_f64();
            if let (Some(before), Some(now)) = (before, purge.p(marker, 50.0))
                && regressed(before, now)
            {
                regressions.push(format!(
                    "{marker}: p50 {now:.1} ms vs {before:.1} ms in {prev_name}"
                ));
            }
        }
    }
    regressions
}

/// The gates of a `--real-engine` run (9.1): names visible (presented frame with rows) at 400 ms p50
/// and 460 ms p90, icons visible with a warm icon cache at 1 s p50. `cold_icons` (the first launch,
/// with an empty icon atlas) is reported and never gated.
fn real_engine_gates(purge: &Series, cold_icons: Option<f64>) -> (Vec<Value>, bool) {
    let (names, names_ok) = gate(
        "names visible (presented frame with rows), real engine and ARP data",
        purge.p("names_visible", 50.0),
        purge.p("names_visible", 90.0),
        NAMES_P50_MS,
        Some(NAMES_P90_MS),
    );
    let (mut icons, icons_ok) = gate(
        "icons visible, warm icon cache (first screenful settled)",
        purge.p("icons_visible", 50.0),
        purge.p("icons_visible", 90.0),
        ICONS_WARM_P50_MS,
        None,
    );
    icons["cold_cache_first_launch_ms"] = json!(cold_icons.map(round1));
    icons["cold_cache"] =
        json!("reported, no gate: launch 1 with an empty atlas (also the dropped warm-up run)");
    (vec![names, icons], names_ok && icons_ok)
}

/// `--real-engine`: `Purge.exe` with the real medium engine and this machine's ARP data. Launch 1
/// starts with an empty icon atlas of its own (`PURGE_BENCH_ICON_ATLAS`, never the user's) and is
/// the cold-cache sample; it is dropped from the warm numbers like the first run of every mode.
fn real_engine(o: &Opts, tmp: &Path) -> Result<bool> {
    let purge_exe = o.purge.join("Purge.exe");
    let engine = o
        .engine
        .clone()
        .unwrap_or_else(|| o.purge.join("purge-engine.exe"));
    if !engine.is_file() {
        bail!(
            "--real-engine needs {} (cargo build --release -p purge-engine, then copy it next to Purge.exe, or pass --engine)",
            engine.display()
        );
    }
    // The app runs in its own directory, so a relative path would name another file there.
    let engine = std::path::absolute(&engine).context("--engine path")?;
    let out_file = tmp.join("markers.txt");
    let atlas = tmp.join("icons.atlas");
    let _ = std::fs::remove_file(&atlas);
    let mut purge_args = vec!["--bench-exit", "--bench-until", "icons_visible"];
    purge_args.extend(o.purge_args.iter().map(String::as_str));
    let env = [
        ("PURGE_ENGINE", engine.as_path()),
        ("PURGE_BENCH_ICON_ATLAS", atlas.as_path()),
    ];
    let at = |m: &Markers, name: &str| m.get(name).copied().unwrap_or(f64::NAN);
    let mut purge = Series::default();
    let mut cold_icons = None;
    for i in 0..o.n {
        let m = launch_with(
            &purge_exe,
            &purge_args,
            &out_file,
            &env,
            "icons_visible",
            true,
        )?;
        eprintln!(
            "run {:2}/{}{}  list_reply {:6.1} names_visible {:6.1} icons_visible {:6.1}",
            i + 1,
            o.n,
            if i == 0 {
                " (dropped; cold icon cache)"
            } else {
                ""
            },
            at(&m, "list_reply"),
            at(&m, "names_visible"),
            at(&m, "icons_visible")
        );
        if i == 0 {
            cold_icons = m.get("icons_visible").copied();
        } else {
            purge.runs.push(m);
        }
    }
    let (gates, mut ok) = real_engine_gates(&purge, cold_icons);
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let name = format!("{}-{}-{host}-real-engine.json", today(), clock());
    let regressions = regressions_since(
        &o.out,
        &format!("-{host}-real-engine.json"),
        &name,
        &purge,
        &["names_visible", "icons_visible"],
    );
    ok &= regressions.is_empty();
    let mut flavour = flavour();
    flavour["stub_engine"] = json!(null);
    flavour["engine"] = json!(format!(
        "real purge-engine --stdio ({}), this host's ARP data",
        engine.display()
    ));
    let doc = json!({
        "schema": "purge.bench-launch-real/0",
        "date": today(),
        "host": host_json(o),
        "flavour": flavour,
        "purge_args": purge_args,
        "xaml_changes": xaml_changes(&o.purge_args),
        "n": o.n, "dropped_first": 1,
        "percentile_rule": "nearest rank",
        "apps": {"purge": purge.json()},
        "gates": gates,
        "regressions_over_10_percent": regressions,
        "note": "kept apart from the stub runs: the program count and the engine's speed are this host's",
        "pass": ok,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    if o.write {
        std::fs::create_dir_all(&o.out)?;
        let path = o.out.join(&name);
        std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")?;
        eprintln!("wrote {}", path.display());
    }
    Ok(ok)
}

/// The S3 page open times (`s3_open - s3_start`) of the runs, and their p50 and p90.
fn s3_summary(purge: &Series) -> Value {
    let times: Vec<f64> = purge
        .runs
        .iter()
        .filter_map(|m| span(m, "s3_start", "s3_open"))
        .collect();
    let complete = times.len() == purge.runs.len();
    json!({
        "metric": "S3 page open (s3_start: navigation asked, after the first frame; s3_open: the frame after the first list row)",
        "items": S3_ITEMS,
        "runs": times.len(),
        "p50": complete.then(|| percentile(&times, 50.0)).flatten().map(round1),
        "p90": complete.then(|| percentile(&times, 90.0)).flatten().map(round1),
        "min": percentile(&times, 1.0).map(round1),
        "max": percentile(&times, 100.0).map(round1),
        "gate": "reported, no gate yet (9.1)",
    })
}

/// `--s3-open`: after the first frame the app opens the Leftovers page (S3) on the sample client's
/// 2,000-item fixture; the time is `s3_open - s3_start`. Reported, not gated.
fn s3_open(o: &Opts, tmp: &Path) -> Result<bool> {
    let purge_exe = o.purge.join("Purge.exe");
    let out_file = tmp.join("markers.txt");
    let items = S3_ITEMS.to_string();
    let mut purge_args = vec![
        "--bench-exit",
        "--bench-stub",
        "--bench-s3",
        items.as_str(),
        "--bench-until",
        "s3_open",
    ];
    purge_args.extend(o.purge_args.iter().map(String::as_str));
    let mut purge = Series::default();
    for i in 0..o.n {
        let m = launch_with(&purge_exe, &purge_args, &out_file, &[], "s3_open", false)?;
        eprintln!(
            "run {:2}/{}{}  S3 page open {:6.1} ms",
            i + 1,
            o.n,
            if i == 0 { " (dropped)" } else { "" },
            span(&m, "s3_start", "s3_open").unwrap_or(f64::NAN)
        );
        if i > 0 {
            purge.runs.push(m);
        }
    }
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let doc = json!({
        "schema": "purge.bench-launch-s3/0",
        "date": today(),
        "host": host_json(o),
        "flavour": flavour(),
        "purge_args": purge_args,
        "n": o.n, "dropped_first": 1,
        "percentile_rule": "nearest rank",
        "s3_page_open": s3_summary(&purge),
        "apps": {"purge": purge.json()},
        "pass": true,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    if o.write {
        std::fs::create_dir_all(&o.out)?;
        let path = o
            .out
            .join(format!("{}-{}-{host}-s3-open.json", today(), clock()));
        std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")?;
        eprintln!("wrote {}", path.display());
    }
    Ok(true)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let dest = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), dest)?;
        }
    }
    Ok(())
}

fn first_launch(o: &Opts, tmp: &Path) -> Result<bool> {
    let out_file = tmp.join("markers.txt");
    let mut purge_args = vec!["--bench-exit", "--bench-stub"];
    purge_args.extend(o.purge_args.iter().map(String::as_str));
    // launches[k] holds launch k+1 of each of the 5 copies.
    let mut launches: Vec<Series> = (0..5).map(|_| Series::default()).collect();
    for copy in 0..5 {
        let dir = tmp.join(format!("copy{copy}"));
        copy_dir(&o.purge, &dir)?;
        for (k, series) in launches.iter_mut().enumerate() {
            let m = launch(&dir.join("Purge.exe"), &purge_args, &out_file)?;
            eprintln!(
                "copy {copy} launch {}: presented {:.1} ms",
                k + 1,
                m.get("presented").copied().unwrap_or(f64::NAN)
            );
            series.runs.push(m);
        }
    }
    let first = &launches[0];
    let (g, pass) = gate(
        "first launch of a fresh copy, presented (Defender state as on the host)",
        first.p("presented", 50.0),
        first.p("presented", 90.0),
        FIRST_LAUNCH_P50_MS,
        None,
    );
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let doc = json!({
        "schema": "purge.bench-launch-first/0",
        "date": today(),
        "host": host_json(o),
        "flavour": flavour(),
        "copies": 5,
        "purge_args": purge_args,
        "xaml_changes": xaml_changes(&o.purge_args),
        "launches": launches.iter().enumerate().map(|(c, s)| json!({"copy": c + 1, "launches": s.json()})).collect::<Vec<_>>(),
        "gates": [g],
        "pass": pass,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    if o.write {
        std::fs::create_dir_all(&o.out)?;
        let path = o
            .out
            .join(format!("{}-{}-{host}-first-launch.json", today(), clock()));
        std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")?;
        eprintln!("wrote {}", path.display());
    }
    Ok(pass)
}

/// One cold-after-reboot launch (9.2(e)), appended to `cold-<host>.json`.
fn cold(o: &Opts, tmp: &Path) -> Result<bool> {
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let path = o.out.join(format!("cold-{host}.json"));
    if o.reset {
        let _ = std::fs::remove_file(&path);
        eprintln!("cold: started a new series ({})", path.display());
    }

    // The protocol: wait for logon plus 120 s of idle, then launch. The user reboots between runs.
    if let Some(uptime) = uptime_secs() {
        if uptime < COLD_UPTIME_S {
            let wait = COLD_UPTIME_S - uptime;
            eprintln!("cold: uptime {uptime:.0} s; waiting {wait:.0} s for 120 s since boot");
            std::thread::sleep(Duration::from_secs_f64(wait));
        }
    } else {
        eprintln!("cold: warning: uptime unreadable; be sure 120 s have passed since logon");
    }
    match cpu_idle_fraction(Duration::from_secs(1)) {
        Some(idle) if idle < COLD_IDLE_FRACTION => eprintln!(
            "cold: warning: CPU only {:.0}% idle over 1 s; the number may be high",
            idle * 100.0
        ),
        Some(idle) => eprintln!("cold: CPU idle {:.0}%", idle * 100.0),
        None => eprintln!("cold: warning: CPU idle could not be read"),
    }

    let out_file = tmp.join("markers.txt");
    let uptime = uptime_secs().unwrap_or(0.0);
    let m = launch(
        &o.purge.join("Purge.exe"),
        &["--bench-exit", "--bench-stub"],
        &out_file,
    )?;
    let presented = m.get("presented").copied().unwrap_or(f64::NAN);

    let mut runs: Vec<Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let markers: serde_json::Map<String, Value> = m
        .iter()
        .map(|(name, ms)| (name.clone(), json!(round1(*ms))))
        .collect();
    runs.push(json!({
        "at": stamp(),
        "uptime_s": round1(uptime),
        "presented": round1(presented),
        "markers": Value::Object(markers),
    }));

    let values: Vec<f64> = runs
        .iter()
        .filter_map(|r| r["presented"].as_f64())
        .collect();
    let p50 = percentile(&values, 50.0);
    // Fewer than five reboots is a series in progress, not a pass or a breach.
    let gated = values.len() >= COLD_MIN_RUNS;
    let pass = !gated || p50.is_some_and(|p| p <= COLD_P50_MS);
    let doc = json!({
        "schema": "purge.bench-launch-cold/0",
        "date": today(),
        "host": host,
        "gate": {
            "gate": "cold after reboot, presented (9.2(e))",
            "runs": values.len(), "min_runs": COLD_MIN_RUNS,
            "p50": p50.map(round1), "limit_p50": COLD_P50_MS,
            "pending": !gated, "pass": pass,
        },
        "pass": pass,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    if o.write {
        std::fs::create_dir_all(&o.out)?;
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&Value::Array(runs))? + "\n",
        )?;
        eprintln!(
            "wrote {} ({}/{} runs)",
            path.display(),
            values.len(),
            COLD_MIN_RUNS
        );
    }
    Ok(pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(percentile(&v, 50.0), Some(10.0));
        assert_eq!(percentile(&v, 90.0), Some(18.0));
        assert_eq!(percentile(&v, 100.0), Some(20.0));
        assert_eq!(percentile(&[7.0], 90.0), Some(7.0));
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 50.0), Some(2.0));
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn marker_line_parses() {
        let m = parse_markers("module_init=37.1 main=40.9 junk presented=655.2 bad=x");
        assert_eq!(m["module_init"], 37.1);
        assert_eq!(m["presented"], 655.2);
        assert_eq!(m.len(), 3);
        assert!(parse_markers("").is_empty());
        assert!(parse_markers("nan=NaN inf=inf").is_empty());
    }

    #[test]
    fn regression_rule_is_ten_percent_on_p50() {
        assert!(!regressed(100.0, 110.0));
        assert!(regressed(100.0, 110.5));
        assert!(!regressed(100.0, 80.0));
        assert!(!regressed(0.0, 50.0));
    }

    #[test]
    fn series_percentile_needs_the_marker_in_every_run() {
        let mut s = Series::default();
        s.runs.push(parse_markers("a=1 b=5"));
        s.runs.push(parse_markers("a=3"));
        assert_eq!(s.p("a", 50.0), Some(1.0));
        assert_eq!(s.p("b", 50.0), None);
    }

    #[test]
    fn gate_checks_both_percentiles() {
        assert!(gate("g", Some(300.0), Some(400.0), 360.0, Some(420.0)).1);
        assert!(!gate("g", Some(300.0), Some(430.0), 360.0, Some(420.0)).1);
        assert!(!gate("g", Some(370.0), Some(400.0), 360.0, Some(420.0)).1);
        assert!(!gate("g", None, None, 360.0, None).1);
        assert!(gate("g", Some(50.0), None, 60.0, None).1);
    }

    #[test]
    fn civil_date_has_the_iso_shape() {
        let d = today();
        assert_eq!(d.len(), 10);
        assert!(d.starts_with("20"));
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn clock_is_six_digits() {
        let c = clock();
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        assert_eq!(stamp().len(), 19);
    }

    fn opts(args: &[&str]) -> Result<Opts> {
        let args: Vec<String> = args.iter().map(|&a| a.to_owned()).collect();
        parse_opts(Path::new("."), &args)
    }

    #[test]
    fn real_engine_and_s3_open_are_modes_of_their_own() {
        let o = opts(&["--purge", "p", "--real-engine", "-n", "2"]).unwrap();
        assert!(o.real_engine && !o.s3_open && o.bare.is_none());
        let o = opts(&["--purge", "p", "--real-engine", "--engine", "e.exe"]).unwrap();
        assert_eq!(o.engine, Some(PathBuf::from("e.exe")));
        assert!(opts(&["--purge", "p", "--s3-open"]).unwrap().s3_open);
        // The stub warm mode still needs the bare control; the new modes do not.
        assert!(opts(&["--purge", "p"]).is_err());
        for both in [
            ["--real-engine", "--s3-open"],
            ["--real-engine", "--cold"],
            ["--s3-open", "--first-launch"],
        ] {
            assert!(
                opts(&["--purge", "p", both[0], both[1]]).is_err(),
                "{both:?}"
            );
        }
        assert!(opts(&["--purge", "p", "--bare", "b", "--engine", "e.exe"]).is_err());
        assert!(opts(&["--purge", "p", "--real-engine", "-n", "1"]).is_err());
        assert!(opts(&["--purge", "p", "--s3-open", "-n", "1"]).is_err());
    }

    #[test]
    fn purge_args_may_not_carry_the_switches_a_mode_sets() {
        for bad in [
            "--bench-stub",
            "--sample",
            "--bench-until icons_visible",
            "--bench-s3 10",
        ] {
            assert!(
                opts(&["--purge", "p", "--real-engine", "--purge-args", bad]).is_err(),
                "{bad}"
            );
        }
        let o = opts(&[
            "--purge",
            "p",
            "--real-engine",
            "--purge-args",
            "--xaml-changes IconNoGridOptimization",
        ])
        .unwrap();
        assert_eq!(xaml_changes(&o.purge_args), ["IconNoGridOptimization"]);
    }

    #[test]
    fn a_line_is_refused_when_it_timed_out_fell_back_or_lacks_its_marker() {
        let good = parse_markers("presented=300 names_visible=320 icons_visible=700");
        assert!(check_line(&good, "icons_visible", true).is_ok());
        let fell_back = parse_markers("presented=300 engine_fallback=200 icons_visible=700");
        assert!(check_line(&fell_back, "icons_visible", true).is_err());
        // The stub modes show the sample data on purpose.
        assert!(check_line(&fell_back, "icons_visible", false).is_ok());
        let timed_out = parse_markers("presented=300 bench_timeout=20300 icons_visible=20301");
        assert!(check_line(&timed_out, "icons_visible", true).is_err());
        let short = parse_markers("presented=300 names_visible=320");
        assert!(check_line(&short, "icons_visible", true).is_err());
        assert!(check_line(&short, "presented", false).is_ok());
    }

    #[test]
    fn s3_page_open_is_the_span_from_start_to_open() {
        let m = parse_markers("presented=300 s3_start=310.5 s3_open=420");
        assert_eq!(span(&m, "s3_start", "s3_open"), Some(109.5));
        assert_eq!(span(&m, "s3_open", "s3_start"), None);
        assert_eq!(span(&m, "s3_start", "nope"), None);

        let mut s = Series::default();
        for (a, b) in [(300.0, 400.0), (300.0, 350.0), (310.0, 500.0)] {
            s.runs
                .push(parse_markers(&format!("s3_start={a} s3_open={b}")));
        }
        let v = s3_summary(&s);
        assert_eq!(v["p50"], json!(100.0));
        assert_eq!(v["p90"], json!(190.0));
        assert_eq!(v["items"], json!(2000));
        // A run without both markers leaves the percentiles out rather than skewing them.
        s.runs.push(parse_markers("s3_start=1"));
        assert_eq!(s3_summary(&s)["p50"], Value::Null);
    }

    #[test]
    fn real_engine_gates_names_at_400_460_and_warm_icons_at_one_second() {
        let series = |lines: &[&str]| Series {
            runs: lines.iter().map(|l| parse_markers(l)).collect(),
        };
        let pass = series(&[
            "names_visible=380 icons_visible=900",
            "names_visible=390 icons_visible=950",
        ]);
        let (gates, ok) = real_engine_gates(&pass, Some(2500.0));
        assert!(ok);
        assert_eq!(gates.len(), 2);
        // The cold cache is reported, never gated.
        assert_eq!(gates[1]["cold_cache_first_launch_ms"], json!(2500.0));

        let slow_names = series(&[
            "names_visible=380 icons_visible=900",
            "names_visible=470 icons_visible=950",
        ]);
        assert!(
            !real_engine_gates(&slow_names, None).0[0]["pass"]
                .as_bool()
                .unwrap()
        );
        assert!(!real_engine_gates(&slow_names, None).1);
        let slow_icons = series(&[
            "names_visible=300 icons_visible=1100",
            "names_visible=300 icons_visible=1200",
        ]);
        assert!(!real_engine_gates(&slow_icons, None).1);
        // A run without names_visible fails the gate instead of being skipped.
        let missing = series(&["names_visible=300 icons_visible=500", "icons_visible=500"]);
        assert!(!real_engine_gates(&missing, None).1);
    }

    #[test]
    fn the_new_markers_are_reported() {
        for m in ["names_visible", "icons_visible", "s3_start", "s3_open"] {
            assert!(MARKERS.contains(&m), "{m}");
        }
    }

    #[test]
    fn xaml_changes_are_read_from_the_extra_switches() {
        let args = ["--xaml-changes", "A,B"].map(str::to_owned).to_vec();
        assert_eq!(xaml_changes(&args), ["A", "B"]);
        assert!(xaml_changes(&[]).is_empty());
        assert!(xaml_changes(&["--theme".to_owned(), "dark".to_owned()]).is_empty());
    }
}
