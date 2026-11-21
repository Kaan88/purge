//! `bench-launch`: the launch bench of M3 design 9.2 (package M3-BENCH).
//!
//! ```text
//! cargo xtask bench-launch --purge <publish dir of Purge.exe> --bare <publish dir of BareWinUI.exe>
//!     [-n 21] [--out bench/launch] [--power <text>] [--purge-args "<switches>"] [--no-write]
//! cargo xtask bench-launch --first-launch --purge <dir> [--out bench/launch]
//! cargo xtask bench-launch --cold [--reset] --purge <dir> [--out bench/launch]
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
];

/// Gate rows (M3_DESIGN.json "budgets").
const REL_MARGIN_MS: f64 = 60.0;
const TICK_P50_MS: f64 = 360.0;
const TICK_P90_MS: f64 = 420.0;
const NAMES_P50_MS: f64 = 400.0;
const NAMES_P90_MS: f64 = 460.0;
const FIRST_LAUNCH_P50_MS: f64 = 1200.0;
const COLD_P50_MS: f64 = 1000.0;
/// A p50 this much over the last file of the same host fails the run.
const REGRESSION: f64 = 1.10;
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

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

/// One launch: starts `exe`, waits for exit, returns the marker line it wrote.
fn launch(exe: &Path, args: &[&str], out_file: &Path) -> Result<Markers> {
    let _ = std::fs::remove_file(out_file);
    let mut child = Command::new(exe)
        .args(args)
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
            other => bail!("unknown option {other}"),
        }
    }
    if o.purge.as_os_str().is_empty() {
        bail!("--purge <publish dir of Purge.exe> is required");
    }
    if o.first_launch && o.cold {
        bail!("--first-launch and --cold are separate runs");
    }
    if o.reset && !o.cold {
        bail!("--reset only applies to --cold");
    }
    if !o.first_launch && !o.cold && o.bare.is_none() {
        bail!("--bare <publish dir of BareWinUI.exe> is required");
    }
    if o.n < 2 && !o.first_launch && !o.cold {
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
    let mut regressions = Vec::new();
    if let Some((prev_name, prev)) = last_file(&o.out, &host, &name) {
        for marker in ["first_tick", "presented"] {
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
        "icons_visible_warm_cache": "not measured: the stub engine sends no icons (M3-S1 owns the icon pipeline)",
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

/// The latest `*-<host>.json` under `dir` other than `exclude` (names start with the date and time).
fn last_file(dir: &Path, host: &str, exclude: &str) -> Option<(String, Value)> {
    let suffix = format!("-{host}.json");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.ends_with(&suffix)
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

    #[test]
    fn xaml_changes_are_read_from_the_extra_switches() {
        let args = ["--xaml-changes", "A,B"].map(str::to_owned).to_vec();
        assert_eq!(xaml_changes(&args), ["A", "B"]);
        assert!(xaml_changes(&[]).is_empty());
        assert!(xaml_changes(&["--theme".to_owned(), "dark".to_owned()]).is_empty());
    }
}
