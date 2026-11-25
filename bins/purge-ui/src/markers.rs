//! Launch markers, the port of `ui/Purge.App/Shell/LaunchMarkers.cs` (ENGINE_PLAN.md §9.2,
//! measurement (a)): each marker is the time in milliseconds since the kernel created this
//! process. When `PURGE_BENCH_OUT` names a file, the markers are appended to it as one line per
//! launch, `name=ms name=ms ...` with one decimal, once the bench's end marker is reached
//! (`cargo xtask bench-launch` reads the last line). Off the bench [`mark`] costs one check and
//! records nothing.
//!
//! The names are the WinUI app's where the step exists here: `main`, `window_ctor` (the host
//! starts the app), `first_tick` (the first frame is drawn), `presented` (after the next DWM
//! composition once the first frame was presented and the window shown), `rows_set`,
//! `names_visible` (the program names are in the first presented frame: `presented`'s time),
//! `icons_visible` (a live engine only: the first presented frame whose rows on screen all have
//! their icons settled: drawn from the atlas or `icon.batch`, or answered without one, which keeps
//! that row's tile), `engine_fallback` (the engine could not be used: the list is the sample
//! data) and `bench_timeout` (the `--bench-until` marker did not come within
//! [`BENCH_TIMEOUT`] of the first frame). `list_patched` is this app's own: the real engine's list
//! has the `programs.patch`es that follow its reply (`purge_client::startup::PATCH_WAIT`).
//!
//! Deliberately not here: TraceLogging, and the WinUI-only markers (`module_init`,
//! `on_launched`, the XAML steps).

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// The marker after which the bench writes its line (and, with `--bench-exit`, closes):
/// `--bench-until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchUntil {
    /// `presented`.
    Presented,
    /// `names_visible`, the default.
    Names,
    /// `icons_visible`.
    Icons,
}

impl BenchUntil {
    pub fn parse(s: &str) -> Option<BenchUntil> {
        match s {
            "presented" => Some(BenchUntil::Presented),
            "names_visible" => Some(BenchUntil::Names),
            "icons_visible" => Some(BenchUntil::Icons),
            _ => None,
        }
    }
}

/// A later `--bench-until` marker gets at most this long after the first frame (the WinUI
/// app's); then `bench_timeout` is marked and the line written as it is.
pub const BENCH_TIMEOUT: Duration = Duration::from_secs(20);

/// With `--bench-exit` and a live engine, the window waits at most this long after the end
/// marker for the icon load to end, so its atlas is saved for the next launch (the WinUI app's).
pub const ICONS_SAVE_WAIT: Duration = Duration::from_secs(10);

struct State {
    out: Option<String>,
    creation: i64,
    marks: Vec<(&'static str, f64)>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        let out = std::env::var("PURGE_BENCH_OUT")
            .ok()
            .filter(|s| !s.is_empty());
        let creation = if out.is_some() { creation_time() } else { 0 };
        Mutex::new(State {
            out,
            creation,
            marks: Vec::new(),
        })
    })
}

/// True when `PURGE_BENCH_OUT` names a file: the launch bench, and only then, keeps markers.
pub fn enabled() -> bool {
    state().lock().map(|s| s.out.is_some()).unwrap_or(false)
}

/// Records `name` now; returns its time, 0 off the bench.
pub fn mark(name: &'static str) -> f64 {
    let Ok(mut s) = state().lock() else {
        return 0.0;
    };
    if s.out.is_none() {
        return 0.0;
    }
    let ms = (now_filetime() - s.creation) as f64 / 10_000.0;
    s.marks.push((name, ms));
    ms
}

/// Records `name` at an earlier marker's time, or a value that is not a time.
pub fn record(name: &'static str, ms: f64) {
    if let Ok(mut s) = state().lock()
        && s.out.is_some()
    {
        s.marks.push((name, ms));
    }
}

/// The markers so far, for the Settings page's expander.
pub fn snapshot() -> Vec<(&'static str, f64)> {
    state().lock().map(|s| s.marks.clone()).unwrap_or_default()
}

/// The marker line: `name=ms` pairs, one decimal, a space between.
pub fn format(marks: &[(&str, f64)]) -> String {
    marks
        .iter()
        .map(|(n, ms)| format!("{n}={ms:.1}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Appends the line to `PURGE_BENCH_OUT`. A write that fails is ignored, as in the WinUI app.
pub fn flush() {
    let Ok(s) = state().lock() else { return };
    let Some(path) = &s.out else { return };
    use std::io::Write;
    let line = format(&s.marks);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Waits for the next DWM composition: "presented" is marked after it.
pub fn dwm_flush() {
    #[cfg(windows)]
    // SAFETY: DwmFlush takes no arguments and only blocks until the next composition.
    unsafe {
        windows_sys::Win32::Graphics::Dwm::DwmFlush();
    }
}

#[cfg(windows)]
fn creation_time() -> i64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the pseudo-handle of this process and four FILETIMEs owned by this frame.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        now_filetime()
    } else {
        filetime(creation)
    }
}

#[cfg(windows)]
fn now_filetime() -> i64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: writes the one FILETIME owned by this frame.
    unsafe { GetSystemTimePreciseAsFileTime(&mut ft) };
    filetime(ft)
}

#[cfg(windows)]
fn filetime(ft: windows_sys::Win32::Foundation::FILETIME) -> i64 {
    ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64
}

#[cfg(not(windows))]
fn creation_time() -> i64 {
    now_filetime()
}

#[cfg(not(windows))]
fn now_filetime() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() / 100) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_is_the_winui_apps() {
        let line = format(&[("main", 12.34), ("presented", 300.0)]);
        assert_eq!(line, "main=12.3 presented=300.0");
    }

    #[test]
    fn the_bench_ends_the_xtask_asks_for_are_known() {
        assert_eq!(BenchUntil::parse("presented"), Some(BenchUntil::Presented));
        assert_eq!(BenchUntil::parse("names_visible"), Some(BenchUntil::Names));
        assert_eq!(BenchUntil::parse("icons_visible"), Some(BenchUntil::Icons));
        assert_eq!(BenchUntil::parse("s3_open"), None);
    }

    #[test]
    fn the_process_began_before_now() {
        let c = creation_time();
        let n = now_filetime();
        assert!(c > 0 && n >= c, "creation {c}, now {n}");
    }
}
