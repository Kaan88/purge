//! `Purge.exe`, the window (docs/UI_RUST_PLAN.md), on the shared Rust toolkit `mdshared-ui`. Its
//! look is the approved mockup's (`mockup/rust-ui`, 1225d9a): one combined design and Bold, the
//! colour presets in light and dark, the page transitions, high contrast.
//!
//! The shell (UI-SHELL) is the host loop, the accessibility tree, the title row, the rail, the
//! pages, the settings and the launch markers. The Programs page is fed by the engine
//! (`purge-engine.exe` beside this exe) through `link` (UI-WIRE); the other pages wait for wave 2
//! (`model`).
#![windows_subsystem = "windows"]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_ui::host::{self, Config};
use mdshared_ui::platform;

mod app;
mod clock;
mod flow;
// UI-FULLFROST.
mod glass;
mod icons;
mod link;
mod look;
mod markers;
mod model;
mod paint;
mod prefs;
mod sample_broker;
mod screens;
mod script;
mod script_steps;
mod transition;
mod ui;
mod view;
mod winplace;

use app::{Options, PurgeApp};
use look::{Choice, Design, Preset, ThemeChoice, Transition};
use markers::BenchUntil;
use mdshared_app::backdrop::Backdrop;
use model::Page;
use prefs::Store;

const HELP: &str = "Purge: uninstalls programs and what they leave behind.

  --theme <name>       system, light or dark, for this run (the saved choice is kept)
  --look <name>        standard or bold, for this run
  --colour <name>      windows, blue, teal, violet, amber, rose or graphite, for this run
  --transition <name>  none, fade, slide, slide-side, flow, slide-up, scale or depth, for this run
  --backdrop <name>    off, mica or acrylic, for this run
  --backdrop-covers <c> chrome (the title row and the rail) or window (the whole window),
                       for this run
  --backdrop-strength <n>  0 to 100: how much of the backdrop shows, for this run
  --page <key>         open on programs, queue, leftovers, history, vault or settings
  --sample             show the sample data without starting the engine
  --bench-stub         the launch bench's sample engine: 300 rows, no engine started
  --bench-exit         close once the launch markers are written (PURGE_BENCH_OUT)
  --bench-until <m>    the marker the bench waits for: presented, names_visible (the
                       default: the program names are in a presented frame) or icons_visible
                       (the rows on screen show their icons; a live engine only)
  --seconds <n>        close by itself after n seconds
  --shot <file>        with --seconds: write a PNG of the last frame before closing
  --script             walk through the screens by made-up events on the sample data,
                       print what was checked, close; starts from the default settings and
                       saves nothing
  --shots <dir>        with --script: write a PNG of the frame after each step
  --timeout <n>        end the process after n seconds, whatever it is doing
                       (default: 240 with --script, n + 15 with --seconds, none otherwise)

In the window: Ctrl+F searches, Ctrl+1..6 opens a page, Ctrl+K opens the command palette.";

/// The hard limit of a `--script` run, in seconds: the walk itself takes about 90.
const SCRIPT_LIMIT_S: u64 = 240;

/// A value of a choice on the command line, or the end of the run with a usage message.
fn choice<C: Choice>(flag: &str, value: Option<String>) -> C {
    match value.as_deref().and_then(C::parse) {
        Some(v) => v,
        None => {
            eprintln!("Purge: {flag} takes one of {}", C::names());
            std::process::exit(2);
        }
    }
}

fn main() {
    let launched = Instant::now();
    markers::mark("main");
    let mut theme: Option<ThemeChoice> = None;
    let mut design: Option<Design> = None;
    let mut preset: Option<Preset> = None;
    let mut transition: Option<Transition> = None;
    let mut backdrop: Option<Backdrop> = None;
    // UI-FULLFROST.
    let mut covers: Option<look::Covers> = None;
    let mut strength: Option<u8> = None;
    let mut page = Page::Programs;
    let mut seconds: Option<u64> = None;
    let mut script = false;
    let mut shots: Option<PathBuf> = None;
    let mut shot_at_end: Option<PathBuf> = None;
    let mut bench_exit = false;
    let mut bench_until = BenchUntil::Names;
    let mut source: Option<link::Source> = None;
    let mut timeout: Option<u64> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--theme" => theme = Some(choice("--theme", args.next())),
            "--look" | "--design" => design = Some(choice("--look", args.next())),
            "--colour" | "--color" => preset = Some(choice("--colour", args.next())),
            "--transition" => transition = Some(choice("--transition", args.next())),
            "--backdrop" => backdrop = Some(choice("--backdrop", args.next())),
            // UI-FULLFROST.
            "--backdrop-covers" => covers = Some(choice("--backdrop-covers", args.next())),
            "--backdrop-strength" => match args.next().as_deref().and_then(glass::parse_strength) {
                Some(n) => strength = Some(n),
                None => {
                    eprintln!("Purge: --backdrop-strength takes a number from 0 to 100");
                    std::process::exit(2);
                }
            },
            "--page" => match args.next().as_deref().and_then(Page::parse_key) {
                Some(p) => page = p,
                None => {
                    eprintln!(
                        "Purge: --page takes programs, queue, leftovers, history, vault or settings"
                    );
                    std::process::exit(2);
                }
            },
            "--sample" => source = Some(link::Source::Sample { bench_rows: 0 }),
            // The WinUI bench's stub: hello and 300 rows, answered at once.
            "--bench-stub" => source = Some(link::Source::Sample { bench_rows: 300 }),
            "--bench-exit" => bench_exit = true,
            "--bench-until" => match args.next().as_deref().and_then(BenchUntil::parse) {
                Some(u) => bench_until = u,
                None => {
                    eprintln!(
                        "Purge: --bench-until takes presented, names_visible or icons_visible"
                    );
                    std::process::exit(2);
                }
            },
            "--seconds" => seconds = args.next().and_then(|s| s.parse().ok()),
            "--script" => script = true,
            "--timeout" => timeout = args.next().and_then(|s| s.parse().ok()),
            "--shots" => shots = args.next().map(PathBuf::from),
            "--shot" => shot_at_end = args.next().map(PathBuf::from),
            "--help" | "-h" | "/?" => {
                println!("{HELP}");
                return;
            }
            // Like the WinUI app, a switch this build does not know is passed over: the bench
            // and the rig give switches of their own.
            other => eprintln!("Purge: {other} is not a switch of this build; passed over"),
        }
    }
    // A panic inside the event loop's callback was seen not to end the process (the loop went
    // on spinning at full CPU). So a panic prints what it has to say and ends the process here.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(101);
    }));
    // A run with nobody at the keyboard never outlives its limit, whatever the loop does: the
    // watchdog is a thread of its own and asks nothing of the event loop.
    let limit = timeout.or(match (script, seconds) {
        (true, _) => Some(SCRIPT_LIMIT_S),
        (false, Some(s)) => Some(s + 15),
        (false, None) => None,
    });
    if let Some(limit) = limit {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(limit));
            eprintln!("Purge: still running after {limit} s, the limit: ending the process");
            std::process::exit(124);
        });
    }

    // The walk starts from the defaults and writes no settings file.
    let mut store = if script { Store::none() } else { Store::user() };
    let saved = store.load();
    let mut prefs = saved;
    prefs.theme = theme.unwrap_or(prefs.theme);
    prefs.design = design.unwrap_or(prefs.design);
    prefs.preset = preset.unwrap_or(prefs.preset);
    prefs.transition = transition.unwrap_or(prefs.transition);
    prefs.backdrop = backdrop.unwrap_or(prefs.backdrop);
    // UI-FULLFROST.
    prefs.glass.covers = covers.unwrap_or(prefs.glass.covers);
    prefs.glass.strength = strength.unwrap_or(prefs.glass.strength);

    // The window's place is remembered only in a run a person sees: the walk, a timed run (and its
    // shot) and the launch bench keep a fixed size and the system's position, and neither read
    // nor write the saved place (`winplace`).
    let bench = bench_exit
        || std::env::var_os("PURGE_BENCH_OUT").is_some_and(|v| !v.is_empty())
        || matches!(source, Some(link::Source::Sample { bench_rows }) if bench_rows > 0);
    let remember_place = !script && !bench && seconds.is_none() && shot_at_end.is_none();
    let size = if remember_place {
        winplace::DEFAULT
    } else {
        winplace::FIXED
    };
    let config = Config::new("Purge")
        .size(size.0, size.1)
        .min_size(winplace::MIN.0, winplace::MIN.1)
        .app_id("Purge")
        .icon_png(include_bytes!("../assets/Purge.png"))
        .dark(prefs.theme.dark(platform::system_is_dark()));
    let o = Options {
        prefs,
        saved,
        store,
        remember_place,
        page,
        bench_exit,
        bench_until,
        // The walk checks what it knows: the sample data.
        source: if script {
            link::Source::Sample { bench_rows: 0 }
        } else {
            source.unwrap_or_else(link::Source::beside_exe)
        },
        seconds,
        script,
        shots,
        shot_at_end,
        launched,
    };
    if let Err(e) = host::run(config, PurgeApp::new(o)) {
        eprintln!("Purge: {e}");
        std::process::exit(1);
    }
}
