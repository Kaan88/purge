//! `Purge.exe`, the window (docs/UI_RUST_PLAN.md), on the shared Rust toolkit `mdshared-ui`. Its
//! look is the approved mockup's (`mockup/rust-ui`, 1225d9a): one combined design and Bold, the
//! colour presets in light and dark, the page transitions, high contrast.
//!
//! This is the shell (UI-SHELL): the host loop, the accessibility tree, the title row, the rail,
//! the pages, the settings, the launch markers. The pages still draw the mockup's placeholder data
//! (`model`); wave 2 feeds them from `purge-ui-model` and `purge-client`.
#![windows_subsystem = "windows"]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_ui::host::{self, Config};
use mdshared_ui::platform;

mod app;
mod look;
mod markers;
mod model;
mod prefs;
mod screens;
mod script;
mod script_steps;
mod transition;
mod ui;
mod view;

use app::{Options, PurgeApp};
use look::{Choice, Design, Preset, ThemeChoice, Transition};
use model::Page;
use prefs::Store;

const HELP: &str = "Purge: uninstalls programs and what they leave behind.

  --theme <name>       system, light or dark, for this run (the saved choice is kept)
  --look <name>        standard or bold, for this run
  --colour <name>      windows, blue, teal, violet, amber, rose or graphite, for this run
  --transition <name>  none, fade, slide, slide-side, flow, slide-up, scale or depth, for this run
  --page <key>         open on programs, queue, leftovers, history, vault or settings
  --sample             show the sample data without starting the engine
  --bench-exit         close once the launch markers are written (PURGE_BENCH_OUT)
  --bench-until <m>    the marker the bench waits for: presented (the only one yet)
  --seconds <n>        close by itself after n seconds
  --script             walk through the screens by made-up events, print what was checked,
                       close; starts from the default settings and saves nothing
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
    let mut page = Page::Programs;
    let mut seconds: Option<u64> = None;
    let mut script = false;
    let mut shots: Option<PathBuf> = None;
    let mut bench_exit = false;
    let mut timeout: Option<u64> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--theme" => theme = Some(choice("--theme", args.next())),
            "--look" | "--design" => design = Some(choice("--look", args.next())),
            "--colour" | "--color" => preset = Some(choice("--colour", args.next())),
            "--transition" => transition = Some(choice("--transition", args.next())),
            "--page" => match args.next().as_deref().and_then(Page::parse_key) {
                Some(p) => page = p,
                None => {
                    eprintln!(
                        "Purge: --page takes programs, queue, leftovers, history, vault or settings"
                    );
                    std::process::exit(2);
                }
            },
            // The shell shows the sample data in every run until wave 2 starts the engine.
            "--sample" | "--bench-stub" => {}
            "--bench-exit" => bench_exit = true,
            "--bench-until" => match args.next().as_deref() {
                Some("presented" | "names_visible") => {}
                other => {
                    eprintln!("Purge: --bench-until takes presented, not {other:?}");
                    std::process::exit(2);
                }
            },
            "--seconds" => seconds = args.next().and_then(|s| s.parse().ok()),
            "--script" => script = true,
            "--timeout" => timeout = args.next().and_then(|s| s.parse().ok()),
            "--shots" => shots = args.next().map(PathBuf::from),
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

    let config = Config::new("Purge")
        .size(1360.0, 860.0)
        .min_size(1080.0, 700.0)
        .app_id("Purge")
        .icon_png(include_bytes!("../assets/Purge.png"))
        .dark(prefs.theme.dark(platform::system_is_dark()));
    let o = Options {
        prefs,
        saved,
        store,
        page,
        bench_exit,
        seconds,
        script,
        shots,
        launched,
    };
    if let Err(e) = host::run(config, PurgeApp::new(o)) {
        eprintln!("Purge: {e}");
        std::process::exit(1);
    }
}
