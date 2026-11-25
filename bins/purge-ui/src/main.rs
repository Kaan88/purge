//! Interactive mockups of Purge's UI on the shared Rust toolkit (`mdshared-ui`).
//!
//! `cargo run --release -p purge-mockup [-- --design winui|refined|flow|bold]`
//!
//! Mockups only: nothing here talks to the engine, lists a real program, or removes anything.
//! All data is made up. See README.md and GAPS.md beside this crate.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_ui::host::{self, Config};
use mdshared_ui::platform;

mod app;
mod model;
mod screens;
mod script;
mod script_steps;
mod ui;
mod view;

use app::{Options, PurgeApp};
use model::{Design, ThemeChoice};

const HELP: &str = "purge-mockup: interactive mockups of Purge's UI. Nothing is uninstalled.

  --design <name>   winui (D0, default), refined (D1), flow (D2), bold (D3)
  --theme <name>    system (default), light, dark
  --seconds <n>     close by itself after n seconds
  --script          walk through the screens by made-up events, print what was checked, close
  --shots <dir>     with --script: write a PNG of the frame after each step
  --timeout <n>     end the process after n seconds, whatever it is doing
                    (default: 180 with --script, n + 15 with --seconds, none otherwise)

In the window: Ctrl+Shift+D switches design (so does Settings), Ctrl+F searches,
Ctrl+1..6 opens a page, Ctrl+K opens the command palette.";

/// The hard limit of a `--script` run, in seconds: the walk itself takes about 70.
const SCRIPT_LIMIT_S: u64 = 180;

fn main() {
    let launched = Instant::now();
    let mut o = Options {
        design: Design::Winui,
        seconds: None,
        script: false,
        shots: None,
        theme: ThemeChoice::System,
        launched,
    };
    let mut timeout: Option<u64> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--design" => match args.next().as_deref().and_then(Design::parse) {
                Some(d) => o.design = d,
                None => {
                    eprintln!("purge-mockup: --design takes winui, refined, flow or bold");
                    std::process::exit(2);
                }
            },
            "--theme" => {
                o.theme = match args.next().as_deref() {
                    Some("light") => ThemeChoice::Light,
                    Some("dark") => ThemeChoice::Dark,
                    _ => ThemeChoice::System,
                }
            }
            "--seconds" => o.seconds = args.next().and_then(|s| s.parse().ok()),
            "--script" => o.script = true,
            "--timeout" => timeout = args.next().and_then(|s| s.parse().ok()),
            "--shots" => o.shots = args.next().map(PathBuf::from),
            "--help" | "-h" | "/?" => {
                println!("{HELP}");
                return;
            }
            other => {
                eprintln!("purge-mockup: unknown argument {other}\n\n{HELP}");
                std::process::exit(2);
            }
        }
    }
    // A panic inside the event loop's callback does not end the process by itself: the loop
    // was seen to go on spinning at full CPU. So a panic prints what it has to say and ends
    // the process here.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(101);
    }));
    // A run with nobody at the keyboard never outlives its limit, whatever the loop does: the
    // watchdog is a thread of its own and asks nothing of the event loop.
    let limit = timeout.or(match (o.script, o.seconds) {
        (true, _) => Some(SCRIPT_LIMIT_S),
        (false, Some(s)) => Some(s + 15),
        (false, None) => None,
    });
    if let Some(limit) = limit {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(limit));
            eprintln!("purge-mockup: still running after {limit} s, the limit: ending the process");
            std::process::exit(124);
        });
    }
    let dark = match o.theme {
        ThemeChoice::System => platform::system_is_dark(),
        ThemeChoice::Light => false,
        ThemeChoice::Dark => true,
    };
    let config = Config::new("Purge (mockup)")
        .size(1360.0, 860.0)
        .min_size(1080.0, 700.0)
        .app_id("purge-mockup")
        .dark(dark);
    if let Err(e) = host::run(config, PurgeApp::new(o)) {
        eprintln!("purge-mockup: {e}");
        std::process::exit(1);
    }
}
