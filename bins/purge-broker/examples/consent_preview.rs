//! The preview harness of the broker's toolkit consent dialog (package BROKER-CONSENT-UI): it draws
//! the dialog from sample views, without a broker, a pipe, an elevation or a plan. Nothing it shows
//! can be run: an answer is printed and forgotten.
//!
//! ```text
//! cargo run --release -p purge-broker --example consent_preview -- --list
//! cargo run --release -p purge-broker --example consent_preview -- --shots <dir> [--scale <n>]
//!         [--system-fonts]
//! cargo run --release -p purge-broker --example consent_preview -- <sample>[,<sample>...]
//!         [--theme light|dark|system] [--contrast] [--seconds <n>] [--shot <file.png>] [--gap <ms>]
//! cargo run --release -p purge-broker --example consent_preview -- --service <sample>[,<sample>...]
//!         [--gap <ms>] [--close-after <ms>]
//! ```
//!
//! - `--shots` draws every sample with the dialog's own measuring, layout and drawing into a bitmap
//!   (no window) and writes PNGs: light, dark and the two contrast palettes, and for some samples
//!   more states (the first second, the box ticked, the list at its end, the pointer on a button, a
//!   contrast theme of the system's kind, one that tries to hide the text, a larger scale).
//!   Drawn as the broker draws: with the three font files of `consent::toolkit::fonts` and the
//!   sheet as they can draw it. `--system-fonts` draws them instead with the system's font
//!   collection and the sheet unescaped, as the dialog drew before TK-1: the control of the
//!   planted-font test (`bins/purge-broker/tests/planted-font.ps1`).
//! - A sample's name opens the real window with the real loop (`consent::toolkit::app`), one sample
//!   after another in the one window, as the broker shows several dialogs in its life. `--seconds`
//!   closes each by itself after that long; `--shot` writes the first armed frame of each as
//!   `<file>` (with the sample's name before the extension when there are several); `--gap` waits
//!   that long between an answer and the next sample, the window hidden meanwhile (the rig's probe,
//!   `vm/guest/tests/consent-ui-probe.ps1`, uses it).
//!
//! - `--service` asks the samples through the broker's own consent service
//!   (`consent::toolkit::service::rehearse`): the real `ToolkitConsent` on a second thread and its
//!   window on the first, as in the broker under `--consent toolkit`. It prints `shown: <sample>`
//!   and `outcome: <sample>: <answer>`. `--close-after` fires each dialog's closer that long after
//!   it was asked for, as the broker does when its parent is gone: the answer is then `Declined`.
//!
//! The process ends by itself after two minutes without `--seconds`, and after the time the samples
//! need with it.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mdshared_ui::gfx::{Gfx, Painter, rgb};
use mdshared_ui::host::{self, Config, Proxy};
use mdshared_ui::platform;
use mdshared_ui::tokens::SystemColors;
use purge_broker::consent::dialog::{PRIMARY, pages};
use purge_broker::consent::sheet::{Sheet, sheet};
use purge_broker::consent::toolkit::app::{ConsentApp, Desk, Msg, opening_size, work_height};
use purge_broker::consent::toolkit::draw::{
    Frame, Hit, Layout, MAX_HEIGHT, MIN_HEIGHT, WIDTH, draw, measure,
};
use purge_broker::consent::toolkit::fonts;
use purge_broker::consent::toolkit::look::{Look, contrast_palette};
use purge_broker::consent::toolkit::service::{Trial, rehearse};
use purge_broker::consent::toolkit::state::{ARM_DELAY, Ctl, Prompt};
use purge_win::taskdialog::Outcome;

/// The sample views, built by the broker's own view functions (`src/consent/samples.rs`).
mod consent {
    pub use purge_broker::consent::{text, view};
    #[path = "../../src/consent/samples.rs"]
    pub mod samples;
}

use consent::samples;

const USAGE: &str = "consent_preview --list | --shots <dir> [--scale <n>] [--system-fonts] | <sample>[,<sample>...] \
                     [--theme light|dark|system] [--contrast] [--seconds <n>] [--shot <file.png>] [--gap <ms>] \
                     | --service <sample>[,<sample>...] [--gap <ms>] [--close-after <ms>]";

fn fail(why: &str) -> ! {
    eprintln!("consent_preview: {why}\n{USAGE}");
    std::process::exit(2);
}

// ---- pictures without a window -----------------------------------------------------------------

/// What a picture shows beyond the sample.
#[derive(Clone, Copy)]
struct Shot {
    /// The time since the dialog opened.
    after: Duration,
    /// The box is ticked.
    ticked: bool,
    /// The list is at its end.
    at_end: bool,
    /// The pointer is on this, and pressed.
    hover: Option<Hit>,
}

const OPEN: Shot = Shot {
    after: Duration::from_millis(1500),
    ticked: false,
    at_end: false,
    hover: None,
};

fn render(gfx: &mut Gfx, sh: &Arc<Sheet>, look: &Look, scale: f32, shot: Shot, out: &Path) {
    let mut scratch = mdshared_text::Bitmap::new(1, 1);
    let m = measure(
        &mut Painter::new(&mut scratch, gfx, scale),
        sh,
        WIDTH,
        scale,
    );
    let h = m.window_height(MAX_HEIGHT);
    let mut prompt = Prompt::new(sh.clone());
    let t0 = Instant::now();
    let now = t0 + shot.after;
    prompt.opened(t0);
    let mut lay = Layout::new(&m, (WIDTH, h), 0.0);
    if shot.at_end {
        lay = Layout::new(&m, (WIDTH, h), f32::MAX);
    }
    if lay.end_in_view() {
        prompt.saw_end(t0);
    }
    if shot.ticked {
        prompt.press(Ctl::Verify, now);
    }
    let mut bmp =
        mdshared_text::Bitmap::new((WIDTH * scale).round() as u32, (h * scale).round() as u32);
    let frame = Frame {
        now,
        hover: shot.hover,
        pressed: None,
    };
    draw(
        &mut Painter::new(&mut bmp, gfx, scale),
        look,
        &prompt,
        &m,
        &lay,
        &frame,
    );
    match bmp.write_png(out) {
        Ok(()) => println!("shot: {}", out.display()),
        Err(e) => fail(&format!("{}: {e}", out.display())),
    }
}

fn theme(window: u32, text: u32, highlight: u32, highlight_text: u32, gray: u32) -> SystemColors {
    SystemColors {
        window: rgb(window),
        window_text: rgb(text),
        highlight: rgb(highlight),
        highlight_text: rgb(highlight_text),
        hot_light: rgb(0x0063B1),
        gray_text: rgb(gray),
        button_face: rgb(window),
        button_text: rgb(text),
    }
}

/// The dialog's fonts, or the end of the preview: without them the broker draws no toolkit dialog.
fn dialog_fonts() -> mdshared_text::FixedFonts {
    fonts::system().unwrap_or_else(|e| fail(&format!("the dialog's fonts: {e}")))
}

/// `s`'s sheet as the window gets it from the broker (`fonts::sheet_for`).
fn drawn_sheet(fonts: &mdshared_text::FixedFonts, s: &samples::Sample) -> Sheet {
    fonts::sheet_for(fonts, &sheet(&s.view)).unwrap_or_else(|| {
        fail(&format!(
            "{}: the dialog's fonts cannot draw it (the broker asks with the TaskDialog)",
            s.name
        ))
    })
}

fn shots(dir: &Path, scale: f32, system_fonts: bool) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        fail(&format!("{}: {e}", dir.display()));
    }
    let fixed = (!system_fonts).then(dialog_fonts);
    let mut gfx = fixed.as_ref().map_or_else(Gfx::new, Gfx::with_fonts);
    let looks = [
        ("light", Look::of(false, false)),
        ("dark", Look::of(true, false)),
        ("contrast-light", Look::of(false, true)),
        ("contrast-dark", Look::of(true, true)),
    ];
    for s in samples::all() {
        let sh = Arc::new(match &fixed {
            Some(fonts) => drawn_sheet(fonts, &s),
            None => sheet(&s.view),
        });
        for (look_name, look) in &looks {
            let out = dir.join(format!("{}.{look_name}.png", s.name));
            render(&mut gfx, &sh, look, scale, OPEN, &out);
        }
        let states: &[(&str, Shot)] = match s.name {
            "quarantine" => &[
                (
                    "first-second",
                    Shot {
                        after: Duration::from_millis(300),
                        ..OPEN
                    },
                ),
                (
                    "ticked",
                    Shot {
                        ticked: true,
                        hover: Some(Hit::Ctl(Ctl::Approve)),
                        ..OPEN
                    },
                ),
            ],
            "quarantine-long" | "purge" => &[
                (
                    "end",
                    Shot {
                        at_end: true,
                        ..OPEN
                    },
                ),
                (
                    "end-ticked",
                    Shot {
                        at_end: true,
                        ticked: true,
                        ..OPEN
                    },
                ),
            ],
            "delete-now" => &[(
                "ticked",
                Shot {
                    ticked: true,
                    ..OPEN
                },
            )],
            _ => &[],
        };
        for (state, shot) in states {
            for (look_name, look) in &looks[..2] {
                let out = dir.join(format!("{}.{state}.{look_name}.png", s.name));
                render(&mut gfx, &sh, look, scale, *shot, &out);
            }
        }
        if s.name == "quarantine" {
            // Contrast themes as the system gives them: Windows' "Desert" and "Night sky", and one
            // whose text is the colour of its window, which the dialog refuses to draw with.
            for (name, colors, dark) in [
                (
                    "system-desert",
                    theme(0xFFFAEF, 0x3D3D3D, 0x903909, 0xFFF5E3, 0x676767),
                    false,
                ),
                (
                    "system-night-sky",
                    theme(0x000000, 0xFFFFFF, 0xD6B4FD, 0x2B2B2B, 0xA6A6A6),
                    true,
                ),
                (
                    "system-hidden-text",
                    theme(0x000000, 0x000000, 0xD6B4FD, 0xD6B4FD, 0x000000),
                    true,
                ),
            ] {
                let look = Look {
                    pal: contrast_palette(Some(&colors), dark),
                    contrast: true,
                };
                let out = dir.join(format!("{}.{name}.png", s.name));
                let shot = Shot {
                    ticked: true,
                    ..OPEN
                };
                render(&mut gfx, &sh, &look, scale, shot, &out);
            }
            let out = dir.join(format!("{}.scale-150.light.png", s.name));
            render(&mut gfx, &sh, &looks[0].1, 1.5, OPEN, &out);
        }
    }
}

// ---- the window --------------------------------------------------------------------------------

struct Waiting {
    id: u64,
    name: &'static str,
    sheet: Arc<Sheet>,
}

struct Queue {
    waiting: VecDeque<Waiting>,
    /// The one in the window: its id and name, and whether its picture is written.
    current: Option<(u64, &'static str, bool)>,
    proxy: Option<Proxy<Msg>>,
}

/// The preview's desk: the samples one after another, every answer printed.
#[derive(Clone)]
struct Preview {
    queue: Arc<Mutex<Queue>>,
    seconds: Option<u64>,
    shot: Option<PathBuf>,
    several: bool,
    /// How long the window stays hidden between an answer and the next sample.
    gap: Duration,
    /// When the process started: the first dialog says how long it took to come up.
    started: Instant,
}

impl Preview {
    /// The dialog `id` is done with: the next sample, or the end of the loop.
    fn advance(&self, id: u64) {
        let mut q = self.queue.lock().unwrap();
        if q.current.is_none_or(|c| c.0 != id) {
            return;
        }
        q.current = None;
        let Some(proxy) = q.proxy.clone() else { return };
        let next = q.waiting.front().map(|w| w.id);
        let gap = self.gap;
        std::thread::spawn(move || {
            std::thread::sleep(gap);
            match next {
                Some(id) => proxy.send(Msg::Show(id)),
                None => proxy.send(Msg::Quit),
            };
        });
    }

    fn shot_path(&self, name: &str) -> Option<PathBuf> {
        let path = self.shot.as_ref()?;
        if !self.several {
            return Some(path.clone());
        }
        let stem = path.file_stem()?.to_string_lossy();
        Some(path.with_file_name(format!("{stem}.{name}.png")))
    }
}

impl Desk for Preview {
    fn started(&self, proxy: Proxy<Msg>) {
        self.queue.lock().unwrap().proxy = Some(proxy);
    }

    fn take(&self, id: Option<u64>) -> Option<(u64, Arc<Sheet>)> {
        let mut q = self.queue.lock().unwrap();
        if q.waiting
            .front()
            .is_none_or(|w| id.is_some_and(|id| id != w.id))
        {
            return None;
        }
        let w = q.waiting.pop_front()?;
        q.current = Some((w.id, w.name, false));
        Some((w.id, w.sheet))
    }

    fn shown(&self, id: u64) {
        let (name, proxy) = {
            let q = self.queue.lock().unwrap();
            (q.current.map_or("?", |c| c.1), q.proxy.clone())
        };
        println!(
            "shown: {name} ({} ms after the start)",
            self.started.elapsed().as_millis()
        );
        if let (Some(seconds), Some(proxy)) = (self.seconds, proxy) {
            let desk = self.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(seconds));
                println!("closed after {seconds} s: {name}");
                proxy.send(Msg::Close(id));
                desk.advance(id);
            });
        }
    }

    fn answered(&self, id: u64, outcome: Outcome) {
        let name = self.queue.lock().unwrap().current.map_or("?", |c| c.1);
        println!("answered: {name}: {outcome:?}");
        self.advance(id);
    }

    fn frame(&self, id: u64, p: &mut Painter, open_for_ms: u128) {
        if open_for_ms < ARM_DELAY.as_millis() {
            return;
        }
        let name = {
            let mut q = self.queue.lock().unwrap();
            match q.current.as_mut() {
                Some(c) if c.0 == id && !c.2 => {
                    c.2 = true;
                    c.1
                }
                _ => return,
            }
        };
        if let Some(path) = self.shot_path(name) {
            match p.bmp.write_png(&path) {
                Ok(()) => println!("shot: {}", path.display()),
                Err(e) => println!("shot failed: {}: {e}", path.display()),
            }
        }
    }
}

fn main() {
    let started = Instant::now();
    let mut names: Vec<String> = Vec::new();
    let mut shots_dir: Option<PathBuf> = None;
    let mut scale = 1.0_f32;
    let mut theme_name = "system".to_owned();
    let mut contrast = false;
    let mut seconds: Option<u64> = None;
    let mut shot: Option<PathBuf> = None;
    let mut gap = Duration::ZERO;
    let mut service = false;
    let mut close_after: Option<Duration> = None;
    let mut system_fonts = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .unwrap_or_else(|| fail(&format!("{flag} needs a value")))
        };
        match a.as_str() {
            "--list" => {
                for s in samples::all() {
                    println!("{}", s.name);
                }
                return;
            }
            "--shots" => shots_dir = Some(PathBuf::from(value("--shots"))),
            "--scale" => {
                scale = value("--scale")
                    .parse()
                    .ok()
                    .filter(|s: &f32| (0.5..=4.0).contains(s))
                    .unwrap_or_else(|| fail("--scale takes a number from 0.5 to 4"));
            }
            "--theme" => theme_name = value("--theme"),
            "--contrast" => contrast = true,
            "--system-fonts" => system_fonts = true,
            "--seconds" => {
                seconds = Some(
                    value("--seconds")
                        .parse()
                        .unwrap_or_else(|_| fail("--seconds takes a whole number")),
                );
            }
            "--shot" => shot = Some(PathBuf::from(value("--shot"))),
            "--service" => service = true,
            "--close-after" => {
                close_after = Some(Duration::from_millis(
                    value("--close-after")
                        .parse()
                        .unwrap_or_else(|_| fail("--close-after takes a whole number of ms")),
                ));
            }
            "--gap" => {
                gap = Duration::from_millis(
                    value("--gap")
                        .parse()
                        .unwrap_or_else(|_| fail("--gap takes a whole number of ms")),
                );
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            flag if flag.starts_with("--") => fail(&format!("{flag} is not a switch")),
            list => names.extend(list.split(',').map(str::to_owned)),
        }
    }
    if let Some(dir) = shots_dir {
        shots(&dir, scale, system_fonts);
        return;
    }
    if names.is_empty() {
        fail("name a sample, or --list, or --shots <dir>");
    }
    let all = samples::all();
    // Nobody at the keyboard: the process never outlives its limit, whatever the loop does.
    let limit = seconds.map_or(120 + gap.as_secs() * names.len() as u64, |s| {
        (s + 3 + gap.as_secs()) * names.len() as u64 + 20
    });
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(limit));
        eprintln!("consent_preview: still running after {limit} s, the limit: ending the process");
        std::process::exit(124);
    });
    if service {
        let trials = names
            .iter()
            .map(|name| {
                let Some(s) = all.iter().find(|s| s.name == name) else {
                    fail(&format!("no sample is called {name:?} (see --list)"));
                };
                Trial {
                    name: s.name.to_owned(),
                    sheet: sheet(&s.view),
                    pages: pages(&s.view),
                    primary: PRIMARY,
                    close_after,
                }
            })
            .collect();
        rehearse(trials, gap, |line| println!("{line}"));
    }
    let fonts = dialog_fonts();
    let mut waiting = VecDeque::new();
    for (i, name) in names.iter().enumerate() {
        let Some(s) = all.iter().find(|s| s.name == name) else {
            fail(&format!("no sample is called {name:?} (see --list)"));
        };
        waiting.push_back(Waiting {
            id: i as u64 + 1,
            name: s.name,
            sheet: Arc::new(drawn_sheet(&fonts, s)),
        });
    }
    let look = match (theme_name.as_str(), contrast) {
        ("system", false) => None,
        ("system", true) => Some(Look::of(platform::system_is_dark(), true)),
        ("light", c) => Some(Look::of(false, c)),
        ("dark", c) => Some(Look::of(true, c)),
        _ => fail("--theme takes light, dark or system"),
    };
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(101);
    }));

    let first = waiting.front().map(|w: &Waiting| w.sheet.clone());
    let system_scale = platform::system_scale();
    let size = first.map_or((WIDTH, MIN_HEIGHT), |sh| {
        opening_size(
            &mut Gfx::with_fonts(&fonts),
            &sh,
            system_scale,
            work_height(system_scale),
        )
    });
    let dark = look.map_or_else(platform::system_is_dark, |l| l.pal.dark);
    let config = Config::new(purge_broker::consent::text::TITLE)
        .size(size.0, size.1)
        .min_size(WIDTH, MIN_HEIGHT)
        .app_id("Purge")
        .dark(dark)
        .fonts(fonts.clone());
    let desk = Preview {
        queue: Arc::new(Mutex::new(Queue {
            waiting,
            current: None,
            proxy: None,
        })),
        seconds,
        shot,
        several: names.len() > 1,
        gap,
        started,
    };
    if let Err(e) = host::run(config, ConsentApp::new(desk, look, &fonts)) {
        eprintln!("consent_preview: {e}");
        std::process::exit(1);
    }
    println!("done");
}
