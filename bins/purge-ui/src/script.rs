//! `--script`: a walk through the screens by made-up events, for a run with nobody at the
//! keyboard. Each step sends the application the same events the host would (a pointer press at
//! a control's middle, a key), waits for the frames to settle, checks what the model and the
//! declared controls say, and can write the frame as a PNG.
//!
//! It tests the application's reactions and its drawing into the bitmap. It does not test what
//! the screen shows, what Windows does with a real mouse, or what Narrator says.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_ui::host::{Button, Cx, Event, KeyPress};
use mdshared_ui::keys::{KeyName, Mods};

use crate::app::PurgeApp;
use crate::ui::Id;

type Act = fn(&mut PurgeApp, &mut Cx<'_, ()>);
type Check = fn(&PurgeApp) -> Result<String, String>;

pub struct Step {
    pub name: &'static str,
    pub act: Act,
    pub check: Check,
    /// How long the frames get to settle before the check, in ms.
    pub settle: u64,
}

enum Phase {
    Act,
    Check,
    Done,
}

pub struct Script {
    steps: Vec<Step>,
    at: usize,
    phase: Phase,
    due: Option<Instant>,
    shots: Option<PathBuf>,
    failed: Vec<&'static str>,
}

pub const CTRL: Mods = Mods {
    ctrl: true,
    shift: false,
    alt: false,
    control: false,
};
pub const SHIFT: Mods = Mods {
    ctrl: false,
    shift: true,
    alt: false,
    control: false,
};
pub const NONE: Mods = Mods {
    ctrl: false,
    shift: false,
    alt: false,
    control: false,
};

impl Script {
    pub fn new(shots: Option<PathBuf>) -> Script {
        Script {
            steps: crate::script_steps::steps(),
            at: 0,
            phase: Phase::Act,
            // The first step waits for the first frames.
            due: Some(Instant::now() + Duration::from_millis(700)),
            shots,
            failed: Vec::new(),
        }
    }

    pub fn due(&self) -> Option<Instant> {
        self.due
    }

    /// Runs what is due. False when the walk is over and the window may close.
    pub fn step(&mut self, app: &mut PurgeApp, cx: &mut Cx<'_, ()>, now: Instant) -> bool {
        match self.phase {
            Phase::Act => {
                let Some(step) = self.steps.get(self.at) else {
                    return self.finish();
                };
                (step.act)(app, cx);
                cx.request_redraw_all();
                self.phase = Phase::Check;
                self.due = Some(now + Duration::from_millis(step.settle));
                true
            }
            Phase::Check => {
                let step = &self.steps[self.at];
                match (step.check)(app) {
                    Ok(what) => println!("ok   {:02} {}: {what}", self.at + 1, step.name),
                    Err(what) => {
                        println!("FAIL {:02} {}: {what}", self.at + 1, step.name);
                        self.failed.push(step.name);
                    }
                }
                if let Some(dir) = &self.shots {
                    app.shot = Some(dir.join(format!("{:02}-{}.png", self.at + 1, step.name)));
                    cx.request_redraw_all();
                }
                self.at += 1;
                self.phase = if self.at < self.steps.len() {
                    Phase::Act
                } else {
                    Phase::Done
                };
                self.due = Some(now + Duration::from_millis(150));
                true
            }
            Phase::Done => self.finish(),
        }
    }

    fn finish(&mut self) -> bool {
        if self.failed.is_empty() {
            println!("script: {} steps, all ok", self.steps.len());
        } else {
            println!(
                "script: {} steps, {} FAILED: {}",
                self.steps.len(),
                self.failed.len(),
                self.failed.join(", ")
            );
        }
        self.due = None;
        false
    }
}

// ---- what a step may do ----------------------------------------------------------------------

impl PurgeApp {
    /// A click of the left button in the middle of the control `id`, as the host would send
    /// it. False when the last frame declared no such control.
    pub fn click(&mut self, cx: &mut Cx<'_, ()>, id: Id) -> bool {
        let Some(r) = self.ctl(id).map(|c| c.rect) else {
            println!("     (no control {id:?} to click)");
            return false;
        };
        self.click_at(cx, r.cx(), r.cy());
        true
    }

    pub fn click_at(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32) {
        use mdshared_ui::host::App;
        self.event(cx, Event::PointerMove { x, y });
        self.event(
            cx,
            Event::Press {
                x,
                y,
                button: Button::Left,
                clicks: 1,
            },
        );
        self.event(
            cx,
            Event::Release {
                x,
                y,
                button: Button::Left,
            },
        );
    }

    /// A key press with these modifiers.
    pub fn press_key(&mut self, cx: &mut Cx<'_, ()>, name: KeyName, mods: Mods) {
        use mdshared_ui::host::App;
        let text = match (&name, mods.ctrl || mods.alt) {
            (KeyName::Char(c), false) => Some(c.to_string()),
            (KeyName::Space, false) => Some(" ".to_string()),
            _ => None,
        };
        self.event(
            cx,
            Event::Key(KeyPress {
                name: Some(name),
                mods,
                text,
                repeat: false,
            }),
        );
    }

    pub fn type_text(&mut self, cx: &mut Cx<'_, ()>, text: &str) {
        for c in text.chars() {
            let name = if c == ' ' {
                KeyName::Space
            } else {
                KeyName::Char(c.to_ascii_lowercase())
            };
            self.press_key(cx, name, NONE);
        }
    }
}
