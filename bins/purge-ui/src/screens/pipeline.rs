//! The Uninstall pipeline page: one program going through the steps on a timer, the progress,
//! and what comes next when it is through. D2 lays the same run out as one flow: the steps in
//! a strip across the page, the step that runs in a card of its own, and the review of the
//! leftovers on the same page once the run is through.

use mdshared_ui::gfx::{Face, Rect};
use mdshared_ui::glyph;
use mdshared_ui::slider::draw_spinner;

use crate::model::{Design, LeftoverPhase, Model, Page, RunPhase, STEPS, StepState};
use crate::ui::{BUTTON_H, Id, Look, Role, Style, Tone, Ui, id, ok_ink};
use crate::view::{RESTORE_MODES, View};

const STEP_H: f32 = 58.0;
const FOOTER: &str = "Purge runs the program's own uninstaller. Nothing else is moved or removed until you confirm the list of leftovers.";
const SKIPPED: &str = "Restore points are switched off for this run.";

/// The mark of a step: in the list of D0 and in the strip of D2.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Done,
    Busy,
    /// The flow waits for the user here (D2's review).
    Yours,
    Waiting,
    Skipped,
}

impl Mark {
    fn of(state: StepState) -> Mark {
        match state {
            StepState::Done => Mark::Done,
            StepState::Running => Mark::Busy,
            StepState::Waiting => Mark::Waiting,
            StepState::Skipped => Mark::Skipped,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Mark::Done => "Done",
            Mark::Busy => "Running",
            Mark::Yours => "Your turn",
            Mark::Waiting => "Waiting",
            Mark::Skipped => "Skipped",
        }
    }
}

fn mark(ui: &mut Ui, mark: Mark, cx: f32, cy: f32, number: usize) {
    let pal = ui.pal;
    let r = Rect::new(cx - 11.0, cy - 11.0, 22.0, 22.0);
    match mark {
        Mark::Done => {
            if ui.hc {
                ui.p.ring(cx, cy, 10.0, 1.5, pal.text, 1.0);
                ui.p.icon(glyph::CHECK, 12.0, cx, cy, pal.text);
            } else {
                ui.p.rbox(r, 11.0, ok_ink(&pal));
                ui.p.icon(glyph::CHECK, 12.0, cx, cy, pal.page);
            }
        }
        Mark::Busy => {
            draw_spinner(ui.p, &pal, ui.cx.anim(), Id("StepSpinner", 0), cx, cy, 9.5);
        }
        Mark::Yours => {
            if ui.hc {
                ui.p.ring(cx, cy, 10.0, 2.5, pal.text, 1.0);
                ui.p.text_center(Face::Semibold, 11.5, r, &number.to_string(), pal.text);
            } else {
                ui.p.rbox(r, 11.0, pal.accent);
                ui.p.text_center(Face::Semibold, 11.5, r, &number.to_string(), pal.on_accent);
            }
        }
        Mark::Waiting => {
            ui.p.ring(cx, cy, 10.0, 1.25, pal.faint, 1.0);
            ui.p.text_center(Face::Ui, 11.5, r, &number.to_string(), pal.muted);
        }
        Mark::Skipped => {
            ui.p.ring(cx, cy, 10.0, 1.25, pal.faint, 1.0);
            ui.p.icon(glyph::MINUS, 11.0, cx, cy, pal.muted);
        }
    }
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    if ui.look.design == Design::Flow {
        return flow(ui, m, v, content);
    }
    let pal = ui.pal;
    let lk = ui.look;
    let pl = &m.pipeline;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;
    let now = ui.now;

    let y = content.y + 38.0;
    let (sub, route, tone) = match &pl.run {
        None => ("Nothing is running".to_string(), "Waiting", Tone::Neutral),
        Some(r) if r.phase == RunPhase::Finished => ("Finished".to_string(), "Done", Tone::Good),
        Some(r) => (
            format!(
                "Step {} of {}",
                r.step.min(STEPS.len() - 1) + 1,
                STEPS.len()
            ),
            "Running",
            Tone::Accent,
        ),
    };
    let cw = ui.chip_w(route);
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        w - cw - 16.0,
    );
    ui.chip(right - cw, y, route, tone);
    ui.reg(
        id("RouteText"),
        Rect::new(right - cw, y - 10.0, cw, 20.0),
        Role::Text,
        route,
        false,
    );

    let fy = footer(ui, content);

    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    let Some(run) = &pl.run else {
        nothing_card(ui, left, y, w);
        return;
    };
    let program = &m.programs.all[run.program.min(m.programs.all.len() - 1)];
    let finished = run.phase == RunPhase::Finished;

    // The whole run's progress.
    let f = pl.fraction(now);
    let status = if finished {
        format!("{} went through all {} steps.", program.name, STEPS.len())
    } else {
        STEPS[run.step.min(STEPS.len() - 1)].title.to_string()
    };
    if lk.hero {
        // D3: the run as one ring, with the program and the step beside it.
        let hero = Rect::new(left, y, w, 112.0);
        ui.card(hero);
        let (rcx, rcy, rr) = (hero.x + 64.0, hero.cy(), 36.0);
        let ink = if ui.hc {
            pal.text
        } else if finished {
            ok_ink(&pal)
        } else {
            pal.accent
        };
        ui.ring_gauge(rcx, rcy, rr, f, &format!("{:.0}%", f * 100.0), ink);
        let ring = Rect::new(rcx - rr, rcy - rr, rr * 2.0, rr * 2.0);
        ui.reg(
            id("OverallProgress"),
            ring,
            Role::Progress(Some(f)),
            "Uninstall progress",
            false,
        );
        let tx = hero.x + 124.0;
        let tw = hero.right() - 24.0 - tx;
        let caption = if finished {
            "FINISHED".to_string()
        } else {
            format!(
                "STEP {} OF {}",
                run.step.min(STEPS.len() - 1) + 1,
                STEPS.len()
            )
        };
        ui.p.text(
            Face::Semibold,
            11.0,
            tx,
            hero.y + 26.0,
            &caption,
            pal.muted,
            tw,
        );
        let status = ui.p.elide(Face::Semibold, 20.0, &status, tw);
        ui.text(
            id("ProgressText"),
            Face::Semibold,
            20.0,
            tx,
            hero.y + 52.0,
            &status,
            pal.text,
            tw,
        );
        ui.tile(
            Rect::new(tx, hero.y + 74.0, 22.0, 22.0),
            &program.name,
            &program.publisher,
        );
        let name = ui.p.elide(Face::Ui, 13.0, &program.name, tw * 0.5);
        let nw = ui.text(
            id("ProgramNameText"),
            Face::Ui,
            13.0,
            tx + 30.0,
            hero.y + 85.0,
            &name,
            pal.text,
            tw * 0.5,
        );
        let route = format!("\u{b7}  {}", route_text(m));
        let rx = tx + 30.0 + nw + 10.0;
        ui.text(
            id("RouteDetailText"),
            Face::Ui,
            12.0,
            rx,
            hero.y + 85.0,
            &route,
            pal.muted,
            hero.right() - 24.0 - rx,
        );
        y += hero.h + 16.0;
    } else {
        let size = if lk.soft { 15.0 } else { 13.0 };
        let face = if lk.soft { Face::Semibold } else { Face::Ui };
        let status = ui.p.elide(face, size, &status, w - 60.0);
        ui.text(
            id("ProgressText"),
            face,
            size,
            left,
            y + 8.0,
            &status,
            pal.text,
            w - 60.0,
        );
        ui.p.text_right(
            Face::Ui,
            12.0,
            right,
            y + 8.0,
            &format!("{:.0}%", f * 100.0),
            pal.muted,
        );
        ui.progress(
            id("OverallProgress"),
            Rect::new(left, y + 24.0, w, 4.0),
            Some(f),
            "Uninstall progress",
        );
        y += 44.0;
    }

    // What comes next, once the run is through.
    if finished {
        y += next_card(ui, m, left, y, w) + 16.0;
    }

    // The program and its steps at the left, the options at the right.
    let side_w = 330.0_f32.min(w * 0.36);
    // D3 has said the program in the ring's card: its steps begin under the command.
    let head_h = if lk.hero { 52.0 } else { 104.0 };
    let main = Rect::new(
        left,
        y,
        w - side_w - 16.0,
        head_h + STEPS.len() as f32 * STEP_H + 12.0,
    );
    let main = Rect::new(main.x, main.y, main.w, main.h.min(fy - 12.0 - y));
    ui.card(main);
    let old = ui.clip(main.inset(1.0));
    let x = main.x + 18.0;
    let mw = main.w - 36.0;
    if lk.hero {
        let command = ui.p.elide(Face::Mono, 12.0, &command_text(m), mw);
        ui.text(
            id("CommandText"),
            Face::Mono,
            12.0,
            x,
            main.y + 22.0,
            &command,
            pal.text,
            mw,
        );
        ui.divider(x, main.y + 40.0, mw);
    } else {
        ui.tile(
            Rect::new(x, main.y + 16.0, 36.0, 36.0),
            &program.name,
            &program.publisher,
        );
        let name = ui.p.elide(Face::Semibold, 15.0, &program.name, mw - 48.0);
        ui.text(
            id("ProgramNameText"),
            Face::Semibold,
            15.0,
            x + 48.0,
            main.y + 25.0,
            &name,
            pal.text,
            mw - 48.0,
        );
        let route = route_text(m);
        ui.text(
            id("RouteDetailText"),
            Face::Ui,
            12.0,
            x + 48.0,
            main.y + 44.0,
            &route,
            pal.muted,
            mw - 48.0,
        );
        let command = ui.p.elide(Face::Mono, 12.0, &command_text(m), mw);
        ui.text(
            id("CommandText"),
            Face::Mono,
            12.0,
            x,
            main.y + 70.0,
            &command,
            pal.text,
            mw,
        );
        ui.divider(x, main.y + 90.0, mw);
    }

    let sy = main.y + head_h;
    let host = Rect::new(x, sy, mw, STEPS.len() as f32 * STEP_H);
    ui.reg(id("StepperHost"), host, Role::Text, &status, false);
    if lk.soft
        && !ui.hc
        && let Some(i) = (0..STEPS.len()).find(|i| pl.state_of(*i) == StepState::Running)
    {
        // D1: the step that runs stands on a tint of the accent. Drawn before the steps, so
        // the line from the step above still reaches its mark.
        let fill = mdshared_ui::gfx::mix(ui.card_fill(), pal.accent, 0.12);
        let top = sy + i as f32 * STEP_H;
        ui.p.rbox(
            Rect::new(x - 8.0, top - 5.0, mw + 16.0, STEP_H - 2.0),
            8.0,
            fill,
        );
    }
    for (i, step) in STEPS.iter().enumerate() {
        let state = pl.state_of(i);
        let top = sy + i as f32 * STEP_H;
        let (cx, cy) = (x + 13.0, top + 15.0);
        let done_ink = ok_ink(&pal);

        // The line to the next step, drawn first so the mark lies over its end.
        if i + 1 < STEPS.len() {
            let c = if state == StepState::Done {
                done_ink
            } else {
                pal.line
            };
            ui.p.fill(Rect::new(cx - 1.0, cy + 13.0, 2.0, STEP_H - 26.0), c);
        }
        let mk = Mark::of(state);
        mark(ui, mk, cx, cy, i + 1);
        let word = mk.word();
        let word_ink = match state {
            StepState::Done => done_ink,
            StepState::Running => pal.accent,
            StepState::Waiting => pal.faint,
            StepState::Skipped => pal.muted,
        };
        let ww = ui.p.text_right(
            Face::Ui,
            12.0,
            x + mw,
            cy,
            word,
            if ui.hc { pal.text } else { word_ink },
        );
        let tx = x + 38.0;
        let tw = mw - 38.0 - ww - 12.0;
        let (face, ink) = match state {
            StepState::Running => (Face::Semibold, pal.text),
            StepState::Done => (Face::Ui, pal.text),
            _ => (Face::Ui, pal.muted),
        };
        ui.p.text(face, 14.0, tx, cy - 1.0, step.title, ink, tw);
        let detail = match state {
            StepState::Done => step.done,
            StepState::Skipped => SKIPPED,
            _ => step.detail,
        };
        let detail = ui.p.elide(Face::Ui, 12.0, detail, tw);
        ui.p.text(Face::Ui, 12.0, tx, cy + 18.0, &detail, pal.muted, tw);
        let label = format!("{}. {}: {word}. {detail}", i + 1, step.title);
        ui.reg(
            Id("Step", i as u32 + 1),
            Rect::new(x, top, mw, STEP_H),
            Role::Text,
            &label,
            false,
        );
        if state == StepState::Running {
            let bar = Rect::new(tx, cy + 31.0, tw.min(360.0), 3.0);
            ui.progress(
                Id("StepProgress", 0),
                bar,
                Some(pl.step_fraction(now)),
                step.title,
            );
        }
    }
    ui.p.restore(old);

    side_card(ui, m, Rect::new(right - side_w, y, side_w, main.h));
}

/// The line at the foot of the page. Returns where it begins.
fn footer(ui: &mut Ui, content: Rect) -> f32 {
    let pal = ui.pal;
    let left = content.x + ui.look.margin;
    let w = content.w - 2.0 * ui.look.margin;
    let fy = content.bottom() - 30.0;
    ui.divider(content.x + 1.0, fy, content.w);
    let footer = ui.p.elide(Face::Ui, 12.0, FOOTER, w);
    ui.text(
        id("FooterText"),
        Face::Ui,
        12.0,
        left,
        fy + 15.0,
        &footer,
        pal.muted,
        w,
    );
    fy
}

fn route_text(m: &Model) -> String {
    let pl = &m.pipeline;
    let Some(program) = pl.run.as_ref().and_then(|r| m.programs.all.get(r.program)) else {
        return String::new();
    };
    format!(
        "{} uninstaller \u{b7} {}",
        program.kind,
        if pl.quiet && program.quiet {
            "runs quietly"
        } else {
            "shows its own windows"
        }
    )
}

fn command_text(m: &Model) -> String {
    let pl = &m.pipeline;
    let Some(program) = pl.run.as_ref().and_then(|r| m.programs.all.get(r.program)) else {
        return String::new();
    };
    if pl.quiet && program.quiet {
        format!("{} /S", program.uninstall)
    } else {
        program.uninstall.clone()
    }
}

/// The card shown while nothing runs.
fn nothing_card(ui: &mut Ui, left: f32, y: f32, w: f32) {
    let pal = ui.pal;
    let text = "Select a program on the Programs page and choose Uninstall. It goes through the steps here, one program at a time, and you review what it left behind before anything moves.";
    let cw = w.min(620.0);
    let th = ui.p.paragraph_height(Face::Ui, 13.0, cw - 56.0, text);
    let card = Rect::new(
        left,
        y,
        cw,
        28.0 + 24.0 + 10.0 + th + 16.0 + BUTTON_H + 28.0,
    );
    ui.card(card);
    ui.reg(
        id("EmptyCard"),
        card,
        Role::Text,
        "Nothing is running",
        false,
    );
    let x = card.x + 28.0;
    ui.p.icon(glyph::DELETE, 18.0, x + 9.0, card.y + 40.0, pal.muted);
    ui.p.text(
        Face::Semibold,
        16.0,
        x + 28.0,
        card.y + 40.0,
        "Nothing is running",
        pal.text,
        cw - 84.0,
    );
    let ty = ui.para(Face::Ui, 13.0, x, card.y + 62.0, cw - 56.0, text, pal.muted);
    let bw = ui.button_w("Go to Programs", None);
    ui.button(
        id("GoPrograms"),
        Rect::new(x, ty + 16.0, bw, BUTTON_H),
        "Go to Programs",
        Style::Standard,
        None,
        true,
    );
}

/// What comes next, once the run is through. Returns the card's height.
fn next_card(ui: &mut Ui, m: &Model, left: f32, y: f32, w: f32) -> f32 {
    let pal = ui.pal;
    let pl = &m.pipeline;
    let name = pl
        .run
        .as_ref()
        .and_then(|r| m.programs.all.get(r.program))
        .map_or("The program", |p| p.name.as_str());
    let review = m.leftovers.phase == LeftoverPhase::Review;
    let (text, detail, button) = if review {
        (
            format!(
                "{name} is uninstalled. {} leftovers found.",
                m.leftovers.count()
            ),
            "Nothing has moved yet. Review the list before anything goes to quarantine."
                .to_string(),
            "Review leftovers",
        )
    } else if let Some(next) = pl.queue.first() {
        (
            format!("Next: {}", m.programs.all[*next].name),
            format!("{} waiting in the pipeline.", pl.queue.len()),
            "Uninstall next",
        )
    } else {
        (
            format!("{name} is uninstalled."),
            "Nothing else is waiting.".to_string(),
            "Back to Programs",
        )
    };
    let card = Rect::new(left, y, w, 66.0);
    ui.card(card);
    ui.p.icon(glyph::CHECK, 18.0, card.x + 27.0, card.cy(), ok_ink(&pal));
    let list = [
        (id("NextButton"), button, Style::Accent, None, true),
        (
            id("SkipButton"),
            "Skip",
            Style::Standard,
            None,
            review || !pl.queue.is_empty(),
        ),
    ];
    let bx = ui.buttons_right(card.right() - 18.0, card.cy() - BUTTON_H / 2.0, &list);
    let tw = bx - 16.0 - (card.x + 50.0);
    let text = ui.p.elide(Face::Semibold, 14.0, &text, tw);
    ui.text(
        id("NextText"),
        Face::Semibold,
        14.0,
        card.x + 50.0,
        card.cy() - 9.0,
        &text,
        pal.text,
        tw,
    );
    let detail = ui.p.elide(Face::Ui, 12.0, &detail, tw);
    ui.text(
        id("NextDetail"),
        Face::Ui,
        12.0,
        card.x + 50.0,
        card.cy() + 10.0,
        &detail,
        pal.muted,
        tw,
    );
    card.h
}

/// The options of this run, and what waits behind it.
fn side_card(ui: &mut Ui, m: &Model, side: Rect) {
    let pal = ui.pal;
    let pl = &m.pipeline;
    let Some(program) = pl.run.as_ref().and_then(|r| m.programs.all.get(r.program)) else {
        return;
    };
    ui.card(side);
    let old = ui.clip(side.inset(1.0));
    let x = side.x + 18.0;
    let sw = side.w - 36.0;
    let mut sy = side.y + 26.0;
    ui.p.text(Face::Semibold, 13.0, x, sy, "This run", pal.text, sw);
    sy += 20.0;
    sy = ui.fact(
        id("RestorePointValue"),
        x,
        sy,
        96.0,
        sw,
        "Restore point",
        RESTORE_MODES[pl.restore_mode.min(2)],
    );
    let quiet = if !pl.quiet {
        "Off: the uninstaller shows its windows"
    } else if program.quiet {
        "On"
    } else {
        "On, but this uninstaller has none"
    };
    sy = ui.fact(id("QuietNote"), x, sy, 96.0, sw, "Quiet mode", quiet);
    sy = ui.fact(
        id("SignerText"),
        x,
        sy,
        96.0,
        sw,
        "Signed by",
        &program.publisher,
    );
    if pl.state_of(0) == StepState::Done {
        sy += 4.0;
        ui.p.icon(glyph::CHECK, 14.0, x + 7.0, sy + 9.0, ok_ink(&pal));
        let made = format!(
            "Restore point \u{201c}Purge: before uninstalling {}\u{201d} was made.",
            program.name
        );
        let h =
            ui.p.paragraph(Face::Ui, 12.5, x + 22.0, sy, sw - 22.0, &made, pal.text);
        ui.reg(
            id("RestorePointMadeText"),
            Rect::new(x, sy, sw, h),
            Role::Text,
            &made,
            false,
        );
        sy += h + 6.0;
    }
    sy += 8.0;
    ui.divider(x, sy, sw);
    sy += 22.0;
    ui.p.text(
        Face::Semibold,
        13.0,
        x,
        sy,
        "Waiting behind it",
        pal.text,
        sw,
    );
    sy += 22.0;
    if pl.queue.is_empty() {
        ui.text(
            id("QueueEmpty"),
            Face::Ui,
            12.5,
            x,
            sy,
            "Nothing else is waiting.",
            pal.muted,
            sw,
        );
        sy += 24.0;
    }
    for (k, p) in pl.queue.iter().take(6).enumerate() {
        let g = &m.programs.all[*p];
        ui.tile(Rect::new(x, sy - 11.0, 22.0, 22.0), &g.name, &g.publisher);
        let name = if k == 5 && pl.queue.len() > 6 {
            format!("and {} more", pl.queue.len() - 5)
        } else {
            g.name.clone()
        };
        let name = ui.p.elide(Face::Ui, 13.0, &name, sw - 32.0);
        ui.text(
            Id("Queued", k as u32 + 1),
            Face::Ui,
            13.0,
            x + 32.0,
            sy,
            &name,
            pal.text,
            sw - 32.0,
        );
        sy += 30.0;
    }
    sy += 4.0;
    ui.divider(x, sy, sw);
    ui.para(
        Face::Ui,
        12.0,
        x,
        sy + 12.0,
        sw,
        "Purge never closes a program for you, and it removes nothing by itself: the uninstaller does the uninstalling.",
        pal.muted,
    );
    ui.p.restore(old);
}

// ---- D2: the run and the review as one flow ---------------------------------------------------

/// The height of the strip of stages, with the gap under it.
const STRIP_H: f32 = 76.0;
/// The stages of the flow: the six steps of the run, then the two that are the user's.
const STAGES: [&str; 8] = [
    "Restore point",
    "Program closed",
    "Record",
    "Uninstaller",
    "Check gone",
    "Find leftovers",
    "Review",
    "Quarantine",
];
const AT_REVIEW: usize = 7;
const AT_RESULT: usize = 8;
const AT_END: usize = 9;

/// Where the flow is: 0 with nothing running, 1 to 6 while that step runs, then the review,
/// the result of the review, and 9 when the run is through with nothing left to review.
fn stage(m: &Model) -> usize {
    match &m.pipeline.run {
        None => 0,
        Some(r) if r.phase != RunPhase::Finished => 1 + r.step.min(STEPS.len() - 1),
        Some(_) => match m.leftovers.phase {
            LeftoverPhase::Review => AT_REVIEW,
            LeftoverPhase::Moved | LeftoverPhase::Undone => AT_RESULT,
            _ => AT_END,
        },
    }
}

/// The stage D2's pipeline page shows; `None` for any other page or design. The window pushes
/// the old stage out when this changes.
pub fn flow_stage(m: &Model) -> Option<usize> {
    (m.design == Design::Flow && m.page == Page::Pipeline).then(|| stage(m))
}

/// The part of D2's pipeline page that changes with the stage: all of it under the strip.
pub fn flow_body(lk: &Look, content: Rect) -> Rect {
    let top = content.y + 76.0 + (lk.margin - 28.0) + STRIP_H;
    Rect::new(
        content.x + 1.0,
        top,
        content.w - 1.0,
        content.bottom() - top,
    )
}

fn flow(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let pl = &m.pipeline;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;
    let now = ui.now;
    let st = stage(m);
    let moved = m.leftovers.phase == LeftoverPhase::Moved;
    let name = pl
        .run
        .as_ref()
        .and_then(|r| m.programs.all.get(r.program))
        .map_or("", |p| p.name.as_str());

    // The title, and at its right what the flow waits for.
    let y = content.y + 38.0;
    let (sub, route, tone) = match st {
        0 => ("Nothing is running".to_string(), "Waiting", Tone::Neutral),
        AT_REVIEW => (
            format!("{name} \u{b7} {} leftovers to review", m.leftovers.count()),
            "Your turn",
            Tone::Caution,
        ),
        AT_RESULT if moved => (
            format!("{name} \u{b7} moved to quarantine"),
            "Done",
            Tone::Good,
        ),
        AT_RESULT => (format!("{name} \u{b7} put back"), "Done", Tone::Good),
        AT_END => (format!("{name} \u{b7} finished"), "Done", Tone::Good),
        _ => (
            format!("{name} \u{b7} step {st} of {}", STEPS.len()),
            "Running",
            Tone::Accent,
        ),
    };
    let mut edge = right;
    if st == AT_REVIEW {
        edge = super::leftovers::review_buttons(ui, m, right, y) - 12.0;
    }
    let cw = ui.chip_w(route);
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        edge - cw - 16.0 - left,
    );
    ui.chip(edge - cw, y, route, tone);
    ui.reg(
        id("RouteText"),
        Rect::new(edge - cw, y - 10.0, cw, 20.0),
        Role::Text,
        route,
        false,
    );

    // The strip: every stage, and how far the flow has come. The line out of the step that
    // runs fills as the step goes.
    let top = content.y + 76.0 + (lk.margin - 28.0);
    let cell = w / STAGES.len() as f32;
    let cy = top + 14.0;
    let done_ink = ok_ink(&pal);
    ui.reg(
        id("StepperHost"),
        Rect::new(left, top, w, 52.0),
        Role::Text,
        &sub,
        false,
    );
    for (k, stage_name) in STAGES.into_iter().enumerate() {
        let mk = if k < STEPS.len() {
            Mark::of(pl.state_of(k))
        } else if k == STEPS.len() {
            match st {
                AT_REVIEW => Mark::Yours,
                AT_RESULT => Mark::Done,
                AT_END => Mark::Skipped,
                _ => Mark::Waiting,
            }
        } else {
            match st {
                AT_RESULT if moved => Mark::Done,
                AT_RESULT => Mark::Skipped,
                _ => Mark::Waiting,
            }
        };
        let cx = left + cell * (k as f32 + 0.5);
        if k + 1 < STAGES.len() {
            let line = Rect::new(cx + 16.0, cy - 1.0, cell - 32.0, 2.0);
            ui.p.fill(line, pal.line);
            let f = match mk {
                Mark::Done => 1.0,
                Mark::Busy => pl.step_fraction(now),
                _ => 0.0,
            };
            if f > 0.0 {
                let ink = if ui.hc {
                    pal.text
                } else if mk == Mark::Busy {
                    pal.accent
                } else {
                    done_ink
                };
                ui.p.fill(Rect::new(line.x, line.y, line.w * f, line.h), ink);
            }
        }
        mark(ui, mk, cx, cy, k + 1);
        let shown = if k + 1 == STAGES.len() && st == AT_RESULT && !moved {
            "Put back"
        } else {
            stage_name
        };
        let (face, ink) = match mk {
            Mark::Busy | Mark::Yours => (Face::Semibold, pal.text),
            Mark::Done => (Face::Ui, pal.text),
            _ => (Face::Ui, pal.muted),
        };
        let label = ui.p.elide(face, 12.5, shown, cell - 8.0);
        let cell_r = Rect::new(cx - cell / 2.0, top, cell, 52.0);
        ui.p.text_center(
            face,
            12.5,
            Rect::new(cell_r.x, top + 30.0, cell, 20.0),
            &label,
            ink,
        );
        let title = STEPS.get(k).map_or(shown, |s| s.title);
        let said = format!("{}. {title}: {}", k + 1, mk.word());
        ui.reg(Id("Step", k as u32 + 1), cell_r, Role::Text, &said, false);
    }

    // Under the strip, the stage itself. The review and its result are the Leftovers page's
    // own, drawn here: the same boxes, the same model.
    let area = Rect::new(
        content.x,
        top + STRIP_H,
        content.w,
        content.bottom() - top - STRIP_H,
    );
    if st == AT_REVIEW || st == AT_RESULT {
        super::leftovers::body(ui, m, v, area);
        return;
    }
    let fy = footer(ui, content);
    match st {
        0 => nothing_card(ui, left, area.y, w),
        AT_END => {
            next_card(ui, m, left, area.y, w);
        }
        _ => {
            let side_w = 330.0_f32.min(w * 0.36);
            let h = 510.0_f32.min(fy - 12.0 - area.y);
            step_card(ui, m, Rect::new(left, area.y, w - side_w - 16.0, h));
            side_card(ui, m, Rect::new(right - side_w, area.y, side_w, h));
        }
    }
}

/// D2: the step that runs, alone in a card, with what is done under it.
fn step_card(ui: &mut Ui, m: &Model, r: Rect) {
    let pal = ui.pal;
    let pl = &m.pipeline;
    let Some(run) = &pl.run else { return };
    let Some(program) = m.programs.all.get(run.program) else {
        return;
    };
    let now = ui.now;
    ui.card(r);
    let old = ui.clip(r.inset(1.0));
    let x = r.x + 24.0;
    let w = r.w - 48.0;
    ui.tile(
        Rect::new(x, r.y + 22.0, 44.0, 44.0),
        &program.name,
        &program.publisher,
    );
    let name = ui.p.elide(Face::Semibold, 17.0, &program.name, w - 58.0);
    ui.text(
        id("ProgramNameText"),
        Face::Semibold,
        17.0,
        x + 58.0,
        r.y + 34.0,
        &name,
        pal.text,
        w - 58.0,
    );
    let route = route_text(m);
    ui.text(
        id("RouteDetailText"),
        Face::Ui,
        12.0,
        x + 58.0,
        r.y + 55.0,
        &route,
        pal.muted,
        w - 58.0,
    );
    let command = ui.p.elide(Face::Mono, 12.0, &command_text(m), w);
    ui.text(
        id("CommandText"),
        Face::Mono,
        12.0,
        x,
        r.y + 88.0,
        &command,
        pal.text,
        w,
    );
    ui.divider(x, r.y + 110.0, w);

    let i = run.step.min(STEPS.len() - 1);
    let step = &STEPS[i];
    let mut y = r.y + 136.0;
    let caption = format!("STEP {} OF {}", i + 1, STEPS.len());
    ui.text(
        id("StepCaption"),
        Face::Semibold,
        11.0,
        x,
        y,
        &caption,
        pal.muted,
        w,
    );
    y += 32.0;
    draw_spinner(
        ui.p,
        &pal,
        ui.cx.anim(),
        Id("StepSpinner", 1),
        x + 11.0,
        y,
        9.5,
    );
    let title = ui.p.elide(Face::Semibold, 22.0, step.title, w - 36.0);
    ui.text(
        id("ProgressText"),
        Face::Semibold,
        22.0,
        x + 36.0,
        y,
        &title,
        pal.text,
        w - 36.0,
    );
    y += 30.0;
    let detail = ui.p.elide(Face::Ui, 13.0, step.detail, w - 36.0);
    ui.text(
        id("StepDetail"),
        Face::Ui,
        13.0,
        x + 36.0,
        y,
        &detail,
        pal.muted,
        w - 36.0,
    );
    y += 26.0;
    let f = pl.step_fraction(now);
    let bar = Rect::new(x + 36.0, y, (w - 36.0 - 48.0).min(520.0), 4.0);
    ui.progress(Id("StepProgress", 0), bar, Some(f), step.title);
    ui.p.text_right(
        Face::Ui,
        12.0,
        bar.right() + 44.0,
        y + 2.0,
        &format!("{:.0}%", f * 100.0),
        pal.muted,
    );
    y += 30.0;
    ui.divider(x, y, w);
    y += 24.0;

    ui.p.text(Face::Semibold, 13.0, x, y, "Done so far", pal.text, w);
    y += 26.0;
    if i == 0 {
        ui.text(
            Id("DoneStep", 0),
            Face::Ui,
            12.5,
            x,
            y,
            "Nothing yet.",
            pal.muted,
            w,
        );
        y += 24.0;
    }
    for (k, before) in STEPS.iter().enumerate().take(i) {
        let skipped = pl.state_of(k) == StepState::Skipped;
        let (icon, ink) = if skipped {
            (glyph::MINUS, pal.muted)
        } else if ui.hc {
            (glyph::CHECK, pal.text)
        } else {
            (glyph::CHECK, ok_ink(&pal))
        };
        ui.p.icon(icon, 13.0, x + 7.0, y, ink);
        let said = if skipped { SKIPPED } else { before.done };
        let said = ui.p.elide(Face::Ui, 12.5, said, w - 24.0);
        ui.text(
            Id("DoneStep", k as u32 + 1),
            Face::Ui,
            12.5,
            x + 24.0,
            y,
            &said,
            pal.text,
            w - 24.0,
        );
        y += 24.0;
    }
    y += 8.0;
    let next = match STEPS.get(i + 1) {
        Some(s) => format!("Next: {}", s.title.to_lowercase()),
        None => "Next: you review what was found, before anything moves.".to_string(),
    };
    let next = ui.p.elide(Face::Ui, 12.5, &next, w);
    ui.text(
        id("NextStepText"),
        Face::Ui,
        12.5,
        x,
        y,
        &next,
        pal.muted,
        w,
    );
    ui.p.restore(old);
}
