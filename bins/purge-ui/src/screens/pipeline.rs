//! The Uninstall page, drawn from `purge-ui-model`'s [`UninstallPageView`] (UI-FLOW): the
//! program and its route, the exact command, the five steps, the quiet and restore-point choices,
//! the bars with their actions, and the card of the next queued program. D2 lays the same run out
//! as one flow: the steps in a strip across the page, the step that runs in a card of its own, and
//! the review of the leftovers on the same page once the scan is in.

use mdshared_ui::gfx::{Face, Rect, Wrap};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Severity};
use mdshared_ui::slider::draw_spinner;
use purge_ui_model::leftovers::LeftoversPhase;
use purge_ui_model::pipeline::page::{Bar, BarClose, UninstallPageView};
use purge_ui_model::pipeline::{NoticeKind, StepState, UninstallStep};

use crate::model::{Model, Page};
use crate::ui::{BUTTON_H, Id, Look, Role, Style, Tone, Ui, id, ok_ink};
use crate::view::{DD_RESTORE, View};

const STEP_H: f32 = 58.0;
/// How many buttons a bar may have: its buttons' ids are `BarButton_{bar * BAR_BUTTONS + k + 1}`.
pub const BAR_BUTTONS: u32 = 8;

/// The mark of a step: in the list of D0 and in the strip of D2.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Done,
    Busy,
    /// The flow waits for the user here (D2's review).
    Yours,
    Waiting,
    Warning,
    Failed,
    Skipped,
}

impl Mark {
    fn of(state: StepState) -> Mark {
        match state {
            StepState::Done => Mark::Done,
            StepState::Active => Mark::Busy,
            StepState::Pending => Mark::Waiting,
            StepState::Warning => Mark::Warning,
            StepState::Failed => Mark::Failed,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Mark::Done => "Done",
            Mark::Busy => "Running",
            Mark::Yours => "Your turn",
            Mark::Waiting => "Waiting",
            Mark::Warning => "Done, with a warning",
            Mark::Failed => "Failed",
            Mark::Skipped => "Skipped",
        }
    }
}

/// `key` tells apart the marks drawn at once (the spinner animates by it).
fn mark(ui: &mut Ui, mark: Mark, cx: f32, cy: f32, number: usize, key: u32) {
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
            draw_spinner(
                ui.p,
                &pal,
                ui.cx.anim(),
                Id("StepSpinner", key),
                cx,
                cy,
                9.5,
            );
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
        Mark::Warning | Mark::Failed => {
            let (g, ink) = if mark == Mark::Warning {
                (
                    glyph::WARN,
                    mdshared_ui::infobar::severity_colors(Severity::Warning, &pal).ink,
                )
            } else {
                (
                    glyph::CLOSE,
                    mdshared_ui::infobar::severity_colors(Severity::Error, &pal).ink,
                )
            };
            let ink = if ui.hc { pal.text } else { ink };
            ui.p.ring(cx, cy, 10.0, 1.5, ink, 1.0);
            ui.p.icon(g, 12.0, cx, cy, ink);
        }
        Mark::Skipped => {
            ui.p.ring(cx, cy, 10.0, 1.25, pal.faint, 1.0);
            ui.p.icon(glyph::MINUS, 11.0, cx, cy, pal.muted);
        }
    }
}

fn severity(kind: NoticeKind) -> Severity {
    match kind {
        NoticeKind::Info => Severity::Info,
        NoticeKind::Warning => Severity::Warning,
        NoticeKind::Error => Severity::Error,
    }
}

/// The page's bars from `y`, each one Text `InfoBarHost[_n]` named "Title Message", with its
/// buttons and close button. Returns the y under them.
fn bars(ui: &mut Ui, bars: &[Bar], x: f32, mut y: f32, w: f32) -> f32 {
    for (k, b) in bars.iter().enumerate() {
        let mut bar =
            InfoBar::new(severity(b.kind), &b.title, &b.message).closable(b.close != BarClose::No);
        let mut ids = Vec::new();
        for (j, button) in b.buttons.iter().enumerate() {
            if button.enabled {
                bar = bar.action(ids.len() as u32, button.label);
                ids.push(Id("BarButton", k as u32 * BAR_BUTTONS + j as u32 + 1));
            }
        }
        let close = (b.close != BarClose::No).then_some(Id("BarClose", k as u32 + 1));
        y = ui.infobar_with(Id("InfoBarHost", k as u32), x, y, w, &bar, close, &ids) + 8.0;
    }
    y
}

/// The share of the run that is through, for the bars and the ring.
fn fraction(v: &UninstallPageView) -> f32 {
    let done = v
        .steps
        .iter()
        .map(|s| match s.state {
            StepState::Done | StepState::Warning | StepState::Failed => 1.0,
            StepState::Active => 0.5,
            StepState::Pending => 0.0,
        })
        .sum::<f32>();
    done / v.steps.len().max(1) as f32
}

/// The step the stepper names now: the active one, else the last one reached.
fn current(v: &UninstallPageView) -> usize {
    v.steps
        .iter()
        .position(|s| s.state == StepState::Active)
        .or_else(|| v.steps.iter().rposition(|s| s.state != StepState::Pending))
        .unwrap_or(0)
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    if ui.look.flow {
        return flow(ui, m, v, content);
    }
    let pal = ui.pal;
    let lk = ui.look;
    let pv = m.flow.page.view(m.flow_env());
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;

    let y = content.y + 38.0;
    heading(ui, m, &pv, left, right, y);

    let fy = footer(ui, content, pv.footer);
    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    y = super::sample_bar(ui, m, left, y, w);
    y = bars(ui, &m.flow_bars(), left, y, w);
    if pv.empty {
        nothing_card(ui, left, y, w, pv.footer);
        return;
    }

    // The whole run's progress.
    let f = fraction(&pv);
    let at = current(&pv);
    let status = pv.steps.get(at).map_or("", |s| s.title).to_string();
    if lk.hero {
        // D3: the run as one ring, with the program and the step beside it.
        let hero = Rect::new(left, y, w, 112.0);
        ui.card(hero);
        let (rcx, rcy, rr) = (hero.x + 64.0, hero.cy(), 36.0);
        let ink = if ui.hc { pal.text } else { pal.accent };
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
        let caption = format!("STEP {} OF {}", at + 1, pv.steps.len());
        ui.p.text(
            Face::Semibold,
            11.0,
            tx,
            hero.y + 26.0,
            &caption,
            pal.muted,
            tw,
        );
        let s = ui.p.elide(Face::Semibold, 20.0, &status, tw);
        ui.text(
            id("ProgressText"),
            Face::Semibold,
            20.0,
            tx,
            hero.y + 52.0,
            &s,
            pal.text,
            tw,
        );
        ui.say_whole(&status);
        ui.tile(
            Rect::new(tx, hero.y + 74.0, 22.0, 22.0),
            &pv.program_name,
            "",
        );
        let name = ui.p.elide(Face::Ui, 13.0, &pv.program_name, tw * 0.5);
        ui.text(
            id("ProgramNameText"),
            Face::Ui,
            13.0,
            tx + 30.0,
            hero.y + 85.0,
            &name,
            pal.text,
            tw * 0.5,
        );
        ui.say_whole(&pv.program_name);
        y += hero.h + 16.0;
    } else {
        let size = if lk.soft { 15.0 } else { 13.0 };
        let face = if lk.soft { Face::Semibold } else { Face::Ui };
        let s = ui.p.elide(face, size, &status, w - 60.0);
        ui.text(
            id("ProgressText"),
            face,
            size,
            left,
            y + 8.0,
            &s,
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

    if let Some(h) = next_card(ui, &pv, left, y, w) {
        y += h + 12.0;
    }
    if let Some(h) = running_card(ui, &pv, left, y, w) {
        y += h + 12.0;
    }

    // The program and its steps at the left, the choices at the right.
    let side_w = 330.0_f32.min(w * 0.36);
    // The command is shown in full: a long one grows the head of the card.
    let extra = command_extra(ui, &pv, w - side_w - 16.0 - 36.0);
    let head_h = if lk.hero { 60.0 } else { 112.0 } + extra;
    let main = Rect::new(
        left,
        y,
        w - side_w - 16.0,
        (head_h + pv.steps.len() as f32 * STEP_H + 12.0).min(fy - 12.0 - y),
    );
    ui.card(main);
    let old = ui.clip(main.inset(1.0));
    let x = main.x + 18.0;
    let mw = main.w - 36.0;
    let mut hy = main.y + 22.0;
    if !lk.hero {
        ui.tile(
            Rect::new(x, main.y + 16.0, 36.0, 36.0),
            &pv.program_name,
            "",
        );
        let name =
            ui.p.elide(Face::Semibold, 15.0, &pv.program_name, mw - 48.0);
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
        ui.say_whole(&pv.program_name);
        let rd = ui.p.elide(Face::Ui, 12.0, &pv.route_detail, mw - 48.0);
        ui.text(
            id("RouteDetailText"),
            Face::Ui,
            12.0,
            x + 48.0,
            main.y + 44.0,
            &rd,
            pal.muted,
            mw - 48.0,
        );
        ui.say_whole(&pv.route_detail);
        hy = main.y + 70.0;
    }
    command_lines(ui, &pv, x, hy, mw);
    ui.divider(x, main.y + head_h - 12.0, mw);
    steps(
        ui,
        &pv,
        Rect::new(x, main.y + head_h, mw, pv.steps.len() as f32 * STEP_H),
    );
    ui.p.restore(old);

    side_card(ui, m, v, &pv, Rect::new(right - side_w, y, side_w, main.h));
}

/// The title, and at its right the route chip.
fn heading(ui: &mut Ui, m: &Model, pv: &UninstallPageView, left: f32, edge: f32, y: f32) {
    let route = if pv.route_chip {
        pv.route_text
    } else {
        "Waiting"
    };
    let tone = if pv.route_chip {
        Tone::Accent
    } else {
        Tone::Neutral
    };
    let cw = ui.chip_w(route);
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &pv.subtitle,
        edge - cw - 16.0 - left,
    );
    ui.say_whole(&pv.subtitle);
    ui.chip(edge - cw, y, route, tone);
    ui.reg(
        id("RouteText"),
        Rect::new(edge - cw, y - 10.0, cw, 20.0),
        Role::Text,
        route,
        false,
    );
}

/// The height of one line of the command's text.
fn command_line_h(ui: &mut Ui, w: f32) -> f32 {
    ui.p.paragraph_height(Face::Mono, 12.0, w, "C")
}

/// How much taller than one line the command is, wrapped `w` wide: what its card grows by.
fn command_extra(ui: &mut Ui, pv: &UninstallPageView, w: f32) -> f32 {
    let Some(command) = &pv.command else {
        return 0.0;
    };
    let one = command_line_h(ui, w);
    let all =
        ui.p.paragraph_height_wrapped(Face::Mono, 12.0, w, command, Wrap::Anywhere);
    (all - one).max(0.0)
}

/// The exact command, in full (wrapped anywhere: a path has no spaces to break at), and its
/// signer under it. `y` is the middle of the command's first line; the card leaves
/// [`command_extra`] for the lines after it.
fn command_lines(ui: &mut Ui, pv: &UninstallPageView, x: f32, y: f32, w: f32) {
    let pal = ui.pal;
    // Before the record step there is no command yet: the route line above says why.
    let Some(command) = &pv.command else {
        return;
    };
    let one = command_line_h(ui, w);
    let top = y - one / 2.0;
    let h = ui.p.paragraph_wrapped(
        Face::Mono,
        12.0,
        x,
        top,
        w,
        command,
        pal.text,
        Wrap::Anywhere,
    );
    ui.reg(
        id("CommandText"),
        Rect::new(x, top, w, h.max(one)),
        Role::Text,
        command,
        false,
    );
    let extra = (h - one).max(0.0);
    let s = ui.p.elide(Face::Ui, 12.0, &pv.signer, w);
    ui.text(
        id("SignerText"),
        Face::Ui,
        12.0,
        x,
        y + 18.0 + extra,
        &s,
        pal.muted,
        w,
    );
    ui.say_whole(&pv.signer);
}

/// The stepper: each step a Text `Step_n` named "n. Title: Word. Detail".
fn steps(ui: &mut Ui, pv: &UninstallPageView, host: Rect) {
    let pal = ui.pal;
    let at = current(pv);
    let status = pv.steps.get(at).map_or("", |s| s.title).to_string();
    ui.reg(id("StepperHost"), host, Role::Text, &status, false);
    let (x, mw) = (host.x, host.w);
    if ui.look.soft
        && !ui.hc
        && let Some(i) = pv.steps.iter().position(|s| s.state == StepState::Active)
    {
        // D1: the step that runs stands on a tint of the accent.
        let fill = mdshared_ui::gfx::mix(ui.card_fill(), pal.accent, 0.12);
        let top = host.y + i as f32 * STEP_H;
        ui.p.rbox(
            Rect::new(x - 8.0, top - 5.0, mw + 16.0, STEP_H - 2.0),
            8.0,
            fill,
        );
    }
    let n = pv.steps.len();
    for (i, step) in pv.steps.iter().enumerate() {
        let top = host.y + i as f32 * STEP_H;
        let (cx, cy) = (x + 13.0, top + 15.0);
        let done_ink = ok_ink(&pal);
        if i + 1 < n {
            let c = if step.state == StepState::Done {
                done_ink
            } else {
                pal.line
            };
            ui.p.fill(Rect::new(cx - 1.0, cy + 13.0, 2.0, STEP_H - 26.0), c);
        }
        let mk = Mark::of(step.state);
        mark(ui, mk, cx, cy, i + 1, 0);
        let word = mk.word();
        let word_ink = match step.state {
            StepState::Done => done_ink,
            StepState::Active => pal.accent,
            StepState::Pending => pal.faint,
            StepState::Warning | StepState::Failed => pal.text,
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
        let (face, ink) = match step.state {
            StepState::Active => (Face::Semibold, pal.text),
            StepState::Pending => (Face::Ui, pal.muted),
            _ => (Face::Ui, pal.text),
        };
        ui.p.text(face, 14.0, tx, cy - 1.0, step.title, ink, tw);
        let detail = step.detail.clone().unwrap_or_default();
        let shown = ui.p.elide(Face::Ui, 12.0, &detail, tw);
        ui.p.text(Face::Ui, 12.0, tx, cy + 18.0, &shown, pal.muted, tw);
        let label = if detail.is_empty() {
            format!("{}. {}: {word}.", i + 1, step.title)
        } else {
            format!("{}. {}: {word}. {detail}", i + 1, step.title)
        };
        ui.reg(
            Id("Step", i as u32 + 1),
            Rect::new(x, top, mw, STEP_H),
            Role::Text,
            &label,
            false,
        );
        if step.state == StepState::Active {
            let bar = Rect::new(tx, cy + 31.0, tw.min(360.0), 3.0);
            ui.progress(Id("StepProgress", 0), bar, None, step.title);
        }
    }
}

/// The line at the foot of the page. Returns where it begins.
fn footer(ui: &mut Ui, content: Rect, text: &str) -> f32 {
    let pal = ui.pal;
    let left = content.x + ui.look.margin;
    let w = content.w - 2.0 * ui.look.margin;
    let fy = content.bottom() - 30.0;
    ui.divider(content.x + 1.0, fy, content.w);
    let shown = ui.p.elide(Face::Ui, 12.0, text, w);
    ui.text(
        id("FooterText"),
        Face::Ui,
        12.0,
        left,
        fy + 15.0,
        &shown,
        pal.muted,
        w,
    );
    ui.say_whole(text);
    fy
}

/// The card shown while nothing was started.
fn nothing_card(ui: &mut Ui, left: f32, y: f32, w: f32, text: &str) {
    let pal = ui.pal;
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

/// The card of the next queued program. Returns its height, when there is one.
fn next_card(ui: &mut Ui, pv: &UninstallPageView, left: f32, y: f32, w: f32) -> Option<f32> {
    let pal = ui.pal;
    let next = pv.next.as_ref()?;
    let card = Rect::new(left, y, w, 66.0);
    ui.card(card);
    ui.p.icon(glyph::RIGHT, 18.0, card.x + 27.0, card.cy(), pal.accent);
    let list = [
        (id("SkipButton"), "Skip", Style::Standard, None, true),
        (
            id("NextButton"),
            next.button.as_str(),
            Style::Accent,
            None,
            next.enabled,
        ),
    ];
    let bx = ui.buttons_right(card.right() - 18.0, card.cy() - BUTTON_H / 2.0, &list);
    // The Skip button's name says whom it skips.
    if let Some(c) = ui_ctl_named(ui, id("SkipButton")) {
        c.label = next.skip_name.clone();
    }
    let tw = bx - 16.0 - (card.x + 50.0);
    let t = ui.p.elide(Face::Semibold, 14.0, &next.text, tw);
    ui.text(
        id("NextText"),
        Face::Semibold,
        14.0,
        card.x + 50.0,
        card.cy() - 9.0,
        &t,
        pal.text,
        tw,
    );
    ui.say_whole(&next.text);
    let detail = next.tooltip.unwrap_or(next.detail);
    let d = ui.p.elide(Face::Ui, 12.0, detail, tw);
    ui.text(
        id("NextDetail"),
        Face::Ui,
        12.0,
        card.x + 50.0,
        card.cy() + 10.0,
        &d,
        pal.muted,
        tw,
    );
    ui.say_whole(detail);
    Some(card.h)
}

/// The last control declared with `id`, to rename it.
fn ui_ctl_named<'a>(ui: &'a mut Ui, cid: Id) -> Option<&'a mut crate::ui::Ctl> {
    ui.ctls.iter_mut().rev().find(|c| c.id == cid)
}

/// The card of the processes that hold the program. Returns its height, when there is one.
fn running_card(ui: &mut Ui, pv: &UninstallPageView, left: f32, y: f32, w: f32) -> Option<f32> {
    let pal = ui.pal;
    let running = pv.running.as_ref()?;
    let card = Rect::new(left, y, w, 56.0);
    ui.card(card);
    ui.p.icon(glyph::WARN, 16.0, card.x + 27.0, card.cy(), pal.text);
    let list = [(
        id("RecheckButton"),
        "Check again",
        Style::Standard,
        None,
        running.retry_enabled,
    )];
    let bx = ui.buttons_right(card.right() - 18.0, card.cy() - BUTTON_H / 2.0, &list);
    let tw = bx - 16.0 - (card.x + 50.0);
    let t = ui.p.elide(Face::Ui, 13.0, &running.text, tw);
    ui.text(
        id("RunningText"),
        Face::Ui,
        13.0,
        card.x + 50.0,
        card.cy(),
        &t,
        pal.text,
        tw,
    );
    ui.say_whole(&running.text);
    Some(card.h)
}

/// The choices of this run: quiet mode and the restore point.
fn side_card(ui: &mut Ui, m: &Model, v: &View, pv: &UninstallPageView, side: Rect) {
    let pal = ui.pal;
    ui.card(side);
    let old = ui.clip(side.inset(1.0));
    let x = side.x + 18.0;
    let sw = side.w - 36.0;
    let mut sy = side.y + 26.0;
    ui.p.text(Face::Semibold, 13.0, x, sy, "This run", pal.text, sw);
    sy += 26.0;
    if pv.quiet_row {
        ui.p.text(Face::Ui, 13.0, x, sy, "Use quiet mode", pal.text, sw - 50.0);
        // The confirmation has its own QuietSwitch: under it the page's is another control.
        let sid = Id("QuietSwitch", u32::from(m.flow.dialog_open()));
        ui.switch_enabled(
            sid,
            x + sw - mdshared_ui::toggle::TOGGLE_W,
            sy,
            pv.quiet_on,
            pv.quiet_enabled,
            purge_ui_model::pipeline::strings::confirm::QUIET_SWITCH_NAME,
        );
        sy += 22.0;
    }
    let h =
        ui.p.paragraph(Face::Ui, 12.0, x, sy, sw, pv.quiet_note, pal.muted);
    ui.reg(
        id("QuietNote"),
        Rect::new(x, sy, sw, h),
        Role::Text,
        pv.quiet_note,
        false,
    );
    sy += h + 16.0;
    ui.p.text(
        Face::Ui,
        13.0,
        x,
        sy,
        "Restore point for the cleanup step",
        pal.text,
        sw,
    );
    sy += 14.0;
    let field = Rect::new(x, sy, sw.min(280.0), mdshared_ui::dropdown::DROPDOWN_H);
    if pv.restore_enabled && !m.flow.dialog_open() {
        ui.dropdown(
            DD_RESTORE,
            field,
            &v.dds.restore,
            "Restore point at the cleanup step",
        );
    } else {
        ui.p.frame(field, 4.0, pal.page, pal.line);
        let value = crate::view::RESTORE_MODES[m.flow_restore_index()];
        ui.p.text(
            Face::Ui,
            13.0,
            field.x + 10.0,
            field.cy(),
            value,
            pal.muted,
            field.w - 20.0,
        );
        ui.reg_disabled(
            DD_RESTORE,
            field,
            Role::Combo {
                value: value.to_string(),
                open: false,
            },
            "Restore point at the cleanup step",
        );
    }
    sy += field.h + 14.0;
    if let Some(tip) = pv.choices_tooltip {
        ui.para(Face::Ui, 12.0, x, sy, sw, tip, pal.muted);
    }
    sy = side.bottom() - 74.0;
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
/// The stages of the flow: the five steps of the run, then the two that are the user's.
const STAGES: [&str; 7] = [
    "Record",
    "Uninstaller",
    "Check gone",
    "Find leftovers",
    "Ready",
    "Review",
    "Quarantine",
];
const AT_REVIEW: usize = 6;
const AT_RESULT: usize = 7;
const AT_END: usize = 8;

/// Where the flow is: 0 with nothing started, 1 to 5 for the step reached, then the review, its
/// result, and 8 when the scan went nowhere (the Leftovers page has none to show).
fn stage(m: &Model) -> usize {
    let c = m.flow.page.controller();
    if c.target().is_none() {
        return 0;
    }
    let ready = c.state_of(UninstallStep::Ready) == StepState::Done;
    if !ready || c.is_busy() {
        let pv = m.flow.page.view(m.flow_env());
        return 1 + current(&pv);
    }
    match m.flow.leftovers.phase() {
        LeftoversPhase::Scanning | LeftoversPhase::Review | LeftoversPhase::Waiting => AT_REVIEW,
        LeftoversPhase::Result | LeftoversPhase::Undone | LeftoversPhase::Interrupted => AT_RESULT,
        LeftoversPhase::Empty => AT_END,
    }
}

/// The stage the flow's pipeline page shows; `None` for any other page, and in a design without
/// the flow. The window pushes the old stage out when this changes.
pub fn flow_stage(m: &Model, lk: &Look) -> Option<usize> {
    (lk.flow && m.page == Page::Pipeline).then(|| stage(m))
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
    let pv = m.flow.page.view(m.flow_env());
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;
    let st = stage(m);
    let moved = m.flow.leftovers.phase() == LeftoversPhase::Result;

    let y = content.y + 38.0;
    let mut edge = right;
    if st == AT_REVIEW && m.flow.leftovers.phase() == LeftoversPhase::Review {
        edge = super::leftovers::review_buttons(ui, m, right, y) - 12.0;
    }
    heading(ui, m, &pv, left, edge, y);

    // The strip: every stage, and how far the flow has come.
    let top = content.y + 76.0 + (lk.margin - 28.0);
    let cell = w / STAGES.len() as f32;
    let cy = top + 14.0;
    let done_ink = ok_ink(&pal);
    ui.reg(
        id("StepperHost"),
        Rect::new(left, top, w, 52.0),
        Role::Text,
        &pv.subtitle,
        false,
    );
    for (k, stage_name) in STAGES.into_iter().enumerate() {
        let step = pv.steps.get(k);
        let mk = if let Some(s) = step {
            Mark::of(s.state)
        } else if k == pv.steps.len() {
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
            if mk == Mark::Done {
                let ink = if ui.hc { pal.text } else { done_ink };
                ui.p.fill(line, ink);
            }
        }
        mark(ui, mk, cx, cy, k + 1, 1);
        let (face, ink) = match mk {
            Mark::Busy | Mark::Yours => (Face::Semibold, pal.text),
            Mark::Done | Mark::Warning | Mark::Failed => (Face::Ui, pal.text),
            _ => (Face::Ui, pal.muted),
        };
        let label = ui.p.elide(face, 12.5, stage_name, cell - 8.0);
        let cell_r = Rect::new(cx - cell / 2.0, top, cell, 52.0);
        ui.p.text_center(
            face,
            12.5,
            Rect::new(cell_r.x, top + 30.0, cell, 20.0),
            &label,
            ink,
        );
        let said = match step {
            Some(s) => match &s.detail {
                Some(d) => format!("{}. {}: {}. {d}", k + 1, s.title, mk.word()),
                None => format!("{}. {}: {}.", k + 1, s.title, mk.word()),
            },
            None => format!("{}. {stage_name}: {}.", k + 1, mk.word()),
        };
        ui.reg(Id("Step", k as u32 + 1), cell_r, Role::Text, &said, false);
    }

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
    let fy = footer(ui, content, pv.footer);
    let y = super::sample_bar(ui, m, left, area.y, w);
    let mut y = bars(ui, &m.flow_bars(), left, y, w);
    if st == 0 {
        nothing_card(ui, left, y, w, pv.footer);
        return;
    }
    if let Some(h) = next_card(ui, &pv, left, y, w) {
        y += h + 12.0;
    }
    if let Some(h) = running_card(ui, &pv, left, y, w) {
        y += h + 12.0;
    }
    let side_w = 330.0_f32.min(w * 0.36);
    let h = 470.0_f32.min(fy - 12.0 - y).max(120.0);
    step_card(ui, &pv, Rect::new(left, y, w - side_w - 16.0, h));
    side_card(ui, m, v, &pv, Rect::new(right - side_w, y, side_w, h));
}

/// D2: the step that runs, alone in a card, with what is done under it.
fn step_card(ui: &mut Ui, pv: &UninstallPageView, r: Rect) {
    let pal = ui.pal;
    ui.card(r);
    let old = ui.clip(r.inset(1.0));
    let x = r.x + 24.0;
    let w = r.w - 48.0;
    ui.tile(Rect::new(x, r.y + 22.0, 44.0, 44.0), &pv.program_name, "");
    let name = ui.p.elide(Face::Semibold, 17.0, &pv.program_name, w - 58.0);
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
    ui.say_whole(&pv.program_name);
    let rd = ui.p.elide(Face::Ui, 12.0, &pv.route_detail, w - 58.0);
    ui.text(
        id("RouteDetailText"),
        Face::Ui,
        12.0,
        x + 58.0,
        r.y + 55.0,
        &rd,
        pal.muted,
        w - 58.0,
    );
    ui.say_whole(&pv.route_detail);
    let extra = command_extra(ui, pv, w);
    command_lines(ui, pv, x, r.y + 88.0, w);
    ui.divider(x, r.y + 122.0 + extra, w);

    let i = current(pv);
    let Some(step) = pv.steps.get(i) else {
        ui.p.restore(old);
        return;
    };
    let mut y = r.y + 146.0 + extra;
    let caption = format!("STEP {} OF {}", i + 1, pv.steps.len());
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
    mark(ui, Mark::of(step.state), x + 11.0, y, i + 1, 2);
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
    let detail = step.detail.clone().unwrap_or_default();
    let d = ui.p.elide(Face::Ui, 13.0, &detail, w - 36.0);
    ui.text(
        id("StepDetail"),
        Face::Ui,
        13.0,
        x + 36.0,
        y,
        &d,
        pal.muted,
        w - 36.0,
    );
    ui.say_whole(&detail);
    y += 26.0;
    if step.state == StepState::Active {
        let bar = Rect::new(x + 36.0, y, (w - 36.0 - 48.0).min(520.0), 4.0);
        ui.progress(Id("StepProgress", 0), bar, None, step.title);
    }
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
    }
    for (k, before) in pv.steps.iter().enumerate().take(i) {
        ui.p.icon(
            glyph::CHECK,
            13.0,
            x + 7.0,
            y,
            if ui.hc { pal.text } else { ok_ink(&pal) },
        );
        let said = match &before.detail {
            Some(d) => format!("{}: {d}", before.title),
            None => before.title.to_string(),
        };
        let s = ui.p.elide(Face::Ui, 12.5, &said, w - 24.0);
        ui.text(
            Id("DoneStep", k as u32 + 1),
            Face::Ui,
            12.5,
            x + 24.0,
            y,
            &s,
            pal.text,
            w - 24.0,
        );
        ui.say_whole(&said);
        y += 24.0;
    }
    ui.p.restore(old);
}
