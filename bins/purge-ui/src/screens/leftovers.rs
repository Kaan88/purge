//! The Leftovers page, drawn from `purge-ui-model`'s [`LeftoversModel`] (UI-FLOW): the scan's
//! groups with their boxes, the band chips and the verdict, the evidence of the selected item, the
//! footer with Move, the wait for the Purge security prompt, the result and "Put back all". The
//! model decides what is ticked and what may be moved; this file only shows it.

use mdshared_ui::gfx::{Face, Rect};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Severity};
use mdshared_ui::pane::draw_row_fill;
use mdshared_ui::scroll::{draw_scrollbar_animated, scrollbar};
use purge_ui_model::info_bar::Severity as ModelSeverity;
use purge_ui_model::leftovers::{LeftoversModel, LeftoversPhase, LeftoversRow, Look};

use crate::model::Model;
use crate::ui::{BUTTON_H, Id, Key, LOCK, Role, Style, Tone, Ui, id, ok_ink, within};
use crate::view::View;

const ROW_H: f32 = 46.0;
const HEAD_H: f32 = 40.0;
const FOOTER_H: f32 = 56.0;
/// The column at the left of the list that holds the boxes.
const GUTTER: f32 = 30.0;

fn look_tone(l: Look) -> Tone {
    match l {
        Look::Safe => Tone::Good,
        Look::Likely | Look::Weak => Tone::Caution,
        Look::Protected => Tone::Outline,
    }
}

fn severity(s: ModelSeverity) -> Severity {
    match s {
        ModelSeverity::Informational => Severity::Info,
        ModelSeverity::Success => Severity::Success,
        ModelSeverity::Warning => Severity::Warning,
        ModelSeverity::Error => Severity::Error,
    }
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let l = &m.flow.leftovers;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let y = content.y + 38.0;

    let mut x = left;
    if let Some(initial) = l.app_initial() {
        ui.tile(Rect::new(x, y - 18.0, 36.0, 36.0), l.program_name(), "");
        let _ = initial;
        x += 48.0;
    }
    let mut room = right - x;
    if l.phase() == LeftoversPhase::Review {
        room = review_buttons(ui, m, right, y) - 16.0 - x;
    }
    let title = l.title();
    let sub = l.subtitle();
    if lk.stacked {
        let t =
            ui.p.elide(Face::Semibold, lk.h1 - 4.0, &title, room.max(120.0));
        ui.text(
            id("TitleText"),
            Face::Semibold,
            lk.h1 - 4.0,
            x,
            y - 8.0,
            &t,
            pal.text,
            room,
        );
        ui.say_whole(&title);
        let s = ui.p.elide(Face::Ui, 13.0, &sub, room.max(0.0));
        ui.text(
            id("SubtitleText"),
            Face::Ui,
            13.0,
            x,
            y + 15.0,
            &s,
            pal.muted,
            room,
        );
        ui.say_whole(&sub);
    } else {
        let sw = ui.p.measure(Face::Ui, 13.0, &sub) + 14.0;
        let t =
            ui.p.elide(Face::Semibold, lk.h1, &title, (room - sw).max(120.0));
        let tw = ui.text(
            id("TitleText"),
            Face::Semibold,
            lk.h1,
            x,
            y,
            &t,
            pal.text,
            room,
        );
        ui.say_whole(&title);
        let s =
            ui.p.elide(Face::Ui, 13.0, &sub, (room - tw - 14.0).max(0.0));
        ui.text(
            id("SubtitleText"),
            Face::Ui,
            13.0,
            x + tw + 14.0,
            y + lk.h1 * 0.2,
            &s,
            pal.muted,
            room,
        );
        ui.say_whole(&sub);
    }

    let top = content.y + 76.0 + (lk.margin - 28.0);
    body(
        ui,
        m,
        v,
        Rect::new(content.x, top, content.w, content.bottom() - top),
    );
}

/// The review's two buttons in a title row, laid from `right` with their middle at `cy`:
/// open or close every group, and show the weak matches. Returns where they begin.
pub fn review_buttons(ui: &mut Ui, m: &Model, right: f32, cy: f32) -> f32 {
    let l = &m.flow.leftovers;
    let weak = l.weak_button_text();
    let list = [
        (
            id("ExpandButton"),
            l.expand_all_text(),
            Style::Subtle,
            None,
            true,
        ),
        (
            id("WeakButton"),
            weak.as_str(),
            Style::Subtle,
            None,
            l.weak_count() > 0,
        ),
    ];
    ui.buttons_right(right, cy - BUTTON_H / 2.0, &list)
}

/// The page's bars from `y`; returns the y under them.
fn bars(ui: &mut Ui, m: &Model, x: f32, mut y: f32, w: f32) -> f32 {
    for (k, b) in m.flow_leftovers_bars().iter().enumerate() {
        let mut bar = InfoBar::new(severity(b.severity), &b.title, &b.message).closable(b.closable);
        let mut ids = Vec::new();
        if let Some(a) = b.action {
            bar = bar.action(0, a.text());
            ids.push(Id("LBarButton", k as u32 + 1));
        }
        let close = b.closable.then_some(Id("LBarClose", k as u32 + 1));
        y = ui.infobar_with(Id("InfoBarHost", k as u32), x, y, w, &bar, close, &ids) + 8.0;
        // Review SF3: a click acts on the bar it showed, never on its place among the bars.
        for cid in ids.iter().chain(&close) {
            ui.key(*cid, Key::bar(&b.title, &b.message));
        }
    }
    y
}

/// Everything under the title, for the phase the page is in. `area` is as wide as the page;
/// the side margins are kept inside it. D2 draws this inside its flow as well.
pub fn body(ui: &mut Ui, m: &Model, v: &mut View, area: Rect) {
    let lk = ui.look;
    let left = area.x + lk.margin;
    let w = area.w - 2.0 * lk.margin;
    let y = super::sample_bar(ui, m, left, area.y, w);
    let y = bars(ui, m, left, y, w);
    let area = Rect::new(area.x, y, area.w, area.bottom() - y);
    let l = &m.flow.leftovers;
    match l.phase() {
        LeftoversPhase::Empty | LeftoversPhase::Interrupted => empty(ui, l, area),
        LeftoversPhase::Scanning => scanning(ui, l, area),
        LeftoversPhase::Review => review(ui, m, v, area),
        LeftoversPhase::Waiting => waiting(ui, l, area),
        LeftoversPhase::Result => result(ui, l, area),
        LeftoversPhase::Undone => undone(ui, l, area),
    }
}

fn empty(ui: &mut Ui, l: &LeftoversModel, area: Rect) {
    let pal = ui.pal;
    let (title, text) = l.empty_panel().unwrap_or(("", ""));
    let x = area.x + ui.look.margin;
    let w = (area.w - 2.0 * ui.look.margin).min(620.0);
    let th = ui.p.paragraph_height(Face::Ui, 13.0, w - 56.0, text);
    let card = Rect::new(x, area.y, w, 28.0 + 30.0 + th + 16.0 + BUTTON_H + 28.0);
    ui.card(card);
    ui.text(
        id("EmptyTitle"),
        Face::Semibold,
        20.0,
        card.x + 28.0,
        card.y + 40.0,
        title,
        pal.text,
        w - 56.0,
    );
    let h = ui.p.paragraph(
        Face::Ui,
        13.0,
        card.x + 28.0,
        card.y + 58.0,
        w - 56.0,
        text,
        pal.muted,
    );
    ui.reg(
        id("EmptyText"),
        Rect::new(card.x + 28.0, card.y + 58.0, w - 56.0, h),
        Role::Text,
        text,
        false,
    );
    let by = card.y + 58.0 + h + 16.0;
    let mut bx = card.x + 28.0;
    if l.phase() == LeftoversPhase::Interrupted {
        let bw = ui.button_w("Open History & undo", None);
        ui.button(
            id("OpenHistory"),
            Rect::new(bx, by, bw, BUTTON_H),
            "Open History & undo",
            Style::Accent,
            None,
            true,
        );
        bx += bw + 8.0;
    }
    let bw = ui.button_w("Go to Programs", None);
    ui.button(
        id("GoPrograms"),
        Rect::new(bx, by, bw, BUTTON_H),
        "Go to Programs",
        Style::Standard,
        None,
        true,
    );
}

fn scanning(ui: &mut Ui, l: &LeftoversModel, area: Rect) {
    let pal = ui.pal;
    let w = (area.w - 2.0 * ui.look.margin).min(560.0);
    let y = area.y + (area.h * 0.28).min(180.0);
    let title = l.subtitle();
    let t = ui.p.elide(Face::Semibold, 22.0, &title, w);
    let tw = ui.p.measure(Face::Semibold, 22.0, &t);
    ui.text(
        id("ScanTitleText"),
        Face::Semibold,
        22.0,
        area.cx() - tw / 2.0,
        y,
        &t,
        pal.text,
        w,
    );
    ui.say_whole(&title);
    let detail = "Comparing what is there now with what was recorded before the uninstall.";
    let dw = ui.p.measure(Face::Ui, 13.0, detail).min(w);
    ui.text(
        id("ScanDetailText"),
        Face::Ui,
        13.0,
        area.cx() - dw / 2.0,
        y + 32.0,
        detail,
        pal.muted,
        w,
    );
    let bar = Rect::new(area.cx() - 160.0, y + 62.0, 320.0, 4.0);
    ui.progress(id("ScanProgress"), bar, None, "Looking for leftovers");
}

/// The wait for the broker's security prompt: what to confirm there, the code its footer shows,
/// and that nothing has moved yet.
fn waiting(ui: &mut Ui, l: &LeftoversModel, area: Rect) {
    let pal = ui.pal;
    let w = (area.w - 2.0 * ui.look.margin).min(620.0);
    let x = area.cx() - w / 2.0;
    let mut y = area.y + (area.h * 0.2).min(140.0);
    ui.p.icon(crate::ui::SHIELD, 30.0, area.cx(), y, pal.accent);
    y += 40.0;
    let title = l.waiting_title();
    let t = ui.p.elide(Face::Semibold, 22.0, title, w);
    let tw = ui.p.measure(Face::Semibold, 22.0, &t);
    ui.text(
        id("WaitingTitleText"),
        Face::Semibold,
        22.0,
        area.cx() - tw / 2.0,
        y,
        &t,
        pal.text,
        w,
    );
    ui.say_whole(title);
    y += 34.0;
    let code = l.waiting_code_text();
    let label = format!("Code {code}");
    let cw = ui.p.measure(Face::Mono, 18.0, &label);
    ui.text(
        id("WaitingCodeText"),
        Face::Mono,
        18.0,
        area.cx() - cw / 2.0,
        y,
        &label,
        pal.text,
        cw + 4.0,
    );
    ui.say_whole(&code);
    y += 30.0;
    let detail = l.waiting_detail();
    let h = ui.p.paragraph_height(Face::Ui, 13.0, w, detail);
    let dw = ui.p.measure(Face::Ui, 13.0, detail).min(w);
    ui.p.paragraph(
        Face::Ui,
        13.0,
        area.cx() - dw / 2.0,
        y,
        w,
        detail,
        pal.muted,
    );
    ui.reg(
        id("WaitingDetailText"),
        Rect::new(x, y, w, h),
        Role::Text,
        detail,
        false,
    );
    y += h + 18.0;
    let bar = Rect::new(area.cx() - 160.0, y, 320.0, 4.0);
    ui.progress(id("WaitingProgress"), bar, None, title);
    y += 24.0;
    if let Some(header) = l.attention_header() {
        ui.p.text(Face::Semibold, 13.0, x, y, &header, pal.text, w);
        y += 22.0;
        for (k, a) in l.attention().iter().enumerate().take(6) {
            let line = format!("{}  \u{b7}  {}", a.display_name, a.reasons_text());
            let s = ui.p.elide(Face::Ui, 12.5, &line, w);
            ui.text(
                Id("AttentionText", k as u32 + 1),
                Face::Ui,
                12.5,
                x,
                y,
                &s,
                pal.text,
                w,
            );
            ui.say_whole(&line);
            y += 20.0;
        }
    }
}

fn card_lines(
    ui: &mut Ui,
    x: f32,
    mut y: f32,
    w: f32,
    name: &'static str,
    lines: &[String],
) -> f32 {
    let pal = ui.pal;
    for (k, line) in lines.iter().enumerate() {
        let h = ui.p.paragraph(Face::Ui, 13.0, x, y, w, line, pal.text);
        ui.reg(
            Id(name, k as u32 + 1),
            Rect::new(x, y, w, h),
            Role::Text,
            line,
            false,
        );
        y += h + 4.0;
    }
    y
}

/// The height of `lines` drawn by [`card_lines`].
fn lines_height(ui: &mut Ui, w: f32, lines: &[String]) -> f32 {
    lines
        .iter()
        .map(|l| ui.p.paragraph_height(Face::Ui, 13.0, w, l) + 4.0)
        .sum()
}

fn result(ui: &mut Ui, l: &LeftoversModel, area: Rect) {
    let pal = ui.pal;
    let x0 = area.x + ui.look.margin;
    let cw = (area.w - 2.0 * ui.look.margin).min(720.0);
    let w = cw - 56.0;
    let mut need = 28.0 + 44.0 + 10.0 + 14.0 + BUTTON_H + 28.0;
    need +=
        ui.p.paragraph_height(Face::Ui, 14.0, w, l.result_detail().unwrap_or(""));
    need += lines_height(ui, w, l.held_lines()) + lines_height(ui, w, l.failed_lines());
    for text in [l.delete_after_result(), l.restore_point_text()]
        .into_iter()
        .flatten()
    {
        need += ui.p.paragraph_height(Face::Ui, 13.0, w, text) + 6.0;
    }
    let card = Rect::new(x0, area.y, cw, need.min(area.bottom() - area.y - 12.0));
    ui.card(card);
    let old = ui.clip(card.inset(1.0));
    let x = card.x + 28.0;
    let mut y = card.y + 28.0;
    let ink = if l.result_complete() {
        ok_ink(&pal)
    } else {
        pal.text
    };
    let icon = if l.result_complete() {
        glyph::CHECK
    } else {
        glyph::WARN
    };
    ui.p.icon(
        icon,
        26.0,
        x + 13.0,
        y + 16.0,
        if ui.hc { pal.text } else { ink },
    );
    let title = l.result_title_text();
    ui.text(
        id("ResultTitleText"),
        Face::Semibold,
        22.0,
        x + 38.0,
        y + 16.0,
        title,
        pal.text,
        w - 38.0,
    );
    ui.say_whole(title);
    y += 44.0;
    let detail = l.result_detail().unwrap_or("");
    let h = ui.p.paragraph(Face::Ui, 14.0, x, y, w, detail, pal.text);
    ui.reg(
        id("ResultDetailText"),
        Rect::new(x, y, w, h.max(1.0)),
        Role::Text,
        detail,
        false,
    );
    y += h + 10.0;
    y = card_lines(ui, x, y, w, "HeldText", l.held_lines());
    y = card_lines(ui, x, y, w, "FailedText", l.failed_lines());
    if let Some(text) = l.delete_after_result() {
        let h = ui.p.paragraph(Face::Ui, 13.0, x, y, w, text, pal.text);
        ui.reg(
            id("DeleteAfterResultText"),
            Rect::new(x, y, w, h),
            Role::Text,
            text,
            false,
        );
        y += h + 6.0;
    }
    if let Some(text) = l.restore_point_text() {
        let h = ui.p.paragraph(Face::Ui, 13.0, x, y, w, text, pal.muted);
        ui.reg(
            id("RestorePointText"),
            Rect::new(x, y, w, h),
            Role::Text,
            text,
            false,
        );
        y += h + 6.0;
    }
    y += 14.0;
    let mut list = vec![(
        id("UndoAllButton"),
        l.undo_text(),
        Style::Standard,
        Some(glyph::UNDO),
        l.can_undo(),
    )];
    if l.can_retry_held() {
        list.push((
            id("RetryHeldButton"),
            "Try the held items again",
            Style::Standard,
            None,
            true,
        ));
    }
    list.push((
        id("OpenVault"),
        "Open quarantine",
        Style::Standard,
        None,
        true,
    ));
    list.push((id("DoneButton"), "Done", Style::Accent, None, true));
    ui.buttons_right(
        card.right() - 28.0,
        y.min(card.bottom() - BUTTON_H - 20.0),
        &list,
    );
    ui.p.restore(old);
}

fn undone(ui: &mut Ui, l: &LeftoversModel, area: Rect) {
    let pal = ui.pal;
    let x0 = area.x + ui.look.margin;
    let cw = (area.w - 2.0 * ui.look.margin).min(720.0);
    let w = cw - 56.0;
    let mut need = 28.0 + 44.0 + 10.0 + 14.0 + BUTTON_H + 28.0;
    need +=
        ui.p.paragraph_height(Face::Ui, 14.0, w, l.undo_detail().unwrap_or(""));
    need += lines_height(ui, w, l.undo_conflict_lines());
    let card = Rect::new(x0, area.y, cw, need.min(area.bottom() - area.y - 12.0));
    ui.card(card);
    let old = ui.clip(card.inset(1.0));
    let x = card.x + 28.0;
    let mut y = card.y + 28.0;
    ui.p.icon(glyph::UNDO, 24.0, x + 13.0, y + 16.0, pal.accent);
    let title = l.undo_title_text();
    ui.text(
        id("UndoTitleText"),
        Face::Semibold,
        22.0,
        x + 38.0,
        y + 16.0,
        title,
        pal.text,
        w - 38.0,
    );
    ui.say_whole(title);
    y += 44.0;
    let detail = l.undo_detail().unwrap_or("");
    let h = ui.p.paragraph(Face::Ui, 14.0, x, y, w, detail, pal.text);
    ui.reg(
        id("UndoDetailText"),
        Rect::new(x, y, w, h.max(1.0)),
        Role::Text,
        detail,
        false,
    );
    y += h + 10.0;
    y = card_lines(ui, x, y, w, "ConflictText", l.undo_conflict_lines()) + 14.0;
    let list = [
        (
            id("OpenHistory"),
            "Open history",
            Style::Standard,
            None,
            true,
        ),
        (id("DoneButton"), "Done", Style::Accent, None, true),
    ];
    ui.buttons_right(
        card.right() - 28.0,
        y.min(card.bottom() - BUTTON_H - 20.0),
        &list,
    );
    ui.p.restore(old);
}

fn review(ui: &mut Ui, m: &Model, v: &mut View, area: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let l = &m.flow.leftovers;
    let left = area.x + lk.margin;
    let right = area.right() - lk.margin;
    let w = right - left;
    let mut y = area.y;

    let fy = area.bottom() - FOOTER_H;
    let side_w = 330.0_f32.min(w * 0.36);
    let col_w = w - side_w - 16.0;
    let foot = l.footer();
    let bands = l.band_summary();

    // What is about to move, and the bands.
    let card = Rect::new(left, y, col_w, 92.0);
    ui.card(card);
    let inks = ui.rating_inks();
    let parts: Vec<(f32, _)> = [bands.safe, bands.likely, bands.protected]
        .iter()
        .zip(inks)
        .map(|(n, c)| (*n as f32, c))
        .collect();
    let mut cx = card.x + 18.0;
    let legend_cy = if lk.hero {
        let (rx, ry) = (cx + 30.0, card.cy());
        ui.donut(rx, ry, 30.0, 7.0, &parts);
        let mid = Rect::new(rx - 30.0, ry - 30.0, 60.0, 60.0);
        ui.p.text_center(
            Face::Semibold,
            18.0,
            mid,
            &l.selected_count().to_string(),
            pal.text,
        );
        cx += 78.0;
        ui.p.text(
            Face::Semibold,
            11.0,
            cx,
            card.cy() - 16.0,
            "READY TO MOVE",
            pal.muted,
            200.0,
        );
        ui.text(
            id("VerdictText"),
            Face::Semibold,
            20.0,
            cx,
            card.cy() + 9.0,
            &foot.verdict,
            pal.text,
            col_w * 0.5,
        );
        card.cy()
    } else {
        ui.p.text(
            Face::Semibold,
            11.0,
            cx,
            card.y + 20.0,
            "READY TO MOVE",
            pal.muted,
            200.0,
        );
        ui.text(
            id("VerdictText"),
            Face::Semibold,
            20.0,
            cx,
            card.y + 44.0,
            &foot.verdict,
            pal.text,
            col_w * 0.5,
        );
        ui.parts_bar(Rect::new(cx, card.y + 68.0, col_w - 36.0, 8.0), &parts);
        card.y + 36.0
    };
    ui.say_whole(&foot.verdict);
    let chips = [
        (
            "SafePill",
            bands.safe_text.as_str(),
            Tone::Good,
            glyph::CHECK,
        ),
        (
            "LikelyPill",
            bands.likely_text.as_str(),
            Tone::Caution,
            glyph::WARN,
        ),
        (
            "ProtectedPill",
            bands.protected_text.as_str(),
            Tone::Outline,
            LOCK,
        ),
    ];
    let mut lx = card.right() - 18.0;
    for (k, (name, text, tone, icon)) in chips.into_iter().enumerate().rev() {
        if lk.soft {
            let cw = ui.chip_w(text);
            lx -= cw;
            ui.chip(lx, legend_cy, text, tone);
            ui.reg(
                id(name),
                Rect::new(lx, legend_cy - 10.0, cw, 20.0),
                Role::Text,
                text,
                false,
            );
            lx -= 8.0;
            continue;
        }
        let tw = ui.p.measure(Face::Ui, 13.0, text);
        lx -= tw;
        ui.text(
            id(name),
            Face::Ui,
            13.0,
            lx,
            legend_cy,
            text,
            pal.text,
            tw + 2.0,
        );
        lx -= 20.0;
        ui.p.icon(
            icon,
            14.0,
            lx + 7.0,
            legend_cy,
            if ui.hc { pal.text } else { inks[k] },
        );
        lx -= 18.0;
    }
    y += 92.0 + 12.0;

    let list = Rect::new(left, y, col_w, fy - 12.0 - y);
    items(ui, m, v, list);
    let pane = Rect::new(right - side_w, card.y, side_w, fy - 12.0 - card.y);
    evidence(ui, l, pane);

    // The footer: what is ticked, the delete box, and the one button that moves it.
    let foot_r = Rect::new(area.x + 1.0, fy, area.w - 1.0, FOOTER_H);
    ui.p.fill(foot_r, pal.bar);
    ui.divider(foot_r.x, fy, foot_r.w);
    let cy = foot_r.cy();
    let cw = ui.text(
        id("FooterCount"),
        Face::Semibold,
        13.0,
        left,
        cy,
        &foot.count,
        pal.text,
        220.0,
    );
    let dw = ui.text(
        id("FooterDetail"),
        Face::Ui,
        13.0,
        left + cw,
        cy,
        &foot.detail,
        pal.muted,
        220.0,
    );
    let mw = ui.button_w(&foot.move_text, None);
    let move_r = Rect::new(right - mw, cy - BUTTON_H / 2.0, mw, BUTTON_H);
    let bw = 26.0 + ui.p.measure(Face::Ui, 12.0, foot.delete_after_text);
    let hw = ui.p.measure(Face::Ui, 12.0, foot.hint);
    let free = move_r.x - 16.0 - (left + cw + dw + 24.0);
    let bx = move_r.x
        - 16.0
        - bw
        - if free >= bw + hw + 20.0 {
            hw + 20.0
        } else {
            0.0
        };
    if free >= bw {
        ui.tick(
            id("DeleteAfterBox"),
            bx,
            cy,
            Some(foot.delete_after),
            foot.delete_after_enabled,
            foot.delete_after_text,
        );
        ui.p.text(
            Face::Ui,
            12.0,
            bx + 26.0,
            cy,
            foot.delete_after_text,
            pal.text,
            bw,
        );
    }
    if free >= bw + hw + 20.0 {
        ui.text(
            id("FooterHint"),
            Face::Ui,
            12.0,
            move_r.x - 16.0 - hw,
            cy,
            foot.hint,
            pal.muted,
            hw + 2.0,
        );
    }
    ui.button(
        id("MoveButton"),
        move_r,
        &foot.move_text,
        Style::Accent,
        None,
        foot.move_enabled,
    );
    // The WinUI button's text block, which the VM rig reads for the count.
    ui.reg(id("MoveText"), move_r, Role::Text, &foot.move_text, false);
}

/// The groups and their items, scrolled as one list.
fn items(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let l = &m.flow.leftovers;
    ui.card(r);
    let view = r.inset(6.0);
    let rows = l.rows();
    let height = |row: &LeftoversRow| match row {
        LeftoversRow::Group { .. } => HEAD_H,
        LeftoversRow::Item(_) => ROW_H,
    };
    let content: f32 = rows.iter().map(height).sum();
    v.left_area = view;
    v.left_content = content;
    let off = v
        .left_scroll
        .offset(ui.cx.anim(), "leftovers-scroll", content, view.h);

    let old = ui.clip(view);
    let row_w = view.w - 10.0;
    let selected = l.selected().copied();
    let mut y = view.y - off;
    for row in &rows {
        let h = height(row);
        let rr = Rect::new(view.x, y, row_w, h);
        y += h;
        if rr.bottom() < view.y || rr.y > view.bottom() {
            continue;
        }
        match *row {
            LeftoversRow::Group { group, hidden } => {
                let Some(head) = l.group_header(group, hidden) else {
                    continue;
                };
                let hid = Id("Group", group as u32 + 1);
                let hit = within(Rect::new(rr.x + GUTTER, rr.y, rr.w - GUTTER, rr.h), view);
                ui.reg(
                    hid,
                    hit,
                    Role::Expander(head.expanded),
                    &l.row_name(*row),
                    true,
                );
                ui.key(hid, Key::Group(head.name.clone()));
                if ui.hot(hid) {
                    draw_row_fill(ui.p, &pal, hit, true, ui.down(hid), false);
                }
                if ui.ringed(hid) {
                    mdshared_ui::focus::draw_ring(ui.p, &pal, hit.inset(2.0), 4.0);
                }
                let chevron = if head.expanded {
                    glyph::DOWN
                } else {
                    glyph::RIGHT
                };
                ui.p.icon(chevron, 12.0, rr.x + GUTTER + 12.0, rr.cy(), pal.muted);
                let name = format!("{}  \u{b7}  {}", head.name, head.count_text);
                ui.p.text(
                    Face::Semibold,
                    13.0,
                    rr.x + GUTTER + 26.0,
                    rr.cy(),
                    &name,
                    pal.text,
                    rr.w * 0.6,
                );
                ui.p.text_right(
                    Face::Ui,
                    12.0,
                    rr.right() - 10.0,
                    rr.cy(),
                    &head.size_text,
                    pal.muted,
                );
                if head.tick_visible && rr.cy() > view.y && rr.cy() < view.bottom() {
                    ui.tick(
                        Id("GroupTick", group as u32 + 1),
                        rr.x + 8.0,
                        rr.cy(),
                        head.checked,
                        head.tick_enabled,
                        &format!("All of {}", head.name),
                    );
                    ui.key(
                        Id("GroupTick", group as u32 + 1),
                        Key::Group(head.name.clone()),
                    );
                }
            }
            LeftoversRow::Item(index) => {
                let Some(item) = l.item_row(index) else {
                    continue;
                };
                let n = index as u32 + 1;
                let rid = Id("Item", n);
                let is_sel = selected == Some(item.candidate_id);
                let hit = within(rr, view);
                ui.reg(rid, hit, Role::Item(is_sel), &l.row_name(*row), true);
                ui.key(rid, Key::Candidate(item.candidate_id));
                let fill = Rect::new(rr.x, rr.y + 1.0, rr.w, rr.h - 2.0);
                draw_row_fill(ui.p, &pal, fill, ui.hot(rid), ui.down(rid), is_sel);
                if ui.ringed(rid) {
                    mdshared_ui::focus::draw_ring(ui.p, &pal, fill.inset(2.0), 4.0);
                }
                let cy = rr.cy();
                if item.check_visible && hit.h >= ROW_H * 0.5 {
                    ui.tick(
                        Id("ItemTick", n),
                        rr.x + 8.0,
                        cy,
                        Some(item.checked),
                        true,
                        &format!("Move {}", item.title),
                    );
                    ui.key(Id("ItemTick", n), Key::Candidate(item.candidate_id));
                }
                let ix = rr.x + GUTTER + 16.0;
                let icon = if item.protected { LOCK } else { glyph::FOLDER };
                ui.p.icon(icon, 15.0, ix, cy, pal.muted);
                ui.p.text_right(
                    Face::Ui,
                    12.0,
                    rr.right() - 10.0,
                    cy,
                    &item.size_text,
                    pal.muted,
                );
                let chip = if item.protected {
                    "Protected"
                } else {
                    item.look.word()
                };
                let cw = ui.chip_w(chip);
                let chip_x = rr.right() - 10.0 - 64.0 - cw;
                ui.chip(chip_x, cy, chip, look_tone(item.look));
                let tx = ix + 16.0;
                let tw = chip_x - 12.0 - tx;
                let title = ui.p.elide(Face::Mono, 12.5, &item.title, tw);
                let ink = if item.protected { pal.muted } else { pal.text };
                ui.p.text(Face::Mono, 12.5, tx, cy - 8.0, &title, ink, tw);
                let why = if item.refused {
                    item.refusal_text.clone()
                } else if item.user_data {
                    format!("{} \u{b7} User data", item.why)
                } else {
                    item.why.clone()
                };
                let why = ui.p.elide(Face::Ui, 12.0, &why, tw);
                ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &why, pal.muted, tw);
            }
        }
    }
    ui.p.restore(old);

    if let Some((track, thumb)) = scrollbar(
        Rect::new(view.x, view.y + 2.0, r.right() - 3.0 - view.x, view.h - 4.0),
        content,
        view.h,
        off,
    ) {
        draw_scrollbar_animated(
            ui.p,
            &pal,
            ui.cx.anim(),
            "leftovers-bar",
            track,
            thumb,
            false,
        );
    }
}

/// Why Purge thinks the selected item is a leftover, and what moving it means.
fn evidence(ui: &mut Ui, l: &LeftoversModel, r: Rect) {
    let pal = ui.pal;
    ui.card(r);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let Some(d) = l.detail() else {
        let t = "Select an item to see why Purge thinks it is a leftover.";
        let h =
            ui.p.paragraph(Face::Ui, 13.0, x, r.y + 20.0, w, t, pal.muted);
        ui.reg(
            id("DNone"),
            Rect::new(x, r.y + 20.0, w, h),
            Role::Text,
            t,
            false,
        );
        return;
    };
    let old = ui.clip(r.inset(1.0));
    let mut y = r.y + 18.0;
    if let Some(title) = &d.title {
        let h =
            ui.p.paragraph(Face::Semibold, 15.0, x, y, w, title, pal.text);
        ui.reg(
            id("DTitle"),
            Rect::new(x, y, w, h),
            Role::Text,
            title,
            false,
        );
        y += h + 8.0;
    }
    let top = y;
    y = super::programs::mono(ui, 12.0, x, y, w, &d.path);
    ui.reg(
        id("DPath"),
        Rect::new(x, top, w, y - top),
        Role::Text,
        &d.path,
        false,
    );
    y += 18.0;

    let band = if d.protected {
        "Protected"
    } else {
        d.look.word()
    };
    let mut cx = x;
    let cw = ui.chip(cx, y, band, look_tone(d.look));
    ui.reg(
        id("DBand"),
        Rect::new(cx, y - 10.0, cw, 20.0),
        Role::Text,
        band,
        false,
    );
    cx += cw + 6.0;
    if d.user_data {
        let cw = ui.chip(cx, y, "User data", Tone::Bad);
        ui.reg(
            id("DUserData"),
            Rect::new(cx, y - 10.0, cw, 20.0),
            Role::Text,
            "User data",
            false,
        );
    }
    y += 22.0;
    let h =
        ui.p.paragraph(Face::Ui, 12.5, x, y, w, d.preselect, pal.muted);
    ui.reg(
        id("DPreselect"),
        Rect::new(x, y, w, h),
        Role::Text,
        d.preselect,
        false,
    );
    y += h + 14.0;
    if let Some(refused) = &d.refused {
        let h = ui.p.paragraph(Face::Ui, 12.5, x, y, w, refused, pal.text);
        ui.reg(
            id("DRefused"),
            Rect::new(x, y, w, h),
            Role::Text,
            refused,
            false,
        );
        y += h + 10.0;
    }
    ui.divider(x, y, w);
    y += 18.0;
    ui.p.text(Face::Semibold, 13.0, x, y, "Evidence", pal.text, w);
    y += 14.0;
    let top = y;
    let mut all = Vec::new();
    for line in &d.evidence {
        ui.p.icon(line.glyph.glyph(), 12.0, x + 6.0, y + 9.0, pal.muted);
        y +=
            ui.p.paragraph(Face::Ui, 12.5, x + 20.0, y, w - 20.0, &line.text, pal.text) + 4.0;
        all.push(line.text.as_str());
    }
    ui.reg(
        id("DEvidence"),
        Rect::new(x, top, w, (y - top).max(1.0)),
        Role::Text,
        &all.join(" "),
        false,
    );
    y += 10.0;
    ui.divider(x, y, w);
    y += 14.0;
    y = ui.fact(id("DContents"), x, y, 82.0, w, "Contents", &d.contents);
    y = ui.fact(id("DIfRemoved"), x, y, 82.0, w, "If removed", &d.if_removed);
    y = ui.fact(id("DFoundBy"), x, y, 82.0, w, "Found by", &d.found_by);
    if let Some(owner) = &d.owner {
        ui.fact(id("DOwner"), x, y, 82.0, w, "Shared", owner);
    }
    ui.p.restore(old);
}
