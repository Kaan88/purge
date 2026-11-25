//! The History & undo page: every cleanup, and the way back for those still in quarantine. Fed by
//! `purge-ui-model`'s `HistoryModel` (UI-PAGES2): the strip is its timeline (day markers and
//! cleanups, oldest left), the list its rows with day headers, the pane its detail of the selected
//! cleanup with the items "Show items" read, and the bars its bars.

use mdshared_ui::gfx::{Face, Rect, Rgb};
use mdshared_ui::glyph;
use mdshared_ui::pane::draw_row_fill;
use purge_ui_model::history::{HistoryChip, HistoryEntry, HistoryRow, HistorySession, text};

use super::model_bars;
use crate::model::Model;
use crate::ui::{BUTTON_H, Id, Key, Role, Style, Tone, Ui, bad_ink, id, within};
use crate::view::View;

const ROW_H: f32 = 58.0;
const DAY_H: f32 = 30.0;
const ITEM_H: f32 = 48.0;
const DAY_TILE_W: f32 = 96.0;

fn chip_tone(chip: HistoryChip) -> Tone {
    match chip {
        HistoryChip::Undoable => Tone::Accent,
        HistoryChip::Caution => Tone::Caution,
        HistoryChip::Neutral => Tone::Neutral,
    }
}

fn chip_icon(chip: HistoryChip) -> &'static str {
    match chip {
        HistoryChip::Undoable => glyph::UNDO,
        HistoryChip::Caution => glyph::WARN,
        HistoryChip::Neutral => glyph::CHECK,
    }
}

fn chip_ink(ui: &Ui, chip: HistoryChip) -> Rgb {
    let pal = ui.pal;
    if ui.hc {
        return pal.text;
    }
    match chip {
        HistoryChip::Undoable => pal.accent,
        HistoryChip::Caution => pal.warn,
        HistoryChip::Neutral => pal.muted,
    }
}

/// The right-hand line of a row: how long it can still be put back, or its state.
fn days_text(s: &HistorySession) -> String {
    if s.interrupted || !s.held {
        String::new()
    } else if s.file_days > 0 {
        format!(
            "{} day{} left",
            s.file_days,
            if s.file_days == 1 { "" } else { "s" }
        )
    } else {
        format!("Registry {} days left", s.backup_days)
    }
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let lk = ui.look;
    let h = &m.history;
    let page = &h.page;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;

    let y = content.y + 38.0;
    let label = "Check for interrupted cleanups";
    let bw = ui.button_w(label, None);
    let sessions = page.sessions();
    let sub = if sessions.is_empty() {
        String::new()
    } else {
        format!(
            "{} cleanup{} \u{b7} {} can be undone",
            sessions.len(),
            if sessions.len() == 1 { "" } else { "s" },
            h.undoable()
        )
    };
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        w - bw - 16.0,
    );
    let r = Rect::new(right - bw, y - BUTTON_H / 2.0, bw, BUTTON_H);
    ui.button(
        id("CheckInterrupted"),
        r,
        label,
        Style::Subtle,
        None,
        page.can_check_interrupted(),
    );

    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    let mut shown = 0u32;
    for (k, bar) in page.bars().iter().enumerate() {
        let said = format!("{} {}", bar.title, bar.message);
        if bar.closable && h.dismissed.contains(&said) {
            continue;
        }
        let host = Id("InfoBarHost", shown);
        shown += 1;
        let actions: &[(Id, &str)] = if bar.action.is_some() {
            &[
                (id("RecoverResume"), text::RESUME),
                (id("RecoverRollBack"), text::ROLL_BACK),
            ]
        } else {
            &[]
        };
        // Its own ids: "BarClose" is the Uninstall page's (UI-REVIEW1 S3).
        let close = Some(Id("HBarClose", k as u32 + 1));
        y = model_bars::bar(ui, host, left, y, w, bar, close, actions) + 8.0;
    }

    let bottom = content.bottom() - 16.0;
    if let Some((title, detail, retry)) = page.state_panel() {
        state_panel(ui, Rect::new(left, y, w, bottom - y), title, &detail, retry);
        return;
    }

    strip(ui, m, Rect::new(left, y, w, 70.0));
    y += 70.0 + 16.0;

    let side_w = 420.0_f32.min(w * 0.44);
    let list = Rect::new(left, y, w - side_w - 16.0, bottom - y);
    ops(ui, m, v, list);

    let pane = Rect::new(right - side_w, y, side_w, bottom - y);
    detail(ui, m, v, pane);
}

/// Loading, empty, or the error with Retry: the page's state instead of the list.
fn state_panel(ui: &mut Ui, r: Rect, title: &str, detail: &str, retry: bool) {
    let pal = ui.pal;
    let x = r.x + 24.0;
    let w = r.w - 48.0;
    let dh = if detail.is_empty() {
        0.0
    } else {
        ui.p.paragraph_height(Face::Ui, 13.0, w, detail) + 12.0
    };
    let card_h = 70.0 + dh + if retry { BUTTON_H + 12.0 } else { 0.0 };
    let card = Rect::new(r.x, r.y, r.w, card_h.min(r.h));
    ui.card(card);
    ui.reg(id("StatePanel"), card, Role::Text, title, false);
    let loading = title == text::READING_HISTORY;
    let ty = card.y + 36.0;
    if loading {
        ui.progress(
            id("LoadingRing"),
            Rect::new(x, card.y + 16.0, w.min(240.0), 3.0),
            None,
            title,
        );
    } else {
        ui.p.icon(glyph::RECENT, 18.0, x + 9.0, ty, pal.muted);
    }
    let tx = if loading { x } else { x + 28.0 };
    ui.text(
        id("StateTitle"),
        Face::Semibold,
        15.0,
        tx,
        ty,
        title,
        pal.text,
        w,
    );
    let mut dy = ty + 18.0;
    if !detail.is_empty() {
        let dh = ui.p.paragraph(Face::Ui, 13.0, x, dy, w, detail, pal.muted);
        ui.reg(
            id("StateDetail"),
            Rect::new(x, dy, w, dh),
            Role::Text,
            detail,
            false,
        );
        dy += dh + 12.0;
    }
    if retry {
        let bw = ui.button_w("Retry", None);
        ui.button(
            id("StateRetry"),
            Rect::new(x, dy, bw, BUTTON_H),
            "Retry",
            Style::Standard,
            None,
            true,
        );
    }
}

/// The strip: the cleanups in order of time, oldest left, each day's marker before its cleanups.
/// When they do not all fit, the newest do, and the selected one is kept in view.
fn strip(ui: &mut Ui, m: &Model, strip: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let h = &m.history;
    let page = &h.page;
    let timeline = page.timeline(&h.clock);
    ui.card(strip);
    ui.reg(
        id("StripCard"),
        strip,
        Role::Text,
        "Cleanups by date",
        false,
    );
    let n_sessions = timeline
        .iter()
        .filter(|r| matches!(r, HistoryRow::Session(_)))
        .count();
    let n_days = timeline.len() - n_sessions;
    let room = strip.w - 12.0 - n_days as f32 * DAY_TILE_W;
    let tile_w = (room / n_sessions.max(1) as f32).clamp(150.0, 220.0);
    let widths: Vec<f32> = timeline
        .iter()
        .map(|r| match r {
            HistoryRow::Day(_) => DAY_TILE_W,
            HistoryRow::Session(_) => tile_w,
        })
        .collect();
    let total: f32 = widths.iter().sum();
    let view_w = strip.w - 12.0;
    // The newest at the right edge, unless that hides the selected one.
    let mut shift = (total - view_w).max(0.0);
    let selected = h.selected_at();
    let mut x = 0.0;
    for (k, row) in timeline.iter().enumerate() {
        if matches!(row, HistoryRow::Session(i) if Some(*i) == selected) && x < shift {
            shift = x;
        }
        x += widths[k];
    }

    let old = ui.clip(strip.inset(1.0));
    let mut x = strip.x + 6.0 - shift;
    let mut rects = Vec::with_capacity(timeline.len());
    for wk in &widths {
        rects.push(Rect::new(x, strip.y + 6.0, wk - 4.0, strip.h - 12.0));
        x += wk;
    }
    let visible = |r: &Rect| r.right() > strip.x && r.x < strip.right();
    // The fills first: D1's line runs over them, from the first marker to the last.
    for (k, row) in timeline.iter().enumerate() {
        let r = rects[k];
        let sid = Id("StripItem", k as u32 + 1);
        let (name, on) = match row {
            HistoryRow::Day(title) => (title.clone(), false),
            HistoryRow::Session(i) => (
                page.session_row(*i)
                    .map(|s| s.mark_name)
                    .unwrap_or_default(),
                Some(*i) == selected,
            ),
        };
        if visible(&r) {
            ui.reg(sid, within(r, strip), Role::Item(on), &name, true);
            // A day marker stands for the cleanup after it, as its click selects.
            if let Some(s) = page
                .timeline_target(&timeline, k)
                .and_then(|i| page.sessions().get(i))
            {
                ui.key(sid, Key::Session(s.id.clone()));
            }
            if matches!(row, HistoryRow::Session(_)) {
                draw_row_fill(ui.p, &pal, r, ui.hot(sid), ui.down(sid), on);
            }
        }
    }
    if lk.soft && timeline.len() > 1 {
        let (a, b) = (rects[0], rects[rects.len() - 1]);
        ui.p.fill(Rect::new(a.x + 16.0, a.y + 12.0, b.x - a.x, 2.0), pal.line);
    }
    for (k, row) in timeline.iter().enumerate() {
        let r = rects[k];
        if !visible(&r) {
            continue;
        }
        let sid = Id("StripItem", k as u32 + 1);
        match row {
            HistoryRow::Day(title) => {
                let (cx, cy) = (r.x + 16.0, r.y + 13.0);
                if lk.soft {
                    let fill = ui.card_fill();
                    ui.p.rbox(Rect::new(cx - 5.0, cy - 5.0, 10.0, 10.0), 5.0, fill);
                    ui.p.ring(cx, cy, 3.5, 1.5, pal.muted, 1.0);
                } else {
                    ui.p.icon(glyph::RECENT, 12.0, cx, cy, pal.muted);
                }
                ui.p.text(
                    Face::Semibold,
                    12.0,
                    r.x + 10.0,
                    r.y + 40.0,
                    title,
                    pal.muted,
                    r.w - 14.0,
                );
            }
            HistoryRow::Session(i) => {
                if let Some(s) = page.sessions().get(*i) {
                    session_tile(ui, m, r, s);
                }
            }
        }
        ui.ring(sid, r, 4.0);
    }
    ui.p.restore(old);
}

fn session_tile(ui: &mut Ui, m: &Model, r: Rect, s: &HistorySession) {
    let pal = ui.pal;
    let lk = ui.look;
    let ink = chip_ink(ui, s.chip);
    let title = format!("{}  {}", s.time, s.name);
    if lk.soft {
        // D1: a time line. A dot per cleanup on one line, what is left of it and its name under.
        let (cx, cy) = (r.x + 16.0, r.y + 13.0);
        let fill = ui.card_fill();
        ui.p.rbox(Rect::new(cx - 7.0, cy - 7.0, 14.0, 14.0), 7.0, fill);
        if s.held || s.interrupted {
            ui.p.rbox(Rect::new(cx - 5.0, cy - 5.0, 10.0, 10.0), 5.0, ink);
        } else {
            ui.p.ring(cx, cy, 4.5, 1.5, ink, 1.0);
        }
        let line = ui.p.elide(Face::Ui, 11.5, &s.restorable(), r.w - 36.0);
        ui.p.text(Face::Ui, 11.5, r.x + 30.0, cy, &line, pal.muted, r.w - 36.0);
        let title = ui.p.elide(Face::Ui, 13.0, &title, r.w - 20.0);
        ui.p.text(
            Face::Ui,
            13.0,
            r.x + 10.0,
            r.y + 40.0,
            &title,
            pal.text,
            r.w - 20.0,
        );
    } else if lk.hero {
        // D3: each cleanup with the ring of the days its files can still be put back in.
        let (cx, cy) = (r.x + 24.0, r.cy());
        days_ring(ui, s, cx, cy, 16.0, m.quarantine.keep_days);
        let tx = r.x + 50.0;
        ui.p.text(Face::Ui, 11.5, tx, cy - 9.0, &s.time, pal.muted, r.w - 56.0);
        let name = ui.p.elide(Face::Ui, 13.0, &s.name, r.w - 56.0);
        ui.p.text(Face::Ui, 13.0, tx, cy + 9.0, &name, pal.text, r.w - 56.0);
    } else {
        ui.p.icon(chip_icon(s.chip), 13.0, r.x + 16.0, r.y + 18.0, ink);
        let line = ui.p.elide(Face::Ui, 12.0, &s.restorable(), r.w - 36.0);
        ui.p.text(
            Face::Ui,
            12.0,
            r.x + 30.0,
            r.y + 18.0,
            &line,
            pal.muted,
            r.w - 36.0,
        );
        let title = ui.p.elide(Face::Ui, 13.0, &title, r.w - 20.0);
        ui.p.text(
            Face::Ui,
            13.0,
            r.x + 10.0,
            r.y + 40.0,
            &title,
            pal.text,
            r.w - 20.0,
        );
    }
}

/// D3: the days a cleanup's files can still be put back in, as a ring that empties; a cleanup
/// with nothing to put back shows its state in an empty ring.
fn days_ring(ui: &mut Ui, s: &HistorySession, cx: f32, cy: f32, radius: f32, keep: u32) {
    let pal = ui.pal;
    if s.held && s.file_days > 0 && !s.interrupted {
        let ink = super::quarantine::days_ink(ui, s.file_days);
        let f = s.file_days as f32 / keep.max(1) as f32;
        ui.ring_gauge(cx, cy, radius, f, &s.file_days.to_string(), ink);
    } else {
        ui.ring_gauge(cx, cy, radius, 0.0, "", pal.muted);
        let ink = chip_ink(ui, s.chip);
        ui.p.icon(chip_icon(s.chip), 13.0, cx, cy, ink);
    }
}

/// The list: a header per day, then that day's cleanups, newest first. It scrolls.
fn ops(ui: &mut Ui, m: &Model, v: &mut View, list: Rect) {
    let h = &m.history;
    let page = &h.page;
    ui.card(list);
    ui.reg(id("Ops"), list, Role::Text, "Cleanups", false);
    let rows = page.rows(&h.clock);
    let view = list.inset(6.0);
    let height = |r: &HistoryRow| match r {
        HistoryRow::Day(_) => DAY_H,
        HistoryRow::Session(_) => ROW_H,
    };
    let content: f32 = rows.iter().map(height).sum();
    v.left_area = view;
    v.left_content = content;
    let off = v
        .left_scroll
        .offset(ui.cx.anim(), "history-scroll", content, view.h);
    let selected = h.selected_at();
    let old = ui.clip(view);
    let mut y = view.y - off;
    for row in &rows {
        let rh = height(row);
        let r = Rect::new(view.x, y, view.w, rh);
        y += rh;
        if r.bottom() < view.y || r.y > view.bottom() {
            continue;
        }
        match row {
            HistoryRow::Day(title) => {
                let pal = ui.pal;
                ui.p.text(
                    Face::Semibold,
                    12.0,
                    r.x + 12.0,
                    r.cy() + 3.0,
                    title,
                    pal.muted,
                    r.w - 24.0,
                );
            }
            HistoryRow::Session(i) => {
                let Some(s) = page.sessions().get(*i) else {
                    continue;
                };
                let oid = Id("Op", *i as u32 + 1);
                // The keyboard went to a row that is cut off: bring it into view.
                let cut = r.y < view.y || r.bottom() > view.bottom();
                if cut && ui.ringed(oid) {
                    let top = r.y - view.y + off;
                    let to = if r.y < view.y { top } else { top + rh - view.h };
                    if v.left_scroll.scroll_to(to, content, view.h) {
                        ui.cx.request_redraw_all();
                    }
                }
                op_row(ui, m, within(r, view), r, *i, s, Some(*i) == selected);
            }
        }
    }
    ui.p.restore(old);
}

fn op_row(ui: &mut Ui, m: &Model, hit: Rect, row: Rect, i: usize, s: &HistorySession, on: bool) {
    let pal = ui.pal;
    let page = &m.history.page;
    let oid = Id("Op", i as u32 + 1);
    let name = page.row_name(&HistoryRow::Session(i));
    ui.reg(oid, hit, Role::Item(on), &name, true);
    ui.key(oid, Key::Session(s.id.clone()));
    let fill = Rect::new(row.x, row.y + 1.0, row.w, row.h - 2.0);
    draw_row_fill(ui.p, &pal, fill, ui.hot(oid), ui.down(oid), on);
    let cy = row.cy();
    let (cx, r) = (row.x + 26.0, 15.0);
    if ui.look.hero {
        days_ring(ui, s, cx, cy, r + 1.0, m.quarantine.keep_days);
    } else {
        ui.p.ring(cx, cy, r, 1.25, pal.line, 1.0);
        ui.p.icon(chip_icon(s.chip), 14.0, cx, cy, pal.muted);
    }

    // From the right: the days left, then the state.
    let days = days_text(s);
    let urgent = s.held && !s.interrupted && s.file_days > 0 && s.file_days <= 7;
    let ink = if urgent && !ui.hc {
        bad_ink(&pal)
    } else {
        pal.muted
    };
    let dw = if days.is_empty() {
        0.0
    } else {
        ui.p.text_right(Face::Ui, 12.0, row.right() - 12.0, cy, &days, ink) + 10.0
    };
    let cw = ui.chip_w(s.state);
    let chip_x = row.right() - 12.0 - dw - cw;
    ui.chip(chip_x, cy, s.state, chip_tone(s.chip));

    let tx = row.x + 52.0;
    let tw = chip_x - 12.0 - tx;
    let mut title_w = tw;
    if s.has_alert {
        title_w = tw - 20.0;
        let ax = tx + ui.p.measure(Face::Ui, 14.0, &s.name).min(title_w) + 10.0;
        let ink = if ui.hc { pal.text } else { pal.warn };
        ui.p.icon(glyph::WARN, 12.0, ax, cy - 9.0, ink);
    }
    let title = ui.p.elide(Face::Ui, 14.0, &s.name, title_w);
    ui.p.text(Face::Ui, 14.0, tx, cy - 9.0, &title, pal.text, title_w);
    let when = format!("{} \u{b7} {}", s.time, s.detail);
    let when = ui.p.elide(Face::Ui, 12.0, &when, tw);
    ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &when, pal.muted, tw);
    ui.ring(oid, fill.inset(2.0), 4.0);
}

/// What the pane's note says for a cleanup's state.
fn note_of(s: &HistorySession) -> &'static str {
    if s.interrupted {
        text::RECOVERY_TEXT
    } else if s.held {
        "Putting back restores every item to where it was. An item whose place is taken by something newer is listed, never overwritten."
    } else {
        "Nothing of this cleanup is held any more: it was put back or rolled back, or what Purge kept of it was deleted."
    }
}

fn item_h(item: &HistoryEntry) -> f32 {
    if item.alert_text.is_some() {
        ITEM_H + 18.0
    } else {
        ITEM_H
    }
}

fn detail(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let h = &m.history;
    let page = &h.page;
    ui.card(r);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let (Some(s), Some(d)) = (page.selected(), page.detail(&h.clock)) else {
        ui.para(
            Face::Ui,
            13.0,
            x,
            r.y + 20.0,
            w,
            "Select a cleanup to see what it did.",
            pal.muted,
        );
        return;
    };
    let view = r.inset(1.0);
    let items = page.items().unwrap_or(&[]);
    let note = note_of(s);
    // The height of what the pane holds, for its scroll.
    let title_h = ui.p.paragraph_height(Face::Semibold, 16.0, w, &d.title);
    let summary_h = ui.p.paragraph_height(Face::Ui, 13.0, w, &d.summary);
    let note_h = ui.p.paragraph_height(Face::Ui, 13.0, w - 24.0, note);
    let expiry_h = ui.p.paragraph_height(Face::Ui, 12.0, w, &d.expiry);
    let items_h: f32 = items.iter().map(item_h).sum();
    let content = 18.0
        + title_h
        + 30.0
        + summary_h
        + 14.0
        + if d.show_items_visible {
            BUTTON_H + 12.0
        } else {
            0.0
        }
        + if items.is_empty() {
            0.0
        } else {
            12.0 + items_h + 14.0
        }
        + note_h
        + 16.0
        + BUTTON_H
        + 12.0
        + expiry_h
        + 18.0;
    v.page_area = view;
    v.page_content = content;
    let off = v
        .page_scroll
        .offset(ui.cx.anim(), "history-detail-scroll", content, view.h);
    let old = ui.clip(view);
    let mut y = r.y + 18.0 - off;
    ui.p.paragraph(Face::Semibold, 16.0, x, y, w, &d.title, pal.text);
    ui.reg(
        id("DTitle"),
        within(Rect::new(x, y, w, title_h), view),
        Role::Text,
        &d.title,
        false,
    );
    y += title_h + 6.0;
    ui.text(
        id("DState"),
        Face::Ui,
        12.0,
        x,
        y + 8.0,
        s.state,
        pal.muted,
        w,
    );
    y += 24.0;
    ui.p.paragraph(Face::Ui, 13.0, x, y, w, &d.summary, pal.muted);
    ui.reg(
        id("DSummary"),
        within(Rect::new(x, y, w, summary_h), view),
        Role::Text,
        &d.summary,
        false,
    );
    y += summary_h + 14.0;

    if d.show_items_visible {
        let label = "Show items";
        let bw = ui.button_w(label, None);
        ui.button(
            id("ShowItems"),
            Rect::new(x, y, bw, BUTTON_H),
            label,
            Style::Standard,
            None,
            d.show_items_enabled,
        );
        y += BUTTON_H + 12.0;
    }
    if !items.is_empty() {
        let border = Rect::new(x, y, w, 12.0 + items_h);
        ui.p.frame(border, 6.0, pal.page, pal.line);
        ui.reg(
            id("DItems"),
            within(border, view),
            Role::Text,
            &format!("{} items", items.len()),
            false,
        );
        let mut iy = border.y + 6.0;
        for (k, item) in items.iter().enumerate() {
            item_row(ui, Rect::new(x, iy, w, item_h(item)), k, item, view);
            iy += item_h(item);
        }
        y = border.bottom() + 14.0;
    }

    let ink = if ui.hc {
        pal.text
    } else if s.interrupted {
        pal.warn
    } else {
        pal.muted
    };
    ui.p.icon(glyph::INFO, 14.0, x + 7.0, y + 9.0, ink);
    ui.p.paragraph(Face::Ui, 13.0, x + 24.0, y, w - 24.0, note, pal.text);
    ui.reg(
        id("DNote"),
        within(Rect::new(x, y, w, note_h), view),
        Role::Text,
        note,
        false,
    );
    y += note_h + 16.0;

    let put_back = &d.restore_selected_text;
    let pw = ui.button_w(put_back, Some(glyph::UNDO));
    ui.button(
        id("RestoreSelected"),
        Rect::new(x, y, pw, BUTTON_H),
        put_back,
        Style::Accent,
        Some(glyph::UNDO),
        d.restore_selected_enabled,
    );
    let aw = ui.button_w("Put back all", None);
    ui.button(
        id("RestoreAll"),
        Rect::new(x + pw + 8.0, y, aw, BUTTON_H),
        "Put back all",
        Style::Standard,
        None,
        d.restore_all_enabled,
    );
    y += BUTTON_H + 12.0;

    ui.p.paragraph(Face::Ui, 12.0, x, y, w, &d.expiry, pal.muted);
    ui.reg(
        id("DExpiry"),
        within(Rect::new(x, y, w, expiry_h), view),
        Role::Text,
        &d.expiry,
        false,
    );
    ui.p.restore(old);
}

/// One item "Show items" read: its tick box (only one that can be put back can be ticked), its
/// name, what it is and how it ended, and the reconcile alert when there is one.
fn item_row(ui: &mut Ui, r: Rect, k: usize, item: &HistoryEntry, view: Rect) {
    let pal = ui.pal;
    let tid = Id("DItemTick", k as u32 + 1);
    let cy = r.y + 14.0;
    let seen = r.bottom() > view.y && r.y < view.bottom();
    if seen {
        ui.tick(
            tid,
            r.x + 12.0,
            cy,
            Some(item.checked),
            item.selectable,
            &item.display_name,
        );
        ui.key(tid, Key::Op(item.op));
    }
    let tx = r.x + 40.0;
    let tw = r.w - 52.0;
    let name = ui.p.elide(Face::Mono, 12.0, &item.display_name, tw);
    ui.p.text(Face::Mono, 12.0, tx, cy, &name, pal.text, tw);
    let what = format!("{} \u{b7} {}", item.kind_text, item.outcome_text);
    let what = ui.p.elide(Face::Ui, 12.0, &what, tw);
    let ink = if item.is_deleted && !ui.hc {
        pal.faint
    } else {
        pal.muted
    };
    ui.p.text(Face::Ui, 12.0, tx, cy + 18.0, &what, ink, tw);
    if let Some(alert) = &item.alert_text {
        let ink = if ui.hc { pal.text } else { pal.warn };
        ui.p.icon(glyph::WARN, 11.0, tx + 5.0, cy + 36.0, ink);
        let a = ui.p.elide(Face::Ui, 12.0, alert, tw - 18.0);
        ui.p.text(Face::Ui, 12.0, tx + 16.0, cy + 36.0, &a, ink, tw - 18.0);
        if seen {
            ui.reg(
                Id("DItemAlert", k as u32 + 1),
                within(Rect::new(tx, cy + 28.0, tw, 16.0), view),
                Role::Text,
                alert,
                false,
            );
        }
    }
}
