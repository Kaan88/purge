//! The History & undo page: every cleanup, and the way back for those still in quarantine.

use mdshared_ui::gfx::{Face, Rect};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Severity};
use mdshared_ui::pane::draw_row_fill;

use crate::model::{Model, Op, OpState, date_of, kb_text};
use crate::ui::{BUTTON_H, Id, Role, Style, Tone, Ui, bad_ink, id, ok_ink};
use crate::view::View;

const ROW_H: f32 = 58.0;

fn state_chip(op: &Op) -> (&'static str, Tone) {
    match op.state {
        OpState::Undoable => ("Can be undone", Tone::Accent),
        OpState::Restored => ("Put back", Tone::Good),
        OpState::Expired => ("Expired", Tone::Neutral),
    }
}

fn state_icon(op: &Op) -> &'static str {
    match op.state {
        OpState::Undoable => glyph::UNDO,
        OpState::Restored => glyph::CHECK,
        OpState::Expired => glyph::CLOSE,
    }
}

pub fn draw(ui: &mut Ui, m: &Model, _v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let h = &m.history;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;

    let y = content.y + 38.0;
    let label = "Check for interrupted cleanups";
    let bw = ui.button_w(label, None);
    let sub = format!(
        "{} cleanups \u{b7} {} can be undone",
        h.ops.len(),
        h.undoable()
    );
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        w - bw - 16.0,
    );
    let r = Rect::new(right - bw, y - BUTTON_H / 2.0, bw, BUTTON_H);
    ui.button(id("CheckInterrupted"), r, label, Style::Subtle, None, true);

    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    if let Some(notice) = &h.notice {
        let bar = InfoBar::new(Severity::Success, "Put back.", notice.as_str());
        y = ui.infobar(id("InfoBarHost"), left, y, w, &bar, Some(id("NoticeClose"))) + 8.0;
    }
    if h.checked {
        let bar = InfoBar::new(
            Severity::Info,
            "No interrupted cleanups.",
            "Every cleanup ran to its end: nothing is half moved.",
        )
        .closable(false);
        y = ui.infobar(Id("InfoBarHost", 1), left, y, w, &bar, None) + 8.0;
    }

    // The strip: the cleanups in order of time, newest first.
    let strip = Rect::new(left, y, w, 70.0);
    ui.card(strip);
    ui.reg(
        id("StripCard"),
        strip,
        Role::Text,
        "Cleanups by date",
        false,
    );
    let old = ui.clip(strip.inset(1.0));
    let tile_w = ((w - 12.0) / h.ops.len().max(1) as f32).clamp(120.0, 220.0);
    let tile = |i: usize| {
        Rect::new(
            strip.x + 6.0 + i as f32 * tile_w,
            strip.y + 6.0,
            tile_w - 4.0,
            strip.h - 12.0,
        )
    };
    let keep = m.quarantine.keep_days;
    // The fills first: D1's line runs over them, from the first cleanup to the last.
    for (i, op) in h.ops.iter().enumerate() {
        let r = tile(i);
        let sid = Id("StripItem", i as u32 + 1);
        let on = i == h.selected;
        ui.reg(
            sid,
            r,
            Role::Item(on),
            &format!("{}, {}", date_of(op.when_days), op.title),
            true,
        );
        draw_row_fill(ui.p, &pal, r, ui.hot(sid), ui.down(sid), on);
    }
    if lk.soft && h.ops.len() > 1 {
        let (a, b) = (tile(0), tile(h.ops.len() - 1));
        ui.p.fill(Rect::new(a.x + 16.0, a.y + 12.0, b.x - a.x, 2.0), pal.line);
    }
    for (i, op) in h.ops.iter().enumerate() {
        let r = tile(i);
        let sid = Id("StripItem", i as u32 + 1);
        let ink = match op.state {
            OpState::Undoable => pal.accent,
            OpState::Restored => ok_ink(&pal),
            OpState::Expired => pal.muted,
        };
        let ink = if ui.hc { pal.text } else { ink };
        if lk.soft {
            // D1: a time line. A dot per cleanup on one line, the date and the title under it.
            let (cx, cy) = (r.x + 16.0, r.y + 13.0);
            let fill = ui.card_fill();
            ui.p.rbox(Rect::new(cx - 7.0, cy - 7.0, 14.0, 14.0), 7.0, fill);
            if op.state == OpState::Expired {
                ui.p.ring(cx, cy, 4.5, 1.5, ink, 1.0);
            } else {
                ui.p.rbox(Rect::new(cx - 5.0, cy - 5.0, 10.0, 10.0), 5.0, ink);
            }
            ui.p.text(
                Face::Ui,
                11.5,
                r.x + 30.0,
                cy,
                &date_of(op.when_days),
                pal.muted,
                r.w - 36.0,
            );
            let title = ui.p.elide(Face::Ui, 13.0, &op.title, r.w - 20.0);
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
            // D3: each cleanup with the ring of the days it can still be undone in.
            let (cx, cy) = (r.x + 24.0, r.cy());
            op_ring(ui, op, cx, cy, 16.0, keep);
            let tx = r.x + 50.0;
            ui.p.text(
                Face::Ui,
                11.5,
                tx,
                cy - 9.0,
                &date_of(op.when_days),
                pal.muted,
                r.w - 56.0,
            );
            let title = ui.p.elide(Face::Ui, 13.0, &op.title, r.w - 56.0);
            ui.p.text(Face::Ui, 13.0, tx, cy + 9.0, &title, pal.text, r.w - 56.0);
        } else {
            ui.p.icon(state_icon(op), 13.0, r.x + 16.0, r.y + 18.0, ink);
            ui.p.text(
                Face::Ui,
                12.0,
                r.x + 30.0,
                r.y + 18.0,
                &date_of(op.when_days),
                pal.muted,
                r.w - 36.0,
            );
            let title = ui.p.elide(Face::Ui, 13.0, &op.title, r.w - 20.0);
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
        ui.ring(sid, r, 4.0);
    }
    ui.p.restore(old);
    y += 70.0 + 16.0;

    let bottom = content.bottom() - 16.0;
    let side_w = 420.0_f32.min(w * 0.44);
    let list = Rect::new(left, y, w - side_w - 16.0, bottom - y);
    ui.card(list);
    ui.reg(id("Ops"), list, Role::Text, "Cleanups", false);
    let old = ui.clip(list.inset(1.0));
    let inner = list.inset(6.0);
    for (i, op) in h.ops.iter().enumerate() {
        let row = Rect::new(inner.x, inner.y + i as f32 * ROW_H, inner.w, ROW_H);
        if row.y >= inner.bottom() {
            break;
        }
        op_row(ui, row, i, op, i == h.selected, keep);
    }
    ui.p.restore(old);

    let pane = Rect::new(right - side_w, y, side_w, bottom - y);
    detail(ui, m, pane);
}

/// D3: the days a cleanup can still be undone in, as a ring that empties; a cleanup that is
/// past undoing shows its state in an empty ring.
fn op_ring(ui: &mut Ui, op: &Op, cx: f32, cy: f32, radius: f32, keep: u32) {
    let pal = ui.pal;
    if op.state == OpState::Undoable {
        let ink = super::quarantine::days_ink(ui, op.days_left);
        let f = op.days_left as f32 / keep.max(1) as f32;
        ui.ring_gauge(cx, cy, radius, f, &op.days_left.to_string(), ink);
    } else {
        ui.ring_gauge(cx, cy, radius, 0.0, "", pal.muted);
        let ink = if op.state == OpState::Restored && !ui.hc {
            ok_ink(&pal)
        } else {
            pal.muted
        };
        ui.p.icon(state_icon(op), 13.0, cx, cy, ink);
    }
}

fn op_row(ui: &mut Ui, row: Rect, i: usize, op: &Op, on: bool, keep: u32) {
    let pal = ui.pal;
    let oid = Id("Op", i as u32 + 1);
    let (chip, tone) = state_chip(op);
    ui.reg(
        oid,
        row,
        Role::Item(on),
        &format!("{}, {}, {chip}", op.title, date_of(op.when_days)),
        true,
    );
    let fill = Rect::new(row.x, row.y + 1.0, row.w, row.h - 2.0);
    draw_row_fill(ui.p, &pal, fill, ui.hot(oid), ui.down(oid), on);
    let cy = row.cy();
    let (cx, r) = (row.x + 26.0, 15.0);
    if ui.look.hero {
        op_ring(ui, op, cx, cy, r + 1.0, keep);
    } else {
        ui.p.ring(cx, cy, r, 1.25, pal.line, 1.0);
        ui.p.icon(state_icon(op), 14.0, cx, cy, pal.muted);
    }

    // From the right: the days left, then the state.
    let days = match op.state {
        OpState::Undoable => format!("{} days left", op.days_left),
        OpState::Restored => "Back in place".to_string(),
        OpState::Expired => "Deleted".to_string(),
    };
    let urgent = op.state == OpState::Undoable && op.days_left <= 7;
    let ink = if urgent && !ui.hc {
        bad_ink(&pal)
    } else {
        pal.muted
    };
    ui.p.text_right(Face::Ui, 12.0, row.right() - 12.0, cy, &days, ink);
    let cw = ui.chip_w(chip);
    let chip_x = row.right() - 12.0 - 92.0 - cw;
    ui.chip(chip_x, cy, chip, tone);

    let tx = row.x + 52.0;
    let tw = chip_x - 12.0 - tx;
    let title = ui.p.elide(Face::Ui, 14.0, &op.title, tw);
    ui.p.text(Face::Ui, 14.0, tx, cy - 9.0, &title, pal.text, tw);
    let when = format!(
        "{} \u{b7} {} \u{b7} {}",
        date_of(op.when_days),
        op.time,
        kb_text(op.kb)
    );
    ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &when, pal.muted, tw);
    ui.ring(oid, fill.inset(2.0), 4.0);
}

fn detail(ui: &mut Ui, m: &Model, r: Rect) {
    let pal = ui.pal;
    let h = &m.history;
    ui.card(r);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let Some(op) = h.current() else {
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
    let old = ui.clip(r.inset(1.0));
    let mut y = r.y + 18.0;
    let th =
        ui.p.paragraph(Face::Semibold, 16.0, x, y, w, &op.title, pal.text);
    ui.reg(
        id("DTitle"),
        Rect::new(x, y, w, th),
        Role::Text,
        &op.title,
        false,
    );
    y += th + 6.0;
    let when = format!(
        "{} at {} \u{b7} {}",
        date_of(op.when_days),
        op.time,
        kb_text(op.kb)
    );
    ui.p.text(Face::Ui, 12.0, x, y + 8.0, &when, pal.muted, w);
    y += 24.0;
    let sh =
        ui.p.paragraph(Face::Ui, 13.0, x, y, w, &op.summary, pal.muted);
    ui.reg(
        id("DSummary"),
        Rect::new(x, y, w, sh),
        Role::Text,
        &op.summary,
        false,
    );
    y += sh + 14.0;

    let label = if h.show_items {
        "Hide items".to_string()
    } else {
        format!("Show items ({})", op.items.len())
    };
    let bw = ui.button_w(&label, None);
    ui.button(
        id("ShowItems"),
        Rect::new(x, y, bw, BUTTON_H),
        &label,
        Style::Standard,
        None,
        true,
    );
    y += BUTTON_H + 12.0;
    if h.show_items {
        let border = Rect::new(x, y, w, 12.0 + op.items.len() as f32 * 40.0);
        ui.p.frame(border, 6.0, pal.page, pal.line);
        ui.reg(
            id("DItems"),
            border,
            Role::Text,
            &format!("{} items", op.items.len()),
            false,
        );
        let mut iy = border.y + 6.0;
        for (path, kind) in &op.items {
            let path = ui.p.elide(Face::Mono, 12.0, path, w - 24.0);
            ui.p.text(
                Face::Mono,
                12.0,
                x + 12.0,
                iy + 12.0,
                &path,
                pal.text,
                w - 24.0,
            );
            ui.p.text(
                Face::Ui,
                12.0,
                x + 12.0,
                iy + 29.0,
                kind,
                pal.muted,
                w - 24.0,
            );
            iy += 40.0;
        }
        y = border.bottom() + 14.0;
    }

    let note = match op.state {
        OpState::Undoable => {
            "Putting back restores every item to where it was. An item whose place is taken by something newer is listed, never overwritten."
        }
        OpState::Restored => {
            "These items are back where they came from. Nothing of this cleanup is in quarantine."
        }
        OpState::Expired => {
            "The days in quarantine ran out and the items were deleted. This cleanup cannot be undone."
        }
    };
    ui.p.icon(glyph::INFO, 14.0, x + 7.0, y + 9.0, pal.muted);
    let nh =
        ui.p.paragraph(Face::Ui, 13.0, x + 24.0, y, w - 24.0, note, pal.text);
    ui.reg(id("DNote"), Rect::new(x, y, w, nh), Role::Text, note, false);
    y += nh + 16.0;

    let n = op.items.len();
    let put_back = match op.state {
        OpState::Undoable => format!("Put back {n} item{}", if n == 1 { "" } else { "s" }),
        OpState::Restored => "Already put back".to_string(),
        OpState::Expired => "Cannot be put back".to_string(),
    };
    let pw = ui.button_w(&put_back, Some(glyph::UNDO));
    let can = op.state == OpState::Undoable;
    ui.button(
        id("RestoreSelected"),
        Rect::new(x, y, pw, BUTTON_H),
        &put_back,
        Style::Accent,
        Some(glyph::UNDO),
        can,
    );
    let aw = ui.button_w("Put back all", None);
    let all = Rect::new(x + pw + 8.0, y, aw, BUTTON_H);
    ui.button(
        id("RestoreAll"),
        all,
        "Put back all",
        Style::Standard,
        None,
        h.undoable() > 0,
    );
    y += BUTTON_H + 12.0;

    let expiry = match op.state {
        OpState::Undoable => format!(
            "Kept for {} more day{}, then deleted for good.",
            op.days_left,
            if op.days_left == 1 { "" } else { "s" }
        ),
        OpState::Restored => "Nothing left to expire.".to_string(),
        OpState::Expired => "Deleted when its days ran out.".to_string(),
    };
    ui.text(
        id("DExpiry"),
        Face::Ui,
        12.0,
        x,
        y + 8.0,
        &expiry,
        pal.muted,
        w,
    );
    ui.p.restore(old);
}
