//! The Quarantine page: what is held, on which volume, and how long each batch has left.

use mdshared_ui::gfx::{Face, Rect, Rgb};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Severity};
use mdshared_ui::link::LINK_H;
use mdshared_ui::pane::draw_row_fill;

use crate::model::{Batch, Model, kb_text};
use crate::ui::{BOX, BUTTON_H, Id, Role, Style, Ui, bad_ink, id};
use crate::view::View;

const ROW_H: f32 = 62.0;
/// A batch with this many days or fewer is "expiring soon".
const SOON: u32 = 7;

/// The colour that says how long a batch has left: the same in its ring and in its volume's bar.
pub(super) fn days_ink(ui: &Ui, days_left: u32) -> Rgb {
    let pal = ui.pal;
    if ui.hc {
        pal.text
    } else if days_left <= SOON {
        bad_ink(&pal)
    } else if days_left <= 14 {
        pal.warn
    } else {
        pal.accent
    }
}

pub fn draw(ui: &mut Ui, m: &Model, _v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let q = &m.quarantine;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;

    let y = content.y + 38.0;
    let soon: Vec<&Batch> = q.batches.iter().filter(|b| b.days_left <= SOON).collect();
    let review = if q.reviewing {
        "Hide what expires soon".to_string()
    } else {
        format!("Review what expires soon ({})", soon.len())
    };
    let list = [
        (
            id("ReviewButton"),
            review.as_str(),
            Style::Standard,
            None,
            !soon.is_empty(),
        ),
        (
            id("EmptyNow"),
            "Empty quarantine\u{2026}",
            Style::Standard,
            Some(glyph::DELETE),
            true,
        ),
    ];
    let bx = ui.buttons_right(right, y - BUTTON_H / 2.0, &list);
    let sub = format!(
        "{} items \u{b7} {} \u{b7} kept {} days",
        q.total_items(),
        kb_text(q.total_kb()),
        q.keep_days
    );
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        bx - 16.0 - left,
    );

    // One card per volume: what is held there, a part of the bar for each batch.
    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    let volumes = q.volumes();
    let vw =
        ((w - 12.0 * (volumes.len().max(1) - 1) as f32) / volumes.len().max(1) as f32).min(360.0);
    let mut said = String::new();
    let top_h = if lk.hero { 124.0 } else { 74.0 };
    if lk.hero {
        // D3: everything held as one ring, a part for each batch in the colour of the days it
        // has left, and the volumes beside it.
        let card = Rect::new(left, y, w, top_h);
        ui.card(card);
        let (rx, ry, rr) = (card.x + 68.0, card.cy(), 40.0);
        let parts: Vec<(f32, _)> = q
            .batches
            .iter()
            .map(|b| ((b.kb as f32).sqrt(), days_ink(ui, b.days_left)))
            .collect();
        ui.donut(rx, ry, rr, 10.0, &parts);
        let mid = Rect::new(rx - rr, ry - rr - 6.0, rr * 2.0, rr * 2.0);
        ui.p.text_center(
            Face::Semibold,
            20.0,
            mid,
            &q.total_items().to_string(),
            pal.text,
        );
        let under = Rect::new(rx - rr, ry + 6.0, rr * 2.0, 16.0);
        ui.p.text_center(Face::Ui, 10.5, under, "items", pal.muted);
        let tx = card.x + 136.0;
        ui.p.text(
            Face::Semibold,
            11.0,
            tx,
            card.y + 32.0,
            "IN QUARANTINE",
            pal.muted,
            220.0,
        );
        let held = format!("{} held", kb_text(q.total_kb()));
        ui.p.text(
            Face::Semibold,
            22.0,
            tx,
            card.y + 60.0,
            &held,
            pal.text,
            260.0,
        );
        let line = format!(
            "{} batches \u{b7} {} expiring soon \u{b7} kept {} days",
            q.batches.len(),
            soon.len(),
            q.keep_days
        );
        ui.p.text(Face::Ui, 12.5, tx, card.y + 90.0, &line, pal.muted, 300.0);
        // The volumes, one line each, at the card's right.
        let vx = (tx + 320.0).max(card.right() - 440.0);
        let vw = card.right() - 20.0 - vx;
        let row_h = 30.0;
        let mut vy = card.cy() - row_h * volumes.len() as f32 / 2.0;
        for (volume, kb) in &volumes {
            let held = format!("{} held", kb_text(*kb));
            if vw >= 160.0 {
                ui.p.text(
                    Face::Semibold,
                    12.5,
                    vx,
                    vy + row_h / 2.0,
                    &format!("Volume {volume}"),
                    pal.text,
                    80.0,
                );
                let hw =
                    ui.p.text_right(Face::Ui, 12.0, vx + vw, vy + row_h / 2.0, &held, pal.muted);
                let parts: Vec<(f32, _)> = q
                    .batches
                    .iter()
                    .filter(|b| b.volume == *volume)
                    .map(|b| ((b.kb as f32).sqrt(), days_ink(ui, b.days_left)))
                    .collect();
                let bar = Rect::new(
                    vx + 78.0,
                    vy + row_h / 2.0 - 4.0,
                    vw - 78.0 - hw - 14.0,
                    8.0,
                );
                if bar.w >= 24.0 {
                    ui.parts_bar(bar, &parts);
                }
            }
            said.push_str(&format!("{volume} {held}. "));
            vy += row_h;
        }
    } else {
        for (k, (volume, kb)) in volumes.iter().enumerate() {
            let card = Rect::new(left + k as f32 * (vw + 12.0), y, vw, 74.0);
            ui.card(card);
            let held = format!("{} held", kb_text(*kb));
            let bar_y = if lk.soft {
                // D1: the amount is what the card is for; the volume is its caption.
                let caption = format!("VOLUME {volume}");
                ui.p.text(
                    Face::Semibold,
                    11.0,
                    card.x + 16.0,
                    card.y + 18.0,
                    &caption,
                    pal.muted,
                    vw - 32.0,
                );
                ui.p.text(
                    Face::Semibold,
                    17.0,
                    card.x + 16.0,
                    card.y + 40.0,
                    &held,
                    pal.text,
                    vw - 32.0,
                );
                card.y + 58.0
            } else {
                ui.p.icon(BOX, 16.0, card.x + 24.0, card.y + 24.0, pal.muted);
                ui.p.text(
                    Face::Semibold,
                    14.0,
                    card.x + 42.0,
                    card.y + 24.0,
                    &format!("Volume {volume}"),
                    pal.text,
                    vw - 60.0,
                );
                ui.p.text_right(
                    Face::Ui,
                    12.0,
                    card.right() - 16.0,
                    card.y + 24.0,
                    &held,
                    pal.muted,
                );
                card.y + 48.0
            };
            let parts: Vec<(f32, _)> = q
                .batches
                .iter()
                .filter(|b| b.volume == *volume)
                .map(|b| ((b.kb as f32).sqrt(), days_ink(ui, b.days_left)))
                .collect();
            let bar_h = if lk.soft { 6.0 } else { 8.0 };
            ui.parts_bar(Rect::new(card.x + 16.0, bar_y, vw - 32.0, bar_h), &parts);
            said.push_str(&format!("{volume} {held}. "));
        }
    }
    ui.reg(
        id("Volumes"),
        Rect::new(left, y, w, top_h),
        Role::Text,
        said.trim(),
        false,
    );
    y += top_h + 12.0;

    let bar = InfoBar::new(
        Severity::Info,
        "Nothing here is deleted yet.",
        "An item is deleted only when its days run out or when you empty the quarantine. Until then History & undo puts it back.",
    )
    .closable(false);
    y = ui.infobar(id("InfoBarHost"), left, y, w, &bar, None) + 8.0;
    if q.reviewing {
        for (k, b) in soon.iter().enumerate() {
            let message = format!(
                "{} items \u{b7} {} are deleted for good in {} day{}. Put them back from History & undo if you still want them.",
                b.items,
                kb_text(b.kb),
                b.days_left,
                if b.days_left == 1 { "" } else { "s" }
            );
            let bar = InfoBar::new(
                Severity::Warning,
                format!("Expiring soon: {}", b.title),
                message,
            )
            .closable(false);
            y = ui.infobar(Id("InfoBarHost", k as u32 + 1), left, y, w, &bar, None) + 8.0;
        }
    }
    y += 4.0;

    let bottom = content.bottom() - 16.0;
    let side_w = 400.0_f32.min(w * 0.42);
    let list = Rect::new(left, y, w - side_w - 16.0, bottom - y);
    ui.card(list);
    let old = ui.clip(list.inset(1.0));
    ui.p.text(
        Face::Semibold,
        14.0,
        list.x + 18.0,
        list.y + 24.0,
        "Batches",
        pal.text,
        200.0,
    );
    let totals = format!(
        "{} batches \u{b7} {} items \u{b7} {}",
        q.batches.len(),
        q.total_items(),
        kb_text(q.total_kb())
    );
    let tw = ui.p.measure(Face::Ui, 12.0, &totals);
    ui.text(
        id("Totals"),
        Face::Ui,
        12.0,
        list.right() - 18.0 - tw,
        list.y + 24.0,
        &totals,
        pal.muted,
        tw + 2.0,
    );
    let inner = Rect::new(list.x + 6.0, list.y + 44.0, list.w - 12.0, list.h - 50.0);
    for (i, b) in q.batches.iter().enumerate() {
        let row = Rect::new(inner.x, inner.y + i as f32 * ROW_H, inner.w, ROW_H);
        if row.y >= inner.bottom() {
            break;
        }
        batch_row(ui, row, i, b, i == q.selected, q.keep_days);
    }
    ui.p.restore(old);

    let pane = Rect::new(right - side_w, y, side_w, bottom - y);
    items(ui, m, pane);
}

fn batch_row(ui: &mut Ui, row: Rect, i: usize, b: &Batch, on: bool, keep: u32) {
    let pal = ui.pal;
    let bid = Id("Batch", i as u32 + 1);
    let left = format!(
        "{} day{} left",
        b.days_left,
        if b.days_left == 1 { "" } else { "s" }
    );
    ui.reg(
        bid,
        row,
        Role::Item(on),
        &format!("{}, {} items, {left}", b.title, b.items),
        true,
    );
    let fill = Rect::new(row.x, row.y + 1.0, row.w, row.h - 2.0);
    draw_row_fill(ui.p, &pal, fill, ui.hot(bid), ui.down(bid), on);
    let cy = row.cy();
    // The days left as a ring: full at the first day, empty at the last.
    let ink = days_ink(ui, b.days_left);
    let f = b.days_left as f32 / keep.max(1) as f32;
    ui.ring_gauge(row.x + 32.0, cy, 18.0, f, &b.days_left.to_string(), ink);

    let soon = b.days_left <= SOON;
    let word_ink = if soon && !ui.hc {
        bad_ink(&pal)
    } else {
        pal.muted
    };
    let word = if soon {
        format!("{left} \u{b7} expiring soon")
    } else {
        left
    };
    let ww =
        ui.p.text_right(Face::Ui, 12.0, row.right() - 14.0, cy, &word, word_ink);
    let tx = row.x + 64.0;
    let tw = row.right() - 14.0 - ww - 12.0 - tx;
    let title = ui.p.elide(Face::Ui, 14.0, b.title, tw);
    ui.p.text(Face::Ui, 14.0, tx, cy - 9.0, &title, pal.text, tw);
    let what = format!(
        "{} items \u{b7} {} \u{b7} on {}",
        b.items,
        kb_text(b.kb),
        b.volume
    );
    ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &what, pal.muted, tw);
    ui.ring(bid, fill.inset(2.0), 4.0);
}

/// The items of the selected batch. The mockup knows them from the history entry of the same
/// program.
fn items(ui: &mut Ui, m: &Model, r: Rect) {
    let pal = ui.pal;
    let q = &m.quarantine;
    ui.card(r);
    ui.reg(id("ItemsPanel"), r, Role::Text, "Items of the batch", false);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let Some(b) = q.batches.get(q.selected) else {
        ui.para(
            Face::Ui,
            13.0,
            x,
            r.y + 20.0,
            w,
            "Select a batch to see its items.",
            pal.muted,
        );
        return;
    };
    let old = ui.clip(r.inset(1.0));
    let title = format!("{} \u{b7} {} items", b.title, b.items);
    let title = ui.p.elide(Face::Semibold, 14.0, &title, w);
    ui.text(
        id("ItemsTitle"),
        Face::Semibold,
        14.0,
        x,
        r.y + 24.0,
        &title,
        pal.text,
        w,
    );
    let mut y = r.y + 46.0;
    ui.divider(x, y, w);
    y += 8.0;
    let known = m
        .history
        .ops
        .iter()
        .find(|o| o.title.ends_with(b.title))
        .map(|o| o.items.as_slice())
        .unwrap_or(&[]);
    for (path, kind) in known {
        let path = ui.p.elide(Face::Mono, 12.0, path, w);
        ui.p.text(Face::Mono, 12.0, x, y + 12.0, &path, pal.text, w);
        ui.p.text(Face::Ui, 12.0, x, y + 29.0, kind, pal.muted, w);
        y += 42.0;
    }
    let more = (b.items as usize).saturating_sub(known.len());
    if more > 0 {
        ui.p.text(
            Face::Ui,
            12.5,
            x,
            y + 10.0,
            &format!("and {more} more"),
            pal.muted,
            w,
        );
        y += 26.0;
    }
    y += 6.0;
    ui.divider(x, y, w);
    y += 12.0;
    let end = format!(
        "Deleted for good in {} day{} unless put back.",
        b.days_left,
        if b.days_left == 1 { "" } else { "s" }
    );
    ui.text(
        id("ItemsExpiry"),
        Face::Ui,
        12.5,
        x,
        y + 8.0,
        &end,
        pal.text,
        w,
    );
    y += 24.0;
    ui.link(
        id("OpenHistory"),
        x,
        y + (24.0 - LINK_H) / 2.0,
        "Put back from History & undo",
    );
    ui.p.restore(old);
}
