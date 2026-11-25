//! The Quarantine page: what is held, on which volume, and how long each cleanup has left. Fed by
//! `purge-ui-model`'s `VaultModel` (UI-PAGES2): a card per volume with its use against its cap,
//! the cleanups that hold something with their days-left rings, and a pane with the selected
//! cleanup's actions ("Put back…", "Delete now…" with its choice, "Choose items…") and, once read,
//! its quarantined items, each with its own "Delete now…".

use mdshared_ui::gfx::{Face, Rect, Rgb};
use mdshared_ui::glyph;
use mdshared_ui::link::LINK_H;
use mdshared_ui::pane::draw_row_fill;
use purge_ui_model::leftovers::format_size;
use purge_ui_model::vault::{VaultBarAction, VaultBatch, VaultChip, VaultItem, WARN_DAYS, text};

use super::model_bars;
use crate::model::Model;
use crate::ui::{BOX, BUTTON_H, Id, Key, Role, Style, Tone, Ui, bad_ink, id, within};
use crate::view::View;

const ROW_H: f32 = 62.0;
const ITEM_H: f32 = 50.0;

/// The colour that says how long a cleanup has left: the same in its ring and in its volume's bar.
pub(super) fn days_ink(ui: &Ui, days_left: i32) -> Rgb {
    let pal = ui.pal;
    if ui.hc {
        pal.text
    } else if days_left <= WARN_DAYS {
        bad_ink(&pal)
    } else if days_left <= 14 {
        pal.warn
    } else {
        pal.accent
    }
}

fn chip_tone(chip: VaultChip) -> Tone {
    match chip {
        VaultChip::Ok => Tone::Accent,
        VaultChip::Expired => Tone::Bad,
        VaultChip::Expiring => Tone::Caution,
        VaultChip::Partial => Tone::Neutral,
    }
}

/// The bytes a cleanup holds on the volume with this root.
fn on_volume(b: &VaultBatch, root: &str) -> u64 {
    b.usage
        .iter()
        .filter(|u| u.root.eq_ignore_ascii_case(root))
        .fold(0u64, |sum, u| sum.saturating_add(u.bytes))
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let q = &m.quarantine;
    let page = &q.page;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let w = right - left;

    let y = content.y + 38.0;
    let review = page.review_button();
    let list = [(
        id("ReviewButton"),
        text::REVIEW_AND_DELETE,
        Style::Standard,
        Some(glyph::DELETE),
        review.enabled,
    )];
    let bx = ui.buttons_right(right, y - BUTTON_H / 2.0, &list);
    if let Some(tip) = review.tooltip
        && let Some(c) = ui
            .ctls
            .iter_mut()
            .rev()
            .find(|c| c.id == id("ReviewButton"))
    {
        // A disabled button says why in its name: it shows no tooltip.
        c.label = format!("{}, {tip}", text::REVIEW_AND_DELETE);
    }
    let sub = if page.batches().is_empty() {
        "Where removed leftovers wait. Nothing here is gone until you delete it.".to_string()
    } else {
        format!(
            "{} items \u{b7} {} \u{b7} files kept {} days",
            q.total_items(),
            format_size(q.total_bytes()),
            q.keep_days
        )
    };
    ui.heading(
        left,
        y,
        m.page.title(),
        id("SubtitleText"),
        &sub,
        bx - 16.0 - left,
    );

    let mut y = content.y + 76.0 + (lk.margin - 28.0);
    let volumes = page.volumes();
    if !volumes.is_empty() {
        let top_h = if lk.hero { 124.0 } else { 74.0 };
        volume_cards(ui, m, Rect::new(left, y, w, top_h));
        y += top_h + 12.0;
    }

    for (n, bar) in page.bars().into_iter().enumerate() {
        let host = Id("InfoBarHost", n as u32);
        let actions: Vec<(Id, &str)> = match bar.action {
            Some(VaultBarAction::OpenHistory) => {
                vec![(id("BarOpenHistory"), VaultBarAction::OpenHistory.text())]
            }
            Some(VaultBarAction::Review) => vec![(id("BarReview"), VaultBarAction::Review.text())],
            None => Vec::new(),
        };
        y = model_bars::bar(ui, host, left, y, w, &bar, None, &actions) + 8.0;
    }
    y += 4.0;

    let bottom = content.bottom() - 16.0;
    if page.shows_empty_card() {
        let card = Rect::new(left, y, w, 78.0);
        ui.card(card);
        let title = "The quarantine is empty.";
        let detail =
            "Cleanups you run from Leftovers appear here, and you can put them back from here.";
        ui.reg(
            id("EmptyCard"),
            card,
            Role::Text,
            &format!("{title} {detail}"),
            false,
        );
        ui.p.icon(BOX, 16.0, card.x + 28.0, card.y + 28.0, pal.muted);
        ui.p.text(
            Face::Semibold,
            14.0,
            card.x + 48.0,
            card.y + 28.0,
            title,
            pal.text,
            w - 64.0,
        );
        ui.p.text(
            Face::Ui,
            13.0,
            card.x + 48.0,
            card.y + 52.0,
            detail,
            pal.muted,
            w - 64.0,
        );
        return;
    }
    if page.batches().is_empty() {
        // Loading or an error: the bars above say which.
        return;
    }

    let side_w = 400.0_f32.min(w * 0.42);
    let list = Rect::new(left, y, w - side_w - 16.0, bottom - y);
    batches(ui, m, v, list);

    let pane = Rect::new(right - side_w, y, side_w, bottom - y);
    side(ui, m, v, pane);
}

/// One card per volume (D3: one card with everything held as a ring, and the volumes beside it).
fn volume_cards(ui: &mut Ui, m: &Model, top: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let q = &m.quarantine;
    let page = &q.page;
    let volumes = page.volumes();
    let mut said = String::new();
    // A volume's bar: a part per cleanup on it in the colour of its days, then the room left
    // under the cap.
    let parts_of = |ui: &Ui, root: &str, used: u64, cap: u64| -> Vec<(f32, Rgb)> {
        let mut parts: Vec<(f32, Rgb)> = page
            .batches()
            .iter()
            .map(|b| (on_volume(b, root), days_ink(ui, b.days_left_shown)))
            .filter(|(bytes, _)| *bytes > 0)
            .map(|(bytes, c)| (bytes as f32, c))
            .collect();
        let held: f32 = parts.iter().map(|p| p.0).sum();
        let other = used.saturating_sub(held as u64) as f32;
        if other > 0.0 {
            parts.push((other, pal.muted));
        }
        let free = cap.saturating_sub(used) as f32;
        parts.push((free.max(1.0), pal.hover));
        parts
    };
    if lk.hero {
        let card = top;
        ui.card(card);
        let (rx, ry, rr) = (card.x + 68.0, card.cy(), 40.0);
        let parts: Vec<(f32, Rgb)> = page
            .batches()
            .iter()
            .map(|b| ((b.bytes as f32).sqrt(), days_ink(ui, b.days_left_shown)))
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
        let held = format!("{} held", format_size(q.total_bytes()));
        ui.p.text(
            Face::Semibold,
            22.0,
            tx,
            card.y + 60.0,
            &held,
            pal.text,
            260.0,
        );
        let soon = page
            .batches()
            .iter()
            .filter(|b| b.expiring || b.expired)
            .count();
        let line = format!(
            "{} cleanups \u{b7} {} expired or expiring \u{b7} files kept {} days",
            page.batches().len(),
            soon,
            q.keep_days
        );
        let line = ui.p.elide(Face::Ui, 12.5, &line, 300.0);
        ui.p.text(Face::Ui, 12.5, tx, card.y + 90.0, &line, pal.muted, 300.0);
        let vx = (tx + 320.0).max(card.right() - 440.0);
        let vw = card.right() - 20.0 - vx;
        let row_h = 30.0;
        let mut vy = card.cy() - row_h * volumes.len() as f32 / 2.0;
        for vol in volumes {
            if vw >= 160.0 {
                ui.p.text(
                    Face::Semibold,
                    12.5,
                    vx,
                    vy + row_h / 2.0,
                    &vol.root,
                    pal.text,
                    60.0,
                );
                let hw = ui.p.text_right(
                    Face::Ui,
                    12.0,
                    vx + vw,
                    vy + row_h / 2.0,
                    &vol.used_text,
                    pal.muted,
                );
                let bar = Rect::new(
                    vx + 48.0,
                    vy + row_h / 2.0 - 4.0,
                    vw - 48.0 - hw - 14.0,
                    8.0,
                );
                if bar.w >= 24.0 {
                    let parts = parts_of(ui, &vol.root, vol.used, vol.cap);
                    ui.parts_bar(bar, &parts);
                }
            }
            said.push_str(&format!("{}. {}. ", vol.tip(), vol.note));
            vy += row_h;
        }
    } else {
        let n = volumes.len().max(1);
        let vw = ((top.w - 12.0 * (n - 1) as f32) / n as f32).min(360.0);
        for (k, vol) in volumes.iter().enumerate() {
            let card = Rect::new(top.x + k as f32 * (vw + 12.0), top.y, vw, top.h);
            ui.card(card);
            let bar_y = if lk.soft {
                // D1: the amount is what the card is for; the volume is its caption.
                ui.p.text(
                    Face::Semibold,
                    11.0,
                    card.x + 16.0,
                    card.y + 16.0,
                    &format!("VOLUME {}", vol.root),
                    pal.muted,
                    vw - 32.0,
                );
                ui.p.text(
                    Face::Semibold,
                    16.0,
                    card.x + 16.0,
                    card.y + 36.0,
                    &vol.used_text,
                    pal.text,
                    vw - 32.0,
                );
                card.y + 52.0
            } else {
                ui.p.icon(BOX, 16.0, card.x + 24.0, card.y + 20.0, pal.muted);
                ui.p.text(
                    Face::Semibold,
                    14.0,
                    card.x + 42.0,
                    card.y + 20.0,
                    &vol.root,
                    pal.text,
                    vw - 60.0,
                );
                ui.p.text_right(
                    Face::Ui,
                    12.0,
                    card.right() - 16.0,
                    card.y + 20.0,
                    &vol.used_text,
                    pal.muted,
                );
                card.y + 38.0
            };
            let bar_h = if lk.soft { 6.0 } else { 8.0 };
            let parts = parts_of(ui, &vol.root, vol.used, vol.cap);
            ui.parts_bar(Rect::new(card.x + 16.0, bar_y, vw - 32.0, bar_h), &parts);
            let note = ui.p.elide(Face::Ui, 11.5, &vol.note, vw - 32.0);
            ui.p.text(
                Face::Ui,
                11.5,
                card.x + 16.0,
                bar_y + bar_h + 11.0,
                &note,
                pal.muted,
                vw - 32.0,
            );
            said.push_str(&format!("{}. {}. ", vol.tip(), vol.note));
        }
    }
    ui.reg(id("Volumes"), top, Role::Text, said.trim(), false);
}

/// The cleanups that hold something, newest first. It scrolls.
fn batches(ui: &mut Ui, m: &Model, v: &mut View, list: Rect) {
    let pal = ui.pal;
    let q = &m.quarantine;
    let page = &q.page;
    ui.card(list);
    ui.reg(id("Batches"), list, Role::Text, "By cleanup", false);
    ui.p.text(
        Face::Semibold,
        14.0,
        list.x + 18.0,
        list.y + 24.0,
        "By cleanup",
        pal.text,
        200.0,
    );
    let totals = page.totals();
    let room = list.w - 140.0;
    let shown = ui.p.elide(Face::Ui, 12.0, totals, room);
    let tw = ui.p.measure(Face::Ui, 12.0, &shown);
    ui.text(
        id("Totals"),
        Face::Ui,
        12.0,
        list.right() - 18.0 - tw,
        list.y + 24.0,
        &shown,
        pal.muted,
        tw + 2.0,
    );
    ui.say_whole(totals);
    let view = Rect::new(list.x + 6.0, list.y + 44.0, list.w - 12.0, list.h - 50.0);
    let content = page.batches().len() as f32 * ROW_H;
    v.left_area = view;
    v.left_content = content;
    let off = v
        .left_scroll
        .offset(ui.cx.anim(), "vault-scroll", content, view.h);
    let selected = q.selected_at();
    let old = ui.clip(view);
    for i in 0..page.batches().len() {
        let row = Rect::new(view.x, view.y - off + i as f32 * ROW_H, view.w, ROW_H);
        if row.bottom() < view.y || row.y > view.bottom() {
            continue;
        }
        let bid = Id("Batch", i as u32 + 1);
        let cut = row.y < view.y || row.bottom() > view.bottom();
        if cut && ui.ringed(bid) {
            let top = row.y - view.y + off;
            let to = if row.y < view.y {
                top
            } else {
                top + ROW_H - view.h
            };
            if v.left_scroll.scroll_to(to, content, view.h) {
                ui.cx.request_redraw_all();
            }
        }
        batch_row(ui, m, within(row, view), row, i, Some(i) == selected);
    }
    ui.p.restore(old);
}

fn batch_row(ui: &mut Ui, m: &Model, hit: Rect, row: Rect, i: usize, on: bool) {
    let pal = ui.pal;
    let page = &m.quarantine.page;
    let (Some(view), Some(b)) = (page.batch_row(i), page.batches().get(i)) else {
        return;
    };
    let bid = Id("Batch", i as u32 + 1);
    ui.reg(bid, hit, Role::Item(on), &view.accessible_name, true);
    ui.key(bid, Key::Session(b.id.clone()));
    let fill = Rect::new(row.x, row.y + 1.0, row.w, row.h - 2.0);
    draw_row_fill(ui.p, &pal, fill, ui.hot(bid), ui.down(bid), on);
    let cy = row.cy();
    // The days left as a ring: full at the first day, empty at the last.
    let ink = days_ink(ui, b.days_left_shown);
    let f = (view.ring / 100.0) as f32;
    ui.ring_gauge(row.x + 32.0, cy, 18.0, f, &view.days_text, ink);

    let cw = ui.chip_w(view.state);
    let chip_x = row.right() - 14.0 - cw;
    ui.chip(chip_x, cy - 9.0, view.state, chip_tone(view.chip));
    let urgent = b.expired || b.expiring;
    let when_ink = if urgent && !ui.hc {
        bad_ink(&pal)
    } else {
        pal.muted
    };
    ui.p.text_right(
        Face::Ui,
        12.0,
        row.right() - 14.0,
        cy + 12.0,
        &view.when,
        when_ink,
    );
    let ww = ui.p.measure(Face::Ui, 12.0, &view.when).max(cw);
    let tx = row.x + 64.0;
    let tw = row.right() - 14.0 - ww - 12.0 - tx;
    let title = ui.p.elide(Face::Ui, 14.0, &view.name, tw);
    ui.p.text(Face::Ui, 14.0, tx, cy - 9.0, &title, pal.text, tw);
    let what = ui.p.elide(Face::Ui, 12.0, &view.summary, tw);
    ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &what, pal.muted, tw);
    ui.ring(bid, fill.inset(2.0), 4.0);
}

/// The selected cleanup: what it holds, its actions, the "Delete now" choice while it is open,
/// and its quarantined items once "Choose items…" read them. It scrolls.
fn side(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let q = &m.quarantine;
    let page = &q.page;
    ui.card(r);
    ui.reg(
        id("ItemsPanel"),
        r,
        Role::Text,
        "The selected cleanup",
        false,
    );
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let (Some(at), Some(b)) = (
        q.selected_at(),
        q.selected.as_ref().and_then(|s| page.batch(s)),
    ) else {
        ui.para(
            Face::Ui,
            13.0,
            x,
            r.y + 20.0,
            w,
            "Select a cleanup to see what it holds.",
            pal.muted,
        );
        return;
    };
    let Some(row) = page.batch_row(at) else {
        return;
    };
    let view = r.inset(1.0);
    let flyout = q.flyout.as_ref().filter(|f| f.session == b.id);
    let choice = page.delete_now_choice(&b.id);
    let listed = page.items_for() == Some(&b.id);
    let items = if listed { page.items() } else { &[] };
    let detail_h = ui.p.paragraph_height(Face::Ui, 12.5, w, &row.detail);
    let flyout_h = match (flyout, &choice) {
        (Some(_), Some(c)) => {
            let intro = ui.p.paragraph_height(Face::Ui, 12.5, w - 28.0, c.intro);
            let also = if c.offers_backups {
                ui.p.paragraph_height(Face::Ui, 12.5, w - 60.0, text::ALSO_BACKUPS_TEXT)
                    .max(20.0)
                    + 12.0
            } else {
                0.0
            };
            28.0 + intro + 12.0 + also + BUTTON_H + 14.0
        }
        _ => 0.0,
    };
    let items_h = if listed {
        30.0 + 36.0 + items.len() as f32 * ITEM_H + 14.0
    } else {
        0.0
    };
    let content =
        24.0 + 22.0 + 20.0 + detail_h + 16.0 + BUTTON_H + 12.0 + flyout_h + 30.0 + items_h;
    v.page_area = view;
    v.page_content = content;
    let off = v
        .page_scroll
        .offset(ui.cx.anim(), "vault-side-scroll", content, view.h);
    let old = ui.clip(view);
    let mut y = r.y - off;

    let title = format!("{} \u{b7} {}", row.name, row.when);
    let shown = ui.p.elide(Face::Semibold, 14.0, &title, w);
    ui.text(
        id("ItemsTitle"),
        Face::Semibold,
        14.0,
        x,
        y + 24.0,
        &shown,
        pal.text,
        w,
    );
    ui.say_whole(&title);
    y += 46.0;
    ui.text(
        id("ItemsSummary"),
        Face::Ui,
        13.0,
        x,
        y,
        &row.summary,
        pal.text,
        w,
    );
    y += 14.0;
    ui.p.paragraph(Face::Ui, 12.5, x, y, w, &row.detail, pal.muted);
    ui.reg(
        id("ItemsExpiry"),
        within(Rect::new(x, y, w, detail_h), view),
        Role::Text,
        &row.detail,
        false,
    );
    y += detail_h + 16.0;

    // The actions: "Put back…", "Delete now…" (with its choice), "Choose items…".
    let mut bx = x;
    let restore_w = ui.button_w(row.restore_text, Some(glyph::UNDO));
    ui.button(
        id("VRestore"),
        Rect::new(bx, y, restore_w, BUTTON_H),
        row.restore_text,
        Style::Accent,
        Some(glyph::UNDO),
        row.can_act,
    );
    bx += restore_w + 8.0;
    if row.delete_visible {
        let label = "Delete now\u{2026}";
        let dw = ui.button_w(label, None);
        ui.button(
            id("VDeleteNow"),
            Rect::new(bx, y, dw, BUTTON_H),
            label,
            Style::Standard,
            None,
            row.can_act,
        );
        ui.say_whole("Delete what this cleanup still holds now");
        bx += dw + 8.0;
    }
    if row.choose_visible {
        let label = "Choose items\u{2026}";
        let cw = ui.button_w(label, None);
        if bx + cw <= x + w {
            ui.button(
                id("VChooseItems"),
                Rect::new(bx, y, cw, BUTTON_H),
                label,
                Style::Subtle,
                None,
                row.can_act,
            );
            ui.say_whole("Choose items to delete now");
        } else {
            y += BUTTON_H + 8.0;
            ui.button(
                id("VChooseItems"),
                Rect::new(x, y, cw, BUTTON_H),
                label,
                Style::Subtle,
                None,
                row.can_act,
            );
            ui.say_whole("Choose items to delete now");
        }
    }
    y += BUTTON_H + 12.0;

    if let (Some(f), Some(c)) = (flyout, &choice) {
        y = delete_choice(ui, Rect::new(x, y, w, flyout_h - 14.0), f.also_backups, c) + 14.0;
    }

    ui.link(
        id("VDetails"),
        x,
        y + (24.0 - LINK_H) / 2.0,
        "Details in History & undo",
    );
    y += 30.0;

    if listed {
        ui.divider(x, y, w);
        y += 8.0;
        let it = page.items_title().unwrap_or_default();
        let cw = ui.button_w("Close", None);
        let shown = ui.p.elide(Face::Semibold, 13.0, &it, w - cw - 8.0);
        ui.text(
            id("ItemsListTitle"),
            Face::Semibold,
            13.0,
            x,
            y + 16.0,
            &shown,
            pal.text,
            w - cw - 8.0,
        );
        ui.say_whole(&it);
        ui.button(
            id("ItemsClose"),
            Rect::new(x + w - cw, y, cw, BUTTON_H),
            "Close",
            Style::Subtle,
            None,
            true,
        );
        ui.say_whole("Close the item list");
        y += 36.0;
        let warn = "Deleting an item here is for good: Undo can no longer put it back. Purge asks in its security prompt first.";
        let wh = ui.p.paragraph(Face::Ui, 12.0, x, y, w, warn, pal.muted);
        y += wh + 6.0;
        let list = Rect::new(x, y, w, items.len() as f32 * ITEM_H);
        ui.reg(
            id("Items"),
            within(list, view),
            Role::Text,
            "Quarantined items of the cleanup",
            false,
        );
        for (k, item) in items.iter().enumerate() {
            item_row(ui, m, Rect::new(x, y, w, ITEM_H), k, item, view);
            y += ITEM_H;
        }
    }
    ui.p.restore(old);
}

/// The "Delete now" choice (the WinUI flyout), under the cleanup's buttons: what it deletes, the
/// opt-in for the registry backups, and "Continue to the security prompt…". Returns its bottom.
fn delete_choice(
    ui: &mut Ui,
    r: Rect,
    also: bool,
    c: &purge_ui_model::vault::DeleteNowChoice,
) -> f32 {
    let pal = ui.pal;
    ui.p.frame(r, 6.0, pal.page, pal.popup_line);
    ui.reg(id("DeleteNowFlyout"), r, Role::Text, c.intro, false);
    let x = r.x + 14.0;
    let w = r.w - 28.0;
    let mut y = r.y + 14.0;
    let ih = ui.p.paragraph(Face::Ui, 12.5, x, y, w, c.intro, pal.text);
    y += ih + 12.0;
    if c.offers_backups {
        let th =
            ui.p.paragraph_height(Face::Ui, 12.5, w - 32.0, text::ALSO_BACKUPS_TEXT)
                .max(20.0);
        ui.tick(
            id("AlsoBackups"),
            x,
            y + 9.0,
            Some(also),
            true,
            text::ALSO_BACKUPS_TEXT,
        );
        ui.p.paragraph(
            Face::Ui,
            12.5,
            x + 30.0,
            y,
            w - 32.0,
            text::ALSO_BACKUPS_TEXT,
            pal.text,
        );
        y += th + 12.0;
    }
    let can = if also {
        c.can_continue_ticked
    } else {
        c.can_continue_unticked
    };
    let gw = ui.button_w(text::CONTINUE_TO_PROMPT, None);
    ui.button(
        id("FlyoutContinue"),
        Rect::new(x, y, gw, BUTTON_H),
        text::CONTINUE_TO_PROMPT,
        Style::Accent,
        None,
        can,
    );
    let cw = ui.button_w("Cancel", None);
    ui.button(
        id("FlyoutCancel"),
        Rect::new(x + gw + 8.0, y, cw, BUTTON_H),
        "Cancel",
        Style::Standard,
        None,
        true,
    );
    r.bottom()
}

fn item_row(ui: &mut Ui, m: &Model, r: Rect, k: usize, item: &VaultItem, view: Rect) {
    let pal = ui.pal;
    let page = &m.quarantine.page;
    let label = "Delete now\u{2026}";
    let bw = ui.button_w(label, None);
    let cy = r.y + r.h / 2.0;
    if r.bottom() > view.y && r.y < view.bottom() {
        let did = Id("ItemDelete", k as u32 + 1);
        ui.button(
            did,
            Rect::new(r.right() - bw, cy - BUTTON_H / 2.0, bw, BUTTON_H),
            label,
            Style::Standard,
            None,
            page.items_can_act(),
        );
        ui.say_whole(&item.delete_label());
        ui.key(did, Key::Expiry(item.expiry_id));
    }
    let tw = r.w - bw - 12.0;
    let path = ui.p.elide(Face::Mono, 12.0, &item.path, tw);
    ui.p.text(Face::Mono, 12.0, r.x, cy - 9.0, &path, pal.text, tw);
    let detail = ui.p.elide(Face::Ui, 12.0, &item.detail, tw);
    let ink = if item.due && !ui.hc {
        bad_ink(&pal)
    } else {
        pal.muted
    };
    ui.p.text(Face::Ui, 12.0, r.x, cy + 9.0, &detail, ink, tw);
}
