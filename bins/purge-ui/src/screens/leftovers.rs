//! The Leftovers page: what a program left behind, in groups that open and close, each item
//! with a box, and the evidence for the item that is selected. Only what is certain starts
//! ticked; the model decides that, and this file only shows it.

use mdshared_ui::expander;
use mdshared_ui::gfx::{Face, Rect};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Severity};
use mdshared_ui::pane::draw_row_fill;
use mdshared_ui::scroll::{draw_scrollbar_animated, scrollbar};

use crate::app::item_no;
use crate::model::{Leftover, LeftoverPhase, Model, Rating, kb_text};
use crate::ui::{BUTTON_H, Id, LOCK, Role, Style, Tone, Ui, id, ok_ink, within};
use crate::view::View;

const ROW_H: f32 = 46.0;
const FOOTER_H: f32 = 56.0;
/// The column at the left of the list that holds the boxes.
const GUTTER: f32 = 30.0;

fn rating_tone(r: Rating) -> Tone {
    match r {
        Rating::Safe => Tone::Good,
        Rating::Likely => Tone::Caution,
        Rating::Protected => Tone::Outline,
    }
}

fn group_icon(title: &str) -> &'static str {
    match title {
        "Registry" => glyph::TABLE,
        "Services and scheduled tasks" => glyph::TASK,
        "Shortcuts" => glyph::LINK,
        _ => glyph::FOLDER,
    }
}

fn user_data(item: &Leftover) -> bool {
    item.what.starts_with("Profile")
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let l = &m.leftovers;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;
    let y = content.y + 38.0;

    // The title, with the program's tile once there is a program.
    let program = l.program.and_then(|p| m.programs.all.get(p));
    let mut x = left;
    if let Some(g) = program {
        ui.tile(Rect::new(x, y - 18.0, 36.0, 36.0), &g.name, &g.publisher);
        x += 48.0;
    }
    let mut room = right - x;
    if l.phase == LeftoverPhase::Review {
        room = review_buttons(ui, m, right, y) - 16.0 - x;
    }
    let title = match program {
        Some(g) => format!("Leftovers of {}", g.name),
        None => "Leftovers".to_string(),
    };
    let sub = match l.phase {
        LeftoverPhase::Empty => "No scan yet".to_string(),
        LeftoverPhase::Waiting => "Post-uninstall scan \u{b7} running".to_string(),
        LeftoverPhase::Review => format!("Post-uninstall scan \u{b7} {} items", l.count()),
        LeftoverPhase::Moved => "Moved to quarantine".to_string(),
        LeftoverPhase::Undone => "Put back".to_string(),
    };
    if lk.stacked {
        // D1: the scan's line stands under the title, as on every page of this design.
        let title =
            ui.p.elide(Face::Semibold, lk.h1 - 4.0, &title, room.max(120.0));
        ui.text(
            id("TitleText"),
            Face::Semibold,
            lk.h1 - 4.0,
            x,
            y - 8.0,
            &title,
            pal.text,
            room,
        );
        let sub = ui.p.elide(Face::Ui, 13.0, &sub, room.max(0.0));
        ui.text(
            id("SubtitleText"),
            Face::Ui,
            13.0,
            x,
            y + 15.0,
            &sub,
            pal.muted,
            room,
        );
    } else {
        let sw = ui.p.measure(Face::Ui, 13.0, &sub) + 14.0;
        let title =
            ui.p.elide(Face::Semibold, lk.h1, &title, (room - sw).max(120.0));
        let tw = ui.text(
            id("TitleText"),
            Face::Semibold,
            lk.h1,
            x,
            y,
            &title,
            pal.text,
            room,
        );
        let sub =
            ui.p.elide(Face::Ui, 13.0, &sub, (room - tw - 14.0).max(0.0));
        ui.text(
            id("SubtitleText"),
            Face::Ui,
            13.0,
            x + tw + 14.0,
            y + lk.h1 * 0.2,
            &sub,
            pal.muted,
            room,
        );
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
/// open or close every group, and tick the Likely items too. Returns where they begin.
pub fn review_buttons(ui: &mut Ui, m: &Model, right: f32, cy: f32) -> f32 {
    let l = &m.leftovers;
    let expand = if l.all_open() {
        "Collapse all"
    } else {
        "Expand all"
    };
    let likely = l.count_of(Rating::Likely);
    let weak = if l.likely_ticked() {
        "Untick the likely ones".to_string()
    } else {
        format!("Tick the likely ones too ({likely})")
    };
    let list = [
        (id("ExpandButton"), expand, Style::Subtle, None, true),
        (
            id("WeakButton"),
            weak.as_str(),
            Style::Subtle,
            None,
            likely > 0,
        ),
    ];
    ui.buttons_right(right, cy - BUTTON_H / 2.0, &list)
}

/// Everything under the title, for the phase the review is in. `area` is as wide as the page;
/// the side margins are kept inside it. D2 draws this inside its flow as well.
pub fn body(ui: &mut Ui, m: &Model, v: &mut View, area: Rect) {
    match m.leftovers.phase {
        LeftoverPhase::Empty => empty(ui, area),
        LeftoverPhase::Waiting => waiting(ui, m, area),
        LeftoverPhase::Review => review(ui, m, v, area),
        LeftoverPhase::Moved => moved(ui, m, area),
        LeftoverPhase::Undone => undone(ui, m, area),
    }
}

fn empty(ui: &mut Ui, area: Rect) {
    let pal = ui.pal;
    let x = area.x + ui.look.margin;
    let w = (area.w - 2.0 * ui.look.margin).min(620.0);
    let text = "Uninstall a program and Purge lists here what it left behind: files, registry keys, tasks and shortcuts. Nothing is moved until you have seen the list.";
    let th = ui.p.paragraph_height(Face::Ui, 13.0, w - 56.0, text);
    let card = Rect::new(x, area.y, w, 28.0 + 30.0 + th + 16.0 + BUTTON_H + 28.0);
    ui.card(card);
    ui.text(
        id("EmptyTitle"),
        Face::Semibold,
        20.0,
        card.x + 28.0,
        card.y + 40.0,
        "No scan yet",
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
    let bw = ui.button_w("Go to Programs", None);
    let r = Rect::new(card.x + 28.0, card.y + 58.0 + h + 16.0, bw, BUTTON_H);
    ui.button(
        id("GoPrograms"),
        r,
        "Go to Programs",
        Style::Standard,
        None,
        true,
    );
}

fn waiting(ui: &mut Ui, m: &Model, area: Rect) {
    let pal = ui.pal;
    let name = m
        .leftovers
        .program
        .and_then(|p| m.programs.all.get(p))
        .map_or("the program", |p| p.name.as_str());
    let w = (area.w - 2.0 * ui.look.margin).min(560.0);
    let x = area.cx() - w / 2.0;
    let y = area.y + (area.h * 0.28).min(180.0);
    let title = format!("Looking for leftovers of {name}");
    let title = ui.p.elide(Face::Semibold, 22.0, &title, w);
    let tw = ui.p.measure(Face::Semibold, 22.0, &title);
    ui.text(
        id("WaitingTitleText"),
        Face::Semibold,
        22.0,
        area.cx() - tw / 2.0,
        y,
        &title,
        pal.text,
        w,
    );
    let detail = "Comparing what is there now with what was recorded before the uninstall.";
    let dw = ui.p.measure(Face::Ui, 13.0, detail).min(w);
    ui.text(
        id("WaitingDetailText"),
        Face::Ui,
        13.0,
        area.cx() - dw / 2.0,
        y + 32.0,
        detail,
        pal.muted,
        w,
    );
    let bar = Rect::new(x + (w - 320.0) / 2.0, y + 62.0, 320.0, 4.0);
    ui.progress(id("WaitingProgress"), bar, None, "Looking for leftovers");
}

fn result_card(ui: &mut Ui, area: Rect, lines: f32) -> Rect {
    let x = area.x + ui.look.margin;
    let w = (area.w - 2.0 * ui.look.margin).min(720.0);
    let card = Rect::new(x, area.y, w, 28.0 + 40.0 + lines + 20.0 + BUTTON_H + 28.0);
    ui.card(card);
    card
}

fn moved(ui: &mut Ui, m: &Model, area: Rect) {
    let pal = ui.pal;
    let l = &m.leftovers;
    let (n, kb) = l.moved;
    let detail = format!(
        "{} is out of the way. Nothing is deleted yet: every item can be put back from History & undo.",
        kb_text(kb)
    );
    let after = if l.delete_after {
        format!(
            "They are deleted for good after {} days.",
            m.quarantine.keep_days
        )
    } else {
        "They stay in quarantine until you empty it.".to_string()
    };
    let point = if m.pipeline.restore_point() {
        "A restore point was made before the uninstall."
    } else {
        "No restore point was made: they are switched off."
    };
    let w = (area.w - 2.0 * ui.look.margin).min(720.0) - 56.0;
    let dh = ui.p.paragraph_height(Face::Ui, 14.0, w, &detail);
    let card = result_card(ui, area, dh + 8.0 + 20.0 + 8.0 + 18.0);
    let x = card.x + 28.0;
    let mut y = card.y + 28.0;
    ui.p.icon(glyph::CHECK, 26.0, x + 13.0, y + 16.0, ok_ink(&pal));
    let title = format!(
        "{n} item{} moved to quarantine",
        if n == 1 { "" } else { "s" }
    );
    ui.text(
        id("ResultTitleText"),
        Face::Semibold,
        24.0,
        x + 38.0,
        y + 16.0,
        &title,
        pal.text,
        w - 38.0,
    );
    y += 40.0;
    let h = ui.p.paragraph(Face::Ui, 14.0, x, y, w, &detail, pal.text);
    ui.reg(
        id("ResultDetailText"),
        Rect::new(x, y, w, h),
        Role::Text,
        &detail,
        false,
    );
    y += h + 8.0;
    ui.text(
        id("DeleteAfterResultText"),
        Face::Ui,
        14.0,
        x,
        y + 10.0,
        &after,
        pal.text,
        w,
    );
    y += 28.0;
    ui.text(
        id("RestorePointText"),
        Face::Ui,
        13.0,
        x,
        y + 9.0,
        point,
        pal.muted,
        w,
    );
    y += 18.0 + 20.0;
    let list = [
        (
            id("UndoAllButton"),
            "Put back all",
            Style::Standard,
            Some(glyph::UNDO),
            true,
        ),
        (
            id("OpenVault"),
            "Open quarantine",
            Style::Standard,
            None,
            true,
        ),
        (id("DoneButton"), "Done", Style::Accent, None, true),
    ];
    ui.buttons_right(card.right() - 28.0, y, &list);
}

fn undone(ui: &mut Ui, m: &Model, area: Rect) {
    let pal = ui.pal;
    let (n, _) = m.leftovers.moved;
    let detail = format!(
        "{n} item{} put back where {} came from. Nothing was deleted, and nothing is in quarantine for this program.",
        if n == 1 { " was" } else { "s were" },
        if n == 1 { "it" } else { "they" },
    );
    let w = (area.w - 2.0 * ui.look.margin).min(720.0) - 56.0;
    let dh = ui.p.paragraph_height(Face::Ui, 14.0, w, &detail);
    let card = result_card(ui, area, dh);
    let x = card.x + 28.0;
    let mut y = card.y + 28.0;
    ui.p.icon(glyph::UNDO, 24.0, x + 13.0, y + 16.0, pal.accent);
    ui.text(
        id("UndoTitleText"),
        Face::Semibold,
        24.0,
        x + 38.0,
        y + 16.0,
        "Everything is back where it was",
        pal.text,
        w - 38.0,
    );
    y += 40.0;
    let h = ui.p.paragraph(Face::Ui, 14.0, x, y, w, &detail, pal.text);
    ui.reg(
        id("UndoDetailText"),
        Rect::new(x, y, w, h),
        Role::Text,
        &detail,
        false,
    );
    y += h + 20.0;
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
    ui.buttons_right(card.right() - 28.0, y, &list);
}

fn review(ui: &mut Ui, m: &Model, v: &mut View, area: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let l = &m.leftovers;
    let left = area.x + lk.margin;
    let right = area.right() - lk.margin;
    let w = right - left;

    let bar = InfoBar::new(
        Severity::Info,
        "Sample data.",
        "Nothing was scanned and nothing will be moved: the engine is not connected yet.",
    )
    .closable(false);
    let mut y = ui.infobar(id("InfoBarHost"), left, area.y, w, &bar, None) + 12.0;

    let fy = area.bottom() - FOOTER_H;
    let side_w = 330.0_f32.min(w * 0.36);
    let col_w = w - side_w - 16.0;

    // What is about to move, by rating.
    let (n, kb) = l.ticked();
    let card = Rect::new(left, y, col_w, 92.0);
    ui.card(card);
    let inks = ui.rating_inks();
    let ratings = [Rating::Safe, Rating::Likely, Rating::Protected];
    let parts: Vec<(f32, _)> = ratings
        .iter()
        .zip(inks)
        .map(|(r, c)| (l.count_of(*r) as f32, c))
        .collect();
    let verdict = format!(
        "{n} item{} \u{b7} {}",
        if n == 1 { "" } else { "s" },
        kb_text(kb)
    );
    let mut cx = card.x + 18.0;
    // Where the legend's middle is: beside the verdict, or level with the ring.
    let legend_cy = if lk.hero {
        // D3: the three ratings as one ring, with the count of what is ticked in it.
        let (rx, ry) = (cx + 30.0, card.cy());
        ui.donut(rx, ry, 30.0, 7.0, &parts);
        let mid = Rect::new(rx - 30.0, ry - 30.0, 60.0, 60.0);
        ui.p.text_center(Face::Semibold, 18.0, mid, &n.to_string(), pal.text);
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
            &verdict,
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
            &verdict,
            pal.text,
            col_w * 0.5,
        );
        ui.parts_bar(Rect::new(cx, card.y + 68.0, col_w - 36.0, 8.0), &parts);
        card.y + 36.0
    };
    // The legend, laid from the right; the icon says the rating where colour cannot.
    let names = ["SafePill", "LikelyPill", "ProtectedPill"];
    let icons = [glyph::CHECK, glyph::WARN, LOCK];
    let mut lx = card.right() - 18.0;
    for k in (0..3).rev() {
        let text = format!("{} {}", l.count_of(ratings[k]), ratings[k].title());
        if lk.soft {
            // D1: the legend in the chips the rows use.
            let cw = ui.chip_w(&text);
            lx -= cw;
            ui.chip(lx, legend_cy, &text, rating_tone(ratings[k]));
            ui.reg(
                id(names[k]),
                Rect::new(lx, legend_cy - 10.0, cw, 20.0),
                Role::Text,
                &text,
                false,
            );
            lx -= 8.0;
            continue;
        }
        let tw = ui.p.measure(Face::Ui, 13.0, &text);
        lx -= tw;
        ui.text(
            id(names[k]),
            Face::Ui,
            13.0,
            lx,
            legend_cy,
            &text,
            pal.text,
            tw + 2.0,
        );
        lx -= 20.0;
        ui.p.icon(
            icons[k],
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
    evidence(ui, m, pane);

    // The footer: what is ticked, and the one button that moves it.
    let foot = Rect::new(area.x + 1.0, fy, area.w - 1.0, FOOTER_H);
    ui.p.fill(foot, pal.bar);
    ui.divider(foot.x, fy, foot.w);
    let cy = foot.cy();
    let count = format!("{n} of {} selected", l.count());
    let cw = ui.text(
        id("FooterCount"),
        Face::Semibold,
        13.0,
        left,
        cy,
        &count,
        pal.text,
        220.0,
    );
    let detail = format!(" \u{b7} {}", kb_text(kb));
    let dw = ui.text(
        id("FooterDetail"),
        Face::Ui,
        13.0,
        left + cw,
        cy,
        &detail,
        pal.muted,
        120.0,
    );
    let move_label = if n == 0 {
        "Nothing is ticked".to_string()
    } else {
        format!(
            "Move {n} item{} to quarantine\u{2026}",
            if n == 1 { "" } else { "s" }
        )
    };
    let mw = ui.button_w(&move_label, None);
    let skw = ui.button_w("Skip", None);
    let move_r = Rect::new(right - mw, cy - BUTTON_H / 2.0, mw, BUTTON_H);
    let skip_r = Rect::new(move_r.x - 8.0 - skw, move_r.y, skw, BUTTON_H);
    // Between the count and the buttons: the box, and the hint when there is room for it.
    let box_label = format!("Delete for good after {} days", m.quarantine.keep_days);
    let bw = 26.0 + ui.p.measure(Face::Ui, 12.0, &box_label);
    let hint = "You'll confirm in the Purge security prompt";
    let hw = ui.p.measure(Face::Ui, 12.0, hint);
    let free = skip_r.x - 16.0 - (left + cw + dw + 24.0);
    let bx = skip_r.x
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
            Some(l.delete_after),
            true,
            &box_label,
        );
        ui.p.text(Face::Ui, 12.0, bx + 26.0, cy, &box_label, pal.text, bw);
    }
    if free >= bw + hw + 20.0 {
        ui.text(
            id("FooterHint"),
            Face::Ui,
            12.0,
            skip_r.x - 16.0 - hw,
            cy,
            hint,
            pal.muted,
            hw + 2.0,
        );
    }
    ui.button(
        id("SkipButton"),
        skip_r,
        "Skip",
        Style::Standard,
        None,
        true,
    );
    ui.button(
        id("MoveButton"),
        move_r,
        &move_label,
        Style::Accent,
        None,
        n > 0,
    );
    // The WinUI button's text block, which the VM rig reads for the count.
    ui.reg(id("MoveText"), move_r, Role::Text, &move_label, false);
}

/// The groups and their items, scrolled as one list.
fn items(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let l = &m.leftovers;
    ui.card(r);
    let view = r.inset(6.0);
    let gid = |g: usize| Id("Group", g as u32 + 1);

    // The heights first: a group that is opening is as tall as its body shows.
    let heights: Vec<f32> = l
        .groups
        .iter()
        .enumerate()
        .map(|(g, group)| {
            let full = group.items.len() as f32 * ROW_H;
            expander::height(ui.cx.anim(), gid(g), group.open, full) + 4.0
        })
        .collect();
    let content: f32 = heights.iter().sum();
    v.left_area = view;
    v.left_content = content;
    let off = v
        .left_scroll
        .offset(ui.cx.anim(), "leftovers-scroll", content, view.h);
    let total_kb: u32 = l
        .groups
        .iter()
        .flat_map(|g| &g.items)
        .map(|i| i.size_kb)
        .sum();

    let old = ui.clip(view);
    let row_w = view.w - 10.0;
    let mut y = view.y - off;
    for (g, group) in l.groups.iter().enumerate() {
        let full = group.items.len() as f32 * ROW_H;
        let area = Rect::new(view.x + GUTTER, y, row_w - GUTTER, heights[g] - 4.0);
        let head = expander::header_rect(area);
        let hid = gid(g);
        ui.reg(
            hid,
            within(head, view),
            Role::Expander(group.open),
            group.title,
            true,
        );
        let look = expander::Look {
            hovered: ui.hot(hid),
            pressed: ui.down(hid),
            focused: ui.ringed(hid),
            disabled: false,
        };
        let body = expander::draw_expander_animated(
            ui.p,
            &pal,
            ui.cx.anim(),
            hid,
            area,
            group.title,
            group.open,
            look,
            full,
        );
        // At the header's right: how many and how much, and a bar of its share of the whole.
        let kb: u32 = group.items.iter().map(|i| i.size_kb).sum();
        let sum = format!("{} \u{b7} {}", group.items.len(), kb_text(kb));
        let tw = ui.p.text_right(
            Face::Ui,
            12.0,
            head.right() - 10.0,
            head.cy(),
            &sum,
            pal.muted,
        );
        let share = if total_kb > 0 {
            (kb as f32 / total_kb as f32).sqrt()
        } else {
            0.0
        };
        let bw = (64.0 * share).max(3.0);
        let bx = head.right() - 10.0 - tw - 12.0 - 64.0;
        ui.p.rbox_a(
            Rect::new(bx + 64.0 - bw, head.cy() - 1.5, bw, 3.0),
            1.5,
            pal.accent,
            0.7,
        );
        // The group's own box, in the gutter: ticked, not ticked, or some.
        let tid = Id("GroupTick", g as u32 + 1);
        let visible = head.cy() > view.y && head.cy() < view.bottom();
        let label = format!("All of {}", group.title);
        let can = group.items.iter().any(|i| i.rating != Rating::Protected);
        if visible {
            ui.tick(tid, view.x + 8.0, head.cy(), group.tick(), can, &label);
        }

        if body.h > 0.5 {
            let inner = ui.clip(within(body, view));
            for (i, item) in group.items.iter().enumerate() {
                let row = Rect::new(view.x, body.y + i as f32 * ROW_H, row_w, ROW_H);
                // The keyboard went to a row that is cut off: bring it into view.
                let cut = row.y < view.y || row.bottom() > view.bottom();
                if cut && group.open && ui.ringed(Id("Item", item_no(g, i))) {
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
                if row.y < body.bottom() {
                    item_row(ui, m, within(body, view), row, (g, i), item, group.title);
                }
            }
            ui.p.restore(inner);
        }
        y += heights[g];
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

fn item_row(
    ui: &mut Ui,
    m: &Model,
    shown: Rect,
    row: Rect,
    at: (usize, usize),
    item: &Leftover,
    group: &str,
) {
    let pal = ui.pal;
    let n = item_no(at.0, at.1);
    let rid = Id("Item", n);
    let selected = m.leftovers.selected == Some(at);
    let label = format!("{}, {}, {}", item.path, item.what, item.rating.title());
    let hit = within(row, shown);
    ui.reg(rid, hit, Role::Item(selected), &label, true);
    let fill = Rect::new(row.x, row.y + 1.0, row.w, row.h - 2.0);
    draw_row_fill(ui.p, &pal, fill, ui.hot(rid), ui.down(rid), selected);
    if ui.ringed(rid) {
        mdshared_ui::focus::draw_ring(ui.p, &pal, fill.inset(2.0), 4.0);
    }

    let cy = row.cy();
    let protected = item.rating == Rating::Protected;
    if hit.h >= ROW_H * 0.5 {
        let tid = Id("ItemTick", n);
        let what = format!("Move {}", item.path);
        ui.tick(tid, row.x + 8.0, cy, Some(item.ticked), !protected, &what);
    }
    let ix = row.x + GUTTER + 16.0;
    let icon = if protected { LOCK } else { group_icon(group) };
    ui.p.icon(icon, 15.0, ix, cy, pal.muted);

    // From the right: the size, then the rating.
    let size = kb_text(item.size_kb);
    ui.p.text_right(Face::Ui, 12.0, row.right() - 10.0, cy, &size, pal.muted);
    let chip = item.rating.title();
    let cw = ui.chip_w(chip);
    let chip_x = row.right() - 10.0 - 64.0 - cw;
    ui.chip(chip_x, cy, chip, rating_tone(item.rating));
    let tx = ix + 16.0;
    let tw = chip_x - 12.0 - tx;
    let path = ui.p.elide(Face::Mono, 12.5, &item.path, tw);
    let ink = if protected { pal.muted } else { pal.text };
    ui.p.text(Face::Mono, 12.5, tx, cy - 8.0, &path, ink, tw);
    let why = if protected {
        format!("{} \u{b7} never moved", item.what)
    } else if item.rating == Rating::Likely {
        format!("{} \u{b7} you decide", item.what)
    } else {
        item.what.to_string()
    };
    let why = ui.p.elide(Face::Ui, 12.0, &why, tw);
    ui.p.text(Face::Ui, 12.0, tx, cy + 10.0, &why, pal.muted, tw);
}

/// Why Purge thinks the selected item is a leftover, and what moving it means.
fn evidence(ui: &mut Ui, m: &Model, r: Rect) {
    let pal = ui.pal;
    let l = &m.leftovers;
    ui.card(r);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let Some((at, item)) = l.selected.and_then(|at| l.item(at).map(|i| (at, i))) else {
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
    let h =
        ui.p.paragraph(Face::Semibold, 15.0, x, y, w, item.what, pal.text);
    ui.reg(
        id("DTitle"),
        Rect::new(x, y, w, h),
        Role::Text,
        item.what,
        false,
    );
    y += h + 8.0;
    let top = y;
    y = super::programs::mono(ui, 12.0, x, y, w, &item.path);
    ui.reg(
        id("DPath"),
        Rect::new(x, top, w, y - top),
        Role::Text,
        &item.path,
        false,
    );
    y += 18.0;

    // The chips: the rating, what kind of data, and whether it is ticked now.
    let (name, tone) = match item.rating {
        Rating::Safe => ("DSafe", Tone::Good),
        Rating::Likely => ("DLikely", Tone::Caution),
        Rating::Protected => ("DProtected", Tone::Outline),
    };
    let mut cx = x;
    let cw = ui.chip(cx, y, item.rating.title(), tone);
    ui.reg(
        id(name),
        Rect::new(cx, y - 10.0, cw, 20.0),
        Role::Text,
        item.rating.title(),
        false,
    );
    cx += cw + 6.0;
    if user_data(item) {
        let cw = ui.chip(cx, y, "User data", Tone::Bad);
        ui.reg(
            id("DUserData"),
            Rect::new(cx, y - 10.0, cw, 20.0),
            Role::Text,
            "User data",
            false,
        );
        cx += cw + 6.0;
    }
    let state = if item.ticked { "Ticked" } else { "Not ticked" };
    ui.chip(cx, y, state, Tone::Neutral);
    y += 22.0;
    let pre = match item.rating {
        Rating::Safe => "Ticked by default: Purge is certain it is the program's.",
        Rating::Likely => "Never ticked by default: tick it yourself if you want it gone.",
        Rating::Protected => "Cannot be ticked: Purge never moves this.",
    };
    let h = ui.p.paragraph(Face::Ui, 12.5, x, y, w, pre, pal.muted);
    ui.reg(
        id("DPreselect"),
        Rect::new(x, y, w, h),
        Role::Text,
        pre,
        false,
    );
    y += h + 14.0;
    ui.divider(x, y, w);
    y += 18.0;

    ui.p.text(Face::Semibold, 13.0, x, y, "Evidence", pal.text, w);
    y += 14.0;
    let top = y;
    for part in item.evidence.split_inclusive(". ") {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        ui.p.icon(glyph::CHECK, 12.0, x + 6.0, y + 9.0, pal.muted);
        y +=
            ui.p.paragraph(Face::Ui, 12.5, x + 20.0, y, w - 20.0, part, pal.text) + 4.0;
    }
    ui.reg(
        id("DEvidence"),
        Rect::new(x, top, w, y - top),
        Role::Text,
        &item.evidence,
        false,
    );
    y += 10.0;
    ui.divider(x, y, w);
    y += 14.0;

    let contents = format!("{} \u{b7} {}", item.what, kb_text(item.size_kb));
    y = ui.fact(id("DContents"), x, y, 82.0, w, "Contents", &contents);
    y = ui.fact(
        id("DIfRemoved"),
        x,
        y,
        82.0,
        w,
        "If removed",
        item.if_removed,
    );
    y = ui.fact(id("DFoundBy"), x, y, 82.0, w, "Found by", item.found_by);
    let kind = l.groups.get(at.0).map_or("", |g| g.title);
    ui.fact(id("DOwner"), x, y, 82.0, w, "Kind", kind);
    ui.p.restore(old);
}
