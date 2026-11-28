//! The Programs page: the tabs and tools, the list and the details pane.

use mdshared_ui::check::{TICK, Tick, draw_tick};
use mdshared_ui::dropdown::DROPDOWN_H;
use mdshared_ui::expander;
use mdshared_ui::focus::draw_ring;
use mdshared_ui::gfx::{self, Face, Rect};
use mdshared_ui::glyph;
use mdshared_ui::link::LINK_H;
use mdshared_ui::pane::draw_row_fill;
use mdshared_ui::rows::Rows;
use mdshared_ui::scroll::draw_scrollbar_animated;
use mdshared_ui::segments::{self, SEGMENT_H, draw_selector_animated};
use mdshared_ui::table::{self, Align, HeaderHit, Sort};
use mdshared_ui::textfield::{FieldArea, FieldColors, FieldHit};

use mdshared_ui::infobar::{InfoBar, Severity};
use purge_ui_model::pipeline::NoticeKind;
use purge_ui_model::programs::ForecastLineKind;
use purge_ui_model::programs::page::RemovedGroupView;

use crate::model::{Expect, Model, Program, SortKey, Tab, size_text};
use crate::ui::{
    BUTTON_H, FILTER, Id, Key, Role, Style, Tone, Ui, bad_ink, id, ok_ink, tile_colour,
};
use crate::view::{DD_SORT, View, column_of};

pub const TAB_IDS: [&str; 4] = ["TabApps", "TabComponents", "TabUnnamed", "TabRecent"];
pub const SORT_IDS: [&str; 4] = ["SortName", "SortSize", "SortJunk", "SortDate"];
/// The keys of the sortable columns, in [`SORT_IDS`] order (Publisher is the Sort menu's only).
pub const SORT_KEYS: [SortKey; 4] = [SortKey::Name, SortKey::Size, SortKey::Junk, SortKey::Date];
pub const LIST: Id = Id("ProgramList", 0);
pub const SEARCH: Id = Id("SearchBox", 0);

pub fn tab_id(tab: Tab) -> Id {
    id(TAB_IDS[tab.index()])
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let pr = &m.programs;
    let left = content.x + lk.margin;
    let right = content.right() - lk.margin;

    // The title, and the page's commands at the right.
    let y = content.y + 38.0;
    let label = pr.view.commands.uninstall_label.clone();
    let more = Rect::new(right - 32.0, y - 16.0, 32.0, BUTTON_H);
    let uw = ui.button_w(&label, Some(glyph::DELETE));
    let sub = pr.view.summary.clone();
    // With sample data the mockup's confirmation and pipeline stand in for the Uninstall page;
    // with the engine the model says when Uninstall can act.
    let can_uninstall = if m.sample() {
        !pr.page.ticked().is_empty()
    } else {
        pr.view.commands.uninstall_enabled
    };
    ui.heading(
        left,
        y,
        "Programs",
        id("Summary"),
        &sub,
        more.x - 16.0 - uw - left,
    );
    let ur = Rect::new(more.x - 8.0 - uw, y - 16.0, uw, BUTTON_H);
    ui.button(
        id("UninstallButton"),
        ur,
        &label,
        Style::Accent,
        Some(glyph::DELETE),
        can_uninstall,
    );
    ui.icon_button(
        id("Commands"),
        more,
        glyph::MORE,
        "More commands",
        Style::Standard,
    );

    // Tabs, then the tools at the right.
    let y = content.y + 76.0 + (lk.margin - 28.0);
    let labels: Vec<String> = Tab::ALL
        .iter()
        .map(|t| format!("{} {}", t.title(), pr.count(*t)))
        .collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let tw = segments::bar_width(ui.p, &refs);
    let hovered = Tab::ALL.iter().position(|t| ui.hot(tab_id(*t)));
    let rects = draw_selector_animated(
        ui.p,
        &pal,
        ui.cx.anim(),
        "program-tabs",
        Rect::new(left, y, tw, SEGMENT_H),
        &refs,
        Some(pr.tab.index()),
        hovered,
    );
    for ((t, r), label) in Tab::ALL.iter().zip(&rects).zip(&labels) {
        ui.reg(tab_id(*t), *r, Role::Tab(*t == pr.tab), label, true);
        ui.ring(tab_id(*t), *r, 4.0);
    }

    // Laid out from the right, declared from the left (the Tab order).
    let sort = Rect::new(right - 190.0, y, 190.0, DROPDOWN_H);
    let filter_label = pr.view.filter_text.as_str();
    let fw = ui.button_w(filter_label, Some(FILTER)).max(78.0);
    let filter = Rect::new(sort.x - 8.0 - fw, y, fw, DROPDOWN_H);
    let selected = pr.view.selected_count.clone();
    let sw = ui.p.measure(Face::Ui, 12.5, &selected);
    let tabs_end = left + tw + 16.0;
    let room = filter.x - 20.0 - sw - tabs_end;
    let search_w = room.clamp(0.0, 240.0);
    if search_w >= 120.0 {
        let field = Rect::new(filter.x - 20.0 - sw - search_w, y, search_w, DROPDOWN_H);
        search_box(ui, v, field);
        ui.text(
            id("SelectedCount"),
            Face::Ui,
            12.5,
            filter.x - 8.0 - sw,
            y + 14.0,
            &selected,
            pal.muted,
            sw + 2.0,
        );
    } else {
        // A narrow window keeps the search and gives up the count beside it.
        let field = Rect::new(
            tabs_end,
            y,
            (filter.x - 8.0 - tabs_end).max(60.0),
            DROPDOWN_H,
        );
        search_box(ui, v, field);
    }
    let style = if pr.view.filters.count() > 0 {
        Style::Standard
    } else {
        Style::Subtle
    };
    ui.button(
        id("FilterButton"),
        filter,
        filter_label,
        style,
        Some(FILTER),
        true,
    );
    ui.dropdown(DD_SORT, sort, &v.dds.sort, "Sort");

    let status_h = 30.0;
    let mut top = y + SEGMENT_H + 12.0;
    // The bar (why the engine could not be used, a folder that is gone, a hint) and the
    // "removed outside Purge" group stand over the list and the details pane.
    if let Some(notice) = &pr.view.notice {
        let severity = match notice.kind {
            NoticeKind::Info => Severity::Info,
            NoticeKind::Warning => Severity::Warning,
            NoticeKind::Error => Severity::Error,
        };
        let bar = InfoBar::new(severity, "", &notice.message);
        top = ui.infobar(
            id("InfoBarHost"),
            left,
            top,
            right - left,
            &bar,
            Some(id("NoticeDismiss")),
        ) + 8.0;
    }
    if let Some(group) = &pr.view.removed {
        top = removed_group(ui, group, left, top, right - left) + 8.0;
    }
    let bottom = content.bottom() - status_h - 12.0;
    let details_w = if lk.soft { 348.0 } else { 330.0 };
    let details = Rect::new(right - details_w, top, details_w, bottom - top);
    let list = Rect::new(left, top, details.x - 16.0 - left, bottom - top);
    program_list(ui, m, v, list);
    program_details(ui, m, v, details);

    let sy = content.bottom() - status_h;
    ui.divider(content.x + 1.0, sy, content.w);
    let cy = sy + status_h / 2.0;
    let status = pr.view.status_left.clone();
    ui.text(
        id("StatusLeft"),
        Face::Ui,
        12.0,
        left,
        cy,
        &status,
        pal.muted,
        300.0,
    );
    let engine = pr.view.status_right.as_str();
    let ew = ui.p.measure(Face::Ui, 12.0, engine);
    ui.text(
        id("StatusRight"),
        Face::Ui,
        12.0,
        right - ew,
        cy,
        engine,
        pal.muted,
        ew + 2.0,
    );
}

/// The search field in its box, with a search icon.
fn search_box(ui: &mut Ui, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let focused = ui.focus.is_focused(SEARCH) && ui.cx.focused();
    ui.reg(
        SEARCH,
        r,
        Role::Edit(v.search.text().to_string()),
        "Search programs",
        true,
    );
    let edge = if focused { pal.accent } else { pal.popup_line };
    ui.p.frame(r, 5.0, pal.field, edge);
    ui.p.icon(glyph::SEARCH, 14.0, r.x + 15.0, r.cy(), pal.muted);
    let colors = FieldColors {
        text: pal.text,
        placeholder: pal.muted,
        selection: pal.selection,
        caret: pal.text,
    };
    let area = Rect::new(r.x + 28.0, r.y + 1.0, r.w - 34.0, r.h - 2.0);
    v.search_area = area;
    // The whole box takes the press (the icon and the padding too); the text is hit as drawn.
    v.search_field = Some(FieldArea::new(
        r,
        FieldHit {
            area,
            face: Face::Ui,
            size: 13.0,
            scale: ui.p.scale,
        },
    ));
    v.search.draw_blinking(
        ui.p,
        ui.cx.anim(),
        "search-caret",
        v.blink,
        area,
        Face::Ui,
        13.0,
        &colors,
        "Search programs (Ctrl+F)",
        focused,
    );
    ui.ring(SEARCH, r, 5.0);
}

fn program_list(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let pr = &m.programs;
    ui.card(r);
    let inner = r.inset(6.0);

    v.table.layout(inner.w);
    v.table.set_sort(Some(Sort {
        column: column_of(pr.sort),
        descending: pr.descending,
    }));
    let header = Rect::new(inner.x, inner.y, inner.w, table::HEADER_H);
    let hot = (0..4).find(|k| ui.hot(id(SORT_IDS[*k])));
    let pressed = hot.is_some_and(|k| ui.down(id(SORT_IDS[k])));
    table::draw_header(
        ui.p,
        &pal,
        &v.table,
        header,
        hot.map(|k| HeaderHit::Title(k + 1)),
        pressed,
    );
    for (k, key) in SORT_KEYS.into_iter().enumerate() {
        let cell = v.table.cell(header, k + 1);
        let sid = id(SORT_IDS[k]);
        let way = match (pr.sort == key, pr.descending) {
            (false, _) => "",
            (true, false) => ", ascending",
            (true, true) => ", descending",
        };
        ui.reg(
            sid,
            cell,
            Role::Button,
            &format!("Sort by {}{way}", key.title()),
            true,
        );
        ui.ring(sid, cell.inset(2.0), 3.0);
    }

    let cap = Rect::new(inner.x, header.bottom() + 2.0, inner.w, 26.0);
    let caption = pr.view.all_label.clone();
    ui.text(
        id("AllAppsLabel"),
        Face::Semibold,
        11.0,
        cap.x + 8.0,
        cap.cy() + 2.0,
        &caption,
        pal.muted,
        300.0,
    );

    let view = Rect::new(
        inner.x,
        cap.bottom(),
        inner.w,
        inner.bottom() - cap.bottom(),
    );
    let count = pr.rows.len();
    v.list.area = view;
    v.list.row_h = lk.row_h;
    v.list.count = count;
    let off = v
        .list
        .scroll
        .offset(ui.cx.anim(), "programs-scroll", v.list.content(), view.h);
    v.list.offset = off;
    let rows = Rows {
        row_h: lk.row_h,
        view: view.h,
        count,
        scroll: off,
    };
    ui.reg(LIST, view, Role::List, "Programs", true);

    // An empty list says why: nothing matches, or the list is still on its way.
    let empty = if !pr.loaded {
        Some(("Reading the installed programs\u{2026}".to_string(), ""))
    } else if count == 0 {
        Some(pr.view.no_match.clone().unwrap_or_else(|| {
            (
                format!("No programs in {}.", pr.tab.title()),
                "Try another tab.",
            )
        }))
    } else {
        None
    };
    if let Some((what, hint)) = empty {
        let cy = view.y + (view.h / 2.0).min(120.0);
        let tw = ui.p.measure(Face::Semibold, 16.0, &what).min(view.w - 24.0);
        ui.text(
            id("NoMatchText"),
            Face::Semibold,
            16.0,
            view.cx() - tw / 2.0,
            cy,
            &what,
            pal.text,
            view.w - 24.0,
        );
        let hw = ui.p.measure(Face::Ui, 13.0, hint).min(view.w - 24.0);
        ui.text(
            id("NoMatchHint"),
            Face::Ui,
            13.0,
            view.cx() - hw / 2.0,
            cy + 26.0,
            hint,
            pal.muted,
            view.w - 24.0,
        );
    }

    let list_ring = ui.ringed(LIST);
    let old = ui.clip(view);
    for i in rows.visible() {
        let row = rows.rect(view, i);
        program_row(ui, m, v, row, i);
        if list_ring && pr.sel.cursor() == Some(i) {
            draw_ring(
                ui.p,
                &pal,
                Rect::new(row.x + 2.0, row.y + 3.0, row.w - 10.0, row.h - 6.0),
                4.0,
            );
        }
    }
    ui.p.restore(old);

    v.list.bar = rows.thumb(Rect::new(
        view.x,
        view.y + 2.0,
        r.right() - 3.0 - view.x,
        view.h - 4.0,
    ));
    if let Some((track, thumb)) = v.list.bar {
        let active = v.list.bar_hot || v.list.drag.is_some();
        draw_scrollbar_animated(
            ui.p,
            &pal,
            ui.cx.anim(),
            "programs-bar",
            track,
            thumb,
            active,
        );
    }
}

/// What a program is expected to leave, as a chip's words and tone.
fn verdict_chip(g: &Program) -> (String, Tone) {
    match g.expect {
        Expect::Clean => ("Clean".to_string(), Tone::Good),
        Expect::Some => (g.junk.clone(), Tone::Caution),
        Expect::Large => (g.junk.clone(), Tone::Bad),
        Expect::Unknown => ("Not known yet".to_string(), Tone::Neutral),
    }
}

fn verdict(ui: &mut Ui, cell: Rect, g: &Program) {
    let pal = ui.pal;
    if ui.look.soft {
        // D1: one chip per row, so the column reads as a column of the same thing.
        let (text, tone) = verdict_chip(g);
        let max = cell.w - table::CELL_PAD * 2.0 - 18.0;
        let text = ui.p.elide(Face::Ui, 11.5, &text, max.max(20.0));
        ui.chip(cell.x + table::CELL_PAD, cell.cy(), &text, tone);
        return;
    }
    let (icon, text, face, c) = match g.expect {
        Expect::Clean => (Some(glyph::CHECK), "Clean", Face::Ui, ok_ink(&pal)),
        Expect::Some => (Some(glyph::WARN), g.junk.as_str(), Face::Ui, pal.warn),
        Expect::Large => (
            Some(glyph::WARN),
            g.junk.as_str(),
            Face::Semibold,
            bad_ink(&pal),
        ),
        Expect::Unknown => (None, "Not known yet", Face::Ui, pal.muted),
    };
    let mut x = cell.x + table::CELL_PAD;
    if let Some(g) = icon {
        ui.p.icon(g, 13.0, x + 7.0, cell.cy(), c);
        x += 19.0;
    }
    let max = cell.right() - x - 4.0;
    let s = ui.p.elide(face, 12.5, text, max);
    ui.p.text(face, 12.5, x, cell.cy(), &s, c, max);
}

fn program_row(ui: &mut Ui, m: &Model, v: &View, row: Rect, i: usize) {
    let pal = ui.pal;
    let pr = &m.programs;
    let Some(g) = pr.rows.get(i).map(|n| &pr.all[*n]) else {
        return;
    };
    let selected = pr.sel.contains(i);
    let body = Rect::new(row.x, row.y + 1.0, row.w - 6.0, row.h - 2.0);
    let hot = v.list.hot == Some(i) && v.list.drag.is_none();
    draw_row_fill(ui.p, &pal, body, hot, false, selected);
    let cell = |k: usize| v.table.cell(row, k);

    // The box shows the selection, as a WinUI list with several selected shows it.
    let t = cell(0);
    let tick = Rect::new(t.x + 12.0, row.cy() - TICK / 2.0, TICK, TICK);
    draw_tick(ui.p, &pal, tick, Tick::new(selected));
    let side = (row.h - 14.0).min(28.0);
    icon_tile(
        ui,
        Rect::new(t.x + 40.0, row.cy() - side / 2.0, side, side),
        g,
    );

    let c = cell(1);
    let x = c.x + table::CELL_PAD;
    let max = c.w - table::CELL_PAD * 2.0;
    let name = ui.p.elide(Face::Ui, 14.0, &g.name, max - 34.0);
    let w =
        ui.p.text(Face::Ui, 14.0, x, row.cy() - 8.0, &name, pal.text, max);
    if g.new_tag {
        ui.p.text(
            Face::Semibold,
            11.0,
            x + w + 8.0,
            row.cy() - 8.0,
            "new",
            ok_ink(&pal),
            40.0,
        );
    }
    let by = ui.p.elide(Face::Ui, 12.0, &g.sub, max);
    ui.p.text(Face::Ui, 12.0, x, row.cy() + 9.0, &by, pal.muted, max);

    // The size and, under it, a bar of its share of the largest (none until it is measured).
    let s = cell(2);
    table::draw_cell_text(
        ui.p,
        Rect::new(s.x, s.y - 3.0, s.w, s.h),
        Align::Right,
        &g.size,
        pal.text,
    );
    if g.bar > 0.0 {
        let bw = ((s.w - table::CELL_PAD * 2.0).min(96.0) * g.bar).max(4.0);
        ui.p.rbox_a(
            Rect::new(s.right() - table::CELL_PAD - bw, row.cy() + 8.0, bw, 3.0),
            1.5,
            pal.accent,
            0.7,
        );
    }

    verdict(ui, cell(3), g);
    table::draw_cell_text(ui.p, cell(4), Align::Left, &g.installed, pal.muted);
}

/// The program's own icon, or the tile with its first letter while it has none.
fn icon_tile(ui: &mut Ui, r: Rect, g: &Program) {
    match &g.icon {
        Some(icon) if !ui.hc => {
            let px = u32::from(icon.px);
            ui.p.image(&icon.bgra, px, px, r, 0.0, 1.0);
        }
        _ => ui.tile(r, &g.name, &g.publisher),
    }
}

/// The "removed outside Purge" group: programs the last session listed that are gone now, each
/// with its check for leftovers and Dismiss. Returns the y under it.
fn removed_group(ui: &mut Ui, group: &RemovedGroupView, x: f32, y: f32, w: f32) -> f32 {
    let pal = ui.pal;
    let row_h = 44.0;
    let h = 36.0 + row_h * group.rows.len() as f32;
    let r = Rect::new(x, y, w, h);
    ui.card(r);
    ui.reg(id("RemovedGroup"), r, Role::Text, &group.header, false);
    ui.p.text(
        Face::Semibold,
        13.0,
        x + 16.0,
        y + 18.0,
        &group.header,
        pal.text,
        w - 32.0,
    );
    let mut ry = y + 36.0;
    for (k, row) in group.rows.iter().enumerate() {
        let n = k as u32;
        let cy = ry + row_h / 2.0;
        ui.tile(
            Rect::new(x + 16.0, cy - 14.0, 28.0, 28.0),
            &row.name,
            &row.name,
        );
        let dismiss_w = ui.button_w("Dismiss", None);
        let check_w = if row.button_visible {
            ui.button_w(row.button_text, None)
        } else {
            0.0
        };
        let text_w = (w - 76.0 - dismiss_w - check_w - 24.0).max(40.0);
        let name = ui.p.elide(Face::Ui, 13.5, &row.name, text_w);
        ui.text(
            Id("RemovedName", n),
            Face::Ui,
            13.5,
            x + 56.0,
            cy - 8.0,
            &name,
            pal.text,
            text_w,
        );
        let detail = ui.p.elide(Face::Ui, 12.0, &row.detail, text_w);
        ui.p.text(
            Face::Ui,
            12.0,
            x + 56.0,
            cy + 9.0,
            &detail,
            pal.muted,
            text_w,
        );
        let mut bx = x + w - 16.0 - dismiss_w;
        ui.button(
            Id("RemovedDismiss", n),
            Rect::new(bx, cy - BUTTON_H / 2.0, dismiss_w, BUTTON_H),
            "Dismiss",
            Style::Subtle,
            None,
            row.can_dismiss,
        );
        // Review SF3: the row acts on the program it showed, never on its place in the group.
        ui.key(
            Id("RemovedDismiss", n),
            Key::Program(row.program_id.clone()),
        );
        if row.button_visible {
            bx -= 8.0 + check_w;
            ui.button(
                Id("RemovedCheck", n),
                Rect::new(bx, cy - BUTTON_H / 2.0, check_w, BUTTON_H),
                row.button_text,
                Style::Standard,
                None,
                row.can_check,
            );
            ui.key(Id("RemovedCheck", n), Key::Program(row.program_id.clone()));
        }
        ry += row_h;
    }
    y + h
}

/// Breaks a path or a command after a backslash or a space, so that no line is wider than `max`.
pub fn wrap_path(ui: &mut Ui, size: f32, text: &str, max: f32) -> Vec<String> {
    let mut lines = vec![String::new()];
    for part in text.split_inclusive(['\\', ' ']) {
        let line = lines.last().cloned().unwrap_or_default();
        if !line.is_empty() && ui.p.measure(Face::Mono, size, &format!("{line}{part}")) > max {
            lines.push(String::new());
        }
        if let Some(last) = lines.last_mut() {
            last.push_str(part);
        }
    }
    lines
}

/// Text in the monospaced face, wrapped as a path; returns the y under it.
pub fn mono(ui: &mut Ui, size: f32, x: f32, y: f32, w: f32, text: &str) -> f32 {
    let c = ui.pal.text;
    let mut y = y;
    for line in wrap_path(ui, size, text, w) {
        ui.p.text(Face::Mono, size, x, y + size * 0.7, &line, c, w);
        y += size * 1.4;
    }
    y
}

fn program_details(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let pr = &m.programs;
    ui.card(r);
    ui.reg(id("DetailsCard"), r, Role::Text, "Details", false);
    let x = r.x + 18.0;
    let w = r.w - 36.0;
    let mut y = r.y + 18.0;

    let (Some(g), Some(d)) = (pr.current().map(|i| &pr.all[i]), pr.view.details.as_ref()) else {
        let cy = r.y + (r.h / 2.0).min(140.0);
        ui.p.icon(glyph::INFO, 22.0, r.cx(), cy - 30.0, pal.faint);
        let t = "Select a program to see what uninstalling it involves.";
        ui.para(Face::Ui, 13.0, x + 20.0, cy, w - 40.0, t, pal.muted);
        return;
    };
    let old = ui.clip(r.inset(1.0));
    let lk = ui.look;
    if lk.hero && !ui.hc {
        // D3: the program's own colour falls away behind its name.
        let fill = ui.card_fill();
        let band = Rect::new(r.x + 1.0, r.y + 1.0, r.w - 2.0, 96.0);
        let from = gfx::mix(fill, tile_colour(&g.publisher), 0.26);
        crate::paint::gradient_down(ui.p, band, lk.radius - 1.0, from, fill, 1.0);
    }
    // D1 keeps the one button that acts at the foot of the pane, where it does not move as
    // the selection changes what is above it.
    let foot = if lk.soft { BUTTON_H + 30.0 } else { 0.0 };
    let pane_bottom = r.bottom() - foot;

    icon_tile(ui, Rect::new(x, y, 44.0, 44.0), g);
    let tx = x + 56.0;
    let name = ui.p.elide(Face::Semibold, 18.0, &d.name, w - 56.0);
    ui.text(
        id("DName"),
        Face::Semibold,
        18.0,
        tx,
        y + 13.0,
        &name,
        pal.text,
        w - 56.0,
    );
    // The rig reads the whole name (an elided one would not match).
    ui.say_whole(&d.name);
    let sub = ui.p.elide(Face::Ui, 12.0, &d.sub, w - 56.0);
    ui.text(
        id("DSub"),
        Face::Ui,
        12.0,
        tx,
        y + 34.0,
        &sub,
        pal.muted,
        w - 56.0,
    );
    y += 56.0;
    let n = pr.sel.len();
    let label = if n > 1 {
        format!("Uninstall {n} selected")
    } else {
        "Uninstall".to_string()
    };
    let can_uninstall = m.sample() || pr.view.commands.details_uninstall_enabled;
    if lk.soft {
        // D1: the verdict first, as the chip the list shows for this program.
        let (text, tone) = verdict_chip(g);
        let text = ui.p.elide(Face::Ui, 11.5, &text, w - 20.0);
        ui.chip(x, y + 6.0, &text, tone);
        y += 34.0;
    } else {
        ui.button(
            id("DUninstallButton"),
            Rect::new(x, y, w, BUTTON_H),
            &label,
            Style::Accent,
            Some(glyph::DELETE),
            can_uninstall,
        );
        y += BUTTON_H + 12.0;
    }
    if lk.hero {
        y = stats(ui, g, x, y + 4.0, w);
    }
    if !lk.soft {
        ui.divider(x, y, w);
        y += 18.0;
    }

    ui.p.text(
        Face::Semibold,
        13.0,
        x,
        y,
        "What Purge expects",
        pal.text,
        w,
    );
    y += 24.0;
    // The model's lines: the engine's forecast when it has one, else "Not known yet".
    let ok = ok_ink(&pal);
    let expects: Vec<(&str, _, &str, &str)> = d
        .expects
        .iter()
        .map(|l| {
            let (icon, c) = match l.kind {
                Some(ForecastLineKind::Removed) => (glyph::CHECK, ok),
                Some(ForecastLineKind::Stays) => (
                    glyph::WARN,
                    if g.expect == Expect::Large {
                        bad_ink(&pal)
                    } else {
                        pal.warn
                    },
                ),
                Some(ForecastLineKind::UserData) => (glyph::WARN, pal.warn),
                None => (glyph::INFO, pal.muted),
            };
            (icon, c, l.text.as_str(), l.detail.as_str())
        })
        .collect();
    for (k, (icon, c, text, detail)) in expects.into_iter().enumerate() {
        ui.p.icon(icon, 14.0, x + 7.0, y + 8.0, c);
        let h =
            ui.p.paragraph(Face::Ui, 12.5, x + 22.0, y, w - 22.0, text, pal.text);
        ui.reg(
            Id("DExpects", k as u32),
            Rect::new(x, y, w, h),
            Role::Text,
            text,
            false,
        );
        y += h + 2.0;
        if !detail.is_empty() {
            ui.p.text(
                Face::Ui,
                12.0,
                x + 22.0,
                y + 8.0,
                detail,
                pal.muted,
                w - 22.0,
            );
            y += 18.0;
        }
        y += 6.0;
    }
    y += 4.0;
    let label_w = 76.0;
    let mut fx = x;
    let mut fw = w;
    if lk.soft {
        // D1: the facts in a box of their own, in place of the rules above and below them.
        ui.well(Rect::new(x, y, w, 5.0 * 23.0 + 14.0));
        y += 18.0;
        fx += 12.0;
        fw -= 24.0;
    } else {
        ui.divider(x, y, w);
        y += 16.0;
    }

    let facts = [
        ("Uninstaller", "DUninstaller", d.uninstaller.clone()),
        ("Location", "DLocation", d.location.clone()),
        ("Installed", "DInstalled", d.installed.clone()),
        ("Size", "DSize", d.size.clone()),
        ("Platform", "DPlatform", d.platform.to_string()),
    ];
    for (label, name, value) in facts {
        if lk.hero && name == "DSize" {
            // D3 says the size beside its ring, above.
            continue;
        }
        ui.p.text(Face::Ui, 12.0, fx, y, label, pal.muted, label_w);
        // A folder that is recorded opens in File Explorer.
        if name == "DLocation" && d.location_tooltip.is_some() {
            let shown = ui.p.elide(Face::Ui, 13.0, &value, fw - label_w);
            ui.link(id("DLocationText"), fx + label_w, y - LINK_H / 2.0, &shown);
        } else {
            ui.text(
                id(name),
                Face::Ui,
                12.5,
                fx + label_w,
                y,
                &value,
                pal.text,
                fw - label_w,
            );
        }
        y += 23.0;
    }
    y += 4.0;
    if lk.soft {
        y += 6.0;
    }

    // The commands, under an expander that opens and closes.
    let cmd = id("Commands.Expander");
    let mut lines: Vec<(&str, &str, String)> =
        vec![("Uninstall", "DUninstall", d.uninstall_command.clone())];
    if !d.quiet_command.is_empty() {
        lines.push(("Quiet", "DQuiet", d.quiet_command.clone()));
    }
    if let Some(code) = &d.product_code {
        lines.push(("Product code", "DProductCode", code.clone()));
    }
    lines.push(("Registry key", "DKey", d.key_path.clone()));
    let wrapped: Vec<(&str, &str, String, Vec<String>)> = lines
        .into_iter()
        .map(|(l, n, t)| {
            let w = wrap_path(ui, 11.5, &t, w);
            (l, n, t, w)
        })
        .collect();
    let full: f32 = 6.0
        + wrapped
            .iter()
            .map(|l| 24.0 + 15.0 * l.3.len() as f32)
            .sum::<f32>();
    let area = Rect::new(x - 6.0, y, w + 12.0, (pane_bottom - y - 4.0).max(0.0));
    let head = expander::header_rect(area);
    ui.reg(
        cmd,
        head,
        Role::Expander(v.commands_open),
        "Commands and registry key",
        true,
    );
    let look = expander::Look {
        hovered: ui.hot(cmd),
        pressed: ui.down(cmd),
        focused: ui.ringed(cmd),
        disabled: false,
    };
    let body = expander::draw_expander_animated(
        ui.p,
        &pal,
        ui.cx.anim(),
        cmd,
        area,
        "Commands and registry key",
        v.commands_open,
        look,
        full,
    );
    if body.h > 0.5 {
        let inner = ui.clip(body);
        let mut y = body.y + 6.0;
        for (label, name, text, parts) in &wrapped {
            ui.p.text(Face::Ui, 12.0, x, y, label, pal.muted, w);
            let top = y;
            y += 10.0;
            for line in parts {
                ui.p.text(Face::Mono, 11.5, x, y + 6.0, line, pal.text, w);
                y += 15.0;
            }
            ui.reg(
                id(name),
                Rect::new(x, top, w, y - top),
                Role::Text,
                text,
                false,
            );
            y += 14.0;
        }
        ui.p.restore(inner);
    }
    if lk.soft {
        // Declared last, so Tab reaches it after everything it acts on.
        let fill = ui.card_fill();
        ui.p.fill(
            Rect::new(r.x + 1.0, pane_bottom, r.w - 2.0, foot - lk.radius),
            fill,
        );
        ui.divider(x, pane_bottom, w);
        ui.button(
            id("DUninstallButton"),
            Rect::new(x, pane_bottom + 14.0, w, BUTTON_H),
            &label,
            Style::Accent,
            Some(glyph::DELETE),
            can_uninstall,
        );
    }
    ui.p.restore(old);
}

/// D3: the program's size and what it is expected to leave, each beside a ring. The first
/// ring is the program's share of the largest one listed; the second is the share of its
/// footprint that stays behind. Returns the y under them.
fn stats(ui: &mut Ui, g: &Program, x: f32, y: f32, w: f32) -> f32 {
    let pal = ui.pal;
    let half = (w - 12.0) / 2.0;
    let cy = y + 22.0;
    let radius = 17.0;

    let share = g.bar;
    let ink = if ui.hc { pal.text } else { pal.accent };
    ui.ring_gauge(x + radius + 2.0, cy, radius, share, "", ink);
    ui.p.icon(glyph::OUTLINE, 13.0, x + radius + 2.0, cy, pal.muted);
    let tx = x + 2.0 * radius + 14.0;
    let tw = half - 2.0 * radius - 14.0;
    ui.text(
        id("DSize"),
        Face::Semibold,
        14.0,
        tx,
        cy - 8.0,
        if g.size.is_empty() {
            "Not measured"
        } else {
            &g.size
        },
        pal.text,
        tw,
    );
    ui.p.text(Face::Ui, 11.5, tx, cy + 9.0, "Size", pal.muted, tw);

    let x2 = x + half + 12.0;
    let (icon, ink, value) = match g.expect {
        Expect::Clean => (glyph::CHECK, ok_ink(&pal), "Clean".to_string()),
        Expect::Some => (glyph::WARN, pal.warn, size_text(g.junk_mb)),
        Expect::Large => (glyph::WARN, bad_ink(&pal), size_text(g.junk_mb)),
        Expect::Unknown => (glyph::INFO, pal.muted, "Not known".to_string()),
    };
    let ink = if ui.hc { pal.text } else { ink };
    let stays = match g.expect {
        Expect::Some | Expect::Large => {
            (g.junk_mb / (g.junk_mb + g.size_mb).max(1.0)).clamp(0.04, 1.0)
        }
        _ => 0.0,
    };
    ui.ring_gauge(x2 + radius + 2.0, cy, radius, stays, "", ink);
    ui.p.icon(icon, 13.0, x2 + radius + 2.0, cy, ink);
    let tx = x2 + 2.0 * radius + 14.0;
    let value = ui.p.elide(Face::Semibold, 14.0, &value, tw);
    ui.text(
        id("DStays"),
        Face::Semibold,
        14.0,
        tx,
        cy - 8.0,
        &value,
        pal.text,
        tw,
    );
    ui.p.text(Face::Ui, 11.5, tx, cy + 9.0, "Stays behind", pal.muted, tw);
    y + 2.0 * radius + 22.0
}
