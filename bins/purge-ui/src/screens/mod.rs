//! The window: title row, rail, the content card with the page in it, and what lies over the
//! page (the confirmation, a drop-down's menu, the command palette, a toast).

use mdshared_app::backdrop::Backdrop;
use mdshared_ui::anim::{Edge, PageEffect, fluent};
use mdshared_ui::chrome::{WIN_BTN_W, WinButton, draw_win_button};
use mdshared_ui::dropdown::{DROPDOWN_H, draw_dropdown_menu_animated};
use mdshared_ui::gfx::{Along, Face, Rect, mix};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Look, Severity, draw_infobar_with};
use mdshared_ui::overlay::{
    Bubble, DIALOG_FOOTER, DIALOG_PAD, DIALOG_RISE, dialog_bounds, dialog_card,
    draw_backdrop_presence, draw_dialog_card, draw_keycaps,
};
use mdshared_ui::pane::draw_row_fill;
use mdshared_ui::toggle::TOGGLE_W;

use crate::model::{Design, LeftoverPhase, Model, Page, RunPhase, STEPS};
use crate::ui::{BOX, BUTTON_H, GEAR, Id, Role, SHIELD, Style, Ui, id};
use crate::view::{DD_ALL, DD_RESTORE, View};

mod history;
mod leftovers;
mod pipeline;
mod programs;
mod quarantine;
mod settings;

pub const NAV: [(Page, &str); 6] = [
    (Page::Programs, "NavPrograms"),
    (Page::Pipeline, "NavQueue"),
    (Page::Leftovers, "NavLeftovers"),
    (Page::History, "NavHistory"),
    (Page::Quarantine, "NavVault"),
    (Page::Settings, "NavSettings"),
];

pub use programs::TAB_IDS as TAB_NAMES;

/// The tab of the Programs page a control is, if it is one.
pub fn programs_tab(id: Id) -> Option<crate::model::Tab> {
    TAB_NAMES
        .iter()
        .position(|n| *n == id.0)
        .map(|i| crate::model::Tab::ALL[i])
}

pub fn programs_tab_id(tab: crate::model::Tab) -> Id {
    programs::tab_id(tab)
}

pub fn nav_id(page: Page) -> Id {
    id(NAV[page.index()].1)
}

fn nav_icon(page: Page) -> &'static str {
    match page {
        Page::Programs => glyph::OUTLINE,
        Page::Pipeline => glyph::DELETE,
        Page::Leftovers => glyph::SEARCH,
        Page::History => glyph::RECENT,
        Page::Quarantine => BOX,
        Page::Settings => GEAR,
    }
}

pub const CAPTIONS: [(WinButton, &str, &str); 3] = [
    (WinButton::Min, "Minimize", "Minimize"),
    (WinButton::Max, "Maximize", "Maximize"),
    (WinButton::Close, "Close", "Close"),
];

/// The backdrop a design asks for behind its chrome.
pub fn backdrop_of(design: Design) -> Backdrop {
    match design {
        Design::Winui => Backdrop::Mica,
        Design::Refined | Design::Flow => Backdrop::Acrylic,
        Design::Bold => Backdrop::Off,
    }
}

/// The content card: everything right of the rail and under the title row.
pub fn content_rect(ui: &Ui) -> Rect {
    let (w, h) = ui.size;
    let lk = ui.look;
    Rect::new(lk.rail_w, lk.title_h, w - lk.rail_w, h - lk.title_h)
}

/// Draws the whole window and declares its controls.
pub fn draw(ui: &mut Ui, m: &Model, v: &mut View) {
    let (w, h) = ui.size;
    let pal = ui.pal;
    let lk = ui.look;
    let content = content_rect(ui);
    v.dds.sync(m);

    // D2: on the pipeline page the next stage of the flow pushes the old one out to the left
    // (and back from the left when the flow starts over). Not while the page itself changes.
    let stage = pipeline::flow_stage(m);
    let flow_body = pipeline::flow_body(&lk, content);
    match (v.flow_shown, stage) {
        (Some(old), Some(new))
            if old != new && lk.motion && v.shown == Some((m.page, m.design)) =>
        {
            let from = if new > old { Edge::Right } else { Edge::Left };
            v.flow_tx
                .begin(ui.cx.anim(), ui.p, flow_body, PageEffect::Push { from });
        }
        (_, None) if v.flow_tx.running() => v.flow_tx.cancel(ui.cx.anim()),
        _ => {}
    }
    v.flow_shown = stage;

    // A page that changed slides in over the old one, which the bitmap still holds.
    if let Some((page, design)) = v.shown
        && design == m.design
        && page != m.page
        && lk.motion
    {
        let effect = match lk.design {
            Design::Flow => PageEffect::Push {
                from: if m.page.index() > page.index() {
                    Edge::Bottom
                } else {
                    Edge::Top
                },
            },
            Design::Bold => PageEffect::Crossfade,
            _ => PageEffect::SlideFade {
                from: Edge::Bottom,
                distance: 28.0,
            },
        };
        v.page_tx.begin(ui.cx.anim(), ui.p, content, effect);
    }
    v.shown = Some((m.page, m.design));

    chrome(ui, m);

    let card = Rect::new(content.x, content.y, content.w + 12.0, content.h + 12.0);
    ui.p.frame(card, lk.radius.min(10.0), pal.page, pal.line);
    if lk.hero && !ui.hc {
        // D3: the accent falls away behind the page's title.
        let band = Rect::new(content.x + 1.0, content.y + 1.0, content.w + 10.0, 78.0);
        let from = mix(pal.page, pal.accent, if pal.dark { 0.20 } else { 0.13 });
        ui.p.gradient(
            band,
            lk.radius.min(10.0) - 1.0,
            from,
            pal.page,
            Along::Y,
            1.0,
        );
    }
    let old = ui.clip(content);
    match m.page {
        Page::Programs => programs::draw(ui, m, v, content),
        Page::Pipeline => pipeline::draw(ui, m, v, content),
        Page::Leftovers => leftovers::draw(ui, m, v, content),
        Page::History => history::draw(ui, m, v, content),
        Page::Quarantine => quarantine::draw(ui, m, v, content),
        Page::Settings => settings::draw(ui, m, v, content),
    }
    ui.p.restore(old);
    if stage.is_some() {
        v.flow_tx.apply(ui.cx.anim(), ui.p, flow_body);
    }
    v.page_tx.apply(ui.cx.anim(), ui.p, content);
    if lk.rail_icons {
        rail_tip(ui, m);
    }

    if m.confirm.is_some() {
        confirm(ui, m, v);
    }
    v.dialog_opened = m.confirm.is_some();

    if let Some(palette) = &mut v.palette {
        ui.modal = true;
        let caret = ui.cx.focused();
        palette.draw(ui.p, &pal, Rect::new(0.0, 0.0, w, h), lk.title_h, caret);
        ui.modal = false;
    }

    // The open drop-down's menu, over everything.
    let window = Rect::new(0.0, 0.0, w, h);
    for dd in DD_ALL {
        if let Some(d) = v.dds.get(dd)
            && d.is_open()
        {
            draw_dropdown_menu_animated(ui.p, &pal, ui.cx.anim(), (dd, "menu"), d, window);
        }
    }

    if let Some(toast) = &v.toast {
        let t = ui.cx.anim().toggle("toast", true, fluent::ENTER);
        Bubble::toast(ui.p, &toast.text, content).draw_presence(ui.p, &pal, t);
    }
}

/// The place of a page's item in the rail.
fn nav_row(ui: &Ui, i: usize, page: Page) -> Rect {
    let lk = ui.look;
    let h = ui.size.1;
    let row_h = if lk.rail_icons { 44.0 } else { 36.0 };
    let y = if page == Page::Settings {
        h - 8.0 - row_h
    } else {
        lk.title_h + 4.0 + i as f32 * (row_h + 2.0)
    };
    Rect::new(8.0, y, lk.rail_w - 16.0, row_h)
}

/// What a page holds just now, in a few words: the second line of the rail's hover card.
fn page_status(m: &Model, page: Page) -> String {
    match page {
        Page::Programs => {
            let pr = &m.programs;
            format!(
                "{} entries \u{b7} {} selected",
                pr.count(pr.tab),
                pr.sel.len()
            )
        }
        Page::Pipeline => match &m.pipeline.run {
            None => "Nothing is running".to_string(),
            Some(r) if r.phase == RunPhase::Finished => "Finished".to_string(),
            Some(r) => format!(
                "Running \u{b7} step {} of {}",
                r.step.min(STEPS.len() - 1) + 1,
                STEPS.len()
            ),
        },
        Page::Leftovers => match m.leftovers.phase {
            LeftoverPhase::Empty => "No scan yet".to_string(),
            LeftoverPhase::Waiting => "Scan running".to_string(),
            LeftoverPhase::Review => format!("{} items to review", m.leftovers.count()),
            LeftoverPhase::Moved => "Moved to quarantine".to_string(),
            LeftoverPhase::Undone => "Put back".to_string(),
        },
        Page::History => format!(
            "{} cleanups \u{b7} {} can be undone",
            m.history.ops.len(),
            m.history.undoable()
        ),
        Page::Quarantine => format!(
            "{} items \u{b7} {}",
            m.quarantine.total_items(),
            crate::model::kb_text(m.quarantine.total_kb())
        ),
        Page::Settings => m.design.title().to_string(),
    }
}

/// D3: the compact rail shows icons only, so the item under the pointer says what it is in a
/// card beside it: the page, what it holds, and its shortcut. The toolkit's tooltip is one line
/// of text; this one is drawn here (see GAPS.md), with the toolkit's shadow and keycaps.
fn rail_tip(ui: &mut Ui, m: &Model) {
    let pal = ui.pal;
    for (i, (page, name)) in NAV.into_iter().enumerate() {
        // Each item's card fades in and out by itself, so one can leave as the next arrives.
        let hot = ui.hot(id(name));
        let t = ui.cx.anim().toggle((id(name), "tip"), hot, fluent::FADE);
        if t <= 0.01 {
            continue;
        }
        let row = nav_row(ui, i, page);
        let status = page_status(m, page);
        let keys = format!("Ctrl+{}", i + 1);
        let tw = ui.p.measure(Face::Semibold, 13.0, page.title());
        let sw = ui.p.measure(Face::Ui, 12.0, &status);
        let w = (tw + 86.0).max(sw + 28.0).max(190.0);
        let h = 54.0;
        let y = (row.cy() - h / 2.0).clamp(ui.look.title_h + 4.0, ui.size.1 - h - 8.0);
        let r = Rect::new(row.right() + 12.0, y.round(), w.ceil(), h);
        let under = ui.p.snapshot(crate::ui::grow(r, 24.0));
        ui.p.shadow(r, 8.0, pal.dark);
        ui.p.frame(r, 8.0, pal.popup, pal.popup_line);
        ui.p.text(
            Face::Semibold,
            13.0,
            r.x + 14.0,
            r.y + 18.0,
            page.title(),
            pal.text,
            tw + 2.0,
        );
        ui.p.text(
            Face::Ui,
            12.0,
            r.x + 14.0,
            r.y + 37.0,
            &status,
            pal.muted,
            r.w - 28.0,
        );
        draw_keycaps(
            ui.p,
            &pal,
            Rect::new(r.x, r.y + 7.0, r.w - 2.0, 22.0),
            &keys,
        );
        if t < 1.0 {
            ui.p.fade(&under, t);
        }
        if hot {
            let said = format!("{}: {status}. {keys}", page.title());
            ui.reg(Id("NavTip", 0), r, Role::Text, &said, false);
        }
    }
}

/// D3: the field in the title row that opens the command palette, with its shortcut as keycaps.
fn command_field(ui: &mut Ui, after: f32, before: f32) {
    let pal = ui.pal;
    let lk = ui.look;
    let w = 340.0_f32.min(before - after - 32.0);
    if w < 200.0 {
        return;
    }
    let x = ((ui.size.0 - w) / 2.0).clamp(after + 16.0, before - 16.0 - w);
    let r = Rect::new(x.round(), (lk.title_h - 28.0) / 2.0, w, 28.0);
    let fid = id("CommandField");
    let label = "Search pages and commands";
    ui.reg(fid, r, Role::Button, label, false);
    let fill = if ui.hot(fid) { pal.hover } else { pal.field };
    ui.p.frame(r, 14.0, fill, pal.popup_line);
    ui.p.icon(glyph::SEARCH, 14.0, r.x + 18.0, r.cy(), pal.muted);
    ui.p.text(
        Face::Ui,
        12.5,
        r.x + 34.0,
        r.cy(),
        label,
        pal.muted,
        r.w - 34.0 - 84.0,
    );
    draw_keycaps(ui.p, &pal, Rect::new(r.x, r.y, r.w + 6.0, r.h), "Ctrl+K");
}

fn chrome(ui: &mut Ui, m: &Model) {
    let (w, h) = ui.size;
    let pal = ui.pal;
    let lk = ui.look;
    ui.p.fill(Rect::new(0.0, 0.0, w, h), pal.title);
    if lk.design == Design::Bold && !ui.hc {
        // D3 has no backdrop: its rail is a quiet gradient of the accent instead.
        let rail = Rect::new(0.0, 0.0, lk.rail_w, h);
        let from = mix(pal.title, pal.accent, 0.22);
        ui.p.gradient(rail, 0.0, from, pal.title, Along::Y, 1.0);
    }
    let title = Rect::new(0.0, 0.0, w, lk.title_h);
    let rail = Rect::new(0.0, lk.title_h, lk.rail_w, h - lk.title_h);
    ui.cx.frost(ui.p, title);
    ui.cx.frost(ui.p, rail);

    let cy = lk.title_h / 2.0;
    let mark_x = if lk.rail_icons { lk.rail_w / 2.0 } else { 22.0 };
    ui.p.icon(glyph::DELETE, 16.0, mark_x, cy, pal.accent);
    let name_x = if lk.rail_icons { lk.rail_w + 4.0 } else { 40.0 };
    let name_w =
        ui.p.text(Face::Semibold, 13.0, name_x, cy, "Purge", pal.text, 80.0);

    // Which design this is; a click moves to the next one. Mockup only.
    let label = format!("{}  \u{b7}  Ctrl+Shift+D", m.design.title());
    let cw = ui.p.measure(Face::Ui, 12.0, &label) + 24.0;
    let chip = Rect::new(name_x + name_w + 14.0, cy - 12.0, cw, 24.0);
    let chip_id = id("DesignChip");
    ui.reg(
        chip_id,
        chip,
        Role::Button,
        &format!("Design: {}", m.design.title()),
        false,
    );
    let fill = if ui.hot(chip_id) { pal.hover } else { pal.page };
    ui.p.frame(chip, 12.0, fill, pal.popup_line);
    ui.p.text_center(Face::Ui, 12.0, chip, &label, pal.muted);

    // Shown only while Purge runs elevated: here, while an uninstall runs.
    let elevated = m
        .pipeline
        .run
        .as_ref()
        .is_some_and(|r| r.phase == RunPhase::Running);
    let mut title_end = w - 3.0 * WIN_BTN_W - 12.0;
    if elevated {
        title_end -= ui.p.measure(Face::Ui, 12.0, "Administrator") + 40.0;
    }
    if lk.hero {
        command_field(ui, chip.right(), title_end);
    }
    if elevated {
        let label = "Administrator";
        let cw = ui.p.measure(Face::Ui, 12.0, label) + 40.0;
        let r = Rect::new(
            w - 3.0 * WIN_BTN_W - 12.0 - cw,
            (lk.title_h - 28.0) / 2.0,
            cw,
            28.0,
        );
        ui.p.frame(r, 14.0, pal.page, pal.popup_line);
        ui.p.icon(SHIELD, 14.0, r.x + 18.0, r.cy(), pal.muted);
        ui.text(
            id("ElevationChip"),
            Face::Ui,
            12.0,
            r.x + 30.0,
            r.cy(),
            label,
            pal.text,
            cw,
        );
    }

    for (i, (b, name, label)) in CAPTIONS.into_iter().enumerate() {
        let x = w - WIN_BTN_W * (3 - i) as f32;
        let r = Rect::new(x, 0.0, WIN_BTN_W, 32.0);
        let bid = id(name);
        ui.reg(bid, r, Role::Button, label, false);
        let maximized = ui.cx.maximized();
        draw_win_button(ui.p, &pal, b, r, maximized, ui.hot(bid), ui.down(bid));
        if b == WinButton::Max {
            // Snap layouts over the maximize button, less the resize band at the top.
            let mut snap = r;
            if !maximized {
                snap.y += mdshared_ui::window::EDGE;
                snap.h -= mdshared_ui::window::EDGE;
            }
            ui.cx
                .set_maximize_button(m.confirm.is_none().then_some(snap));
        }
    }

    // The rail.
    for (i, (page, name)) in NAV.into_iter().enumerate() {
        let nid = id(name);
        let row = nav_row(ui, i, page);
        let on = page == m.page;
        ui.reg(nid, row, Role::Tab(on), page.title(), true);
        let (hot, down) = (ui.hot(nid), ui.down(nid));
        if lk.design == Design::Bold && on && !ui.hc {
            ui.p.rbox(row, 10.0, pal.accent);
        } else {
            draw_row_fill(ui.p, &pal, row, hot, down, on);
        }
        let ink = if lk.design == Design::Bold && on && !ui.hc {
            pal.on_accent
        } else {
            pal.text
        };
        // The pill WinUI's navigation view draws at the left of the selected item.
        let pill_h = if lk.motion {
            ui.cx.anim().toggle((nid, "pill"), on, fluent::MOVE) * 16.0
        } else if on {
            16.0
        } else {
            0.0
        };
        if pill_h > 0.5 && lk.design != Design::Bold {
            let pill = Rect::new(row.x, row.cy() - pill_h / 2.0, 3.0, pill_h);
            ui.p.rbox(pill, 1.5, pal.accent);
        }
        let badge = m.badge(page);
        if lk.rail_icons {
            ui.p.icon(nav_icon(page), 18.0, row.cx(), row.cy(), ink);
            if let Some((count, true)) = &badge {
                let r = Rect::new(row.right() - 18.0, row.y + 4.0, 16.0, 16.0);
                ui.p.rbox(r, 8.0, if on { pal.on_accent } else { pal.accent });
                let c = if on { pal.accent } else { pal.on_accent };
                ui.p.text_center(Face::Semibold, 10.0, r, count, c);
            }
        } else {
            ui.p.icon(nav_icon(page), 16.0, row.x + 22.0, row.cy(), ink);
            let face = if on { Face::Semibold } else { Face::Ui };
            ui.p.text(
                face,
                14.0,
                row.x + 40.0,
                row.cy(),
                page.title(),
                ink,
                row.w - 84.0,
            );
            match &badge {
                Some((count, true)) => {
                    let r = Rect::new(row.right() - 28.0, row.cy() - 9.0, 18.0, 18.0);
                    ui.p.rbox(r, 9.0, pal.accent);
                    ui.p.text_center(Face::Semibold, 11.0, r, count, pal.on_accent);
                }
                Some((count, false)) => {
                    ui.p.text_right(
                        Face::Ui,
                        12.0,
                        row.right() - 12.0,
                        row.cy(),
                        count,
                        pal.muted,
                    );
                }
                None => {}
            }
        }
        ui.ring(nid, row, 4.0);
    }
}

/// The confirmation before an uninstall: the backdrop, the card, what will happen and the three
/// buttons. Nothing reaches the pipeline except through its "Uninstall".
fn confirm(ui: &mut Ui, m: &Model, v: &mut View) {
    let Some(c) = &m.confirm else { return };
    let (w, h) = ui.size;
    let pal = ui.pal;
    let first = &m.programs.all[c.programs[0]];
    let many = c.programs.len() > 1;
    let extra = if m.pipeline.still_running { 0.0 } else { -74.0 }
        + if many {
            22.0 * c.programs.len().min(4) as f32
        } else {
            0.0
        };
    let r = dialog_card(540.0 + DIALOG_PAD * 2.0, 622.0 + extra, w, h);

    // The card rises into place and fades in as one thing (what `anim::pop` does; the drawing
    // here needs the whole `Ui`, which a closure given the painter alone cannot have).
    let t = ui
        .cx
        .anim()
        .value_from("confirm", 0.0_f32, 1.0, fluent::ENTER_LARGE);
    draw_backdrop_presence(ui.p, &pal, w, h, t);
    let bounds = dialog_bounds(r);
    let dy = DIALOG_RISE * (1.0 - t);
    let covered = Rect::new(bounds.x, bounds.y, bounds.w, bounds.h + dy);
    let under = ui.p.snapshot(crate::ui::grow(covered, 1.0));
    let origin = ui.p.offset(0.0, dy);
    ui.modal = true;

    let footer = draw_dialog_card(ui.p, &pal, r);
    let x = r.x + DIALOG_PAD;
    let cw = r.w - DIALOG_PAD * 2.0;
    let mut y = r.y + DIALOG_PAD;
    let title = if many {
        format!("Uninstall {} programs?", c.programs.len())
    } else {
        format!("Uninstall {}?", first.name)
    };
    let title = ui.p.elide(Face::Semibold, 20.0, &title, cw);
    ui.text(
        id("DialogTitle"),
        Face::Semibold,
        20.0,
        x,
        y + 10.0,
        &title,
        pal.text,
        cw,
    );
    y += 40.0;
    if many {
        for (i, p) in c.programs.iter().take(4).enumerate() {
            let name = if i == 3 && c.programs.len() > 4 {
                format!("and {} more", c.programs.len() - 3)
            } else {
                m.programs.all[*p].name.clone()
            };
            ui.p.icon(glyph::DELETE, 13.0, x + 8.0, y + 9.0, pal.muted);
            ui.p.text(
                Face::Ui,
                13.0,
                x + 24.0,
                y + 9.0,
                &name,
                pal.text,
                cw - 24.0,
            );
            y += 22.0;
        }
    }
    ui.p.text(
        Face::Semibold,
        13.0,
        x,
        y + 8.0,
        "Purge will:",
        pal.text,
        cw,
    );
    y += 24.0;
    for step in [
        "1. Record what the program registered",
        "2. Run its uninstaller as administrator",
        "3. Check that it is gone",
        "4. Find its leftovers",
        "5. Review the list before anything moves",
    ] {
        ui.p.text(Face::Ui, 13.0, x + 8.0, y + 9.0, step, pal.text, cw);
        y += 21.0;
    }
    y += 10.0;
    ui.p.text(Face::Ui, 12.0, x, y + 7.0, "Command", pal.muted, cw);
    y += 20.0;
    let box_r = Rect::new(x, y, cw, 32.0);
    ui.p.frame(box_r, 5.0, pal.page, pal.line);
    let command = if many {
        format!(
            "{} commands, one after another. First: {}",
            c.programs.len(),
            first.uninstall
        )
    } else {
        first.uninstall.clone()
    };
    let command = ui.p.elide(Face::Mono, 12.0, &command, cw - 20.0);
    ui.text(
        id("CommandText"),
        Face::Mono,
        12.0,
        x + 10.0,
        box_r.cy(),
        &command,
        pal.text,
        cw - 20.0,
    );
    y += 40.0;
    let signer = format!("Signed by {}", first.publisher);
    ui.text(
        id("SignerText"),
        Face::Ui,
        12.0,
        x,
        y + 7.0,
        &signer,
        pal.muted,
        cw,
    );
    y += 24.0;
    if m.pipeline.still_running {
        let bar = InfoBar::new(
            Severity::Warning,
            "Still running: firefox.exe",
            "Close it yourself; Purge never closes a program for you. Check again once it is closed.",
        )
        .closable(false);
        let bh = bar.height(ui.p, cw);
        let br = Rect::new(x, y, cw, bh);
        let look = Look {
            high_contrast: ui.hc,
            ..Look::default()
        };
        draw_infobar_with(ui.p, &pal, br, &bar, look);
        ui.reg(
            id("RunningText"),
            br,
            Role::Text,
            "Still running: firefox.exe",
            false,
        );
        y += bh + 16.0;
    }
    ui.p.text(Face::Ui, 13.0, x, y + 10.0, "Use quiet mode", pal.text, cw);
    ui.switch(
        id("QuietSwitch"),
        x + cw - TOGGLE_W,
        y + 10.0,
        m.pipeline.quiet,
        "Use quiet mode",
    );
    y += 28.0;
    let quiet = if first.quiet {
        format!("Quiet command: {} /S", first.uninstall)
    } else {
        "This uninstaller has no quiet mode: its own windows will show.".to_string()
    };
    y = ui.para(Face::Ui, 12.0, x, y, cw, &quiet, pal.muted) + 14.0;
    ui.p.text(
        Face::Ui,
        13.0,
        x,
        y + 8.0,
        "Restore point for the cleanup step",
        pal.text,
        cw,
    );
    y += 22.0;
    let field = Rect::new(x, y, 280.0, DROPDOWN_H);
    ui.dropdown(
        DD_RESTORE,
        field,
        &v.dds.restore,
        "Restore point for the cleanup step",
    );
    y += DROPDOWN_H + 14.0;
    let room = (footer.y - y - 4.0).max(0.0);
    if room >= 30.0 {
        ui.para(
            Face::Ui,
            12.0,
            x,
            y,
            cw,
            "Nothing is moved or removed by Purge until you confirm the list on the next page.",
            pal.muted,
        );
    }

    let mut list = vec![(id("CloseButton"), "Not now", Style::Standard, None, true)];
    if m.pipeline.still_running {
        list.push((
            id("SecondaryButton"),
            "Check again",
            Style::Standard,
            None,
            true,
        ));
    }
    list.push((id("PrimaryButton"), "Uninstall", Style::Accent, None, true));
    let by = footer.y + (DIALOG_FOOTER - BUTTON_H) / 2.0;
    ui.buttons_right(footer.right() - DIALOG_PAD, by, &list);

    ui.modal = false;
    ui.p.restore_offset(origin);
    if t < 1.0 {
        ui.p.fade(&under, t);
    }
}
