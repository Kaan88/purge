//! The window: title row, rail, the content card with the page in it, and what lies over the
//! page (the confirmation, a drop-down's menu, the command palette, a toast).

use mdshared_ui::anim::{Edge, PageEffect, fluent};
use mdshared_ui::chrome::{WIN_BTN_W, WinButton, draw_win_button};
use mdshared_ui::dropdown::{DROPDOWN_H, draw_dropdown_menu_animated};
use mdshared_ui::gfx::{Along, Face, Rect, Wrap, mix};
use mdshared_ui::glyph;
use mdshared_ui::infobar::{InfoBar, Look, Severity, draw_infobar_with};
use mdshared_ui::overlay::{
    Bubble, DIALOG_FOOTER, DIALOG_PAD, DIALOG_RISE, dialog_bounds, dialog_card,
    draw_backdrop_presence, draw_dialog_card, draw_keycaps,
};
use mdshared_ui::pane::draw_row_fill;
use mdshared_ui::scroll::{draw_scrollbar_animated, scrollbar};
use mdshared_ui::toggle::TOGGLE_W;

use crate::look::{Choice, Design, Effect, Transition};
use purge_ui_model::leftovers::LeftoversPhase;
use purge_ui_model::pipeline::page::ConfirmButton;

use crate::model::{Model, Page};
use crate::ui::{BOX, BUTTON_H, GEAR, Id, Role, SHIELD, Style, Ui, id, within};
use crate::view::{DD_ALL, DD_RESTORE, View};

mod history;
mod leftovers;
// UI-PAGES2: the bars of the History and Quarantine models.
mod model_bars;
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

pub use pipeline::BAR_BUTTONS;
pub use programs::TAB_IDS as TAB_NAMES;
pub use settings::swatch_id;

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

    // The flow (D2's pipeline page): the next stage of the uninstall pushes the old one out to
    // the left (and back from the left when the flow starts over), unless the user chose no
    // motion. Not while the page itself changes.
    let moves = m.prefs.transition != Transition::None;
    let stage = pipeline::flow_stage(m, &lk);
    let flow_body = pipeline::flow_body(&lk, content);
    match (v.flow_shown, stage) {
        (Some(old), Some(new))
            if old != new && moves && v.shown == Some((m.page, m.prefs.design)) =>
        {
            let from = if new > old { Edge::Right } else { Edge::Left };
            let push = Effect::Toolkit(PageEffect::Push { from });
            v.flow_tx.begin(ui.cx.anim(), ui.p, flow_body, push);
        }
        (_, None) if v.flow_tx.running() => v.flow_tx.cancel(ui.cx.anim()),
        _ => {}
    }
    v.flow_shown = stage;

    // A page that changed comes in over the old one, which the bitmap still holds, by the
    // transition the user chose (`look::Transition`). A change of design redraws plainly.
    if let Some((page, design)) = v.shown
        && design == m.prefs.design
        && page != m.page
    {
        match m.prefs.transition.effect(page.index(), m.page.index()) {
            Some(effect) => v.page_tx.begin(ui.cx.anim(), ui.p, content, effect),
            // No motion: a switch still running from the page before ends here, or the page
            // before that would go on blending over this one.
            None => v.page_tx.cancel(ui.cx.anim()),
        }
    }
    v.shown = Some((m.page, m.prefs.design));

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

    if m.flow.confirm.is_some() {
        confirm(ui, m, v);
    } else {
        v.confirm_at = None;
        v.confirm_scroll = mdshared_ui::scroll::SmoothScroll::new();
        v.confirm_area = Rect::default();
        if m.flow.elevation.showing().is_some() {
            elevation(ui, m.flow.elevation.showing_read_only());
        } else if let Some(t) = &m.flow.takeover {
            takeover(ui, t);
        }
    }
    v.dialog_opened = m.flow.dialog_open();

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

/// Under `--sample`, the flow pages' fixed bar: nothing on this PC changes, whatever the pretend
/// uninstall shows. Returns the y under it (`y` when there is none).
pub(crate) fn sample_bar(ui: &mut Ui, m: &Model, x: f32, y: f32, w: f32) -> f32 {
    if !m.sample() {
        return y;
    }
    let bar = InfoBar::new(Severity::Info, "", crate::model::SAMPLE_BAR).closable(false);
    ui.infobar(id("SampleBar"), x, y, w, &bar, None) + 8.0
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
        Page::Pipeline => {
            let pv = m.flow.page.view(m.flow_env());
            if pv.empty {
                "Nothing is running".to_string()
            } else {
                pv.subtitle
            }
        }
        Page::Leftovers => match m.flow.leftovers.phase() {
            LeftoversPhase::Empty => "No scan yet".to_string(),
            LeftoversPhase::Scanning => "Scan running".to_string(),
            LeftoversPhase::Review => {
                format!("{} items to review", m.flow.leftovers.items().len())
            }
            LeftoversPhase::Waiting => "Waiting for your confirmation".to_string(),
            LeftoversPhase::Result => "Moved to quarantine".to_string(),
            LeftoversPhase::Undone => "Put back".to_string(),
            LeftoversPhase::Interrupted => "Interrupted".to_string(),
        },
        // UI-PAGES2.
        Page::History => format!(
            "{} cleanups \u{b7} {} can be undone",
            m.history.page.sessions().len(),
            m.history.undoable()
        ),
        Page::Quarantine => format!(
            "{} items \u{b7} {}",
            m.quarantine.total_items(),
            purge_ui_model::leftovers::format_size(m.quarantine.total_bytes())
        ),
        Page::Settings => format!("Look: {}", m.prefs.design.title()),
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
        // D3's rail is a quiet gradient of the accent. Over a backdrop (Mica, Acrylic) it is a
        // tint of the glass instead: what differs from the flat colour stays over the desktop
        // (`frost`), so the accent is laid on a little stronger and never fades out wholly, or
        // a busy desktop behind the window would wash Bold's colour out of the rail.
        let rail = Rect::new(0.0, 0.0, lk.rail_w, h);
        let (top, bottom) = if ui.cx.frosted() {
            (0.30, 0.08)
        } else {
            (0.22, 0.0)
        };
        let from = mix(pal.title, pal.accent, top);
        let to = mix(pal.title, pal.accent, bottom);
        ui.p.gradient(rail, 0.0, from, to, Along::Y, 1.0);
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

    // Shown only while Purge runs elevated: here, while an uninstall runs.
    let elevated = m.flow.page.is_busy();
    let mut title_end = w - 3.0 * WIN_BTN_W - 12.0;
    if elevated {
        title_end -= ui.p.measure(Face::Ui, 12.0, "Administrator") + 40.0;
    }
    if lk.hero {
        command_field(ui, name_x + name_w + 14.0, title_end);
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
                .set_maximize_button((!m.flow.dialog_open()).then_some(snap));
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

/// A dialog's card rising into place over the backdrop: what `anim::pop` does, here by hand
/// because the drawing needs the whole `Ui`. [`close_dialog`] ends it.
struct Opened {
    card: Rect,
    footer: Rect,
    under: mdshared_ui::anim::Snapshot,
    origin: (i32, i32),
    t: f32,
}

fn open_dialog(ui: &mut Ui, key: &'static str, cw: f32, ch: f32) -> Opened {
    let (w, h) = ui.size;
    let pal = ui.pal;
    let card = dialog_card(cw + DIALOG_PAD * 2.0, ch, w, h);
    let t = ui
        .cx
        .anim()
        .value_from(key, 0.0_f32, 1.0, fluent::ENTER_LARGE);
    draw_backdrop_presence(ui.p, &pal, w, h, t);
    let bounds = dialog_bounds(card);
    let dy = DIALOG_RISE * (1.0 - t);
    let covered = Rect::new(bounds.x, bounds.y, bounds.w, bounds.h + dy);
    let under = ui.p.snapshot(crate::ui::grow(covered, 1.0));
    let origin = ui.p.offset(0.0, dy);
    ui.modal = true;
    let footer = draw_dialog_card(ui.p, &pal, card);
    Opened {
        card,
        footer,
        under,
        origin,
        t,
    }
}

fn close_dialog(ui: &mut Ui, o: Opened) {
    ui.modal = false;
    ui.p.restore_offset(o.origin);
    if o.t < 1.0 {
        ui.p.fade(&o.under, o.t);
    }
}

/// How long the confirmation's Uninstall stays disabled after the dialog appears, so a click
/// meant for what was under it never lands on it.
pub const ARM_DELAY: std::time::Duration = std::time::Duration::from_millis(400);

/// The gap under each wrapped step of the confirmation.
const STEP_GAP: f32 = 4.0;
/// The command box's padding above and below its wrapped text.
const COMMAND_PAD: f32 = 8.0;

/// The heights of the confirmation's wrapped parts, `cw` wide: each step, the command, the
/// quiet line.
struct ConfirmSizes {
    steps: Vec<f32>,
    command: f32,
    quiet_line: f32,
}

fn confirm_sizes(ui: &mut Ui, c: &crate::flow::Confirm, cw: f32) -> ConfirmSizes {
    let d = &c.dialog;
    ConfirmSizes {
        steps: d
            .steps
            .iter()
            .map(|s| ui.p.paragraph_height(Face::Ui, 13.0, cw - 8.0, s).max(17.0))
            .collect(),
        command: ui
            .p
            .paragraph_height_wrapped(Face::Mono, 12.0, cw - 20.0, c.command(), Wrap::Anywhere)
            .max(16.0),
        quiet_line: ui.p.paragraph_height(Face::Ui, 12.0, cw, &d.quiet_line),
    }
}

/// The height the confirmation needs for all it shows, the command and the steps in full.
fn confirm_height(ui: &mut Ui, c: &crate::flow::Confirm, cw: f32) -> f32 {
    let d = &c.dialog;
    let z = confirm_sizes(ui, c, cw);
    let mut h = DIALOG_PAD + 40.0 + 24.0;
    h += z.steps.iter().map(|s| s + STEP_GAP).sum::<f32>();
    h += 10.0 + 20.0 + z.command + 2.0 * COMMAND_PAD + 8.0 + 24.0;
    if let Some(running) = &d.still_running {
        let bar = InfoBar::new(Severity::Warning, "", running).closable(false);
        h += bar.height(ui.p, cw) + 16.0;
    }
    h += 28.0 + z.quiet_line + 14.0;
    h += 22.0 + DROPDOWN_H + 14.0 + 34.0;
    h + DIALOG_FOOTER
}

/// The confirmation before an uninstall (the model's [`ConfirmDialog`]): what will happen, the
/// exact command for the quiet switch's position, the restore point and the three buttons.
/// Nothing reaches the pipeline except through its "Uninstall", which waits [`ARM_DELAY`] after
/// the dialog appears.
///
/// The steps and the command are wrapped and shown in full (the WinUI dialog wrapped its
/// command and scrolled); when it all is taller than the window, the part above the buttons
/// scrolls, by the wheel and to the control the keyboard is on.
///
/// [`ConfirmDialog`]: purge_ui_model::pipeline::page::ConfirmDialog
fn confirm(ui: &mut Ui, m: &Model, v: &mut View) {
    let Some(c) = &m.flow.confirm else { return };
    let d = &c.dialog;
    let pal = ui.pal;
    let cw = 540.0;
    let full = confirm_height(ui, c, cw);
    let z = confirm_sizes(ui, c, cw);
    let ch = full.min(ui.size.1 - 24.0);
    let now = ui.cx.now();
    let opened = *v.confirm_at.get_or_insert(now);
    let armed = now.saturating_duration_since(opened) >= ARM_DELAY;
    if !armed {
        ui.cx.anim().wake_at(opened + ARM_DELAY);
    }
    let o = open_dialog(ui, "confirm", cw, ch);
    let r = o.card;
    let x = r.x + DIALOG_PAD;

    // The part above the buttons, scrolled when it does not fit.
    let body = Rect::new(r.x, r.y, r.w, (o.footer.y - r.y).max(0.0));
    let content = full - DIALOG_FOOTER;
    v.confirm_area = body;
    v.confirm_content = content;
    let off = v
        .confirm_scroll
        .offset(ui.cx.anim(), "confirm-scroll", content, body.h);
    let clip = ui.clip(body);
    let first = ui.ctls.len();
    let mut y = r.y + DIALOG_PAD - off;

    let drawn = ui.p.elide(Face::Semibold, 20.0, &d.title, cw);
    ui.text(
        id("DialogTitle"),
        Face::Semibold,
        20.0,
        x,
        y + 10.0,
        &drawn,
        pal.text,
        cw,
    );
    ui.say_whole(&d.title);
    y += 40.0;
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
    for (k, (step, sh)) in d.steps.iter().zip(&z.steps).enumerate() {
        // Each step is read by its text: step 2 says the route (the rig reads it).
        ui.p.paragraph(Face::Ui, 13.0, x + 8.0, y + 1.0, cw - 8.0, step, pal.text);
        ui.reg(
            Id("ConfirmStep", k as u32 + 1),
            Rect::new(x + 8.0, y, cw - 8.0, *sh),
            Role::Text,
            step,
            false,
        );
        y += sh + STEP_GAP;
    }
    y += 10.0;
    ui.p.text(Face::Ui, 12.0, x, y + 7.0, "Command", pal.muted, cw);
    y += 20.0;
    // The command in full, broken anywhere (a path has no spaces to break at): what runs is
    // never cut short. Its name is the whole command.
    let command = c.command();
    let box_r = Rect::new(x, y, cw, z.command + 2.0 * COMMAND_PAD);
    ui.p.frame(box_r, 5.0, pal.page, pal.line);
    ui.p.paragraph_wrapped(
        Face::Mono,
        12.0,
        x + 10.0,
        y + COMMAND_PAD,
        cw - 20.0,
        command,
        pal.text,
        Wrap::Anywhere,
    );
    ui.reg(id("CommandText"), box_r, Role::Text, command, false);
    y += box_r.h + 8.0;
    let signer = ui.p.elide(Face::Ui, 12.0, &d.signer, cw);
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
    ui.say_whole(&d.signer);
    y += 24.0;
    if let Some(running) = &d.still_running {
        let bar = InfoBar::new(Severity::Warning, "", running).closable(false);
        let bh = bar.height(ui.p, cw);
        let br = Rect::new(x, y, cw, bh);
        let look = Look {
            high_contrast: ui.hc,
            ..Look::default()
        };
        draw_infobar_with(ui.p, &pal, br, &bar, look);
        ui.reg(id("RunningText"), br, Role::Text, running, false);
        y += bh + 16.0;
    }
    ui.p.text(
        Face::Ui,
        13.0,
        x,
        y + 10.0,
        d.quiet_label,
        pal.text,
        cw - TOGGLE_W - 12.0,
    );
    ui.switch_enabled(
        id("QuietSwitch"),
        x + cw - TOGGLE_W,
        y + 10.0,
        c.quiet_on,
        d.quiet_enabled,
        d.quiet_label,
    );
    y += 28.0;
    let qh =
        ui.p.paragraph(Face::Ui, 12.0, x, y, cw, &d.quiet_line, pal.muted);
    ui.reg(
        id("QuietLineText"),
        Rect::new(x, y, cw, qh),
        Role::Text,
        &d.quiet_line,
        false,
    );
    y += qh + 14.0;
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
    ui.para(
        Face::Ui,
        12.0,
        x,
        y,
        cw,
        "Nothing is moved or removed by Purge until you confirm the list on the next page.",
        pal.muted,
    );
    ui.p.restore(clip);

    // The keyboard went to a control that is cut off: bring it into view. Then the body's
    // controls take the pointer only where they show, never over the backdrop.
    let ringed = ui.ctls[first..]
        .iter()
        .find(|c| c.focusable && ui.ringed(c.id))
        .map(|c| c.rect);
    if let Some(rr) = ringed
        && (rr.y < body.y || rr.bottom() > body.bottom())
    {
        let top = rr.y - body.y + off;
        let to = if rr.y < body.y {
            top - 8.0
        } else {
            top + rr.h + 8.0 - body.h
        };
        if v.confirm_scroll.scroll_to(to, content, body.h) {
            ui.cx.request_redraw_all();
        }
    }
    for c in &mut ui.ctls[first..] {
        c.rect = within(c.rect, body);
    }
    if let Some((track, thumb)) = scrollbar(
        Rect::new(body.right() - 6.0, body.y + 4.0, 3.0, body.h - 8.0),
        content,
        body.h,
        off,
    ) {
        draw_scrollbar_animated(ui.p, &pal, ui.cx.anim(), "confirm-bar", track, thumb, false);
    }

    // Ids of their own, not the WinUI template parts: the rig presses these by id and name, so
    // a "Not now" or "Uninstall" elsewhere in the window can never be taken for them.
    let mut list = vec![(
        id("ConfirmNotNowButton"),
        "Not now",
        Style::Standard,
        None,
        true,
    )];
    if d.check_again {
        list.push((
            id("ConfirmCheckAgainButton"),
            "Check again",
            Style::Standard,
            None,
            true,
        ));
    }
    list.push((
        id("ConfirmUninstallButton"),
        "Uninstall",
        Style::Accent,
        None,
        armed,
    ));
    let by = o.footer.y + (DIALOG_FOOTER - BUTTON_H) / 2.0;
    ui.buttons_right(o.footer.right() - DIALOG_PAD, by, &list);
    close_dialog(ui, o);
}

/// The button the confirmation's control `name` stands for.
pub fn confirm_button(name: &str) -> Option<ConfirmButton> {
    match name {
        "ConfirmUninstallButton" => Some(ConfirmButton::Uninstall),
        "ConfirmCheckAgainButton" => Some(ConfirmButton::CheckAgain),
        "ConfirmNotNowButton" => Some(ConfirmButton::NotNow),
        _ => None,
    }
}

pub const ELEVATION_TITLE: &str = "This needs administrator permission";
const ELEVATION_TEXT: &str = "For this, Purge starts a helper called purge-broker.exe with administrator permission. Windows asks you first, and may show the publisher as unknown until Purge is signed.";
const ELEVATION_CHANGES: &str = "Any program can show a prompt like that, so the Windows prompt is not your approval. Before anything is moved or removed, Purge shows its own review and waits for you.";
const ELEVATION_READS: &str = "The helper only reads Purge's records of earlier cleanups; nothing is moved or removed. Anything that would change your PC later is asked for in Purge's own review first.";

/// The explanation before the first Windows prompt of this run (`ElevationPrompts.cs`): every
/// page that starts the broker comes through it, so its words name no page.
fn elevation(ui: &mut Ui, read_only: bool) {
    let pal = ui.pal;
    let cw = 440.0;
    let second = if read_only {
        ELEVATION_READS
    } else {
        ELEVATION_CHANGES
    };
    let h1 = ui.p.paragraph_height(Face::Ui, 14.0, cw, ELEVATION_TEXT);
    let h2 = ui.p.paragraph_height(Face::Ui, 14.0, cw, second);
    let ch = DIALOG_PAD + 44.0 + h1 + 14.0 + h2 + DIALOG_PAD + DIALOG_FOOTER;
    let o = open_dialog(ui, "elevation", cw, ch);
    let x = o.card.x + DIALOG_PAD;
    let mut y = o.card.y + DIALOG_PAD;
    ui.text(
        id("DialogTitle"),
        Face::Semibold,
        20.0,
        x,
        y + 10.0,
        ELEVATION_TITLE,
        pal.text,
        cw,
    );
    y += 44.0;
    let a =
        ui.p.paragraph(Face::Ui, 14.0, x, y, cw, ELEVATION_TEXT, pal.text);
    ui.reg(
        id("DialogText"),
        Rect::new(x, y, cw, a),
        Role::Text,
        ELEVATION_TEXT,
        false,
    );
    y += a + 14.0;
    let b = ui.p.paragraph(Face::Ui, 14.0, x, y, cw, second, pal.text);
    ui.reg(
        id("DialogDetailText"),
        Rect::new(x, y, cw, b),
        Role::Text,
        second,
        false,
    );
    // The WinUI ContentDialog's template parts: the rig presses these by id.
    let list = [
        (
            id("DialogCloseButton"),
            "Not now",
            Style::Standard,
            None,
            true,
        ),
        (
            id("DialogPrimaryButton"),
            "Continue",
            Style::Accent,
            None,
            true,
        ),
    ];
    let by = o.footer.y + (DIALOG_FOOTER - BUTTON_H) / 2.0;
    ui.buttons_right(o.footer.right() - DIALOG_PAD, by, &list);
    close_dialog(ui, o);
}

/// The takeover question's title: "End the leftovers review of Firefox?".
pub fn takeover_title(t: &crate::flow::Takeover) -> String {
    format!("End {}?", t.what)
}

/// The question before a launch ends work another page still holds in the one broker session
/// ([`crate::flow::Takeover`]). "Not now" is where the keyboard starts.
fn takeover(ui: &mut Ui, t: &crate::flow::Takeover) {
    let pal = ui.pal;
    let cw = 440.0;
    let title = takeover_title(t);
    let first = format!(
        "Purge's administrator part works for one page at a time. The {} page needs it now, but the {} page still holds {}.",
        t.asking.page_name(),
        t.holder.page_name(),
        t.what
    );
    let second = "If you end it, that work has to be started again, and Windows may ask for permission again. Ending it moves or removes nothing.";
    let h1 = ui.p.paragraph_height(Face::Ui, 14.0, cw, &first);
    let h2 = ui.p.paragraph_height(Face::Ui, 14.0, cw, second);
    let th =
        ui.p.paragraph_height(Face::Semibold, 20.0, cw, &title)
            .max(24.0);
    let ch = DIALOG_PAD + th + 20.0 + h1 + 14.0 + h2 + DIALOG_PAD + DIALOG_FOOTER;
    let o = open_dialog(ui, "takeover", cw, ch);
    let x = o.card.x + DIALOG_PAD;
    let mut y = o.card.y + DIALOG_PAD;
    ui.p.paragraph(Face::Semibold, 20.0, x, y, cw, &title, pal.text);
    ui.reg(
        id("DialogTitle"),
        Rect::new(x, y, cw, th),
        Role::Text,
        &title,
        false,
    );
    y += th + 20.0;
    let a = ui.p.paragraph(Face::Ui, 14.0, x, y, cw, &first, pal.text);
    ui.reg(
        id("DialogText"),
        Rect::new(x, y, cw, a),
        Role::Text,
        &first,
        false,
    );
    y += a + 14.0;
    let b = ui.p.paragraph(Face::Ui, 14.0, x, y, cw, second, pal.text);
    ui.reg(
        id("DialogDetailText"),
        Rect::new(x, y, cw, b),
        Role::Text,
        second,
        false,
    );
    let list = [
        (
            id("TakeoverNotNowButton"),
            "Not now",
            Style::Standard,
            None,
            true,
        ),
        (id("TakeoverEndButton"), "End it", Style::Accent, None, true),
    ];
    let by = o.footer.y + (DIALOG_FOOTER - BUTTON_H) / 2.0;
    ui.buttons_right(o.footer.right() - DIALOG_PAD, by, &list);
    close_dialog(ui, o);
}
