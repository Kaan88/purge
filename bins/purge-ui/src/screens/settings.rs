//! The Settings page: the mockup's cards of rows, with the look's four choices (design, colour,
//! theme, page transition) and a live preview of them, and what the WinUI app's
//! `Views/SettingsView.xaml` has: the rule of what Purge ticks for you, the quarantine's keeping
//! times with "Open quarantine", About with the version, and the launch markers' expander in a
//! development build.
//!
//! Every choice applies at once, to the whole window, and is saved (`prefs`). Nothing here
//! pretends: a row whose subject this version does not let the user change says so and stays as
//! it is (DECISIONS 2026-11-24, "nothing on screen may pretend").

use mdshared_ui::dropdown::DROPDOWN_H;
use mdshared_ui::expander;
use mdshared_ui::gfx::{Face, Rect, Rgb, mix};
use mdshared_ui::overlay::draw_keycaps;
use mdshared_ui::scroll::{draw_scrollbar_animated, scrollbar};
use mdshared_ui::toggle::TOGGLE_W;

use crate::look::{Choice, Design, Preset};
use crate::model::Model;
use crate::ui::{BUTTON_H, Id, Role, Style, Ui, grow, id};
use crate::view::{DD_DESIGN, DD_PRESET, DD_THEME, DD_TRANSITION, View};

const ROW_H: f32 = 66.0;
const GAP: f32 = 18.0;
const LABEL_H: f32 = 28.0;
const DD_W: f32 = 240.0;
/// The preview under the appearance rows: the colour swatches and the transition's tile.
const PREVIEW_H: f32 = 132.0;
const SWATCH: f32 = 26.0;

/// What a row holds at its right.
enum Control {
    Dropdown(Id),
    /// A switch the user cannot turn: what it says is a fact of this version.
    Locked(Id, bool),
    Button(Id, &'static str),
    /// Lines of text under the title instead of a control.
    Facts(&'static [&'static str]),
}

struct Row {
    title: &'static str,
    detail: String,
    control: Control,
}

/// The id of the preset swatch at `i`.
pub fn swatch_id(i: usize) -> Id {
    Id("ColourSwatch", i as u32 + 1)
}

pub const PREVIEW_BUTTON: Id = Id("PreviewTransition", 0);

const TICKS: &[&str] = &[
    "After an uninstall, Purge ticks only leftovers it rates Safe. Likely items and weak matches wait for your own tick, and Protected items can never be ticked.",
    "When the uninstaller failed or Purge could not check that the program is gone, the scan is a forced one and nothing is ticked.",
    "You see the whole list and confirm it in Purge's security prompt before anything moves. Everything moved can be put back from History & undo.",
];

fn sections(m: &Model, animates: bool) -> Vec<(&'static str, Vec<Row>)> {
    let row = |title, detail: &str, control| Row {
        title,
        detail: detail.to_string(),
        control,
    };
    let motion = if animates {
        "How a page comes in. None, or Windows' animation effects off, means no motion."
    } else {
        "Windows' animation effects are off, so pages change without motion."
    };
    let mut out = vec![
        (
            "Appearance",
            vec![
                row(
                    "Look",
                    "Standard is calm and roomy; Bold has an icon rail, a command field and rings.",
                    Control::Dropdown(DD_DESIGN),
                ),
                row(
                    "Colour",
                    "An accent and a tint, in light and dark. High contrast uses the Windows colours.",
                    Control::Dropdown(DD_PRESET),
                ),
                row(
                    "Theme",
                    "Light, dark, or follow Windows.",
                    Control::Dropdown(DD_THEME),
                ),
                row("Page transition", motion, Control::Dropdown(DD_TRANSITION)),
            ],
        ),
        (
            "Uninstalling",
            vec![
                row(
                    "Ask before every uninstall",
                    "Always on: nothing reaches the pipeline without the confirmation.",
                    Control::Locked(id("ConfirmEach"), true),
                ),
                row("What Purge ticks for you", "", Control::Facts(TICKS)),
            ],
        ),
        (
            "Quarantine",
            vec![row(
                "Keeping times",
                "Files are kept 30 days; registry, service and task backups 180 days. When something expires, Purge offers to delete it and asks first; nothing is deleted on its own.",
                Control::Button(id("OpenQuarantine"), "Open quarantine"),
            )],
        ),
        (
            "Privacy",
            vec![row(
                "Send nothing",
                "Purge has no telemetry and makes no network request. There is nothing to turn on.",
                Control::Locked(id("SendNothing"), true),
            )],
        ),
    ];
    if m.prefs.design == Design::Bold {
        out.push((
            "Keyboard",
            vec![row(
                "Command palette",
                "Every page and command by name. Ctrl+K opens it from anywhere.",
                Control::Button(id("PaletteButton"), "Open"),
            )],
        ));
    }
    out
}

/// The width the title and detail of a row with a control have.
fn control_room(ui: &mut Ui, row: &Row, w: f32) -> f32 {
    let control_w = match &row.control {
        Control::Dropdown(_) => DD_W.min(w * 0.4),
        Control::Locked(..) => TOGGLE_W,
        Control::Button(_, label) => ui.button_w(label, None),
        Control::Facts(_) => 0.0,
    };
    w - 36.0 - control_w - 20.0
}

/// The height of a row: a fact row is as tall as its paragraphs, and a detail too long for one
/// line wraps.
fn row_h(ui: &mut Ui, row: &Row, w: f32) -> f32 {
    if let Control::Facts(lines) = &row.control {
        let tw = w - 36.0;
        let body: f32 = lines
            .iter()
            .map(|l| ui.p.paragraph_height(Face::Ui, 13.0, tw, l) + 8.0)
            .sum();
        return 40.0 + body + 6.0;
    }
    let room = control_room(ui, row, w);
    if ui.p.measure(Face::Ui, 12.0, &row.detail) <= room {
        return ROW_H;
    }
    let lines = ui.p.paragraph_height(Face::Ui, 12.0, room, &row.detail);
    (ROW_H - 18.0 + lines).max(ROW_H)
}

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let left = content.x + lk.margin;
    let room = content.w - 2.0 * lk.margin;
    // Bold keeps a column at the right for the keyboard, when the window has the room.
    let keys_w = if lk.hero && room >= 760.0 + 20.0 + 300.0 {
        340.0_f32.min(room - 780.0)
    } else {
        0.0
    };
    let w = (room - if keys_w > 0.0 { keys_w + 20.0 } else { 0.0 }).min(820.0);
    ui.heading(
        left,
        content.y + 38.0,
        m.page.title(),
        id("SubtitleText"),
        "Changes apply at once and are kept for next time",
        w,
    );

    let top = content.y + 70.0 + (lk.margin - 28.0);
    let view = Rect::new(
        content.x + 1.0,
        top,
        content.w - 2.0,
        content.bottom() - top,
    );
    let animates = ui.cx.anim().animates();
    let secs = sections(m, animates);
    let heights: Vec<Vec<f32>> = secs
        .iter()
        .map(|(_, rows)| rows.iter().map(|r| row_h(ui, r, w)).collect())
        .collect();

    // The markers' text is measured before the layout: the expander is as tall as it shows.
    let markers = markers(m, v);
    let marker_h = 12.0 + markers.len() as f32 * 18.0;
    let exp = id("MarkersExpander");
    let exp_h = if v.dev {
        expander::height(ui.cx.anim(), exp, m.settings.markers_open, marker_h) + 8.0
    } else {
        0.0
    };
    let total: f32 = heights
        .iter()
        .map(|hs| LABEL_H + hs.iter().sum::<f32>() + GAP)
        .sum::<f32>()
        + PREVIEW_H
        + LABEL_H
        + 74.0
        + 8.0
        + exp_h
        + 24.0;
    v.page_area = view;
    v.page_content = total;
    let off = v
        .page_scroll
        .offset(ui.cx.anim(), "settings-scroll", total, view.h);

    let old = ui.clip(view);
    let mut y = view.y + 6.0 - off;
    if keys_w > 0.0 {
        shortcuts(ui, left + w + 20.0, y, keys_w, view);
    }
    let seen = |r: Rect| r.bottom() > view.y + 8.0 && r.y < view.bottom() - 8.0;
    for (s, (title, rows)) in secs.iter().enumerate() {
        section_label(ui, left, y, w, title);
        y += LABEL_H;
        let appearance = s == 0;
        let rows_h: f32 = heights[s].iter().sum();
        let card_h = rows_h + if appearance { PREVIEW_H } else { 0.0 };
        let card = Rect::new(left, y, w, card_h);
        ui.card(card);
        let mut ry = card.y;
        for (k, row) in rows.iter().enumerate() {
            let r = Rect::new(card.x, ry, card.w, heights[s][k]);
            if k > 0 {
                ui.divider(r.x + 1.0, r.y, r.w - 2.0);
            }
            // A row scrolled out of the page declares nothing: its controls could not be seen.
            if seen(r) {
                setting(ui, v, r, row);
            }
            ry += r.h;
        }
        if appearance {
            let r = Rect::new(card.x, ry, card.w, PREVIEW_H);
            ui.divider(r.x + 1.0, r.y, r.w - 2.0);
            if seen(r) {
                preview(ui, m, v, r);
            } else if v.preview_tx.running() {
                v.preview_tx.cancel(ui.cx.anim());
            }
        }
        y += card.h + GAP;
    }

    section_label(ui, left, y, w, "About");
    y += LABEL_H;
    let about = Rect::new(left, y, w, 74.0);
    ui.card(about);
    let line = about_line(m);
    let line = ui.p.elide(Face::Ui, 14.0, &line, w - 36.0);
    ui.text(
        id("AboutLine"),
        Face::Ui,
        14.0,
        about.x + 18.0,
        about.y + 26.0,
        &line,
        pal.text,
        w - 36.0,
    );
    let credit = "Leftover scanners include code ported from Bulk Crap Uninstaller (Apache-2.0).";
    let credit = ui.p.elide(Face::Ui, 12.0, credit, w - 36.0);
    ui.p.text(
        Face::Ui,
        12.0,
        about.x + 18.0,
        about.y + 50.0,
        &credit,
        pal.muted,
        w - 36.0,
    );
    y += 74.0 + 8.0;

    if v.dev {
        let area = Rect::new(left, y, w, exp_h - 8.0);
        let head = expander::header_rect(area);
        if seen(head) {
            ui.reg(
                exp,
                head,
                Role::Expander(m.settings.markers_open),
                "Launch markers (this start)",
                true,
            );
        }
        let look = expander::Look {
            hovered: ui.hot(exp),
            pressed: ui.down(exp),
            focused: ui.ringed(exp),
            disabled: false,
        };
        let body = expander::draw_expander_animated(
            ui.p,
            &pal,
            ui.cx.anim(),
            exp,
            area,
            "Launch markers (this start)",
            m.settings.markers_open,
            look,
            marker_h,
        );
        if body.h > 0.5 {
            let inner = ui.clip(body);
            let mut my = body.y + 6.0;
            for line in &markers {
                ui.p.text(
                    Face::Mono,
                    12.0,
                    body.x + 28.0,
                    my + 9.0,
                    line,
                    pal.text,
                    body.w - 40.0,
                );
                my += 18.0;
            }
            ui.reg(id("Markers"), body, Role::Text, &markers.join("; "), false);
            ui.p.restore(inner);
        }
    }
    ui.p.restore(old);

    if let Some((track, thumb)) = scrollbar(
        Rect::new(view.x, view.y + 2.0, view.w - 3.0, view.h - 4.0),
        total,
        view.h,
        off,
    ) {
        draw_scrollbar_animated(
            ui.p,
            &pal,
            ui.cx.anim(),
            "settings-bar",
            track,
            thumb,
            false,
        );
    }
}

/// "Purge 0.1.9 · engine … · policy …", with "sample data" while the window shows the sample
/// data: the WinUI app's About line.
pub fn about_line(m: &Model) -> String {
    let f = &m.settings.facts;
    let mut parts = vec![format!("Purge {}", f.version)];
    if let Some(engine) = &f.engine {
        parts.push(format!("engine {engine}"));
    }
    if let Some(policy) = &f.policy {
        parts.push(format!("policy {policy}"));
    }
    if f.engine.is_none() {
        parts.push("sample data".to_string());
    }
    parts.join(" \u{b7} ")
}

/// The name over a group of settings. The soft look sets it small and in capitals.
fn section_label(ui: &mut Ui, x: f32, y: f32, w: f32, title: &str) {
    let pal = ui.pal;
    if ui.look.soft {
        ui.p.text(
            Face::Semibold,
            11.0,
            x + 2.0,
            y + 14.0,
            &title.to_uppercase(),
            pal.muted,
            w,
        );
    } else {
        ui.p.text(Face::Semibold, 13.0, x, y + 12.0, title, pal.text, w);
    }
}

/// The live preview under the appearance rows: a swatch for each colour preset (a click
/// chooses it), and a tile of two small pages that changes by the chosen transition.
fn preview(ui: &mut Ui, m: &Model, v: &mut View, r: Rect) {
    let pal = ui.pal;
    let x = r.x + 18.0;
    ui.p.text(Face::Ui, 14.0, x, r.y + 24.0, "Preview", pal.text, 200.0);
    ui.p.text(
        Face::Ui,
        12.0,
        x,
        r.y + 44.0,
        if ui.hc {
            "High contrast is on: Windows' colours are used"
        } else {
            "Colours: a click chooses one"
        },
        pal.muted,
        260.0,
    );
    let accent = mdshared_ui::platform::system_accent();
    let cy = r.y + 84.0;
    for (i, preset) in Preset::ALL.iter().enumerate() {
        let sid = swatch_id(i);
        let cx = x + SWATCH / 2.0 + 4.0 + i as f32 * (SWATCH + 12.0);
        let sr = Rect::new(cx - SWATCH / 2.0, cy - SWATCH / 2.0, SWATCH, SWATCH);
        let on = m.prefs.preset == *preset;
        ui.reg(sid, grow(sr, 4.0), Role::Item(on), preset.title(), true);
        if on {
            ui.p.ring(cx, cy, SWATCH / 2.0 + 4.0, 2.0, pal.text, 1.0);
        } else if ui.hot(sid) {
            ui.p.ring(cx, cy, SWATCH / 2.0 + 4.0, 1.0, pal.muted, 1.0);
        }
        if ui.hc {
            // Under a contrast theme the presets wait: an outline each, the chosen one filled.
            let fill = if on { pal.text } else { pal.page };
            ui.p.frame(sr, SWATCH / 2.0, fill, pal.text);
        } else {
            ui.p.rbox(sr, SWATCH / 2.0, preset.swatch(pal.dark, accent));
        }
        if *preset == Preset::Windows && (on || !ui.hc) {
            // The Windows accent's swatch carries four small panes, as the Windows mark does.
            let ink = if ui.hc { pal.page } else { [255, 255, 255] };
            for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                let q = Rect::new(cx + dx * 3.0 - 2.5, cy + dy * 3.0 - 2.5, 5.0, 5.0);
                ui.p.fill(q, ink);
            }
        }
        ui.ring(sid, grow(sr, 6.0), SWATCH / 2.0 + 6.0);
    }

    // The transition's tile and the button that plays it.
    let bw = ui.button_w("Play transition", None);
    let tile = Rect::new(r.right() - 18.0 - 190.0, r.y + 16.0, 190.0, 100.0);
    let b = Rect::new(tile.x - 16.0 - bw, tile.cy() - BUTTON_H / 2.0, bw, BUTTON_H);
    ui.button(
        PREVIEW_BUTTON,
        b,
        "Play transition",
        Style::Standard,
        None,
        true,
    );
    if v.preview_shown != Some(v.preview_b) {
        if v.preview_shown.is_some()
            && let Some(e) = m
                .prefs
                .transition
                .effect(usize::from(!v.preview_b), usize::from(v.preview_b))
        {
            v.preview_tx.begin(ui.cx.anim(), ui.p, tile, e);
        }
        v.preview_shown = Some(v.preview_b);
    }
    let clip = ui.clip(tile);
    mini_page(ui, tile, v.preview_b);
    ui.p.restore(clip);
    v.preview_tx.apply(ui.cx.anim(), ui.p, tile);
    ui.p.stroke_path(
        &mdshared_ui::gfx::Path::polygon(&[
            (tile.x, tile.y),
            (tile.right(), tile.y),
            (tile.right(), tile.bottom()),
            (tile.x, tile.bottom()),
        ]),
        1.0,
        pal.line,
        1.0,
    );
    ui.reg(
        id("TransitionPreview"),
        tile,
        Role::Text,
        &format!("Preview of {}", m.prefs.transition.title()),
        false,
    );
}

/// One of the preview's two small pages: a list (`false`) or a page of cards (`true`).
fn mini_page(ui: &mut Ui, r: Rect, second: bool) {
    let pal = ui.pal;
    ui.p.fill(r, pal.page);
    let ink = |k: f32| -> Rgb { mix(pal.page, pal.text, k) };
    let x = r.x + 12.0;
    ui.p.rbox(Rect::new(x, r.y + 10.0, 70.0, 8.0), 4.0, ink(0.7));
    if second {
        for i in 0..2 {
            let c = Rect::new(x + i as f32 * 84.0, r.y + 30.0, 76.0, 58.0);
            ui.p.rbox(c, 6.0, ink(0.08));
            ui.p.rbox(Rect::new(c.x + 8.0, c.y + 10.0, 40.0, 6.0), 3.0, ink(0.5));
            ui.p.rbox(
                Rect::new(c.x + 8.0, c.y + 36.0, 50.0, 10.0),
                5.0,
                pal.accent,
            );
        }
    } else {
        for i in 0..4 {
            let row = Rect::new(x, r.y + 30.0 + i as f32 * 16.0, r.w - 24.0, 12.0);
            if i == 1 {
                ui.p.rbox(row, 3.0, mix(pal.page, pal.accent, 0.25));
            }
            ui.p.rbox(
                Rect::new(row.x + 4.0, row.y + 3.0, 8.0, 6.0),
                2.0,
                pal.accent,
            );
            let len = 60.0 + (i * 13 % 30) as f32;
            ui.p.rbox(
                Rect::new(row.x + 18.0, row.y + 3.0, len, 6.0),
                3.0,
                ink(0.45),
            );
        }
    }
}

/// What the keyboard does, each with its keys as the toolkit's keycaps.
const SHORTCUTS: [(&str, &str); 11] = [
    ("Command palette", "Ctrl+K"),
    ("Programs", "Ctrl+1"),
    ("Uninstall pipeline", "Ctrl+2"),
    ("Leftovers", "Ctrl+3"),
    ("History & undo", "Ctrl+4"),
    ("Quarantine", "Ctrl+5"),
    ("Settings", "Ctrl+6"),
    ("Search programs", "Ctrl+F"),
    ("Select every program", "Ctrl+A"),
    ("Uninstall the selected", "Del, Enter"),
    ("Close, or clear the search", "Esc"),
];

/// Bold: the keyboard's column, beside the settings and scrolled with them.
fn shortcuts(ui: &mut Ui, x: f32, y: f32, w: f32, view: Rect) {
    let pal = ui.pal;
    section_label(ui, x, y, w, "Keyboard");
    let row_h = 34.0;
    let card = Rect::new(x, y + LABEL_H, w, SHORTCUTS.len() as f32 * row_h + 12.0);
    ui.card(card);
    for (k, (what, keys)) in SHORTCUTS.into_iter().enumerate() {
        let row = Rect::new(card.x, card.y + 6.0 + k as f32 * row_h, card.w, row_h);
        ui.p.text(
            Face::Ui,
            13.0,
            row.x + 16.0,
            row.cy(),
            what,
            pal.text,
            row.w - 150.0,
        );
        draw_keycaps(
            ui.p,
            &pal,
            Rect::new(row.x, row.y, row.w - 4.0, row.h),
            keys,
        );
        if row.bottom() > view.y + 8.0 && row.y < view.bottom() - 8.0 {
            let said = format!("{what}: {}", keys.replace(", ", " or "));
            ui.reg(Id("Shortcut", k as u32 + 1), row, Role::Text, &said, false);
        }
    }
}

fn markers(m: &Model, v: &View) -> Vec<String> {
    let mut out = vec![match v.first_frame_ms {
        Some(ms) => format!("first frame     {ms:.1} ms after main began"),
        None => "first frame     not drawn yet".to_string(),
    }];
    for (name, ms) in crate::markers::snapshot() {
        out.push(format!("{name:<15} {ms:8.1}"));
    }
    out.push(format!(
        "look            {} \u{b7} {} \u{b7} {}",
        m.prefs.design.name(),
        m.prefs.preset.name(),
        m.prefs.transition.name()
    ));
    out
}

fn setting(ui: &mut Ui, v: &View, r: Rect, row: &Row) {
    let pal = ui.pal;
    let x = r.x + 18.0;
    if let Control::Facts(lines) = &row.control {
        let tw = r.w - 36.0;
        ui.p.text(Face::Ui, 14.0, x, r.y + 22.0, row.title, pal.text, tw);
        let mut y = r.y + 40.0;
        for (i, line) in lines.iter().enumerate() {
            let h = ui.p.paragraph(Face::Ui, 13.0, x, y, tw, line, pal.text);
            let at = Rect::new(x, y, tw, h);
            ui.reg(Id("TickRule", i as u32 + 1), at, Role::Text, line, false);
            y += h + 8.0;
        }
        return;
    }
    let tw = control_room(ui, row, r.w);
    let control_w = r.w - 36.0 - 20.0 - tw;
    let wraps = r.h > ROW_H + 0.5;
    let title_y = if wraps { r.y + 22.0 } else { r.cy() - 10.0 };
    ui.p.text(Face::Ui, 14.0, x, title_y, row.title, pal.text, tw);
    if wraps {
        let y = title_y + 10.0;
        ui.p.paragraph(Face::Ui, 12.0, x, y, tw, &row.detail, pal.muted);
    } else {
        let detail = ui.p.elide(Face::Ui, 12.0, &row.detail, tw);
        ui.p.text(Face::Ui, 12.0, x, r.cy() + 10.0, &detail, pal.muted, tw);
    }
    let cx = r.right() - 18.0 - control_w;
    match &row.control {
        Control::Dropdown(did) => {
            let field = Rect::new(cx, r.cy() - DROPDOWN_H / 2.0, control_w, DROPDOWN_H);
            let dd = match *did {
                DD_THEME => &v.dds.theme,
                DD_DESIGN => &v.dds.design,
                DD_PRESET => &v.dds.preset,
                _ => &v.dds.transition,
            };
            ui.dropdown(*did, field, dd, row.title);
        }
        Control::Locked(sid, on) => ui.switch(*sid, cx, r.cy(), *on, row.title),
        Control::Button(bid, label) => {
            let b = Rect::new(cx, r.cy() - BUTTON_H / 2.0, control_w, BUTTON_H);
            ui.button(*bid, b, label, Style::Standard, None, true);
        }
        Control::Facts(_) => {}
    }
}
