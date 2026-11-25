//! The Settings page: the toolkit's drop-downs, switches and an expander, in cards of rows.

use mdshared_ui::dropdown::DROPDOWN_H;
use mdshared_ui::expander;
use mdshared_ui::gfx::{Face, Rect};
use mdshared_ui::overlay::draw_keycaps;
use mdshared_ui::scroll::{draw_scrollbar_animated, scrollbar};
use mdshared_ui::toggle::TOGGLE_W;

use crate::model::{Design, Model, Tab};
use crate::ui::{BUTTON_H, Id, Role, Style, Ui, id};
use crate::view::{DD_DESIGN, DD_KEEP, DD_THEME, View};

const ROW_H: f32 = 66.0;
const GAP: f32 = 18.0;
const LABEL_H: f32 = 28.0;
const DD_W: f32 = 240.0;

/// What a row holds at its right.
enum Control {
    Dropdown(Id),
    Switch(Id, bool),
    Button(Id, &'static str),
}

struct Row {
    title: &'static str,
    detail: String,
    control: Control,
}

fn sections(m: &Model) -> Vec<(&'static str, Vec<Row>)> {
    let s = &m.settings;
    let row = |title, detail: &str, control| Row {
        title,
        detail: detail.to_string(),
        control,
    };
    let mut out = vec![
        (
            "Appearance",
            vec![
                row(
                    "App theme",
                    "Light, dark, or what Windows uses.",
                    Control::Dropdown(DD_THEME),
                ),
                row(
                    "Design",
                    "The mockup's four designs share one model. Ctrl+Shift+D switches too.",
                    Control::Dropdown(DD_DESIGN),
                ),
            ],
        ),
        (
            "Uninstalling",
            vec![
                row(
                    "Ask before every uninstall",
                    "Always on: nothing reaches the pipeline without the confirmation.",
                    Control::Switch(id("ConfirmEach"), s.confirm_each),
                ),
                row(
                    "Show components and unnamed entries",
                    &format!(
                        "{} components and {} entries with no name are listed in their own tabs.",
                        m.programs.count(Tab::Components),
                        m.programs.count(Tab::Unnamed)
                    ),
                    Control::Switch(id("ShowComponents"), s.show_components),
                ),
            ],
        ),
        (
            "Quarantine",
            vec![row(
                "Keep items for",
                "After that they are deleted for good. Until then History & undo puts them back.",
                Control::Dropdown(DD_KEEP),
            )],
        ),
        (
            "Privacy",
            vec![row(
                "Send nothing",
                "Purge has no telemetry and makes no network request. The switch is here to say so.",
                Control::Switch(id("SendNothing"), s.send_nothing),
            )],
        ),
    ];
    if m.design == Design::Bold {
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

pub fn draw(ui: &mut Ui, m: &Model, v: &mut View, content: Rect) {
    let pal = ui.pal;
    let lk = ui.look;
    let left = content.x + lk.margin;
    let room = content.w - 2.0 * lk.margin;
    // D3 keeps a column at the right for the keyboard, when the window has the room.
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
        "Mockup: nothing here is saved",
        w,
    );

    let top = content.y + 70.0 + (lk.margin - 28.0);
    let view = Rect::new(
        content.x + 1.0,
        top,
        content.w - 2.0,
        content.bottom() - top,
    );
    let secs = sections(m);

    // The markers' text is measured before the layout: the expander is as tall as it shows.
    let markers = markers(m, v);
    let marker_h = 12.0 + markers.len() as f32 * 18.0;
    let exp = id("MarkersExpander");
    let exp_h = expander::height(ui.cx.anim(), exp, m.settings.markers_open, marker_h);
    let total: f32 = secs
        .iter()
        .map(|(_, rows)| LABEL_H + rows.len() as f32 * ROW_H + GAP)
        .sum::<f32>()
        + LABEL_H
        + 54.0
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
    for (title, rows) in &secs {
        section_label(ui, left, y, w, title);
        y += LABEL_H;
        let card = Rect::new(left, y, w, rows.len() as f32 * ROW_H);
        ui.card(card);
        for (k, row) in rows.iter().enumerate() {
            let r = Rect::new(card.x, card.y + k as f32 * ROW_H, card.w, ROW_H);
            if k > 0 {
                ui.divider(r.x + 1.0, r.y, r.w - 2.0);
            }
            // A row scrolled out of the page declares nothing: its controls could not be seen.
            if r.bottom() > view.y + 8.0 && r.y < view.bottom() - 8.0 {
                setting(ui, v, r, row);
            }
        }
        y += card.h + GAP;
    }

    section_label(ui, left, y, w, "About");
    y += LABEL_H;
    let about = Rect::new(left, y, w, 54.0);
    ui.card(about);
    let line = "Purge mockup \u{b7} mdshared-ui 294d330 (main) \u{b7} made-up data, no engine, nothing is removed";
    let line = ui.p.elide(Face::Ui, 14.0, line, w - 36.0);
    ui.text(
        id("AboutLine"),
        Face::Ui,
        14.0,
        about.x + 18.0,
        about.cy(),
        &line,
        pal.text,
        w - 36.0,
    );
    y += 54.0 + 8.0;

    let area = Rect::new(left, y, w, exp_h);
    let head = expander::header_rect(area);
    if head.bottom() > view.y + 8.0 && head.y < view.bottom() - 8.0 {
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

/// The name over a group of settings. D1 sets it small and in capitals, as a caption.
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

/// What the keyboard does, each with its keys as the toolkit's keycaps.
const SHORTCUTS: [(&str, &str); 12] = [
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
    ("Next design", "Ctrl+Shift+D"),
];

/// D3: the keyboard's column, beside the settings and scrolled with them.
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
    let first = match v.first_frame_ms {
        Some(ms) => format!("first frame     {ms:.1} ms after main began"),
        None => "first frame     not drawn yet".to_string(),
    };
    vec![
        first,
        format!(
            "programs        {} made up, no engine asked",
            m.programs.all.len()
        ),
        format!("design          {}", m.design.name()),
    ]
}

fn setting(ui: &mut Ui, v: &View, r: Rect, row: &Row) {
    let pal = ui.pal;
    let control_w = match &row.control {
        Control::Dropdown(_) => DD_W.min(r.w * 0.4),
        Control::Switch(..) => TOGGLE_W,
        Control::Button(_, label) => ui.button_w(label, None),
    };
    let x = r.x + 18.0;
    let tw = r.w - 36.0 - control_w - 20.0;
    ui.p.text(Face::Ui, 14.0, x, r.cy() - 10.0, row.title, pal.text, tw);
    let detail = ui.p.elide(Face::Ui, 12.0, &row.detail, tw);
    ui.p.text(Face::Ui, 12.0, x, r.cy() + 10.0, &detail, pal.muted, tw);
    let cx = r.right() - 18.0 - control_w;
    match &row.control {
        Control::Dropdown(did) => {
            let field = Rect::new(cx, r.cy() - DROPDOWN_H / 2.0, control_w, DROPDOWN_H);
            let dd = match *did {
                DD_THEME => &v.dds.theme,
                DD_DESIGN => &v.dds.design,
                _ => &v.dds.keep,
            };
            ui.dropdown(*did, field, dd, row.title);
        }
        Control::Switch(sid, on) => ui.switch(*sid, cx, r.cy(), *on, row.title),
        Control::Button(bid, label) => {
            let b = Rect::new(cx, r.cy() - BUTTON_H / 2.0, control_w, BUTTON_H);
            ui.button(*bid, b, label, Style::Standard, None, true);
        }
    }
}
