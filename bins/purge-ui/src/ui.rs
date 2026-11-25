//! What every screen draws with: the frame's painter and host, the list of controls the frame
//! declares (one list serves the pointer's hits, the Tab order and the accessibility tree), and
//! the small pieces the toolkit has no widget for (see GAPS.md).

use mdshared_ui::check::{TICK, Tick, draw_tick_animated};
use mdshared_ui::chrome;
use mdshared_ui::dropdown::{self, Dropdown, draw_dropdown_animated};
use mdshared_ui::focus::{Focus, draw_ring};
use mdshared_ui::gfx::{Face, Painter, Rect, Rgb, mix, rgb};
use mdshared_ui::host::Cx;
use mdshared_ui::infobar::{
    self, Hit, InfoBar, Severity, draw_infobar_with, severity_colors, severity_colors_in,
};
use mdshared_ui::link::{self, draw_link};
use mdshared_ui::overlay::{dialog_button_w, draw_dialog_button, draw_dialog_button_disabled};
use mdshared_ui::slider;
use mdshared_ui::theme::Palette;
use mdshared_ui::toggle::{self, TOGGLE_H, TOGGLE_W, Toggle, draw_toggle_animated};

use crate::look::Design;

/// The height of a push button.
pub const BUTTON_H: f32 = 32.0;

// Icons the toolkit's `glyph` set does not have, on the same 16 grid.
pub const SHIELD: &str = "M8 1.8l5.2 1.9v4c0 3.2-2.2 5.5-5.2 6.6-3-1.1-5.2-3.4-5.2-6.6v-4z";
pub const LOCK: &str = "M4 7h8a.5 .5 0 0 1 .5 .5v6a.5 .5 0 0 1-.5 .5H4a.5 .5 0 0 1-.5-.5v-6A.5 .5 0 0 1 4 7zM5.5 7V5a2.5 2.5 0 0 1 5 0v2";
pub const FILTER: &str = "M2.5 3h11L9.5 8v5l-3-1.5V8z";
pub const BOX: &str = "M2 3h12v3H2zM3 6v7h10V6M6.500 8.500h3";
pub const GEAR: &str = "M5.800 8a2.200 2.200 0 1 0 4.400 0a2.200 2.200 0 1 0-4.400 0zM8 1.500v2M8 12.500v2M1.500 8h2M12.500 8h2M3.400 3.400l1.400 1.400M11.200 11.200l1.400 1.400M3.400 12.600l1.400-1.400M11.200 4.800l1.400-1.400";

// ---- ids and controls ------------------------------------------------------------------------

/// A control's name: the AutomationId Purge's XAML gives it, and a number for the controls a
/// list repeats. It names the control to the pointer, the keyboard focus, the animator and the
/// accessibility tree alike.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Id(pub &'static str, pub u32);

pub const fn id(name: &'static str) -> Id {
    Id(name, 0)
}

impl Id {
    /// The AutomationId: the name, with the number after it for a repeated control.
    pub fn author(self) -> String {
        if self.1 == 0 {
            self.0.to_string()
        } else {
            format!("{}_{}", self.0, self.1)
        }
    }
}

/// What a control is, with the part of its state a screen reader says.
#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    Button,
    Link,
    /// Ticked, not ticked, or `None` for some of its group.
    Check(Option<bool>),
    Switch(bool),
    Combo {
        value: String,
        open: bool,
    },
    /// One tab of a row of tabs, or one page of the rail; selected or not.
    Tab(bool),
    Expander(bool),
    /// Text a test reads (a result's title, a count). Takes no keyboard.
    Text,
    Edit(String),
    Progress(Option<f32>),
    /// A list whose rows the application adds to the tree itself (`Ctl::rect` is its viewport).
    List,
    /// One row of a short list, selected or not.
    Item(bool),
}

/// What a row's control stands for, kept with the control when it is drawn (UI-REVIEW1 S7): a
/// click is resolved by this, never by the row's place in a list that may have changed since the
/// frame the user saw.
#[derive(Clone, Debug, PartialEq)]
pub enum Key {
    /// A leftovers item.
    Candidate(purge_rpc::methods::CandidateRef),
    /// A cleanup (History) or a batch of it (Quarantine).
    Session(purge_model::exec::session::SessionId),
    /// An item of the cleanup History shows.
    Op(purge_model::exec::op::OpId),
    /// A quarantined item.
    Expiry(purge_rpc::methods::ExpiryId),
}

#[derive(Clone, Debug)]
pub struct Ctl {
    pub id: Id,
    /// What the control stands for, when it is a row's ([`Ui::key`]).
    pub key: Option<Key>,
    pub rect: Rect,
    pub role: Role,
    pub label: String,
    /// Tab reaches it and a click focuses it.
    pub focusable: bool,
    pub disabled: bool,
    /// Declared by the dialog (or sheet, or palette) that is open over the page.
    pub modal: bool,
}

// ---- the look of a design --------------------------------------------------------------------

/// The measures that differ between the designs. The screens read these and never the design's
/// name, except where a design lays a screen out differently.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Look {
    pub design: Design,
    pub title_h: f32,
    pub rail_w: f32,
    /// The rail shows icons only.
    pub rail_icons: bool,
    /// The page's side margin.
    pub margin: f32,
    /// The size of a page's title.
    pub h1: f32,
    /// The corner radius of a card.
    pub radius: f32,
    /// The height of a row of the programs list.
    pub row_h: f32,
    /// The rail's pill moves; rows fade their hover. (Page transitions are a setting of their
    /// own: `look::Transition`.)
    pub motion: bool,
    /// D1: a page's secondary line stands under its title, not beside it.
    pub stacked: bool,
    /// D1: a card is a quiet panel a shade off the page, with no outline.
    pub soft: bool,
    /// D3: a tinted band behind the page's title, the command field in the title row, and
    /// rings where the other designs have bars.
    pub hero: bool,
    /// D2: the pipeline page is the whole uninstall, the review of its leftovers included.
    pub flow: bool,
}

impl Look {
    pub fn of(design: Design) -> Look {
        match design {
            // D1's measures, quiet cards and stacked headings, with D2's rounder cards and its
            // uninstall flow on the pipeline page.
            Design::Standard => Look {
                design,
                title_h: 48.0,
                rail_w: 248.0,
                rail_icons: false,
                margin: 36.0,
                h1: 30.0,
                radius: 12.0,
                row_h: 46.0,
                motion: true,
                stacked: true,
                soft: true,
                hero: false,
                flow: true,
            },
            Design::Bold => Look {
                design,
                title_h: 44.0,
                rail_w: 64.0,
                rail_icons: true,
                margin: 32.0,
                h1: 34.0,
                radius: 14.0,
                row_h: 44.0,
                motion: true,
                stacked: false,
                soft: false,
                hero: true,
                flow: false,
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Style {
    Accent,
    Standard,
    /// No fill and no border until hovered.
    Subtle,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Good,
    Caution,
    Bad,
    Neutral,
    Accent,
    Outline,
}

/// The colours of the program tiles, picked by publisher as Purge picks them.
const TILES: [u32; 10] = [
    0x0F6CBD, 0x8764B8, 0xC239B3, 0xCA5010, 0x498205, 0x038387, 0x986F0B, 0x4F6BED, 0x3B3B3B,
    0xC4314B,
];

pub fn tile_colour(publisher: &str) -> Rgb {
    let hash = publisher.bytes().fold(0x811c_9dc5_u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    rgb(TILES[hash as usize % TILES.len()])
}

pub fn grow(r: Rect, d: f32) -> Rect {
    Rect::new(r.x - d, r.y - d, r.w + 2.0 * d, r.h + 2.0 * d)
}

/// The part of `a` inside `b`; a rectangle with no area when they do not meet.
pub fn within(a: Rect, b: Rect) -> Rect {
    let (x0, y0) = (a.x.max(b.x), a.y.max(b.y));
    let (x1, y1) = (a.right().min(b.right()), a.bottom().min(b.bottom()));
    Rect::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
}

pub fn ok_ink(pal: &Palette) -> Rgb {
    severity_colors(Severity::Success, pal).ink
}

pub fn bad_ink(pal: &Palette) -> Rgb {
    severity_colors(Severity::Error, pal).ink
}

// ---- the frame -------------------------------------------------------------------------------

/// One frame's drawing: the painter, the host, the palette, the pointer's state, and the
/// controls declared so far.
pub struct Ui<'a, 'p, 'c> {
    pub p: &'a mut Painter<'p>,
    pub cx: &'a mut Cx<'c, ()>,
    pub pal: Palette,
    pub look: Look,
    /// High contrast is on: colour alone must carry nothing, and fills that are tints of the
    /// page are replaced by frames.
    pub hc: bool,
    /// The colour of a link when the palette's accent is not it (a contrast theme's own).
    pub link_ink: Option<Rgb>,
    pub focus: &'a mut Focus<Id>,
    pub ctls: Vec<Ctl>,
    pub hover: Option<Id>,
    pub pressed: Option<Id>,
    /// The controls being declared belong to what is open over the page.
    pub modal: bool,
    /// The window, logical px.
    pub size: (f32, f32),
}

impl Ui<'_, '_, '_> {
    // -- declaring controls --

    /// Declares a control: it takes the pointer where `rect` is, and the keyboard when
    /// `focusable`.
    pub fn reg(&mut self, id: Id, rect: Rect, role: Role, label: &str, focusable: bool) {
        if focusable {
            if self.modal {
                self.focus.add_in(SCOPE, id);
            } else {
                self.focus.add(id);
            }
        }
        self.ctls.push(Ctl {
            id,
            key: None,
            rect,
            role,
            label: label.to_string(),
            focusable,
            disabled: false,
            modal: self.modal,
        });
    }

    /// Declares a control that is there but cannot be used.
    pub fn reg_disabled(&mut self, id: Id, rect: Rect, role: Role, label: &str) {
        self.ctls.push(Ctl {
            id,
            key: None,
            rect,
            role,
            label: label.to_string(),
            focusable: false,
            disabled: true,
            modal: self.modal,
        });
    }

    /// Gives the control `id` declared last what it stands for: its clicks act on `key`.
    pub fn key(&mut self, id: Id, key: Key) {
        if let Some(c) = self.ctls.iter_mut().rev().find(|c| c.id == id) {
            c.key = Some(key);
        }
    }

    pub fn hot(&self, id: Id) -> bool {
        self.hover == Some(id)
    }

    pub fn down(&self, id: Id) -> bool {
        self.pressed == Some(id)
    }

    pub fn ringed(&self, id: Id) -> bool {
        self.focus.ring_visible(id)
    }

    /// The focus ring round `r` when the keyboard is on `id`.
    pub fn ring(&mut self, id: Id, r: Rect, radius: f32) {
        if self.focus.ring_visible(id) {
            draw_ring(self.p, &self.pal, r, radius);
        }
    }

    /// Restricts drawing to `r` within the clip there already is, and returns that one for
    /// `Painter::restore`. (`Painter::clip` alone replaces the clip, so a list inside a page
    /// inside the frame's damage would draw outside the damage.)
    pub fn clip(&mut self, r: Rect) -> (i32, i32, i32, i32) {
        let old = self.p.clip(r);
        let new = self.p.clip(r);
        self.p.restore((
            new.0.max(old.0),
            new.1.max(old.1),
            new.2.min(old.2),
            new.3.min(old.3),
        ));
        old
    }

    // -- text --

    /// Text a test can read by its AutomationId. Returns its width.
    #[allow(clippy::too_many_arguments)] // a place, a style and a name
    pub fn text(
        &mut self,
        id: Id,
        face: Face,
        size: f32,
        x: f32,
        cy: f32,
        text: &str,
        c: Rgb,
        max: f32,
    ) -> f32 {
        let w = self.p.text(face, size, x, cy, text, c, max);
        let r = Rect::new(x, cy - size * 0.7, w.max(1.0), size * 1.4);
        self.reg(id, r, Role::Text, text, false);
        w
    }

    /// Gives the control declared last the whole of `text` as its name, for text drawn elided:
    /// a reader says the whole name, and a test matches it exactly. The drawing is unchanged.
    pub fn say_whole(&mut self, text: &str) {
        if let Some(c) = self.ctls.last_mut() {
            c.label = text.to_string();
        }
    }

    /// A paragraph; returns the y under it.
    #[allow(clippy::too_many_arguments)] // a place, a width and a style
    pub fn para(
        &mut self,
        face: Face,
        size: f32,
        x: f32,
        y: f32,
        w: f32,
        text: &str,
        c: Rgb,
    ) -> f32 {
        y + self.p.paragraph(face, size, x, y, w, text, c)
    }

    /// A page title with a secondary line beside it.
    pub fn heading(&mut self, x: f32, cy: f32, title: &str, sub_id: Id, sub: &str, max: f32) {
        let pal = self.pal;
        let h1 = self.look.h1;
        if self.look.stacked {
            // D1: the title, and what it counts on a line of its own under it.
            self.p
                .text(Face::Semibold, h1, x, cy - 7.0, title, pal.text, max);
            if !sub.is_empty() {
                let s = self.p.elide(Face::Ui, 13.0, sub, max);
                self.text(sub_id, Face::Ui, 13.0, x, cy + 18.0, &s, pal.muted, max);
            }
            return;
        }
        let w = self.p.text(Face::Semibold, h1, x, cy, title, pal.text, max);
        if !sub.is_empty() {
            let room = (max - w - 14.0).max(0.0);
            let s = self.p.elide(Face::Ui, 13.0, sub, room);
            self.text(
                sub_id,
                Face::Ui,
                13.0,
                x + w + 14.0,
                cy + h1 * 0.2,
                &s,
                pal.muted,
                room,
            );
        }
    }

    // -- buttons --

    pub fn button_w(&mut self, label: &str, icon: Option<&str>) -> f32 {
        dialog_button_w(self.p, label).max(self.p.measure(Face::Semibold, 13.0, label) + 28.0)
            + if icon.is_some() { 22.0 } else { 0.0 }
    }

    /// A push button: the toolkit's dialog button, with an icon in front when given.
    pub fn button(
        &mut self,
        id: Id,
        r: Rect,
        label: &str,
        style: Style,
        icon: Option<&str>,
        enabled: bool,
    ) {
        let pal = self.pal;
        if !enabled {
            self.reg_disabled(id, r, Role::Button, label);
            if style == Style::Subtle {
                self.p.text_center(Face::Ui, 13.0, r, label, pal.faint);
            } else {
                // The toolkit's disabled button centres its label; the icon is left out.
                draw_dialog_button_disabled(self.p, &pal, r, label, style == Style::Accent);
            }
            return;
        }
        self.reg(id, r, Role::Button, label, true);
        let (hot, down) = (self.hot(id), self.down(id));
        let ink = match style {
            Style::Accent => pal.on_accent,
            Style::Standard | Style::Subtle => pal.text,
        };
        match style {
            Style::Accent => draw_dialog_button(self.p, &pal, r, "", true, hot, down),
            Style::Standard => draw_dialog_button(self.p, &pal, r, "", false, hot, down),
            Style::Subtle => {
                if let Some(fill) = chrome::button_fill(&pal, hot, down && hot, false, false) {
                    self.p.rbox(r, 4.0, fill);
                }
            }
        }
        let face = if style == Style::Accent {
            Face::Semibold
        } else {
            Face::Ui
        };
        let tw = self.p.measure(face, 13.0, label);
        let iw = if icon.is_some() {
            if label.is_empty() { 16.0 } else { 22.0 }
        } else {
            0.0
        };
        let x = r.x + ((r.w - tw - iw) / 2.0).max(4.0);
        if let Some(g) = icon {
            self.p.icon(g, 15.0, x + 8.0, r.cy(), ink);
        }
        if !label.is_empty() {
            self.p
                .text(face, 13.0, x + iw, r.cy(), label, ink, r.w - iw);
        }
        self.ring(id, r, 4.0);
    }

    /// A square button that shows only an icon; `label` is what a screen reader says.
    pub fn icon_button(&mut self, id: Id, r: Rect, glyph: &str, label: &str, style: Style) {
        let pal = self.pal;
        self.reg(id, r, Role::Button, label, true);
        let (hot, down) = (self.hot(id), self.down(id));
        match style {
            Style::Accent => draw_dialog_button(self.p, &pal, r, "", true, hot, down),
            Style::Standard => draw_dialog_button(self.p, &pal, r, "", false, hot, down),
            Style::Subtle => {
                if let Some(fill) = chrome::button_fill(&pal, hot, down && hot, false, false) {
                    self.p.rbox(r, 4.0, fill);
                }
            }
        }
        let ink = if style == Style::Accent {
            pal.on_accent
        } else {
            pal.text
        };
        self.p.icon(glyph, 16.0, r.cx(), r.cy(), ink);
        self.ring(id, r, 4.0);
    }

    /// Buttons laid from `right` leftwards; returns the left edge of the leftmost.
    pub fn buttons_right(
        &mut self,
        right: f32,
        y: f32,
        list: &[(Id, &str, Style, Option<&str>, bool)],
    ) -> f32 {
        // Measured first, then drawn left to right: the order they are declared in is the
        // order Tab visits them.
        let widths: Vec<f32> = list.iter().map(|b| self.button_w(b.1, b.3)).collect();
        let total: f32 = widths.iter().sum::<f32>() + 8.0 * list.len().saturating_sub(1) as f32;
        let left = right - total;
        let mut x = left;
        for (&(id, label, style, icon, enabled), w) in list.iter().zip(widths) {
            self.button(
                id,
                Rect::new(x, y, w, BUTTON_H),
                label,
                style,
                icon,
                enabled,
            );
            x += w + 8.0;
        }
        left
    }

    // -- the toolkit's small widgets, declared and drawn in one call --

    /// A tick box whose middle is at `cy`. `on` is `None` for a box some of whose group is
    /// ticked, which the toolkit's `Tick` cannot show: that state is drawn here.
    pub fn tick(&mut self, id: Id, x: f32, cy: f32, on: Option<bool>, enabled: bool, label: &str) {
        let pal = self.pal;
        let r = Rect::new(x, cy - TICK / 2.0, TICK, TICK);
        if enabled {
            self.reg(id, grow(r, 5.0), Role::Check(on), label, true);
        } else {
            self.reg_disabled(id, grow(r, 5.0), Role::Check(on), label);
        }
        let ringed = self.ringed(id);
        match on {
            Some(v) => {
                let mut t = if enabled {
                    Tick::new(v)
                } else {
                    Tick::disabled(v)
                };
                if ringed {
                    t = t.with_focus();
                }
                draw_tick_animated(self.p, &pal, self.cx.anim(), id, r, t);
            }
            None => {
                self.p.rbox(r, 3.0, pal.accent);
                self.p.fill(
                    Rect::new(r.x + 4.0, r.cy() - 1.0, r.w - 8.0, 2.0),
                    pal.on_accent,
                );
                if ringed {
                    draw_ring(self.p, &pal, r, 3.0);
                }
            }
        }
    }

    /// A switch whose middle is at `cy`, with its left edge at `x`.
    pub fn switch(&mut self, id: Id, x: f32, cy: f32, on: bool, label: &str) {
        self.switch_enabled(id, x, cy, on, true, label);
    }

    /// [`Ui::switch`] that may be disabled (it still says its position).
    pub fn switch_enabled(
        &mut self,
        id: Id,
        x: f32,
        cy: f32,
        on: bool,
        enabled: bool,
        label: &str,
    ) {
        let pal = self.pal;
        let r = Rect::new(x, cy - TOGGLE_H / 2.0, TOGGLE_W, TOGGLE_H);
        if enabled {
            self.reg(id, grow(r, 4.0), Role::Switch(on), label, true);
        } else {
            self.reg_disabled(id, grow(r, 4.0), Role::Switch(on), label);
        }
        let look = toggle::Look {
            hovered: self.hot(id),
            pressed: self.down(id),
            focused: self.ringed(id),
            disabled: !enabled,
        };
        draw_toggle_animated(self.p, &pal, self.cx.anim(), id, r, &Toggle::new(on), look);
    }

    /// A link with its top-left at `(x, y)`; returns its rectangle.
    pub fn link(&mut self, id: Id, x: f32, y: f32, text: &str) -> Rect {
        let pal = self.pal;
        let r = link::link_rect(self.p, x, y, text);
        self.reg(id, r, Role::Link, text, true);
        let look = link::Look {
            hovered: self.hot(id),
            pressed: self.down(id),
            focused: self.ringed(id),
            disabled: false,
            // A contrast theme has a colour of its own for links; its accent is the selection's.
            ink: self.link_ink,
        };
        draw_link(self.p, &pal, r, text, look);
        r
    }

    /// The field of a drop-down. Its menu is drawn over everything else, at the frame's end.
    pub fn dropdown(&mut self, id: Id, r: Rect, dd: &Dropdown<usize>, label: &str) {
        let pal = self.pal;
        self.reg(
            id,
            r,
            Role::Combo {
                value: dd.selected_label().to_string(),
                open: dd.is_open(),
            },
            label,
            true,
        );
        let look = dropdown::Look {
            hovered: self.hot(id),
            focused: self.ringed(id),
            disabled: false,
        };
        draw_dropdown_animated(self.p, &pal, self.cx.anim(), id, r, dd, look);
    }

    /// The toolkit's info bar at `(x, y)`, `w` wide; returns the y under it. `close` names the
    /// close button of a bar that can be closed.
    pub fn infobar(
        &mut self,
        host: Id,
        x: f32,
        y: f32,
        w: f32,
        bar: &InfoBar,
        close: Option<Id>,
    ) -> f32 {
        self.infobar_with(host, x, y, w, bar, close, &[])
    }

    /// [`Ui::infobar`] with action buttons: `actions[k]` names the bar's action `k` (its
    /// [`infobar::Action::id`] is `k`).
    #[allow(clippy::too_many_arguments)] // a place, the bar and its controls' names
    pub fn infobar_with(
        &mut self,
        host: Id,
        x: f32,
        y: f32,
        w: f32,
        bar: &InfoBar,
        close: Option<Id>,
        actions: &[Id],
    ) -> f32 {
        let pal = self.pal;
        let h = bar.height(self.p, w);
        let r = Rect::new(x, y, w, h);
        let label = format!("{} {}", bar.title(), bar.message());
        self.reg(host, r, Role::Text, label.trim(), false);
        let parts = bar.parts(self.p, r);
        let mut look = infobar::Look {
            high_contrast: self.hc,
            ..infobar::Look::default()
        };
        for (k, (aid, ar)) in parts.actions.iter().enumerate() {
            let Some(&cid) = actions.get(*aid as usize) else {
                continue;
            };
            let text = bar
                .actions()
                .get(k)
                .map_or("", |a| a.label.as_str())
                .to_owned();
            self.reg(cid, *ar, Role::Button, &text, true);
            if self.hot(cid) {
                look.hover = Some(Hit::Action(*aid));
            }
            if self.down(cid) {
                look.pressed = Some(Hit::Action(*aid));
            }
            if self.ringed(cid) {
                look.focused = Some(Hit::Action(*aid));
            }
        }
        if let (Some(cid), Some(cr)) = (close, parts.close) {
            self.reg(cid, cr, Role::Button, "Close", true);
            if self.hot(cid) {
                look.hover = Some(Hit::Close);
            }
            if self.down(cid) {
                look.pressed = Some(Hit::Close);
            }
            if self.ringed(cid) {
                look.focused = Some(Hit::Close);
            }
        }
        draw_infobar_with(self.p, &pal, r, bar, look);
        y + h
    }

    /// The toolkit's progress bar: `fraction` full, or running to and fro for `None`.
    pub fn progress(&mut self, id: Id, r: Rect, fraction: Option<f32>, label: &str) {
        let pal = self.pal;
        self.reg(id, r, Role::Progress(fraction), label, false);
        match fraction {
            Some(f) => slider::draw_progress(self.p, &pal, r, f),
            None => slider::draw_progress_indeterminate(self.p, &pal, self.cx.anim(), id, r),
        }
    }

    /// A label and its value on one line, as the details panes list their facts. Returns the y
    /// of the next line.
    #[allow(clippy::too_many_arguments)] // a place, two texts and a name
    pub fn fact(
        &mut self,
        id: Id,
        x: f32,
        y: f32,
        label_w: f32,
        w: f32,
        label: &str,
        value: &str,
    ) -> f32 {
        let pal = self.pal;
        self.p
            .text(Face::Ui, 12.0, x, y + 9.0, label, pal.muted, label_w);
        let h = self
            .p
            .paragraph(Face::Ui, 12.5, x + label_w, y, w - label_w, value, pal.text);
        self.reg(
            id,
            Rect::new(x + label_w, y, w - label_w, h),
            Role::Text,
            value,
            false,
        );
        y + h.max(18.0) + 6.0
    }

    // -- pieces the toolkit has no widget for --

    /// The fill of a card in this design.
    pub fn card_fill(&self) -> Rgb {
        let pal = self.pal;
        if self.look.soft && !self.hc {
            mix(pal.page, pal.text, if pal.dark { 0.07 } else { 0.04 })
        } else if pal.dark {
            pal.bar
        } else {
            pal.field
        }
    }

    pub fn card(&mut self, r: Rect) {
        let pal = self.pal;
        let fill = self.card_fill();
        let radius = self.look.radius;
        if self.look.soft && !self.hc {
            // D1: no outline. A contrast theme keeps it: there a shade says nothing.
            self.p.rbox(r, radius, fill);
        } else {
            crate::paint::frame(self.p, r, radius, fill, pal.line);
        }
    }

    /// A sunken box inside a card, for a group of facts.
    pub fn well(&mut self, r: Rect) {
        let pal = self.pal;
        if self.look.soft && !self.hc {
            self.p.rbox(r, 8.0, pal.page);
        } else {
            crate::paint::frame(self.p, r, 6.0, pal.page, pal.line);
        }
    }

    pub fn divider(&mut self, x: f32, y: f32, w: f32) {
        let px = self.p.px();
        let line = self.pal.line;
        self.p.fill(Rect::new(x, y, w, px), line);
    }

    pub fn chip_w(&mut self, label: &str) -> f32 {
        self.p.measure(Face::Ui, 11.5, label) + 16.0
    }

    /// A small labelled pill; returns its width.
    pub fn chip(&mut self, x: f32, cy: f32, label: &str, tone: Tone) -> f32 {
        let pal = self.pal;
        let w = self.chip_w(label);
        let r = Rect::new(x, cy - 10.0, w, 20.0);
        let (fill, line, ink) = match tone {
            Tone::Good | Tone::Caution | Tone::Accent | Tone::Bad => {
                let c = severity_colors_in(
                    match tone {
                        Tone::Good => Severity::Success,
                        Tone::Caution => Severity::Warning,
                        Tone::Bad => Severity::Error,
                        _ => Severity::Info,
                    },
                    &pal,
                    self.hc,
                );
                (c.fill, c.line, c.ink)
            }
            Tone::Neutral => (pal.hover, pal.line, pal.muted),
            Tone::Outline => (pal.page, pal.popup_line, pal.muted),
        };
        if self.hc {
            // A tint of the page says nothing in a contrast theme: the frame and the words do.
            self.p.frame(r, 10.0, pal.page, pal.text);
            self.p.text_center(Face::Ui, 11.5, r, label, pal.text);
        } else {
            self.p.frame(r, 10.0, fill, line);
            self.p.text_center(Face::Ui, 11.5, r, label, ink);
        }
        w
    }

    /// A rounded square with the first letter of a name.
    pub fn tile(&mut self, r: Rect, name: &str, publisher: &str) {
        let first = name.chars().find(|c| c.is_alphanumeric()).unwrap_or('?');
        let initial: String = first.to_uppercase().collect();
        if self.hc {
            let pal = self.pal;
            self.p.frame(r, r.w * 0.23, pal.page, pal.text);
            self.p
                .text_center(Face::Semibold, r.w * 0.48, r, &initial, pal.text);
        } else {
            self.p.rbox(r, r.w * 0.23, tile_colour(publisher));
            self.p
                .text_center(Face::Semibold, r.w * 0.48, r, &initial, [255, 255, 255]);
        }
    }

    /// A bar of several colours: each part's share of `r` is its share of the parts' sum.
    pub fn parts_bar(&mut self, r: Rect, parts: &[(f32, Rgb)]) {
        let pal = self.pal;
        let total: f32 = parts.iter().map(|p| p.0.max(0.0)).sum();
        self.p.rbox(r, r.h / 2.0, pal.hover);
        if total <= 0.0 {
            return;
        }
        let old = self.p.clip(r);
        let mut x = r.x;
        let live: Vec<&(f32, Rgb)> = parts.iter().filter(|p| p.0 > 0.0).collect();
        for (i, (v, c)) in live.iter().enumerate() {
            let w = r.w * v / total;
            let gap = if i + 1 < live.len() { 2.0 } else { 0.0 };
            self.p
                .rbox(Rect::new(x, r.y, (w - gap).max(1.0), r.h), r.h / 2.0, *c);
            x += w;
        }
        self.p.restore(old);
        if self.hc {
            self.p.stroke_path(
                &mdshared_ui::gfx::Path::polygon(&[
                    (r.x, r.y),
                    (r.right(), r.y),
                    (r.right(), r.bottom()),
                    (r.x, r.bottom()),
                ]),
                1.0,
                pal.text,
                1.0,
            );
        }
    }

    /// A ring that is `fraction` full, with `text` in its middle: the days an item has left.
    pub fn ring_gauge(&mut self, cx: f32, cy: f32, radius: f32, fraction: f32, text: &str, c: Rgb) {
        let pal = self.pal;
        let width = (radius * 0.22).max(2.5);
        self.p.ring(cx, cy, radius, width, pal.hover, 1.0);
        // The toolkit's arc takes turns clockwise from twelve o'clock, not radians.
        let f = fraction.clamp(0.0, 1.0);
        if f > 0.0 {
            self.p.arc(cx, cy, radius, width, 0.0, f, c, 1.0);
        }
        let r = Rect::new(cx - radius, cy - radius, radius * 2.0, radius * 2.0);
        self.p
            .text_center(Face::Semibold, (radius * 0.62).max(10.0), r, text, pal.text);
    }

    /// A ring of several colours: each part's share of the ring is its share of the parts' sum.
    /// A small gap parts them, so that a contrast theme, where they may be one colour, still
    /// shows how many there are.
    pub fn donut(&mut self, cx: f32, cy: f32, radius: f32, width: f32, parts: &[(f32, Rgb)]) {
        let pal = self.pal;
        self.p.ring(cx, cy, radius, width, pal.hover, 1.0);
        let live: Vec<&(f32, Rgb)> = parts.iter().filter(|p| p.0 > 0.0).collect();
        let total: f32 = live.iter().map(|p| p.0).sum();
        if total <= 0.0 {
            return;
        }
        // In turns clockwise from twelve o'clock, as the toolkit's arc takes them. Its ends are
        // round and reach half the width past each end, so the gap is that and a little more.
        let gap = if live.len() > 1 && radius > 0.0 {
            (width / radius + 0.06) / std::f32::consts::TAU
        } else {
            0.0
        };
        let mut from = 0.0_f32;
        for (v, c) in live {
            let sweep = v / total;
            if sweep > gap * 1.5 {
                self.p.arc(
                    cx,
                    cy,
                    radius,
                    width,
                    from + gap / 2.0,
                    from + sweep - gap / 2.0,
                    *c,
                    1.0,
                );
            } else {
                // Too small a share for a part with gaps: a dot where its middle is.
                let mid = from + sweep / 2.0;
                self.p
                    .arc(cx, cy, radius, width, mid - 0.002, mid + 0.002, *c, 1.0);
            }
            from += sweep;
        }
    }

    /// The colours of the three ratings: safe, likely, protected.
    pub fn rating_inks(&self) -> [Rgb; 3] {
        [ok_ink(&self.pal), self.pal.warn, self.pal.muted]
    }
}

/// The focus scope of whatever is open over the page (the dialog, the palette, the sheet).
pub const SCOPE: Id = Id("Overlay", 0);
