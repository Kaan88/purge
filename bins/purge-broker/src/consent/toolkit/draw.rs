//! Measuring, laying out and drawing a [`Sheet`] with the toolkit's painter. Nothing here knows a
//! window: [`measure`] and [`draw`] take a painter (the window's, or one over a plain bitmap for the
//! preview's pictures and the tests), and [`Layout`] is pure arithmetic over what was measured.
//!
//! The window is the dialog: a title row with the close box, a band with the icon and the main
//! instruction, the list (the only part that scrolls), the verification box, and the foot with the
//! footer text and the two buttons. The box, the footer and the buttons never scroll out of view.
//!
//! Every word drawn is the sheet's, but two hints beside a disabled button ([`SCROLL_HINT`],
//! [`TICK_HINT`]). Text is wrapped, never cut: a line that does not fit its column breaks inside a
//! word (a path has no spaces), and the only elided text is the title row's, which is the same
//! fixed words on every dialog. The label of the button that approves is drawn whole, as the
//! TaskDialog shows it: the view builds it of fixed words and a count, never of a name, and the
//! tests here hold the longest it can build to the room the button has.

use std::ops::Range;
use std::time::Instant;

use mdshared_ui::check::{TICK, Tick, draw_tick};
use mdshared_ui::chrome::{self, WinButton, draw_win_button};
use mdshared_ui::focus::draw_ring;
use mdshared_ui::gfx::{Face, Painter, Rect, Wrap, mix};
use mdshared_ui::glyph;
use mdshared_ui::overlay::{dialog_button_w, draw_dialog_button, draw_dialog_button_disabled};
use mdshared_ui::scroll::{draw_scrollbar, scrollbar};

use super::super::sheet::{Block, Sheet};
use super::super::view::Icon;
use super::look::Look;
use super::state::{Ctl, Prompt};

/// The dialog's width, logical px.
pub const WIDTH: f32 = 620.0;
/// The least and the most it is tall; a longer list scrolls.
pub const MIN_HEIGHT: f32 = 260.0;
/// See [`MIN_HEIGHT`].
pub const MAX_HEIGHT: f32 = 760.0;
/// What one line of the list moves by a key.
pub const LINE: f32 = 40.0;

/// Beside the disabled button while the end of the list has not been on screen.
pub const SCROLL_HINT: &str = "Scroll to the end of the list to continue.";
/// Beside the disabled button while the box is not ticked.
pub const TICK_HINT: &str = "Tick the box to continue.";
/// The label of Cancel.
pub const CANCEL: &str = "Cancel";
/// What a screen reader calls the close box.
pub const CLOSE: &str = "Close";

/// The shield, on the 16 grid of the toolkit's glyphs (Purge.exe's own).
const SHIELD: &str = "M8 1.8l5.2 1.9v4c0 3.2-2.2 5.5-5.2 6.6-3-1.1-5.2-3.4-5.2-6.6v-4z";

const TITLE_H: f32 = chrome::TITLE_H;
const PAD: f32 = 24.0;
const BADGE: f32 = 40.0;
const BUTTON_H: f32 = 32.0;
const BODY_TOP: f32 = 16.0;
const BODY_BOTTOM: f32 = 12.0;

/// One line of the list as it was measured: where it starts in the list and how tall it is, its
/// gaps included.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Row {
    /// Its top, from the top of the list.
    pub top: f32,
    /// Its height with the gap under it.
    pub h: f32,
}

/// What [`measure`] found for one sheet at one width and scale.
#[derive(Debug, Clone, PartialEq)]
pub struct Metrics {
    /// The width it was measured for.
    pub width: f32,
    /// The painter's scale then.
    pub scale: f32,
    /// The band with the icon and the instruction.
    pub header_h: f32,
    /// Every line of the list.
    pub rows: Vec<Row>,
    /// The whole list, its padding included.
    pub content_h: f32,
    /// The verification row; 0 without a box.
    pub verify_h: f32,
    /// The foot: footer text and buttons.
    pub footer_h: f32,
    /// The footer text alone.
    pub footer_text_h: f32,
    /// The button that approves.
    pub approve_w: f32,
    /// Cancel.
    pub cancel_w: f32,
}

/// The column a block's text is wrapped in, its face and size, and the space above and below it.
fn block_style(block: &Block, inner: f32) -> (f32, Face, f32, f32, f32) {
    match block {
        Block::Summary(_) => (inner, Face::Ui, 13.0, 0.0, 8.0),
        Block::AttentionHeading(_) => (inner, Face::Semibold, 13.0, 8.0, 8.0),
        Block::Attention(_) => (inner - 27.0, Face::Ui, 13.0, 8.0, 14.0),
        Block::OthersHeading(_) => (inner, Face::Semibold, 13.0, 10.0, 6.0),
        Block::Other(_) | Block::More(_) => (inner - 12.0, Face::Ui, 12.0, 0.0, 6.0),
    }
}

/// Measures `sheet` for a dialog `width` wide. `scale` is the painter's, kept with the result so
/// that a caller knows when to measure again.
pub fn measure(p: &mut Painter, sheet: &Sheet, width: f32, scale: f32) -> Metrics {
    let inner = (width - 2.0 * PAD).max(1.0);
    let instruction = p.paragraph_height_wrapped(
        Face::Semibold,
        17.0,
        inner - BADGE - 14.0,
        &sheet.instruction,
        Wrap::Anywhere,
    );
    let header_h = 18.0 + instruction.max(BADGE) + 18.0;
    let mut rows = Vec::with_capacity(sheet.blocks.len());
    let mut top = BODY_TOP;
    for block in &sheet.blocks {
        let (w, face, size, above, below) = block_style(block, inner);
        let text = p.paragraph_height_wrapped(face, size, w, block.text(), Wrap::Anywhere);
        let h = above + text.max(size) + below;
        rows.push(Row { top, h });
        top += h;
    }
    let content_h = top + BODY_BOTTOM;
    let verify_h = sheet.verification.as_ref().map_or(0.0, |text| {
        p.paragraph_height_wrapped(Face::Ui, 13.0, inner - TICK - 10.0, text, Wrap::Anywhere)
            .max(TICK)
            + 24.0
    });
    let footer_text_h =
        p.paragraph_height_wrapped(Face::Ui, 12.0, inner, &sheet.footer, Wrap::Anywhere);
    let cancel_w = dialog_button_w(p, CANCEL);
    let approve_w = dialog_button_w(p, &sheet.approve).min((inner - cancel_w - 8.0).max(96.0));
    Metrics {
        width,
        scale,
        header_h,
        rows,
        content_h,
        verify_h,
        footer_h: 12.0 + footer_text_h + 12.0 + BUTTON_H + 16.0,
        footer_text_h,
        approve_w,
        cancel_w,
    }
}

impl Metrics {
    /// The height at which nothing scrolls.
    pub fn full_height(&self) -> f32 {
        TITLE_H + self.header_h + self.content_h + self.verify_h + self.footer_h
    }

    /// The height the window takes: everything when it fits under `most` (the work area's share,
    /// at most [`MAX_HEIGHT`]), never less than [`MIN_HEIGHT`].
    pub fn window_height(&self, most: f32) -> f32 {
        let most = if most.is_finite() { most } else { MAX_HEIGHT };
        self.full_height()
            .min(most.min(MAX_HEIGHT))
            .max(MIN_HEIGHT)
            .ceil()
    }
}

/// Where the pointer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// On a control.
    Ctl(Ctl),
    /// On the scroll bar's thumb.
    Thumb,
    /// On the scroll bar beside its thumb.
    Track,
    /// On the title row: the window is dragged by it.
    Title,
}

/// Where everything is in a window of one size, with the list at one offset. Logical px.
#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    /// The window.
    pub size: (f32, f32),
    /// The title row.
    pub title: Rect,
    /// The close box.
    pub close: Rect,
    /// The band with the instruction.
    pub header: Rect,
    /// The list's viewport.
    pub body: Rect,
    /// The verification row, when there is a box.
    pub verify: Option<Rect>,
    /// The foot.
    pub footer: Rect,
    /// The button that approves.
    pub approve: Rect,
    /// Cancel.
    pub cancel: Rect,
    /// The list's offset, kept inside what it can scroll.
    pub scroll: f32,
    /// The furthest offset; 0 when the list fits.
    pub max_scroll: f32,
    /// The scroll bar's track and thumb, when the list scrolls.
    pub bar: Option<(Rect, Rect)>,
    /// The lines of the list the viewport touches.
    pub visible: Range<usize>,
}

impl Layout {
    /// The layout of `m` in a `w` x `h` window with the list at `scroll`.
    pub fn new(m: &Metrics, size: (f32, f32), scroll: f32) -> Layout {
        let (w, h) = size;
        let title = Rect::new(0.0, 0.0, w, TITLE_H);
        let header = Rect::new(0.0, TITLE_H, w, m.header_h);
        let footer_y = (h - m.footer_h).max(header.bottom());
        let footer = Rect::new(0.0, footer_y, w, (h - footer_y).max(0.0));
        let verify_y = (footer_y - m.verify_h).max(header.bottom());
        let verify = (m.verify_h > 0.0).then(|| Rect::new(0.0, verify_y, w, footer_y - verify_y));
        let body = Rect::new(
            0.0,
            header.bottom(),
            w,
            (verify_y - header.bottom()).max(0.0),
        );
        let max_scroll = (m.content_h - body.h).max(0.0);
        let scroll = if scroll.is_finite() {
            scroll.clamp(0.0, max_scroll)
        } else {
            0.0
        };
        let buttons_y = h - 16.0 - BUTTON_H;
        let cancel = Rect::new(w - PAD - m.cancel_w, buttons_y, m.cancel_w, BUTTON_H);
        let approve = Rect::new(
            cancel.x - 8.0 - m.approve_w,
            buttons_y,
            m.approve_w,
            BUTTON_H,
        );
        let first = m.rows.partition_point(|r| r.top + r.h <= scroll);
        let end = m.rows.partition_point(|r| r.top < scroll + body.h);
        Layout {
            size,
            title,
            close: chrome::win_button_rect(w, 0),
            header,
            body,
            verify,
            footer,
            approve,
            cancel,
            scroll,
            max_scroll,
            bar: scrollbar(body, m.content_h, body.h, scroll),
            visible: first..end.max(first),
        }
    }

    /// Whether the end of the list is in the viewport.
    pub fn end_in_view(&self) -> bool {
        self.body.h > 0.0 && self.scroll >= self.max_scroll - 1.0
    }

    /// Line `i` of the list on screen, not cut to the viewport.
    pub fn row(&self, m: &Metrics, i: usize) -> Rect {
        let r = m.rows[i];
        Rect::new(
            PAD,
            self.body.y + r.top - self.scroll,
            self.size.0 - 2.0 * PAD,
            r.h,
        )
    }

    /// The part of line `i` in the viewport, or `None` when none of it is.
    pub fn row_in_view(&self, m: &Metrics, i: usize) -> Option<Rect> {
        let r = self.row(m, i);
        let (y0, y1) = (r.y.max(self.body.y), r.bottom().min(self.body.bottom()));
        (y1 > y0).then(|| Rect::new(r.x, y0, r.w, y1 - y0))
    }

    /// Where the box takes a click: the tick and its label.
    pub fn verify_hit(&self) -> Option<Rect> {
        self.verify
            .map(|v| Rect::new(PAD - 6.0, v.y + 4.0, v.w - 2.0 * PAD + 12.0, v.h - 8.0))
    }

    /// The tick itself.
    pub fn tick(&self) -> Option<Rect> {
        self.verify
            .map(|v| Rect::new(PAD, v.y + 12.0 + 1.0, TICK, TICK))
    }

    /// What is at `(x, y)`.
    pub fn hit(&self, x: f32, y: f32) -> Option<Hit> {
        if self.close.contains(x, y) {
            return Some(Hit::Ctl(Ctl::Close));
        }
        if self.title.contains(x, y) {
            return Some(Hit::Title);
        }
        if self.cancel.contains(x, y) {
            return Some(Hit::Ctl(Ctl::Cancel));
        }
        if self.approve.contains(x, y) {
            return Some(Hit::Ctl(Ctl::Approve));
        }
        if self.verify_hit().is_some_and(|r| r.contains(x, y)) {
            return Some(Hit::Ctl(Ctl::Verify));
        }
        if let Some((track, thumb)) = self.bar {
            if thumb.contains(x, y) {
                return Some(Hit::Thumb);
            }
            if track.contains(x, y) {
                return Some(Hit::Track);
            }
        }
        None
    }

    /// The rectangle of a control.
    pub fn ctl(&self, ctl: Ctl) -> Option<Rect> {
        match ctl {
            Ctl::Verify => self.verify_hit(),
            Ctl::Approve => Some(self.approve),
            Ctl::Cancel => Some(self.cancel),
            Ctl::Close => Some(self.close),
        }
    }
}

/// What a frame shows beyond the prompt's own state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Frame {
    /// The time of the frame: whether the button is enabled is asked with it.
    pub now: Instant,
    /// What the pointer is over.
    pub hover: Option<Hit>,
    /// What a held press started on.
    pub pressed: Option<Hit>,
}

/// Restricts drawing to `r` within the clip there already is; returns that one for
/// `Painter::restore` (`Painter::clip` alone replaces the clip).
fn clip_within(p: &mut Painter, r: Rect) -> (i32, i32, i32, i32) {
    let old = p.clip(r);
    let new = p.clip(r);
    p.restore((
        new.0.max(old.0),
        new.1.max(old.1),
        new.2.min(old.2),
        new.3.min(old.3),
    ));
    old
}

fn draw_row(p: &mut Painter, look: &Look, block: &Block, r: Rect) {
    let pal = &look.pal;
    let inner = r.w;
    let (w, face, size, above, _) = block_style(block, inner);
    let y = r.y + above;
    match block {
        Block::Summary(text) => {
            p.paragraph_wrapped(face, size, r.x, y, w, text, pal.text, Wrap::Anywhere);
        }
        Block::AttentionHeading(text) => {
            p.paragraph_wrapped(face, size, r.x, y, w, text, pal.text, Wrap::Anywhere);
        }
        Block::Attention(text) => {
            // A card of its own, with a bar of the warning colour on its left.
            let card = Rect::new(r.x, r.y, r.w, r.h - 6.0);
            if look.contrast {
                p.frame(card, 6.0, pal.popup, pal.text);
            } else {
                p.rbox(card, 6.0, mix(pal.popup, pal.warn, 0.10));
                let old = clip_within(p, Rect::new(card.x, card.y, 3.0, card.h));
                p.rbox(card, 6.0, pal.warn);
                p.restore(old);
            }
            p.paragraph_wrapped(face, size, r.x + 15.0, y, w, text, pal.text, Wrap::Anywhere);
        }
        Block::OthersHeading(text) => {
            p.paragraph_wrapped(face, size, r.x, y, w, text, pal.muted, Wrap::Anywhere);
        }
        Block::Other(text) | Block::More(text) => {
            p.paragraph_wrapped(
                face,
                size,
                r.x + 12.0,
                y,
                w,
                text,
                pal.muted,
                Wrap::Anywhere,
            );
        }
    }
}

/// The hint beside the disabled button, if any.
pub fn hint(prompt: &Prompt, now: Instant) -> Option<&'static str> {
    if prompt.approve_enabled(now) || !prompt.armed(now) {
        None
    } else if !prompt.seen_end() {
        Some(SCROLL_HINT)
    } else if prompt.sheet().verification.is_some() && !prompt.ticked() {
        Some(TICK_HINT)
    } else {
        None
    }
}

/// Draws the whole dialog: every pixel of the window.
pub fn draw(
    p: &mut Painter,
    look: &Look,
    prompt: &Prompt,
    m: &Metrics,
    lay: &Layout,
    frame: &Frame,
) {
    let pal = &look.pal;
    let sheet = prompt.sheet();
    let (w, h) = lay.size;
    let px = p.px();
    // Shown whether or not the window has the keyboard: the default must be seen on a dialog that
    // opened behind another window too.
    let ring = |ctl: Ctl| prompt.ring() && prompt.focus() == ctl;
    let hot = |ctl: Ctl| frame.hover == Some(Hit::Ctl(ctl));
    let down = |ctl: Ctl| frame.pressed == Some(Hit::Ctl(ctl));
    p.fill(Rect::new(0.0, 0.0, w, h), pal.popup);

    // The list first: what it draws outside its viewport is cut, and the parts around it are
    // drawn over nothing of it.
    let old = clip_within(p, lay.body);
    for i in lay.visible.clone() {
        draw_row(p, look, &sheet.blocks[i], lay.row(m, i));
    }
    p.restore(old);
    if let Some((track, thumb)) = lay.bar {
        let active = matches!(frame.hover, Some(Hit::Thumb | Hit::Track))
            || frame.pressed == Some(Hit::Thumb);
        draw_scrollbar(p, pal, track, thumb, active);
    }

    // The title row.
    p.fill(lay.title, pal.title);
    let title = p.elide(
        Face::Ui,
        12.0,
        &sheet.title,
        w - PAD - chrome::WIN_BTN_W - 8.0,
    );
    p.text(Face::Ui, 12.0, PAD, lay.title.cy(), &title, pal.muted, w);
    draw_win_button(
        p,
        pal,
        WinButton::Close,
        lay.close,
        false,
        hot(Ctl::Close),
        down(Ctl::Close),
    );

    // The band: the icon and the instruction.
    let band = if look.contrast {
        pal.popup
    } else {
        mix(pal.popup, pal.accent, 0.09)
    };
    p.fill(lay.header, band);
    p.fill(
        Rect::new(0.0, lay.header.bottom() - px, w, px),
        if look.contrast || lay.scroll > 0.0 {
            pal.popup_line
        } else {
            band
        },
    );
    let badge = Rect::new(PAD, lay.header.y + 18.0, BADGE, BADGE);
    let (badge_fill, badge_ink, glyph) = match sheet.icon {
        Icon::Shield => (pal.accent, pal.on_accent, SHIELD),
        Icon::Warning => {
            let (fill, ink) = look.danger();
            (fill, ink, glyph::WARN)
        }
    };
    p.rbox(badge, BADGE / 2.0, badge_fill);
    p.icon(glyph, 20.0, badge.cx(), badge.cy(), badge_ink);
    let text_x = PAD + BADGE + 14.0;
    let text_w = w - PAD - text_x;
    let text_h = p.paragraph_height_wrapped(
        Face::Semibold,
        17.0,
        text_w,
        &sheet.instruction,
        Wrap::Anywhere,
    );
    p.paragraph_wrapped(
        Face::Semibold,
        17.0,
        text_x,
        lay.header.y + 18.0 + ((BADGE - text_h) / 2.0).max(0.0),
        text_w,
        &sheet.instruction,
        pal.text,
        Wrap::Anywhere,
    );

    // The verification box.
    if let (Some(row), Some(tick), Some(text)) = (lay.verify, lay.tick(), &sheet.verification) {
        p.fill(Rect::new(0.0, row.y, w, px), pal.popup_line);
        // Off until the end of the list has been on screen (review S6).
        let mut state = if prompt.verify_enabled() {
            Tick::new(prompt.ticked())
        } else {
            Tick::disabled(prompt.ticked())
        };
        if ring(Ctl::Verify) {
            state = state.with_focus();
            draw_ring(p, pal, tick, 4.0);
        }
        draw_tick(p, pal, tick, state);
        p.paragraph_wrapped(
            Face::Ui,
            13.0,
            PAD + TICK + 10.0,
            row.y + 12.0,
            w - 2.0 * PAD - TICK - 10.0,
            text,
            pal.text,
            Wrap::Anywhere,
        );
    }

    // The foot: the footer text, then the hint and the buttons.
    let foot = if look.contrast {
        pal.popup
    } else {
        mix(
            pal.popup,
            if pal.dark { [0, 0, 0] } else { pal.bar },
            if pal.dark { 0.22 } else { 0.7 },
        )
    };
    p.fill(lay.footer, foot);
    p.fill(Rect::new(0.0, lay.footer.y, w, px), pal.popup_line);
    p.paragraph_wrapped(
        Face::Ui,
        12.0,
        PAD,
        lay.footer.y + 12.0,
        w - 2.0 * PAD,
        &sheet.footer,
        pal.muted,
        Wrap::Anywhere,
    );
    if let Some(text) = hint(prompt, frame.now) {
        let room = lay.approve.x - PAD - 12.0;
        let text = p.elide(Face::Ui, 12.0, text, room);
        p.text(
            Face::Ui,
            12.0,
            PAD,
            lay.approve.cy(),
            &text,
            pal.muted,
            room,
        );
    }
    // Whole, never elided: what the button does is not cut short.
    let label = sheet.approve.as_str();
    if !prompt.approve_enabled(frame.now) {
        draw_dialog_button_disabled(p, pal, lay.approve, label, true);
    } else if sheet.icon == Icon::Warning && !look.contrast {
        let (fill, ink) = look.danger();
        let (hovered, pressed) = (hot(Ctl::Approve), down(Ctl::Approve) && hot(Ctl::Approve));
        let fill = if pressed {
            mix(fill, pal.popup, 0.2)
        } else if hovered {
            mix(fill, pal.popup, 0.1)
        } else {
            fill
        };
        p.rbox(lay.approve, 5.0, fill);
        p.text_center(Face::Semibold, 13.0, lay.approve, label, ink);
    } else {
        draw_dialog_button(
            p,
            pal,
            lay.approve,
            label,
            true,
            hot(Ctl::Approve),
            down(Ctl::Approve),
        );
    }
    if ring(Ctl::Approve) {
        draw_ring(p, pal, lay.approve, 5.0);
    }
    draw_dialog_button(
        p,
        pal,
        lay.cancel,
        CANCEL,
        false,
        hot(Ctl::Cancel),
        down(Ctl::Cancel),
    );
    if ring(Ctl::Cancel) {
        draw_ring(p, pal, lay.cancel, 5.0);
    }
    if look.contrast {
        // No shadow tells a contrast theme's window from what is behind it: an edge does.
        for edge in [
            Rect::new(0.0, 0.0, w, px),
            Rect::new(0.0, h - px, w, px),
            Rect::new(0.0, 0.0, px, h),
            Rect::new(w - px, 0.0, px, h),
        ] {
            p.fill(edge, pal.popup_line);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use mdshared_ui::gfx::Gfx;
    use mdshared_ui::host::access_rect;

    use super::super::super::samples;
    use super::super::super::sheet::sheet;
    use super::super::state::ARM_DELAY;
    use super::*;

    fn metrics(rows: usize, verify: bool) -> Metrics {
        let mut top = BODY_TOP;
        let rows: Vec<Row> = (0..rows)
            .map(|_| {
                let r = Row { top, h: 30.0 };
                top += 30.0;
                r
            })
            .collect();
        Metrics {
            width: WIDTH,
            scale: 1.0,
            header_h: 76.0,
            rows,
            content_h: top + BODY_BOTTOM,
            verify_h: if verify { 40.0 } else { 0.0 },
            footer_h: 88.0,
            footer_text_h: 16.0,
            approve_w: 220.0,
            cancel_w: 96.0,
        }
    }

    #[test]
    fn a_short_list_fits_and_its_end_is_in_view_at_once() {
        let m = metrics(3, true);
        let h = m.window_height(900.0);
        assert_eq!(h, m.full_height().ceil());
        let lay = Layout::new(&m, (WIDTH, h), 0.0);
        assert_eq!(lay.max_scroll, 0.0);
        assert!(lay.end_in_view());
        assert!(lay.bar.is_none());
        assert_eq!(lay.visible, 0..3);
        // The parts stack without a gap or an overlap, and the buttons are inside the foot.
        assert_eq!(lay.header.y, lay.title.bottom());
        assert_eq!(lay.body.y, lay.header.bottom());
        let verify = lay.verify.unwrap();
        assert_eq!(verify.y, lay.body.bottom());
        assert_eq!(lay.footer.y, verify.bottom());
        assert_eq!(lay.footer.bottom(), h);
        for b in [lay.approve, lay.cancel] {
            assert!(b.y > lay.footer.y && b.bottom() < h, "{b:?}");
            assert!(b.x >= PAD && b.right() <= WIDTH - PAD + 0.5, "{b:?}");
        }
        assert!(
            lay.approve.right() < lay.cancel.x,
            "approve is left of Cancel"
        );
    }

    #[test]
    fn a_long_list_scrolls_and_its_end_comes_into_view_only_at_the_end() {
        let m = metrics(500, false);
        let h = m.window_height(2000.0);
        assert_eq!(h, MAX_HEIGHT);
        let top = Layout::new(&m, (WIDTH, h), 0.0);
        assert!(top.max_scroll > 10_000.0);
        assert!(!top.end_in_view());
        assert!(top.bar.is_some());
        assert_eq!(top.visible.start, 0);
        assert!(top.visible.end < 30);
        let nearly = Layout::new(&m, (WIDTH, h), top.max_scroll - 2.0);
        assert!(!nearly.end_in_view());
        let end = Layout::new(&m, (WIDTH, h), f32::MAX);
        assert_eq!(end.scroll, end.max_scroll);
        assert!(end.end_in_view());
        assert_eq!(end.visible.end, 500);
        // Every visible row touches the viewport, and the rows before and after do not.
        for lay in [&top, &nearly, &end] {
            for i in 0..500 {
                assert_eq!(
                    lay.row_in_view(&m, i).is_some(),
                    lay.visible.contains(&i),
                    "row {i} at {}",
                    lay.scroll
                );
            }
        }
        // A scroll that is not a number is the top.
        assert_eq!(Layout::new(&m, (WIDTH, h), f32::NAN).scroll, 0.0);
        assert_eq!(Layout::new(&m, (WIDTH, h), -50.0).scroll, 0.0);
    }

    #[test]
    fn a_window_too_small_keeps_the_buttons_and_gives_the_list_what_is_left() {
        let m = metrics(50, true);
        let lay = Layout::new(&m, (WIDTH, 150.0), 0.0);
        assert!(lay.body.h >= 0.0);
        assert!(lay.footer.h >= 0.0);
        assert!(!lay.end_in_view() || lay.body.h > 0.0);
        assert_eq!(m.window_height(100.0), MIN_HEIGHT);
        assert_eq!(m.window_height(f32::NAN), MAX_HEIGHT);
    }

    #[test]
    fn hits_name_the_control_under_the_pointer() {
        let m = metrics(500, true);
        let lay = Layout::new(&m, (WIDTH, MAX_HEIGHT), 0.0);
        let mid = |r: Rect| (r.cx(), r.cy());
        let at = |(x, y)| lay.hit(x, y);
        assert_eq!(at(mid(lay.cancel)), Some(Hit::Ctl(Ctl::Cancel)));
        assert_eq!(at(mid(lay.approve)), Some(Hit::Ctl(Ctl::Approve)));
        assert_eq!(at(mid(lay.close)), Some(Hit::Ctl(Ctl::Close)));
        assert_eq!(at(mid(lay.tick().unwrap())), Some(Hit::Ctl(Ctl::Verify)));
        assert_eq!(at((100.0, 10.0)), Some(Hit::Title));
        let (track, thumb) = lay.bar.unwrap();
        assert_eq!(at(mid(thumb)), Some(Hit::Thumb));
        assert_eq!(at((track.cx(), track.bottom() - 4.0)), Some(Hit::Track));
        assert_eq!(at(mid(lay.body)), None);
        // Between the two buttons is neither.
        assert_eq!(at((lay.approve.right() + 4.0, lay.approve.cy())), None);
    }

    /// Every sample, in light, dark and both contrast palettes, measured and drawn with the real
    /// painter into a bitmap: the layout holds for real text, and the frame is not blank.
    #[test]
    fn every_sample_measures_and_draws() {
        let fonts = super::super::fonts::system().unwrap();
        let mut gfx = Gfx::with_fonts(&fonts);
        for s in samples::all() {
            // As the window gets it: what the fonts cannot draw written out (TK-1).
            let sh = Arc::new(super::super::fonts::sheet_for(&fonts, &sheet(&s.view)).unwrap());
            for (dark, contrast) in [(false, false), (true, false), (false, true), (true, true)] {
                let look = Look::of(dark, contrast);
                let mut scratch = mdshared_text::Bitmap::new(1, 1);
                let m = measure(
                    &mut Painter::new(&mut scratch, &mut gfx, 1.0),
                    &sh,
                    WIDTH,
                    1.0,
                );
                assert_eq!(m.rows.len(), sh.blocks.len(), "{}", s.name);
                assert!(m.rows.windows(2).all(|w| w[0].top + w[0].h == w[1].top));
                let h = m.window_height(MAX_HEIGHT);
                let mut prompt = Prompt::new(sh.clone());
                let t0 = Instant::now();
                prompt.opened(t0);
                let lay = Layout::new(&m, (WIDTH, h), 0.0);
                if lay.end_in_view() {
                    prompt.saw_end(t0);
                }
                // The label of the button is drawn whole: it has the room it asks for.
                assert_eq!(
                    m.approve_w,
                    dialog_button_w(&mut Painter::new(&mut scratch, &mut gfx, 1.0), &sh.approve),
                    "{}: {:?} fits its button",
                    s.name,
                    sh.approve
                );
                assert_eq!(
                    lay.end_in_view(),
                    m.full_height() <= MAX_HEIGHT + 1.0,
                    "{}",
                    s.name
                );
                assert!(lay.body.h >= 40.0, "{}: the list has room", s.name);
                let mut bmp = mdshared_text::Bitmap::new(WIDTH as u32, h as u32);
                let frame = Frame {
                    now: t0 + ARM_DELAY + Duration::from_millis(1),
                    hover: None,
                    pressed: None,
                };
                draw(
                    &mut Painter::new(&mut bmp, &mut gfx, 1.0),
                    &look,
                    &prompt,
                    &m,
                    &lay,
                    &frame,
                );
                let first = [bmp.pixels[0], bmp.pixels[1], bmp.pixels[2]];
                let varied = bmp
                    .pixels
                    .chunks_exact(4)
                    .filter(|px| px[..3] != first)
                    .count();
                assert!(varied > 2_000, "{}: {varied} px drawn", s.name);
            }
        }
        // The bounds a reader is given are device px of the same rectangles.
        let r = access_rect(Rect::new(10.0, 20.0, 30.0, 40.0), 1.5);
        assert_eq!((r.x0, r.y1), (15.0, 90.0));
    }

    #[test]
    fn the_hint_says_why_the_button_is_off() {
        let all = samples::all();
        let long = all.iter().find(|s| s.name == "quarantine-long").unwrap();
        let mut p = Prompt::new(Arc::new(sheet(&long.view)));
        let t0 = Instant::now();
        assert_eq!(hint(&p, t0), None, "not on screen yet");
        p.opened(t0);
        assert_eq!(hint(&p, t0), None, "the first second needs no words");
        let now = t0 + ARM_DELAY;
        assert_eq!(hint(&p, now), Some(SCROLL_HINT));
        p.saw_end(now);
        assert_eq!(hint(&p, now), Some(TICK_HINT));
        p.press(Ctl::Verify, now);
        // Ticked: the button is still off for the delay of the end, which needs no words.
        assert_eq!(hint(&p, now), None);
        assert!(!p.approve_enabled(now));
        assert!(p.approve_enabled(now + ARM_DELAY));
        assert_eq!(hint(&p, now + ARM_DELAY), None);
    }

    /// The label of the button that approves is never elided, so the longest one the view can
    /// build must fit: fixed words and a count of at most ten digits (`view`'s `items`). This one
    /// is longer than any of them.
    #[test]
    fn the_longest_label_fits_the_button() {
        let mut gfx = Gfx::with_fonts(&super::super::fonts::system().unwrap());
        let all = samples::all();
        let mut sh = sheet(&all[0].view);
        sh.approve = "Delete 4,294,967,295 registry backups now, for good".to_owned();
        for scale in [1.0, 1.25, 1.5, 2.0, 3.0] {
            let mut scratch = mdshared_text::Bitmap::new(1, 1);
            let mut p = Painter::new(&mut scratch, &mut gfx, scale);
            let m = measure(&mut p, &sh, WIDTH, scale);
            assert_eq!(m.approve_w, dialog_button_w(&mut p, &sh.approve), "{scale}");
            let lay = Layout::new(&m, (WIDTH, MIN_HEIGHT), 0.0);
            assert!(lay.approve.x >= PAD, "{scale}");
        }
    }
}
