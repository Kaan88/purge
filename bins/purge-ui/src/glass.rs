//! UI-FULLFROST: the backdrop behind the whole window, and how strongly it shows.
//!
//! The toolkit's frost (`mdshared_ui::frost`) lets Mica or Acrylic through the chrome: the app
//! marks the chrome's pixels (alpha byte [`frost::MARK`]) and the host keys them out as it
//! presents, with a veil fixed by the backdrop (none for Mica, 150 of 255 for Acrylic). Two
//! things here go further, without changing the toolkit:
//!
//! - **What it covers** ([`Covers`]). "Title and rail" is the toolkit's look. "Whole window"
//!   also marks the content card, and the page's surfaces drawn on it become a second layer:
//!   after the page is laid, every opaque pixel of the content (cards, lists, the details pane,
//!   rows, buttons) is re-marked [`LAYER`] ([`raise`]); the page's own ground, its text and
//!   what is blended onto it keep [`frost::MARK`]. Whatever is drawn after that (the rail's
//!   cards, dialogs, menus, the palette, toasts) is opaque, as it always was.
//! - **How much shows** ([`veils`]). The app keys the marked pixels itself, at the end of each
//!   frame ([`Glass::end`]), with the toolkit's own [`Key`] and a veil of the user's strength:
//!   the ground and the chrome let `keep` of the backdrop through, the layer half of that. No
//!   pixel is left with the toolkit's mark, so the host's own keying finds nothing to do.
//!
//! Keying in place changes the bitmap. A frame fills every pixel it draws over before it blends
//! anything there, so drawing never reads the keyed pixels; a page switch does, when it takes
//! its picture of the old page at its start. So the frame as drawn (flat colours and marks) is
//! kept aside where it is keyed ([`areas`]: the title row and the rail, or the whole
//! window), and put back under a switch just before it takes its picture
//! ([`Glass::restore`]). The switch's blend keeps the marks (`transition::mix`): the old
//! page's ground stays glass, and the new page's surfaces never let the old page through.
//!
//! **The clamp.** A strength of 100 % is the most backdrop that keeps text readable over the
//! worst backdrop: body text ([`Palette::text`]) at 4.5 : 1 (WCAG AA) and secondary text
//! ([`Palette::muted`]) at 3 : 1, over every glass ground text is drawn on ([`grounds`]: the
//! chrome, the page, and Bold's tints of the accent in the rail and the title band), with the
//! backdrop anywhere
//! between [`WORST_DARK`] or [`WORST_LIGHT`]. Those are what Acrylic itself measured over a pure
//! black and a pure white window (dark: 53 to 144; light: 135 to 227, grey levels), widened by
//! about 15 levels; Mica's tinted wallpaper stays well inside them. In dark the clamp lets 40 to
//! 47 % of the backdrop through (a veil of at least 134 to 153 of 255, about Acrylic's own 150),
//! and in Bold over the whole window 24 to 47 % (its title band is a tint of the accent); in
//! light 87 to 93 % (a veil of at least 17 to 33), by preset. [`keep_max`] finds the
//! largest share of the backdrop that passes, for the palette in use (every preset, the
//! Windows accent); the slider's 0 to 100 % spans 0 to that.
//!
//! Deliberately not here: a veil per backdrop (the slider is one setting for Mica and
//! Acrylic), a blur of our own, and frosting anything drawn over the page.

use mdshared_app::settings::Writer;
use mdshared_ui::cover::contrast;
use mdshared_ui::frost::{self, Key, MARK};
use mdshared_ui::gfx::{Painter, Rect, Rgb, mix};
use mdshared_ui::theme::Palette;

use crate::look::{Choice, Covers, Design};

/// The strength a new settings file starts with, picked from real captures over a busy desktop:
/// the backdrop reads clearly in dark and light, and the page's cards stay apart from its ground.
pub const STRENGTH_DEFAULT: u8 = 50;

/// A key's step on the slider, in percent.
pub const STEP: f32 = 5.0;

/// The alpha byte of a page surface ("Whole window"): keyed with the layer's veil.
pub const LAYER: u8 = 253;

/// Of the backdrop the ground lets through, the share a page surface lets through.
pub const LAYER_SHARE: f32 = 0.5;

/// The darkest and lightest the backdrop can be behind a dark window, grey levels (Acrylic over
/// black and white measured 53 and 144).
pub const WORST_DARK: (u8, u8) = (38, 160);
/// The same behind a light window (measured 135 and 227).
pub const WORST_LIGHT: (u8, u8) = (120, 242);

/// Body text's least contrast over the backdrop, and secondary text's.
pub const TEXT_CONTRAST: f32 = 4.5;
/// Secondary text is 12 to 13 px, so WCAG AA would want 4.5 : 1 of it too. It is kept at 3 : 1
/// on purpose (alpha.4 review, N3): measured with 4.5 : 1, the clamp lets only 7 to 16 % of the
/// backdrop through in dark (40 to 47 % at 3 : 1), and in Bold over the whole window nothing at
/// all for some presets, where the title band's tint gives muted text 4.1 : 1 even opaque. The
/// slider would have no range left. Raising it means darker or lighter muted colours in the
/// palettes first, not a tighter clamp.
pub const MUTED_CONTRAST: f32 = 3.0;
/// An icon's least contrast over the backdrop, where no text is drawn (WCAG 1.4.11, non-text).
pub const ICON_CONTRAST: f32 = 3.0;

// ---- the settings ----------------------------------------------------------------------------

/// The two settings, kept in the settings file as `backdrop_covers` and `backdrop_strength`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GlassPrefs {
    pub covers: Covers,
    /// 0 to 100: of the most backdrop that keeps text readable, how much shows.
    pub strength: u8,
}

impl Default for GlassPrefs {
    fn default() -> GlassPrefs {
        GlassPrefs {
            covers: Covers::Chrome,
            strength: STRENGTH_DEFAULT,
        }
    }
}

impl GlassPrefs {
    /// Reads one line of the settings file; false when the key is not one of these.
    pub fn read(&mut self, key: &str, value: &str) -> bool {
        match key {
            "backdrop_covers" => self.covers = Covers::parse(value).unwrap_or(self.covers),
            "backdrop_strength" => self.strength = parse_strength(value).unwrap_or(self.strength),
            _ => return false,
        }
        true
    }

    pub fn write(&self, w: &mut Writer) {
        w.line("backdrop_covers", self.covers.name());
        w.line("backdrop_strength", &self.strength.to_string());
    }
}

/// A strength as the settings file or the command line give it: a whole number, kept to 100.
pub fn parse_strength(s: &str) -> Option<u8> {
    let n: u32 = s.trim().trim_end_matches('%').parse().ok()?;
    Some(n.min(100) as u8)
}

// ---- the veils -------------------------------------------------------------------------------

/// The colour that counts as "nothing drawn". Over the chrome only, the toolkit's own; over the
/// whole window, the page's ground and cards count too: in dark the darkest of them, in light
/// the lightest (light cards are white), so every surface is a faint lightening or darkening
/// of the glass.
pub fn key_colour(pal: &Palette, covers: Covers) -> Rgb {
    if covers == Covers::Chrome {
        return frost::key_colour(pal);
    }
    let sum = |c: &Rgb| c.iter().map(|&v| v as u32).sum::<u32>();
    let all = [pal.title, pal.bar, pal.pane, pal.page, pal.field];
    let pick = if pal.dark {
        all[..4].iter().min_by_key(|c| sum(c))
    } else {
        all.iter().max_by_key(|c| sum(c))
    };
    *pick.unwrap_or(&pal.page)
}

/// The pixel `px` (premultiplied `0xAARRGGBB`, as [`Key::apply`] gives it) over a grey
/// backdrop `d`.
fn over(px: u32, d: u8) -> Rgb {
    let a = px >> 24;
    let keep = 255 - a;
    let ch = |s: u32| ((px >> s) & 0xff) + (keep * d as u32 + 127) / 255;
    [
        ch(16).min(255) as u8,
        ch(8).min(255) as u8,
        ch(0).min(255) as u8,
    ]
}

fn pack(c: Rgb) -> u32 {
    ((MARK as u32) << 24) | ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32
}

/// The veil (0 to 255) that lets `keep` (0 to 1) of the backdrop through a pixel of the key.
fn veil_of(keep: f32) -> u8 {
    255 - (keep.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// D3 (Bold): the accent's share in the rail's gradient over a backdrop, at its top and its
/// bottom (`screens::chrome`). It is glass, and the rail's text is drawn over it.
pub const RAIL_TINT: (f32, f32) = (0.30, 0.08);

/// D3: the accent's share at the top of the band behind a page's title (`screens::page`); the
/// band fades to the page. Over the whole window it is glass, and the title is drawn over it.
pub fn hero_tint(dark: bool) -> f32 {
    if dark { 0.20 } else { 0.13 }
}

/// A ground marked as glass, and what is drawn on it: text (body and secondary), or only icons
/// in body text's colour.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Ground {
    colour: Rgb,
    /// Text is drawn on it: body text needs [`TEXT_CONTRAST`] and secondary text
    /// [`MUTED_CONTRAST`]. Otherwise only icons are, which need [`ICON_CONTRAST`] (WCAG 1.4.11).
    text: bool,
}

/// The glass grounds of `design` with `covers`: the title row, the key colour, the page ("Whole
/// window"), and Bold's two tints of the accent: the rail's gradient (sampled along it) and the
/// band behind a page's title.
///
/// Bold's rail carries only its icons, in body text's colour (`screens::chrome`; the selected
/// one is on its accent pill, a badge's count on its own accent disc): no text is drawn on it.
/// (Secondary text could not be: the rail's top is too strong a tint for it even opaque,
/// 2.5 : 1 in some dark presets.) The title band carries the page's title and, beside it, its
/// secondary line.
/// How many steps [`grounds`] takes along each of Bold's gradients.
const GRADIENT_STEPS: usize = 16;

fn grounds(pal: &Palette, covers: Covers, design: Design) -> Vec<Ground> {
    let both = |colour| Ground { colour, text: true };
    let mut out = vec![both(pal.title), both(key_colour(pal, covers))];
    if covers == Covers::Window {
        out.push(both(pal.page));
    }
    if design == Design::Bold {
        // The gradient is a line through the colours; its luminance need not change one way
        // along it (the accent's channels move apart), so it is sampled, ends included (review
        // N8: finer than the 5 and 3 points it was; the clamp's margin covers what lies between,
        // and a test samples at 64).
        let (top, bottom) = RAIL_TINT;
        for i in 0..=GRADIENT_STEPS {
            let t = top + (bottom - top) * i as f32 / GRADIENT_STEPS as f32;
            out.push(Ground {
                colour: mix(pal.title, pal.accent, t),
                text: false,
            });
        }
        if covers == Covers::Window {
            let from = hero_tint(pal.dark);
            for i in 0..=GRADIENT_STEPS {
                let t = from * i as f32 / GRADIENT_STEPS as f32;
                out.push(both(mix(pal.page, pal.accent, t)));
            }
        }
    }
    out
}

/// The least contrast over the glass grounds of `design` ([`grounds`]), at `keep`, over the
/// worst backdrop, each as a share of what it needs: body text's, secondary text's and icons'.
/// 1 or more passes.
fn worst_share(pal: &Palette, covers: Covers, design: Design, keep: f32) -> f32 {
    let (text, muted, icons) = worst_contrast(pal, covers, design, keep);
    (text / TEXT_CONTRAST)
        .min(muted / MUTED_CONTRAST)
        .min(icons / ICON_CONTRAST)
}

/// The least contrast over the glass grounds of `design` ([`grounds`]), at `keep`, over the
/// worst backdrop: body text's and secondary text's where text is drawn, and icons' (body
/// text's colour) where only icons are.
pub fn worst_contrast(pal: &Palette, covers: Covers, design: Design, keep: f32) -> (f32, f32, f32) {
    let k = key_colour(pal, covers);
    let key = Key::new(k, veil_of(keep));
    let (lo, hi) = if pal.dark { WORST_DARK } else { WORST_LIGHT };
    let grounds = grounds(pal, covers, design);
    let (mut text, mut muted, mut icons) = (f32::MAX, f32::MAX, f32::MAX);
    for d in [lo, hi] {
        for g in &grounds {
            let ground = over(key.apply(pack(g.colour)), d);
            let ink = contrast(over(key.apply(pack(pal.text)), d), ground);
            if g.text {
                text = text.min(ink);
                muted = muted.min(contrast(over(key.apply(pack(pal.muted)), d), ground));
            } else {
                icons = icons.min(ink);
            }
        }
    }
    (text, muted, icons)
}

/// What the clamp keeps in hand over each limit, as a share of it: what a gradient's colours
/// between its samples may lose (`the_gradients_read_between_the_clamps_samples`).
const CLAMP_MARGIN: f32 = 0.01;

/// The clamp: the largest share of the backdrop (0 to 1) whose text still reads over the
/// worst backdrop ([`TEXT_CONTRAST`], [`MUTED_CONTRAST`]).
pub fn keep_max(pal: &Palette, covers: Covers, design: Design) -> f32 {
    // The contrast need not fall evenly as the veil thins (a tint keeps more of itself than the
    // key does), so every whole step of the veil is tried from opaque on, and the clamp is the
    // last before the first that fails: every veil the slider can give is one that passed.
    //
    // The gradients are sampled ([`grounds`]) and each sample is rounded to whole channels, so
    // a colour between two samples can read a hair worse than both (review N8: 2.996 : 1
    // where 3 is needed). The clamp keeps [`CLAMP_MARGIN`] in hand for it.
    let mut good = 0u8;
    for clear in 1..=255u8 {
        if worst_share(pal, covers, design, clear as f32 / 255.0) < 1.0 + CLAMP_MARGIN {
            break;
        }
        good = clear;
    }
    good as f32 / 255.0
}

/// The veils of the ground (and chrome) and of the page's surfaces, 0 to 255, at `strength`
/// (0 to 100) of the most the palette allows.
pub fn veils(pal: &Palette, covers: Covers, design: Design, strength: u8) -> (u8, u8) {
    let keep = strength.min(100) as f32 / 100.0 * keep_max(pal, covers, design);
    // The ground's veil rounded first, so the layer never lets more through than the ground.
    let base = veil_of(keep);
    let layer = veil_of((255 - base) as f32 / 255.0 * LAYER_SHARE);
    (base, layer)
}

/// The keys of one look: what the marked pixels become.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    base: Key,
    layer: Key,
}

impl Keys {
    pub fn new(pal: &Palette, covers: Covers, design: Design, strength: u8) -> Keys {
        let k = key_colour(pal, covers);
        let (base, layer) = veils(pal, covers, design, strength);
        Keys {
            base: Key::new(k, base),
            layer: Key::new(k, layer),
        }
    }

    /// A pixel of the frame as drawn (`0xAARRGGBB`) as the window gets it: a marked one keyed
    /// by its mark, any other as it is. Never [`frost::MARK`] again, so the host's own keying
    /// passes over it.
    #[inline]
    pub fn apply(&self, px: u32) -> u32 {
        let out = match (px >> 24) as u8 {
            MARK => self.base.apply(px),
            LAYER => self.layer.apply(px),
            _ => return px,
        };
        if (out >> 24) as u8 == MARK {
            out | 0xff00_0000
        } else {
            out
        }
    }
}

// ---- marking ---------------------------------------------------------------------------------

/// The clip in force, in device px.
fn clip_of(p: &mut Painter) -> (i32, i32, i32, i32) {
    let old = p.clip(Rect::new(-1.0e7, -1.0e7, 2.0e7, 2.0e7));
    p.restore(old);
    old
}

/// A device rectangle cut to the bitmap, as `usize`; `None` when empty.
fn cut(r: (i32, i32, i32, i32), w: u32, h: u32) -> Option<(usize, usize, usize, usize)> {
    let x0 = r.0.clamp(0, w as i32) as usize;
    let y0 = r.1.clamp(0, h as i32) as usize;
    let x1 = r.2.clamp(0, w as i32) as usize;
    let y1 = r.3.clamp(0, h as i32) as usize;
    (x0 < x1 && y0 < y1).then_some((x0, y0, x1, y1))
}

/// "Whole window": the page's surfaces in `r` (logical px) become the second layer: every
/// opaque pixel there (alpha 255) is marked [`LAYER`], within the clip. Call it once the page
/// is laid and before anything is drawn over it.
pub fn raise(p: &mut Painter, r: Rect) {
    let clip = clip_of(p);
    let d = p.dev_rect(r);
    let r = (
        d.0.max(clip.0),
        d.1.max(clip.1),
        d.2.min(clip.2),
        d.3.min(clip.3),
    );
    let Some((x0, y0, x1, y1)) = cut(r, p.bmp.width, p.bmp.height) else {
        return;
    };
    let stride = p.bmp.width as usize * 4;
    for y in y0..y1 {
        raise_row(&mut p.bmp.pixels[y * stride + x0 * 4..y * stride + x1 * 4]);
    }
}

/// [`raise`] along one row of BGRA pixels, without a branch: 255 less 2 is [`LAYER`].
#[inline]
fn raise_row(row: &mut [u8]) {
    const _: () = assert!(LAYER == 253);
    for px in row.chunks_exact_mut(4) {
        px[3] -= u8::from(px[3] == 255) * 2;
    }
}

/// Where marks can be, logical px, in a window `size` with a title row `title_h` tall and a rail
/// `rail_w` wide: the title row and the rail (they do not overlap), or the whole window.
pub fn areas(covers: Covers, title_h: f32, rail_w: f32, (w, h): (f32, f32)) -> [Option<Rect>; 2] {
    match covers {
        Covers::Chrome => [
            Some(Rect::new(0.0, 0.0, w, title_h)),
            Some(Rect::new(0.0, title_h, rail_w, (h - title_h).max(0.0))),
        ],
        Covers::Window => [Some(Rect::new(0.0, 0.0, w, h)), None],
    }
}

// ---- the frame ---------------------------------------------------------------------------------

/// One area of the glass (device px, cut to the bitmap) and the frame as drawn there, in rows
/// of its own width.
struct Kept {
    rect: (usize, usize, usize, usize),
    px: Vec<u8>,
}

impl Kept {
    fn stride(&self) -> usize {
        (self.rect.2 - self.rect.0) * 4
    }
}

/// The frame as drawn, kept while the window shows it keyed; see the [module](self).
#[derive(Default)]
pub struct Glass {
    /// The bitmap as drawn (BGRA) in each area where it is keyed: the title row and the rail,
    /// or the whole window. Only there, since nothing else is ever put back.
    kept: Vec<Kept>,
    size: (u32, u32),
    /// The bitmap is keyed where the last frames drew: `kept` holds what they drew.
    live: bool,
    /// Some frame was keyed: marks may still come back in a page switch's pictures.
    seen: bool,
    /// The clip of the frame being drawn, device px.
    clip: (i32, i32, i32, i32),
}

/// Where `a` and `b` overlap, as a device rectangle (empty when they do not).
fn meet(a: (i32, i32, i32, i32), b: (i32, i32, i32, i32)) -> (i32, i32, i32, i32) {
    (a.0.max(b.0), a.1.max(b.1), a.2.min(b.2), a.3.min(b.3))
}

fn signed(r: (usize, usize, usize, usize)) -> (i32, i32, i32, i32) {
    (r.0 as i32, r.1 as i32, r.2 as i32, r.3 as i32)
}

impl Glass {
    /// Before a frame is drawn: notes where it draws (the clip in force). Nothing is put back
    /// yet: a frame fills every pixel it draws over before it blends anything there, so only
    /// what reads the last frame needs it ([`Glass::restore`]).
    pub fn begin(&mut self, p: &mut Painter) {
        self.clip = clip_of(p);
        if self.live && (self.size != (p.bmp.width, p.bmp.height)) {
            // A new bitmap: the host draws all of it.
            self.live = false;
        }
    }

    /// Puts the frame as drawn back in `r` (logical px) where the window shows it keyed, within
    /// the frame's clip: before a page switch takes its picture of the old page there, so it
    /// reads flat colours and marks, as it always did. Outside the clip this frame draws
    /// nothing, so nothing there is put back either.
    ///
    /// Only a frame drawn whole may take such a picture (review N7): the picture reads all of
    /// `r`, and outside the clip the bitmap still holds the last frame keyed. That holds today
    /// because the app asks only for whole frames (`request_redraw_all`; the host draws all of
    /// a new or uncovered bitmap too), and every page or stage change asks for one. An app that
    /// starts asking for pieces must put back all of `r` here, or take no picture on a piece.
    pub fn restore(&self, p: &mut Painter, r: Rect) {
        let (w, h) = (p.bmp.width, p.bmp.height);
        debug_assert!(
            self.clip.0 <= 0
                && self.clip.1 <= 0
                && self.clip.2 >= w as i32
                && self.clip.3 >= h as i32,
            "a page switch's picture taken on a frame not drawn whole: {:?} of {w}x{h}",
            self.clip
        );
        if !self.live || self.size != (w, h) {
            return;
        }
        let d = meet(p.dev_rect(r), self.clip);
        let stride = w as usize * 4;
        for k in &self.kept {
            let Some((x0, y0, x1, y1)) = cut(meet(d, signed(k.rect)), w, h) else {
                continue;
            };
            let ks = k.stride();
            let (kx0, kx1) = ((x0 - k.rect.0) * 4, (x1 - k.rect.0) * 4);
            for y in y0..y1 {
                let ky = (y - k.rect.1) * ks;
                p.bmp.pixels[y * stride + x0 * 4..y * stride + x1 * 4]
                    .copy_from_slice(&k.px[ky + kx0..ky + kx1]);
            }
        }
    }

    /// After a frame is drawn: with `keys` (the window is frosted), keeps the frame as drawn
    /// in `areas` (logical px: where marks can be) and keys it in place; without, clears any
    /// mark a page switch's pictures brought back, so the frame is opaque.
    pub fn end(&mut self, p: &mut Painter, keys: Option<&Keys>, areas: &[Rect]) {
        let (w, h) = (p.bmp.width, p.bmp.height);
        let Some(keys) = keys else {
            if self.seen
                && let Some((x0, y0, x1, y1)) = cut(self.clip, w, h)
            {
                let stride = w as usize * 4;
                for y in y0..y1 {
                    let row = &mut p.bmp.pixels[y * stride + x0 * 4..y * stride + x1 * 4];
                    for px in row.chunks_exact_mut(4) {
                        if px[3] == MARK || px[3] == LAYER {
                            px[3] = 255;
                        }
                    }
                }
            }
            self.live = false;
            self.kept = Vec::new();
            return;
        };
        let rects: Vec<_> = areas
            .iter()
            .filter_map(|a| cut(p.dev_rect(*a), w, h))
            .collect();
        let mut clip = self.clip;
        let same = self.kept.len() == rects.len()
            && self.kept.iter().zip(&rects).all(|(k, r)| k.rect == *r);
        if !self.live || self.size != (w, h) || !same {
            // The first keyed frame, or the glass moved (a new bitmap, a change of cover or of
            // design, which the host draws whole): all of each area is the frame as drawn.
            self.kept = rects
                .iter()
                .map(|&rect| Kept {
                    rect,
                    px: vec![0; (rect.2 - rect.0) * (rect.3 - rect.1) * 4],
                })
                .collect();
            self.size = (w, h);
            clip = (0, 0, w as i32, h as i32);
        }
        for k in &mut self.kept {
            if let Some(r) = cut(meet(signed(k.rect), clip), w, h) {
                key_rows(&mut p.bmp.pixels, w as usize, r, k, keys);
            }
        }
        self.live = true;
        self.seen = true;
    }
}

/// The slots of a band's table of keyed colours.
const CACHE: usize = 4096;

#[inline]
fn slot_of(v: u32) -> usize {
    (v.wrapping_mul(0x9E37_79B1) >> 20) as usize & (CACHE - 1)
}

/// The least a keying thread is given, in pixels: less is not worth a thread.
const PIXELS_PER_THREAD: usize = 128 * 1024;

/// The threads that key `pixels` px in `rows` rows: by the work, not the height (a tall, narrow
/// rail is little work). More than four gained nothing on the machines measured: the work is
/// mostly moving memory.
fn keying_threads(pixels: usize, rows: usize) -> usize {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4)
        .min(pixels.div_ceil(PIXELS_PER_THREAD))
        .min(rows)
        .max(1)
}

/// Keys the rectangle `r` of `pixels` (BGRA rows of `width` px) in place, copying each pixel
/// as it was into the same place of `kept` (`r` lies inside its area). The rows are shared out
/// among the cores.
fn key_rows(
    pixels: &mut [u8],
    width: usize,
    (x0, y0, x1, y1): (usize, usize, usize, usize),
    kept: &mut Kept,
    keys: &Keys,
) {
    let stride = width * 4;
    let ks = kept.stride();
    let (kx0, kx1) = ((x0 - kept.rect.0) * 4, (x1 - kept.rect.0) * 4);
    let ky0 = y0 - kept.rect.1;
    let h = y1 - y0;
    let rows = &mut pixels[y0 * stride..y1 * stride];
    let into = &mut kept.px[ky0 * ks..(ky0 + h) * ks];
    let band = |rows: &mut [u8], into: &mut [u8]| {
        // A frame has few colours: the answers are kept in a small table by the pixel. (0 is
        // never a marked pixel, so an empty slot never answers.)
        let mut seen = vec![(0u32, 0u32); CACHE];
        // And most pixels are the one before them again.
        let (mut last_in, mut last_out) = (0u32, 0u32);
        for (row, keep) in rows.chunks_exact_mut(stride).zip(into.chunks_exact_mut(ks)) {
            let span = x0 * 4..x1 * 4;
            keep[kx0..kx1].copy_from_slice(&row[span.clone()]);
            for px in row[span].chunks_exact_mut(4) {
                let v = u32::from_le_bytes([px[0], px[1], px[2], px[3]]);
                if v == last_in {
                    px.copy_from_slice(&last_out.to_le_bytes());
                    continue;
                }
                let a = (v >> 24) as u8;
                if a != MARK && a != LAYER {
                    continue;
                }
                let slot = &mut seen[slot_of(v)];
                if slot.0 != v {
                    *slot = (v, keys.apply(v));
                }
                (last_in, last_out) = *slot;
                px.copy_from_slice(&last_out.to_le_bytes());
            }
        }
    };
    let threads = keying_threads(h * (x1 - x0), h);
    if threads == 1 {
        return band(rows, into);
    }
    let per = h.div_ceil(threads);
    // Each band is handed over through its slot, so a band whose thread cannot be made is
    // keyed here instead (as `transition::compose` does).
    type Slot<'a> = std::sync::Mutex<Option<(&'a mut [u8], &'a mut [u8])>>;
    let slots: Vec<Slot<'_>> = rows
        .chunks_mut(per * stride)
        .zip(into.chunks_mut(per * ks))
        .map(|b| std::sync::Mutex::new(Some(b)))
        .collect();
    let run = |slot: &Slot<'_>| {
        if let Some((r, k)) = slot.lock().ok().and_then(|mut b| b.take()) {
            band(r, k);
        }
    };
    std::thread::scope(|s| {
        let run = &run;
        for slot in &slots[1..] {
            if std::thread::Builder::new()
                .spawn_scoped(s, move || run(slot))
                .is_err()
            {
                run(slot);
            }
        }
        run(&slots[0]);
    });
}

/// The frame as drawn (`pixels`, BGRA) keyed as [`Glass::end`] keys it, for a shot.
pub fn key_copy(pixels: &mut [u8], keys: &Keys) {
    for px in pixels.chunks_exact_mut(4) {
        let v = u32::from_le_bytes([px[0], px[1], px[2], px[3]]);
        px.copy_from_slice(&keys.apply(v).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::look::Preset;
    use mdshared_ui::theme::{DARK, LIGHT};

    fn palettes() -> Vec<Palette> {
        let mut out = vec![DARK, LIGHT];
        for p in Preset::ALL {
            for dark in [false, true] {
                for accent in [None, Some([0xE8, 0x11, 0x23]), Some([0x00, 0x78, 0xD4])] {
                    out.push(p.palette(dark, accent));
                }
            }
        }
        out
    }

    #[test]
    fn text_reads_over_the_worst_backdrop_at_every_strength() {
        for pal in palettes() {
            for covers in Covers::ALL {
                for design in Design::ALL {
                    for s in (0..=100).step_by(5) {
                        let (base, layer) = veils(&pal, *covers, *design, s);
                        assert!(layer >= base, "the layer is never clearer than the ground");
                        let keep = (255 - base) as f32 / 255.0;
                        let (t, m, i) = worst_contrast(&pal, *covers, *design, keep);
                        assert!(
                            t >= TEXT_CONTRAST && m >= MUTED_CONTRAST && i >= ICON_CONTRAST,
                            "dark={} {covers:?} {design:?} {s}%: text {t:.2}, muted {m:.2}, icons {i:.2}",
                            pal.dark
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bolds_tints_of_the_accent_are_grounds_of_the_clamp() {
        // The review's case (alpha.4, S1): Bold, dark, whole window, at 100 %. Text over the
        // rail's gradient and the title band reads at the limits, over the worst backdrop.
        for pal in palettes().into_iter().filter(|p| p.dark) {
            let g: Vec<Rgb> = grounds(&pal, Covers::Window, Design::Bold)
                .iter()
                .map(|g| g.colour)
                .collect();
            let rail = [
                mix(pal.title, pal.accent, RAIL_TINT.0),
                mix(pal.title, pal.accent, RAIL_TINT.1),
            ];
            let band = mix(pal.page, pal.accent, hero_tint(true));
            assert!(rail.iter().chain([&band]).all(|c| g.contains(c)));
            let (base, _) = veils(&pal, Covers::Window, Design::Bold, 100);
            let key = Key::new(key_colour(&pal, Covers::Window), base);
            let at = |c: Rgb, d: u8| over(key.apply(pack(c)), d);
            for d in [WORST_DARK.0, WORST_DARK.1] {
                for tint in rail {
                    let icons = contrast(at(pal.text, d), at(tint, d));
                    assert!(icons >= ICON_CONTRAST, "rail {tint:?} over {d}: {icons:.2}");
                }
                let text = contrast(at(pal.text, d), at(band, d));
                let muted = contrast(at(pal.muted, d), at(band, d));
                assert!(
                    text >= TEXT_CONTRAST && muted >= MUTED_CONTRAST,
                    "band over {d}: {text:.2} {muted:.2}"
                );
            }
        }
    }

    #[test]
    fn the_gradients_read_between_the_clamps_samples() {
        // Review N8: the clamp samples each gradient at `GRADIENT_STEPS` + 1 points (it was 5
        // and 3). Sampled at 64 points each, every strength the slider gives still reads, in every
        // palette and both covers. The gradients are only Bold's (`screens::chrome`, `page`).
        const N: usize = 64;
        for pal in palettes() {
            let (lo, hi) = if pal.dark { WORST_DARK } else { WORST_LIGHT };
            for covers in Covers::ALL {
                let mut fine = Vec::new();
                let (top, bottom) = RAIL_TINT;
                for i in 0..=N {
                    let t = top + (bottom - top) * i as f32 / N as f32;
                    fine.push((mix(pal.title, pal.accent, t), false));
                }
                if *covers == Covers::Window {
                    let from = hero_tint(pal.dark);
                    for i in 0..=N {
                        let t = from * i as f32 / N as f32;
                        fine.push((mix(pal.page, pal.accent, t), true));
                    }
                }
                for s in (0..=100).step_by(5) {
                    let (base, _) = veils(&pal, *covers, Design::Bold, s);
                    let key = Key::new(key_colour(&pal, *covers), base);
                    let at = |c: Rgb, d: u8| over(key.apply(pack(c)), d);
                    for d in [lo, hi] {
                        for &(g, text) in &fine {
                            let ink = contrast(at(pal.text, d), at(g, d));
                            if text {
                                let muted = contrast(at(pal.muted, d), at(g, d));
                                assert!(
                                    ink >= TEXT_CONTRAST && muted >= MUTED_CONTRAST,
                                    "dark={} {covers:?} {s}% band {g:?} over {d}: {ink:.3} {muted:.3}",
                                    pal.dark
                                );
                            } else {
                                assert!(
                                    ink >= ICON_CONTRAST,
                                    "dark={} {covers:?} {s}% rail {g:?} over {d}: {ink:.3}",
                                    pal.dark
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_clamp_lets_a_good_part_of_the_backdrop_through() {
        // The trial is worth having only if the slider has room: at least a quarter of the
        // backdrop shows at 100 % in every palette, and a fifth in Bold over the whole window,
        // where the page's title and its secondary line sit on a tint of the accent (in dark
        // with the brightest accents, 24 %).
        for pal in palettes() {
            for covers in Covers::ALL {
                for design in Design::ALL {
                    let k = keep_max(&pal, *covers, *design);
                    let least = if (*covers, *design) == (Covers::Window, Design::Bold) {
                        0.20
                    } else {
                        0.25
                    };
                    assert!(
                        k >= least,
                        "dark={} {covers:?} {design:?}: {k:.2}",
                        pal.dark
                    );
                }
            }
        }
    }

    #[test]
    fn zero_is_opaque_and_strength_grows_the_backdrop() {
        let (b0, l0) = veils(&DARK, Covers::Window, Design::Bold, 0);
        assert_eq!((b0, l0), (255, 255));
        let mut last = 255;
        for s in (0..=100).step_by(5) {
            let (b, _) = veils(&DARK, Covers::Window, Design::Bold, s);
            assert!(b <= last, "{s}");
            last = b;
        }
        assert!(last < 200);
    }

    #[test]
    fn keys_leave_unmarked_pixels_and_never_leave_the_hosts_mark() {
        let keys = Keys::new(&DARK, Covers::Window, Design::Bold, 100);
        assert_eq!(keys.apply(0xff12_3456), 0xff12_3456);
        assert_eq!(keys.apply(0x0012_3456), 0x0012_3456);
        for c in (0..=255u32).step_by(5) {
            for a in [MARK, LAYER] {
                let px = ((a as u32) << 24) | (c << 16) | (c << 8) | c;
                let out = keys.apply(px);
                assert_ne!((out >> 24) as u8, MARK, "{px:08x}");
                let al = out >> 24;
                for s in [0, 8, 16] {
                    assert!((out >> s) & 0xff <= al, "premultiplied: {out:08x}");
                }
            }
        }
    }

    #[test]
    fn the_layer_shows_less_backdrop_than_the_ground() {
        for pal in [DARK, LIGHT] {
            let keys = Keys::new(&pal, Covers::Window, Design::Bold, 100);
            let k = key_colour(&pal, Covers::Window);
            let px = |mark: u8| {
                ((mark as u32) << 24) | ((k[0] as u32) << 16) | ((k[1] as u32) << 8) | k[2] as u32
            };
            let ground = keys.apply(px(MARK)) >> 24;
            let layer = keys.apply(px(LAYER)) >> 24;
            assert!(layer > ground, "dark={}: {layer} vs {ground}", pal.dark);
        }
    }

    #[test]
    fn the_whole_windows_key_is_the_emptiest_surface() {
        assert_eq!(key_colour(&DARK, Covers::Window), DARK.page);
        assert_eq!(key_colour(&LIGHT, Covers::Window), LIGHT.field);
        assert_eq!(key_colour(&DARK, Covers::Chrome), frost::key_colour(&DARK));
    }

    #[test]
    fn keying_threads_go_by_the_pixels() {
        // A rail 64 px wide and 1400 tall is little work, however tall; a whole window is not.
        assert_eq!(keying_threads(64 * 1400, 1400), 1);
        assert_eq!(keying_threads(2560 * 44, 44), 1);
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        assert_eq!(keying_threads(2560 * 1400, 1400), cores.clamp(1, 4));
        assert_eq!(keying_threads(10_000_000, 2), 2.min(cores.clamp(1, 4)));
    }

    #[test]
    fn an_area_keeps_only_its_own_pixels_in_rows_of_its_width() {
        // A bitmap 8 by 6; the area is columns 2 to 5 of rows 1 to 4, and the frame keyed the
        // part of it in columns 3 to 5 of rows 2 to 3.
        let (w, h) = (8usize, 6usize);
        let mut px = vec![0u8; w * h * 4];
        for (i, p) in px.chunks_exact_mut(4).enumerate() {
            let c = i as u8;
            p.copy_from_slice(&[c, c, c, if i % 2 == 0 { MARK } else { 255 }]);
        }
        let before = px.clone();
        let mut kept = Kept {
            rect: (2, 1, 6, 5),
            px: vec![0; 4 * 4 * 4],
        };
        let keys = Keys::new(&DARK, Covers::Window, Design::Bold, 100);
        key_rows(&mut px, w, (3, 2, 6, 4), &mut kept, &keys);
        for y in 0..h {
            for x in 0..w {
                let at = (y * w + x) * 4;
                let v = u32::from_le_bytes(before[at..at + 4].try_into().unwrap());
                let got = u32::from_le_bytes(px[at..at + 4].try_into().unwrap());
                let inside = (3..6).contains(&x) && (2..4).contains(&y);
                assert_eq!(got, if inside { keys.apply(v) } else { v }, "{x},{y}");
                if inside {
                    let k = ((y - 1) * 4 + (x - 2)) * 4;
                    assert_eq!(&kept.px[k..k + 4], &before[at..at + 4], "kept {x},{y}");
                }
            }
        }
        // Nothing outside the keyed part was written into the copy.
        assert!(kept.px[..16].iter().all(|&b| b == 0), "row 1 untouched");
    }

    #[test]
    fn strengths_parse() {
        assert_eq!(parse_strength("35"), Some(35));
        assert_eq!(parse_strength(" 80% "), Some(80));
        assert_eq!(parse_strength("400"), Some(100));
        assert_eq!(parse_strength("-3"), None);
        assert_eq!(parse_strength("half"), None);
    }
}
