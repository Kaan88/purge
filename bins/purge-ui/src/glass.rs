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
//! ([`Palette::muted`]) at 3 : 1, over the ground and the chrome, with the backdrop anywhere
//! between [`WORST_DARK`] or [`WORST_LIGHT`]. Those are what Acrylic itself measured over a pure
//! black and a pure white window (dark: 53 to 144; light: 135 to 227, grey levels), widened by
//! about 15 levels; Mica's tinted wallpaper stays well inside them. In dark the clamp lets 40 to
//! 47 % of the backdrop through (a veil of at least 134 to 153 of 255, about Acrylic's own 150);
//! in light 87 to 93 % (a veil of at least 17 to 33), by preset. [`keep_max`] finds the
//! largest share of the backdrop that passes, for the palette in use (every preset, the
//! Windows accent); the slider's 0 to 100 % spans 0 to that.
//!
//! Deliberately not here: a veil per backdrop (the slider is one setting for Mica and
//! Acrylic), a blur of our own, and frosting anything drawn over the page.

use mdshared_app::settings::Writer;
use mdshared_ui::cover::contrast;
use mdshared_ui::frost::{self, Key, MARK};
use mdshared_ui::gfx::{Painter, Rect, Rgb};
use mdshared_ui::theme::Palette;

use crate::look::{Choice, Covers};

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
pub const MUTED_CONTRAST: f32 = 3.0;

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

/// The least contrast of text over the ground and the chrome, at `keep`, over the worst
/// backdrop: body text's and secondary text's.
pub fn worst_contrast(pal: &Palette, covers: Covers, keep: f32) -> (f32, f32) {
    let k = key_colour(pal, covers);
    let key = Key::new(k, veil_of(keep));
    let (lo, hi) = if pal.dark { WORST_DARK } else { WORST_LIGHT };
    let mut grounds = vec![pal.title, k];
    if covers == Covers::Window {
        grounds.push(pal.page);
    }
    let (mut text, mut muted) = (f32::MAX, f32::MAX);
    for d in [lo, hi] {
        for g in &grounds {
            let g = over(key.apply(pack(*g)), d);
            text = text.min(contrast(over(key.apply(pack(pal.text)), d), g));
            muted = muted.min(contrast(over(key.apply(pack(pal.muted)), d), g));
        }
    }
    (text, muted)
}

/// The clamp: the largest share of the backdrop (0 to 1) whose text still reads over the
/// worst backdrop ([`TEXT_CONTRAST`], [`MUTED_CONTRAST`]).
pub fn keep_max(pal: &Palette, covers: Covers) -> f32 {
    let ok = |keep: f32| {
        let (t, m) = worst_contrast(pal, covers, keep);
        t >= TEXT_CONTRAST && m >= MUTED_CONTRAST
    };
    if ok(1.0) {
        return 1.0;
    }
    let (mut good, mut bad) = (0.0_f32, 1.0_f32);
    for _ in 0..16 {
        let mid = (good + bad) / 2.0;
        if ok(mid) {
            good = mid;
        } else {
            bad = mid;
        }
    }
    // Whole steps of the veil: the one found, or a step more opaque.
    (255 - veil_of(good)) as f32 / 255.0
}

/// The veils of the ground (and chrome) and of the page's surfaces, 0 to 255, at `strength`
/// (0 to 100) of the most the palette allows.
pub fn veils(pal: &Palette, covers: Covers, strength: u8) -> (u8, u8) {
    let keep = strength.min(100) as f32 / 100.0 * keep_max(pal, covers);
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
    pub fn new(pal: &Palette, covers: Covers, strength: u8) -> Keys {
        let k = key_colour(pal, covers);
        let (base, layer) = veils(pal, covers, strength);
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

/// The frame as drawn, kept while the window shows it keyed; see the [module](self).
#[derive(Default)]
pub struct Glass {
    /// The bitmap as drawn (BGRA), where it is keyed.
    shadow: Vec<u8>,
    size: (u32, u32),
    /// The bitmap is keyed where the last frames drew: `shadow` holds what they drew.
    live: bool,
    /// Some frame was keyed: marks may still come back in a page switch's pictures.
    seen: bool,
    /// The clip of the frame being drawn, device px.
    clip: (i32, i32, i32, i32),
    /// Where the glass is (device px): only there is anything keyed and kept. The title row and
    /// the rail, or the whole window.
    areas: Vec<(usize, usize, usize, usize)>,
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

    /// Puts the frame as drawn back in `r` (logical px) where the window shows it keyed: before
    /// a page switch takes its picture of the old page there, so it reads flat colours and
    /// marks, as it always did.
    pub fn restore(&self, p: &mut Painter, r: Rect) {
        let (w, h) = (p.bmp.width, p.bmp.height);
        if !self.live || self.size != (w, h) || self.shadow.len() != p.bmp.pixels.len() {
            return;
        }
        let d = p.dev_rect(r);
        let stride = w as usize * 4;
        for a in &self.areas {
            let r = (
                d.0.max(a.0 as i32),
                d.1.max(a.1 as i32),
                d.2.min(a.2 as i32),
                d.3.min(a.3 as i32),
            );
            let Some((x0, y0, x1, y1)) = cut(r, w, h) else {
                continue;
            };
            for y in y0..y1 {
                let row = y * stride + x0 * 4..y * stride + x1 * 4;
                p.bmp.pixels[row.clone()].copy_from_slice(&self.shadow[row]);
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
            return;
        };
        let mut clip = self.clip;
        if !self.live || self.size != (w, h) || self.shadow.len() != p.bmp.pixels.len() {
            // The first keyed frame: all of the bitmap is the frame as drawn.
            self.shadow.clear();
            self.shadow.resize(p.bmp.pixels.len(), 0);
            self.size = (w, h);
            clip = (0, 0, w as i32, h as i32);
        }
        // The glass of this frame; where the last one had glass and this one has none (the
        // cover changed), the host drew everything again, opaque.
        self.areas.clear();
        for a in areas {
            if let Some(r) = cut(p.dev_rect(*a), w, h) {
                self.areas.push(r);
            }
        }
        for a in &self.areas {
            let r = (a.0 as i32, a.1 as i32, a.2 as i32, a.3 as i32);
            let r = (
                r.0.max(clip.0),
                r.1.max(clip.1),
                r.2.min(clip.2),
                r.3.min(clip.3),
            );
            if let Some(r) = cut(r, w, h) {
                key_rows(&mut p.bmp.pixels, &mut self.shadow, w as usize, r, keys);
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

/// Keys the rectangle `r` of `pixels` (BGRA rows of `width` px) in place, copying each pixel
/// as it was into the same place of `shadow`. The rows are shared out among the cores.
fn key_rows(
    pixels: &mut [u8],
    shadow: &mut [u8],
    width: usize,
    (x0, y0, x1, y1): (usize, usize, usize, usize),
    keys: &Keys,
) {
    let stride = width * 4;
    let rows = &mut pixels[y0 * stride..y1 * stride];
    let kept = &mut shadow[y0 * stride..y1 * stride];
    let h = y1 - y0;
    let band = |rows: &mut [u8], kept: &mut [u8]| {
        // A frame has few colours: the answers are kept in a small table by the pixel. (0 is
        // never a marked pixel, so an empty slot never answers.)
        let mut seen = vec![(0u32, 0u32); CACHE];
        // And most pixels are the one before them again.
        let (mut last_in, mut last_out) = (0u32, 0u32);
        for (row, keep) in rows
            .chunks_exact_mut(stride)
            .zip(kept.chunks_exact_mut(stride))
        {
            let span = x0 * 4..x1 * 4;
            keep[span.clone()].copy_from_slice(&row[span.clone()]);
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
    // More than four bands gained nothing on the machines measured: the work is mostly moving
    // memory.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4)
        .min(h.div_ceil(128))
        .max(1);
    if threads == 1 {
        return band(rows, kept);
    }
    let per = h.div_ceil(threads) * stride;
    // Each band is handed over through its slot, so a band whose thread cannot be made is
    // keyed here instead (as `transition::compose` does).
    type Slot<'a> = std::sync::Mutex<Option<(&'a mut [u8], &'a mut [u8])>>;
    let slots: Vec<Slot<'_>> = rows
        .chunks_mut(per)
        .zip(kept.chunks_mut(per))
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
                for s in (0..=100).step_by(5) {
                    let (base, layer) = veils(&pal, *covers, s);
                    assert!(layer >= base, "the layer is never clearer than the ground");
                    let keep = (255 - base) as f32 / 255.0;
                    let (t, m) = worst_contrast(&pal, *covers, keep);
                    assert!(
                        t >= TEXT_CONTRAST && m >= MUTED_CONTRAST,
                        "dark={} {covers:?} {s}%: text {t:.2}, muted {m:.2}",
                        pal.dark
                    );
                }
            }
        }
    }

    #[test]
    fn the_clamp_lets_a_good_part_of_the_backdrop_through() {
        // The trial is worth having only if the slider has room: at least a quarter of the
        // backdrop shows at 100 % in every palette.
        for pal in palettes() {
            for covers in Covers::ALL {
                let k = keep_max(&pal, *covers);
                assert!(k >= 0.25, "dark={} {covers:?}: {k:.2}", pal.dark);
            }
        }
    }

    #[test]
    fn zero_is_opaque_and_strength_grows_the_backdrop() {
        let (b0, l0) = veils(&DARK, Covers::Window, 0);
        assert_eq!((b0, l0), (255, 255));
        let mut last = 255;
        for s in (0..=100).step_by(5) {
            let (b, _) = veils(&DARK, Covers::Window, s);
            assert!(b <= last, "{s}");
            last = b;
        }
        assert!(last < 200);
    }

    #[test]
    fn keys_leave_unmarked_pixels_and_never_leave_the_hosts_mark() {
        let keys = Keys::new(&DARK, Covers::Window, 100);
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
            let keys = Keys::new(&pal, Covers::Window, 100);
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
    fn strengths_parse() {
        assert_eq!(parse_strength("35"), Some(35));
        assert_eq!(parse_strength(" 80% "), Some(80));
        assert_eq!(parse_strength("400"), Some(100));
        assert_eq!(parse_strength("-3"), None);
        assert_eq!(parse_strength("half"), None);
    }
}
