//! A page switch with the effects of `look::Effect`: the toolkit's three (`anim::PageEffect`:
//! cross-fade, slide-and-fade, push), and two it does not have:
//!
//! - **Scale**: the new page grows from 94 % to full size about the region's middle and fades in
//!   over the old one.
//! - **Depth**: the old page sinks back to 96 % and fades out as the new one settles from 103 % to
//!   full size.
//!
//! All five are drawn here, on the toolkit's idea (`anim::page`): the old page is a copy of the
//! region taken at the switch, and each frame, once the new page is drawn as always, the two are
//! laid over each other in place, each moved or scaled about the region's middle, for a quarter of
//! a second (Depth: a third). The toolkit's three move and mix as its `PageTransition` does (the
//! same timing, curve, distances and rounding).
//!
//! Why not the toolkit's own: it walks the region pixel by pixel on one core, 3.5 to 6 ms a frame
//! on a 1360 by 860 window, and Scale and Depth, sampled pixel by pixel in floating point, took 40
//! and 65 ms (15 to 25 frames a second). Here a move or a scale is the same along a whole row or
//! column, so where each column and each row samples from is worked out once a frame; the pixels
//! are mixed as whole words (red with blue in one multiply, green in another); and the rows are
//! shared out among the cores.
//!
//! The page itself is drawn once (UI-REDRAW): on the switch's first frame it is drawn as
//! always and kept (`hold`), and the frames after lay the two pages kept over each other
//! without drawing it again (`step`, `holds`, `lay`), until what the page shows changes
//! (`drop_held`: the next frame draws and keeps it again) or the switch ends (the page is drawn
//! live from then on). The first frame shows the old page alone in every effect, so it is put
//! back by a copy rather than a blend, on the frame that also draws the new page. A region that
//! is drawn every frame anyway (Settings' preview, the pipeline's stage push) uses `apply`,
//! which keeps it afresh each frame.
//!
//! Like the toolkit's, a switch ends at once when the bitmap's size, the scale or the region's
//! place changed under it, and nothing starts when the animator does not animate (Windows' "Show
//! animations" off). With `PURGE_TX_LOG` set, each switch prints when it ends the time between
//! its frames and the cost of its blend.
//!
//! Deliberately not here: a switch that survives a resize, and an effect that needs the old page
//! drawn again (both as in the toolkit's `anim::page`).

use std::ops::Range;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mdshared_ui::anim::{Animator, Easing, Edge, Id, Motion, PageEffect, fluent};
use mdshared_ui::gfx::{Painter, Rect};

use crate::look::Effect;

/// One region's switch from an old page to a new one.
pub struct PageSwitch {
    run: Option<Run>,
    id: Id,
    name: &'static str,
    log: Option<Log>,
}

/// A switch under way.
struct Run {
    effect: Effect,
    /// The old page's pixels (BGRA words, the region's rows) and its device rectangle.
    old: Vec<u32>,
    rect: (i32, i32, i32, i32),
    /// The bitmap's size and the painter's scale at the start.
    of: (u32, u32),
    scale: f32,
    duration: Duration,
    /// The new page as a frame drew it (`held`), laid over the old one until it is out of date.
    new: Vec<u32>,
    held: bool,
    /// The progress at this frame, from 0 to 1.
    t: f32,
}

impl PageSwitch {
    /// A switch that is not running; `id` names its progress in the animator.
    pub fn new(id: &'static str) -> PageSwitch {
        PageSwitch {
            run: None,
            id: Id::new((id, "own")),
            name: id,
            log: None,
        }
    }

    /// Whether a switch is in flight.
    pub fn running(&self) -> bool {
        self.run.is_some()
    }

    /// Ends the switch now.
    pub fn cancel(&mut self, anim: &mut Animator) {
        self.run = None;
        anim.forget(self.id);
    }

    /// Starts a switch: the painter's bitmap must still hold the old page in `r`. A switch
    /// begun while another runs starts from what is on screen, the half-blended pages.
    pub fn begin(&mut self, anim: &mut Animator, p: &Painter, r: Rect, e: Effect) {
        let mut old = self.run.take().map(|run| run.old).unwrap_or_default();
        self.cancel(anim);
        if let Some(log) = self.log.take() {
            log.print(self.name);
        }
        if !anim.animates() {
            return;
        }
        let bmp = &*p.bmp;
        let (x0, y0, x1, y1) = p.dev_rect(r);
        let rect = (
            x0.max(0),
            y0.max(0),
            x1.min(bmp.width as i32),
            y1.min(bmp.height as i32),
        );
        if rect.0 >= rect.2
            || rect.1 >= rect.3
            || bmp.pixels.len() < (bmp.width * bmp.height * 4) as usize
        {
            return;
        }
        words(bmp.width, &bmp.pixels, rect, &mut old);
        self.run = Some(Run {
            effect: e,
            old,
            rect,
            of: (bmp.width, bmp.height),
            scale: p.scale,
            duration: if e == Effect::Depth {
                fluent::SLOW
            } else {
                fluent::NORMAL
            },
            new: Vec::new(),
            held: false,
            t: 0.0,
        });
        anim.set(self.id, 0.0_f32);
        if logging() {
            self.log = Some(Log {
                effect: e,
                last: None,
                gaps: Vec::new(),
                blends: Vec::new(),
                draws: Vec::new(),
                redrawn: 0,
            });
        }
    }

    /// Blends the old page into `r`, which holds the new page as this frame drew it. Call it
    /// every frame after the region is drawn and before anything over it. Returns whether the
    /// switch still runs. (A region that is drawn every frame: the Settings page's preview, the
    /// pipeline's stage push.)
    pub fn apply(&mut self, anim: &mut Animator, p: &mut Painter, r: Rect) -> bool {
        if !self.step(anim, p, r) {
            return false;
        }
        self.hold(p);
        self.lay(p);
        true
    }

    /// The first half of a frame of a region that is drawn once (the page): before the region
    /// is drawn, moves the switch on to this frame and says whether it still runs. A switch
    /// that ended (or was cancelled: the bitmap's size, the scale or the region's place
    /// changed) leaves the region to be drawn as it is. While it runs, the region is drawn only
    /// when [`holds`](Self::holds) says no, and then [`hold`](Self::hold) keeps it; then
    /// [`lay`](Self::lay) lays the two pages over each other.
    pub fn step(&mut self, anim: &mut Animator, p: &Painter, r: Rect) -> bool {
        if let Some(log) = &mut self.log {
            let now = Instant::now();
            if let Some(last) = log.last.replace(now) {
                log.gaps.push(ms(now - last));
            }
        }
        let running = self.advance(anim, p, r);
        if !running && let Some(log) = self.log.take() {
            log.print(self.name);
        }
        running
    }

    fn advance(&mut self, anim: &mut Animator, p: &Painter, r: Rect) -> bool {
        let Some(run) = &mut self.run else {
            return false;
        };
        let bmp = &*p.bmp;
        let dev = p.dev_rect(r);
        let region = (
            dev.0.max(0),
            dev.1.max(0),
            dev.2.min(bmp.width as i32),
            dev.3.min(bmp.height as i32),
        );
        if run.of != (bmp.width, bmp.height) || run.rect != region || run.scale != p.scale {
            self.cancel(anim);
            return false;
        }
        let t: f32 = anim.value(self.id, 1.0, Motion::tween(run.duration, Easing::Linear));
        if t >= 1.0 {
            self.run = None;
            return false;
        }
        run.t = t;
        true
    }

    /// Whether the new page is kept from an earlier frame: the region need not be drawn.
    pub fn holds(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.held)
    }

    /// Keeps the new page as the bitmap holds it now, just drawn, for the frames after.
    pub fn hold(&mut self, p: &Painter) {
        if let Some(run) = &mut self.run {
            words(p.bmp.width, &p.bmp.pixels, run.rect, &mut run.new);
            run.held = true;
        }
    }

    /// The new page kept is out of date (what it shows changed): the next frame draws it again.
    pub fn drop_held(&mut self) {
        if let Some(run) = &mut self.run {
            run.held = false;
        }
    }

    /// The second half of a frame (after [`step`](Self::step) and [`hold`](Self::hold)): lays
    /// the old page and the new one kept over each other in the region, as far as this frame
    /// has them. Everything under the region is covered.
    pub fn lay(&mut self, p: &mut Painter) {
        let start = Instant::now();
        let Some(run) = &self.run else {
            return;
        };
        if !run.held {
            return;
        }
        let t = run.t;
        if t <= 0.0 {
            // The switch's first frame: every effect shows the old page alone, in place (the
            // new one is wholly transparent, or a whole region away). It is put back as it was,
            // which costs a copy, not a blend, on the frame that also draws the new page.
            let bmp = &mut *p.bmp;
            unwords(bmp.width, &mut bmp.pixels, run.rect, &run.old);
            if let Some(log) = &mut self.log {
                log.blends.push(ms(start.elapsed()));
            }
            return;
        }
        let size = (run.rect.2 - run.rect.0, run.rect.3 - run.rect.1);
        let (old, new, a) = places(run.effect, t, size, run.scale);
        let bmp = &mut *p.bmp;
        compose(
            bmp.width,
            &mut bmp.pixels,
            run.rect,
            &Picture::of(&run.old, run.rect, old),
            &Picture::of(&run.new, run.rect, new),
            parts(a),
        );
        if let Some(log) = &mut self.log {
            log.blends.push(ms(start.elapsed()));
        }
    }

    /// With `PURGE_TX_LOG` set, the cost of a whole frame's drawing while the switch runs, and
    /// whether that frame drew the page, for its line.
    pub fn note_draw(&mut self, ms: f64, drew: bool) {
        if let Some(log) = &mut self.log {
            log.draws.push(ms);
            log.redrawn += usize::from(drew);
        }
    }
}

/// Where the old page and the new one are shown at progress `t` of `effect` in a region `w` by
/// `h` device px at `scale`, and the new one's opacity.
fn places(effect: Effect, t: f32, (w, h): (i32, i32), scale: f32) -> (Place, Place, f32) {
    // How far the new page still is from its place, of the way it has to go.
    let left = 1.0 - fluent::DECELERATE.at(t);
    let place = |scale: f32, shift: (i32, i32)| Place {
        scale,
        shift,
        clamp: false,
    };
    let still = place(1.0, (0, 0));
    // The old page's place, the new one's, and the new one's opacity.
    match effect {
        Effect::Toolkit(PageEffect::Crossfade) => (still, still, 1.0 - left),
        Effect::Toolkit(PageEffect::SlideFade { from, distance }) => {
            let (ux, uy) = direction(from);
            let d = distance * scale * left;
            let shift = ((ux * d).round() as i32, (uy * d).round() as i32);
            // The band the new page has not reached yet repeats its edge.
            let new = Place {
                clamp: true,
                ..place(1.0, shift)
            };
            (still, new, t * 2.0)
        }
        Effect::Toolkit(PageEffect::Push { from }) => {
            let (ux, uy) = direction(from);
            let shift = (
                (ux * w as f32 * left).round() as i32,
                (uy * h as f32 * left).round() as i32,
            );
            let ahead = (shift.0 - ux as i32 * w, shift.1 - uy as i32 * h);
            (place(1.0, ahead), place(1.0, shift), 1.0)
        }
        // The fade leads the growth, so the page is legible before it is still.
        Effect::Scale => (still, place(0.94 + 0.06 * (1.0 - left), (0, 0)), t * 1.8),
        Effect::Depth => (
            place(0.96 + 0.04 * left, (0, 0)),
            place(1.0 + 0.03 * left, (0, 0)),
            1.0 - left,
        ),
    }
}

/// The direction from the region's middle to a side.
fn direction(e: Edge) -> (f32, f32) {
    match e {
        Edge::Left => (-1.0, 0.0),
        Edge::Right => (1.0, 0.0),
        Edge::Top => (0.0, -1.0),
        Edge::Bottom => (0.0, 1.0),
    }
}

/// A fraction as parts of 256.
fn parts(t: f32) -> u32 {
    if t.is_nan() {
        return 256;
    }
    (t.clamp(0.0, 1.0) * 256.0).round() as u32
}

/// The pixels of a device rectangle of a bitmap `width` px wide, as BGRA words, into `out`.
fn words(width: u32, pixels: &[u8], (x0, y0, x1, y1): (i32, i32, i32, i32), out: &mut Vec<u32>) {
    out.clear();
    let n = (x1 - x0) as usize * 4;
    out.reserve(n / 4 * (y1 - y0) as usize);
    for row in y0..y1 {
        let o = (row as usize * width as usize + x0 as usize) * 4;
        out.extend(
            pixels[o..o + n]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])),
        );
    }
}

/// The words `px` (as `words` took them) back into the device rectangle of a bitmap `width` px
/// wide.
fn unwords(width: u32, pixels: &mut [u8], (x0, y0, x1, y1): (i32, i32, i32, i32), px: &[u32]) {
    let w = (x1 - x0) as usize;
    for (row, src) in (y0..y1).zip(px.chunks_exact(w)) {
        let o = (row as usize * width as usize + x0 as usize) * 4;
        put(&mut pixels[o..o + w * 4], 0..w, src.iter().copied());
    }
}

/// Where a page is shown in the region: at `scale` about the region's middle, moved by `shift`
/// device px. With `clamp`, the places the moved page does not reach repeat its edge; without,
/// they are left to the other page.
#[derive(Clone, Copy)]
struct Place {
    scale: f32,
    shift: (i32, i32),
    clamp: bool,
}

/// Where along one side of the region a shown page samples: for each place on screen, the two
/// source places either side and the weight of the second (of 256); and the span of places the
/// page reaches.
struct Axis {
    at: Vec<(u32, u32, u32)>,
    span: Range<usize>,
    /// Moved by whole pixels and not clamped: the span's source is one run, `shift` before it.
    run: Option<i32>,
    /// At full size: every place samples one source place.
    whole: bool,
}

impl Axis {
    fn new(n: usize, scale: f32, shift: i32, clamp: bool) -> Axis {
        let whole = (scale - 1.0).abs() < 1e-4;
        let m = n as f32 / 2.0;
        let last = n.saturating_sub(1) as u32;
        let (mut from, mut to) = (n, 0);
        let at = (0..n)
            .map(|d| {
                let s = if whole {
                    (d as i32 - shift) as f32
                } else {
                    (d as f32 + 0.5 - m) / scale + m - 0.5 - shift as f32
                };
                if !clamp && (s < -0.5 || s > n as f32 - 0.5) {
                    return (0, 0, 0);
                }
                from = from.min(d);
                to = d + 1;
                let f = s.clamp(0.0, last as f32);
                let i0 = (f as u32).min(last);
                let i1 = (i0 + 1).min(last);
                (i0, i1, ((f - i0 as f32) * 256.0) as u32)
            })
            .collect();
        Axis {
            at,
            span: from..to.max(from),
            run: (whole && !clamp).then_some(shift),
            whole,
        }
    }
}

/// A page's pixels (`w` words a row) shown at a `Place`.
struct Picture<'a> {
    px: &'a [u32],
    w: usize,
    cols: Axis,
    rows: Axis,
}

impl Picture<'_> {
    fn of(px: &[u32], (x0, y0, x1, y1): (i32, i32, i32, i32), at: Place) -> Picture<'_> {
        let (w, h) = ((x1 - x0) as usize, (y1 - y0) as usize);
        Picture {
            px,
            w,
            cols: Axis::new(w, at.scale, at.shift.0, at.clamp),
            rows: Axis::new(h, at.scale, at.shift.1, at.clamp),
        }
    }

    /// Row `y` of the shown page into `out`, over the span it reaches, which it returns; `tmp`
    /// (a row long) is for the work.
    fn row(&self, y: usize, out: &mut [u32], tmp: &mut [u32]) -> Range<usize> {
        if !self.rows.span.contains(&y) || self.cols.span.is_empty() {
            return 0..0;
        }
        let (r0, r1, wy) = self.rows.at[y];
        let top = &self.px[r0 as usize * self.w..][..self.w];
        let span = self.cols.span.clone();
        let cols = &self.cols.at[span.clone()];
        if wy == 0 {
            match self.cols.run {
                Some(shift) => {
                    let from = (span.start as i32 - shift) as usize;
                    out[span.clone()].copy_from_slice(&top[from..from + span.len()]);
                }
                None if self.cols.whole => {
                    for (o, &(c0, _, _)) in out[span.clone()].iter_mut().zip(cols) {
                        *o = top[c0 as usize];
                    }
                }
                None => {
                    for (o, &(c0, c1, wx)) in out[span.clone()].iter_mut().zip(cols) {
                        *o = mix(top[c0 as usize], top[c1 as usize], wx);
                    }
                }
            }
            return span;
        }
        // Rows mixed first, over the columns the span reads, then the columns: two mixes a
        // pixel rather than three.
        let bottom = &self.px[r1 as usize * self.w..][..self.w];
        let (lo, hi) = (cols[0].0 as usize, cols[cols.len() - 1].1 as usize + 1);
        for ((v, &a), &b) in tmp[lo..hi]
            .iter_mut()
            .zip(&top[lo..hi])
            .zip(&bottom[lo..hi])
        {
            *v = mix(a, b, wy);
        }
        for (o, &(c0, c1, wx)) in out[span.clone()].iter_mut().zip(cols) {
            *o = mix(tmp[c0 as usize], tmp[c1 as usize], wx);
        }
        span
    }
}

/// `a` and `b` mixed, `w` of 256 parts `b`, rounded, opaque: red with blue in one multiply (each
/// in its own 16 bits), green in another.
#[inline]
fn mix(a: u32, b: u32, w: u32) -> u32 {
    const RB: u32 = 0x00FF_00FF;
    let v = 256 - w;
    let rb = (((a & RB) * v + (b & RB) * w + 0x0080_0080) >> 8) & RB;
    let g = ((((a >> 8) & 0xFF) * v + ((b >> 8) & 0xFF) * w + 0x80) >> 8) & 0xFF;
    rb | (g << 8) | 0xFF00_0000
}

/// Writes `old` and `new` over the region `rect` of a bitmap `width` px wide: mixed (`alpha` of
/// 256 parts `new`) where both reach, either alone where one does, and the bitmap left as it is
/// where neither does. The rows are shared out among the cores.
fn compose(
    width: u32,
    pixels: &mut [u8],
    rect: (i32, i32, i32, i32),
    old: &Picture<'_>,
    new: &Picture<'_>,
    alpha: u32,
) {
    let stride = width as usize * 4;
    let (x0, w) = (rect.0 as usize, (rect.2 - rect.0) as usize);
    let rows = &mut pixels[rect.1 as usize * stride..rect.3 as usize * stride];
    let h = rows.len() / stride;
    // Bands of at least 64 rows, so a small region (the Settings preview) stays on one core.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 8)
        .min(h.div_ceil(64))
        .max(1);
    let per = h.div_ceil(threads).max(1);
    let band = |first: usize, rows: &mut [u8]| {
        let (mut o, mut n, mut tmp) = (vec![0u32; w], vec![0u32; w], vec![0u32; w]);
        for (i, line) in rows.chunks_exact_mut(stride).enumerate() {
            let os = old.row(first + i, &mut o, &mut tmp);
            let ns = new.row(first + i, &mut n, &mut tmp);
            let line = &mut line[x0 * 4..(x0 + w) * 4];
            // Each page alone where it reaches, then the two mixed where both do.
            put(line, os.clone(), o[os.clone()].iter().copied());
            put(line, ns.clone(), n[ns.clone()].iter().copied());
            let both = os.start.max(ns.start)..os.end.min(ns.end).max(os.start.max(ns.start));
            match alpha {
                256 => {}
                0 => put(line, both.clone(), o[both].iter().copied()),
                a => put(
                    line,
                    both.clone(),
                    o[both.clone()]
                        .iter()
                        .zip(&n[both])
                        .map(|(&o, &n)| mix(o, n, a)),
                ),
            }
        }
    };
    if threads == 1 {
        return band(0, rows);
    }
    std::thread::scope(|s| {
        for (k, chunk) in rows.chunks_mut(per * stride).enumerate() {
            let band = &band;
            s.spawn(move || band(k * per, chunk));
        }
    });
}

/// Writes the words `px` over the places `span` of a row of BGRA bytes.
fn put(line: &mut [u8], span: Range<usize>, px: impl Iterator<Item = u32>) {
    for (d, px) in line[span.start * 4..span.end * 4]
        .chunks_exact_mut(4)
        .zip(px)
    {
        d.copy_from_slice(&px.to_le_bytes());
    }
}

/// With `PURGE_TX_LOG` set: the time between the frames of a switch and the cost of its blend,
/// printed when it ends.
struct Log {
    effect: Effect,
    last: Option<Instant>,
    gaps: Vec<f64>,
    blends: Vec<f64>,
    draws: Vec<f64>,
    /// The frames that drew the page again rather than lay the kept one.
    redrawn: usize,
}

pub fn logging() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PURGE_TX_LOG").is_some())
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

impl Log {
    fn print(&self, name: &str) {
        let stat = |v: &[f64]| {
            let max = v.iter().copied().fold(0.0, f64::max);
            let avg = v.iter().sum::<f64>() / v.len().max(1) as f64;
            (avg, max)
        };
        let (ga, gm) = stat(&self.gaps);
        let (ba, bm) = stat(&self.blends);
        let (da, dm) = stat(&self.draws);
        let over = self.gaps.iter().filter(|g| **g > 16.0).count();
        // A frame of a 100 Hz display, with room for the timer's jitter.
        let late = self.gaps.iter().filter(|g| **g > 12.0).count();
        println!(
            "tx {name} {:?}: {} frames, frame {ga:.1} avg / {gm:.1} max ms ({late} over 12, \
             {over} over 16 ms), blend {ba:.2} avg / {bm:.2} max ms, draw {da:.2} avg / {dm:.2} \
             max ms ({} drew the page)",
            self.effect,
            self.gaps.len() + 1,
            self.redrawn,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grey(v: u8) -> u32 {
        u32::from_le_bytes([v, v, v, 255])
    }

    fn flat(w: i32, h: i32, v: u8) -> Vec<u32> {
        vec![grey(v); (w * h) as usize]
    }

    fn place(scale: f32, shift: (i32, i32), clamp: bool) -> Place {
        Place {
            scale,
            shift,
            clamp,
        }
    }

    fn at(p: &Picture<'_>, x: usize, y: usize) -> Option<u32> {
        let (mut out, mut tmp) = (vec![0; p.w], vec![0; p.w]);
        p.row(y, &mut out, &mut tmp).contains(&x).then(|| out[x])
    }

    #[test]
    fn full_size_samples_are_the_pixels() {
        let mut px = flat(4, 3, 90);
        px[6] = grey(7);
        let p = Picture::of(&px, (0, 0, 4, 3), place(1.0, (0, 0), false));
        assert_eq!(at(&p, 2, 1), Some(grey(7)));
        assert_eq!(at(&p, 0, 0), Some(grey(90)));
    }

    #[test]
    fn a_smaller_picture_leaves_its_edges_to_the_other() {
        let px = flat(100, 100, 200);
        let small = Picture::of(&px, (0, 0, 100, 100), place(0.9, (0, 0), false));
        assert_eq!(at(&small, 0, 0), None);
        assert_eq!(at(&small, 50, 0), None);
        assert_eq!(at(&small, 50, 50), Some(grey(200)));
        // Larger than the region: every pixel is covered.
        let large = Picture::of(&px, (0, 0, 100, 100), place(1.03, (0, 0), false));
        assert!(at(&large, 0, 0).is_some());
        assert!(at(&large, 99, 99).is_some());
    }

    #[test]
    fn a_scaled_picture_mixes_its_neighbours() {
        // Black then white columns, shown a little larger: a grey between them.
        let px: Vec<u32> = (0..40 * 4)
            .map(|i| grey(if i % 40 < 20 { 0 } else { 255 }))
            .collect();
        let p = Picture::of(&px, (0, 0, 40, 4), place(1.03, (0, 0), false));
        let row: Vec<u8> = (0..40).map(|x| at(&p, x, 1).unwrap() as u8).collect();
        assert_eq!((row[0], row[39]), (0, 255));
        assert!(row.iter().any(|&v| v > 0 && v < 255), "{row:?}");
        assert!(row.windows(2).all(|w| w[0] <= w[1]), "{row:?}");
    }

    #[test]
    fn a_moved_picture_leaves_or_repeats_its_edge() {
        // Columns 0..10 by their grey; moved 3 to the right.
        let px: Vec<u32> = (0..10 * 2).map(|i| grey((i % 10) as u8 * 10)).collect();
        let moved = Picture::of(&px, (0, 0, 10, 2), place(1.0, (3, 0), false));
        assert_eq!(at(&moved, 2, 0), None, "not reached: the other page's");
        assert_eq!(at(&moved, 3, 0), Some(grey(0)));
        assert_eq!(at(&moved, 9, 1), Some(grey(60)));
        let repeated = Picture::of(&px, (0, 0, 10, 2), place(1.0, (3, 0), true));
        assert_eq!(at(&repeated, 0, 0), Some(grey(0)), "the edge repeated");
        assert_eq!(at(&repeated, 9, 0), Some(grey(60)));
        // Left by four and up by one row: the last row is not reached.
        let up = Picture::of(&px, (0, 0, 10, 2), place(1.0, (-4, -1), false));
        assert_eq!(at(&up, 0, 0), Some(grey(40)));
        assert_eq!(at(&up, 6, 0), None);
        assert_eq!(at(&up, 0, 1), None);
    }

    #[test]
    fn mix_ends_are_exact_and_the_middle_rounds() {
        let o = u32::from_le_bytes([10, 20, 30, 255]);
        let n = u32::from_le_bytes([200, 100, 0, 255]);
        assert_eq!(mix(o, n, 0), o);
        assert_eq!(mix(o, n, 256), n);
        assert_eq!(mix(o, n, 128), u32::from_le_bytes([105, 60, 15, 255]));
        assert_eq!(mix(grey(0), grey(255), 128), grey(128));
    }

    #[test]
    fn compose_mixes_where_both_reach_and_leaves_the_rest() {
        // A region of 200 by 300 in a bitmap of 220 by 310: tall enough for several bands.
        let (bw, bh) = (220u32, 310u32);
        let rect = (10, 5, 210, 305);
        let (old, new) = (flat(200, 300, 200), flat(200, 300, 0));
        let mut bmp = vec![9u8; (bw * bh * 4) as usize];
        let o = Picture::of(&old, rect, place(1.0, (0, 0), false));
        let n = Picture::of(&new, rect, place(0.9, (0, 0), false));
        compose(bw, &mut bmp, rect, &o, &n, 128);
        let px = |bmp: &[u8], x: u32, y: u32| bmp[((y * bw + x) * 4) as usize];
        assert_eq!(px(&bmp, 110, 150), 100, "both: mixed");
        assert_eq!(px(&bmp, 110, 280), 100, "both, in the last band");
        assert_eq!(px(&bmp, 110, 300), 200, "the old page alone below the new");
        assert_eq!(px(&bmp, 11, 6), 200, "the old page alone at the edge");
        assert_eq!(px(&bmp, 5, 150), 9, "outside the region: untouched");
        assert_eq!(px(&bmp, 110, 307), 9);
        // A push half way: the old page on the left, the new one on the right, nothing mixed.
        let o = Picture::of(&old, rect, place(1.0, (-100, 0), false));
        let n = Picture::of(&new, rect, place(1.0, (100, 0), false));
        compose(bw, &mut bmp, rect, &o, &n, 256);
        assert_eq!(px(&bmp, 109, 150), 200);
        assert_eq!(px(&bmp, 110, 150), 0);
        // Both at half size: mixed in the middle; where neither reaches, the bitmap as it was.
        let o = Picture::of(&old, rect, place(0.5, (0, 0), false));
        let n = Picture::of(&new, rect, place(0.5, (0, 0), false));
        compose(bw, &mut bmp, rect, &o, &n, 128);
        assert_eq!(px(&bmp, 109, 150), 100);
        assert_eq!(px(&bmp, 11, 6), 200);
    }

    /// Every effect at its first frame shows the old page alone, in place: what `lay` puts back
    /// without a blend is what the blend would give.
    #[test]
    fn the_first_frame_is_the_old_page() {
        let (bw, bh) = (220u32, 310u32);
        let rect = (10, 5, 210, 305);
        // Two pages that differ everywhere, with detail, so a shift or a scale would show.
        let old: Vec<u32> = (0..200 * 300).map(|i| grey((i * 7 % 251) as u8)).collect();
        let new: Vec<u32> = (0..200 * 300).map(|i| grey((i * 13 % 241) as u8)).collect();
        let effects = [
            Effect::Toolkit(PageEffect::Crossfade),
            Effect::Toolkit(PageEffect::SlideFade {
                from: Edge::Bottom,
                distance: 28.0,
            }),
            Effect::Toolkit(PageEffect::SlideFade {
                from: Edge::Left,
                distance: 40.0,
            }),
            Effect::Toolkit(PageEffect::Push { from: Edge::Top }),
            Effect::Toolkit(PageEffect::Push { from: Edge::Bottom }),
            Effect::Scale,
            Effect::Depth,
        ];
        for e in effects {
            let (o, n, a) = places(e, 0.0, (200, 300), 1.25);
            let mut blended = vec![9u8; (bw * bh * 4) as usize];
            compose(
                bw,
                &mut blended,
                rect,
                &Picture::of(&old, rect, o),
                &Picture::of(&new, rect, n),
                parts(a),
            );
            let mut copied = vec![9u8; (bw * bh * 4) as usize];
            unwords(bw, &mut copied, rect, &old);
            assert!(blended == copied, "{e:?}");
            let mut back = Vec::new();
            words(bw, &copied, rect, &mut back);
            assert!(back == old, "{e:?}: the words round trip");
        }
    }

    #[test]
    fn parts_of_256() {
        assert_eq!(parts(0.5), 128);
        assert_eq!(parts(f32::NAN), 256);
        assert_eq!(parts(3.0), 256);
        assert_eq!(parts(-1.0), 0);
    }
}
