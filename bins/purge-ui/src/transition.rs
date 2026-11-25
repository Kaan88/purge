//! A page switch with the effects of `look::Effect`: the toolkit's own (`anim::PageTransition`:
//! cross-fade, slide-and-fade, push), and two it does not have, drawn here on the same idea (the
//! old page is a copy of the region taken at the switch, blended with the new page as each frame
//! draws it):
//!
//! - **Scale**: the new page grows from 94 % to full size about the region's middle and fades in
//!   over the old one.
//! - **Depth**: the old page sinks back to 96 % and fades out as the new one settles from 103 % to
//!   full size.
//!
//! Both sample with bilinear weights in whole bytes, once over the region a frame, for a quarter
//! of a second (Depth: a third). Like the toolkit's, a switch ends at once when the bitmap's size,
//! the scale or the region's place changed under it, and nothing starts when the animator does
//! not animate (Windows' "Show animations" off).
//!
//! Deliberately not here: a switch that survives a resize, and an effect that needs the old page
//! drawn again (both as in the toolkit's `anim::page`).

use std::time::Duration;

use mdshared_ui::anim::{Animator, Easing, Id, Motion, PageTransition, fluent};
use mdshared_ui::gfx::{Painter, Rect};

use crate::look::Effect;

/// One region's switch from an old page to a new one.
pub struct PageSwitch {
    toolkit: PageTransition,
    own: Option<Own>,
    id: Id,
}

/// A switch drawn here.
struct Own {
    scale_in: bool,
    /// The old page's pixels (BGRA rows) and its device rectangle.
    old: Vec<u8>,
    rect: (i32, i32, i32, i32),
    /// The bitmap's size and the painter's scale at the start.
    of: (u32, u32),
    scale: f32,
    duration: Duration,
    /// The new page as this frame drew it, kept between frames for its memory.
    new: Vec<u8>,
}

impl PageSwitch {
    /// A switch that is not running; `id` names its progress in the animator.
    pub fn new(id: &'static str) -> PageSwitch {
        PageSwitch {
            toolkit: PageTransition::new(id),
            own: None,
            id: Id::new((id, "own")),
        }
    }

    /// Whether a switch is in flight.
    pub fn running(&self) -> bool {
        self.own.is_some() || self.toolkit.running()
    }

    /// Ends the switch now.
    pub fn cancel(&mut self, anim: &mut Animator) {
        self.toolkit.cancel(anim);
        self.own = None;
        anim.forget(self.id);
    }

    /// Starts a switch: the painter's bitmap must still hold the old page in `r`.
    pub fn begin(&mut self, anim: &mut Animator, p: &Painter, r: Rect, e: Effect) {
        self.cancel(anim);
        let scale_in = match e {
            Effect::Toolkit(effect) => return self.toolkit.begin(anim, p, r, effect),
            Effect::Scale => true,
            Effect::Depth => false,
        };
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
        self.own = Some(Own {
            scale_in,
            old: copy(bmp.width, &bmp.pixels, rect),
            rect,
            of: (bmp.width, bmp.height),
            scale: p.scale,
            duration: if scale_in {
                fluent::NORMAL
            } else {
                fluent::SLOW
            },
            new: Vec::new(),
        });
        anim.set(self.id, 0.0_f32);
    }

    /// Blends the old page into `r`, which holds the new page as this frame drew it. Call it
    /// every frame after the region is drawn and before anything over it. Returns whether the
    /// switch still runs.
    pub fn apply(&mut self, anim: &mut Animator, p: &mut Painter, r: Rect) -> bool {
        if self.toolkit.running() {
            return self.toolkit.apply(anim, p, r);
        }
        let Some(own) = &mut self.own else {
            return false;
        };
        let dev = p.dev_rect(r);
        let bmp = &mut *p.bmp;
        let region = (
            dev.0.max(0),
            dev.1.max(0),
            dev.2.min(bmp.width as i32),
            dev.3.min(bmp.height as i32),
        );
        if own.of != (bmp.width, bmp.height) || own.rect != region || own.scale != p.scale {
            self.own = None;
            anim.forget(self.id);
            return false;
        }
        let t: f32 = anim.value(self.id, 1.0, Motion::tween(own.duration, Easing::Linear));
        if t >= 1.0 {
            self.own = None;
            return false;
        }
        let e = fluent::DECELERATE.at(t);
        own.new.clear();
        own.new
            .extend_from_slice(&copy(bmp.width, &bmp.pixels, own.rect));
        let (w, h) = (own.rect.2 - own.rect.0, own.rect.3 - own.rect.1);
        let (s_old, s_new, a) = if own.scale_in {
            // The fade leads the growth, so the page is legible before it is still.
            (1.0, 0.94 + 0.06 * e, (t * 1.8).min(1.0))
        } else {
            (1.0 - 0.04 * e, 1.03 - 0.03 * e, e)
        };
        let alpha = (a.clamp(0.0, 1.0) * 256.0).round() as u32;
        let stride = bmp.width as usize * 4;
        for y in 0..h {
            let o = (own.rect.1 + y) as usize * stride + own.rect.0 as usize * 4;
            for x in 0..w {
                let new = sample(&own.new, w, h, x, y, s_new);
                let old = sample(&own.old, w, h, x, y, s_old);
                let px = match (old, new) {
                    (Some(o), Some(n)) => blend(o, n, alpha),
                    (None, Some(n)) => n,
                    (Some(o), None) => o,
                    (None, None) => continue,
                };
                let d = o + x as usize * 4;
                bmp.pixels[d..d + 4].copy_from_slice(&px);
            }
        }
        true
    }
}

/// The pixels of a device rectangle of a bitmap `width` px wide.
fn copy(width: u32, pixels: &[u8], (x0, y0, x1, y1): (i32, i32, i32, i32)) -> Vec<u8> {
    let n = (x1 - x0) as usize * 4;
    let mut out = Vec::with_capacity(n * (y1 - y0) as usize);
    for row in y0..y1 {
        let o = (row as usize * width as usize + x0 as usize) * 4;
        out.extend_from_slice(&pixels[o..o + n]);
    }
    out
}

/// `old` and `new` mixed, `a` of 256 parts `new`.
fn blend(old: [u8; 4], new: [u8; 4], a: u32) -> [u8; 4] {
    let m = |o: u8, n: u8| ((o as u32 * (256 - a) + n as u32 * a + 128) >> 8) as u8;
    [m(old[0], new[0]), m(old[1], new[1]), m(old[2], new[2]), 255]
}

/// The pixel at `(x, y)` of a `w` by `h` picture shown at `scale` about its middle, with
/// bilinear weights; `None` where the shown picture does not reach.
fn sample(px: &[u8], w: i32, h: i32, x: i32, y: i32, scale: f32) -> Option<[u8; 4]> {
    if (scale - 1.0).abs() < 1e-4 {
        let o = ((y * w + x) * 4) as usize;
        return Some([px[o], px[o + 1], px[o + 2], 255]);
    }
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    let sx = (x as f32 + 0.5 - cx) / scale + cx - 0.5;
    let sy = (y as f32 + 0.5 - cy) / scale + cy - 0.5;
    if sx < -0.5 || sy < -0.5 || sx > w as f32 - 0.5 || sy > h as f32 - 0.5 {
        return None;
    }
    let (fx, fy) = (sx.max(0.0), sy.max(0.0));
    let (x0, y0) = ((fx as i32).min(w - 1), (fy as i32).min(h - 1));
    let (x1, y1) = ((x0 + 1).min(w - 1), (y0 + 1).min(h - 1));
    let ax = ((fx - x0 as f32) * 256.0) as u32;
    let ay = ((fy - y0 as f32) * 256.0) as u32;
    let at = |x: i32, y: i32| ((y * w + x) * 4) as usize;
    let (p00, p10, p01, p11) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
    let mut out = [0, 0, 0, 255];
    for (c, o) in out.iter_mut().enumerate().take(3) {
        let top = px[p00 + c] as u32 * (256 - ax) + px[p10 + c] as u32 * ax;
        let bottom = px[p01 + c] as u32 * (256 - ax) + px[p11 + c] as u32 * ax;
        *o = ((top * (256 - ay) + bottom * ay + 32768) >> 16) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(w: i32, h: i32, v: u8) -> Vec<u8> {
        (0..w * h).flat_map(|_| [v, v, v, 255]).collect()
    }

    #[test]
    fn full_size_samples_are_the_pixels() {
        let px = flat(4, 3, 90);
        assert_eq!(sample(&px, 4, 3, 2, 1, 1.0), Some([90, 90, 90, 255]));
    }

    #[test]
    fn a_smaller_picture_leaves_its_edges_to_the_other() {
        let px = flat(100, 100, 200);
        assert_eq!(sample(&px, 100, 100, 0, 0, 0.9), None);
        assert_eq!(
            sample(&px, 100, 100, 50, 50, 0.9),
            Some([200, 200, 200, 255])
        );
        // Larger than the region: every pixel is covered.
        assert!(sample(&px, 100, 100, 0, 0, 1.03).is_some());
        assert!(sample(&px, 100, 100, 99, 99, 1.03).is_some());
    }

    #[test]
    fn blend_ends_are_exact() {
        let (o, n) = ([10, 20, 30, 255], [200, 100, 0, 255]);
        assert_eq!(blend(o, n, 0), o);
        assert_eq!(blend(o, n, 256), n);
    }
}
