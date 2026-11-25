//! The toolkit's box and gradient, pixel for pixel, at less cost for the large ones: the content
//! card, the page's cards and wells, and Bold's band behind a page's title (UI-REDRAW).
//!
//! `Painter::frame` fills its whole box twice (the outline's colour, then the fill inside it),
//! and `Painter::gradient` works out the round of its corners for every pixel of a row that
//! has a corner, the whole row across. Here only the corners are left to them, each in its own
//! clip; the rest is plain boxes and rows, each pixel written once. What comes out is the same
//! (the checks: `--script --shots` before and after, compared byte for byte).

use mdshared_ui::gfx::{Along, Painter, Rect, Rgb};

/// Clips to a rectangle in device px (the painter's offset taken off, as `Painter::clip` adds
/// it), within the clip in force; returns the clip before, for `Painter::restore`.
fn clip_dev(p: &mut Painter, (x0, y0, x1, y1): (i32, i32, i32, i32)) -> (i32, i32, i32, i32) {
    let s = p.scale;
    let (ox, oy) = p.origin();
    let (lx0, ly0) = ((x0 - ox) as f32 / s, (y0 - oy) as f32 / s);
    let (lx1, ly1) = ((x1 - ox) as f32 / s, (y1 - oy) as f32 / s);
    p.clip(Rect::new(lx0, ly0, lx1 - lx0, ly1 - ly0))
}

/// The round of a box `r` with `radius` in device px, as the toolkit clamps it, and the side
/// of the square at each corner that holds all of it (and a pixel more).
fn corner(p: &Painter, r: Rect, radius: f32) -> ((i32, i32, i32, i32), i32) {
    let (x0, y0, x1, y1) = p.dev_rect(r);
    let rad = (radius * p.scale)
        .min((x1 - x0) as f32 / 2.0)
        .min((y1 - y0) as f32 / 2.0)
        .max(0.0);
    ((x0, y0, x1, y1), rad.ceil() as i32 + 1)
}

/// `Painter::frame`: a filled box with a one-device-pixel outline.
pub fn frame(p: &mut Painter, r: Rect, radius: f32, fill: Rgb, stroke: Rgb) {
    let ((x0, y0, x1, y1), b) = corner(p, r, radius);
    if x1 - x0 <= 2 * b || y1 - y0 <= 2 * b {
        return p.frame(r, radius, fill, stroke);
    }
    // The corners, by the toolkit (a corner off the bitmap or out of the clip costs nothing).
    for (cx, cy) in [(x0, y0), (x1 - b, y0), (x0, y1 - b), (x1 - b, y1 - b)] {
        let old = clip_dev(p, (cx, cy, cx + b, cy + b));
        p.frame(r, radius, fill, stroke);
        p.restore(old);
    }
    // The outline between them, then the inside.
    p.fill_dev(x0 + b, y0, x1 - b, y0 + 1, stroke, 1.0);
    p.fill_dev(x0 + b, y1 - 1, x1 - b, y1, stroke, 1.0);
    p.fill_dev(x0, y0 + b, x0 + 1, y1 - b, stroke, 1.0);
    p.fill_dev(x1 - 1, y0 + b, x1, y1 - b, stroke, 1.0);
    p.fill_dev(x0 + b, y0 + 1, x1 - b, y0 + b, fill, 1.0);
    p.fill_dev(x0 + b, y1 - b, x1 - b, y1 - 1, fill, 1.0);
    fill_dev(p, (x0 + 1, y0 + b, x1 - 1, y1 - b), fill);
}

/// `Painter::gradient` from top to bottom: the columns of the corners by the toolkit, the
/// columns between as plain rows (a row of a top-to-bottom gradient is one colour, and the round
/// does not reach them).
pub fn gradient_down(p: &mut Painter, r: Rect, radius: f32, from: Rgb, to: Rgb, alpha: f32) {
    let ((x0, y0, x1, y1), b) = corner(p, r, radius);
    if x1 - x0 <= 2 * b || y1 <= y0 {
        return p.gradient(r, radius, from, to, Along::Y, alpha);
    }
    for (cx0, cx1) in [(x0, x0 + b), (x1 - b, x1)] {
        let old = clip_dev(p, (cx0, y0, cx1, y1));
        p.gradient(r, radius, from, to, Along::Y, alpha);
        p.restore(old);
    }
    let old = clip_dev(p, (x0 + b, y0, x1 - b, y1));
    p.gradient(r, 0.0, from, to, Along::Y, alpha);
    p.restore(old);
}

/// `Painter::fill_dev` at full opacity, the rows shared out among the cores when the box is
/// large (the content card's inside: more than a million pixels at 125 %, 1.6 ms on one core).
fn fill_dev(p: &mut Painter, (x0, y0, x1, y1): (i32, i32, i32, i32), c: Rgb) {
    // The clip in force, read by setting none narrower.
    let clip = clip_dev(p, (i32::MIN / 4, i32::MIN / 4, i32::MAX / 4, i32::MAX / 4));
    p.restore(clip);
    let (x0, y0) = (x0.max(clip.0).max(0), y0.max(clip.1).max(0));
    let (x1, y1) = (
        x1.min(clip.2).min(p.bmp.width as i32),
        y1.min(clip.3).min(p.bmp.height as i32),
    );
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let (w, h) = ((x1 - x0) as usize, (y1 - y0) as usize);
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4)
        .min(w * h / 250_000)
        .max(1);
    if threads == 1 {
        return p.fill_dev(x0, y0, x1, y1, c, 1.0);
    }
    let stride = p.bmp.width as usize * 4;
    let px = [c[2], c[1], c[0], 255];
    let rows = &mut p.bmp.pixels[y0 as usize * stride..y1 as usize * stride];
    let per = h.div_ceil(threads);
    let x0 = x0 as usize * 4;
    let fill = |band: &mut [u8]| {
        for line in band.chunks_exact_mut(stride) {
            for d in line[x0..x0 + w * 4].chunks_exact_mut(4) {
                d.copy_from_slice(&px);
            }
        }
    };
    // Each band sits in a slot its thread takes; a thread the OS will not make leaves its band
    // in the slot, and this thread fills it (a refused thread must not panic the window).
    let slots: Vec<std::sync::Mutex<Option<&mut [u8]>>> = rows
        .chunks_mut(per * stride)
        .map(|b| std::sync::Mutex::new(Some(b)))
        .collect();
    let take = |slot: &std::sync::Mutex<Option<&mut [u8]>>| {
        let band = slot.lock().map(|mut g| g.take()).unwrap_or(None);
        if let Some(band) = band {
            fill(band);
        }
    };
    std::thread::scope(|s| {
        for slot in &slots {
            let take = &take;
            if std::thread::Builder::new()
                .spawn_scoped(s, move || take(slot))
                .is_err()
            {
                take(slot);
            }
        }
    });
}

/// Draws boxes and gradients both ways, the toolkit's and these, on two copies of the bitmap
/// `p` draws into, and says whether every pixel came out the same: sizes from a button's to the
/// content card's, radii from none to round, scales from 100 % to 200 %, opaque and see-through
/// gradients, inside a clip that cuts them and under an offset. The walk (`--script`) runs it on
/// its first frame, over what that frame drew. Returns how many were compared.
pub fn self_check(p: &mut Painter) -> Result<usize, String> {
    let mut a = p.bmp.clone();
    let mut b = p.bmp.clone();
    let (fill, stroke, to) = ([250, 249, 248], [200, 30, 30], [20, 90, 200]);
    let rects = [
        Rect::new(10.0, 10.0, 120.0, 32.0),
        Rect::new(33.3, 47.7, 301.1, 211.9),
        Rect::new(60.0, 40.0, 900.0, 700.0),
        Rect::new(250.0, 48.0, 1122.0, 824.0),
        Rect::new(5.0, 5.0, 14.0, 9.0),
    ];
    let mut n = 0;
    for scale in [1.0, 1.25, 1.5, 1.75, 2.0] {
        for radius in [0.0, 1.0, 4.0, 6.0, 7.5, 10.0, 12.0] {
            for (k, &r) in rects.iter().enumerate() {
                // Every other case in a clip that cuts the box, and moved by an offset.
                let cut = k % 2 == 1;
                let draw = |bmp: &mut _, gfx: &mut _, ours: bool| {
                    let mut q = Painter::new(bmp, gfx, scale);
                    if cut {
                        q.offset(3.0, 2.0);
                        q.clip(Rect::new(r.x + r.w * 0.3, r.y - 4.0, r.w, r.h * 0.6));
                    }
                    let band = Rect::new(r.x + 1.0, r.y + 1.0, r.w - 2.0, r.h.min(96.0));
                    if ours {
                        frame(&mut q, r, radius, fill, stroke);
                        gradient_down(&mut q, band, radius - 1.0, to, fill, 1.0);
                        gradient_down(&mut q, band, radius, stroke, to, 0.6);
                    } else {
                        q.frame(r, radius, fill, stroke);
                        q.gradient(band, radius - 1.0, to, fill, Along::Y, 1.0);
                        q.gradient(band, radius, stroke, to, Along::Y, 0.6);
                    }
                };
                draw(&mut a, &mut *p.gfx, false);
                draw(&mut b, &mut *p.gfx, true);
                n += 1;
                if a.pixels != b.pixels {
                    let at = a.pixels.iter().zip(&b.pixels).position(|(x, y)| x != y);
                    let at = at.unwrap_or(0) / 4;
                    let w = a.width as usize;
                    return Err(format!(
                        "{r:?} radius {radius} at {scale}: first difference at {}, {}",
                        at % w,
                        at / w
                    ));
                }
            }
        }
    }
    Ok(n)
}
