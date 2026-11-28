//! Where the window opens (UI-WINPLACE): where it was last time, or centred on its monitor the
//! first time, and kept up to date while it runs.
//!
//! The place is the toolkit's [`WindowState`], saved under the `window` key of the settings file
//! (`prefs`). It is put back in [`Placer::start`], while the window is still hidden, so it does
//! not jump; it is cloaked (DWM keeps it unseen) until a frame is laid out for its new size. A
//! window saved maximized is placed at its restored rectangle, shown cloaked by the host,
//! maximized at the first wake and uncloaked once the maximized frame is drawn: the restored
//! rectangle stays the one it goes back to, and nothing is seen between. A saved place that names no monitor now, or is damaged, is a first launch.
//!
//! The place is captured again when the window closes, and about a second after it last moved or
//! changed size ([`DEBOUNCE`]), so a crash or a kill keeps the last place. winit's moves do not
//! reach the application, so every event the window gets compares its rectangle with the last
//! one seen ([`Placer::watch`]): a move ends with the pointer over the window, the keyboard or
//! the next frame.
//!
//! Deliberately not here: the scripted walk, `--seconds`, `--shot` and the launch bench, which
//! keep the fixed size of [`FIXED`] and the system's position, and neither read nor write the
//! place (`main`).

use std::time::{Duration, Instant};

use mdshared_app::sister::Rect as ScreenRect;
use mdshared_ui::gfx::Rect;
use mdshared_ui::host::Cx;
use mdshared_ui::place;
use mdshared_ui::window_state::{self, WindowState};

/// The size of a first launch, in logical px.
pub const DEFAULT: (f32, f32) = (1480.0, 940.0);
/// The size of the runs that must not depend on the user's place, in logical px.
pub const FIXED: (f32, f32) = (1360.0, 860.0);
/// The smallest the window may be, in logical px.
pub const MIN: (f32, f32) = (1080.0, 700.0);
/// The share of the work area a first launch may take at most.
const FIT: f64 = 0.9;
/// How long after the last move or resize the place is saved.
pub const DEBOUNCE: Duration = Duration::from_millis(1000);
/// How long a cloaked window waits for its maximized frame before it is shown anyway.
const UNCLOAK_LIMIT: Duration = Duration::from_millis(600);

/// The outer rectangle of a first launch on a work area of `work` physical px at `scale`: the
/// [`DEFAULT`] size, no more than [`FIT`] of the work area but no less than [`MIN`] (nor more
/// than the work area itself), centred in it.
pub fn first(work: ScreenRect, scale: f32) -> ScreenRect {
    let scale = if scale.is_finite() && scale > 0.0 {
        f64::from(scale)
    } else {
        1.0
    };
    let edge = |want: f32, min: f32, room: u32| -> u32 {
        let room = f64::from(room.max(1));
        let w = (f64::from(want) * scale)
            .min((room * FIT).floor())
            .max((f64::from(min) * scale).round())
            .min(room);
        w.round().max(1.0) as u32
    };
    let w = edge(DEFAULT.0, MIN.0, work.w);
    let h = edge(DEFAULT.1, MIN.1, work.h);
    ScreenRect {
        x: work.x.saturating_add((work.w.saturating_sub(w) / 2) as i32),
        y: work.y.saturating_add((work.h.saturating_sub(h) / 2) as i32),
        w,
        h,
    }
}

/// `state` with its restored size no smaller than [`MIN`].
pub fn at_least_min(state: &WindowState) -> WindowState {
    let mut s = state.clone();
    s.rect = Rect::new(s.rect.x, s.rect.y, s.rect.w.max(MIN.0), s.rect.h.max(MIN.1));
    s
}

/// What the placed window still waits for before it is seen.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Pending {
    None,
    /// Cloaked and placed at its restored rectangle: maximize at the first wake.
    Maximize,
    /// Cloaked: shown at the first frame laid out for the window's size (and maximized, when
    /// `maximized`), or at the instant whatever happens.
    Uncloak {
        until: Instant,
        maximized: bool,
    },
}

/// The window's place while it runs.
pub struct Placer {
    /// The place last saved (or read at the start).
    saved: Option<WindowState>,
    /// The outer rectangle and maximized flag last seen.
    seen: Option<(ScreenRect, bool)>,
    /// When to capture and save the place.
    due: Option<Instant>,
    pending: Pending,
}

impl Placer {
    /// Puts the hidden window where `saved` says, or centres it on its monitor when there is no
    /// saved place or it fits no monitor now.
    ///
    /// The host lays out its first frame at the size it read before this call, so a window given
    /// another size here is cloaked until a frame is laid out for the size it has ([`drawn`]):
    /// the first frame is never seen cut off.
    ///
    /// [`drawn`]: Self::drawn
    pub fn start<M>(cx: &Cx<'_, M>, saved: Option<WindowState>) -> Placer {
        let window = cx.window();
        let placement = saved.as_ref().and_then(|s| {
            let monitors = window_state::monitors(window);
            window_state::restore(&at_least_min(s), &monitors)
        });
        let (rect, maximized) = match placement {
            Some(p) => (Some(p.rect), p.maximized),
            None => (
                place::work_area(window).map(|work| first(work, window.scale_factor() as f32)),
                false,
            ),
        };
        let mut pending = Pending::None;
        if let Some(rect) = rect {
            // Where it cannot be cloaked, the window is seen as it comes: a maximize at the first
            // wake is the system's animation.
            let cloaked = cloak(cx, true);
            set(cx, rect);
            pending = if maximized {
                Pending::Maximize
            } else if cloaked {
                Pending::Uncloak {
                    until: cx.now() + UNCLOAK_LIMIT,
                    maximized: false,
                }
            } else {
                Pending::None
            };
        }
        Placer {
            saved,
            seen: None,
            due: None,
            pending,
        }
    }

    /// When the placer wants a wake.
    pub fn due(&self, now: Instant) -> Option<Instant> {
        let pending = match self.pending {
            Pending::None => None,
            Pending::Maximize => Some(now),
            Pending::Uncloak { until, .. } => Some(until),
        };
        [self.due, pending].into_iter().flatten().min()
    }

    /// Compares the window's rectangle with the last one seen; a change saves the place
    /// [`DEBOUNCE`] later. A minimized window is passed over.
    pub fn watch<M>(&mut self, cx: &Cx<'_, M>, now: Instant) {
        let window = cx.window();
        if self.pending != Pending::None || window.is_minimized() == Some(true) {
            return;
        }
        let Some(outer) = place::outer(window) else {
            return;
        };
        let now_seen = (outer, window.is_maximized());
        if self.seen != Some(now_seen) {
            // The first look is where the start put it: nothing to save yet.
            if self.seen.is_some() {
                self.due = Some(now + DEBOUNCE);
            }
            self.seen = Some(now_seen);
        }
    }

    /// A frame is being drawn: a cloaked window whose frame is now laid out for its size (and
    /// maximized, if it waits for that) is shown.
    pub fn drawn<M>(&mut self, cx: &Cx<'_, M>) {
        let Pending::Uncloak { maximized, .. } = self.pending else {
            return;
        };
        let inner = cx.window().inner_size();
        let scale = cx.scale().max(0.05);
        let (w, h) = cx.size();
        let fits = (w - inner.width as f32 / scale).abs() < 1.0
            && (h - inner.height as f32 / scale).abs() < 1.0;
        if fits && (!maximized || cx.maximized()) {
            cloak(cx, false);
            self.pending = Pending::None;
        }
    }

    /// The wake: the pending maximize, or the save that is due. Returns the place to save.
    pub fn wake<M>(&mut self, cx: &Cx<'_, M>, now: Instant) -> Option<WindowState> {
        match self.pending {
            Pending::Maximize => {
                cx.window().set_maximized(true);
                self.pending = Pending::Uncloak {
                    until: now + UNCLOAK_LIMIT,
                    maximized: true,
                };
                return None;
            }
            Pending::Uncloak { until, .. } if until <= now => {
                cloak(cx, false);
                self.pending = Pending::None;
            }
            _ => {}
        }
        if self.due.is_some_and(|d| d <= now) {
            self.due = None;
            return self.capture(cx);
        }
        None
    }

    /// The window closes: the place as it is now, if it changed since it was saved.
    pub fn close<M>(&mut self, cx: &Cx<'_, M>) -> Option<WindowState> {
        self.due = None;
        if self.pending == Pending::Maximize {
            // Closed before the maximize was made: what was read at the start stays.
            return None;
        }
        self.capture(cx)
    }

    fn capture<M>(&mut self, cx: &Cx<'_, M>) -> Option<WindowState> {
        let now = window_state::capture(cx.window())?;
        if self.saved.as_ref() == Some(&now) {
            return None;
        }
        self.saved = Some(now.clone());
        Some(now)
    }
}

/// [`place::set`], again when the move took the window to a monitor of another scale (winit
/// resizes it for the new scale on the way).
fn set<M>(cx: &Cx<'_, M>, rect: ScreenRect) {
    let window = cx.window();
    let before = window.scale_factor();
    place::set(window, rect);
    if window.scale_factor() != before {
        place::set(window, rect);
    }
}

/// Hides (`true`) or shows the window through DWM without hiding it for the system: a cloaked
/// window can be shown and maximized unseen. False where it could not be done.
#[cfg(windows)]
fn cloak<M>(cx: &Cx<'_, M>, on: bool) -> bool {
    use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute};
    // winit's window id on Windows is the window's handle.
    let hwnd = u64::from(cx.window().id()) as usize as *mut core::ffi::c_void;
    let value: i32 = i32::from(on);
    // SAFETY: the handle is this window's, live while `window` is; the value is a BOOL of its
    // size.
    let hr = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_CLOAK as u32,
            (&raw const value).cast(),
            std::mem::size_of::<i32>() as u32,
        )
    };
    hr >= 0
}

#[cfg(not(windows))]
fn cloak<M>(_cx: &Cx<'_, M>, _on: bool) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(x: i32, y: i32, w: u32, h: u32) -> ScreenRect {
        ScreenRect { x, y, w, h }
    }

    #[test]
    fn a_small_screen_gets_ninety_percent_but_never_less_than_the_minimum() {
        // 1366x768 less a 40 px taskbar: 90% is 1229 x 655, and 655 is under the 700 minimum.
        let p = first(r(0, 0, 1366, 728), 1.0);
        assert_eq!(p, r(68, 14, 1229, 700));
    }

    #[test]
    fn a_full_hd_screen_gets_the_default_width_and_ninety_percent_of_the_height() {
        let p = first(r(0, 0, 1920, 1040), 1.0);
        assert_eq!(p, r(220, 52, 1480, 936));
    }

    #[test]
    fn a_4k_screen_at_scale_2_is_the_same_logical_size() {
        let p = first(r(0, 0, 3840, 2080), 2.0);
        assert_eq!(p, r(440, 104, 2960, 1872));
    }

    #[test]
    fn a_large_screen_gets_the_default_and_a_secondary_monitor_is_offset() {
        let p = first(r(-2560, 100, 2560, 1400), 1.0);
        assert_eq!(p, r(-2560 + 540, 100 + 230, 1480, 940));
    }

    #[test]
    fn a_work_area_smaller_than_the_minimum_is_filled_not_exceeded() {
        let p = first(r(0, 0, 1024, 600), 1.0);
        assert_eq!(p, r(0, 0, 1024, 600));
        // Nonsense scale is taken for 1.
        assert_eq!(first(r(0, 0, 1920, 1040), f32::NAN), r(220, 52, 1480, 936));
    }

    #[test]
    fn a_saved_size_under_the_minimum_is_raised_to_it() {
        let s = WindowState::from_setting(
            "x=10;y=20;w=400;h=300;max=0;scale=1;mon=A;monx=0;mony=0;monw=1920;monh=1080",
        )
        .unwrap();
        let m = at_least_min(&s);
        assert_eq!(
            (m.rect.x, m.rect.y, m.rect.w, m.rect.h),
            (10.0, 20.0, 1080.0, 700.0)
        );
    }
}
