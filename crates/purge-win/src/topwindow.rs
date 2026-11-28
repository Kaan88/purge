//! Placing and raising a top-level window of this process: what the consent dialogs share. The
//! TaskDialog ([`crate::taskdialog`]) centres itself on the work area of the monitor the cursor is on
//! and asks for the foreground when it is created; the broker's toolkit dialog does the same for its
//! own window through these functions.
//!
//! Nothing here takes the foreground by a trick: [`raise`] is a plain `SetForegroundWindow`, which
//! works when the UI called `AllowSetForegroundWindow` for this process, and flashes the taskbar
//! button when it does not.

use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FlashWindowEx, GetCursorPos, GetWindowRect, SW_HIDE,
    SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SetForegroundWindow, SetWindowPos, ShowWindow,
};

/// A work area or a window, device px: `(left, top, right, bottom)`.
pub type Area = (i32, i32, i32, i32);

/// Top-left corner that centres a `w` x `h` window on `work` and, when it is larger than the work area,
/// keeps its top left corner (title bar and first lines) on screen.
pub fn centered(work: Area, w: i32, h: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work;
    let x = left + ((right - left) - w) / 2;
    let y = top + ((bottom - top) - h) / 2;
    (x.max(left), y.max(top))
}

/// Work area of the monitor that holds the cursor, nearest monitor when it is in none.
pub fn cursor_work_area() -> Option<Area> {
    let mut pt = POINT { x: 0, y: 0 };
    // SAFETY: `pt` is a valid out pointer.
    if unsafe { GetCursorPos(&mut pt) } == 0 {
        return None;
    }
    // SAFETY: plain value argument.
    let monitor = unsafe { MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_null() {
        return None;
    }
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` has its size set and is a valid out pointer.
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
        return None;
    }
    let w = info.rcWork;
    Some((w.left, w.top, w.right, w.bottom))
}

/// Moves window `hwnd` to the centre of `work` without resizing, restacking or activating it. False
/// when the window's rectangle cannot be read or it cannot be moved.
pub fn center_on(hwnd: isize, work: Area) -> bool {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: `rect` is a valid out pointer; a stale handle just fails.
    if unsafe { GetWindowRect(hwnd as HWND, &mut rect) } == 0 {
        return false;
    }
    let (x, y) = centered(work, rect.right - rect.left, rect.bottom - rect.top);
    // SAFETY: moves a window of this process; a stale handle just fails.
    unsafe {
        SetWindowPos(
            hwnd as HWND,
            std::ptr::null_mut(),
            x,
            y,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        ) != 0
    }
}

/// Asks for the foreground for `hwnd`, and flashes its taskbar button three times when the system
/// refuses. True when the window is in the foreground.
pub fn raise(hwnd: isize) -> bool {
    // SAFETY: plain window calls; a stale handle just fails.
    unsafe {
        if SetForegroundWindow(hwnd as HWND) != 0 {
            return true;
        }
        let info = FLASHWINFO {
            cbSize: size_of::<FLASHWINFO>() as u32,
            hwnd: hwnd as HWND,
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 3,
            dwTimeout: 0,
        };
        FlashWindowEx(&info);
    }
    false
}

/// Hides window `hwnd` at once. Call it on the thread that owns the window. For a window whose
/// thread is about to stop for good (a panic on it): what it shows is nobody's any more, and it
/// will not paint or answer again. A stale handle just fails.
pub fn hide(hwnd: isize) {
    // SAFETY: plain window call; a stale handle just fails.
    unsafe {
        ShowWindow(hwnd as HWND, SW_HIDE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centring_on_a_work_area() {
        // A second monitor to the left, with a negative origin.
        assert_eq!(centered((-1920, 0, 0, 1040), 520, 400), (-1220, 320));
        assert_eq!(centered((0, 0, 1920, 1040), 520, 400), (700, 320));
        // Taller than the work area: the top stays on screen.
        assert_eq!(centered((0, 40, 1280, 760), 600, 1500), (340, 40));
        // Wider than the work area: the left edge stays on screen.
        assert_eq!(centered((100, 0, 900, 700), 1000, 300), (100, 200));
    }

    #[test]
    fn a_window_that_is_not_there_is_neither_moved_nor_raised() {
        assert!(!center_on(0, (0, 0, 800, 600)));
        assert!(!raise(0));
        hide(0);
    }
}
