//! `TaskDialogIndirect` wrapper for the broker's consent dialog (M3 design section 8, package M3-WIN-TASKDLG).
//!
//! The dialog runs on its own thread. A [`Page`] describes one dialog page; several pages are chained with
//! `TDM_NAVIGATE_PAGE` and the wrapper adds "Back" and "Next" buttons. The caller's own buttons are custom
//! buttons with ids at or above [`MIN_BUTTON_ID`]; Cancel is always present, is the default unless the page
//! says otherwise, and is what Esc, Alt+F4 and the close box return.
//!
//! Rules kept here: no hyperlinks, no command links, no radio buttons, no owner window, no timeout
//! answer. The primary button is armed about a second after its page shows, so a click aimed at another
//! window cannot land on it. [`Outcome::Approved`] is returned only for the primary id, and when that
//! button is gated by the verification box, only if the box was ticked. Every other end, including a
//! close from another thread, is [`Outcome::Declined`]; a failure to show is an `Err` that the caller
//! treats the same way.
//!
//! The window is centred on the work area of the monitor the cursor is on when it is created, and again
//! after every page change (a page resizes it); a window larger than the work area keeps its top left
//! corner on screen.
//!
//! `comctl32` v6 is needed for `TaskDialogIndirect`; the binary carries a manifest for it
//! (`bins/purge-broker/purge-broker.manifest`). The function is looked up at run time, so a process without the
//! manifest (a test binary) links and loads fine and showing returns `ErrorKind::Unsupported`.
//!
//! Strings: each page is built into a [`Built`] that owns every wide string and button array its config points
//! at. All built pages live in the dialog thread's state until the dialog ends, so the pointers stay valid for
//! `TDM_NAVIGATE_PAGE` too.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::UI::Controls::{TASKDIALOG_BUTTON, TASKDIALOGCONFIG};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FlashWindowEx, GetCursorPos, GetWindowRect,
    PostMessageW, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SendMessageW, SetForegroundWindow,
    SetWindowPos,
};
use windows_sys::core::{BOOL, HRESULT, PCWSTR};

/// Lowest id a caller's custom button may use. Ids 1 to 8 are the common buttons.
pub const MIN_BUTTON_ID: i32 = 100;
/// Ids the wrapper uses for its paging buttons.
const ID_NEXT: i32 = 9001;
const ID_BACK: i32 = 9002;
const ID_CANCEL: i32 = 2;

const TDCBF_CANCEL_BUTTON: i32 = 0x8;
const TDF_ALLOW_DIALOG_CANCELLATION: i32 = 0x8;
const TDF_CALLBACK_TIMER: i32 = 0x0000_0800;
const TDF_SIZE_TO_CONTENT: i32 = 0x0100_0000;

/// How long the primary button stays disabled after its page shows (review M3-R1 S6): an approving
/// click cannot land on the instant the dialog appears under the user's cursor.
const ARM_DELAY: Duration = Duration::from_secs(1);

const WM_USER: u32 = 0x400;
const TDM_NAVIGATE_PAGE: u32 = WM_USER + 101;
const TDM_CLICK_BUTTON: u32 = WM_USER + 102;
const TDM_ENABLE_BUTTON: u32 = WM_USER + 111;

const TDN_CREATED: u32 = 0;
const TDN_NAVIGATED: u32 = 1;
const TDN_BUTTON_CLICKED: u32 = 2;
const TDN_TIMER: u32 = 4;
const TDN_DESTROYED: u32 = 5;
const TDN_VERIFICATION_CLICKED: u32 = 8;

/// `TD_WARNING_ICON` and `TD_SHIELD_ICON` as `MAKEINTRESOURCE` values.
const TD_WARNING_ICON: usize = 0xFFFF;
const TD_SHIELD_ICON: usize = 0xFFFC;

/// Main icon of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Icon {
    /// No icon.
    #[default]
    None,
    /// The UAC shield.
    Shield,
    /// The warning triangle.
    Warning,
}

/// A custom button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    /// Id at or above [`MIN_BUTTON_ID`], unique across all pages.
    pub id: i32,
    /// Label.
    pub label: String,
}

/// One dialog page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// Window title.
    pub title: String,
    /// Main instruction (the large text).
    pub instruction: String,
    /// Content text.
    pub content: String,
    /// Expanded information, collapsed behind "Show details".
    pub expanded: Option<String>,
    /// Footer text.
    pub footer: Option<String>,
    /// Main icon.
    pub icon: Icon,
    /// Custom buttons of this page, in order. Paging buttons are added by the wrapper.
    pub buttons: Vec<Button>,
    /// Button that has the focus; `None` means Cancel.
    pub default_button: Option<i32>,
    /// Text of the verification box; `None` for no box.
    pub verification: Option<String>,
    /// Button id that is disabled until the verification box is ticked. Needs `verification`.
    pub gated_button: Option<i32>,
}

/// How a dialog ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The primary button was clicked (and its gate, if any, was open).
    Approved,
    /// Anything else.
    Declined,
}

/// A page with every string and array its config points at.
struct Built {
    config: TASKDIALOGCONFIG,
    // Owned storage behind the pointers in `config`; never read, kept alive.
    _strings: Vec<Vec<u16>>,
    _buttons: Vec<TASKDIALOG_BUTTON>,
    /// Ids of all custom buttons of this page, including paging buttons.
    button_ids: Vec<i32>,
    gated: Option<i32>,
}

// SAFETY: the raw pointers in `config` refer only to heap data owned by the same `Built`, so the value
// can move to the dialog thread whole.
unsafe impl Send for Built {}

fn wide(s: &str) -> io::Result<Vec<u16>> {
    if s.contains('\0') {
        return Err(invalid("text contains a NUL"));
    }
    Ok(s.encode_utf16().chain(Some(0)).collect())
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

/// Checks the pages as a whole: ids, the gate, where the primary button is.
fn validate(pages: &[Page], primary: i32) -> io::Result<()> {
    if pages.is_empty() {
        return Err(invalid("no pages"));
    }
    if primary < MIN_BUTTON_ID || primary == ID_NEXT || primary == ID_BACK {
        return Err(invalid("primary id is not a custom id"));
    }
    let mut seen: Vec<i32> = Vec::new();
    let last = pages.len() - 1;
    let mut primary_pages = 0;
    for (i, p) in pages.iter().enumerate() {
        for b in &p.buttons {
            if b.id < MIN_BUTTON_ID || b.id == ID_NEXT || b.id == ID_BACK {
                return Err(invalid("button id is reserved"));
            }
            if seen.contains(&b.id) {
                return Err(invalid("duplicate button id"));
            }
            seen.push(b.id);
            if b.id == primary {
                primary_pages += 1;
                if i != last {
                    return Err(invalid("primary button must be on the last page"));
                }
            }
        }
        if let Some(d) = p.default_button
            && d != ID_CANCEL
            && !p.buttons.iter().any(|b| b.id == d)
        {
            return Err(invalid("default button is not on the page"));
        }
        if let Some(g) = p.gated_button {
            if p.verification.is_none() {
                return Err(invalid("gated button needs a verification box"));
            }
            if !p.buttons.iter().any(|b| b.id == g) {
                return Err(invalid("gated button is not on the page"));
            }
        }
    }
    if primary_pages != 1 {
        return Err(invalid("primary button must appear exactly once"));
    }
    Ok(())
}

fn build_page(page: &Page, index: usize, count: usize) -> io::Result<Built> {
    let mut strings: Vec<Vec<u16>> = Vec::new();
    let mut keep = |s: &str| -> io::Result<PCWSTR> {
        let w = wide(s)?;
        let ptr = w.as_ptr();
        strings.push(w);
        Ok(ptr)
    };
    let title = keep(&page.title)?;
    let instruction = keep(&page.instruction)?;
    let content = keep(&page.content)?;
    let expanded = page.expanded.as_deref().map(&mut keep).transpose()?;
    let footer = page.footer.as_deref().map(&mut keep).transpose()?;
    let verification = page.verification.as_deref().map(&mut keep).transpose()?;
    let collapsed_text = keep("Show details")?;
    let expanded_text = keep("Hide details")?;

    let mut labels: Vec<(i32, PCWSTR)> = Vec::new();
    for b in &page.buttons {
        labels.push((b.id, keep(&b.label)?));
    }
    if index > 0 {
        labels.push((ID_BACK, keep("Back")?));
    }
    if index + 1 < count {
        labels.push((ID_NEXT, keep("Next")?));
    }
    let buttons: Vec<TASKDIALOG_BUTTON> = labels
        .iter()
        .map(|&(id, text)| TASKDIALOG_BUTTON {
            nButtonID: id,
            pszButtonText: text,
        })
        .collect();
    let button_ids: Vec<i32> = labels.iter().map(|l| l.0).collect();

    let mut config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT | TDF_CALLBACK_TIMER,
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: title,
        pszMainInstruction: instruction,
        pszContent: content,
        cButtons: buttons.len() as u32,
        pButtons: if buttons.is_empty() {
            std::ptr::null()
        } else {
            buttons.as_ptr()
        },
        nDefaultButton: page.default_button.unwrap_or(ID_CANCEL),
        pszVerificationText: verification.unwrap_or(std::ptr::null()),
        ..Default::default()
    };
    if let Some(e) = expanded {
        config.pszExpandedInformation = e;
        config.pszCollapsedControlText = collapsed_text;
        config.pszExpandedControlText = expanded_text;
    }
    config.pszFooter = footer.unwrap_or(std::ptr::null());
    config.Anonymous1.pszMainIcon = match page.icon {
        Icon::None => std::ptr::null(),
        Icon::Shield => TD_SHIELD_ICON as PCWSTR,
        Icon::Warning => TD_WARNING_ICON as PCWSTR,
    };
    Ok(Built {
        config,
        _strings: strings,
        _buttons: buttons,
        button_ids,
        gated: page.gated_button,
    })
}

fn build_all(pages: &[Page], primary: i32) -> io::Result<Vec<Built>> {
    validate(pages, primary)?;
    let n = pages.len();
    pages
        .iter()
        .enumerate()
        .map(|(i, p)| build_page(p, i, n))
        .collect()
}

/// State shared between the dialog thread and other threads.
struct Shared {
    hwnd: AtomicIsize,
    close_requested: AtomicBool,
    created: Mutex<bool>,
    created_cv: Condvar,
}

impl Shared {
    fn click_cancel(&self) {
        let h = self.hwnd.load(Ordering::SeqCst);
        if h != 0 {
            // SAFETY: PostMessageW is sound for any handle value; a stale handle just fails.
            unsafe { PostMessageW(h as HWND, TDM_CLICK_BUTTON, ID_CANCEL as WPARAM, 0) };
        }
    }
}

/// Dialog-thread state, reached from the callback through `lpCallbackData`.
struct State {
    pages: Vec<Built>,
    current: usize,
    primary: i32,
    verified: bool,
    clicked: i32,
    /// When the primary button of the current page may be enabled; `None` when there is nothing to arm.
    arm_at: Option<Instant>,
    /// Work area `(left, top, right, bottom)` of the monitor the cursor was on when the window was
    /// created; every page is centred on it.
    work_area: Option<(i32, i32, i32, i32)>,
    shared: Arc<Shared>,
}

/// Top-left corner that centres a `w` x `h` window on `work` and, when it is larger than the work area,
/// keeps its top left corner (title bar and first lines) on screen.
fn centered(work: (i32, i32, i32, i32), w: i32, h: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work;
    let x = left + ((right - left) - w) / 2;
    let y = top + ((bottom - top) - h) / 2;
    (x.max(left), y.max(top))
}

/// Work area of the monitor that holds the cursor, nearest monitor when it is in none.
fn cursor_work_area() -> Option<(i32, i32, i32, i32)> {
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

/// Moves the dialog to the centre of the work area chosen at creation. A page change resizes the window,
/// so this runs again after every navigation.
fn place(st: &State, hwnd: HWND) {
    let Some(work) = st.work_area else {
        return;
    };
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: `rect` is a valid out pointer; the window is the dialog's own.
    if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
        return;
    }
    let (x, y) = centered(work, rect.right - rect.left, rect.bottom - rect.top);
    // SAFETY: moves the dialog's own window without resizing, restacking or activating it.
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            x,
            y,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

unsafe extern "system" fn callback(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    _lparam: LPARAM,
    refdata: isize,
) -> HRESULT {
    // SAFETY: `refdata` is the `State` pointer set in `run`, alive and used only on this thread.
    let st = unsafe { &mut *(refdata as *mut State) };
    match msg {
        TDN_CREATED => {
            st.shared.hwnd.store(hwnd as isize, Ordering::SeqCst);
            st.work_area = cursor_work_area();
            place(st, hwnd);
            // SAFETY: plain window calls on the dialog's own handle.
            unsafe {
                if SetForegroundWindow(hwnd) == 0 {
                    let info = FLASHWINFO {
                        cbSize: size_of::<FLASHWINFO>() as u32,
                        hwnd,
                        dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
                        uCount: 3,
                        dwTimeout: 0,
                    };
                    FlashWindowEx(&info);
                }
            }
            apply_gate(st, hwnd);
            delay_primary(st, hwnd);
            if let Ok(mut c) = st.shared.created.lock() {
                *c = true;
                st.shared.created_cv.notify_all();
            }
            if st.shared.close_requested.load(Ordering::SeqCst) {
                st.shared.click_cancel();
            }
        }
        TDN_NAVIGATED => {
            st.verified = false;
            apply_gate(st, hwnd);
            delay_primary(st, hwnd);
            place(st, hwnd);
            if st.shared.close_requested.load(Ordering::SeqCst) {
                st.shared.click_cancel();
            }
        }
        TDN_TIMER => arm_primary(st, hwnd),
        TDN_VERIFICATION_CLICKED => {
            st.verified = wparam != 0;
            if let Some(g) = st.pages[st.current].gated {
                // A gated primary button is also held back by the arming delay: ticking the box in
                // the first second does not enable it, the timer does once the delay has passed.
                let enable = st.verified && (g != st.primary || st.arm_at.is_none());
                // SAFETY: message to the dialog window.
                unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON, g as WPARAM, isize::from(enable)) };
            }
        }
        TDN_BUTTON_CLICKED => {
            let id = wparam as i32;
            if id == ID_NEXT && st.current + 1 < st.pages.len() {
                return navigate(st, hwnd, st.current + 1);
            }
            if id == ID_BACK && st.current > 0 {
                return navigate(st, hwnd, st.current - 1);
            }
            if id == ID_NEXT || id == ID_BACK {
                return 1;
            }
            // Only Cancel and the page's own buttons can end the dialog.
            if id != ID_CANCEL && !st.pages[st.current].button_ids.contains(&id) {
                return 1;
            }
            // Belt and braces: a gated primary button never ends the dialog unticked.
            if id == st.primary && st.pages[st.current].gated.is_some() && !st.verified {
                return 1;
            }
            st.clicked = id;
        }
        TDN_DESTROYED => st.shared.hwnd.store(0, Ordering::SeqCst),
        _ => {}
    }
    0
}

fn navigate(st: &mut State, hwnd: HWND, to: usize) -> HRESULT {
    st.current = to;
    let cfg: *const TASKDIALOGCONFIG = &st.pages[to].config;
    // SAFETY: the config and everything it points at live in `st.pages` until the dialog ends.
    unsafe { SendMessageW(hwnd, TDM_NAVIGATE_PAGE, 0, cfg as LPARAM) };
    1 // keep the dialog open
}

fn apply_gate(st: &State, hwnd: HWND) {
    if let Some(g) = st.pages[st.current].gated {
        // SAFETY: message to the dialog window.
        unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON, g as WPARAM, 0) };
    }
}

/// Disables the primary button of the current page and starts its arming delay. The primary is only on
/// the last page (`validate`); on any other page there is nothing to delay.
fn delay_primary(st: &mut State, hwnd: HWND) {
    if !st.pages[st.current].button_ids.contains(&st.primary) {
        st.arm_at = None;
        return;
    }
    // SAFETY: message to the dialog window.
    unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON, st.primary as WPARAM, 0) };
    st.arm_at = Some(Instant::now() + ARM_DELAY);
}

/// Enables the primary button once [`ARM_DELAY`] has passed on the page that holds it. A gated primary
/// is enabled only if the verification box is ticked by then (otherwise the tick enables it). A timer
/// that only enables a button is not a timeout answer (review M3-R1 S6).
fn arm_primary(st: &mut State, hwnd: HWND) {
    let Some(at) = st.arm_at else {
        return;
    };
    if Instant::now() < at {
        return;
    }
    st.arm_at = None;
    if st.pages[st.current].gated != Some(st.primary) || st.verified {
        // SAFETY: message to the dialog window.
        unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON, st.primary as WPARAM, 1) };
    }
}

type TaskDialogIndirectFn =
    unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut BOOL) -> HRESULT;

fn load_task_dialog() -> io::Result<TaskDialogIndirectFn> {
    let name: Vec<u16> = "comctl32.dll\0".encode_utf16().collect();
    // SAFETY: NUL-terminated name; System32 only (the activation-context redirect to v6 still applies
    // to a bare name); the module stays loaded for the process.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: NUL-terminated ANSI name.
    let f = unsafe { GetProcAddress(module, c"TaskDialogIndirect".as_ptr().cast()) };
    match f {
        // SAFETY: the export has this signature.
        Some(f) => Ok(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskDialogIndirectFn>(f)
        }),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TaskDialogIndirect needs comctl32 v6 (application manifest)",
        )),
    }
}

fn run(pages: Vec<Built>, primary: i32, shared: Arc<Shared>) -> io::Result<Outcome> {
    let td = load_task_dialog()?;
    let mut st = Box::new(State {
        pages,
        current: 0,
        primary,
        verified: false,
        clicked: 0,
        arm_at: None,
        work_area: None,
        shared,
    });
    let st_ptr: *mut State = &mut *st;
    for b in &mut st.pages {
        b.config.pfCallback = Some(callback);
        b.config.lpCallbackData = st_ptr as isize;
    }
    let mut button = 0i32;
    let mut verified: BOOL = 0;
    let cfg: *const TASKDIALOGCONFIG = &st.pages[0].config;
    // SAFETY: the config and its strings live in `st`, which outlives the call.
    let hr = unsafe { td(cfg, &mut button, std::ptr::null_mut(), &mut verified) };
    if hr < 0 {
        return Err(io::Error::from_raw_os_error(hr));
    }
    let gated = st.pages.last().is_some_and(|p| p.gated.is_some());
    let approved = st.clicked == primary
        && button == primary
        && (!gated || (verified != 0 && st.verified))
        && !st.shared.close_requested.load(Ordering::SeqCst);
    Ok(if approved {
        Outcome::Approved
    } else {
        Outcome::Declined
    })
}

/// A dialog running on its own thread.
pub struct Dialog {
    shared: Arc<Shared>,
    thread: JoinHandle<io::Result<Outcome>>,
}

/// Closes a [`Dialog`] from any thread, as Cancel.
#[derive(Clone)]
pub struct CloseHandle(Arc<Shared>);

impl CloseHandle {
    /// Asks the dialog to end as Cancel. Safe before the window exists and after it is gone.
    pub fn close(&self) {
        self.0.close_requested.store(true, Ordering::SeqCst);
        self.0.click_cancel();
    }
}

impl Dialog {
    /// Validates and builds the pages, then shows the dialog on a new thread. `primary` is the custom id whose
    /// click means approval; it must be on the last page.
    pub fn open(pages: &[Page], primary: i32) -> io::Result<Dialog> {
        let built = build_all(pages, primary)?;
        let shared = Arc::new(Shared {
            hwnd: AtomicIsize::new(0),
            close_requested: AtomicBool::new(false),
            created: Mutex::new(false),
            created_cv: Condvar::new(),
        });
        let sh = shared.clone();
        let thread = std::thread::Builder::new()
            .name("purge-taskdialog".into())
            .spawn(move || run(built, primary, sh))?;
        Ok(Dialog { shared, thread })
    }

    /// A handle that closes the dialog from another thread.
    pub fn close_handle(&self) -> CloseHandle {
        CloseHandle(self.shared.clone())
    }

    /// Waits until the window is up (`TDN_CREATED`). Returns false on timeout or when the dialog thread ended
    /// without showing a window.
    pub fn wait_created(&self, timeout: Duration) -> bool {
        let Ok(guard) = self.shared.created.lock() else {
            return false;
        };
        let r = self
            .shared
            .created_cv
            .wait_timeout_while(guard, timeout, |c| !*c && !self.thread.is_finished());
        matches!(r, Ok((g, _)) if *g)
    }

    /// Waits for the dialog to end.
    pub fn wait(self) -> io::Result<Outcome> {
        self.thread
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("dialog thread panicked")))
    }
}

/// Validates and builds `pages` exactly as [`Dialog::open`] does, without showing anything: the rules
/// of ids, the gate and the primary button, and every string (no NUL). For callers that test the pages
/// they build.
pub fn check(pages: &[Page], primary: i32) -> io::Result<()> {
    build_all(pages, primary).map(|_| ())
}

/// Shows the dialog and waits for the answer.
pub fn show(pages: &[Page], primary: i32) -> io::Result<Outcome> {
    Dialog::open(pages, primary)?.wait()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn btn(id: i32, label: &str) -> Button {
        Button {
            id,
            label: label.into(),
        }
    }

    fn three_pages() -> Vec<Page> {
        let base = |n: &str| Page {
            title: "Purge security prompt".into(),
            instruction: format!("Page {n}"),
            content: "Items".into(),
            ..Default::default()
        };
        let mut last = base("3");
        last.buttons = vec![btn(100, "Move 22 items to quarantine")];
        last.verification = Some("I reviewed the items marked".into());
        last.gated_button = Some(100);
        last.icon = Icon::Shield;
        last.expanded = Some("more".into());
        last.footer = Some("Code A1B2-C3D4".into());
        vec![base("1"), base("2"), last]
    }

    fn wstr(p: PCWSTR) -> String {
        let mut v = Vec::new();
        let mut i = 0;
        loop {
            // SAFETY: test reads a NUL-terminated string built by `wide`.
            let c = unsafe { *p.add(i) };
            if c == 0 {
                break;
            }
            v.push(c);
            i += 1;
        }
        String::from_utf16(&v).unwrap()
    }

    #[test]
    fn structure_of_three_pages() {
        let built = build_all(&three_pages(), 100).unwrap();
        assert_eq!(built.len(), 3);
        assert_eq!(built[0].button_ids, vec![ID_NEXT]);
        assert_eq!(built[1].button_ids, vec![ID_BACK, ID_NEXT]);
        assert_eq!(built[2].button_ids, vec![100, ID_BACK]);
        assert_eq!(built[2].gated, Some(100));
        for b in &built {
            let c = b.config;
            let (size, flags, common, default) =
                (c.cbSize, c.dwFlags, c.dwCommonButtons, c.nDefaultButton);
            assert_eq!(size as usize, size_of::<TASKDIALOGCONFIG>());
            assert_eq!(common, TDCBF_CANCEL_BUTTON);
            assert_eq!(default, ID_CANCEL);
            assert_ne!(flags & TDF_ALLOW_DIALOG_CANCELLATION, 0);
            assert_ne!(flags & TDF_CALLBACK_TIMER, 0);
            // No hyperlinks, command links, radio buttons.
            assert_eq!(
                flags & !(TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT | TDF_CALLBACK_TIMER),
                0
            );
            let radio = c.cRadioButtons;
            assert_eq!(radio, 0);
        }
        let c = built[2].config;
        // SAFETY: the union was written as a resource id.
        let icon = unsafe { c.Anonymous1.pszMainIcon } as usize;
        assert_eq!(icon, TD_SHIELD_ICON);
        let (v, e, f) = (c.pszVerificationText, c.pszExpandedInformation, c.pszFooter);
        assert_eq!(wstr(v), "I reviewed the items marked");
        assert_eq!(wstr(e), "more");
        assert_eq!(wstr(f), "Code A1B2-C3D4");
        assert!(built[0].config.pszVerificationText.is_null());
    }

    #[test]
    fn strings_outlive_the_page_and_the_vec() {
        let pages = three_pages();
        let built = build_all(&pages, 100).unwrap();
        drop(pages);
        let moved: Vec<Built> = built.into_iter().rev().collect();
        let c = moved[0].config;
        let (title, content, bp, n) = (c.pszWindowTitle, c.pszContent, c.pButtons, c.cButtons);
        assert_eq!(wstr(title), "Purge security prompt");
        assert_eq!(wstr(content), "Items");
        assert_eq!(n, 2);
        // SAFETY: `pButtons` points at the page's owned button array of `n` entries.
        let first = unsafe { *bp };
        let (id, text) = (first.nButtonID, first.pszButtonText);
        assert_eq!(id, 100);
        assert_eq!(wstr(text), "Move 22 items to quarantine");
    }

    #[test]
    fn validation_rules() {
        let ok = three_pages();
        assert!(validate(&ok, 100).is_ok());
        assert!(validate(&[], 100).is_err());
        assert!(validate(&ok, 101).is_err(), "primary must exist");
        assert!(validate(&ok, 5).is_err(), "primary must be custom");

        let mut p = three_pages();
        p[0].buttons.push(btn(100, "dup"));
        assert!(validate(&p, 100).is_err(), "duplicate id");

        let mut p = three_pages();
        p[0].buttons.push(btn(ID_NEXT, "x"));
        assert!(validate(&p, 100).is_err(), "reserved id");

        let mut p = three_pages();
        p[2].verification = None;
        assert!(validate(&p, 100).is_err(), "gate without a box");

        let mut p = three_pages();
        p[2].default_button = Some(555);
        assert!(validate(&p, 100).is_err(), "default not on page");
        p[2].default_button = Some(100);
        assert!(validate(&p, 100).is_ok());

        let mut p = three_pages();
        p[0].buttons.push(btn(101, "early"));
        assert!(validate(&p, 101).is_err(), "primary only on the last page");

        let mut p = three_pages();
        p[0].content = "a\0b".into();
        assert!(build_all(&p, 100).is_err(), "NUL in text");
    }

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

    /// Without the broker manifest the test binary has comctl32 v5, so showing fails fast with
    /// Unsupported; if the function is present the dialog is closed as Cancel. Never blocks.
    #[test]
    fn open_without_manifest_does_not_block() {
        let mut one = three_pages().pop().unwrap();
        one.gated_button = None;
        one.verification = None;
        let d = Dialog::open(&[one], 100).unwrap();
        d.close_handle().close();
        let r = d.wait();
        assert!(matches!(r, Err(_) | Ok(Outcome::Declined)));
    }

    /// Interactive: three pages, a gated primary button. Needs the v6 manifest, so it only shows a dialog in a
    /// manifested host; the rig probe (M3-RIG-UAC) runs it from the broker binary.
    #[test]
    #[ignore = "shows a real dialog"]
    fn interactive_three_pages() {
        let out = show(&three_pages(), 100);
        println!("{out:?}");
    }
}
