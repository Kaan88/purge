//! The toolkit dialog's window: the toolkit's host loop ([`mdshared_ui::host`]) around one
//! [`Prompt`] at a time. It turns the host's events into calls on the prompt, draws it
//! ([`super::draw`]), gives UI Automation its tree ([`super::access`]) and tells its [`Desk`] when the
//! dialog is up and how it ended. It decides nothing itself: every rule is the prompt's.
//!
//! **One window for the whole process.** The host's loop can be made once in a process, and only on
//! the thread the process started on, so the window lives as long as the broker and is hidden between
//! dialogs. Before it is hidden it is painted blank, and a dialog is drawn before it counts as shown,
//! so that the words of one dialog are never on screen as another.
//!
//! **The window is the broker's alone.** It has no owner window and is never made a child of
//! another; the host creates it as a top-level window of this process. It asks for the foreground
//! once per dialog with a plain `SetForegroundWindow` ([`purge_win::topwindow::raise`]), which works
//! because the UI called `AllowSetForegroundWindow` for the broker, and flashes otherwise.

use std::sync::Arc;

use mdshared_ui::a11y::{self, Request, Tree};
use mdshared_ui::cursor::Cursor;
use mdshared_ui::gfx::{Gfx, Painter, Rect};
use mdshared_ui::host::{App, Button, Cx, Event, Proxy};
use mdshared_ui::scroll::offset_for_thumb;
use purge_win::taskdialog::Outcome;
use purge_win::topwindow;
use winit::dpi::LogicalSize;
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};

use super::super::sheet::Sheet;
use super::access;
use super::draw::{Frame, Hit, LINE, Layout, MAX_HEIGHT, Metrics, WIDTH, draw, measure};
use super::look::Look;
use super::state::{ARM_DELAY, Did, Prompt, Scroll};

/// What reaches the window from other threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    /// Dialog `id` is waiting at the desk: take it and show it.
    Show(u64),
    /// Dialog `id` is no longer wanted (the broker is ending): take it down. Its answer is the
    /// desk's business already.
    Close(u64),
    /// End the loop. Only the preview sends it: the broker's window lives as long as the broker.
    Quit,
}

/// Who the window shows dialogs for: the broker's consent service, or the preview.
pub trait Desk: 'static {
    /// The loop runs; `proxy` reaches it from any thread.
    fn started(&self, proxy: Proxy<Msg>);
    /// The dialog to show: `id`'s, or with `None` whichever is waiting. `None` when it is no
    /// longer wanted. A dialog is handed out once.
    fn take(&self, id: Option<u64>) -> Option<(u64, Arc<Sheet>)>;
    /// Dialog `id` is on screen and can be answered.
    fn shown(&self, id: u64);
    /// Dialog `id` was answered.
    fn answered(&self, id: u64, outcome: Outcome);
    /// A frame of dialog `id` was drawn into `p`; `open_for_ms` since it was first on screen. For
    /// the preview's pictures; nothing by default.
    fn frame(&self, id: u64, p: &mut Painter, open_for_ms: u128) {
        let _ = (id, p, open_for_ms);
    }
}

/// The dialog on screen.
struct Open {
    id: u64,
    prompt: Prompt,
    metrics: Option<Metrics>,
    layout: Option<Layout>,
    scroll: f32,
    /// The desk was told it is up.
    told: bool,
}

/// The window's application.
pub struct ConsentApp<D: Desk> {
    desk: D,
    /// Measures a sheet before its first frame, to size the window.
    gfx: Gfx,
    look: Look,
    /// A look given by hand (the preview); the system's otherwise.
    fixed_look: Option<Look>,
    open: Option<Open>,
    hover: Option<Hit>,
    pressed: Option<Hit>,
    /// The thumb is dragged: where on it the pointer took hold.
    grip: Option<f32>,
    /// The blank frame is drawn; the window is hidden at the next wake.
    hide: bool,
}

/// The size a dialog for `sheet` opens at, logical px, on a screen whose work area is `work_h` high.
pub fn opening_size(gfx: &mut Gfx, sheet: &Sheet, scale: f32, work_h: Option<f32>) -> (f32, f32) {
    let mut scratch = mdshared_text::Bitmap::new(1, 1);
    let m = measure(
        &mut Painter::new(&mut scratch, gfx, scale),
        sheet,
        WIDTH,
        scale,
    );
    (
        WIDTH,
        m.window_height(work_h.map_or(MAX_HEIGHT, |h| h - 48.0)),
    )
}

/// The height of the work area the cursor is on, logical px at `scale`.
pub fn work_height(scale: f32) -> Option<f32> {
    let (_, top, _, bottom) = topwindow::cursor_work_area()?;
    Some((bottom - top) as f32 / scale.max(0.25))
}

impl<D: Desk> ConsentApp<D> {
    /// An application that shows the desk's dialogs. `look`: a look given by hand, or `None` for
    /// the system's.
    pub fn new(desk: D, look: Option<Look>) -> ConsentApp<D> {
        ConsentApp {
            desk,
            gfx: Gfx::new(),
            look: look.unwrap_or_else(|| Look::of(false, false)),
            fixed_look: look,
            open: None,
            hover: None,
            pressed: None,
            grip: None,
            hide: false,
        }
    }

    fn hwnd(cx: &Cx<'_, Msg>) -> Option<isize> {
        match cx.window().window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
            _ => None,
        }
    }

    fn retheme(&mut self, cx: &mut Cx<'_, Msg>) {
        self.look = self
            .fixed_look
            .unwrap_or_else(|| Look::system(cx.high_contrast()));
        cx.set_dark(self.look.pal.dark);
        cx.request_redraw_all();
    }

    /// Takes dialog `id` (or whichever waits) from the desk and puts it in the window: sized to
    /// what it says, centred on the monitor the cursor is on. `first`: the host shows the window
    /// itself after the first frame.
    fn show(&mut self, cx: &mut Cx<'_, Msg>, id: Option<u64>, first: bool) {
        let Some((id, sheet)) = self.desk.take(id) else {
            return;
        };
        if let Some(old) = self.open.take() {
            // Never two at once: the one before is closed as Cancel.
            self.desk.answered(old.id, Outcome::Declined);
        }
        let scale = cx.scale();
        let (w, h) = opening_size(&mut self.gfx, &sheet, scale, work_height(scale));
        let _ = cx.window().request_inner_size(LogicalSize::new(w, h));
        if let (Some(hwnd), Some(work)) = (Self::hwnd(cx), topwindow::cursor_work_area()) {
            topwindow::center_on(hwnd, work);
        }
        self.open = Some(Open {
            id,
            prompt: Prompt::new(sheet),
            metrics: None,
            layout: None,
            scroll: 0.0,
            told: false,
        });
        self.hover = None;
        self.pressed = None;
        self.grip = None;
        self.hide = false;
        if !first {
            cx.window().set_visible(true);
        }
        cx.request_redraw_all();
    }

    /// The dialog ended: the desk is told, and the window is painted blank and then hidden.
    fn finish(&mut self, cx: &mut Cx<'_, Msg>, outcome: Outcome) {
        if let Some(open) = self.open.take() {
            self.desk.answered(open.id, outcome);
        }
        self.take_down(cx);
    }

    fn take_down(&mut self, cx: &mut Cx<'_, Msg>) {
        self.open = None;
        self.hover = None;
        self.pressed = None;
        self.grip = None;
        self.hide = false;
        cx.request_redraw_all();
    }

    fn did(&mut self, cx: &mut Cx<'_, Msg>, did: Did) {
        match did {
            Did::Nothing => {}
            Did::Changed => cx.request_redraw_all(),
            Did::Scroll(by) => self.scroll(cx, by),
            Did::Answered(outcome) => self.finish(cx, outcome),
        }
    }

    fn scroll_to(&mut self, cx: &mut Cx<'_, Msg>, to: f32) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let max = open.layout.as_ref().map_or(0.0, |l| l.max_scroll);
        let to = if to.is_finite() {
            to.clamp(0.0, max)
        } else {
            0.0
        };
        if to != open.scroll {
            open.scroll = to;
            cx.request_redraw_all();
        }
    }

    fn scroll(&mut self, cx: &mut Cx<'_, Msg>, by: Scroll) {
        let Some(open) = self.open.as_ref() else {
            return;
        };
        let page = open.layout.as_ref().map_or(0.0, |l| l.body.h - LINE);
        let to = match by {
            Scroll::Lines(n) => open.scroll + n as f32 * LINE,
            Scroll::Pages(n) => open.scroll + n as f32 * page.max(LINE),
            Scroll::Top => 0.0,
            Scroll::End => f32::MAX,
        };
        self.scroll_to(cx, to);
    }

    fn hit(&self, x: f32, y: f32) -> Option<Hit> {
        self.open
            .as_ref()
            .and_then(|o| o.layout.as_ref())
            .and_then(|l| l.hit(x, y))
    }

    fn pointer_move(&mut self, cx: &mut Cx<'_, Msg>, x: f32, y: f32) {
        if let (Some(grip), Some(open)) = (self.grip, self.open.as_ref())
            && let (Some(lay), Some(m)) = (open.layout.as_ref(), open.metrics.as_ref())
            && let Some((track, thumb)) = lay.bar
        {
            let to = offset_for_thumb(track, thumb.h, y - grip, m.content_h, lay.body.h);
            self.scroll_to(cx, to);
            return;
        }
        let hover = self.hit(x, y);
        if hover != self.hover {
            self.hover = hover;
            cx.request_redraw_all();
        }
        cx.set_cursor(Cursor::Default);
    }

    fn press(&mut self, cx: &mut Cx<'_, Msg>, x: f32, y: f32) {
        let now = cx.now();
        let hit = self.hit(x, y);
        let Some(open) = self.open.as_mut() else {
            return;
        };
        match hit {
            Some(Hit::Ctl(ctl)) => {
                self.pressed = hit;
                open.prompt.pointer_on(ctl, now);
            }
            Some(Hit::Thumb) => {
                self.pressed = hit;
                let top = open
                    .layout
                    .as_ref()
                    .and_then(|l| l.bar)
                    .map_or(y, |(_, thumb)| thumb.y);
                self.grip = Some(y - top);
                open.prompt.pointer_used();
            }
            Some(Hit::Track) => {
                open.prompt.pointer_used();
                let above = open
                    .layout
                    .as_ref()
                    .and_then(|l| l.bar)
                    .is_some_and(|(_, thumb)| y < thumb.y);
                self.scroll(cx, Scroll::Pages(if above { -1 } else { 1 }));
            }
            Some(Hit::Title) => {
                open.prompt.pointer_used();
                cx.drag_window();
            }
            None => {
                open.prompt.pointer_used();
            }
        }
        cx.request_redraw_all();
    }

    fn release(&mut self, cx: &mut Cx<'_, Msg>, x: f32, y: f32) {
        let now = cx.now();
        self.pressed = None;
        self.grip = None;
        cx.request_redraw_all();
        // What a click is, and whether this was one, is the prompt's to say.
        let over = match self.hit(x, y) {
            Some(Hit::Ctl(ctl)) => Some(ctl),
            _ => None,
        };
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let did = open.prompt.pointer_up(over, now);
        self.did(cx, did);
    }

    fn action(&mut self, cx: &mut Cx<'_, Msg>, request: Request) {
        let now = cx.now();
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let did = match request {
            Request::Click(node) => match access::ctl_of(node) {
                Some(ctl) => open.prompt.press(ctl, now),
                None => Did::Nothing,
            },
            Request::Focus(node) => match access::ctl_of(node) {
                Some(ctl) => open.prompt.focus_on(ctl, now),
                None => Did::Nothing,
            },
            _ => Did::Nothing,
        };
        self.did(cx, did);
    }
}

impl<D: Desk> App for ConsentApp<D> {
    type Message = Msg;

    fn start(&mut self, cx: &mut Cx<'_, Msg>) {
        self.desk.started(cx.proxy());
        cx.window().set_resizable(false);
        self.retheme(cx);
        self.show(cx, None, true);
    }

    fn event(&mut self, cx: &mut Cx<'_, Msg>, event: Event) {
        let now = cx.now();
        match event {
            Event::PointerMove { x, y } => self.pointer_move(cx, x, y),
            Event::PointerLeave => {
                if self.hover.take().is_some() {
                    cx.request_redraw_all();
                }
            }
            Event::Press {
                x,
                y,
                button: Button::Left,
                ..
            } => self.press(cx, x, y),
            Event::Release {
                x,
                y,
                button: Button::Left,
            } => self.release(cx, x, y),
            Event::Wheel { dy, .. } => {
                if let Some(open) = self.open.as_mut() {
                    open.prompt.pointer_used();
                    let to = open.scroll - dy;
                    self.scroll_to(cx, to);
                }
            }
            Event::Key(press) => {
                let (Some(name), Some(open)) = (press.name, self.open.as_mut()) else {
                    return;
                };
                let did = open.prompt.key(&name, press.mods, press.repeat, now);
                self.did(cx, did);
            }
            Event::Focus(_) => cx.request_redraw_all(),
            Event::Scale(_) | Event::Resize { .. } => {
                if let Some(open) = self.open.as_mut() {
                    open.metrics = None;
                }
                cx.request_redraw_all();
            }
            Event::Theme { .. } | Event::Contrast(_) => self.retheme(cx),
            Event::Wake(_) => {
                if self.hide && self.open.is_none() {
                    // The blank frame is on screen: nothing more is drawn until the next dialog.
                    self.hide = false;
                    if cx.window().is_visible().unwrap_or(true) {
                        cx.window().set_visible(false);
                    }
                    return;
                }
                // The button arms by the clock, and a first frame drawn before the window was
                // shown is drawn again now that it is.
                cx.request_redraw_all();
            }
            // The close box of the system, Alt+F4, the taskbar: Cancel.
            Event::CloseRequested => {
                let did = self.open.as_mut().map(|o| o.prompt.cancel());
                match did {
                    Some(did) => self.did(cx, did),
                    None => self.take_down(cx),
                }
            }
            Event::Action(request) => self.action(cx, a11y::request(request)),
            _ => {}
        }
    }

    fn draw(&mut self, cx: &mut Cx<'_, Msg>, p: &mut Painter, _damage: Rect) {
        let now = cx.now();
        let size = cx.size();
        let scale = cx.scale();
        let Some(open) = self.open.as_mut() else {
            // Blank, so that nothing of the last dialog is in the window when it is hidden, nor
            // when it is next shown.
            p.fill(Rect::new(0.0, 0.0, size.0, size.1), self.look.pal.popup);
            // Also for a first frame drawn before the window was shown (the dialog it started for
            // was withdrawn meanwhile): the host shows the window next, and the wake hides it.
            self.hide = true;
            cx.wake_at(now);
            cx.accessibility_changed();
            return;
        };
        let visible = cx.window().is_visible().unwrap_or(true);
        let stale = open
            .metrics
            .as_ref()
            .is_none_or(|m| m.width != size.0 || m.scale != scale);
        if stale {
            open.metrics = Some(measure(p, open.prompt.sheet(), size.0, scale));
        }
        let Some(m) = open.metrics.as_ref() else {
            return;
        };
        let lay = Layout::new(m, size, open.scroll);
        open.scroll = lay.scroll;
        if visible {
            if open.prompt.opened(now) {
                // On screen for the first time: the delay of the button runs from here.
                cx.wake_at(now + ARM_DELAY);
            }
            if lay.end_in_view() {
                open.prompt.saw_end();
            }
            if let Some(at) = open.prompt.opened_at()
                && !open.prompt.armed(now)
            {
                cx.wake_at(at + ARM_DELAY);
            }
        } else {
            // The host draws the first frame before it shows the window: come back once it has.
            cx.wake_at(now);
        }
        open.prompt.tick(now);
        let frame = Frame {
            now,
            hover: self.hover,
            pressed: self.pressed,
        };
        draw(p, &self.look, &open.prompt, m, &lay, &frame);
        cx.set_no_resize(&[Rect::new(0.0, 0.0, size.0, size.1)]);
        if let Some(at) = open.prompt.opened_at() {
            self.desk
                .frame(open.id, p, now.saturating_duration_since(at).as_millis());
        }
        open.layout = Some(lay);
        if visible && !open.told {
            open.told = true;
            if let Some(hwnd) = Self::hwnd(cx) {
                topwindow::raise(hwnd);
            }
            self.desk.shown(open.id);
        }
        cx.accessibility_changed();
    }

    fn message(&mut self, cx: &mut Cx<'_, Msg>, message: Msg) {
        match message {
            Msg::Show(id) => self.show(cx, Some(id), false),
            Msg::Close(id) => {
                if self.open.as_ref().is_some_and(|o| o.id == id) {
                    self.take_down(cx);
                }
            }
            Msg::Quit => cx.exit(),
        }
    }

    fn accessibility(&mut self, cx: &mut Cx<'_, Msg>, tree: &mut Tree) -> a11y::accesskit::NodeId {
        let now = cx.now();
        let scale = cx.scale();
        match self.open.as_ref() {
            Some(Open {
                prompt,
                metrics: Some(m),
                layout: Some(lay),
                ..
            }) => access::build(tree, scale, prompt, m, lay, now),
            _ => access::build_empty(tree, cx.title(), scale),
        }
    }
}
