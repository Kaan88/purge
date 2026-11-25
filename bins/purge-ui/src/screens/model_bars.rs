//! The bars a `purge-ui-model` page model says to show (UI-PAGES2: History and Quarantine), drawn
//! with the toolkit's info bar: each is one Text named "Title Message" (the rig reads bars so), its
//! close button and its action buttons controls of their own.

use mdshared_ui::gfx::Rect;
use mdshared_ui::infobar::{self, Hit, InfoBar, Severity, draw_infobar_with};
use purge_ui_model::info_bar::{InfoBar as ModelBar, Severity as ModelSeverity};

use crate::ui::{Id, Role, Ui};

/// The toolkit's severity for the model's.
fn severity(s: ModelSeverity) -> Severity {
    match s {
        ModelSeverity::Informational => Severity::Info,
        ModelSeverity::Success => Severity::Success,
        ModelSeverity::Warning => Severity::Warning,
        ModelSeverity::Error => Severity::Error,
    }
}

/// Draws `bar` at `(x, y)`, `w` wide, as the control `host`; `close` names its close button when
/// the bar can be closed, and `actions` its buttons (id and label), at most two. Returns the y
/// under it.
#[allow(clippy::too_many_arguments)] // a place, the bar and the ids of its parts
pub fn bar<A>(
    ui: &mut Ui,
    host: Id,
    x: f32,
    y: f32,
    w: f32,
    model: &ModelBar<A>,
    close: Option<Id>,
    actions: &[(Id, &str)],
) -> f32 {
    let pal = ui.pal;
    let mut bar = InfoBar::new(
        severity(model.severity),
        model.title.as_str(),
        model.message.as_str(),
    )
    .closable(model.closable && close.is_some());
    for (k, (_, label)) in actions.iter().enumerate() {
        bar = bar.action(k as u32, *label);
    }
    let h = bar.height(ui.p, w);
    let r = Rect::new(x, y, w, h);
    let label = format!("{} {}", model.title, model.message);
    ui.reg(host, r, Role::Text, label.trim(), false);
    let parts = bar.parts(ui.p, r);
    let mut look = infobar::Look {
        high_contrast: ui.hc,
        ..infobar::Look::default()
    };
    for (k, ar) in &parts.actions {
        let Some((aid, label)) = actions.get(*k as usize) else {
            continue;
        };
        ui.reg(*aid, *ar, Role::Button, label, true);
        if ui.hot(*aid) {
            look.hover = Some(Hit::Action(*k));
        }
        if ui.down(*aid) {
            look.pressed = Some(Hit::Action(*k));
        }
        if ui.ringed(*aid) {
            look.focused = Some(Hit::Action(*k));
        }
    }
    if let (Some(cid), Some(cr)) = (close, parts.close) {
        ui.reg(cid, cr, Role::Button, "Close", true);
        if ui.hot(cid) {
            look.hover = Some(Hit::Close);
        }
        if ui.down(cid) {
            look.pressed = Some(Hit::Close);
        }
        if ui.ringed(cid) {
            look.focused = Some(Hit::Close);
        }
    }
    draw_infobar_with(ui.p, &pal, r, &bar, look);
    y + h
}
