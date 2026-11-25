//! Draws a [`ConsentView`] as TaskDialog pages (design 8) and asks. The Win32 layer
//! (`purge_win::taskdialog`) draws what [`pages`] returns and nothing else; the words are the view's.
//!
//! Layout: the attention entries, [`super::view::PAGE_ENTRIES`] to a page (and a page closes early at
//! [`super::view::PAGE_CHARS`] characters), with the summary on the first page. The last page has
//! the verification box (when there is an attention entry), the other items in the expanded information,
//! and the one custom button, [`PRIMARY`], which is gated by the box. Cancel is the default on every
//! page; the wrapper adds Next and Back, and arms the button a second after the last page shows.

use purge_win::taskdialog::{Button, Icon as DialogIcon, Outcome, Page};

use crate::serve::{Ctx, Handler};

use super::sheet::sheet;
use super::text::{MARK, TITLE};
use super::view::{ConsentView, Icon};

/// The id of the button that approves: the only way to [`Outcome::Approved`].
pub const PRIMARY: i32 = 100;

const NEXT_HINT: &str = "Use Next to continue. The button that goes ahead is on the last page.";

/// The pages of the dialog for `view`, in order. The primary button is on the last page only.
pub fn pages(view: &ConsentView) -> Vec<Page> {
    let chunks = view.attention_pages();
    let total = view.attention.len();
    let count = chunks.len().max(1);
    let icon = match view.icon {
        Icon::Shield => DialogIcon::Shield,
        Icon::Warning => DialogIcon::Warning,
    };
    let mut out = Vec::with_capacity(count);
    let mut from = 0;
    for index in 0..count {
        let last = index + 1 == count;
        let mut content = String::new();
        if index == 0 {
            content.push_str(&view.summary.join("\n"));
        }
        if let Some(chunk) = chunks.get(index) {
            if !content.is_empty() {
                content.push_str("\n\n");
            }
            if count == 1 {
                content.push_str(&format!("{MARK} Needs your attention ({total})"));
            } else {
                content.push_str(&format!(
                    "{MARK} Needs your attention: {} to {} of {total} (page {} of {count})",
                    from + 1,
                    from + chunk.len(),
                    index + 1
                ));
            }
            for entry in *chunk {
                content.push('\n');
                content.push_str(&entry.text);
            }
            from += chunk.len();
        }
        if !last {
            content.push_str("\n\n");
            content.push_str(NEXT_HINT);
        }
        let mut page = Page {
            title: TITLE.to_owned(),
            instruction: view.instruction.clone(),
            content,
            footer: Some(view.footer.clone()),
            icon,
            ..Page::default()
        };
        if last {
            page.buttons = vec![Button {
                id: PRIMARY,
                label: view.button.clone(),
            }];
            if let Some(text) = &view.verification {
                page.verification = Some(text.clone());
                page.gated_button = Some(PRIMARY);
            }
            if !view.others.is_empty() {
                let mut expanded: Vec<&str> = view.others.iter().map(|e| e.text.as_str()).collect();
                if let Some(more) = &view.others_more {
                    expanded.push(more);
                }
                page.expanded = Some(expanded.join("\n"));
            } else if let Some(more) = &view.others_more {
                page.expanded = Some(more.clone());
            }
        }
        out.push(page);
    }
    out
}

/// Shows the dialog for `view` and waits. [`Outcome::Approved`] only for the primary button with the
/// box ticked; the client is sent `consent.shown` with the view's code when the window is up.
///
/// The consent the broker was wired with shows either the pages (the TaskDialog) or the sheet (the
/// toolkit window, `super::toolkit`); both are made here from the one view.
pub fn ask<H: Handler>(ctx: &Ctx<'_, H>, view: &ConsentView) -> Outcome {
    ctx.consent_sheet(&sheet(view), &pages(view), PRIMARY, view.code)
}
