//! The bars a page shows above its content (WinUI `InfoBar`): what the Leftovers, History and
//! Quarantine models say the view draws, in order.

/// How a bar looks; each severity has its own glyph, so the meaning never rests on colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// A note.
    Informational,
    /// Something went as asked.
    Success,
    /// Something needs a look.
    Warning,
    /// Something failed.
    Error,
}

/// One bar: severity, title, message, whether the user may close it, and the action button it
/// carries (`A` is the page's own action enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoBar<A> {
    /// How it looks.
    pub severity: Severity,
    /// The bold first part; may be empty.
    pub title: String,
    /// The text after the title; may be empty.
    pub message: String,
    /// Whether it has a close button.
    pub closable: bool,
    /// The button it carries, if any.
    pub action: Option<A>,
}

impl<A> InfoBar<A> {
    /// A bar without a button.
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
        closable: bool,
    ) -> Self {
        Self {
            severity,
            title: title.into(),
            message: message.into(),
            closable,
            action: None,
        }
    }

    /// The same bar with a button.
    pub fn with_action(mut self, action: A) -> Self {
        self.action = Some(action);
        self
    }
}
