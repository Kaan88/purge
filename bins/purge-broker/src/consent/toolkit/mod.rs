//! The consent dialog drawn with Purge's own toolkit (`mdshared-ui`), so that it looks like the
//! application: package BROKER-CONSENT-UI. It is in the elevated broker like the TaskDialog it
//! stands in for, says the same ([`super::sheet`] regroups the same [`super::view::ConsentView`]),
//! and gives the same answer to the same callers ([`crate::serve::Consent`]). The TaskDialog stays:
//! it is the default (`--consent`, `crate::args`), and what is shown whenever the toolkit window
//! cannot be.
//!
//! | Module | What |
//! |---|---|
//! | [`state`] | the rules: Cancel is the default, the arming delay, the box, the end of the list; the one way to an approval |
//! | [`fonts`] | the three font files the window draws with, and what they cannot draw (TK-1) |
//! | [`look`] | the colours: Purge's Bold and Violet, light or dark by the system, the contrast theme |
//! | [`draw`] | measuring, layout and drawing with the toolkit's painter; no window |
//! | [`access`] | what UI Automation sees: ids, names, roles |
//! | [`app`] | the window: the toolkit's host loop around one dialog at a time |
//! | [`service`] | [`ToolkitConsent`], the broker's `Consent`; the threads; the fall back to the TaskDialog |

pub mod access;
pub mod app;
pub mod draw;
pub mod fonts;
pub mod look;
pub mod service;
pub mod state;

pub use service::{ToolkitConsent, UiThread};
