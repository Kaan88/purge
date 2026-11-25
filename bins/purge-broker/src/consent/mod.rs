//! The consent dialog of the broker (M3 design section 8, package M3-CONSENT).
//!
//! | Module | What |
//! |---|---|
//! | [`view`] | the pure view model: [`view::view`] (quarantine), [`view::view_restore`], [`view::view_recover`], [`view::view_purge`] |
//! | [`text`] | every name and path goes through here: escapes, look-alikes, cuts, quotes; sizes and counts |
//! | [`dialog`] | the view as TaskDialog pages, and asking through [`crate::serve::Ctx::consent_sheet`] |
//! | [`sheet`] | the view as one scrolling sheet, for the toolkit window |
//! | [`toolkit`] | the dialog drawn with Purge's own toolkit (BROKER-CONSENT-UI): behind `--consent toolkit`, the TaskDialog otherwise and whenever its window cannot be shown |
//!
//! A handler builds the view from the plan it is about to run, asks, and runs that same plan only on
//! [`purge_win::taskdialog::Outcome::Approved`].

pub mod dialog;
pub mod sheet;
pub mod text;
pub mod toolkit;
pub mod view;

#[cfg(test)]
mod samples;
#[cfg(test)]
mod tests;
