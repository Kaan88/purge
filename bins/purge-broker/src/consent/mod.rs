//! The consent dialog of the broker (M3 design section 8, package M3-CONSENT).
//!
//! | Module | What |
//! |---|---|
//! | [`view`] | the pure view model: [`view::view`] (quarantine), [`view::view_restore`], [`view::view_recover`], [`view::view_purge`] |
//! | [`text`] | every name and path goes through here: escapes, look-alikes, cuts, quotes; sizes and counts |
//! | [`dialog`] | the view as TaskDialog pages, and asking through [`crate::serve::Ctx::consent`] |
//!
//! A handler builds the view from the plan it is about to run, asks, and runs that same plan only on
//! [`purge_win::taskdialog::Outcome::Approved`].

pub mod dialog;
pub mod text;
pub mod view;

#[cfg(test)]
mod tests;
