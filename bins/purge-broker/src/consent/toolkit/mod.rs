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
//! | [`look`] | the colours: Purge's Bold and Violet, light or dark by the system, the contrast theme |

pub mod look;
pub mod state;
