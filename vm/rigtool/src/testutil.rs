//! Fixture helpers for unit tests: hand-written snaps.

use crate::snap::{Header, Snap, header_line};

pub fn snap_text(f: impl FnOnce(&mut String)) -> Snap {
    let mut t = header_line(&Header::default());
    f(&mut t);
    Snap::from_text(&t).unwrap()
}

/// Same, with a `#roots` line so the snap knows what it captured.
pub fn snap_with_roots(roots: &[&str], f: impl FnOnce(&mut String)) -> Snap {
    let mut t = header_line(&Header::default());
    t.push_str(&crate::snap::meta_line("roots", &roots.iter().map(|s| s.to_string()).collect::<Vec<_>>()));
    f(&mut t);
    Snap::from_text(&t).unwrap()
}
