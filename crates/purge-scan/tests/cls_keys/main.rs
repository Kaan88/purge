//! Goldens for the Classes key scanners of M1a package P34: CLS-PROGID, CLS-VERBS, CLS-PROTOCOL,
//! CLS-AUMID and CLS-REGAPPS (ENGINE_PLAN.md §5.6 "Classes", §1.4 Git / Firefox / VS Code targets).
//!
//! Each test builds a registry fixture and a fingerprint, runs one or more scanners and compares the
//! candidates, rendered one per line by [`common::render`], with the expected list.

mod common;

mod aumid;
mod firefox;
mod git;
mod hardening;
mod progid;
mod protocol;
mod regapps;
mod verbs;
