//! App identity resolution.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.4): build an `AppIdentity` for a program (names, tokens,
//! publisher, vendor aliases, signer and `VersionInfo` facts), the tokenizer and matcher used by scanners,
//! and the mega-vendor list that stops a big publisher name from acting as evidence on its own.
//!
//! Milestone: M1a (§11.1).

pub mod identity;
pub mod kbdata;
pub mod matcher;
pub mod sift4;
pub mod tokenizer;
