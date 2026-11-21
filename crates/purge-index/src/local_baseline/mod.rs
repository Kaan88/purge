//! The local baseline: what this Windows installation says about itself, read once per
//! (edition, build, ubr) and read-only (docs/BASELINE_LOCAL_DESIGN.md §3).
//!
//! Every source turns what it reads into [`Records`], the text records of the baseline format; the
//! union of all sources is the local baseline (L1: a source only adds). Hashing, the file format and
//! the completeness seal belong to the builder (BL-BUILD), not to the sources.
//!
//! Sources:
//!
//! - [`manifest`]: S1, component manifests (`WinSxS\Manifests`), with the macro table in [`macros`].
//! - [`hive`]: S2, the default profile's hive, and S3, `HKU\.DEFAULT`.
//! - [`appx`]: S4, inbox package manifests and the package repository's generated ProgIDs.

pub mod appx;
pub mod hive;
pub mod macros;
pub mod manifest;
mod records;

pub use records::{NO_DATA_HASH, Records, ValueRecord, escape_into};
