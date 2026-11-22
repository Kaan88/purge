//! The local baseline: what this Windows installation says about itself, read once per
//! (edition, build, ubr) and read-only (docs/BASELINE_LOCAL_DESIGN.md §3).
//!
//! Every source turns what it reads into [`Records`], the text records of the baseline format; the
//! union of all sources is the local baseline (L1: a source only adds). The builder ([`build`]) reads
//! them all, seals the result (§3.4) and encodes the file ([`file`]); [`LocalBaseline`] reads it back
//! into the hashed sets the shipped baselines use.
//!
//! Sources:
//!
//! - [`manifest`]: S1, component manifests (`WinSxS\Manifests`), with the macro table in [`macros`].
//! - [`hive`]: S2, the default profile's hive, and S3, `HKU\.DEFAULT`.
//! - [`appx`]: S4, inbox package manifests and the package repository's generated ProgIDs.
//!
//! [`cache`] stores the result per source in an admin-only directory and loads it back (design §5).

pub mod appx;
pub mod build;
pub mod cache;
pub mod file;
pub mod hive;
pub mod macros;
pub mod manifest;
mod records;

pub use build::{
    BUILDER_VERSION, BuildControl, BuildOptions, BuildTimings, FileStamps, LocalBaselineFile,
    LocalPartFile, S3_DENIED_BY_DESIGN, SealFloors, SourceStamp, build, build_part, file_stamps,
    iso_utc, read_s3,
};
pub use cache::{
    CacheFiles, FileRule, LoadedLocal, LocalCache, PartIds, PartState, PathFiles, admin_only_file,
    cache_temp_name, part_file_names, shipped_sets_file_name,
};
pub use file::{
    LocalBaseline, LocalBaselineError, LocalHeader, LocalSource, SourceLine, SourceStatus,
    local_file_name,
};
pub use records::{NO_DATA_HASH, Records, ValueRecord, escape_into};
