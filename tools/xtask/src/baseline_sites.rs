//! `baseline-sites`: every use of the baseline view in the scan and the harvest, and every use of its
//! absence side anywhere in the workspace, is a listed site with a class (BASELINE_LOCAL_DESIGN.md §4.3;
//! DECISIONS.md, Post-M1b, 2026-11-21 "presence-only").
//!
//! The view answers two questions. **P** (presence, "is this Windows' own?") may be asked anywhere, at
//! every trust: a wrong "present" costs a missed leftover. **A** (absence, "is this key proven not
//! Windows' own?") enables a delete, so it is asked only through the **capped path** of each crate:
//!
//! - `crates/purge-scan/src/framework/absence.rs` (`ScanCtx::key_absence`, `has_exact_baseline` and its
//!   other name `has_matching_exact_baseline`: both need the exact baseline of the Windows the scan runs
//!   on);
//! - `crates/purge-harvest/src/refsnap.rs` (`HarvestCtx::key_absence`, `has_exact_baseline`).
//!
//! The local baseline is presence-only: the capped path hands a view's inferred absence out as
//! `Unknown`, so below Exact an A site does what it did without a baseline.
//!
//! The check reads the production code of every crate of the workspace (`crates/*`, `bins/*`, `tools/*`
//! with a `src`): comments removed, string literals emptied, and without what a `#[cfg(test)]` stands on,
//! which is that one item (a test module, also one in a file of its own, a function, a field) and not
//! the rest of the file. It fails when:
//!
//! 1. in the scan or the harvest, a call of a view method or of one of the crates' own baseline helpers
//!    ([`CALLS`]) is not in the site table ([`SITES`]) with exactly that count, or a listed site is gone
//!    (the table is stale);
//! 2. `key_absent`, the view's absence question, is called outside the capped files, in any crate, or
//!    more than once in one, or a capped file no longer turns `Absence::Inferred` into
//!    `Absence::Unknown`;
//! 3. a P call is negated (`!…has_key(…)`: presence read as absence) more often than its site lists;
//!    the listed negations are "Windows has it, so it is not the app's", which is the P direction;
//! 4. `Absence::Inferred` is named, or the carrier `.absence(` is called, at a place the table does not
//!    list: a new consumer of inferred absence needs a row and a review;
//! 5. in any other crate, one of [`WIDE_CALLS`] (the absence question, an inferred answer, the exact
//!    value, the constructor of an Exact view) stands at a place the table does not list; and a public
//!    method of `BaselineView` is not classified in [`VIEW_API`], so a new way to ask the view cannot
//!    go uncounted.
//!
//! Limits, known and accepted (review BL-R1 S6): negation is textual (`== false`, an `else` branch or a
//! `let` followed by `!name` is not seen; the count rule catches a new call, not an existing call whose
//! use is turned round), and outside the scan and the harvest presence calls are not counted (their
//! names are too common to tell apart there, and no code there offers anything). The site table's
//! review is the real check; this is the tripwire.
//!
//! It prints every site with its class and what the site does below Exact.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The class of a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Presence: blocks, protects, or removes an anchor or token. Any trust; the union of the view.
    P,
    /// Absence: one conjunct of a proof that lets a key be deleted. Through the capped path only.
    A,
    /// The exact value of the exact baseline (a restore source). `None` below Exact.
    X,
    /// The machinery itself: the capped path, the seal, what the fingerprint records.
    M,
}

impl Class {
    fn letter(self) -> &'static str {
        match self {
            Class::P => "P",
            Class::A => "A",
            Class::X => "X",
            Class::M => "M",
        }
    }
}

/// One listed site: every call of `call` in `file` of `krate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    /// The crate's directory name (`purge-scan`, `purge-harvest`, `purge-index`, `purge-engine`, …).
    pub krate: &'static str,
    /// The file, relative to the crate's `src`, `/`-separated.
    pub file: &'static str,
    /// The call ([`CALLS`]).
    pub call: &'static str,
    /// The class.
    pub class: Class,
    /// How many calls the file's production code has.
    pub count: usize,
    /// How many of them are negated (`!` directly before the receiver).
    pub negated: usize,
    /// What the site does with a view below Exact.
    pub below_exact: &'static str,
}

/// The view's presence methods.
const VIEW_P: &[&str] = &[
    "has_key_exact_view",
    "has_key",
    "has_value",
    "has_path",
    "path_kind",
    "has_profile_path",
    "has_segment",
    "has_token",
];

/// The calls the check counts: the view's methods, then the crates' own baseline helpers, then the two
/// texts of rule 4.
pub const CALLS: &[&str] = &[
    "has_key_exact_view",
    "has_key",
    "has_value",
    "has_path",
    "path_kind",
    "has_profile_path",
    "has_segment",
    "has_token",
    "key_absent",
    "exact_value",
    "is_exact_for",
    "holds_nothing",
    "trust",
    // Helpers of purge-scan (`ScanCtx`, `CandidateBuilder`) and purge-harvest (`HarvestCtx`, file-local).
    "in_baseline",
    "baseline_blocker",
    "key_absence",
    "has_exact_baseline",
    "has_matching_exact_baseline",
    "has_foreign_exact_baseline",
    "matching_exact_baseline",
    "absence_trust",
    "presence",
    "baseline_cap_missing",
    // Rule 4.
    "absence",
    "Absence::Inferred",
];

/// The calls counted in every crate but the scan and the harvest: the absence side of the view, and the
/// one way to make an Exact view. Presence calls are not counted there (see the module documentation).
pub const WIDE_CALLS: &[&str] = &[
    "key_absent",
    "exact_value",
    "Absence::Inferred",
    "BaselineView::exact",
];

/// The workspace directories whose members are crates.
pub const GROUPS: &[&str] = &["crates", "bins", "tools"];

/// The file of `purge-index` (relative to its `src`) that defines `BaselineView`.
pub const VIEW_FILE: &str = "baseline_view.rs";

/// What a public method of `BaselineView` is to this check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    /// Answers "is this Windows' own?": any trust, the union.
    Presence,
    /// Answers "is this key proven not Windows' own?": through the capped path only.
    Absence,
    /// Hands out the exact baseline's data.
    ExactValue,
    /// What the capped paths and the fingerprint record are built on (the trust, the match).
    Machinery,
    /// Says something about the view itself (its name, its parts, an area), nothing about a key.
    Fact,
    /// Makes a view.
    Constructor,
}

impl ViewKind {
    /// Whether calls of the method are counted in the scan and the harvest ([`CALLS`]).
    pub const fn counted(self) -> bool {
        !matches!(self, ViewKind::Fact | ViewKind::Constructor)
    }
}

/// Every public method of `BaselineView`, classified. A method that is not here fails the check, so a
/// new way to ask the view is classified before it is used.
pub const VIEW_API: &[(&str, ViewKind)] = &[
    ("exact", ViewKind::Constructor),
    ("assemble", ViewKind::Constructor),
    ("merged", ViewKind::Constructor),
    ("local", ViewKind::Constructor),
    ("none", ViewKind::Constructor),
    ("open", ViewKind::Constructor),
    ("empty", ViewKind::Constructor),
    ("or_empty", ViewKind::Constructor),
    ("is_exact_for", ViewKind::Machinery),
    ("holds_nothing", ViewKind::Machinery),
    ("trust", ViewKind::Machinery),
    ("name", ViewKind::Fact),
    ("local_id", ViewKind::Fact),
    ("neighbour_names", ViewKind::Fact),
    ("warnings", ViewKind::Fact),
    ("area_of", ViewKind::Fact),
    ("has_key", ViewKind::Presence),
    ("has_key_exact_view", ViewKind::Presence),
    ("has_value", ViewKind::Presence),
    ("has_path", ViewKind::Presence),
    ("path_kind", ViewKind::Presence),
    ("has_profile_path", ViewKind::Presence),
    ("has_segment", ViewKind::Presence),
    ("has_token", ViewKind::Presence),
    ("key_absent", ViewKind::Absence),
    ("exact_value", ViewKind::ExactValue),
];

/// The capped files, as (crate, file).
pub const CAPPED: &[(&str, &str)] = &[
    ("purge-scan", "framework/absence.rs"),
    ("purge-harvest", "refsnap.rs"),
];

/// How a capped file turns inferred absence into no answer.
pub const CAP_ARM: &str = "Absence::Inferred(_) => Absence::Unknown";

const fn site(
    krate: &'static str,
    file: &'static str,
    call: &'static str,
    class: Class,
    count: usize,
    negated: usize,
    below_exact: &'static str,
) -> Site {
    Site {
        krate,
        file,
        call,
        class,
        count,
        negated,
        below_exact,
    }
}

const SCAN: &str = "purge-scan";
const HARVEST: &str = "purge-harvest";
const INDEX: &str = "purge-index";
const ENGINE: &str = "purge-engine";
const UNION_BLOCK: &str = "union of the view: more WindowsBaseline blocks";

/// The site table.
pub const SITES: &[Site] = &[
    // ---- the other crates: the absence side only ([`WIDE_CALLS`]) ---------------------------------------
    site(
        INDEX,
        "baseline_view.rs",
        "Absence::Inferred",
        Class::M,
        1,
        0,
        "BaselineView::key_absent: the one place an inferred answer is made (Merged or Local, in a \
         marked area); the capped paths hand it out as Unknown",
    ),
    site(
        ENGINE,
        "pipeline/baseline.rs",
        "BaselineView::exact",
        Class::M,
        1,
        0,
        "the one production maker of an Exact view, from the shipped baseline Baseline::try_select \
         chose for the machine's own Windows; not reached below Exact",
    ),
    // ---- purge-scan: the capped path and the framework ------------------------------------------------
    site(
        SCAN,
        "framework/absence.rs",
        "key_absent",
        Class::M,
        1,
        0,
        "the capped path: Inferred is handed out as Unknown",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "Absence::Inferred",
        Class::M,
        3,
        0,
        "the cap arm, the residue's inferred test, and the carrier CandidateBuilder::absence \
         (no production caller)",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "trust",
        Class::M,
        4,
        0,
        "matching_exact_baseline and has_foreign_exact_baseline (is the view Exact at all), the seal's \
         trust test, and the residue's no-view reason",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "is_exact_for",
        Class::M,
        1,
        0,
        "matching_exact_baseline: the exact baseline must be of the Windows the scan runs on; false \
         below Exact",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "has_exact_baseline",
        Class::M,
        4,
        2,
        "false below Exact: key_absence turns a Proven of another Windows' baseline into Unknown (the \
         listed negation), has_matching_exact_baseline is its other name, has_foreign_exact_baseline \
         (the second listed negation) names an Exact view that is not this Windows', absence_trust is \
         None",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "matching_exact_baseline",
        Class::M,
        1,
        0,
        "has_exact_baseline: false below Exact and for a baseline of another Windows",
    ),
    site(
        SCAN,
        "framework.rs",
        "baseline_cap_missing",
        Class::M,
        1,
        0,
        "the seal in ScanCtx::run: drops a key candidate that claims absence without BaselineInferred",
    ),
    site(
        SCAN,
        "framework.rs",
        "trust",
        Class::M,
        2,
        0,
        "the seal's fault line names the trust; the residue records the view's",
    ),
    site(
        SCAN,
        "framework.rs",
        "has_path",
        Class::P,
        1,
        0,
        UNION_BLOCK,
    ),
    site(SCAN, "framework.rs", "has_key", Class::P, 3, 0, UNION_BLOCK),
    site(
        SCAN,
        "framework.rs",
        "has_value",
        Class::P,
        1,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "framework.rs",
        "in_baseline",
        Class::P,
        1,
        0,
        "baseline_blocker: union of the view; a user's slot-store slot is present without an exact \
         baseline of this Windows",
    ),
    site(
        SCAN,
        "framework.rs",
        "baseline_blocker",
        Class::P,
        1,
        0,
        "common_blockers: union of the view",
    ),
    site(
        SCAN,
        "framework.rs",
        "has_token",
        Class::P,
        2,
        1,
        "union: a token Windows knows names no Clients key (the listed negation: Windows has it, so it is not the app's) and gives no token evidence",
    ),
    site(
        SCAN,
        "framework.rs",
        "key_absence",
        Class::A,
        1,
        0,
        "key_record_covers (the delete-whole-key record vouching for a value): never below Exact",
    ),
    site(
        SCAN,
        "framework.rs",
        "Absence::Inferred",
        Class::A,
        1,
        0,
        "key_record_covers: the arm answers false",
    ),
    site(
        SCAN,
        "framework.rs",
        "has_exact_baseline",
        Class::A,
        4,
        3,
        "key_record_covers; the Inno key record is Tier B with baseline=none; no HarvestedToken on a key; \
         in_baseline (the third listed negation): without an exact baseline of this Windows a slot of a \
         user's numbered-slot store is Windows' own, the P direction (unknown is present; BL-GATE S1)",
    ),
    site(
        SCAN,
        "framework/m1b.rs",
        "has_key",
        Class::P,
        2,
        0,
        "object guard facts of a service and a task: union",
    ),
    site(
        SCAN,
        "framework/m1b.rs",
        "has_value",
        Class::P,
        1,
        0,
        "object guard facts of a firewall rule: union",
    ),
    // ---- purge-scan: scanners -------------------------------------------------------------------------
    site(
        SCAN,
        "skeleton.rs",
        "has_exact_baseline",
        Class::A,
        1,
        1,
        "NotProven::NoBaseline: no ProvenOwnedSkeleton",
    ),
    site(
        SCAN,
        "skeleton.rs",
        "has_foreign_exact_baseline",
        Class::A,
        1,
        0,
        "false below Exact; it only names the reason (BaselineMismatch) when the gate above is false",
    ),
    site(
        SCAN,
        "skeleton.rs",
        "key_absence",
        Class::A,
        2,
        0,
        "not reached below Exact; Unknown would be NotProven::NoBaseline",
    ),
    site(
        SCAN,
        "skeleton.rs",
        "Absence::Inferred",
        Class::A,
        1,
        0,
        "the arm answers NotProven::NoBaseline",
    ),
    site(
        SCAN,
        "cls_progid.rs",
        "has_matching_exact_baseline",
        Class::A,
        1,
        0,
        "classes::has_matching_baseline: false, so key_offerable and proven_not_windows are false (values-only; com_shellex caps a value at Tier B; ComKeyOwnership is Tier B with baseline=none)",
    ),
    site(
        SCAN,
        "cls_progid.rs",
        "key_absence",
        Class::A,
        1,
        0,
        "classes::proven_not_windows: not reached below Exact",
    ),
    site(
        SCAN,
        "cls_assoc/handler.rs",
        "matching_exact_baseline",
        Class::A,
        1,
        0,
        "handler::matching_baseline: None, so the skeleton standing is NoBaseline (X-SYSTIDY, ChainedRef Tier B)",
    ),
    site(
        SCAN,
        "cls_assoc/handler.rs",
        "key_absence",
        Class::A,
        1,
        0,
        "baseline_standing: not reached below Exact",
    ),
    site(
        SCAN,
        "cls_assoc.rs",
        "exact_value",
        Class::X,
        1,
        0,
        "restore_source: None, the default stays report-only",
    ),
    site(
        SCAN,
        "ref_any/record.rs",
        "has_matching_exact_baseline",
        Class::A,
        1,
        0,
        "the record keeps UnmatchedChildren: not preselected",
    ),
    site(
        SCAN,
        "ref_any/record.rs",
        "in_baseline",
        Class::P,
        1,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "reg_software.rs",
        "has_key_exact_view",
        Class::P,
        1,
        0,
        "union: a vendor container Windows has is withheld",
    ),
    site(
        SCAN,
        "fs_vendorparent.rs",
        "in_baseline",
        Class::P,
        1,
        0,
        "union: a vendor parent Windows has is withheld",
    ),
    site(
        SCAN,
        "com_class.rs",
        "in_baseline",
        Class::P,
        5,
        0,
        "union: a class, AppID or TypeLib Windows has is not offered",
    ),
    site(
        SCAN,
        "com_interface.rs",
        "in_baseline",
        Class::P,
        1,
        0,
        "union: an interface Windows has is not offered",
    ),
    site(
        SCAN,
        "com_shellex.rs",
        "in_baseline",
        Class::P,
        3,
        0,
        "union: a handler key or value Windows has is not offered",
    ),
    site(
        SCAN,
        "reg_diag.rs",
        "in_baseline",
        Class::P,
        2,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "reg_arp_msi.rs",
        "baseline_blocker",
        Class::P,
        2,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "reg_instfolders.rs",
        "baseline_blocker",
        Class::P,
        1,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "reg_privacy.rs",
        "baseline_blocker",
        Class::P,
        2,
        0,
        UNION_BLOCK,
    ),
    site(
        SCAN,
        "reg_shareddlls.rs",
        "baseline_blocker",
        Class::P,
        1,
        0,
        UNION_BLOCK,
    ),
    // ---- purge-harvest --------------------------------------------------------------------------------
    site(
        HARVEST,
        "refsnap.rs",
        "key_absent",
        Class::M,
        1,
        0,
        "the capped path: Inferred is handed out as Unknown",
    ),
    site(
        HARVEST,
        "refsnap.rs",
        "Absence::Inferred",
        Class::M,
        1,
        0,
        "the cap arm",
    ),
    site(
        HARVEST,
        "refsnap.rs",
        "trust",
        Class::M,
        2,
        0,
        "has_exact_baseline; presence (an Exact view of another Windows is not used)",
    ),
    site(
        HARVEST,
        "refsnap.rs",
        "is_exact_for",
        Class::M,
        1,
        0,
        "has_exact_baseline: false below Exact",
    ),
    site(
        HARVEST,
        "refsnap.rs",
        "has_exact_baseline",
        Class::M,
        1,
        1,
        "presence: the view itself below Exact",
    ),
    site(
        HARVEST,
        "refsnap.rs",
        "presence",
        Class::M,
        1,
        0,
        "key_absence asks the presence view",
    ),
    site(
        HARVEST,
        "harvest.rs",
        "trust",
        Class::M,
        3,
        0,
        "the mismatch test of an Exact view; baseline_view_ref records the presence-only trust",
    ),
    site(
        HARVEST,
        "harvest.rs",
        "is_exact_for",
        Class::M,
        1,
        1,
        "an Exact view of another Windows is replaced by the empty view",
    ),
    site(
        HARVEST,
        "harvest.rs",
        "holds_nothing",
        Class::M,
        1,
        0,
        "baseline_view_ref: an empty view records nothing",
    ),
    site(
        HARVEST,
        "anchors.rs",
        "has_key",
        Class::P,
        1,
        0,
        "Pass::in_baseline: union of the view",
    ),
    site(
        HARVEST,
        "anchors.rs",
        "in_baseline",
        Class::P,
        5,
        2,
        "union: a CLSID, AppID, TypeLib or ProgID key Windows has is no anchor (the listed negations: Windows has it, so it is not the app's)",
    ),
    site(
        HARVEST,
        "tokens.rs",
        "has_token",
        Class::P,
        1,
        0,
        "union: a token Windows knows is dropped",
    ),
    site(
        HARVEST,
        "msi.rs",
        "has_key",
        Class::P,
        1,
        0,
        "union: a table row on a key Windows has gives no anchor",
    ),
    site(
        HARVEST,
        "sysobj.rs",
        "has_key",
        Class::P,
        2,
        0,
        "object guard facts of a service and a task: union",
    ),
    site(
        HARVEST,
        "sysobj.rs",
        "has_value",
        Class::P,
        1,
        0,
        "object guard facts of a firewall rule: union",
    ),
    site(
        HARVEST,
        "coproducts.rs",
        "presence",
        Class::P,
        1,
        0,
        "the view asked for a shared directory",
    ),
    site(
        HARVEST,
        "coproducts.rs",
        "has_path",
        Class::P,
        1,
        0,
        "union: a directory Windows has is no shared root of a co-product",
    ),
    site(
        HARVEST,
        "subtree.rs",
        "has_key",
        Class::P,
        1,
        0,
        "subtree::in_baseline: union of the view",
    ),
    site(
        HARVEST,
        "subtree.rs",
        "presence",
        Class::P,
        1,
        0,
        "the view the capture asks",
    ),
    site(
        HARVEST,
        "subtree.rs",
        "in_baseline",
        Class::P,
        2,
        0,
        "union: a key Windows has is recorded for its own values only and is never fully attributed",
    ),
    site(
        HARVEST,
        "subtree.rs",
        "key_absence",
        Class::A,
        1,
        0,
        "keys_with: the climb to the ancestors ends at once, as without a baseline",
    ),
    site(
        HARVEST,
        "assoc.rs",
        "has_exact_baseline",
        Class::A,
        1,
        0,
        "Journal::exact: false",
    ),
    site(
        HARVEST,
        "assoc.rs",
        "key_absence",
        Class::A,
        1,
        0,
        "ext_in_baseline / openwith_in_baseline: Some(true) when a set has the key, None otherwise; never Some(false)",
    ),
    site(
        HARVEST,
        "assoc.rs",
        "Absence::Inferred",
        Class::A,
        1,
        0,
        "the arm answers None below Exact",
    ),
    site(
        HARVEST,
        "assoc.rs",
        "in_baseline",
        Class::A,
        2,
        0,
        "the closure over key_absence above (report facts, not read by the scan)",
    ),
];

/// One call found in the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The workspace group of the crate: `crates`, `bins` or `tools`.
    pub group: String,
    /// The crate.
    pub krate: String,
    /// The file, relative to the crate's `src`.
    pub file: String,
    /// The call.
    pub call: &'static str,
    /// The 1-based line.
    pub line: usize,
    /// Whether a `!` stands directly before the receiver.
    pub negated: bool,
}

/// Every `.rs` file below `dir`, sorted, as (relative `/`-separated name, path).
fn rust_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("listing {}", d.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The crates of the workspace below `root`, as (group, crate, `src` directory): every directory of
/// [`GROUPS`] that has a `src`.
pub fn crates(root: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut out = Vec::new();
    for group in GROUPS {
        let dir = root.join(group);
        if !dir.is_dir() {
            continue;
        }
        let mut names = Vec::new();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() && entry.path().join("src").is_dir() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        for name in names {
            let src = dir.join(&name).join("src");
            out.push(((*group).to_owned(), name, src));
        }
    }
    Ok(out)
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `text` without its comments and with every string and character literal emptied (`""`, `' '`), so
/// that what is left is code. Line breaks are kept, also those inside a comment or a string, so a
/// position in the result is on the line it has in the file.
fn code_only(text: &str) -> Vec<char> {
    let src: Vec<char> = text.chars().collect();
    let at = |i: usize| src.get(i).copied();
    let mut out: Vec<char> = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c == '/' && at(i + 1) == Some('/') {
            while i < src.len() && src[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && at(i + 1) == Some('*') {
            // Block comments nest.
            let mut depth = 0usize;
            while i < src.len() {
                if src[i] == '/' && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if src[i] == '*' && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if src[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        // A raw string: `r"…"`, `r#"…"#`, with a `b` or `c` before the `r`.
        let raw_at = match (c, at(i + 1)) {
            ('r', _) => Some(i + 1),
            ('b' | 'c', Some('r')) => Some(i + 2),
            _ => None,
        };
        if let Some(mut j) = raw_at
            && !out.last().copied().is_some_and(is_ident)
        {
            let mut hashes = 0;
            while at(j) == Some('#') {
                hashes += 1;
                j += 1;
            }
            if at(j) == Some('"') {
                j += 1;
                out.push('"');
                while j < src.len() {
                    if src[j] == '"' && (0..hashes).all(|k| at(j + 1 + k) == Some('#')) {
                        j += 1 + hashes;
                        break;
                    }
                    if src[j] == '\n' {
                        out.push('\n');
                    }
                    j += 1;
                }
                out.push('"');
                i = j;
                continue;
            }
        }
        if c == '"' {
            out.push('"');
            i += 1;
            while i < src.len() {
                match src[i] {
                    '\\' => {
                        if at(i + 1) == Some('\n') {
                            out.push('\n');
                        }
                        i += 2;
                    }
                    '"' => {
                        i += 1;
                        break;
                    }
                    other => {
                        if other == '\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
            }
            out.push('"');
            continue;
        }
        if c == '\'' {
            if at(i + 1) == Some('\\') {
                // An escaped character: `'\''`, `'\n'`, `'\u{1F600}'`.
                let mut j = i + 3;
                while j < src.len() && src[j] != '\'' {
                    j += 1;
                }
                out.extend(['\'', ' ', '\'']);
                i = j + 1;
                continue;
            }
            if at(i + 1).is_some() && at(i + 2) == Some('\'') {
                out.extend(['\'', ' ', '\'']);
                i += 3;
                continue;
            }
            // A lifetime or a label.
        }
        out.push(c);
        i += 1;
    }
    out
}

/// The index of the bracket that closes the one at `open`, or the end of the code.
fn closing(code: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in code.iter().enumerate().skip(open) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    code.len()
}

fn skip_space(code: &[char], mut i: usize) -> usize {
    while i < code.len() && code[i].is_whitespace() {
        i += 1;
    }
    i
}

/// The identifier that starts at `i` (empty when none does).
fn word_at(code: &[char], i: usize) -> String {
    code[i.min(code.len())..]
        .iter()
        .take_while(|c| is_ident(**c))
        .collect()
}

/// Item keywords whose item ends with its `{…}` body, or with a `;` when it has none.
const BODY_ITEMS: &[&str] = &[
    "fn",
    "mod",
    "impl",
    "struct",
    "enum",
    "union",
    "trait",
    "extern",
    "macro_rules",
    "unsafe",
    "async",
    "default",
];
/// Item keywords whose item ends with the first `;` outside every bracket.
const SEMI_ITEMS: &[&str] = &["use", "const", "static", "type"];

/// Where the thing a `#[cfg(test)]` stands on ends (exclusive); `start` is its first character, after
/// the attributes. An out-of-line module (`mod name;`) is added to `modules`.
///
/// An item ends with its body or its `;`. Anything else (a field, a variant, a statement, a match arm)
/// ends with the first `,` or `;` outside every bracket, before the bracket that closes what it stands
/// in, or after a `{…}` that nothing but `else` follows. Where the two readings differ this one takes
/// the shorter: code read as production by mistake can only make the check fail.
fn test_item_end(code: &[char], start: usize, modules: &mut Vec<String>) -> usize {
    let mut i = start;
    let mut word = word_at(code, i);
    if word == "pub" {
        i = skip_space(code, i + word.len());
        if code.get(i) == Some(&'(') {
            i = skip_space(code, closing(code, i) + 1);
        }
        word = word_at(code, i);
    }
    let after = word_at(code, skip_space(code, i + word.len()));
    let const_fn =
        word == "const" && matches!(after.as_str(), "fn" | "unsafe" | "async" | "extern");
    if BODY_ITEMS.contains(&word.as_str()) || const_fn {
        let mut depth = 0usize;
        let mut j = i;
        while j < code.len() {
            match code[j] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth = depth.saturating_sub(1),
                ';' if depth == 0 => {
                    if word == "mod" && !after.is_empty() {
                        modules.push(after);
                    }
                    return j + 1;
                }
                '{' if depth == 0 => return (closing(code, j) + 1).min(code.len()),
                _ => {}
            }
            j += 1;
        }
        return code.len();
    }
    let semi_only = SEMI_ITEMS.contains(&word.as_str());
    let mut depth = 0usize;
    let mut j = i;
    while j < code.len() {
        match code[j] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return j;
                }
                depth -= 1;
                if depth == 0 && code[j] == '}' && !semi_only {
                    let next = skip_space(code, j + 1);
                    match code.get(next) {
                        Some(',' | ';') => return next + 1,
                        _ if word_at(code, next) == "else" => {}
                        _ => return j + 1,
                    }
                }
            }
            ';' if depth == 0 => return j + 1,
            ',' if depth == 0 && !semi_only => return j + 1,
            _ => {}
        }
        j += 1;
    }
    code.len()
}

/// The production code of a file and the out-of-line test modules it declares (`#[cfg(test)] mod x;`).
///
/// Comments are removed and literals emptied ([`code_only`]); then every item, field, statement or arm
/// that a `#[cfg(test)]` stands on is blanked, and only that: the code after a test module is still
/// read. A file that is test code as a whole (`#![cfg(test)]`) gives no code. Line breaks are kept, so
/// offsets give line numbers.
pub fn analyse(text: &str) -> (String, Vec<String>) {
    let mut code = code_only(text);
    let mut modules = Vec::new();
    let squeezed: String = code.iter().filter(|c| !c.is_whitespace()).collect();
    if squeezed.contains("#![cfg(test)]") {
        let blank: String = code.iter().filter(|c| **c == '\n').collect();
        return (blank, modules);
    }
    let needle: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut from = 0;
    while let Some(at) = code[from.min(code.len())..]
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .map(|p| p + from)
    {
        // Further attributes of the same item.
        let mut start = skip_space(&code, at + needle.len());
        while code.get(start) == Some(&'#') {
            let open = skip_space(&code, start + 1);
            if code.get(open) != Some(&'[') {
                break;
            }
            start = skip_space(&code, closing(&code, open) + 1);
        }
        let end = test_item_end(&code, start, &mut modules).clamp(start, code.len());
        for c in &mut code[at..end] {
            if *c != '\n' {
                *c = ' ';
            }
        }
        from = end.max(at + needle.len());
    }
    (code.into_iter().collect(), modules)
}

/// The production code of a file ([`analyse`]).
pub fn production_code(text: &str) -> String {
    analyse(text).0
}

/// Whether the call whose name follows `before` is negated: walking back over the receiver chain
/// (identifiers, `.`, `::`, `&`, an empty `()`, white space) and over the opening parentheses of the
/// expression, the next character is a `!` that is not the bang of a macro (`matches!(x.f())` is no
/// negation).
fn negated(before: &str) -> bool {
    let chars: Vec<char> = before.chars().collect();
    let mut i = chars.len();
    while i > 0 {
        let c = chars[i - 1];
        if is_ident(c) || matches!(c, '.' | ':' | '&') || c.is_whitespace() {
            i -= 1;
        } else if c == ')' && i >= 2 && chars[i - 2] == '(' {
            i -= 2;
        } else {
            break;
        }
    }
    loop {
        if i == 0 {
            return false;
        }
        match chars[i - 1] {
            '(' => {
                i -= 1;
                while i > 0 && chars[i - 1].is_whitespace() {
                    i -= 1;
                }
                // The parenthesis of a call (`f(x.has_key(k))`) starts an argument, not a negation.
                if i > 0 && is_ident(chars[i - 1]) {
                    return false;
                }
            }
            '!' => return !(i >= 2 && is_ident(chars[i - 2])),
            _ => return false,
        }
    }
}

/// The calls of `call` in `code` as (byte offset of the name, negated).
///
/// A method or helper name counts when it is a whole identifier followed (after white space) by `(` and
/// is not being defined (`fn name(`). For the view's own methods a receiver is required (`x.name(`). A
/// path (`Absence::Inferred`, `BaselineView::exact`) counts wherever the text stands as a whole path.
/// Negated: walking back from the name over the receiver chain (identifiers, `.`, `::`, `()`, `&`,
/// white space), the character before it is `!`.
fn calls_of(code: &str, call: &'static str) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    let literal = call.contains("::");
    let view_method = VIEW_API
        .iter()
        .any(|(name, kind)| *name == call && kind.counted());
    let mut from = 0;
    while let Some(at) = code[from..].find(call).map(|i| i + from) {
        from = at + call.len();
        let before = &code[..at];
        let after = &code[at + call.len()..];
        if before.chars().next_back().is_some_and(is_ident)
            || after.chars().next().is_some_and(is_ident)
        {
            continue;
        }
        if literal {
            out.push((at, false));
            continue;
        }
        if !after.trim_start().starts_with('(') {
            continue;
        }
        let head = before.trim_end();
        if head.ends_with("fn") {
            continue;
        }
        let has_receiver = head.ends_with('.');
        if (view_method || call == "absence") && !has_receiver {
            continue;
        }
        out.push((at, negated(before)));
    }
    out
}

/// The files of a crate that are test code as a whole: `file` declares `#[cfg(test)] mod name;`, so
/// `name.rs`, `name/mod.rs` and everything below `name/` beside it are not production code.
fn test_module_files(file: &str, modules: &[String]) -> Vec<String> {
    let (dir, stem) = match file.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), file),
    };
    // `a/b.rs` holds its modules in `a/b/`; `mod.rs`, `lib.rs` and `main.rs` beside themselves.
    let base = match stem.strip_suffix(".rs") {
        Some("mod" | "lib" | "main") | None => dir,
        Some(stem) => format!("{dir}{stem}/"),
    };
    modules
        .iter()
        .flat_map(|m| [format!("{base}{m}.rs"), format!("{base}{m}/")])
        .collect()
}

/// The production code of every file of a crate, as (file, code): files that are test modules as a
/// whole are left out.
fn production_files(src: &Path) -> Result<Vec<(String, String)>> {
    let mut read = Vec::new();
    let mut test_files: Vec<String> = Vec::new();
    for (rel, path) in rust_files(src)? {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let (code, modules) = analyse(&text);
        test_files.extend(test_module_files(&rel, &modules));
        read.push((rel, code));
    }
    read.retain(|(rel, _)| {
        !test_files.iter().any(|t| match t.strip_suffix('/') {
            Some(_) => rel.starts_with(t.as_str()),
            None => rel == t,
        })
    });
    Ok(read)
}

/// Every counted call in the production code of the workspace below `root`: [`CALLS`] in the scan and
/// the harvest, [`WIDE_CALLS`] in every other crate.
pub fn find(root: &Path) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    let all = crates(root)?;
    for needed in [SCAN, HARVEST, INDEX] {
        if !all.iter().any(|(_, name, _)| name == needed) {
            anyhow::bail!("no crate {needed} below {}", root.display());
        }
    }
    for (group, krate, src) in all {
        let calls = if krate == SCAN || krate == HARVEST {
            CALLS
        } else {
            WIDE_CALLS
        };
        for (rel, code) in production_files(&src)? {
            for call in calls {
                for (at, negated) in calls_of(&code, call) {
                    // `has_key` is also the head of `has_key_exact_view`: the identifier test in
                    // `calls_of` keeps them apart.
                    out.push(Found {
                        group: group.clone(),
                        krate: krate.clone(),
                        file: rel.clone(),
                        call,
                        line: code[..at].matches('\n').count() + 1,
                        negated,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// The names of the public methods of `BaselineView` in the production code `code` of
/// `purge-index/src/baseline_view.rs`: every `pub fn` directly in an `impl BaselineView { … }` block.
pub fn view_methods(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let text: String = chars.iter().collect();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("impl BaselineView").map(|i| i + from) {
        from = at + "impl BaselineView".len();
        // Byte offsets and character offsets differ after a non-ASCII character.
        let start = text[..from].chars().count();
        let open = skip_space(&chars, start);
        if chars.get(open) != Some(&'{') {
            continue;
        }
        let close = closing(&chars, open);
        let mut depth = 0usize;
        let mut i = open;
        while i < close {
            match chars[i] {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                'p' if depth == 1
                    && word_at(&chars, i) == "pub"
                    && !(i > 0 && is_ident(chars[i - 1])) =>
                {
                    // `pub fn`, also `pub const fn`, `pub async unsafe fn`; not `pub(crate) fn`.
                    let mut next = skip_space(&chars, i + 3);
                    while matches!(word_at(&chars, next).as_str(), "const" | "async" | "unsafe") {
                        next = skip_space(&chars, next + word_at(&chars, next).len());
                    }
                    if word_at(&chars, next) == "fn" {
                        let name = word_at(&chars, skip_space(&chars, next + 2));
                        if !name.is_empty() {
                            out.push(name);
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    out
}

/// Rule 5: what is wrong with the public methods `methods` of `BaselineView` against [`VIEW_API`].
pub fn view_api_problems(methods: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for m in methods {
        if !VIEW_API.iter().any(|(name, _)| name == m) {
            out.push(format!(
                "crates/{INDEX}/src/{VIEW_FILE}: `BaselineView::{m}` is a public method the check \
                 does not know: add it to VIEW_API (tools/xtask/src/baseline_sites.rs) as presence, \
                 absence, exact value, machinery, a fact or a constructor"
            ));
        }
    }
    for (name, kind) in VIEW_API {
        if !methods.iter().any(|m| m == name) {
            out.push(format!(
                "crates/{INDEX}/src/{VIEW_FILE}: VIEW_API lists `BaselineView::{name}`, the code has \
                 no such public method: the list is stale"
            ));
        }
        if kind.counted() && !CALLS.contains(name) {
            out.push(format!(
                "VIEW_API: `{name}` answers presence or absence and is not in CALLS, so its calls \
                 are not counted"
            ));
        }
    }
    out
}

/// (crate, file, call).
type SiteKey = (String, String, &'static str);
/// The calls of one site: how many, how many negated, their lines.
type Calls = (usize, usize, Vec<usize>);

/// What is wrong with the calls `found` against [`SITES`], one line each; empty when the check passes.
/// `capped_text(crate, file)` gives the production code of a capped file.
pub fn problems(
    found: &[Found],
    capped_text: &dyn Fn(&str, &str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: BTreeMap<SiteKey, Calls> = BTreeMap::new();
    let mut groups: BTreeMap<&str, &str> = BTreeMap::new();
    for f in found {
        let e = seen
            .entry((f.krate.clone(), f.file.clone(), f.call))
            .or_default();
        e.0 += 1;
        e.1 += usize::from(f.negated);
        e.2.push(f.line);
        groups.insert(f.krate.as_str(), f.group.as_str());
    }
    let shown = |krate: &str, file: &str| {
        let group = groups.get(krate).copied().unwrap_or("crates");
        format!("{group}/{krate}/src/{file}")
    };
    let listed = |krate: &str, file: &str, call: &str| {
        SITES
            .iter()
            .find(|s| s.krate == krate && s.file == file && s.call == call)
    };
    for ((krate, file, call), (count, negated, lines)) in &seen {
        let at = shown(krate, file);
        let capped = CAPPED.contains(&(krate.as_str(), file.as_str()));
        // Rule 2.
        if *call == "key_absent" && !capped {
            out.push(format!(
                "{at}:{lines:?}: `key_absent` outside the capped path; ask ScanCtx::key_absence / \
                 HarvestCtx::key_absence"
            ));
            continue;
        }
        let Some(site) = listed(krate, file, call) else {
            // Rule 1 and rule 4.
            out.push(format!(
                "{at}:{lines:?}: {count} call(s) of `{call}` are not in the site table \
                 (tools/xtask/src/baseline_sites.rs SITES): classify the site as P or A and say what \
                 it does below Exact"
            ));
            continue;
        };
        if site.count != *count {
            out.push(format!(
                "{at}:{lines:?}: {count} call(s) of `{call}`, the site table lists {}: classify the \
                 new site, or correct the table",
                site.count
            ));
        }
        // Rule 3.
        if *negated > site.negated {
            let what = if VIEW_P.contains(call) || matches!(*call, "in_baseline") {
                "a presence answer is negated: absence is asked only through key_absence"
            } else {
                "more negated calls than the site table lists"
            };
            out.push(format!(
                "{at}:{lines:?}: `!…{call}(`: {what} ({negated} negated, {} listed)",
                site.negated
            ));
        }
    }
    for site in SITES {
        let key = (site.krate.to_owned(), site.file.to_owned(), site.call);
        if !seen.contains_key(&key) {
            out.push(format!(
                "{}: the site table lists `{}`, the code has none: the table is stale",
                shown(site.krate, site.file),
                site.call
            ));
        }
    }
    // Rule 2, the cap itself.
    for (krate, file) in CAPPED {
        match capped_text(krate, file) {
            Some(code) if code.contains(CAP_ARM) => {}
            Some(_) => out.push(format!(
                "crates/{krate}/src/{file}: the capped path no longer holds `{CAP_ARM}`: below \
                 Exact an A site must not see inferred absence (presence-only)"
            )),
            None => out.push(format!(
                "crates/{krate}/src/{file}: the capped file is missing"
            )),
        }
    }
    out
}

/// The (P, A, X, M) call counts of the site table.
pub fn class_counts() -> [usize; 4] {
    let mut n = [0usize; 4];
    for s in SITES {
        let i = match s.class {
            Class::P => 0,
            Class::A => 1,
            Class::X => 2,
            Class::M => 3,
        };
        n[i] += s.count;
    }
    n
}

/// Every problem of the workspace below `root`: the site table against the code, and the view's
/// public methods against [`VIEW_API`].
pub fn check(root: &Path) -> Result<Vec<String>> {
    let found = find(root)?;
    let crates_dir = root.join("crates");
    let code_of = |krate: &str, file: &str| {
        std::fs::read_to_string(crates_dir.join(krate).join("src").join(file))
            .ok()
            .map(|text| production_code(&text))
    };
    let mut out = problems(&found, &code_of);
    match code_of(INDEX, VIEW_FILE) {
        Some(code) => out.extend(view_api_problems(&view_methods(&code))),
        None => out.push(format!("crates/{INDEX}/src/{VIEW_FILE} is missing")),
    }
    Ok(out)
}

/// Runs the check over the workspace; `Ok(false)` when a rule fails.
pub fn run(root: &Path) -> Result<bool> {
    let problems = check(root)?;
    for site in SITES {
        println!(
            "baseline-sites: {} {:<13} {:<24} {:<28} x{}{}  below Exact: {}",
            site.class.letter(),
            site.krate,
            site.file,
            site.call,
            site.count,
            if site.negated > 0 {
                format!(" ({} negated)", site.negated)
            } else {
                String::new()
            },
            site.below_exact
        );
    }
    for p in &problems {
        eprintln!("baseline-sites: {p}");
    }
    if problems.is_empty() {
        let [p, a, x, m] = class_counts();
        println!(
            "baseline-sites: ok ({} rows over {} crates: {p} presence calls, {a} absence calls \
             through the capped path, {x} exact-value call, {m} calls of the machinery; \
             `key_absent` only in {}; {} public methods of BaselineView classified)",
            SITES.len(),
            crates(root)?.len(),
            CAPPED
                .iter()
                .map(|(k, f)| format!("{k}/src/{f}"))
                .collect::<Vec<_>>()
                .join(" and "),
            VIEW_API.len()
        );
    }
    Ok(problems.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy of the workspace's crate sources (every crate, in the workspace's layout) in a fresh
    /// temporary directory, removed on drop.
    struct Copy {
        dir: PathBuf,
    }

    impl Copy {
        fn of_the_workspace(tag: &str) -> Copy {
            let dir = std::env::temp_dir().join(format!(
                "purge-xtask-baseline-sites-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            for (group, krate, src) in crates(&crate::workspace_root()).unwrap() {
                for (rel, path) in rust_files(&src).unwrap() {
                    let to = dir.join(&group).join(&krate).join("src").join(&rel);
                    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                    std::fs::copy(&path, &to).unwrap();
                }
            }
            Copy { dir }
        }

        fn problems(&self) -> Vec<String> {
            check(&self.dir).unwrap()
        }

        /// A file of a crate below `crates`.
        fn path(&self, krate: &str, file: &str) -> PathBuf {
            self.dir.join("crates").join(krate).join("src").join(file)
        }
    }

    impl Drop for Copy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The tree as committed passes, every A row goes through the capped path, and every crate that
    /// names the view is among the crates read.
    #[test]
    fn xtask_baseline_sites_passes_on_the_tree() {
        let root = crate::workspace_root();
        assert!(run(&root).unwrap());
        let copy = Copy::of_the_workspace("clean");
        assert_eq!(copy.problems(), Vec::<String>::new());
        // No row lists the view's absence question outside the capped files.
        for s in SITES {
            if s.call == "key_absent" {
                assert!(CAPPED.contains(&(s.krate, s.file)), "{s:?}");
            }
        }
        let [p, a, x, _] = class_counts();
        assert!(p > 0 && a > 0 && x == 1);

        // The crates that use the baseline (they name the view, its absence question or its exact
        // value in their sources) are all read; so is every other crate of the workspace.
        let read = crates(&root).unwrap();
        let mut users = Vec::new();
        for (_, krate, src) in &read {
            let uses = rust_files(src).unwrap().iter().any(|(_, path)| {
                let text = std::fs::read_to_string(path).unwrap();
                ["BaselineView", "key_absent", "exact_value"]
                    .iter()
                    .any(|name| text.contains(name))
            });
            if uses {
                users.push(krate.as_str());
            }
        }
        for krate in [SCAN, HARVEST, INDEX, ENGINE, "xtask"] {
            assert!(users.contains(&krate), "{krate} is not read: {users:?}");
        }
        assert!(read.len() >= 14, "{}", read.len());

        // The view's public methods are the classified ones.
        let view = std::fs::read_to_string(copy.path(INDEX, VIEW_FILE)).unwrap();
        let mut methods = view_methods(&production_code(&view));
        let mut listed: Vec<String> = VIEW_API
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        methods.sort();
        listed.sort();
        assert_eq!(methods, listed);
    }

    /// Rule 2: `key_absent` in a scanner, in the harvest, a second one in a capped file, and a capped
    /// file that lets `Inferred` through each fail.
    #[test]
    fn xtask_baseline_sites_catches_absence_outside_the_capped_path() {
        let copy = Copy::of_the_workspace("absent");
        std::fs::write(
            copy.path(SCAN, "reg_planted.rs"),
            "fn f(ctx: &ScanCtx<'_>, key: &str) -> bool {\n    matches!(ctx.baseline.key_absent(key), \
             Absence::Inferred(_))\n}\n",
        )
        .unwrap();
        let p = copy.problems();
        assert!(
            p.iter().any(|l| l.contains("purge-scan/src/reg_planted.rs")
                && l.contains("`key_absent` outside the capped path")),
            "{p:?}"
        );
        // The mention of `Absence::Inferred` is reported on its own (rule 4).
        assert!(
            p.iter()
                .any(|l| l.contains("reg_planted.rs") && l.contains("`Absence::Inferred`")),
            "{p:?}"
        );
        std::fs::remove_file(copy.path(SCAN, "reg_planted.rs")).unwrap();

        std::fs::write(
            copy.path(HARVEST, "planted.rs"),
            "fn f(ctx: &HarvestCtx<'_>, key: &str) -> Absence {\n    ctx.presence()\n        \
             .key_absent(key)\n}\n",
        )
        .unwrap();
        let p = copy.problems();
        assert!(
            p.iter()
                .any(|l| l.contains("purge-harvest/src/planted.rs:[3]")
                    && l.contains("`key_absent` outside the capped path")),
            "{p:?}"
        );
        std::fs::remove_file(copy.path(HARVEST, "planted.rs")).unwrap();
        assert_eq!(copy.problems(), Vec::<String>::new());

        // The cap arm removed from the scan's capped file: an A site would see inferred absence.
        let capped = copy.path(SCAN, "framework/absence.rs");
        let text = std::fs::read_to_string(&capped).unwrap();
        assert!(text.contains(CAP_ARM));
        std::fs::write(
            &capped,
            text.replace(CAP_ARM, "Absence::Inferred(t) => Absence::Inferred(t)"),
        )
        .unwrap();
        let p = copy.problems();
        assert!(
            p.iter()
                .any(|l| l.contains("framework/absence.rs") && l.contains("no longer holds")),
            "{p:?}"
        );
        // A second raw question in the capped file is a count mismatch.
        std::fs::write(
            &capped,
            format!("{text}\nfn second(ctx: &ScanCtx<'_>) -> Absence {{ ctx.baseline.key_absent(\"k\") }}\n"),
        )
        .unwrap();
        let p = copy.problems();
        assert!(
            p.iter().any(|l| l.contains("framework/absence.rs")
                && l.contains("`key_absent`")
                && l.contains("lists 1")),
            "{p:?}"
        );
    }

    /// Rules 1, 3 and 4: an unlisted presence call, a negated presence call in a listed file, the
    /// carrier called from a scanner, and a stale row each fail. Comments and test modules are not
    /// read.
    #[test]
    fn xtask_baseline_sites_catches_unlisted_and_negated_sites() {
        let copy = Copy::of_the_workspace("negated");
        std::fs::write(
            copy.path(SCAN, "reg_planted.rs"),
            "// ctx.baseline.key_absent(key) in a comment is not code\n\
             fn f(ctx: &ScanCtx<'_>, key: &str) -> bool {\n    !ctx.baseline.has_key(key)\n}\n\
             fn g(b: &mut CandidateBuilder<'_>, a: Absence) {\n    b.absence(a);\n}\n\
             #[cfg(test)]\nmod tests {\n    fn t(v: &BaselineView) { let _ = v.key_absent(\"k\"); }\n}\n",
        )
        .unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(
            p[0].contains("reg_planted.rs:[6]") && p[0].contains("`absence`"),
            "{p:?}"
        );
        assert!(
            p[1].contains("reg_planted.rs:[3]") && p[1].contains("`has_key`"),
            "{p:?}"
        );
        std::fs::remove_file(copy.path(SCAN, "reg_planted.rs")).unwrap();

        // A listed P site that starts to negate.
        let file = copy.path(SCAN, "reg_software.rs");
        let text = std::fs::read_to_string(&file).unwrap();
        let call = "ctx.baseline.has_key_exact_view(key)";
        assert!(text.contains(call));
        std::fs::write(&file, text.replacen(call, &format!("!{call}"), 1)).unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            p[0].contains("reg_software.rs") && p[0].contains("a presence answer is negated"),
            "{p:?}"
        );
        // A listed site that is gone.
        std::fs::write(&file, text.replacen(call, "false", 1)).unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            p[0].contains("reg_software.rs") && p[0].contains("stale"),
            "{p:?}"
        );
    }

    /// Review BL-R1 S6: the code after a `#[cfg(test)]` item is read (the check used to stop at the
    /// first one, which in `purge-harvest/src/inno.rs` is line 57 of over a thousand); a test module in a
    /// file of its own is test code for as long as its `mod` line says so; and the other crates of
    /// the workspace are read for the absence side and for the view's own interface.
    #[test]
    fn xtask_baseline_sites_reads_past_test_items_and_every_crate() {
        let copy = Copy::of_the_workspace("wide");

        // After an out-of-line test module, and after an inline one.
        std::fs::write(
            copy.path(HARVEST, "planted.rs"),
            "#[cfg(test)]\nmod tests;\n\nfn late(ctx: &HarvestCtx<'_>, key: &str) -> Absence {\n    \
             ctx.baseline.key_absent(key)\n}\n",
        )
        .unwrap();
        std::fs::create_dir_all(copy.path(HARVEST, "planted")).unwrap();
        std::fs::write(
            copy.path(HARVEST, "planted/tests.rs"),
            "fn t(v: &BaselineView) { let _ = v.key_absent(\"k\"); }\n",
        )
        .unwrap();
        std::fs::write(
            copy.path(SCAN, "reg_planted.rs"),
            "#[cfg(test)]\nmod tests {\n    fn t(v: &BaselineView) { let _ = v.key_absent(\"k\"); }\n}\n\n\
             fn late(ctx: &ScanCtx<'_>, key: &str) -> bool {\n    ctx.baseline.has_key(key)\n}\n",
        )
        .unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(
            p.iter()
                .any(|l| l.contains("crates/purge-harvest/src/planted.rs:[5]")
                    && l.contains("`key_absent` outside the capped path")),
            "{p:?}"
        );
        assert!(
            p.iter()
                .any(|l| l.contains("crates/purge-scan/src/reg_planted.rs:[7]")
                    && l.contains("`has_key`")),
            "{p:?}"
        );
        std::fs::remove_file(copy.path(HARVEST, "planted.rs")).unwrap();
        std::fs::remove_dir_all(copy.path(HARVEST, "planted")).unwrap();
        std::fs::remove_file(copy.path(SCAN, "reg_planted.rs")).unwrap();
        assert_eq!(copy.problems(), Vec::<String>::new());

        // A crate that is neither the scan nor the harvest asks the view for absence.
        std::fs::write(
            copy.path("purge-plan", "planted.rs"),
            "fn f(v: &BaselineView, k: &str) -> bool {\n    matches!(v.key_absent(k), \
             Absence::Inferred(_))\n}\n",
        )
        .unwrap();
        let engine = copy
            .dir
            .join("bins")
            .join(ENGINE)
            .join("src")
            .join("planted.rs");
        std::fs::write(
            &engine,
            "fn g(b: Baseline) -> BaselineView {\n    BaselineView::exact(b)\n}\n\
             fn h(v: &BaselineView) -> Option<BaselineValue> {\n    v.exact_value(\"k\", \"\")\n}\n",
        )
        .unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 4, "{p:?}");
        for (file, what) in [
            (
                "crates/purge-plan/src/planted.rs:[2]",
                "`key_absent` outside the capped path",
            ),
            (
                "crates/purge-plan/src/planted.rs:[2]",
                "`Absence::Inferred`",
            ),
            (
                "bins/purge-engine/src/planted.rs:[2]",
                "`BaselineView::exact`",
            ),
            ("bins/purge-engine/src/planted.rs:[5]", "`exact_value`"),
        ] {
            assert!(
                p.iter().any(|l| l.contains(file) && l.contains(what)),
                "{file} {what}: {p:?}"
            );
        }
        std::fs::remove_file(copy.path("purge-plan", "planted.rs")).unwrap();
        std::fs::remove_file(&engine).unwrap();

        // The view's own test file is left out only because its `mod` line is `#[cfg(test)]`.
        let view = copy.path(INDEX, VIEW_FILE);
        let text = std::fs::read_to_string(&view).unwrap();
        let line = "#[cfg(test)]\nmod tests;";
        let text_lf = text.replace("\r\n", "\n");
        assert!(text_lf.contains(line));
        std::fs::write(&view, text_lf.replace(line, "mod tests;")).unwrap();
        let p = copy.problems();
        assert!(
            p.iter().any(
                |l| l.contains("crates/purge-index/src/baseline_view/tests.rs")
                    && l.contains("`key_absent` outside the capped path")
            ),
            "{p:?}"
        );

        // Rule 5: a new public method of the view has to be classified.
        std::fs::write(
            &view,
            format!(
                "{text_lf}\nimpl BaselineView {{\n    pub fn key_gone(&self, key: &str) -> bool {{\n        \
                 !self.has_key(key)\n    }}\n    fn private(&self) {{}}\n    pub(crate) fn inner(&self) {{}}\n}}\n"
            ),
        )
        .unwrap();
        let p = copy.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            p[0].contains("`BaselineView::key_gone` is a public method the check does not know"),
            "{p:?}"
        );
        // And one that is gone makes the list stale.
        std::fs::write(
            &view,
            text_lf.replace("pub fn holds_nothing(", "fn holds_nothing("),
        )
        .unwrap();
        let p = copy.problems();
        assert!(
            p.iter()
                .any(|l| l.contains("`BaselineView::holds_nothing`") && l.contains("stale")),
            "{p:?}"
        );
    }

    #[test]
    fn calls_are_whole_identifiers_with_a_receiver() {
        let code = "fn in_baseline(&self) {}\nlet a = x.has_key_exact_view(k);\nlet b = !self\n    \
                    .baseline\n    .has_key(k);\nlet c = has_key(k);\nlet d = !pass.in_baseline(&k) \
                    && in_baseline(v, k);\nlet e = y.trusted(); let f = v.trust();\n";
        assert_eq!(calls_of(code, "has_key_exact_view").len(), 1);
        let has_key = calls_of(code, "has_key");
        assert_eq!(has_key.len(), 1);
        assert!(has_key[0].1, "negated across lines");
        let wrap = calls_of(code, "in_baseline");
        assert_eq!(wrap.iter().map(|c| c.1).collect::<Vec<_>>(), [true, false]);
        assert_eq!(calls_of(code, "trust").len(), 1);
        for (text, is_negated) in [
            ("if !ctx.", true),
            ("if !(ctx.", true),
            ("if !self.ctx.presence().", true),
            ("if matches!(ctx.", false),
            ("if !matches!(ctx.", false),
            ("let x = f(ctx.", false),
            ("a != ctx.", false),
        ] {
            assert_eq!(negated(text), is_negated, "{text}");
        }
        // A path counts as a whole path only.
        let paths = "let v = BaselineView::exact(b); let w = v.exact_value(k, n); \
                     let x = BaselineView::exact_for(b); let y = MyBaselineView::exact(b);";
        assert_eq!(calls_of(paths, "BaselineView::exact").len(), 1);
        assert_eq!(calls_of(paths, "exact_value").len(), 1);
    }

    /// What is read as production code: no comment, no literal, and not what a `#[cfg(test)]` stands on;
    /// everything else, on the line it has in the file.
    #[test]
    fn production_code_leaves_out_comments_literals_and_test_items_only() {
        let count = |text: &str, call: &'static str| calls_of(&production_code(text), call).len();
        let lines = |text: &str| production_code(text).matches('\n').count();

        // The old reader stopped at the first test item and cut a line at `//` inside a string.
        let text = "a // x.key_absent()\n#[cfg(test)]\nmod t { x.key_absent() }\nfn p() { y.key_absent(k) }\n";
        assert_eq!(count(text, "key_absent"), 1);
        assert_eq!(lines(text), 4);
        let code = production_code(text);
        assert_eq!(code.lines().next(), Some("a "));
        assert!(code.lines().nth(3).unwrap().contains("y.key_absent(k)"));
        let text = "let s = \"http://host/x.key_absent(k)\"; v.key_absent(k);\n";
        assert_eq!(count(text, "key_absent"), 1);

        // Literals: escapes, raw strings, a quote as a character, lifetimes, strings over lines.
        for (text, want) in [
            (
                "let s = \"a \\\" x.key_absent(k) \\\\\"; v.key_absent(k);",
                1,
            ),
            ("let s = r#\"x.key_absent(\"k\")\"#; v.key_absent(k);", 1),
            (
                "let s = br##\"x.key_absent(k) \"# \"##; v.key_absent(k);",
                1,
            ),
            ("let q = '\"'; v.key_absent(k); let r = '\"';", 1),
            ("let q = '\\''; v.key_absent(k); let n = '\\n';", 1),
            ("fn f<'a>(v: &'a V) -> &'a str { v.key_absent(k) }", 1),
            (
                "let s = \"one\ntwo x.key_absent(k)\nthree\";\nv.key_absent(k);",
                1,
            ),
            (
                "/* x.key_absent(k) /* nested */ still x.key_absent(k) */ v.key_absent(k);",
                1,
            ),
        ] {
            assert_eq!(count(text, "key_absent"), want, "{text}");
            assert_eq!(lines(text), text.matches('\n').count(), "{text}");
        }

        // What a `#[cfg(test)]` stands on, and nothing after it.
        for (text, want) in [
            // An inline module, with braces in strings and comments inside.
            (
                "#[cfg(test)]\nmod tests {\n    fn t() { x.key_absent(\"}\"); } // }\n}\nfn p() { v.key_absent(k) }",
                1,
            ),
            // A module in a file of its own.
            ("#[cfg(test)]\nmod tests;\nfn p() { v.key_absent(k) }", 1),
            // A function, with further attributes and a visibility.
            (
                "#[cfg(test)]\n#[allow(dead_code)]\npub(crate) fn t(a: [u8; 2]) -> bool { x.key_absent(k) }\nfn p() { v.key_absent(k) }",
                1,
            ),
            (
                "#[cfg(test)]\npub const fn t() -> bool { x.key_absent(k) }\nfn p() { v.key_absent(k) }",
                1,
            ),
            // An import, a constant, an impl block.
            (
                "#[cfg(test)]\nuse a::{b, c};\nfn p() { v.key_absent(k) }",
                1,
            ),
            (
                "#[cfg(test)]\nconst T: [u8; 2] = [x.key_absent(k), 2];\nfn p() { v.key_absent(k) }",
                1,
            ),
            (
                "#[cfg(test)]\nimpl T {\n    fn t(&self) { x.key_absent(k) }\n}\nimpl P { fn p(&self) { v.key_absent(k) } }",
                1,
            ),
            // A field and what follows it; a variant; a statement; a block statement; a match arm.
            (
                "struct S {\n    #[cfg(test)]\n    pub t: fn() -> bool,\n    pub p: u8,\n}\nfn p() { v.key_absent(k) }",
                1,
            ),
            (
                "fn p() {\n    #[cfg(test)]\n    let t = x.key_absent(k);\n    v.key_absent(k);\n}",
                1,
            ),
            (
                "fn p() {\n    #[cfg(test)]\n    {\n        x.key_absent(k);\n    }\n    v.key_absent(k);\n}",
                1,
            ),
            (
                "fn p() {\n    S {\n        a: v.key_absent(k),\n        #[cfg(test)]\n        t: x.key_absent(k),\n    }\n}",
                1,
            ),
            (
                "fn p() {\n    match a {\n        #[cfg(test)]\n        T => x.key_absent(k),\n        _ => v.key_absent(k),\n    }\n}",
                1,
            ),
            // The last thing in a block ends where the block ends.
            (
                "fn p() {\n    S {\n        #[cfg(test)]\n        t: x.key_absent(k)\n    }\n}\nfn q() { v.key_absent(k) }",
                1,
            ),
            // Not a test item: another configuration.
            (
                "#[cfg(any(test, feature = \"x\"))]\nfn p() { v.key_absent(k) }",
                1,
            ),
            ("#[cfg(not(test))]\nfn p() { v.key_absent(k) }", 1),
            // A file that is test code as a whole.
            ("#![cfg(test)]\nfn t() { x.key_absent(k) }", 0),
        ] {
            assert_eq!(count(text, "key_absent"), want, "{text}");
            assert_eq!(lines(text), text.matches('\n').count(), "{text}");
        }
        assert_eq!(
            analyse(
                "#[cfg(test)]\nmod tests;\n#[cfg(test)]\npub(crate) mod fixtures;\nmod real;\n"
            )
            .1,
            ["tests", "fixtures"]
        );
        assert!(
            analyse("#[cfg(test)]\nmod tests { }\nmod real;\n")
                .1
                .is_empty()
        );

        // The files of an out-of-line test module, by the file that declares it.
        let files = |file: &str| test_module_files(file, &["tests".to_owned()]);
        assert_eq!(files("inno.rs"), ["inno/tests.rs", "inno/tests/"]);
        assert_eq!(
            files("local_baseline/cache.rs"),
            [
                "local_baseline/cache/tests.rs",
                "local_baseline/cache/tests/"
            ]
        );
        assert_eq!(
            files("framework/mod.rs"),
            ["framework/tests.rs", "framework/tests/"]
        );
        assert_eq!(files("lib.rs"), ["tests.rs", "tests/"]);
        assert_eq!(files("main.rs"), ["tests.rs", "tests/"]);
    }

    /// The public methods of the view are read from its `impl` blocks: `pub fn` only, at the top level
    /// of the block.
    #[test]
    fn view_methods_are_the_pub_fns_of_the_impl_blocks() {
        let code = production_code(
            "impl BaselineView {\n    /// Doc.\n    pub fn a(&self) -> bool { let pub_fn = 1; true }\n    \
             pub const fn b() {}\n    pub(crate) fn c(&self) {}\n    fn d(&self) {}\n    pub async unsafe fn e() {}\n}\n\
             impl fmt::Debug for BaselineView { fn fmt(&self) {} }\n\
             impl BaselineViewRef { pub fn z(&self) {} }\n\
             impl BaselineView {\n    pub fn f(&self) { struct X; impl X { pub fn nested(&self) {} } }\n    \
             #[cfg(test)]\n    pub fn t(&self) {}\n}\n",
        );
        assert_eq!(view_methods(&code), ["a", "b", "e", "f"]);
        let unknown = view_api_problems(&["has_key".to_owned(), "new_question".to_owned()]);
        assert!(
            unknown
                .iter()
                .any(|l| l.contains("`BaselineView::new_question` is a public method")),
            "{unknown:?}"
        );
        assert!(
            unknown
                .iter()
                .any(|l| l.contains("`BaselineView::trust`") && l.contains("stale")),
            "{unknown:?}"
        );
        // Every counted kind is in CALLS, so its calls are counted in the scan and the harvest.
        for (name, kind) in VIEW_API {
            assert_eq!(kind.counted(), CALLS.contains(name), "{name}");
        }
    }
}
