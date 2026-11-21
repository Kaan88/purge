//! `baseline-sites`: every use of the baseline view in the scan and the harvest is a listed site with a
//! class (BASELINE_LOCAL_DESIGN.md §4.3; DECISIONS.md, Post-M1b, 2026-11-21 "presence-only").
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
//! The check reads the production code of `purge-scan/src` and `purge-harvest/src` (each file up to its
//! first `#[cfg(test)]` at the start of a line, comments removed) and fails when:
//!
//! 1. a call of a view method or of one of the crates' own baseline helpers ([`CALLS`]) is not in the
//!    site table ([`SITES`]) with exactly that count, or a listed site is gone (the table is stale);
//! 2. `key_absent`, the view's absence question, is called outside the capped files, or more than once
//!    in one, or a capped file no longer turns `Absence::Inferred` into `Absence::Unknown`;
//! 3. a P call is negated (`!…has_key(…)`: presence read as absence) more often than its site lists;
//!    the listed negations are "Windows has it, so it is not the app's", which is the P direction;
//! 4. `Absence::Inferred` is named, or the carrier `.absence(` is called, at a place the table does not
//!    list: a new consumer of inferred absence needs a row and a review.
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
    /// `purge-scan` or `purge-harvest`.
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
const UNION_BLOCK: &str = "union of the view: more WindowsBaseline blocks";

/// The site table.
pub const SITES: &[Site] = &[
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
        2,
        0,
        "the cap arm, and the carrier CandidateBuilder::absence (no production caller)",
    ),
    site(
        SCAN,
        "framework/absence.rs",
        "trust",
        Class::M,
        3,
        0,
        "matching_exact_baseline and has_foreign_exact_baseline (is the view Exact at all), the seal's \
         trust test",
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
        1,
        0,
        "the seal's fault line names the trust",
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
    site(SCAN, "framework.rs", "has_key", Class::P, 1, 0, UNION_BLOCK),
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
        "baseline_blocker: union of the view",
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
        3,
        2,
        "key_record_covers; the Inno key record is Tier B with baseline=none; no HarvestedToken on a key",
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

/// The production code of a file: up to its first `#[cfg(test)]` at the start of a line, each line cut
/// at `//`. Line breaks are kept, so offsets give line numbers.
pub fn production_code(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with("#[cfg(test)]") {
            break;
        }
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
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
/// is not being defined (`fn name(`). For the view's own methods a receiver is required (`x.name(`).
/// `Absence::Inferred` counts wherever the text stands. Negated: walking back from the name over the
/// receiver chain (identifiers, `.`, `::`, `()`, `&`, white space), the character before it is `!`.
fn calls_of(code: &str, call: &'static str) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    let literal = call.contains("::");
    let view_method = CALLS
        .iter()
        .position(|c| *c == call)
        .is_some_and(|i| i < 13);
    let mut from = 0;
    while let Some(at) = code[from..].find(call).map(|i| i + from) {
        from = at + call.len();
        if literal {
            out.push((at, false));
            continue;
        }
        let before = &code[..at];
        let after = &code[at + call.len()..];
        if before.chars().next_back().is_some_and(is_ident)
            || !after.trim_start().starts_with('(')
            || after.chars().next().is_some_and(is_ident)
        {
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

/// Every counted call in the production code of the two crates below `crates_dir`.
pub fn find(crates_dir: &Path) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    for krate in [SCAN, HARVEST] {
        let src = crates_dir.join(krate).join("src");
        if !src.is_dir() {
            anyhow::bail!("no directory {}", src.display());
        }
        for (rel, path) in rust_files(&src)? {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let code = production_code(&text);
            for call in CALLS {
                for (at, negated) in calls_of(&code, call) {
                    // `has_key` is also the head of `has_key_exact_view`: the identifier test in
                    // `calls_of` keeps them apart.
                    out.push(Found {
                        krate: krate.to_owned(),
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
    for f in found {
        let e = seen
            .entry((f.krate.clone(), f.file.clone(), f.call))
            .or_default();
        e.0 += 1;
        e.1 += usize::from(f.negated);
        e.2.push(f.line);
    }
    let listed = |krate: &str, file: &str, call: &str| {
        SITES
            .iter()
            .find(|s| s.krate == krate && s.file == file && s.call == call)
    };
    for ((krate, file, call), (count, negated, lines)) in &seen {
        let at = format!("crates/{krate}/src/{file}");
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
                "crates/{}/src/{}: the site table lists `{}`, the code has none: the table is stale",
                site.krate, site.file, site.call
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

/// Runs the check over the workspace; `Ok(false)` when a rule fails.
pub fn run(root: &Path) -> Result<bool> {
    let crates_dir = root.join("crates");
    let found = find(&crates_dir)?;
    let capped_text = |krate: &str, file: &str| {
        std::fs::read_to_string(crates_dir.join(krate).join("src").join(file))
            .ok()
            .map(|text| production_code(&text))
    };
    let problems = problems(&found, &capped_text);
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
            "baseline-sites: ok ({} rows: {p} presence calls, {a} absence calls through the capped \
             path, {x} exact-value call, {m} calls of the machinery; `key_absent` only in {})",
            SITES.len(),
            CAPPED
                .iter()
                .map(|(k, f)| format!("{k}/src/{f}"))
                .collect::<Vec<_>>()
                .join(" and ")
        );
    }
    Ok(problems.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy of the two crates' sources in a fresh temporary directory, removed on drop.
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
            for krate in [SCAN, HARVEST] {
                let src = crate::workspace_root()
                    .join("crates")
                    .join(krate)
                    .join("src");
                for (rel, path) in rust_files(&src).unwrap() {
                    let to = dir.join(krate).join("src").join(&rel);
                    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                    std::fs::copy(&path, &to).unwrap();
                }
            }
            Copy { dir }
        }

        fn problems(&self) -> Vec<String> {
            let found = find(&self.dir).unwrap();
            let dir = self.dir.clone();
            problems(&found, &move |krate, file| {
                std::fs::read_to_string(dir.join(krate).join("src").join(file))
                    .ok()
                    .map(|t| production_code(&t))
            })
        }

        fn path(&self, krate: &str, file: &str) -> PathBuf {
            self.dir.join(krate).join("src").join(file)
        }
    }

    impl Drop for Copy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The tree as committed passes, and every A row goes through the capped path.
    #[test]
    fn xtask_baseline_sites_passes_on_the_tree() {
        assert!(run(&crate::workspace_root()).unwrap());
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
        assert_eq!(
            production_code("a // x.key_absent()\n#[cfg(test)]\nmod t { x.key_absent() }\n"),
            "a \n"
        );
    }
}
