//! REG-ENV (ENGINE_PLAN.md §5.6): what an app left in the machine and user `Environment` keys.
//!
//! The two keys (`HKLM\SYSTEM\<current set>\Control\Session Manager\Environment` and
//! `HKU\<SID>\Environment`) are structural containers; only values and entries of list values are
//! offered.
//!
//! # A `PATH` entry
//!
//! Every string value is read as a `;`-separated list. One entry becomes a
//! `Target::RegMultiSzSegment` with `Action::EditSegment` when all of these hold:
//!
//! 1. it names a directory at or under an InstallRoot, compared as written and with its `%NAME%`
//!    references expanded for the interactive user;
//! 2. that directory is gone (the source proves it absent, checked on the expanded path);
//! 3. the reference snapshot of the harvest has the entry (or, when the harvest recorded the value as
//!    a whole, the value with the root the entry lies under). An entry that is not in the snapshot was
//!    not the app's at harvest and yields nothing;
//! 4. the Inno log does not flag the value as having existed before the install.
//!
//! Evidence: `InPreUninstallRefSnapshot`, `PointsIntoInstallRoot` (which is what makes the edit a
//! declared one for the policy's harm rule), `DanglingRef` when the whole root is gone, and
//! `InstallerManifest` when the Inno log has a record on the value.
//!
//! The Inno log has no per-entry records, so an entry outside every root is never attributed here; the
//! MSI `Environment` table and the remembered manifest, which can declare such entries, come with
//! their milestones.
//!
//! # A whole variable
//!
//! A value is offered whole (`DeleteValue`) only when the Inno log has a value record on it that does
//! not say it existed before, and, if it is a list, every entry of it lies under an InstallRoot.
//! `Path`, `PATHEXT`, `TEMP` and the other variables of Windows itself are never offered whole.
//!
//! # Spelling
//!
//! The machine key is read as `HKLM\SYSTEM\ControlSet00N\…` and emitted as
//! `HKLM\SYSTEM\CurrentControlSet\…`, the form the rig canonicalises to (`vm/rigtool/src/canon.rs`
//! rewrites every `ControlSet00N` to it) and the one a plan must name: the edit has to hit whatever set
//! is current when it runs.

use purge_guard::prefix;
use purge_model::{Action, AnchorKind, Candidate, Category, Target};
use purge_source::types::RegValue;

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::reg_software::common;

/// The scanner's catalog id.
pub const ID: &str = "REG-ENV";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        Some(0),
    ),
    RootSpec::reg(r"HKU\*\Environment", Some(0)),
];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] = &[
    r"HKU\*\Environment",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
];

/// Variables Windows itself defines or every program shares. They are never offered whole, whatever an
/// installer's log says about them (an Inno script that flags `Path` for deletion on uninstall is a
/// known mistake): only single entries of them can be the app's.
const SHARED_VARIABLES: [&str; 14] = [
    "Path",
    "PATHEXT",
    "PSModulePath",
    "TEMP",
    "TMP",
    "ComSpec",
    "windir",
    "OS",
    "DriverData",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
];

/// The machine key below a control set.
const MACHINE_TAIL: &str = r"Control\Session Manager\Environment";

/// The REG-ENV scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegEnv;

impl Scanner for RegEnv {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        common::for_each_app(ctx, app, |ctx, _| scan_app(ctx, &mut out));
        common::dedupe(out)
    }
}

fn scan_app(ctx: &ScanCtx<'_>, out: &mut Vec<Candidate>) {
    let set = ctx
        .reg
        .current_control_set()
        .ok()
        .filter(|n| *n != 0)
        .unwrap_or(ctx.guard.current_control_set);
    // (the key as read, the key as emitted)
    let mut keys = vec![(
        format!(r"HKLM\SYSTEM\ControlSet{set:03}\{MACHINE_TAIL}"),
        format!(r"HKLM\SYSTEM\CurrentControlSet\{MACHINE_TAIL}"),
    )];
    for sid in common::user_sids(ctx) {
        let key = format!(r"HKU\{sid}\Environment");
        keys.push((key.clone(), key));
    }
    for (read, emit) in keys {
        let Ok(values) = ctx.reg.values(&read) else {
            continue;
        };
        for value in &values {
            variable(ctx, &emit, value, out);
        }
    }
}

/// One entry of a variable that lies under an InstallRoot.
struct Entry<'v> {
    /// Position among the `;`-separated parts, empty ones counted.
    index: u32,
    /// The entry as written, trimmed.
    text: &'v str,
    /// The spelling (as written or expanded) that lies under the root.
    under_root: String,
    /// The entry with its `%NAME%` references expanded for the user.
    expanded: String,
}

fn variable(ctx: &ScanCtx<'_>, key: &str, value: &RegValue, out: &mut Vec<Candidate>) {
    let Some(text) = value.data.string().filter(|_| value.data.is_complete()) else {
        return;
    };
    let fp = ctx.fp;
    let on_value = |target: &Target| {
        matches!(target, Target::RegValue { path, name }
            if ctx.same_key(path, key) && prefix::eq_ci(name, &value.name))
    };
    let existed_before = fp
        .inno
        .iter()
        .any(|r| r.existed_before && on_value(&r.target));

    let mut entries: Vec<Entry<'_>> = Vec::new();
    let mut total = 0usize;
    for (index, part) in text.split(';').enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        total += 1;
        let bare = part.trim_matches('"').trim_end_matches(prefix::SEP);
        let expanded = common::expand_env(bare, ctx.env);
        let under_root = [bare, expanded.as_str()]
            .into_iter()
            .find(|p| ctx.inside_install_root(p).is_some());
        if let Some(under_root) = under_root {
            entries.push(Entry {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                text: part,
                under_root: under_root.to_owned(),
                expanded,
            });
        }
    }

    // The whole variable: declared by the installer, and nothing in it is anyone else's.
    let whole_target = Target::RegValue {
        path: key.to_owned(),
        name: value.name.clone(),
    };
    let mut whole = ctx.candidate(
        ID,
        whole_target,
        Action::DeleteValue,
        Category::Registration,
    );
    let shared_variable = SHARED_VARIABLES
        .iter()
        .any(|name| prefix::eq_ci(name, value.name.trim()));
    if !shared_variable && whole.installer_manifest() && (total <= 1 || entries.len() == total) {
        whole.in_ref_snapshot();
        for entry in &entries {
            whole.points_into_install_root(&entry.under_root);
        }
        whole.common_blockers();
        out.push(whole.build());
        return;
    }
    if existed_before {
        return;
    }

    for (n, entry) in entries.iter().enumerate() {
        if !ctx.fs.exists(&entry.expanded).is_absent() || !in_snapshot(ctx, key, &value.name, entry)
        {
            continue;
        }
        let repeated = entries[..n]
            .iter()
            .any(|e| prefix::eq_ci(e.text, entry.text));
        let mut b = ctx.candidate(
            ID,
            Target::RegMultiSzSegment {
                path: key.to_owned(),
                name: value.name.clone(),
                segment: entry.text.to_owned(),
                index: repeated.then_some(entry.index),
            },
            Action::EditSegment,
            Category::Registration,
        );
        b.in_ref_snapshot();
        if !b.points_into_install_root(&entry.under_root) {
            continue;
        }
        if let Some(dangling) = ctx.dangling(&entry.expanded) {
            b.dangling_ref(&dangling);
        }
        b.installer_manifest();
        b.common_blockers();
        out.push(b.build());
    }
}

/// Whether the harvest recorded this entry: as a segment of the value, or through the value as a whole
/// referring to the root (or a file) the entry leads to.
fn in_snapshot(ctx: &ScanCtx<'_>, key: &str, name: &str, entry: &Entry<'_>) -> bool {
    let bare = entry.text.trim_matches('"').trim_end_matches(prefix::SEP);
    let same_dir = |segment: &str| {
        let segment = segment
            .trim()
            .trim_matches('"')
            .trim_end_matches(prefix::SEP);
        prefix::eq_ci(segment, bare)
            || prefix::is_same(&common::expand_env(segment, ctx.env), &entry.expanded)
    };
    ctx.fp.ref_snapshot.iter().any(|e| match &e.target {
        Target::RegMultiSzSegment {
            path,
            name: n,
            segment,
            ..
        } => ctx.same_key(path, key) && prefix::eq_ci(n, name) && same_dir(segment),
        Target::RegValue { path, name: n } => {
            ctx.same_key(path, key)
                && prefix::eq_ci(n, name)
                && matches!(e.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
                && [entry.under_root.as_str(), entry.expanded.as_str()]
                    .into_iter()
                    .any(|p| {
                        prefix::is_same_or_inside(p, &e.anchor.text)
                            || prefix::is_inside(&e.anchor.text, p)
                    })
        }
        _ => false,
    })
}
