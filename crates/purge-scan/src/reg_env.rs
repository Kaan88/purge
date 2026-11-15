//! REG-ENV (ENGINE_PLAN.md §5.6): what an app left in the machine and user `Environment` keys.
//!
//! The two keys (`HKLM\SYSTEM\<current set>\Control\Session Manager\Environment` and
//! `HKU\<SID>\Environment`) are structural containers; only values and entries of list values are
//! offered.
//!
//! # Lists and single values
//!
//! A variable is a **list** when it holds two or more `;`-separated entries, or when it is one of the
//! variables that are lists by what they are ([`LIST_VARIABLES`]: `Path` with one entry is still a
//! list). Only a list is edited by entry. Any other variable is one value (`GIT_SSH`, `JAVA_HOME`): an
//! entry edit would leave it empty but present, so it is offered as the value it is (`DeleteValue`), on
//! the same conditions and evidence as an entry.
//!
//! Whose the variable is, is a separate question. `Environment` is a place every program and the user
//! write to, so a reference to the app's files is Tier A only for a value the installer's log records
//! (`ScanCtx::owns_registration`); a variable or `PATH` entry the user made by hand is listed, never
//! preselected.
//!
//! # A `PATH` entry
//!
//! Every list is read entry by entry. One entry becomes a
//! `Target::RegMultiSzSegment` with `Action::EditSegment` when all of these hold:
//!
//! 1. it names **one** directory at or under an InstallRoot, compared as written and with its
//!    `%NAME%` references expanded for the interactive user. The entry is read with
//!    `prefix::ListEntry::read`, as the harvest reads it: an entry that holds a `;`, a `"` inside
//!    it, or a second path (`<app>\cmd,C:\Users\me\tools`), as written **or expanded**
//!    (`%MYDIRS%` with `MYDIRS` = `<app>\cmd;C:\Users\me\tools`), is not one directory. The edit
//!    would take the user's part out with the app's, so such an entry is never offered;
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
//! What a reference expands to is taken from the interactive user's environment, and only for a
//! `REG_EXPAND_SZ` value (in a `REG_SZ` value Windows leaves `%NAME%` as it is, and so does this
//! scanner: such an entry names no directory). In the machine key and in another user's key that
//! environment is not the one the entry is read with: an entry there that refers to a variable
//! some user sets, or that Windows sets per user, is offered at Tier B at most
//! ([`per_user_reference`]).
//!
//! Two kinds of entry are one directory and still not provably the installer's, whatever the log
//! says about the list (it has no per-entry records): an entry that is nothing but a reference to
//! another variable (`%MYDIRS%`, with `MYDIRS` = `<app>\cmd`: the user's indirection, the directory
//! is named in the other variable), and an entry with a `,` or with a `\\` after its start in it
//! (a `,` is legal in a directory name and no separator to Windows, and a doubled `\` is harmless,
//! but a list typed with commas or blanks looks the same: `<app>\cmd,tools`,
//! `<app>\cmd \\server\tools`). Both are offered at Tier B
//! at most: listed, never preselected. The same cap applies to a single-value variable and to a
//! whole variable that leads into the app's folder that way.
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

use std::collections::BTreeMap;

use purge_guard::prefix;
use purge_model::{Action, AnchorKind, Candidate, Category, Target};
use purge_source::types::{REG_EXPAND_SZ, RegValue, SourceError};

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

/// Variables that are lists whatever they hold at the moment: one entry in `Path` is an entry, not the
/// whole variable.
const LIST_VARIABLES: [&str; 8] = [
    "Path",
    "PATHEXT",
    "PSModulePath",
    "CLASSPATH",
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "PYTHONPATH",
];

/// Variables Windows sets for each user from the profile, whatever the `Environment` keys hold.
const PER_USER_VARIABLES: [&str; 8] = [
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "USERNAME",
    "HOMEDRIVE",
    "HOMEPATH",
    "TEMP",
    "TMP",
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
    /// Why the entry cannot be proven to be the installer's, if it cannot
    /// (`prefix::ListEntry::indirect`, `prefix::ListEntry::ambiguous`).
    unproven: Option<&'static str>,
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

    // Windows expands the references of a `REG_EXPAND_SZ` value only: in a `REG_SZ` value
    // `%NAME%` is text, and the entry names no directory of the app through it.
    let unexpanded = BTreeMap::new();
    let env = if value.data.ty == REG_EXPAND_SZ {
        ctx.env
    } else {
        &unexpanded
    };
    let mut entries: Vec<Entry<'_>> = Vec::new();
    let mut total = 0usize;
    // Split as the harvest does: a `;` inside quotes is part of the entry.
    for (index, part) in prefix::list_entries(&text).into_iter().enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        total += 1;
        // Not one directory anybody can name with certainty, as written or with its references
        // expanded (a quoted `;`, a quote that is never closed or is left inside, a second path
        // after the first, a `%NAME%` that holds a list): maybe several entries of the user's
        // read as one. It counts as an entry that is not the app's and is never offered.
        let Some(read) = prefix::ListEntry::read(part, env) else {
            continue;
        };
        let under_root = [read.bare, read.expanded.as_str()]
            .into_iter()
            .find(|p| ctx.inside_install_root(p).is_some());
        if let Some(under_root) = under_root {
            entries.push(Entry {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                text: part,
                under_root: under_root.to_owned(),
                unproven: if read.indirect {
                    Some("the entry is a reference to another variable")
                } else if read.ambiguous {
                    Some("the entry holds a comma or a second path start and may be two entries")
                } else if per_user_reference(ctx, key, read.bare) {
                    Some("the entry refers to a variable that is set per user")
                } else {
                    None
                },
                expanded: read.expanded,
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
        // The installer's record names the variable, not what it holds. A variable of that name
        // that leads somewhere else now (the user set `FOO_HOME` again for a copy of their own
        // after the uninstall) or holds no path at all is the installer's by name only: nothing
        // tells its content from a later one, so it is listed and never preselected.
        if entries.len() != total || total == 0 {
            whole.cap_at_tier_b("the variable does not lead into the app's folder");
        }
        // It leads there through another variable, or may hold a second entry.
        if let Some(why) = entries.iter().find_map(|e| e.unproven) {
            whole.cap_at_tier_b(why);
        }
        // One install run found the variable in place: it is not the installer's alone, whatever
        // another run of the same log recorded.
        if existed_before {
            whole.cap_at_tier_b("the installer found the variable in place");
        }
        whole.common_blockers();
        out.push(whole.build());
        return;
    }
    if existed_before {
        return;
    }

    let is_list = total >= 2
        || LIST_VARIABLES
            .iter()
            .any(|name| prefix::eq_ci(name, value.name.trim()));
    if !is_list {
        // One value, not a list: taking its only entry out would leave an empty variable behind.
        let Some(entry) = entries.first() else {
            return;
        };
        if shared_variable
            || !ctx.fs.exists(&entry.expanded).is_absent()
            || !in_snapshot(ctx, env, key, &value.name, entry)
        {
            return;
        }
        let mut b = ctx.candidate(
            ID,
            Target::RegValue {
                path: key.to_owned(),
                name: value.name.clone(),
            },
            Action::DeleteValue,
            Category::Registration,
        );
        b.in_ref_snapshot();
        if !b.points_into_install_root(&entry.under_root) {
            return;
        }
        if let Some(dangling) = ctx.dangling(&entry.expanded) {
            b.dangling_ref(&dangling);
        }
        // Without the installer's record on the variable (a record leads to the whole-variable
        // branch above) and in a shared place this is Tier B anyway. It is Tier A when the
        // `Environment` key itself counts as the app's place (a delete-the-whole-key record on
        // it and a baseline that does not have the key): then the caps of an entry apply.
        if let Some(why) = entry.unproven {
            b.cap_at_tier_b(why);
        }
        b.common_blockers();
        out.push(b.build());
        return;
    }

    for (n, entry) in entries.iter().enumerate() {
        if !ctx.fs.exists(&entry.expanded).is_absent()
            || !in_snapshot(ctx, env, key, &value.name, entry)
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
        // The installer's record is on the list, not on its entries: it does not show that the
        // installer wrote an entry that only refers to another variable, or one that may be two.
        if let Some(why) = entry.unproven {
            b.cap_at_tier_b(why);
        }
        b.common_blockers();
        out.push(b.build());
    }
}

/// Whether an entry of `key` refers to a variable that need not mean, for those who read `key`,
/// what it means in the interactive user's environment the entry was expanded with.
///
/// The machine key is read by the system and by every user, and another user's key by that
/// user. `%ROOT%\cmd` in the machine `Path` leads to the app's folder for the interactive user
/// when their own `ROOT` says so, and somewhere else for everybody whose `ROOT` is the machine's.
/// So in a key that is not the interactive user's, a reference to a variable that a user's
/// `Environment` (or `Volatile Environment`) key sets, or that Windows sets per user, proves
/// nothing about where the entry leads. A user key that cannot be read counts as setting it.
fn per_user_reference(ctx: &ScanCtx<'_>, key: &str, bare: &str) -> bool {
    let own = format!(r"HKU\{}\Environment", ctx.fp.user_sid.trim());
    if ctx.same_key(key, &own) || !bare.contains('%') {
        return false;
    }
    // Everything between two `%`: more than the references when a `%` stands alone, never less.
    let pieces: Vec<&str> = bare.split('%').collect();
    let names: Vec<&str> = pieces
        .get(1..pieces.len().saturating_sub(1))
        .unwrap_or_default()
        .to_vec();
    let sets = |user_key: String, name: &str| match ctx.reg.values(&user_key) {
        Ok(values) => values.iter().any(|v| prefix::eq_ci(v.name.trim(), name)),
        Err(SourceError::NotFound) => false,
        Err(_) => true,
    };
    names.into_iter().any(|name| {
        let name = name.trim();
        PER_USER_VARIABLES.iter().any(|v| prefix::eq_ci(v, name))
            || common::user_sids(ctx).iter().any(|sid| {
                sets(format!(r"HKU\{sid}\Environment"), name)
                    || sets(format!(r"HKU\{sid}\Volatile Environment"), name)
            })
    })
}

/// Whether the harvest recorded this entry: as a segment of the value, or through the value as a whole
/// referring to the root (or a file) the entry leads to.
fn in_snapshot(
    ctx: &ScanCtx<'_>,
    env: &BTreeMap<String, String>,
    key: &str,
    name: &str,
    entry: &Entry<'_>,
) -> bool {
    let bare = prefix::unquoted_list_entry(entry.text).trim_end_matches(prefix::SEP);
    let same_dir = |segment: &str| {
        let segment = prefix::unquoted_list_entry(segment).trim_end_matches(prefix::SEP);
        prefix::eq_ci(segment, bare)
            || prefix::is_same(&common::expand_env(segment, env), &entry.expanded)
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
