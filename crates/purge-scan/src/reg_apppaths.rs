//! REG-APPPATHS (ENGINE_PLAN.md §5.6): `App Paths\<exe>` and `Classes\Applications\<exe>`.
//!
//! Both locations hold one key per executable name. Such a key is the app's when the paths in it lead
//! into the app:
//!
//! - an `App Paths\<exe>` key whose default value names a file at or under an InstallRoot, or a file of
//!   the exe set;
//! - a `Classes\Applications\<exe>` key in which a value (a verb's command, an icon) does, or which is
//!   named after one of the app's main executables and says nothing against it (see "A bare name").
//!
//! A reference into a root that is gone (a dangling reference) lands under the recorded root all the
//! same, so "into the roots or dangling" is one lexical test here.
//!
//! A file that outlived the uninstall without the installer's log naming it is not shown to be the
//! app's (`ScanCtx::survived_unproven`: the user's own tool in the app's folder, x0-git-toolsdir's
//! `App Paths\rg.exe`). A key whose every path leads to such a file is the registration of a program
//! that still works: it is not offered unless the installer's record covers the key.
//!
//! # A bare name
//!
//! An executable's file name is not an identity: a portable copy of the same program, another install
//! of it and any other product's `updater.exe` carry it too. A `Classes\Applications\<exe>` key that
//! is matched by the name of a main exe alone, with no path in it that leads into the app, is offered
//! only when
//!
//! - the installer's record covers the key, or
//! - the whole subtree was read, no value in it names a path (so nothing in it points anywhere else:
//!   the portable copy's `shell\open\command`), **and** the name is the product's own (`firefox.exe`
//!   of Firefox), not one any product might use (`updater.exe`, `Code.exe`).
//!
//! A key another installed app claims (by the exe name, or by something in the key) is listed all the
//! same, with `ReferencedByOtherApp`: it is shown as kept for that app.
//!
//! [`bare_name_leads_elsewhere`] is the same question for scanners that meet the bare name somewhere
//! else (`OpenWithList`).
//!
//! The key is not the app's alone when another app claims the exe name or when something in the key
//! refers to another app: it is then still listed, with `ReferencedByOtherApp`.
//!
//! # Evidence (Key scope)
//!
//! - `InstallerManifest(Inno)` and `ProvenOwnedSkeleton` when the fingerprint has the record;
//! - `ChainedRef` to the file the key leads to: Tier A for a file under an InstallRoot or of the exe
//!   set, Tier B for an inferred root or a bare main-exe name;
//! - `AppNamedKeyWithRootRef` when the key is named after the very file its value points at under an
//!   InstallRoot, the whole subtree was read and nothing in it refers to another app. This is the
//!   "app-named key with a value into the root" proof applied to the exe-keyed containers, where the
//!   key name is the executable's rather than the product's;
//! - a name match of the exe's stem.
//!
//! The containers themselves (`App Paths`) are structural and never offered.

use purge_guard::prefix;
use purge_model::{Action, AnchorKind, Blocker, Candidate, Category, Target, Tier};
use purge_source::types::RegValue;

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::reg_software::common::{self, Foreign};

/// The scanner's catalog id.
pub const ID: &str = "REG-APPPATHS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        Some(1),
    ),
    RootSpec::reg(r"HKCR\Applications", Some(1)),
];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] = &[r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"];

/// The REG-APPPATHS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegAppPaths;

impl Scanner for RegAppPaths {
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
        common::for_each_app(ctx, app, |ctx, app| scan_app(ctx, app, &mut out));
        common::dedupe(out)
    }
}

/// The containers: `(key, is App Paths)`.
fn containers(ctx: &ScanCtx<'_>) -> Vec<(String, bool)> {
    let mut keys: Vec<(String, bool)> = common::software_bases(ctx)
        .into_iter()
        .map(|base| {
            (
                format!(r"{base}\{}\App Paths", common::CURRENT_VERSION),
                true,
            )
        })
        .collect();
    keys.push((r"HKLM\SOFTWARE\Classes\Applications".to_owned(), false));
    for sid in common::user_sids(ctx) {
        keys.push((format!(r"HKU\{sid}_Classes\Applications"), false));
    }
    keys
}

fn scan_app(ctx: &ScanCtx<'_>, app: &AppIdentityView, out: &mut Vec<Candidate>) {
    let foreign = Foreign::new(ctx);
    for (container, app_paths) in containers(ctx) {
        let Ok(names) = ctx.reg.subkeys(&container) else {
            continue;
        };
        for exe in names.iter().take(ctx.limits.max_key_children) {
            exe_key(
                ctx,
                app,
                &foreign,
                &format!(r"{container}\{exe}"),
                exe,
                app_paths,
                out,
            );
        }
    }
}

/// Whether `path` names a file called `exe`.
fn names_file(path: &str, exe: &str) -> bool {
    prefix::leaf(path).is_some_and(|leaf| prefix::eq_ci(leaf, exe))
}

/// The paths of this app that the values name, without repeats.
fn own_paths<'v>(app: &AppIdentityView, values: impl Iterator<Item = &'v RegValue>) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for value in values {
        for m in common::value_matches(&app.refs, value) {
            let is_path = matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe);
            if let (true, false, Some(path)) = (is_path, m.name_only, m.path) {
                if !paths.iter().any(|p| prefix::is_same(p, &path)) {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

/// Whether `path` is a file that outlived the app's removal without being shown to be the app's
/// (`ScanCtx::survived_unproven`). While the app is not verified gone its own files are all still
/// there, and a file that is present says nothing.
fn outlived(ctx: &ScanCtx<'_>, path: &str) -> bool {
    ctx.verify_gone_passed() && ctx.survived_unproven(path)
}

/// Whether the `Classes\Applications\<exe>` keys show that the bare name `exe` is not this app's: one
/// of them holds a path, and none holds a path that leads into the app (a file that outlived the
/// uninstall unproven does not count as the app's). With no such key, or none that names a path,
/// nothing is known and the answer is `false`.
pub(crate) fn bare_name_leads_elsewhere(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    exe: &str,
) -> bool {
    let mut elsewhere = false;
    for (container, app_paths) in containers(ctx) {
        if app_paths {
            continue;
        }
        let walk = common::walk(ctx, &format!(r"{container}\{exe}"));
        let own = own_paths(app, walk.values.iter().map(|(_, value)| value));
        if own.iter().any(|path| !outlived(ctx, path)) {
            return false;
        }
        elsewhere |= !own.is_empty()
            || walk
                .values
                .iter()
                .any(|(_, value)| common::names_a_path(value));
    }
    elsewhere
}

fn exe_key(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    foreign: &Foreign,
    key: &str,
    exe: &str,
    app_paths: bool,
    out: &mut Vec<Candidate>,
) {
    let fp = ctx.fp;
    let walk = common::walk(ctx, key);
    let paths = if app_paths {
        // The default value is the registration; `Path` and the rest only accompany it.
        own_paths(
            app,
            walk.values
                .iter()
                .filter(|(at, value)| prefix::is_same(at, key) && value.name.is_empty())
                .map(|(_, value)| value),
        )
    } else {
        own_paths(app, walk.values.iter().map(|(_, value)| value))
    };
    let main_exe_name = fp.main_exes().any(|file| names_file(&file.path, exe));
    if paths.is_empty() && (app_paths || !main_exe_name) {
        return;
    }

    let mut b = ctx.candidate(
        ID,
        Target::RegKey {
            path: key.to_owned(),
        },
        Action::DeleteKey,
        Category::Registration,
    );
    let mut any = b.installer_manifest();
    any |= b.proven_owned_skeleton();
    let recorded = any;
    let stem = exe.rsplit_once('.').map_or(exe, |(stem, _)| stem);
    let names: Vec<_> = [
        app.identity.matches_full_name(stem),
        app.identity.matches_name(stem),
    ]
    .into_iter()
    .flatten()
    .collect();
    let other = foreign.in_walk(&app.refs, &walk);
    let claimed = ctx.other_apps.anchor_blocker(AnchorKind::Exe, exe);
    // A key that is kept for a known other app stays listed as kept, with that app's name.
    if !recorded && other.is_none() && claimed.is_none() {
        if paths.is_empty() {
            // A bare name (module documentation).
            let elsewhere = !walk.complete
                || walk
                    .values
                    .iter()
                    .any(|(_, value)| common::names_a_path(value));
            let product_name = names.iter().any(|m| !m.needs_tier_ab_neighbour);
            if elsewhere || !product_name {
                return;
            }
        } else if paths.iter().all(|path| outlived(ctx, path)) {
            // Every path leads to a file that is still there and that nothing shows to be the app's.
            return;
        }
    }
    for path in &paths {
        let in_root = ctx.inside_install_root(path).is_some();
        let unproven = ctx.survived_unproven(path);
        let tier = if (in_root || ctx.is_app_file(path)) && !unproven {
            Tier::A
        } else {
            Tier::B
        };
        any |= b.chained_ref(tier, path);
        if in_root && !unproven && names_file(path, exe) && walk.complete && other.is_none() {
            any |= b.app_named_key_with_root_ref(path);
        }
    }
    if paths.is_empty() {
        any |= b.chained_ref(Tier::B, exe);
    }
    if !any {
        return;
    }
    for m in &names {
        b.name_match(m);
    }
    if let Some(app) = other {
        b.blocker(Blocker::ReferencedByOtherApp { app });
    }
    if let Some(blocker) = claimed {
        b.blocker(blocker);
    }
    b.child_count(walk.count());
    b.common_blockers();
    out.push(b.build());
}
