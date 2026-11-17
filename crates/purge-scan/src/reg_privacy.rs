//! Scanner REG-PRIVACY (ENGINE_PLAN.md §5.6, §8.4, C-PATHSTORES): the per-user usage traces Windows keeps
//! about the app's programs, each a single value named after one of the app's files.
//!
//! # Where
//!
//! For every user hive looked at (`user_sids`: a machine-wide app's every loaded user, a per-user
//! app's own user only), the path-keyed stores of C-PATHSTORES other than
//! `SharedDLLs` and `Installer\Folders` (REG-SHAREDDLLS and REG-INSTFOLDERS read those):
//!
//! - `AppCompatFlags\Layers` (compatibility settings the user chose for a program),
//! - `AppCompatFlags\Compatibility Assistant\Store` and its sibling `Persisted` (PCA),
//! - `MuiCache` in the user's Classes (`<path>.FriendlyAppName`, `<path>.ApplicationCompany`),
//! - `UserAssist\{GUID}\Count` (ROT13 names, a known-folder GUID in front),
//! - `FeatureUsage\{AppBadgeUpdated, AppLaunch, AppSwitched, ShowJumpView}`,
//!
//! plus the shell's shortcut-usage slots `UFH\SHC`, and once per scan the machine's
//! `AppCompatFlags\Layers`. The store keys are read directly with one `values()` each (UserAssist: one
//! `subkeys()` and one `values()` per `Count`); the shared reference walk is not used, because the names
//! are encoded or suffixed and the walk matches them only by accident. The store keys are value
//! containers: they are never candidates, only their single values are.
//!
//! # When a value is the app's
//!
//! Only by its **name**: [`ScanCtx::path_from_value_name`] decodes it as the store requires, and the
//! decoded path must lie at or under an InstallRoot of the fingerprint or be one of its exe paths. A bare
//! file name, a UNC or relative name, a resource reference (`@...`), an AUMID, a `UEME_` counter and the
//! value's data never count. Another product with a program of the same file name elsewhere is therefore
//! never touched, and neither is a trace of a program in another installed app's root (that root at or
//! inside the app's root blocks it: `InsideOtherApp`).
//!
//! In the machine's `Layers` and in a hive other than the interactive user's (whose environment and
//! known folders the sources hold) a name that only becomes a path through the environment (`%NAME%`)
//! or through a per-user known folder (`{FOLDERID_LocalAppData}\...` in UserAssist) is not decoded: it
//! would be decoded with somebody else's profile and could name that user's own install of the same
//! app.
//!
//! Known limit: only UserAssist names are expanded from a known-folder GUID (C-PATHSTORES). A
//! FeatureUsage name in that form (`{FOLDERID_ProgramFilesX64}\App\app.exe`) is not a path to the
//! framework and is not offered.
//!
//! # What a candidate says
//!
//! `Target::RegValue` on the store key as read, `Action::DeleteValue`, `Category::Privacy`, evidence from
//! [`CandidateBuilder::path_named_value`](crate::framework::CandidateBuilder::path_named_value):
//! `PointsIntoInstallRoot`, plus `DanglingRef` when the named file is proven absent and the whole root is
//! gone on its recorded volume (P-PATH-1: Safe). A named file that is present, or whose state is unknown,
//! gives `PointsIntoInstallRoot` alone: Likely.
//!
//! - The machine's `AppCompatFlags\Layers` values are settings an administrator made for every user, not
//!   traces: `Category::AppData`, and capped at Tier B (at most Likely).
//! - The named file's blockers: another product's MSI component on it (and the soft
//!   `MsiPackageUnreadable` while MSI ownership is not fully known), another app's root at or around
//!   it, another app's record of it.
//!
//! # UFH\SHC
//!
//! Values named `0`, `1`, ... each hold one `REG_MULTI_SZ` record (`<shortcut>`, `<target>`,
//! `[<arguments>]`). A value is offered whole only when every non-empty string in it is a full path at or
//! under an InstallRoot, or the path of a shortcut the harvest recorded for the app (the installer's log
//! creates it, or the installer declares it outside the roots). A record with arguments, or with a path
//! of anybody else, is left alone: no segment edit here. Evidence `PointsIntoInstallRoot`, plus
//! `DanglingRef` when every named file is proven absent and the whole root is gone. The slot store is a
//! shared place of the framework (`ScanCtx::owns_registration`: Windows reuses a slot for the next
//! program), so this evidence is Tier B and the value at most Likely.
//!
//! # Reads
//!
//! At most [`MAX_USER_KEY_READS`] key reads per user hive, plus one for the machine's `Layers`
//! (M1B_DESIGN.json `budgets`: "REG-PRIVACY at most 12 keys per loaded user"). A UserAssist `Count` key
//! beyond the budget is not read.
//!
//! # Unknown
//!
//! A store that cannot be read (anything but "not found") offers nothing; so does a hive list that
//! cannot be read (then only the fingerprint's own user is looked at). Each such spot is marked
//! `// warning:` for the scan-warning channel that is not wired yet.

use purge_guard::canon::canon_path;
use purge_guard::prefix;
use purge_model::{Action, Blocker, Candidate, Category, RootKind, Target};
use purge_source::types::{RegValue, SourceError};

use crate::framework::{AppIdentityView, PathStore, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "REG-PRIVACY";

/// Most key reads (`values()`, `subkeys()`) in one user hive (M1B_DESIGN.json `budgets`).
pub const MAX_USER_KEY_READS: usize = 12;

/// The machine's `AppCompatFlags\Layers`.
const MACHINE_LAYERS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

/// `...\AppCompatFlags` below a user's `Software`.
const USER_APPCOMPAT: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags";
/// `...\Explorer` below a user's `Software`.
const USER_EXPLORER: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";
/// `MuiCache` below a user's Classes root.
const MUICACHE_IN_CLASSES: &str = r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
/// `UFH\SHC` below a user's `Software`.
const USER_SHC: &str = r"Software\Microsoft\Windows\CurrentVersion\UFH\SHC";
/// The `FeatureUsage` stores, below `...\Explorer\FeatureUsage`.
const FEATURE_USAGE: [&str; 4] = [
    "AppBadgeUpdated",
    "AppLaunch",
    "AppSwitched",
    "ShowJumpView",
];

/// What the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        Some(2),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\SHC",
        Some(0),
    ),
];

/// The stores as the guard spells them (`purge_guard::containers::M1B_VALUE_CONTAINERS`). `UFH\SHC` is
/// not one: its values are numbered slots, judged by what they hold.
const VALUE_CONTAINERS: &[&str] = &[
    r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
    r"HKU\*\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
];

/// The `KNOWNFOLDERID`s of folders that are the same for every user (`KnownFolders.h`). A UserAssist
/// name that starts with any other known-folder GUID names a folder of one profile.
const MACHINE_FOLDER_GUIDS: &[&str] = &[
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}", // Windows
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", // System
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", // SystemX86
    "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}", // Fonts
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}", // ProgramFiles
    "{6D809377-6AF0-444B-8957-A3773F02200E}", // ProgramFilesX64
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", // ProgramFilesX86
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}", // ProgramFilesCommon
    "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}", // ProgramFilesCommonX64
    "{DE974D24-D9C6-4D3E-BF91-F4455120B917}", // ProgramFilesCommonX86
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}", // ProgramData
    "{DFDF76A2-C82A-4D63-906A-5644AC457385}", // Public
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}", // PublicDesktop
    "{A4115719-D62E-491D-AA7C-E74B8BE3B067}", // CommonStartMenu
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", // CommonPrograms
    "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}", // CommonStartup
];

/// The REG-PRIVACY scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegPrivacy;

impl Scanner for RegPrivacy {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        // Without an InstallRoot or an exe path no name can be the app's: nothing is read.
        if !ctx.fp.roots.iter().any(|r| r.kind == RootKind::InstallRoot) && ctx.fp.exes.is_empty() {
            return Vec::new();
        }
        let mut scan = Scan {
            ctx,
            out: Vec::new(),
            seen: Vec::new(),
        };
        // The machine's compatibility settings. They are no user's: a name that needs a profile's
        // environment to be a path is not decoded there either.
        if let Some(values) = read_values(ctx, MACHINE_LAYERS) {
            for value in &values {
                scan.store_value(MACHINE_LAYERS, PathStore::AppCompatLayers, value, false);
            }
        }
        let home = ctx.sys.user_sid().ok();
        for sid in user_sids(ctx) {
            let at_home = home.as_deref().is_some_and(|h| prefix::eq_ci(h, &sid));
            scan.user(&sid, at_home);
        }
        scan.out
    }
}

/// The values of `key`; `None` when it is absent or cannot be read.
fn read_values(ctx: &ScanCtx<'_>, key: &str) -> Option<Vec<RegValue>> {
    match ctx.reg.values(key) {
        Ok(values) => Some(values),
        Err(SourceError::NotFound) => None,
        // warning: the store could not be read (not captured, access denied): nothing is offered from it.
        Err(_) => None,
    }
}

/// The user SIDs whose hives are looked at. Service accounts and `.DEFAULT` are left out.
///
/// - A **machine-wide** app: the fingerprint's user, then every loaded user hive (anybody may have run
///   the app's programs).
/// - A **per-user** app: the fingerprint's user and the user whose hive holds the registration, no one
///   else: another user's traces of the same path are of that user's own install.
fn user_sids(ctx: &ScanCtx<'_>) -> Vec<String> {
    let is_user = |sid: &str| {
        let sid = sid.to_ascii_uppercase();
        (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
            && !sid.ends_with("_CLASSES")
            && !sid.contains(prefix::SEP)
    };
    let mut sids: Vec<String> = vec![ctx.fp.user_sid.trim().to_owned()];
    match ctx.fp.app.program_id.hive_sid() {
        Some(own) => sids.push(own.trim().to_owned()),
        None => {
            // warning: when the loaded user hives cannot be listed, only the fingerprint's user and the
            // hives the guard knows are looked at.
            if let Ok(loaded) = ctx.reg.loaded_user_sids() {
                sids.extend(loaded);
            }
            sids.extend(ctx.guard.loaded_sids.iter().cloned());
        }
    }
    let mut out: Vec<String> = Vec::new();
    for sid in sids {
        if is_user(&sid) && !out.iter().any(|known| prefix::eq_ci(known, &sid)) {
            out.push(sid);
        }
    }
    out
}

/// ROT13 of the ASCII letters of `text` (UserAssist names); every other character is kept.
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from((c as u8 - b'a' + 13) % 26 + b'a'),
            'A'..='Z' => char::from((c as u8 - b'A' + 13) % 26 + b'A'),
            _ => c,
        })
        .collect()
}

/// Whether the value name `name` of `store` becomes a path only through one user's profile: an
/// environment reference, or (UserAssist) a known-folder GUID of a per-user folder.
fn profile_dependent(store: PathStore, name: &str) -> bool {
    if name.contains('%') {
        return true;
    }
    if store != PathStore::UserAssist {
        return false;
    }
    let decoded = rot13(name);
    let Some(after) = decoded.strip_prefix('{') else {
        return false;
    };
    let Some(end) = after.find('}') else {
        return false;
    };
    let guid = &decoded[..end + 2];
    !MACHINE_FOLDER_GUIDS
        .iter()
        .any(|g| g.eq_ignore_ascii_case(guid))
}

/// One scan's state.
struct Scan<'s, 'c> {
    ctx: &'s ScanCtx<'c>,
    out: Vec<Candidate>,
    /// The values offered so far: canonical key (folded) and folded name.
    seen: Vec<(String, String)>,
}

impl Scan<'_, '_> {
    /// Reads the stores of one user hive, at most [`MAX_USER_KEY_READS`] key reads.
    fn user(&mut self, sid: &str, at_home: bool) {
        let ctx = self.ctx;
        let mut reads = 0usize;
        let read = |key: &str, reads: &mut usize| -> Option<Vec<RegValue>> {
            *reads += 1;
            read_values(ctx, key)
        };
        let user = format!(r"HKU\{sid}");
        let fixed: [(String, PathStore); 3] = [
            (
                format!(r"{user}\{USER_APPCOMPAT}\Layers"),
                PathStore::AppCompatLayers,
            ),
            (
                format!(r"{user}\{USER_APPCOMPAT}\Compatibility Assistant\Store"),
                PathStore::PcaStore,
            ),
            (
                format!(r"{user}\{USER_APPCOMPAT}\Compatibility Assistant\Persisted"),
                PathStore::PcaPersisted,
            ),
        ];
        for (key, store) in &fixed {
            if let Some(values) = read(key, &mut reads) {
                self.store_values(key, *store, &values, at_home);
            }
        }
        // MuiCache: the Classes hive's own spelling; the `Software\Classes` spelling of the same key
        // only when that one is not there (a snapshot that captured the other spelling).
        let mui = format!(r"{user}_Classes\{MUICACHE_IN_CLASSES}");
        let mui_alias = format!(r"{user}\Software\Classes\{MUICACHE_IN_CLASSES}");
        reads += 1;
        match ctx.reg.values(&mui) {
            Ok(values) => self.store_values(&mui, PathStore::MuiCache, &values, at_home),
            Err(_) => {
                if let Some(values) = read(&mui_alias, &mut reads) {
                    self.store_values(&mui_alias, PathStore::MuiCache, &values, at_home);
                }
                // warning: neither spelling could be read when either error is not "not found".
            }
        }
        for name in FEATURE_USAGE {
            let key = format!(r"{user}\{USER_EXPLORER}\FeatureUsage\{name}");
            if let Some(values) = read(&key, &mut reads) {
                self.store_values(&key, PathStore::FeatureUsage, &values, at_home);
            }
        }
        let shc = format!(r"{user}\{USER_SHC}");
        if let Some(values) = read(&shc, &mut reads) {
            for value in &values {
                self.shc_value(&shc, value, at_home);
            }
        }
        // UserAssist last: one `subkeys()`, then one `values()` per `{GUID}\Count` within the budget.
        let user_assist = format!(r"{user}\{USER_EXPLORER}\UserAssist");
        reads += 1;
        let guids = match ctx.reg.subkeys(&user_assist) {
            Ok(guids) => guids,
            Err(SourceError::NotFound) => Vec::new(),
            Err(_) => {
                // warning: the UserAssist key could not be listed: nothing is offered from it.
                Vec::new()
            }
        };
        for guid in guids {
            if reads >= MAX_USER_KEY_READS {
                // warning: UserAssist has more `Count` keys than the read budget allows; the rest are
                // not read.
                break;
            }
            let key = format!(r"{user_assist}\{guid}\Count");
            if ctx.path_keyed_store(&key) != Some(PathStore::UserAssist) {
                continue;
            }
            if let Some(values) = read(&key, &mut reads) {
                self.store_values(&key, PathStore::UserAssist, &values, at_home);
            }
        }
    }

    fn store_values(&mut self, key: &str, store: PathStore, values: &[RegValue], at_home: bool) {
        for value in values {
            self.store_value(key, store, value, at_home);
        }
    }

    /// Whether the value `name` of `key` was offered already (the same key under another spelling); marks
    /// it offered otherwise. A key that does not canonicalise is taken as spelled.
    fn first_time(&mut self, key: &str, name: &str) -> bool {
        let canonical = purge_guard::canon::canon_key(key, None, self.ctx.guard, None)
            .map(|k| k.key_path())
            .unwrap_or_else(|_| key.to_owned());
        let entry = (prefix::fold(&canonical), prefix::fold(name));
        if self.seen.contains(&entry) {
            return false;
        }
        self.seen.push(entry);
        true
    }

    /// The candidate for one value of a path-keyed store, if its name is a path of the app.
    /// `at_home`: the value is in the interactive user's hive.
    fn store_value(&mut self, key: &str, store: PathStore, value: &RegValue, at_home: bool) {
        let ctx = self.ctx;
        if ctx.path_keyed_store(key) != Some(store) {
            return;
        }
        if !at_home && profile_dependent(store, &value.name) {
            return;
        }
        let Some(path) = ctx.path_from_value_name(store, &value.name) else {
            return;
        };
        let own = ctx.inside_install_root(&path).is_some()
            || ctx.fp.exes.iter().any(|e| prefix::is_same(&e.path, &path));
        if !own {
            return;
        }
        let machine = !key
            .get(..4)
            .is_some_and(|hive| hive.eq_ignore_ascii_case(r"HKU\"));
        let category = if machine {
            Category::AppData
        } else {
            Category::Privacy
        };
        let missing = ctx.fs.exists(&path).is_absent();
        let mut b = ctx.candidate(
            ID,
            Target::RegValue {
                path: key.to_owned(),
                name: value.name.clone(),
            },
            Action::DeleteValue,
            category,
        );
        b = b.path_named_value(store, missing);
        if !b.has_positive_evidence() {
            return;
        }
        if machine {
            b.cap_at_tier_b("the machine's compatibility layers are settings, not traces");
        }
        for blocker in file_blockers(ctx, &path) {
            b.blocker(blocker);
        }
        b.baseline_blocker()
            .existed_before_blocker()
            .other_app_blockers();
        if !self.first_time(key, &value.name) {
            return;
        }
        self.out.push(b.build());
    }

    /// The candidate for one slot of `UFH\SHC`, if every string in it is the app's.
    fn shc_value(&mut self, key: &str, value: &RegValue, at_home: bool) {
        let ctx = self.ctx;
        if !value.data.is_complete() {
            return;
        }
        let Some(strings) = value.data.multi_sz() else {
            return;
        };
        let mut paths: Vec<String> = Vec::new();
        let mut in_root: Vec<String> = Vec::new();
        for text in strings.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let Some(path) = shc_path(ctx, text, at_home) else {
                return;
            };
            if ctx.inside_install_root(&path).is_some() {
                in_root.push(path.clone());
            } else if !recorded_shortcut(ctx, &path) {
                return;
            }
            paths.push(path);
        }
        let Some(first) = in_root.first() else {
            return;
        };
        let mut b = ctx.candidate(
            ID,
            Target::RegValue {
                path: key.to_owned(),
                name: value.name.clone(),
            },
            Action::DeleteValue,
            Category::Privacy,
        );
        if !b.points_into_install_root(first) {
            return;
        }
        let all_missing = paths.iter().all(|p| ctx.fs.exists(p).is_absent());
        if all_missing {
            let proofs: Vec<_> = in_root.iter().map(|p| ctx.dangling(p)).collect();
            if let Some(Some(dangling)) = proofs.first()
                && proofs.iter().all(Option::is_some)
            {
                b.dangling_ref(dangling);
            }
        }
        for path in &paths {
            for blocker in file_blockers(ctx, path) {
                b.blocker(blocker);
            }
        }
        b.baseline_blocker()
            .existed_before_blocker()
            .other_app_blockers();
        if !self.first_time(key, &value.name) {
            return;
        }
        self.out.push(b.build());
    }
}

/// One string of a `UFH\SHC` record as a canonical full drive path; `None` when it is anything else
/// (arguments, a relative or UNC name, a short-name segment the guard cannot vouch for). Environment
/// references are expanded only in the interactive user's hive.
fn shc_path(ctx: &ScanCtx<'_>, text: &str, at_home: bool) -> Option<String> {
    let expanded = if text.contains('%') {
        if !at_home {
            return None;
        }
        prefix::expand_env(text, ctx.env)
    } else {
        text.to_owned()
    };
    let b = expanded.as_bytes();
    let absolute = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !absolute || expanded.contains('%') {
        return None;
    }
    let canon = canon_path(&expanded, ctx.guard, None).ok()?;
    (!canon.needs_long_name).then_some(canon.path)
}

/// Whether `path` is a shortcut the harvest recorded for the app: the installer's log creates it, or
/// the installer declares it outside the roots.
fn recorded_shortcut(ctx: &ScanCtx<'_>, path: &str) -> bool {
    let is_link = prefix::leaf(path).is_some_and(|leaf| {
        let leaf = leaf.to_ascii_lowercase();
        leaf.ends_with(".lnk") || leaf.ends_with(".url")
    });
    is_link
        && (ctx.installer_logged_file(path)
            || ctx
                .fp
                .outside_root_files
                .iter()
                .any(|f| prefix::is_same(&f.path, path)))
}

/// The blockers the file a trace names gives the trace: another product's MSI component on it (or one of
/// the app's products Windows still lists), MSI ownership that is unknown there, another app's root at
/// or around it, another app's record of it.
fn file_blockers(ctx: &ScanCtx<'_>, path: &str) -> Vec<Blocker> {
    let mut out = ctx.msi_blockers(&Target::Path {
        path: path.to_owned(),
    });
    for blocker in ctx.other_apps.path_blockers(path) {
        if matches!(
            blocker,
            Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
        ) && !out.contains(&blocker)
        {
            out.push(blocker);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed_and_the_stores_are_guard_containers() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
        for container in VALUE_CONTAINERS {
            assert!(
                purge_guard::containers::M1B_VALUE_CONTAINERS.contains(container),
                "{container}"
            );
            let folded = container.to_ascii_lowercase();
            assert!(
                ROOTS.iter().any(|r| {
                    let root = r.pattern.to_ascii_lowercase();
                    folded == root || folded.starts_with(&format!("{root}\\"))
                }),
                "{container}"
            );
        }
        // Every store of C-PATHSTORES but SharedDLLs and Installer\Folders.
        assert_eq!(VALUE_CONTAINERS.len(), 9);
    }

    #[test]
    fn per_user_known_folders_are_profile_dependent() {
        let name = |plain: &str| rot13(plain);
        assert!(!profile_dependent(
            PathStore::UserAssist,
            &name(r"{6D809377-6AF0-444B-8957-A3773F02200E}\App\app.exe")
        ));
        assert!(profile_dependent(
            PathStore::UserAssist,
            &name(r"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}\Programs\App\app.exe")
        ));
        assert!(!profile_dependent(
            PathStore::UserAssist,
            &name(r"C:\App\app.exe")
        ));
        assert!(profile_dependent(
            PathStore::MuiCache,
            r"%LOCALAPPDATA%\App\app.exe.FriendlyAppName"
        ));
        assert!(!profile_dependent(
            PathStore::MuiCache,
            r"C:\App\app.exe.FriendlyAppName"
        ));
    }

    #[test]
    fn rot13_round_trips() {
        assert_eq!(
            rot13(&rot13(r"C:\Program Files\App\app.exe")),
            r"C:\Program Files\App\app.exe"
        );
        assert_eq!(rot13("UEME_CTLSESSION"), "HRZR_PGYFRFFVBA");
    }
}
