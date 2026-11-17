//! Validated roots of an app (ENGINE_PLAN.md §5.2 "`validate_root`", "Root kinds", §11.2 "wrong root").
//!
//! A root is the strongest thing the harvest can say about an app: everything under an `InstallRoot` is
//! Tier A. A wrong root is therefore the most dangerous mistake the engine can make, and this module is
//! where it is prevented. Nothing becomes a [`Root`] without passing [`validate_root`].
//!
//! # What is rejected
//!
//! [`validate_root`] is lexical and pure. A path cannot be any kind of root when it
//!
//! - does not canonicalise (relative, UNC, device namespace, an unresolved 8.3 name, …);
//! - is a volume root;
//! - is refused by the guard ([`DenyList::root_rejection`]): `%WINDIR%` and everything in it (so also
//!   `Windows\Installer`), a `Program Files` directory itself, `ProgramData`, the `%LOCALAPPDATA%\Programs`
//!   root, a profile root, a Known Folder, anything inside a user-content Known Folder, anything under a
//!   sync root, a Package Cache or the InstallShield information folder;
//! - is a `Common Files` directory or lies inside one;
//! - is, or contains, the root of another installed app (a vendor folder holding other apps);
//! - contains an anchor of another installed app: its uninstaller, its `DisplayIcon` file, or a service
//!   image that lies in one of that app's directories.
//!
//! [`resolve_root`] adds what needs the file system: 8.3 names are expanded first, and the path must be
//! an existing directory that is not a reparse point.
//!
//! # Root kinds and trust
//!
//! [`collect`] turns the entry's records into candidates, strongest first: ARP `InstallLocation` and the
//! Inno `{app}` directory (`Inno Setup: App Path`, or the uninstaller's directory when the uninstall log
//! names it) give an `InstallRoot`; the directories of `DisplayIcon` and of the uninstaller give an
//! `InferredRoot` (Tier B only, never quarantined whole). An inferred root at or below another root adds
//! nothing and is dropped. AppX locations join in M1b; the MSI component rule (R-MSI,
//! [`crate::msi::component_roots`]) adds its roots after this step and never widens these.
//!
//! Trust follows Rule T (§5.3): a root read from an `HKU` Uninstall key is `UserWritable` whatever the
//! directory's ACL says; otherwise it is `AdminOnly` only when the source reports that just
//! administrators can write the directory and all its ancestors.
//!
//! # Other apps
//!
//! [`RootEnv::from_sources`] gathers the other apps' facts from the inventory and the Services keys. An
//! entry with the same `UninstallString` as the target is the same registration seen through another
//! view or hive and is not "another app". A service has no owner of record, so its image counts as an
//! anchor of another app only when it lies in a directory that app declares (its `InstallLocation`, or
//! the directory of its uninstaller or icon).

use std::collections::BTreeMap;
use std::fmt;

use purge_guard::canon::{GuardEnv, ProfileEnv, canon_path};
use purge_guard::deny::DenyList;
use purge_guard::prefix;
use purge_inventory::kind;
use purge_model::{InventoryDoc, InventoryEntry, Root, RootKind, RootSource, SourceTrust};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{KnownFolder, SourceError};
use purge_win::env::{EnvMap, expand_with};

/// The Services key, in the spelling every source accepts.
const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";
/// Where Windows lists cloud sync roots.
const SYNC_ROOT_MANAGER: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager";
/// The key holding `ProfilesDirectory`.
const PROFILE_LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

// ---------------------------------------------------------------------------------------------------------
// Path helpers shared by the harvest modules
// ---------------------------------------------------------------------------------------------------------

/// The interactive user's environment as an [`EnvMap`].
pub(crate) fn env_map(env: &BTreeMap<String, String>) -> EnvMap {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// A raw registry path value made ready for canonicalisation: trimmed, one pair of quotes removed,
/// `%NAME%` references expanded. `None` when nothing is left.
pub(crate) fn clean_value(raw: &str, env: &EnvMap) -> Option<String> {
    let s = raw.trim().trim_matches('"').trim();
    if s.is_empty() {
        return None;
    }
    Some(if s.contains('%') {
        expand_with(s, env)
    } else {
        s.to_owned()
    })
}

/// The canonical form of a file path, or `None` when it has none.
pub(crate) fn canon_file(path: &str, guard: &GuardEnv) -> Option<String> {
    canon_path(path, guard, None).ok().map(|c| c.path)
}

/// The file a `DisplayIcon`-style value names: the value without a trailing `,<index>`.
pub(crate) fn icon_file(raw: &str) -> &str {
    let s = raw.trim().trim_matches('"');
    match s.rsplit_once(',') {
        Some((file, index))
            if !index.trim().is_empty()
                && index
                    .trim()
                    .trim_start_matches('-')
                    .bytes()
                    .all(|b| b.is_ascii_digit()) =>
        {
            file.trim().trim_matches('"')
        }
        _ => s,
    }
}

/// The executable a command line runs, as a canonical path: split, expanded, canonicalised.
pub(crate) fn command_exe(command: &str, env: &EnvMap, guard: &GuardEnv) -> Option<String> {
    let split = purge_win::cmdline::split(command).ok()?;
    let exe = clean_value(&split.exe, env)?;
    canon_file(&exe, guard)
}

/// The directory holding a canonical file path; `None` for a path directly on a drive.
pub(crate) fn parent_dir(path: &str) -> Option<String> {
    let parent = prefix::parent(path)?;
    (prefix::depth(parent) >= 2).then(|| parent.to_owned())
}

/// Whether `path` is one of `roots` or lies below one.
pub(crate) fn under_any(path: &str, roots: &[Root]) -> bool {
    roots
        .iter()
        .any(|r| prefix::is_same_or_inside(path, &r.path))
}

/// The Package Cache roots of the machine the guard describes: `%ProgramData%\Package Cache` and the
/// `%LOCALAPPDATA%\Package Cache` of every profile, canonical (M1b: Burn caches bundles and packages
/// there, and no root and no MSI key path in them is ever the app's install folder).
pub fn package_cache_roots(guard: &GuardEnv) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let candidates = std::iter::once(guard.program_data.as_str())
        .chain(guard.profiles.iter().map(|p| p.local_appdata.as_str()))
        .filter(|dir| !dir.trim().is_empty())
        .filter_map(|dir| {
            canon_file(
                &format!("{}\\Package Cache", dir.trim_end_matches('\\')),
                guard,
            )
        });
    for dir in candidates {
        if !out.iter().any(|have| prefix::is_same(have, &dir)) {
            out.push(dir);
        }
    }
    out
}

/// Whether `dir` (canonical) is a direct child of one of the Package Cache roots.
pub fn is_package_cache_entry(dir: &str, guard: &GuardEnv) -> bool {
    let Some(parent) = prefix::parent(dir) else {
        return false;
    };
    package_cache_roots(guard)
        .iter()
        .any(|root| prefix::is_same(root, parent))
}

// ---------------------------------------------------------------------------------------------------------
// GuardEnv from the sources
// ---------------------------------------------------------------------------------------------------------

/// Builds the [`GuardEnv`] of the machine the sources describe. Facts that cannot be read are left empty;
/// the deny-list then fails closed and every root is rejected, which the returned warnings explain.
pub fn guard_env(reg: &dyn RegistrySource, sys: &dyn SystemSource) -> (GuardEnv, Vec<String>) {
    let mut warnings = Vec::new();
    let env = sys.env().unwrap_or_else(|e| {
        warnings.push(format!("roots: cannot read the environment: {e}"));
        BTreeMap::new()
    });
    let folders = sys.known_folders().unwrap_or_else(|e| {
        warnings.push(format!("roots: cannot read the known folders: {e}"));
        BTreeMap::new()
    });
    let var = |name: &str| env.get(name).filter(|v| !v.trim().is_empty()).cloned();
    let folder = |f: KnownFolder| folders.get(&f).filter(|v| !v.trim().is_empty()).cloned();

    let windir = folder(KnownFolder::Windows)
        .or_else(|| var("WINDIR"))
        .or_else(|| var("SYSTEMROOT"))
        .unwrap_or_default();
    let system_drive = var("SYSTEMDRIVE")
        .or_else(|| (windir.len() >= 2).then(|| windir[..2].to_owned()))
        .unwrap_or_default();
    let program_files = folder(KnownFolder::ProgramFiles)
        .or_else(|| var("PROGRAMW6432"))
        .or_else(|| var("PROGRAMFILES"))
        .unwrap_or_default();
    let program_files_x86 =
        folder(KnownFolder::ProgramFilesX86).or_else(|| var("PROGRAMFILES(X86)"));
    let program_data = folder(KnownFolder::ProgramData)
        .or_else(|| var("PROGRAMDATA"))
        .unwrap_or_default();

    let user_sid = sys.user_sid().ok();
    let profiles_src = sys.profiles().unwrap_or_else(|e| {
        warnings.push(format!("roots: cannot read the profile list: {e}"));
        Vec::new()
    });
    let emap = env_map(&env);
    let profiles_dir = reg
        .value(PROFILE_LIST, "ProfilesDirectory")
        .ok()
        .and_then(|d| d.string())
        .and_then(|s| clean_value(&s, &emap))
        .or_else(|| {
            folder(KnownFolder::Public)
                .or_else(|| var("PUBLIC"))
                .and_then(|p| prefix::parent(&p).map(str::to_owned))
        })
        .or_else(|| (!system_drive.is_empty()).then(|| format!("{system_drive}\\Users")))
        .unwrap_or_default();

    let mut profiles: Vec<ProfileEnv> = Vec::new();
    for p in &profiles_src {
        let root = p.path.trim_end_matches('\\').to_owned();
        if root.is_empty() {
            continue;
        }
        let mut profile = ProfileEnv {
            sid: p.sid.clone(),
            appdata: format!("{root}\\AppData\\Roaming"),
            local_appdata: format!("{root}\\AppData\\Local"),
            root,
            known_folders: Vec::new(),
            user_content_folders: Vec::new(),
        };
        if user_sid
            .as_deref()
            .is_some_and(|me| me.eq_ignore_ascii_case(&p.sid))
        {
            if let Some(v) = folder(KnownFolder::RoamingAppData).or_else(|| var("APPDATA")) {
                profile.appdata = v;
            }
            if let Some(v) = folder(KnownFolder::LocalAppData).or_else(|| var("LOCALAPPDATA")) {
                profile.local_appdata = v;
            }
            for (f, path) in &folders {
                if !f.is_per_user() || *f == KnownFolder::Profile || path.trim().is_empty() {
                    continue;
                }
                profile.known_folders.push(path.clone());
                if matches!(
                    f,
                    KnownFolder::Desktop | KnownFolder::Documents | KnownFolder::Downloads
                ) {
                    profile.user_content_folders.push(path.clone());
                }
            }
        }
        profiles.push(profile);
    }

    let mut sync_roots = Vec::new();
    for id in reg.subkeys(SYNC_ROOT_MANAGER).unwrap_or_default() {
        let key = format!("{SYNC_ROOT_MANAGER}\\{id}\\UserSyncRoots");
        for value in reg.values(&key).unwrap_or_default() {
            if let Some(path) = value.data.string().and_then(|s| clean_value(&s, &emap)) {
                sync_roots.push(path);
            }
        }
    }
    for name in ["ONEDRIVE", "ONEDRIVECONSUMER", "ONEDRIVECOMMERCIAL"] {
        sync_roots.extend(var(name));
    }
    sync_roots.sort_by_key(|s| s.to_lowercase());
    sync_roots.dedup_by_key(|s| s.to_lowercase());

    let guard = GuardEnv {
        system_drive,
        windir,
        program_files,
        program_files_x86,
        program_data,
        profiles_dir,
        profiles,
        current_control_set: reg.current_control_set().unwrap_or(0),
        sync_roots,
        other_app_roots: Vec::new(),
        protected_dirs: Vec::new(),
        loaded_sids: reg.loaded_user_sids().unwrap_or_default(),
        purge_dirs: Vec::new(),
    };
    let missing = guard.missing();
    if !missing.is_empty() {
        warnings.push(format!(
            "roots: system facts missing ({}); every root is rejected",
            missing.join(", ")
        ));
    }
    (guard, warnings)
}

// ---------------------------------------------------------------------------------------------------------
// Other apps
// ---------------------------------------------------------------------------------------------------------

/// What kind of fact about another app a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OtherAnchorKind {
    /// Its ARP `InstallLocation` (a directory).
    InstallLocation,
    /// The executable its `UninstallString` runs.
    Uninstaller,
    /// The file its `DisplayIcon` names.
    DisplayIcon,
    /// The image of a service that lives in one of its directories.
    ServiceImage,
}

impl OtherAnchorKind {
    fn label(self) -> &'static str {
        match self {
            Self::InstallLocation => "InstallLocation",
            Self::Uninstaller => "UninstallString",
            Self::DisplayIcon => "DisplayIcon",
            Self::ServiceImage => "service ImagePath",
        }
    }
}

/// One path that belongs to another installed app.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OtherAnchor {
    /// The owning app, for messages (its display name).
    pub app: String,
    /// What the path is.
    pub kind: OtherAnchorKind,
    /// The canonical path.
    pub path: String,
}

/// Everything [`validate_root`] needs besides the path: the guard's facts and the other apps' paths.
#[derive(Debug, Clone)]
pub struct RootEnv {
    guard: GuardEnv,
    deny: DenyList,
    common_files: Vec<String>,
    other_dirs: Vec<OtherAnchor>,
    other_files: Vec<OtherAnchor>,
}

impl RootEnv {
    /// An environment with no other apps. `guard.other_app_roots` is ignored: other apps are added with
    /// [`RootEnv::add_other_dir`] and [`RootEnv::add_other_file`], because the guard's rule for them
    /// would also refuse a root *inside* another app's directory, which §5.2 does not ask for.
    pub fn new(guard: &GuardEnv) -> Self {
        let mut raw = guard.clone();
        raw.other_app_roots.clear();
        let deny = DenyList::compile(&raw);
        // A guard environment that does not normalise makes the deny-list refuse everything; the raw
        // copy is then only used for messages.
        let guard = raw.normalised().unwrap_or(raw);
        let common_files = guard
            .program_files_dirs()
            .map(|pf| format!("{pf}\\Common Files"))
            .collect();
        Self {
            guard,
            deny,
            common_files,
            other_dirs: Vec::new(),
            other_files: Vec::new(),
        }
    }

    /// The guard facts, with every directory in canonical form.
    pub fn guard(&self) -> &GuardEnv {
        &self.guard
    }

    /// The compiled deny-list.
    pub fn deny(&self) -> &DenyList {
        &self.deny
    }

    /// The other apps' directories.
    pub fn other_dirs(&self) -> &[OtherAnchor] {
        &self.other_dirs
    }

    /// The other apps' files.
    pub fn other_files(&self) -> &[OtherAnchor] {
        &self.other_files
    }

    /// The `Common Files` directories of every `Program Files` directory, canonical.
    pub fn common_files(&self) -> &[String] {
        &self.common_files
    }

    /// Declares a root directory of another app. Returns `false` when the path does not canonicalise or
    /// is a volume root.
    pub fn add_other_dir(&mut self, app: &str, path: &str) -> bool {
        let Some(path) = canon_file(path, &self.guard).filter(|p| prefix::depth(p) >= 2) else {
            return false;
        };
        push_anchor(
            &mut self.other_dirs,
            app,
            OtherAnchorKind::InstallLocation,
            path,
        );
        true
    }

    /// Declares a file of another app (uninstaller, icon, service image). Returns `false` when the path
    /// does not canonicalise.
    pub fn add_other_file(&mut self, app: &str, kind: OtherAnchorKind, path: &str) -> bool {
        let Some(path) = canon_file(path, &self.guard).filter(|p| prefix::depth(p) >= 2) else {
            return false;
        };
        push_anchor(&mut self.other_files, app, kind, path);
        true
    }

    /// The environment for harvesting `entry`: the machine's guard facts plus the paths of every other
    /// entry of `inventory` and of the services living in their directories. See the module
    /// documentation for what counts as another app.
    pub fn from_sources(
        reg: &dyn RegistrySource,
        sys: &dyn SystemSource,
        entry: &InventoryEntry,
        inventory: &InventoryDoc,
    ) -> (Self, Vec<String>) {
        let (guard, warnings) = guard_env(reg, sys);
        let env = env_map(&sys.env().unwrap_or_default());
        let mut this = Self::new(&guard);
        this.add_other_entries(entry, &inventory.entries, &env);
        this.add_services(reg, &env);
        (this, warnings)
    }

    /// Adds the paths of every entry that is another app than `entry`.
    pub fn add_other_entries(
        &mut self,
        entry: &InventoryEntry,
        all: &[InventoryEntry],
        env: &EnvMap,
    ) {
        let same_command =
            |other: &InventoryEntry| match (&entry.uninstall_string, &other.uninstall_string) {
                (Some(a), Some(b)) => {
                    !a.trim().is_empty() && a.trim().eq_ignore_ascii_case(b.trim())
                }
                _ => false,
            };
        for other in all {
            if other.program_id == entry.program_id || same_command(other) {
                continue;
            }
            let app = other.display_name.as_str();
            if let Some(dir) = other
                .install_location
                .as_deref()
                .and_then(|l| clean_value(l, env))
            {
                self.add_other_dir(app, &dir);
            }
            if let Some(exe) = other
                .uninstall_string
                .as_deref()
                .and_then(|c| command_exe(c, env, &self.guard))
            {
                self.add_other_file(app, OtherAnchorKind::Uninstaller, &exe);
            }
            if let Some(icon) = other
                .display_icon
                .as_deref()
                .and_then(|i| clean_value(icon_file(i), env))
            {
                self.add_other_file(app, OtherAnchorKind::DisplayIcon, &icon);
            }
        }
    }

    /// Adds the image of every service that lives in a directory another app declares.
    pub fn add_services(&mut self, reg: &dyn RegistrySource, env: &EnvMap) {
        // The directories the other apps declare, outside Windows (a service image in System32 says
        // nothing about who owns it).
        let mut dirs: Vec<(String, String)> = self
            .other_dirs
            .iter()
            .map(|a| (a.app.clone(), a.path.clone()))
            .chain(
                self.other_files
                    .iter()
                    .filter_map(|a| Some((a.app.clone(), parent_dir(&a.path)?))),
            )
            .filter(|(_, dir)| {
                !prefix::is_same_or_inside(dir, &self.guard.windir)
                    && self.deny.root_rejection(dir, true).is_none()
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        if dirs.is_empty() {
            return;
        }
        for name in reg.subkeys(SERVICES_KEY).unwrap_or_default() {
            let key = format!("{SERVICES_KEY}\\{name}");
            let mut images: Vec<String> = Vec::new();
            for (key, value) in [
                (key.clone(), "ImagePath"),
                (format!("{key}\\Parameters"), "ServiceDll"),
            ] {
                if let Some(image) = reg
                    .value(&key, value)
                    .ok()
                    .and_then(|d| d.string())
                    .and_then(|raw| service_image(&raw, env, &self.guard))
                {
                    images.push(image);
                }
            }
            for image in images {
                if let Some((app, _)) = dirs.iter().find(|(_, dir)| prefix::is_inside(&image, dir))
                {
                    let label = format!("{app} (service {name})");
                    push_anchor(
                        &mut self.other_files,
                        &label,
                        OtherAnchorKind::ServiceImage,
                        image,
                    );
                }
            }
        }
    }
}

fn push_anchor(list: &mut Vec<OtherAnchor>, app: &str, kind: OtherAnchorKind, path: String) {
    let anchor = OtherAnchor {
        app: app.to_owned(),
        kind,
        path,
    };
    if !list
        .iter()
        .any(|a| a.kind == kind && prefix::is_same(&a.path, &anchor.path))
    {
        list.push(anchor);
    }
}

/// The canonical path of a service image from an `ImagePath` or `ServiceDll` value: NT prefixes and the
/// `\SystemRoot\` and `System32\` forms resolved, variables expanded, arguments removed.
pub(crate) fn service_image(raw: &str, env: &EnvMap, guard: &GuardEnv) -> Option<String> {
    let s = raw.trim();
    let unquoted = s.trim_start_matches('"');
    let s = if let Some(rest) = strip_prefix_ci(unquoted, r"\??\") {
        rest.to_owned()
    } else if let Some(rest) = strip_prefix_ci(unquoted, r"\SystemRoot\") {
        format!("{}\\{rest}", guard.windir)
    } else if strip_prefix_ci(unquoted, r"System32\").is_some() {
        format!("{}\\{unquoted}", guard.windir)
    } else {
        s.to_owned()
    };
    command_exe(&s, env, guard)
}

/// `s` without the ASCII-case-insensitive `prefix`.
pub(crate) fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix))
    .then(|| &s[prefix.len()..])
}

// ---------------------------------------------------------------------------------------------------------
// validate_root
// ---------------------------------------------------------------------------------------------------------

/// Why a path cannot be a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRejection {
    /// The path does not canonicalise; the guard's `canon.*` code says why.
    NotCanonical(&'static str),
    /// A segment looks like an 8.3 short name and was not resolved.
    ShortName,
    /// A volume root (`C:\`).
    VolumeRoot,
    /// The guard refuses it; the rule name says which location it is.
    Denied(String),
    /// A `Common Files` directory, or inside one.
    CommonFiles,
    /// It is, or contains, the root of another installed app.
    HoldsOtherApp {
        /// The other app.
        app: String,
        /// That app's root.
        path: String,
    },
    /// It contains an anchor of another installed app.
    ParentOfOtherAnchor {
        /// The other app.
        app: String,
        /// What the anchor is.
        kind: OtherAnchorKind,
        /// The anchor's path.
        path: String,
    },
    /// The directory does not exist.
    Missing,
    /// The path is a file.
    NotADirectory,
    /// The path is a reparse point (junction, symbolic link, mount point).
    ReparsePoint,
    /// The source could not read it.
    Unreadable(SourceError),
}

impl RootRejection {
    /// A short stable code, for logs and tests.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotCanonical(_) => "not-canonical",
            Self::ShortName => "short-name",
            Self::VolumeRoot => "volume-root",
            Self::Denied(_) => "denied",
            Self::CommonFiles => "common-files",
            Self::HoldsOtherApp { .. } => "holds-other-app",
            Self::ParentOfOtherAnchor { .. } => "parent-of-other-anchor",
            Self::Missing => "missing",
            Self::NotADirectory => "not-a-directory",
            Self::ReparsePoint => "reparse-point",
            Self::Unreadable(_) => "unreadable",
        }
    }
}

impl fmt::Display for RootRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical(code) => write!(f, "not a canonical local path (canon.{code})"),
            Self::ShortName => f.write_str("holds an unresolved 8.3 name"),
            Self::VolumeRoot => f.write_str("a volume root"),
            Self::Denied(rule) => write!(f, "refused by the guard ({rule})"),
            Self::CommonFiles => f.write_str("in a Common Files directory"),
            Self::HoldsOtherApp { app, path } => {
                write!(f, "holds the root of another app ({app}: {path})")
            }
            Self::ParentOfOtherAnchor { app, kind, path } => {
                write!(
                    f,
                    "holds the {} of another app ({app}: {path})",
                    kind.label()
                )
            }
            Self::Missing => f.write_str("does not exist"),
            Self::NotADirectory => f.write_str("not a directory"),
            Self::ReparsePoint => f.write_str("a reparse point"),
            Self::Unreadable(e) => write!(f, "cannot be read ({e})"),
        }
    }
}

impl std::error::Error for RootRejection {}

/// Decides whether `path` may be a root of the app (§5.2). Lexical and pure; `source` does not change
/// the answer (a rejected path can be no kind of root) and is taken so that every caller states where
/// the claim came from.
///
/// Returns the canonical path, without a trailing separator.
///
/// # Errors
///
/// The first [`RootRejection`] that applies; see the module documentation for the list.
pub fn validate_root(
    path: &str,
    source: RootSource,
    env: &RootEnv,
) -> Result<String, RootRejection> {
    let _ = source;
    let canon = canon_path(path.trim().trim_matches('"').trim(), &env.guard, None)
        .map_err(|e| RootRejection::NotCanonical(e.code()))?;
    if canon.needs_long_name {
        return Err(RootRejection::ShortName);
    }
    let path = canon.path;
    if prefix::depth(&path) < 2 {
        return Err(RootRejection::VolumeRoot);
    }
    if let Some(rule) = env.deny.root_rejection(&path, true) {
        return Err(RootRejection::Denied(rule));
    }
    if env
        .common_files
        .iter()
        .any(|dir| prefix::is_same_or_inside(&path, dir))
    {
        return Err(RootRejection::CommonFiles);
    }
    if let Some(other) = env
        .other_dirs
        .iter()
        .find(|o| prefix::is_same_or_inside(&o.path, &path))
    {
        return Err(RootRejection::HoldsOtherApp {
            app: other.app.clone(),
            path: other.path.clone(),
        });
    }
    if let Some(other) = env
        .other_files
        .iter()
        .find(|o| prefix::is_inside(&o.path, &path))
    {
        return Err(RootRejection::ParentOfOtherAnchor {
            app: other.app.clone(),
            kind: other.kind,
            path: other.path.clone(),
        });
    }
    Ok(path)
}

/// Validates `path` against the file system as well and builds the [`Root`]: 8.3 names are expanded
/// first, the directory must exist and must not be a reparse point, and trust, volume serial and the
/// parent's existence are recorded. `user_hive` says the claim was read from an `HKU` Uninstall key.
///
/// # Errors
///
/// A [`RootRejection`], from [`validate_root`] or from the file-system checks.
pub fn resolve_root(
    fs: &dyn FileSystemSource,
    path: &str,
    source: RootSource,
    user_hive: bool,
    env: &RootEnv,
) -> Result<Root, RootRejection> {
    let raw = path.trim().trim_matches('"').trim();
    let lexical = canon_path(raw, &env.guard, None)
        .map_err(|e| RootRejection::NotCanonical(e.code()))?
        .path;
    // The long form also gives the on-disk spelling. A path that does not exist keeps its lexical form
    // and is rejected below with the precise reason.
    let long = fs
        .long_path(&lexical)
        .ok()
        .and_then(|p| canon_file(&p, &env.guard));
    let candidate = long.unwrap_or(lexical);
    let path = validate_root(&candidate, source, env)?;
    let meta = match fs.metadata(&path) {
        Ok(meta) => meta,
        Err(SourceError::NotFound) => return Err(RootRejection::Missing),
        Err(e) => return Err(RootRejection::Unreadable(e)),
    };
    if meta.is_reparse_point() {
        return Err(RootRejection::ReparsePoint);
    }
    if !meta.is_dir() {
        return Err(RootRejection::NotADirectory);
    }
    let trust = if !user_hive && fs.is_admin_only_writable(&path).unwrap_or(false) {
        SourceTrust::AdminOnly
    } else {
        SourceTrust::UserWritable
    };
    let parent = match prefix::parent(&path) {
        Some(p) if prefix::depth(p) >= 2 => p.to_owned(),
        Some(drive) => format!("{drive}\\"),
        None => String::new(),
    };
    Ok(Root {
        kind: source.root_kind(),
        source,
        trust,
        volume_serial: fs.volume_info(&path).ok().and_then(|v| v.serial),
        parent_existed: !parent.is_empty() && fs.exists(&parent).is_present(),
        path,
    })
}

// ---------------------------------------------------------------------------------------------------------
// Collecting an entry's roots
// ---------------------------------------------------------------------------------------------------------

/// A root claim that did not pass validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRoot {
    /// The path as claimed.
    pub path: String,
    /// Where the claim came from.
    pub source: RootSource,
    /// Why it was rejected.
    pub reason: RootRejection,
}

impl fmt::Display for RejectedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "root {:?} from {:?} rejected: {}",
            self.path, self.source, self.reason
        )
    }
}

/// What the Inno Setup records say about the app directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InnoRootFacts {
    /// The `Inno Setup: App Path` value of the Uninstall key, as written.
    pub app_path: Option<String>,
    /// The app directories the uninstall log's install runs name.
    pub log_app_dirs: Vec<String>,
}

/// The roots of one entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootSet {
    /// The validated roots: install roots first, each path once.
    pub roots: Vec<Root>,
    /// The claims that were rejected.
    pub rejected: Vec<RejectedRoot>,
}

impl RootSet {
    /// The roots of kind `InstallRoot`.
    pub fn install_roots(&self) -> impl Iterator<Item = &Root> {
        self.roots
            .iter()
            .filter(|r| r.kind == RootKind::InstallRoot)
    }
}

/// Collects and validates the roots of `entry`. `env_vars` is the interactive user's environment, used
/// to expand the entry's values; see the module documentation for the sources and their kinds.
pub fn collect(
    fs: &dyn FileSystemSource,
    entry: &InventoryEntry,
    inno: &InnoRootFacts,
    env_vars: &EnvMap,
    env: &RootEnv,
) -> RootSet {
    let guard = env.guard();
    let uninstaller = entry
        .uninstall_string
        .as_deref()
        .filter(|c| !kind::is_msiexec(c))
        .and_then(|c| command_exe(c, env_vars, guard));
    let uninstaller_dir = uninstaller.as_deref().and_then(parent_dir);

    let mut claims: Vec<(String, RootSource)> = Vec::new();
    if let Some(dir) = entry
        .install_location
        .as_deref()
        .and_then(|l| clean_value(l, env_vars))
    {
        claims.push((dir, RootSource::ArpInstallLocation));
    }
    if let Some(dir) = inno
        .app_path
        .as_deref()
        .and_then(|l| clean_value(l, env_vars))
    {
        claims.push((dir, RootSource::InnoApp));
    }
    // The uninstaller's directory is the Inno `{app}` only when the log itself names that directory.
    if let Some(dir) = &uninstaller_dir {
        let confirmed = inno
            .log_app_dirs
            .iter()
            .filter_map(|d| canon_file(d.trim_end_matches('\\'), guard))
            .any(|d| prefix::is_same(&d, dir));
        if confirmed {
            claims.push((dir.clone(), RootSource::InnoApp));
        }
    }
    if let Some(dir) = entry
        .display_icon
        .as_deref()
        .and_then(|i| clean_value(icon_file(i), env_vars))
        .and_then(|file| canon_file(&file, guard))
        .as_deref()
        .and_then(parent_dir)
    {
        claims.push((dir, RootSource::DisplayIcon));
    }
    if let Some(dir) = uninstaller_dir {
        claims.push((dir, RootSource::UninstallerDir));
    }

    let user_hive = entry.hive_sid.is_some();
    let mut set = RootSet::default();
    for (path, source) in claims {
        match resolve_root(fs, &path, source, user_hive, env) {
            Ok(root) => {
                let redundant = set.roots.iter().any(|have| {
                    prefix::is_same(&have.path, &root.path)
                        || (root.kind != RootKind::InstallRoot
                            && have.kind == RootKind::InstallRoot
                            && prefix::is_inside(&root.path, &have.path))
                });
                if !redundant {
                    set.roots.push(root);
                }
            }
            Err(reason) => {
                let rejected = RejectedRoot {
                    path,
                    source,
                    reason,
                };
                if !set.rejected.contains(&rejected) {
                    set.rejected.push(rejected);
                }
            }
        }
    }
    // An inferred root below any other root adds nothing (an icon in a subdirectory of the app).
    let all = set.roots.clone();
    set.roots.retain(|root| {
        root.kind == RootKind::InstallRoot
            || !all.iter().any(|o| prefix::is_inside(&root.path, &o.path))
    });
    // Install roots first; the claim order is kept inside each kind.
    set.roots
        .sort_by_key(|r| u8::from(r.kind != RootKind::InstallRoot));
    set
}

/// Builders shared by the tests of this crate.
#[cfg(test)]
pub(crate) mod tests_support {
    use purge_model::{
        InstallScope, InstallerKind, InventoryEntry, ProgramId, RawFlags, View, WritableBy,
    };

    /// A machine-wide entry with nothing but its key name and display name.
    pub(crate) fn entry(key: &str, name: &str) -> InventoryEntry {
        let program_id = ProgramId::machine(View::K64, key).unwrap();
        InventoryEntry {
            key_path: program_id.key_path(),
            program_id,
            hive_sid: None,
            view: View::K64,
            display_name: name.to_owned(),
            version: None,
            publisher: None,
            flags: RawFlags::default(),
            installer_kind: InstallerKind::Unknown,
            scope: InstallScope::Machine,
            product_code: None,
            upgrade_code: None,
            inno_app_id: None,
            writable_by: WritableBy::Admin,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            install_time_evidence: Vec::new(),
            msi: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::entry;
    use super::*;
    use purge_model::{ProgramId, View};
    use purge_source::fixture::Fixture;

    const SID: &str = GuardEnv::SAMPLE_SID;

    fn env() -> RootEnv {
        let mut guard = GuardEnv::sample();
        guard.sync_roots = vec![r"C:\Users\tester\OneDrive".into()];
        RootEnv::new(&guard)
    }

    fn reject(path: &str, env: &RootEnv) -> RootRejection {
        validate_root(path, RootSource::ArpInstallLocation, env)
            .expect_err(&format!("{path} must be rejected"))
    }

    fn denied(path: &str, env: &RootEnv) -> String {
        match reject(path, env) {
            RootRejection::Denied(rule) => rule,
            other => panic!("{path}: expected a guard rule, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_install_directories_pass() {
        let env = env();
        for (given, want) in [
            (r"C:\Program Files\Git\", r"C:\Program Files\Git"),
            (
                r#""C:\Program Files\Mozilla Firefox""#,
                r"C:\Program Files\Mozilla Firefox",
            ),
            (
                r"c:/Program Files (x86)/Notepad++",
                r"C:\Program Files (x86)\Notepad++",
            ),
            (
                r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code",
                r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code",
            ),
            (r"D:\Tools\App", r"D:\Tools\App"),
            (r"C:\ProgramData\Vendor\App", r"C:\ProgramData\Vendor\App"),
        ] {
            assert_eq!(
                validate_root(given, RootSource::ArpInstallLocation, &env).as_deref(),
                Ok(want),
                "{given}"
            );
        }
    }

    #[test]
    fn deny_listed_locations_are_rejected() {
        let env = env();
        assert_eq!(denied(r"C:\Windows", &env), "fs.windir");
        assert_eq!(denied(r"C:\Windows\System32\MyApp", &env), "fs.windir");
        assert_eq!(denied(r"C:\Program Files\Purge", &env), "fs.purge");
        // Common Files itself, and anything inside it.
        for path in [
            r"C:\Program Files\Common Files",
            r"C:\Program Files\Common Files\Vendor",
            r"C:\Program Files (x86)\Common Files\Vendor\Shared",
        ] {
            let r = reject(path, &env);
            assert!(
                matches!(r, RootRejection::CommonFiles | RootRejection::Denied(_)),
                "{path}: {r:?}"
            );
        }
        assert_eq!(
            reject(r"C:\Program Files\Common Files\Vendor", &env),
            RootRejection::CommonFiles
        );
    }

    #[test]
    fn known_folders_and_user_content_are_rejected() {
        let env = env();
        assert_eq!(denied(r"C:\Users\tester", &env), "fs.profile-root");
        assert_eq!(
            denied(r"C:\Users\tester\AppData\Roaming", &env),
            "fs.known-folder"
        );
        assert_eq!(
            denied(r"C:\Users\tester\AppData\Local", &env),
            "fs.known-folder"
        );
        assert_eq!(
            denied(r"C:\Users\tester\Documents", &env),
            "fs.known-folder"
        );
        // Regression: an app installed into Documents.
        assert_eq!(
            denied(r"C:\Users\tester\Documents\MyApp", &env),
            "root.user-content"
        );
        assert_eq!(
            denied(r"C:\Users\tester\Desktop\Portable\App", &env),
            "root.user-content"
        );
        assert_eq!(
            denied(r"C:\Users\tester\Downloads\app-1.0", &env),
            "root.user-content"
        );
        // A redirected Documents folder.
        let mut guard = GuardEnv::sample();
        guard.profiles[0].user_content_folders = vec![r"D:\Docs".into()];
        let env = RootEnv::new(&guard);
        assert!(matches!(reject(r"D:\Docs", &env), RootRejection::Denied(_)));
        assert_eq!(denied(r"D:\Docs\MyApp", &env), "root.user-content");
    }

    #[test]
    fn sync_roots_are_rejected() {
        let env = env();
        assert_eq!(denied(r"C:\Users\tester\OneDrive", &env), "fs.sync-root");
        assert_eq!(
            denied(r"C:\Users\tester\OneDrive\Apps\Tool", &env),
            "fs.sync-root"
        );
    }

    #[test]
    fn containers_are_rejected() {
        let env = env();
        assert_eq!(reject(r"C:\", &env), RootRejection::VolumeRoot);
        assert_eq!(reject(r"D:\", &env), RootRejection::VolumeRoot);
        // Regression: InstallLocation `C:\Program Files\`.
        assert_eq!(denied(r"C:\Program Files\", &env), "fs.program-files");
        assert_eq!(denied(r"C:\Program Files (x86)", &env), "fs.program-files");
        assert_eq!(denied(r"C:\ProgramData", &env), "fs.programdata");
        assert_eq!(
            denied(r"C:\Users\tester\AppData\Local\Programs", &env),
            "fs.local-programs"
        );
        assert_eq!(denied(r"C:\Users", &env), "fs.profiles-dir");
    }

    #[test]
    fn installer_stores_are_rejected() {
        let env = env();
        assert_eq!(
            denied(
                r"C:\ProgramData\Package Cache\{11111111-2222-3333-4444-555555555555}",
                &env
            ),
            "root.package-cache"
        );
        assert_eq!(
            denied(r"C:\Users\tester\AppData\Local\Package Cache\{1}v1", &env),
            "root.package-cache"
        );
        assert_eq!(denied(r"C:\Windows\Installer\{1}", &env), "fs.windir");
        assert_eq!(
            denied(
                r"C:\Program Files (x86)\InstallShield Installation Information\{1}",
                &env
            ),
            "root.installshield-info"
        );
    }

    #[test]
    fn unusable_paths_are_rejected() {
        let env = env();
        for (path, code) in [
            ("", "empty"),
            (r"Program Files\App", "relative"),
            (r"\\server\share\App", "unc"),
            (r"C:\Program Files\App\..\Other", "dot-segment"),
            (r"\\.\C:\App", "device-namespace"),
        ] {
            assert_eq!(
                reject(path, &env),
                RootRejection::NotCanonical(code),
                "{path}"
            );
        }
        assert_eq!(reject(r"C:\PROGRA~1\App", &env), RootRejection::ShortName);
    }

    /// A vendor folder holding another app: `Program Files\Mozilla\Thunderbird` is installed, so
    /// `Program Files\Mozilla` cannot be Firefox's root; `Program Files\Mozilla Firefox` can.
    #[test]
    fn vendor_folder_holding_another_app_is_rejected() {
        let mut env = env();
        assert!(env.add_other_dir(
            "Mozilla Thunderbird",
            r"C:\Program Files\Mozilla\Thunderbird\"
        ));
        assert_eq!(
            reject(r"C:\Program Files\Mozilla", &env),
            RootRejection::HoldsOtherApp {
                app: "Mozilla Thunderbird".into(),
                path: r"C:\Program Files\Mozilla\Thunderbird".into(),
            }
        );
        // The other app's own root is not ours either.
        assert_eq!(
            reject(r"C:\Program Files\Mozilla\Thunderbird", &env).code(),
            "holds-other-app"
        );
        assert!(
            validate_root(
                r"C:\Program Files\Mozilla Firefox",
                RootSource::InnoApp,
                &env
            )
            .is_ok()
        );
        assert!(
            validate_root(
                r"C:\Program Files\Mozilla\Firefox",
                RootSource::InnoApp,
                &env
            )
            .is_ok()
        );
        // A directory inside another app's root is not refused by this rule.
        assert!(
            validate_root(
                r"C:\Program Files\Mozilla\Thunderbird\addon",
                RootSource::InnoApp,
                &env
            )
            .is_ok()
        );
    }

    #[test]
    fn parent_of_another_apps_anchor_is_rejected() {
        for kind in [
            OtherAnchorKind::Uninstaller,
            OtherAnchorKind::DisplayIcon,
            OtherAnchorKind::ServiceImage,
        ] {
            let mut env = env();
            assert!(env.add_other_file("Other", kind, r"C:\Apps\Suite\Other\tool.exe"));
            assert_eq!(
                reject(r"C:\Apps\Suite", &env),
                RootRejection::ParentOfOtherAnchor {
                    app: "Other".into(),
                    kind,
                    path: r"C:\Apps\Suite\Other\tool.exe".into(),
                },
                "{kind:?}"
            );
            assert_eq!(
                reject(r"C:\Apps\Suite\Other", &env).code(),
                "parent-of-other-anchor"
            );
            assert!(validate_root(r"C:\Apps\Suite\Mine", RootSource::InnoApp, &env).is_ok());
            assert!(validate_root(r"C:\Apps\Suite2", RootSource::InnoApp, &env).is_ok());
        }
    }

    fn machine() -> Fixture {
        Fixture::builder()
            .user_sid(SID)
            .profile(SID, r"C:\Users\tester")
            .env("SYSTEMDRIVE", "C:")
            .env("WINDIR", r"C:\Windows")
            .env("PROGRAMFILES", r"C:\Program Files")
            .env("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            .env("PROGRAMDATA", r"C:\ProgramData")
            .env("PUBLIC", r"C:\Users\Public")
            .env("APPDATA", r"C:\Users\tester\AppData\Roaming")
            .env("LOCALAPPDATA", r"C:\Users\tester\AppData\Local")
            .env("ONEDRIVE", r"C:\Users\tester\OneDrive")
            .known_folder(KnownFolder::Documents, r"D:\Docs")
            .admin_only_roots(&[
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\Windows",
            ])
            .volume(r"C:\", Some(0x1234_5678), true, "NTFS")
            .dir(r"C:\Program Files\Mozilla Firefox\uninstall")
            .file(r"C:\Program Files\Mozilla Firefox\firefox.exe", 10)
            .file(r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe", 10)
            .dir(r"C:\Program Files\Mozilla Thunderbird")
            .dir(r"C:\Program Files (x86)\Mozilla Maintenance Service")
            .dir(r"C:\Users\tester\AppData\Local\Programs\Tool")
            .key(r"HKLM\SYSTEM\ControlSet001\Services")
            .build()
    }

    #[test]
    fn guard_env_is_read_from_the_sources() {
        let mut f = machine();
        f.set_value(
            &format!(r"{SYNC_ROOT_MANAGER}\Box!S-1!x\UserSyncRoots"),
            SID,
            purge_source::types::RegData::from_sz(r"C:\Users\tester\Box"),
        );
        let (guard, warnings) = guard_env(&f, &f);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(guard.missing().is_empty());
        assert_eq!(guard.windir, r"C:\Windows");
        assert_eq!(guard.profiles_dir, r"C:\Users");
        assert_eq!(guard.current_control_set, 1);
        assert_eq!(
            guard.sync_roots,
            [r"C:\Users\tester\Box", r"C:\Users\tester\OneDrive"]
        );
        let profile = guard.profile(SID).unwrap();
        assert_eq!(profile.local_appdata, r"C:\Users\tester\AppData\Local");
        assert_eq!(profile.user_content_folders, [r"D:\Docs"]);
        let env = RootEnv::new(&guard);
        assert_eq!(denied(r"D:\Docs\App", &env), "root.user-content");
        assert_eq!(denied(r"C:\Users\tester\Box\App", &env), "fs.sync-root");

        // Without system facts every root is rejected.
        let empty = Fixture::new();
        let (guard, warnings) = guard_env(&empty, &empty);
        assert!(
            warnings.iter().any(|w| w.contains("missing")),
            "{warnings:?}"
        );
        let env = RootEnv::new(&guard);
        assert!(validate_root(r"C:\Program Files\Git", RootSource::InnoApp, &env).is_err());
    }

    #[test]
    fn other_apps_come_from_the_inventory_and_the_services() {
        let mut f = machine();
        f.set_value(
            r"HKLM\SYSTEM\ControlSet001\Services\MozillaMaintenance",
            "ImagePath",
            purge_source::types::RegData::from_expand_sz(
                r#""C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe" -x"#,
            ),
        );
        f.set_value(
            r"HKLM\SYSTEM\ControlSet001\Services\Unrelated",
            "ImagePath",
            purge_source::types::RegData::from_expand_sz(r"\SystemRoot\System32\svchost.exe -k x"),
        );
        let mut firefox = entry("Mozilla Firefox", "Mozilla Firefox");
        firefox.install_location = Some(r"C:\Program Files\Mozilla Firefox".into());
        firefox.uninstall_string =
            Some(r#""C:\Program Files\Mozilla Firefox\uninstall\helper.exe""#.into());
        // The same registration seen through the 32-bit view is not another app.
        let mut twin = firefox.clone();
        twin.program_id = ProgramId::machine(View::K32, "Mozilla Firefox").unwrap();
        let mut thunderbird = entry("Mozilla Thunderbird", "Mozilla Thunderbird");
        thunderbird.install_location = Some(r"C:\Program Files\Mozilla Thunderbird\".into());
        thunderbird.display_icon =
            Some(r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe,0".into());
        let mut service = entry("MozillaMaintenanceService", "Mozilla Maintenance Service");
        service.uninstall_string =
            Some(r#""C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S"#.into());
        let inventory = InventoryDoc {
            schema: Default::default(),
            entries: vec![firefox.clone(), twin, thunderbird, service],
            msi_only: Vec::new(),
        };
        let (env, warnings) = RootEnv::from_sources(&f, &f, &firefox, &inventory);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            env.other_dirs()
                .iter()
                .map(|a| a.path.as_str())
                .collect::<Vec<_>>(),
            [r"C:\Program Files\Mozilla Thunderbird"]
        );
        let files: Vec<_> = env
            .other_files()
            .iter()
            .map(|a| (a.kind, a.path.as_str()))
            .collect();
        assert_eq!(
            files,
            [
                (
                    OtherAnchorKind::DisplayIcon,
                    r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe"
                ),
                (
                    OtherAnchorKind::Uninstaller,
                    r"C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe"
                ),
                (
                    OtherAnchorKind::ServiceImage,
                    r"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
                ),
            ]
        );
        assert!(
            validate_root(
                r"C:\Program Files\Mozilla Firefox",
                RootSource::InnoApp,
                &env
            )
            .is_ok()
        );
        assert_eq!(
            reject(r"C:\Program Files (x86)\Mozilla Maintenance Service", &env).code(),
            "parent-of-other-anchor"
        );
    }

    #[test]
    fn resolve_checks_the_file_system_and_records_the_facts() {
        let mut f = machine();
        f.add_file(r"C:\Program Files\single.exe", 1);
        f.add_dir(r"C:\Program Files\Linked");
        f.set_reparse_tag(r"C:\Program Files\Linked", 0xA000_0003);
        f.set_short_name(r"C:\Program Files\Mozilla Firefox", "MOZILL~1");
        let (guard, _) = guard_env(&f, &f);
        let env = RootEnv::new(&guard);
        let resolve = |path: &str, user_hive| {
            resolve_root(&f, path, RootSource::ArpInstallLocation, user_hive, &env)
        };

        let root = resolve(r"c:\program files\mozilla firefox\", false).unwrap();
        assert_eq!(
            root,
            Root {
                path: r"C:\Program Files\Mozilla Firefox".into(),
                kind: RootKind::InstallRoot,
                source: RootSource::ArpInstallLocation,
                trust: SourceTrust::AdminOnly,
                volume_serial: Some(0x1234_5678),
                parent_existed: true,
            }
        );
        // An 8.3 spelling resolves to the same root.
        assert_eq!(
            resolve(r"C:\Program Files\MOZILL~1", false).unwrap().path,
            root.path
        );
        // Rule T: a claim read from an HKU key is user-writable whatever the directory's ACL.
        assert_eq!(
            resolve(r"C:\Program Files\Mozilla Firefox", true)
                .unwrap()
                .trust,
            SourceTrust::UserWritable
        );
        // A directory the user can write.
        assert_eq!(
            resolve(r"C:\Users\tester\AppData\Local\Programs\Tool", false)
                .unwrap()
                .trust,
            SourceTrust::UserWritable
        );
        assert_eq!(
            resolve(r"C:\Program Files\Gone", false),
            Err(RootRejection::Missing)
        );
        assert_eq!(
            resolve(r"C:\Program Files\single.exe", false),
            Err(RootRejection::NotADirectory)
        );
        assert_eq!(
            resolve(r"C:\Program Files\Linked", false),
            Err(RootRejection::ReparsePoint)
        );
        assert_eq!(
            resolve(r"C:\Program Files\", false),
            Err(RootRejection::Denied("fs.program-files".into()))
        );
    }

    #[test]
    fn collect_orders_kinds_and_drops_redundant_claims() {
        let mut f = machine();
        f.add_dir(r"C:\Program Files\Git\mingw64\share");
        f.add_file(r"C:\Program Files\Git\unins000.exe", 1);
        f.add_dir(r"C:\Program Files\Notepad++");
        let (guard, _) = guard_env(&f, &f);
        let env = RootEnv::new(&guard);
        let vars = env_map(&f.env().unwrap());

        // Inno: InstallLocation, App Path and the log agree; icon and uninstaller add nothing.
        let mut git = entry("Git_is1", "Git");
        git.install_location = Some(r"C:\Program Files\Git\".into());
        git.uninstall_string = Some(r#""C:\Program Files\Git\unins000.exe""#.into());
        git.display_icon = Some(r"C:\Program Files\Git\mingw64\share\git.ico".into());
        let inno = InnoRootFacts {
            app_path: Some(r"C:\Program Files\Git".into()),
            log_app_dirs: vec![r"C:\Program Files\Git".into()],
        };
        let set = collect(&f, &git, &inno, &vars, &env);
        assert_eq!(set.roots.len(), 1, "{set:?}");
        assert_eq!(set.roots[0].source, RootSource::ArpInstallLocation);
        assert!(set.rejected.is_empty());

        // Only the log confirms the uninstaller's directory.
        git.install_location = None;
        let inno = InnoRootFacts {
            app_path: None,
            log_app_dirs: vec![r"C:\Program Files\Git\".into()],
        };
        let set = collect(&f, &git, &inno, &vars, &env);
        assert_eq!(set.roots.len(), 1);
        assert_eq!(
            (set.roots[0].kind, set.roots[0].source),
            (RootKind::InstallRoot, RootSource::InnoApp)
        );
        // A log naming another directory confirms nothing.
        let inno = InnoRootFacts {
            app_path: None,
            log_app_dirs: vec![r"C:\Program Files\Other".into()],
        };
        let set = collect(&f, &git, &inno, &vars, &env);
        assert_eq!(set.roots.len(), 1);
        assert_eq!(
            (set.roots[0].kind, set.roots[0].source),
            (RootKind::InferredRoot, RootSource::UninstallerDir)
        );

        // NSIS without InstallLocation: inferred only; a bad InstallLocation is reported.
        let mut npp = entry("Notepad++", "Notepad++ (64-bit x64)");
        npp.install_location = Some(r"C:\Program Files\".into());
        npp.display_icon = Some(r"C:\Program Files\Notepad++\notepad++.exe".into());
        npp.uninstall_string = Some(r#""C:\Program Files\Notepad++\uninstall.exe""#.into());
        let set = collect(&f, &npp, &InnoRootFacts::default(), &vars, &env);
        assert_eq!(set.roots.len(), 1);
        assert_eq!(
            (set.roots[0].kind, set.roots[0].source),
            (RootKind::InferredRoot, RootSource::DisplayIcon)
        );
        assert_eq!(set.install_roots().count(), 0);
        assert_eq!(set.rejected.len(), 1);
        assert_eq!(
            set.rejected[0].reason,
            RootRejection::Denied("fs.program-files".into())
        );
        assert!(set.rejected[0].to_string().contains("fs.program-files"));

        // msiexec's directory is never a claim.
        let mut msi = entry("{11111111-2222-3333-4444-555555555555}", "Some MSI");
        msi.uninstall_string = Some(r"MsiExec.exe /X{11111111-2222-3333-4444-555555555555}".into());
        let set = collect(&f, &msi, &InnoRootFacts::default(), &vars, &env);
        assert!(set.roots.is_empty() && set.rejected.is_empty(), "{set:?}");
    }
}
