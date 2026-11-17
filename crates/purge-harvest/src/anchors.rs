//! The registry anchors of an app (ENGINE_PLAN.md §5.4 "Anchors"): the ProgID set P, its COM ids, its
//! AppUserModelIDs and its Run entries, read while the app is still installed.
//!
//! Everything here starts from one question: *does this registration point at the app's files?* A path
//! is the app's when it lies under an **InstallRoot** or is a file of the exe set (which holds the files
//! of the InstallRoots and the main exes of an inferred root). A bare inferred directory proves nothing
//! and is not used.
//!
//! # The ProgID set P
//!
//! A ProgID is a direct child of a Classes root (`HKLM\SOFTWARE\Classes`, `HKU\<sid>_Classes`) that is
//! not an extension (`.txt`) and not one of the structural keys (`CLSID`, `Directory`, `*`, …). It is a
//! *candidate* when at least one `shell\<verb>\command` of it targets the app. A candidate is in P only
//! when
//!
//! - **every** verb command of it, in every Classes root, *runs* the app: its executable is one of the
//!   app's files, or it is a host that Windows ships (`rundll32`, `cmd`, …) or a bare program name and
//!   the command names one of the app's files. A command whose executable is another program's file is
//!   that program's, even when one of the app's files is among its arguments (a sandbox or launcher
//!   that wraps the app);
//! - it is not one of the classes and URL schemes Windows ships ([`WELL_KNOWN_SHARED`]), a fallback
//!   for a Windows without a matching baseline;
//! - the key is not in the clean-Windows baseline (when one matches this Windows) and is not owned by
//!   TrustedInstaller: Windows did not ship it. A key whose owner cannot be read counts as owned by
//!   Windows;
//! - no registered application that is not the app's lists it in its `Capabilities` associations;
//! - the key itself is not older than the app's install ([`ComCutoff`], as for COM classes). A URL
//!   scheme that a second, unregistered copy of the same program set up first and that the installed
//!   app re-pointed at itself (`HKCU\Software\Classes\vscode` of a portable VS Code) keeps the last
//!   write time of its first registration: the installed app only rewrote the command below it.
//!
//! A candidate that fails one of these existed before the app, or is shared with something else; the
//! app only modified it. It is reported in [`AnchorHarvest::modified_progids`] and is never an anchor.
//! A `DefaultIcon` in the roots, or an AUMID, never makes a ProgID a candidate.
//!
//! # COM ids
//!
//! A CLSID is a *candidate* when its `InprocServer32` or `LocalServer32` lies in the app's files. That
//! alone says only that the app wrote the server path: an installer overwrites the server of a class
//! another product registered first (two products of one vendor that both register the same proxy DLL
//! under one CLSID, each pointing it at its own copy). A candidate is the app's only when, in every
//! Classes root that has it,
//!
//! - the key is not in the baseline and is not owned by TrustedInstaller (an owner that cannot be read
//!   counts as Windows);
//! - the key is not older than the app's install (its last write is not more than a day before the
//!   earliest install-time hint; a key that existed before was only modified);
//! - no other installed app ships a file with the name of the server in one of its own directories
//!   (the class is shared, and whichever product was installed last holds the path).
//!
//! A candidate that fails one of these is "modified, not owned": it is reported in
//! [`AnchorHarvest::modified_clsids`] and is never an anchor, so nothing that merely mentions the id
//! (an `Interface\{iid}\ProxyStubClsid32` value, say) is attributed through it. The `AppID` value of
//! an owned class gives an AppID. A type library is the app's when one of its `win32`/`win64` paths
//! lies in the app's files and its key passes the baseline and age tests. They are recorded as
//! anchors for the reference scanners; removing COM keys is a later milestone.
//!
//! # AUMIDs
//!
//! Three sources: `Classes\AppUserModelId\<name>` keys whose values reference the app's files (or whose
//! activator is one of the app's CLSIDs), the `System.AppUserModel.ID` of Start Menu and desktop
//! shortcuts that start the app, and the names under which the app is listed in
//! `RegisteredApplications` (its `Capabilities` key references the app's files).
//!
//! # Other apps' names
//!
//! While walking, the names that belong to *something else* are collected in
//! [`AnchorHarvest::foreign_names`]: ProgIDs whose commands run other programs, AUMID keys and registered
//! applications that are not the app's. The token harvest drops a token that occurs in any of them.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use purge_guard::canon::GuardEnv;
use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_index::matcher::{AnchorSet, RefMatcher};
use purge_inventory::kind::is_braced_guid;
use purge_model::{AnchorKind, Anchors, ExeFile, FileTime, Root, RootKind, RunEntry};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{ExistsState, KnownFolder, SourceError};
use purge_win::env::EnvMap;

use crate::roots::{OtherAnchor, canon_file, clean_value, command_exe, env_map, parent_dir};

/// `HKLM\SOFTWARE\Classes`.
const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";
/// The 32-bit half of the machine's Classes, in its physical spelling (which every source accepts;
/// `HKLM\SOFTWARE\WOW6432Node\Classes` is a link to it).
const HKLM_CLASSES_32: &str = r"HKLM\SOFTWARE\Classes\WOW6432Node";

/// Direct children of a Classes root that are containers or shell objects, never ProgIDs of one app.
const STRUCTURAL: [&str; 34] = [
    "*",
    "ActivatableClasses",
    "AllFilesystemObjects",
    "AllSyncRootObjects",
    "AppID",
    "Applications",
    "AppUserModelId",
    "AppX",
    "AudioCD",
    "CID",
    "CLSID",
    "Component Categories",
    "DesktopBackground",
    "Directory",
    "DirectShow",
    "Drive",
    "DVD",
    "Extensions",
    "Filter",
    "Folder",
    "Installer",
    "Interface",
    "LibraryFolder",
    "Local Settings",
    "Media Type",
    "MIME",
    "Network",
    "PackagedCom",
    "Printers",
    "PROTOCOLS",
    "SystemFileAssociations",
    "TypeLib",
    "Unknown",
    "WOW6432Node",
];

/// Classes and URL schemes that Windows ships and many programs add verbs to or take over. They are
/// never in P, whatever their commands say: without a baseline for this Windows nothing else would
/// tell `http` taken over by a browser from a ProgID the browser created.
pub const WELL_KNOWN_SHARED: [&str; 58] = [
    "Application.Manifest",
    "batfile",
    "CABFolder",
    "callto",
    "chm.file",
    "cmdfile",
    "comfile",
    "CompressedFolder",
    "cplfile",
    "dllfile",
    "emffile",
    "exefile",
    "file",
    "fonfile",
    "ftp",
    "giffile",
    "hlpfile",
    "htmlfile",
    "http",
    "https",
    "icofile",
    "inffile",
    "inifile",
    "InternetShortcut",
    "jpegfile",
    "JSEFile",
    "JSFile",
    "ldap",
    "lnkfile",
    "mailto",
    "mhtmlfile",
    "Microsoft.PowerShellScript.1",
    "mms",
    "Msi.Package",
    "Msi.Patch",
    "news",
    "nntp",
    "ocxfile",
    "otffile",
    "Paint.Picture",
    "piffile",
    "pngfile",
    "regfile",
    "rtffile",
    "scrfile",
    "sms",
    "snews",
    "sysfile",
    "tel",
    "telnet",
    "textfile",
    "ttffile",
    "txtfile",
    "VBEFile",
    "VBSFile",
    "wmffile",
    "WSFFile",
    "xmlfile",
];

/// Bounds of the shortcut walk.
const SHORTCUT_MAX_DEPTH: usize = 5;
const SHORTCUT_MAX_DIRS: usize = 2_000;

/// Shortest `RegisteredApplications` name taken as an anchor; shorter ones match too much.
const MIN_REGISTERED_NAME: usize = 4;

/// Why a ProgID the app registered verbs on is not in P.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModifiedReason {
    /// Some verb commands of it run other programs.
    ForeignCommand,
    /// The key is in the clean-Windows baseline.
    InBaseline,
    /// The key is owned by TrustedInstaller, or its owner could not be read.
    WindowsOwned,
    /// One of the classes and URL schemes Windows ships ([`WELL_KNOWN_SHARED`]).
    WellKnownShared,
    /// A registered application that is not the app's lists it in its associations.
    ReferencedOutside {
        /// The `RegisteredApplications` name of that application.
        by: String,
    },
    /// The ProgID's key was last written before the app's install ([`ComCutoff`]): something else
    /// registered it first, and the app only pointed its command at itself.
    PredatesInstall,
}

/// A pre-existing or shared ProgID the app added verbs to: not in P, never an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifiedProgId {
    /// The ProgID.
    pub name: String,
    /// Why it is not in P.
    pub reason: ModifiedReason,
}

/// Why a CLSID whose server is one of the app's files is not an anchor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModifiedClsidReason {
    /// The key is owned by TrustedInstaller, or its owner could not be read.
    WindowsOwned,
    /// The key was last written before the app's install ([`ComCutoff`]): it existed before.
    PredatesInstall,
    /// A server value names the app's root in a form that resolves to no file (a command line that
    /// cannot be taken apart), so the shared-server test cannot be made. Unknown is not owned.
    UnresolvedServer,
    /// Another installed app ships a file with the server's name: the class is shared.
    SharedServer {
        /// The display name of that app.
        by: String,
    },
}

/// A COM class the app points at its own server without owning the registration: never an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifiedClsid {
    /// The CLSID, braced.
    pub id: String,
    /// Why it is not the app's.
    pub reason: ModifiedClsidReason,
}

/// One day in `FILETIME` ticks: the slack of the "not older than the install" test for a loose hint.
const DAY_TICKS: u64 = 24 * 60 * 60 * 10_000_000;

/// What [`collect`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorHarvest {
    /// The anchors, each list sorted and without duplicates. The package fields stay empty: the
    /// sparse-package link fills them.
    pub anchors: Anchors,
    /// ProgIDs the app only modified, sorted by name.
    pub modified_progids: Vec<ModifiedProgId>,
    /// COM classes whose server path the app set without owning the key, sorted by id.
    pub modified_clsids: Vec<ModifiedClsid>,
    /// Names registered by something else (see the module documentation), sorted.
    pub foreign_names: Vec<String>,
    /// What could not be read, for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// What the anchor harvest reads.
#[derive(Clone, Copy)]
pub struct AnchorInput<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The file system (shortcuts).
    pub fs: &'a dyn FileSystemSource,
    /// Machine facts (known folders).
    pub sys: &'a dyn SystemSource,
    /// The app's validated roots.
    pub roots: &'a [Root],
    /// The app's exe set.
    pub exes: &'a [ExeFile],
    /// The machine's guard facts, for canonical paths.
    pub guard: &'a GuardEnv,
    /// The interactive user's environment.
    pub env: &'a BTreeMap<String, String>,
    /// The users whose hives are read (the interactive user, the user the app is installed for).
    pub user_sids: &'a [String],
    /// The baseline **for this Windows**, when there is one.
    pub baseline: Option<&'a Baseline>,
    /// The directories of every other installed app (`RootEnv::other_dirs`), for the shared-server
    /// test of COM classes.
    pub other_dirs: &'a [OtherAnchor],
    /// The files of every other installed app (`RootEnv::other_files`); the directory of a
    /// `DisplayIcon` file outside Windows counts as one of that app's directories.
    pub other_files: &'a [OtherAnchor],
    /// The time before which a registry key cannot be this install's own registration, when one is
    /// known. See [`ComCutoff`].
    pub install_time: Option<ComCutoff>,
}

/// The time before which a registry key cannot have been written by this install of the app.
///
/// The creation time of the install directory is exact: no file of this install existed before it,
/// so a registration last written even a second earlier was made by something else and can at most
/// have been re-pointed by the app (the M1a gate: Thunderbird registered its accessibility class 44
/// seconds before Firefox's directory was created). Every other hint is loose: `InstallDate` has day
/// precision, and the Uninstall key and the uninstall log are written at the end of an install or by
/// a later update, so they get one day of slack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComCutoff {
    /// The hint.
    pub time: FileTime,
    /// Whether `time` is the creation time of the install directory.
    pub exact: bool,
}

impl ComCutoff {
    /// The cutoff for an app with these install-time hints: the install directory's creation time
    /// when the inventory has it, the earliest other hint otherwise.
    #[must_use]
    pub fn of(hints: &[purge_model::InstallTimeEvidence]) -> Option<Self> {
        use purge_model::InstallTimeSource::InstallDirCreation;
        let earliest = |exact: bool| {
            hints
                .iter()
                .filter(|h| (h.source == InstallDirCreation) == exact && h.time.0 != 0)
                .map(|h| h.time)
                .min()
                .map(|time| Self { time, exact })
        };
        earliest(true).or_else(|| earliest(false))
    }

    /// Whether a key last written at `lwt` is older than this install.
    pub(crate) fn is_after(self, lwt: FileTime) -> bool {
        let slack = if self.exact { 0 } else { DAY_TICKS };
        lwt.0 != 0 && lwt.0 < self.time.0.saturating_sub(slack)
    }
}

/// A registry reader that turns "not there" into nothing and counts everything else.
struct Reader<'a> {
    reg: &'a dyn RegistrySource,
    unreadable: Cell<usize>,
    /// The first location that could not be read, with the error.
    first_unreadable: RefCell<Option<String>>,
}

impl Reader<'_> {
    fn note<T>(&self, key: &str, result: Result<T, SourceError>) -> Option<T> {
        match result {
            Ok(v) => Some(v),
            Err(SourceError::NotFound) => None,
            Err(e) => {
                self.unreadable.set(self.unreadable.get() + 1);
                self.first_unreadable
                    .borrow_mut()
                    .get_or_insert_with(|| format!("{key}: {e}"));
                None
            }
        }
    }

    fn subkeys(&self, key: &str) -> Vec<String> {
        self.note(key, self.reg.subkeys(key)).unwrap_or_default()
    }

    fn string(&self, key: &str, name: &str) -> Option<String> {
        self.note(key, self.reg.value(key, name))
            .and_then(|d| d.string())
            .filter(|s| !s.trim().is_empty())
    }

    /// Every string value of a key, as (name, data).
    fn strings(&self, key: &str) -> Vec<(String, String)> {
        self.note(key, self.reg.values(key))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.data.string().map(|s| (v.name, s)))
            .collect()
    }
}

/// The ownership test and the readers, shared by the passes.
struct Pass<'a> {
    input: AnchorInput<'a>,
    reader: Reader<'a>,
    env: EnvMap,
    install_roots: Vec<&'a str>,
    matcher: RefMatcher,
}

impl<'a> Pass<'a> {
    fn new(input: AnchorInput<'a>) -> Self {
        let install_roots: Vec<&str> = input
            .roots
            .iter()
            .filter(|r| r.kind == RootKind::InstallRoot)
            .map(|r| r.path.as_str())
            .collect();
        let mut set = AnchorSet::new();
        for root in &install_roots {
            set.add_root(root);
        }
        for exe in input.exes {
            set.add_exe_path(&exe.path);
        }
        Self {
            input,
            reader: Reader {
                reg: input.reg,
                unreadable: Cell::new(0),
                first_unreadable: RefCell::new(None),
            },
            env: env_map(input.env),
            install_roots,
            matcher: RefMatcher::with_env(&set, input.env.clone()),
        }
    }

    /// Nothing can be the app's: it has no InstallRoot and no exe.
    fn is_blind(&self) -> bool {
        self.install_roots.is_empty() && self.input.exes.is_empty()
    }

    /// Whether a canonical path is one of the app's files.
    fn is_ours(&self, path: &str) -> bool {
        self.install_roots
            .iter()
            .any(|r| prefix::is_same_or_inside(path, r))
            || self
                .input
                .exes
                .iter()
                .any(|e| prefix::is_same(&e.path, path))
    }

    /// Whether a string (a command line, an icon path, any value) references the app's files.
    fn references(&self, text: &str) -> bool {
        self.matcher.find(text).is_some_and(|m| {
            !m.name_only && matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
        })
    }

    /// Whether a command line starts the app or names one of its files: the loose test, for Run
    /// entries ("pointing into the roots"). Ownership of a key is decided by [`Pass::runs_app`].
    fn command_targets(&self, command: &str) -> bool {
        command_exe(command, &self.env, self.input.guard).is_some_and(|exe| self.is_ours(&exe))
            || self.references(command)
    }

    /// Whether a command line *runs* the app, the test for ownership of a ProgID or a COM server
    /// (stricter than [`Pass::command_targets`]): its executable is the app's; or the executable is a
    /// host Windows ships (anything under `%WINDIR%`) or cannot be resolved to a path (a bare
    /// `rundll32.exe`, `java`), and the command names one of the app's files. A command whose
    /// executable is some other program's file belongs to that program, even when it passes one of
    /// the app's files as an argument.
    fn runs_app(&self, command: &str) -> bool {
        match command_exe(command, &self.env, self.input.guard) {
            Some(exe) if self.is_ours(&exe) => true,
            Some(exe) if !self.is_windows_host(&exe) => false,
            _ => self.references(command),
        }
    }

    /// Whether a canonical path lies in the Windows directory.
    fn is_windows_host(&self, exe: &str) -> bool {
        let windir = self.input.guard.windir.trim_end_matches(['\\', '/']);
        !windir.is_empty() && prefix::is_inside(exe, windir)
    }

    /// Whether a plain path value (a server DLL, a type library, a shortcut target) is the app's.
    fn path_is_ours(&self, raw: &str) -> bool {
        clean_value(raw, &self.env)
            .and_then(|p| canon_file(&p, self.input.guard))
            .is_some_and(|p| self.is_ours(&p))
            || self.runs_app(raw)
    }

    fn in_baseline(&self, key: &str) -> bool {
        self.input
            .baseline
            .is_some_and(|b| Baseline::key_in_scope(key) && b.has_key(key))
    }

    /// Whether Windows owns the key. A key that is not there is not owned; a key whose information
    /// cannot be read might be, and counts as owned (it then stays out of P).
    fn ti_owned(&self, key: &str) -> bool {
        match self.input.reg.key_info(key) {
            Ok(info) => info.ti_owned == Some(true),
            Err(SourceError::NotFound) => false,
            Err(_) => true,
        }
    }

    /// Whether the key was last written before the app's install ([`ComCutoff`]: before the install
    /// directory existed, or more than a day before a looser hint). Unknown times (no install-time
    /// hint, a key without a recorded time) prove nothing and give `false`.
    fn predates_install(&self, key: &str) -> bool {
        let Some(cutoff) = self.input.install_time else {
            return false;
        };
        self.input
            .reg
            .key_info(key)
            .is_ok_and(|info| cutoff.is_after(info.lwt))
    }

    /// The canonical path a server value names, when it is one of the app's files.
    fn own_file(&self, raw: &str) -> Option<String> {
        clean_value(raw, &self.env)
            .and_then(|p| canon_file(&p, self.input.guard))
            .filter(|p| self.is_ours(p))
            .or_else(|| command_exe(raw, &self.env, self.input.guard).filter(|p| self.is_ours(p)))
            .or_else(|| self.hosted_file(raw))
    }

    /// The app's file that a host's command line names (`rundll32.exe "C:\App\helper.dll",Serve`):
    /// the text from the first mention of an InstallRoot up to the next quote or comma, shortened at
    /// spaces until it names a file of the exe set or one that is there. `None` when no such file is found; the caller
    /// then knows nothing about the server.
    fn hosted_file(&self, command: &str) -> Option<String> {
        let folded = command.to_ascii_lowercase();
        let start = self
            .install_roots
            .iter()
            .filter_map(|root| folded.find(&root.to_ascii_lowercase()))
            .min()?;
        let rest = command.get(start..)?;
        let mut text = rest.split(['"', ',']).next()?.trim();
        loop {
            if let Some(path) = canon_file(text, self.input.guard).filter(|p| self.is_ours(p)) {
                let known = self
                    .input
                    .exes
                    .iter()
                    .any(|e| prefix::is_same(&e.path, &path));
                if known || self.input.fs.exists(&path) == ExistsState::Present {
                    return Some(path);
                }
            }
            text = text.rsplit_once(' ')?.0.trim_end();
        }
    }

    /// The other installed app that ships a file named like `file` (one of the app's files) in one of
    /// its own directories: directly in it, or at the place the file has below the app's InstallRoot.
    /// Only a file that is positively there counts.
    ///
    /// The other app's directories are its `InstallLocation` and the directories of the files its
    /// Uninstall entry and services name (uninstaller, icon, service image), unless such a file lies
    /// in the Windows directory (`msiexec.exe`, a system icon): that names no directory of the app.
    ///
    /// A directory that is one of this app's own says nothing about another app (a second
    /// registration of the same program names the same directory) and is skipped. A directory
    /// *above* this app's root is tested (a suite root such as `Program Files\Vendor` that a sibling
    /// product registers), but only for a file that is not inside this app's root: the app's own copy
    /// must not count as the other product's.
    fn shipped_by_other(&self, file: &str) -> Option<String> {
        let name = prefix::leaf(file).filter(|n| !n.is_empty())?;
        let relative = self
            .install_roots
            .iter()
            .find_map(|root| prefix::strip_prefix(file, root))
            .map(|rest| rest.trim_matches(prefix::SEP))
            .filter(|rest| !rest.is_empty() && !prefix::eq_ci(rest, name));
        let dirs = self
            .input
            .other_dirs
            .iter()
            .map(|d| (d.app.as_str(), d.path.clone()))
            .chain(
                self.input
                    .other_files
                    .iter()
                    .filter_map(|f| parent_dir(&f.path).map(|dir| (f.app.as_str(), dir))),
            );
        let windir = self.input.guard.windir.trim_end_matches(['\\', '/']);
        for (app, dir) in dirs {
            let dir = dir.trim_end_matches(prefix::SEP);
            if dir.is_empty() || (!windir.is_empty() && prefix::is_same_or_inside(dir, windir)) {
                continue;
            }
            if self.is_ours(dir) {
                continue;
            }
            let there = |rest: &str| {
                let path = format!(r"{dir}\{rest}");
                !self.is_ours(&path) && self.input.fs.exists(&path) == ExistsState::Present
            };
            if there(name) || relative.is_some_and(there) {
                return Some(app.to_owned());
            }
        }
        None
    }

    /// Why the COM class at `key`, whose server values `servers` name the app's files, is not the
    /// app's own registration; `None` when nothing speaks against it.
    fn clsid_modified(&self, key: &str, servers: &[String]) -> Option<ModifiedClsidReason> {
        if self.ti_owned(key) {
            return Some(ModifiedClsidReason::WindowsOwned);
        }
        if self.predates_install(key) {
            return Some(ModifiedClsidReason::PredatesInstall);
        }
        let files: Vec<String> = servers.iter().filter_map(|s| self.own_file(s)).collect();
        if let Some(by) = files.iter().find_map(|file| self.shipped_by_other(file)) {
            return Some(ModifiedClsidReason::SharedServer { by });
        }
        (files.len() < servers.len()).then_some(ModifiedClsidReason::UnresolvedServer)
    }

    fn classes_roots(&self) -> Vec<String> {
        let mut roots = vec![HKLM_CLASSES.to_owned()];
        roots.extend(
            self.input
                .user_sids
                .iter()
                .map(|sid| format!(r"HKU\{sid}_Classes")),
        );
        roots
    }
}

/// A set of names that compares case-insensitively and keeps the first spelling.
#[derive(Default)]
struct NameSet(BTreeMap<String, String>);

impl NameSet {
    fn insert(&mut self, name: &str) {
        self.0
            .entry(prefix::fold(name))
            .or_insert_with(|| name.to_owned());
    }

    fn contains(&self, name: &str) -> bool {
        self.0.contains_key(&prefix::fold(name))
    }

    fn into_sorted(self) -> Vec<String> {
        self.0.into_values().collect()
    }
}

pub(crate) fn is_structural(name: &str) -> bool {
    name.starts_with('.') || STRUCTURAL.iter().any(|s| s.eq_ignore_ascii_case(name))
}

/// The verb commands of one ProgID over all Classes roots.
#[derive(Default)]
struct ProgIdFacts {
    name: String,
    keys: Vec<String>,
    ours: usize,
    other: usize,
}

/// A registered application (`RegisteredApplications`).
struct Registered {
    name: String,
    ours: bool,
    progids: Vec<String>,
}

fn registered_applications(pass: &Pass<'_>) -> Vec<Registered> {
    let mut hives: Vec<(String, String, bool)> = vec![
        (
            r"HKLM\SOFTWARE\RegisteredApplications".to_owned(),
            "HKLM".to_owned(),
            false,
        ),
        (
            r"HKLM\SOFTWARE\WOW6432Node\RegisteredApplications".to_owned(),
            "HKLM".to_owned(),
            true,
        ),
    ];
    for sid in pass.input.user_sids {
        hives.push((
            format!(r"HKU\{sid}\Software\RegisteredApplications"),
            format!(r"HKU\{sid}"),
            false,
        ));
    }

    let mut out: Vec<Registered> = Vec::new();
    for (list_key, hive, wow) in hives {
        for (name, data) in pass.reader.strings(&list_key) {
            let rel = data.trim().trim_matches('\\');
            if name.is_empty() || rel.is_empty() {
                continue;
            }
            // A 32-bit registration names its key as a 32-bit process sees it.
            let mut candidates = vec![format!(r"{hive}\{rel}")];
            if wow {
                if let Some(rest) = crate::roots::strip_prefix_ci(rel, r"SOFTWARE\") {
                    candidates.insert(0, format!(r"{hive}\SOFTWARE\WOW6432Node\{rest}"));
                }
            }
            let Some(cap) = candidates
                .into_iter()
                .find(|k| pass.input.reg.key_exists(k).is_present())
            else {
                continue;
            };
            let mut ours = pass
                .reader
                .strings(&cap)
                .iter()
                .any(|(_, d)| pass.references(d));
            if !ours {
                if let Some(parent) = prefix::parent(&cap) {
                    ours = [
                        format!(r"{parent}\DefaultIcon"),
                        format!(r"{parent}\shell\open\command"),
                    ]
                    .iter()
                    .filter_map(|k| pass.reader.string(k, ""))
                    .any(|d| pass.references(&d));
                }
            }
            let mut progids: Vec<String> = Vec::new();
            for sub in ["FileAssociations", "URLAssociations"] {
                progids.extend(
                    pass.reader
                        .strings(&format!(r"{cap}\{sub}"))
                        .into_iter()
                        .map(|(_, d)| d.trim().to_owned())
                        .filter(|d| !d.is_empty()),
                );
            }
            out.push(Registered {
                name,
                ours,
                progids,
            });
        }
    }
    out
}

/// Collects the ProgID facts of every Classes root.
fn progid_facts(pass: &Pass<'_>) -> BTreeMap<String, ProgIdFacts> {
    let mut facts: BTreeMap<String, ProgIdFacts> = BTreeMap::new();
    for classes in pass.classes_roots() {
        for name in pass.reader.subkeys(&classes) {
            if is_structural(&name) {
                continue;
            }
            let key = format!(r"{classes}\{name}");
            let shell = format!(r"{key}\shell");
            let (mut ours, mut other) = (0usize, 0usize);
            for verb in pass.reader.subkeys(&shell) {
                let Some(command) = pass.reader.string(&format!(r"{shell}\{verb}\command"), "")
                else {
                    continue;
                };
                if pass.runs_app(&command) {
                    ours += 1;
                } else {
                    other += 1;
                }
            }
            if ours + other == 0 {
                continue;
            }
            let entry = facts.entry(prefix::fold(&name)).or_default();
            if entry.name.is_empty() {
                entry.name = name;
            }
            entry.keys.push(key);
            entry.ours += ours;
            entry.other += other;
        }
    }
    facts
}

/// The server a CLSID key names, as raw value data.
fn clsid_servers(pass: &Pass<'_>, key: &str) -> Vec<String> {
    ["InprocServer32", "LocalServer32"]
        .iter()
        .filter_map(|server| pass.reader.string(&format!(r"{key}\{server}"), ""))
        .collect()
}

fn collect_com(
    pass: &Pass<'_>,
    clsids: &mut NameSet,
    appids: &mut NameSet,
    typelibs: &mut NameSet,
    modified: &mut Vec<ModifiedClsid>,
) {
    let mut clsid_roots: Vec<String> = pass
        .classes_roots()
        .into_iter()
        .map(|c| format!(r"{c}\CLSID"))
        .collect();
    clsid_roots.push(format!(r"{HKLM_CLASSES_32}\CLSID"));
    for sid in pass.input.user_sids {
        clsid_roots.push(format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID"));
    }
    // A class is the app's only when every key that points it at the app passes: one that fails in
    // any root is "modified" in all of them.
    let mut owned = NameSet::default();
    let mut owned_appids: Vec<(String, String)> = Vec::new();
    let mut not_owned: BTreeMap<String, ModifiedClsid> = BTreeMap::new();
    for root in &clsid_roots {
        for id in pass.reader.subkeys(root) {
            if !is_braced_guid(&id) {
                continue;
            }
            let key = format!(r"{root}\{id}");
            let ours: Vec<String> = clsid_servers(pass, &key)
                .into_iter()
                .filter(|s| pass.path_is_ours(s))
                .collect();
            if ours.is_empty() || pass.in_baseline(&key) {
                continue;
            }
            if let Some(reason) = pass.clsid_modified(&key, &ours) {
                not_owned
                    .entry(prefix::fold(&id))
                    .or_insert(ModifiedClsid { id, reason });
                continue;
            }
            owned.insert(&id);
            if let Some(appid) = pass.reader.string(&key, "AppID") {
                let appid = appid.trim();
                let appid_key = format!(
                    r"{}\AppID\{appid}",
                    prefix::parent(root).unwrap_or(HKLM_CLASSES)
                );
                if is_braced_guid(appid)
                    && !pass.in_baseline(&appid_key)
                    && !pass.predates_install(&appid_key)
                {
                    owned_appids.push((prefix::fold(&id), appid.to_owned()));
                }
            }
        }
    }
    for id in owned.into_sorted() {
        if !not_owned.contains_key(&prefix::fold(&id)) {
            clsids.insert(&id);
        }
    }
    for (clsid, appid) in owned_appids {
        if !not_owned.contains_key(&clsid) {
            appids.insert(&appid);
        }
    }
    modified.extend(not_owned.into_values());

    for classes in pass.classes_roots() {
        let root = format!(r"{classes}\TypeLib");
        for id in pass.reader.subkeys(&root) {
            if !is_braced_guid(&id) {
                continue;
            }
            let key = format!(r"{root}\{id}");
            let ours = pass.reader.subkeys(&key).iter().any(|version| {
                let version_key = format!(r"{key}\{version}");
                pass.reader.subkeys(&version_key).iter().any(|lcid| {
                    ["win32", "win64"].iter().any(|platform| {
                        pass.reader
                            .string(&format!(r"{version_key}\{lcid}\{platform}"), "")
                            .is_some_and(|path| pass.path_is_ours(&path))
                    })
                })
            });
            if ours && !pass.in_baseline(&key) && !pass.predates_install(&key) {
                typelibs.insert(&id);
            }
        }
    }
}

/// The AUMIDs of shortcuts that start the app, from the Start Menu and desktop folders.
fn shortcut_aumids(pass: &Pass<'_>, aumids: &mut NameSet) {
    let Ok(folders) = pass.input.sys.known_folders() else {
        return;
    };
    let mut stack: Vec<(String, usize)> = [
        KnownFolder::CommonStartMenu,
        KnownFolder::StartMenu,
        KnownFolder::PublicDesktop,
        KnownFolder::Desktop,
    ]
    .iter()
    .filter_map(|f| folders.get(f))
    .map(|p| (p.trim_end_matches('\\').to_owned(), 0))
    .collect();
    stack.reverse();
    let mut dirs = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if dirs >= SHORTCUT_MAX_DIRS {
            break;
        }
        dirs += 1;
        let Ok(entries) = pass.input.fs.list_dir(&dir) else {
            continue;
        };
        for entry in entries {
            if entry.meta.is_reparse_point() {
                continue;
            }
            let path = format!(r"{dir}\{}", entry.name);
            if entry.meta.is_dir() {
                if depth < SHORTCUT_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let is_lnk = entry
                .name
                .rsplit_once('.')
                .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("lnk"));
            if !is_lnk {
                continue;
            }
            // A source that did not capture shortcut contents simply has none to offer.
            let Ok(info) = pass.input.fs.read_shortcut(&path) else {
                continue;
            };
            let (Some(target), Some(aumid)) = (info.raw_path, info.aumid) else {
                continue;
            };
            let aumid = aumid.trim();
            if !aumid.is_empty() && pass.path_is_ours(&target) {
                aumids.insert(aumid);
            }
        }
    }
}

fn run_entries(pass: &Pass<'_>) -> Vec<RunEntry> {
    const TAILS: [&str; 2] = ["Run", "RunOnce"];
    let mut keys: Vec<String> = Vec::new();
    for tail in TAILS {
        keys.push(format!(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\{tail}"
        ));
        keys.push(format!(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\{tail}"
        ));
    }
    for sid in pass.input.user_sids {
        for tail in TAILS {
            keys.push(format!(
                r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\{tail}"
            ));
        }
    }
    let mut out: Vec<RunEntry> = Vec::new();
    for key in keys {
        for (name, data) in pass.reader.strings(&key) {
            if pass.command_targets(&data) {
                out.push(RunEntry {
                    key: key.clone(),
                    name,
                    data,
                });
            }
        }
    }
    out.sort_by_key(|r| (prefix::fold(&r.key), prefix::fold(&r.name)));
    out.dedup_by(|a, b| prefix::eq_ci(&a.key, &b.key) && prefix::eq_ci(&a.name, &b.name));
    out
}

/// Reads the app's registry anchors; see the module documentation.
pub fn collect(input: AnchorInput<'_>) -> AnchorHarvest {
    let pass = Pass::new(input);
    let mut out = AnchorHarvest::default();
    if pass.is_blind() {
        out.warnings.push(
            "anchors: the app has no install root and no exe; no registry anchor can be attributed"
                .into(),
        );
        return out;
    }
    let mut foreign = NameSet::default();
    let mut aumids = NameSet::default();

    // Registered applications: the app's own names, and what other applications claim.
    let registered = registered_applications(&pass);
    let mut claimed_outside: BTreeMap<String, String> = BTreeMap::new();
    for app in &registered {
        if app.ours {
            if app.name.chars().count() >= MIN_REGISTERED_NAME {
                aumids.insert(&app.name);
            }
        } else {
            foreign.insert(&app.name);
            for progid in &app.progids {
                claimed_outside
                    .entry(prefix::fold(progid))
                    .or_insert_with(|| app.name.clone());
            }
        }
    }

    // ProgIDs.
    let mut progids = NameSet::default();
    for facts in progid_facts(&pass).into_values() {
        if facts.ours == 0 {
            foreign.insert(&facts.name);
            continue;
        }
        let machine_key = format!(r"{HKLM_CLASSES}\{}", facts.name);
        let reason = if facts.other > 0 {
            Some(ModifiedReason::ForeignCommand)
        } else if pass.in_baseline(&machine_key) || facts.keys.iter().any(|k| pass.in_baseline(k)) {
            Some(ModifiedReason::InBaseline)
        } else if pass.ti_owned(&machine_key) || facts.keys.iter().any(|k| pass.ti_owned(k)) {
            Some(ModifiedReason::WindowsOwned)
        } else if WELL_KNOWN_SHARED
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&facts.name))
        {
            Some(ModifiedReason::WellKnownShared)
        } else if let Some(by) = claimed_outside.get(&prefix::fold(&facts.name)) {
            Some(ModifiedReason::ReferencedOutside { by: by.clone() })
        } else if facts.keys.iter().any(|k| pass.predates_install(k)) {
            Some(ModifiedReason::PredatesInstall)
        } else {
            None
        };
        match reason {
            None => progids.insert(&facts.name),
            Some(reason) => out.modified_progids.push(ModifiedProgId {
                name: facts.name,
                reason,
            }),
        }
    }

    // COM ids.
    let (mut clsids, mut appids, mut typelibs) =
        (NameSet::default(), NameSet::default(), NameSet::default());
    collect_com(
        &pass,
        &mut clsids,
        &mut appids,
        &mut typelibs,
        &mut out.modified_clsids,
    );

    // AUMIDs.
    for classes in pass.classes_roots() {
        let root = format!(r"{classes}\AppUserModelId");
        for name in pass.reader.subkeys(&root) {
            let values = pass.reader.strings(&format!(r"{root}\{name}"));
            let ours = values.iter().any(|(value, data)| {
                pass.references(data)
                    || (value.eq_ignore_ascii_case("CustomActivator")
                        && clsids.contains(data.trim()))
            });
            if ours {
                aumids.insert(&name);
            } else {
                foreign.insert(&name);
            }
        }
    }
    shortcut_aumids(&pass, &mut aumids);

    out.anchors = Anchors {
        progids: progids.into_sorted(),
        clsids: clsids.into_sorted(),
        appids: appids.into_sorted(),
        typelibs: typelibs.into_sorted(),
        aumids: aumids.into_sorted(),
        package_families: Vec::new(),
        package_full_names: Vec::new(),
        run_entries: run_entries(&pass),
    };
    out.modified_progids.sort_by_key(|m| prefix::fold(&m.name));

    // A name the app owns is never foreign, whatever another hive says about it.
    let own: BTreeSet<String> = out
        .anchors
        .progids
        .iter()
        .chain(&out.anchors.aumids)
        .map(|n| prefix::fold(n))
        .collect();
    out.foreign_names = foreign
        .into_sorted()
        .into_iter()
        .filter(|n| !own.contains(&prefix::fold(n)))
        .collect();

    let unreadable = pass.reader.unreadable.get();
    if let Some(first) = pass.reader.first_unreadable.borrow().as_deref() {
        out.warnings.push(format!(
            "anchors: {unreadable} registry location(s) could not be read (first: {first}); the anchors may be incomplete"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roots::OtherAnchorKind;
    use purge_model::{RootSource, SourceTrust};
    use purge_source::fixture::{Fixture, FixtureBuilder};
    use purge_source::types::ShortcutInfo;

    const SID: &str = GuardEnv::SAMPLE_SID;
    const APP: &str = r"C:\Program Files\App";

    fn root(path: &str, source: RootSource) -> Root {
        Root {
            path: path.into(),
            kind: source.root_kind(),
            source,
            trust: SourceTrust::AdminOnly,
            volume_serial: None,
            parent_existed: true,
        }
    }

    fn exe(path: &str, main: bool) -> ExeFile {
        ExeFile {
            path: path.into(),
            main,
        }
    }

    fn command(b: FixtureBuilder, progid_key: &str, verb: &str, command: &str) -> FixtureBuilder {
        b.sz(&format!(r"{progid_key}\shell\{verb}\command"), "", command)
    }

    fn harvest(f: &Fixture, roots: &[Root], exes: &[ExeFile]) -> AnchorHarvest {
        let guard = GuardEnv::sample();
        let env: BTreeMap<String, String> =
            [("PROGRAMFILES".to_owned(), r"C:\Program Files".to_owned())].into();
        let sids = [SID.to_owned()];
        collect(AnchorInput {
            reg: f,
            fs: f,
            sys: f,
            roots,
            exes,
            guard: &guard,
            env: &env,
            user_sids: &sids,
            baseline: None,
            other_dirs: &[],
            other_files: &[],
            install_time: None,
        })
    }

    fn app_roots() -> ([Root; 1], [ExeFile; 2]) {
        (
            [root(APP, RootSource::ArpInstallLocation)],
            [
                exe(r"C:\Program Files\App\App.exe", true),
                exe(r"C:\Program Files\App\helper.dll", false),
            ],
        )
    }

    #[test]
    fn p_holds_progids_whose_every_command_targets_the_app() {
        let user_classes = format!(r"HKU\{SID}_Classes");
        let mut b = Fixture::builder();
        // The app's own ProgIDs, machine-wide and per-user, quoted and through an environment variable.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\App.Document",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\App.Document",
            "print",
            r#""%ProgramFiles%\App\App.exe" /p "%1""#,
        );
        b = command(
            b,
            &format!(r"{user_classes}\appproto"),
            "open",
            r#""c:\program files\app\APP.EXE" --url "%1""#,
        );
        // Hosted by rundll32: the command names a file of the app.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\App.Hosted",
            "open",
            r#"rundll32.exe "C:\Program Files\App\helper.dll",Open %1"#,
        );
        // A pre-existing ProgID the app added a verb to.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\txtfile",
            "open",
            r"%SystemRoot%\system32\NOTEPAD.EXE %1",
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\txtfile",
            "App",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        // The same name clean in one hive and foreign in the other.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Split.File",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = command(
            b,
            &format!(r"{user_classes}\Split.File"),
            "open",
            r#""C:\Tools\other.exe" "%1""#,
        );
        // Somebody else's ProgID, and one that only has the app's icon.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Other.Document",
            "open",
            r#""C:\Program Files\Other\other.exe" "%1""#,
        );
        b = b.sz(
            r"HKLM\SOFTWARE\Classes\IconOnly.File\DefaultIcon",
            "",
            r"C:\Program Files\App\App.exe,0",
        );
        // Structural keys never are ProgIDs, even with nothing but the app's verbs.
        b = command(
            b,
            &format!(r"{user_classes}\Directory"),
            "App",
            r#""C:\Program Files\App\App.exe" "%V""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\*",
            "App",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\.app",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Applications\App.exe",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        // A sibling directory with the root as a name prefix is not the app.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Sibling.File",
            "open",
            r#""C:\Program Files\App Two\two.exe" "%1""#,
        );
        let f = b.build();

        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(
            got.anchors.progids,
            ["App.Document", "App.Hosted", "appproto"]
        );
        assert_eq!(
            got.modified_progids,
            [
                ModifiedProgId {
                    name: "Split.File".into(),
                    reason: ModifiedReason::ForeignCommand
                },
                ModifiedProgId {
                    name: "txtfile".into(),
                    reason: ModifiedReason::ForeignCommand
                },
            ]
        );
        assert_eq!(got.foreign_names, ["Other.Document", "Sibling.File"]);
        assert!(got.warnings.is_empty(), "{:?}", got.warnings);
        // Deterministic.
        assert_eq!(harvest(&f, &roots, &exes), got);
    }

    #[test]
    fn windows_owned_and_outside_referenced_progids_are_only_modified() {
        let mut b = Fixture::builder();
        // Every command is the app's, but the key belongs to Windows.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\inifile",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = b.ti_owned(r"HKLM\SOFTWARE\Classes\inifile", true);
        // Every command is the app's, but another registered application lists it.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Shared.Html",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = b
            .sz(
                r"HKLM\SOFTWARE\RegisteredApplications",
                "Other Browser",
                r"Software\Clients\StartMenuInternet\Other\Capabilities",
            )
            .sz(
                r"HKLM\SOFTWARE\Clients\StartMenuInternet\Other\Capabilities",
                "ApplicationIcon",
                r"C:\Program Files\Other\other.exe,0",
            )
            .sz(
                r"HKLM\SOFTWARE\Clients\StartMenuInternet\Other\Capabilities\FileAssociations",
                ".html",
                "Shared.Html",
            );
        // The app's own registration lists its own ProgID: that is not an outside reference.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\AppHTML-0011223344556677",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = b
            .sz(
                r"HKLM\SOFTWARE\RegisteredApplications",
                "App-0011223344556677",
                r"Software\Clients\StartMenuInternet\App-0011223344556677\Capabilities",
            )
            .sz(
                r"HKLM\SOFTWARE\Clients\StartMenuInternet\App-0011223344556677\Capabilities",
                "ApplicationIcon",
                r"C:\Program Files\App\App.exe,0",
            )
            .sz(
                r"HKLM\SOFTWARE\Clients\StartMenuInternet\App-0011223344556677\Capabilities\URLAssociations",
                "http",
                "AppHTML-0011223344556677",
            );
        let f = b.build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(got.anchors.progids, ["AppHTML-0011223344556677"]);
        assert_eq!(
            got.modified_progids,
            [
                ModifiedProgId {
                    name: "inifile".into(),
                    reason: ModifiedReason::WindowsOwned
                },
                ModifiedProgId {
                    name: "Shared.Html".into(),
                    reason: ModifiedReason::ReferencedOutside {
                        by: "Other Browser".into()
                    }
                },
            ]
        );
        // The registered name is an anchor; the other application's name is foreign.
        assert_eq!(got.anchors.aumids, ["App-0011223344556677"]);
        assert_eq!(got.foreign_names, ["Other Browser"]);
    }

    /// VM run x0-vscode-zipcopy: a portable copy of the app registered the `vscode` scheme, then the
    /// installer only pointed its command at the installed copy. The scheme key is older than the
    /// install: the app modified it, it does not own it.
    #[test]
    fn a_progid_key_older_than_the_install_is_modified_not_owned() {
        const DAY: u64 = 24 * 60 * 60 * 10_000_000;
        const INSTALL: u64 = 400 * DAY;
        let scheme = format!(r"HKU\{SID}_Classes\vscode");
        let fixture = |key_lwt: u64| {
            command(
                Fixture::builder()
                    .sz(&scheme, "URL Protocol", "")
                    .key_lwt(&scheme, key_lwt)
                    .file(r"C:\Program Files\App\App.exe", 10),
                &scheme,
                "open",
                r#""C:\Program Files\App\App.exe" --open-url -- "%1""#,
            )
            // The installer rewrote the command: that key is new.
            .key_lwt(&format!(r"{scheme}\shell\open\command"), INSTALL + 5)
            .build()
        };
        let (roots, exes) = app_roots();
        let run = |f: &Fixture, install_time: Option<ComCutoff>| {
            let guard = GuardEnv::sample();
            let env: BTreeMap<String, String> = BTreeMap::new();
            let sids = [SID.to_owned()];
            collect(AnchorInput {
                reg: f,
                fs: f,
                sys: f,
                roots: &roots,
                exes: &exes,
                guard: &guard,
                env: &env,
                user_sids: &sids,
                baseline: None,
                other_dirs: &[],
                other_files: &[],
                install_time,
            })
        };
        let exact = Some(ComCutoff {
            time: FileTime(INSTALL),
            exact: true,
        });

        // Written 58 seconds before the install directory existed.
        let got = run(&fixture(INSTALL - 580_000_000), exact);
        assert!(got.anchors.progids.is_empty(), "{:?}", got.anchors.progids);
        assert_eq!(
            got.modified_progids,
            [ModifiedProgId {
                name: "vscode".into(),
                reason: ModifiedReason::PredatesInstall
            }]
        );
        // Written by the install: the app's own.
        let got = run(&fixture(INSTALL + 5), exact);
        assert_eq!(got.anchors.progids, ["vscode"]);
        assert!(got.modified_progids.is_empty());
        // A looser hint has a day of slack, and without any hint nothing is concluded.
        let loose = Some(ComCutoff {
            time: FileTime(INSTALL),
            exact: false,
        });
        assert_eq!(
            run(&fixture(INSTALL - 580_000_000), loose).anchors.progids,
            ["vscode"]
        );
        assert!(
            run(&fixture(INSTALL - 2 * DAY), loose)
                .anchors
                .progids
                .is_empty()
        );
        assert_eq!(
            run(&fixture(INSTALL - 2 * DAY), None).anchors.progids,
            ["vscode"]
        );
    }

    #[test]
    fn com_cutoff_prefers_the_install_directory() {
        use purge_model::{InstallTimeEvidence, InstallTimeSource};
        let hint = |source, time| InstallTimeEvidence {
            source,
            time: FileTime(time),
        };
        // Visual Studio Code in the gate run: InstallDate (midnight), the key, the directory, the log.
        let all = [
            hint(InstallTimeSource::ArpInstallDate, 100),
            hint(InstallTimeSource::KeyLastWrite, 900),
            hint(InstallTimeSource::InstallDirCreation, 500),
            hint(InstallTimeSource::UninstallLogCreation, 510),
        ];
        assert_eq!(
            ComCutoff::of(&all),
            Some(ComCutoff {
                time: FileTime(500),
                exact: true
            })
        );
        // No directory time (a snapshot source): the earliest hint, loose.
        assert_eq!(
            ComCutoff::of(&[all[1].clone(), all[0].clone()]),
            Some(ComCutoff {
                time: FileTime(100),
                exact: false
            })
        );
        assert_eq!(ComCutoff::of(&[]), None);
    }

    /// The M1a gate case: Thunderbird registered the accessibility proxy class and its interfaces;
    /// Firefox, installed afterwards, only pointed the class at its own copy of the DLL. The class is
    /// shared, not Firefox's, whether the two installs are seconds or months apart.
    #[test]
    fn a_shared_or_older_com_class_is_modified_not_owned() {
        const PROXY: &str = "{1814CEEB-49E2-407F-AF99-FA755A7D2607}";
        const OWN: &str = "{1021605B-F25D-4D6E-8EE4-8D0BDCBBD4CD}";
        const OWN_APPID: &str = "{1021605B-F25D-4D6E-8EE4-8D0BDCBBD4CE}";
        const OLD_TLB: &str = "{DDDDDDDD-2222-3333-4444-555555555555}";
        const DAY: u64 = 24 * 60 * 60 * 10_000_000;
        const INSTALL: u64 = 400 * DAY;
        let clsid = r"HKLM\SOFTWARE\Classes\CLSID";
        let other = r"C:\Program Files\Other Mail";
        let fixture = |proxy_key_lwt: u64, other_ships_it: bool| {
            let mut b = Fixture::builder()
                .sz(&format!(r"{clsid}\{PROXY}"), "", "PSFactoryBuffer")
                .key_lwt(&format!(r"{clsid}\{PROXY}"), proxy_key_lwt)
                .sz(
                    &format!(r"{clsid}\{PROXY}\InProcServer32"),
                    "",
                    r"C:\Program Files\App\helper.dll",
                )
                .key_lwt(&format!(r"{clsid}\{PROXY}\InProcServer32"), INSTALL + 5)
                // A class the app created itself, with its AppID.
                .sz(
                    &format!(r"{clsid}\{OWN}\LocalServer32"),
                    "",
                    r#""C:\Program Files\App\App.exe" -Embedding"#,
                )
                .sz(&format!(r"{clsid}\{OWN}"), "AppID", OWN_APPID)
                .key_lwt(&format!(r"{clsid}\{OWN}"), INSTALL + 5)
                .file(r"C:\Program Files\App\App.exe", 10)
                .file(r"C:\Program Files\App\helper.dll", 10)
                .file(r"C:\Program Files\Other Mail\mail.exe", 10);
            if other_ships_it {
                b = b.file(r"C:\Program Files\Other Mail\helper.dll", 10);
            }
            b.build()
        };
        let other_dirs = [OtherAnchor {
            app: "Other Mail".into(),
            kind: OtherAnchorKind::InstallLocation,
            path: other.into(),
        }];
        let (roots, exes) = app_roots();
        // Whether `INSTALL` is the creation time of the install directory or a looser hint.
        let exact = std::cell::Cell::new(false);
        let run = |f: &Fixture, dirs: &[OtherAnchor], files: &[OtherAnchor]| {
            let guard = GuardEnv::sample();
            let env: BTreeMap<String, String> = BTreeMap::new();
            let sids = [SID.to_owned()];
            collect(AnchorInput {
                reg: f,
                fs: f,
                sys: f,
                roots: &roots,
                exes: &exes,
                guard: &guard,
                env: &env,
                user_sids: &sids,
                baseline: None,
                other_dirs: dirs,
                other_files: files,
                install_time: Some(ComCutoff {
                    time: FileTime(INSTALL),
                    exact: exact.get(),
                }),
            })
        };

        // Installed 45 seconds after the other product (inside the one-day slack of the age test):
        // the other product ships a file of the same name, so the class is shared.
        let got = run(&fixture(INSTALL - 450_000_000, true), &other_dirs, &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(got.anchors.appids, [OWN_APPID]);
        assert_eq!(
            got.modified_clsids,
            [ModifiedClsid {
                id: PROXY.into(),
                reason: ModifiedClsidReason::SharedServer {
                    by: "Other Mail".into()
                }
            }]
        );
        // The other product is known only by its icon: the icon's directory is its directory.
        let icon = [OtherAnchor {
            app: "Other Mail".into(),
            kind: OtherAnchorKind::DisplayIcon,
            path: r"C:\Program Files\Other Mail\mail.exe".into(),
        }];
        let got = run(&fixture(INSTALL + 5, true), &[], &icon);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(got.modified_clsids.len(), 1);

        // Known only by its uninstaller, which sits in the product's folder: the same.
        let uninstaller = [OtherAnchor {
            app: "Other Mail".into(),
            kind: OtherAnchorKind::Uninstaller,
            path: r"C:\Program Files\Other Mail\mail.exe".into(),
        }];
        let got = run(&fixture(INSTALL + 5, true), &[], &uninstaller);
        assert_eq!(got.anchors.clsids, [OWN]);
        // An uninstaller in the Windows directory (msiexec) names no directory of the product.
        let msiexec = [OtherAnchor {
            app: "Other Mail".into(),
            kind: OtherAnchorKind::Uninstaller,
            path: r"C:\Windows\System32\msiexec.exe".into(),
        }];
        let mut f = fixture(INSTALL + 5, false);
        f.add_file(r"C:\Windows\System32\helper.dll", 10);
        let got = run(&f, &[], &msiexec);
        assert_eq!(got.anchors.clsids, [OWN, PROXY]);
        // A sibling registered on the suite folder above the app's root: a copy of the DLL directly
        // in the suite folder is the suite's, the app's own copy below it is not counted.
        let suite = [OtherAnchor {
            app: "Suite".into(),
            kind: OtherAnchorKind::InstallLocation,
            path: r"C:\Program Files".into(),
        }];
        let got = run(&fixture(INSTALL + 5, false), &suite, &[]);
        assert_eq!(got.anchors.clsids, [OWN, PROXY]);
        let mut f = fixture(INSTALL + 5, false);
        f.add_file(r"C:\Program Files\helper.dll", 10);
        let got = run(&f, &suite, &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(
            got.modified_clsids[0].reason,
            ModifiedClsidReason::SharedServer { by: "Suite".into() }
        );
        // A server value that names the app's folder but resolves to no file of the app: the test
        // cannot be made, and a class that cannot be tested is not an anchor.
        let mut f = fixture(INSTALL + 5, false);
        f.set_value(
            &format!(r"{clsid}\{PROXY}\InProcServer32"),
            "",
            purge_source::types::RegData::from_sz(
                r"rundll32.exe C:\Program Files\App\plugins\gone.dll,Run",
            ),
        );
        let got = run(&f, &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(
            got.modified_clsids[0].reason,
            ModifiedClsidReason::UnresolvedServer
        );

        // The key is months older than the install: it existed before, whoever else ships what.
        let got = run(&fixture(INSTALL - 90 * DAY, false), &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(
            got.modified_clsids,
            [ModifiedClsid {
                id: PROXY.into(),
                reason: ModifiedClsidReason::PredatesInstall
            }]
        );

        // The gate case with nothing known about the other product (no directory in its Uninstall
        // entry, a differently named server): the class key is 45 seconds older than the app's
        // install directory. Against that exact time there is no slack: the key was there before
        // any file of this install, so the app only re-pointed it.
        exact.set(true);
        let got = run(&fixture(INSTALL - 450_000_000, false), &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert_eq!(
            got.modified_clsids,
            [ModifiedClsid {
                id: PROXY.into(),
                reason: ModifiedClsidReason::PredatesInstall
            }]
        );
        // A key written one tick after the directory was created is the install's own.
        let got = run(&fixture(INSTALL + 1, false), &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN, PROXY]);
        // Against a loose hint (day-precision InstallDate, the Uninstall key's last write) 45
        // seconds prove nothing either way: only the one-day slack applies.
        exact.set(false);
        let got = run(&fixture(INSTALL - 450_000_000, false), &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN, PROXY]);

        // Created by the app's own install and shipped by nobody else: the app's.
        let got = run(&fixture(INSTALL + 5, false), &other_dirs, &icon);
        assert_eq!(got.anchors.clsids, [OWN, PROXY]);
        assert!(got.modified_clsids.is_empty());

        // The same class owned in the 64-bit root and older in the 32-bit one is modified in both.
        let mut f = fixture(INSTALL + 5, false);
        let wow = format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{PROXY}");
        f.set_value(
            &format!(r"{wow}\InProcServer32"),
            "",
            purge_source::types::RegData::from_sz(r"C:\Program Files\App\helper.dll"),
        );
        f.set_key_lwt(&wow, FileTime(INSTALL - 90 * DAY));
        // A type library older than the install is not the app's either.
        let tlb = format!(r"HKLM\SOFTWARE\Classes\TypeLib\{OLD_TLB}");
        f.set_value(
            &format!(r"{tlb}\1.0\0\win64"),
            "",
            purge_source::types::RegData::from_sz(r"C:\Program Files\App\helper.dll"),
        );
        f.set_key_lwt(&tlb, FileTime(INSTALL - 90 * DAY));
        let got = run(&f, &[], &[]);
        assert_eq!(got.anchors.clsids, [OWN]);
        assert!(got.anchors.typelibs.is_empty());
        assert_eq!(got.modified_clsids.len(), 1);

        // A class Windows owns is never the app's.
        let mut f = fixture(INSTALL + 5, false);
        f.set_ti_owned(&format!(r"{clsid}\{PROXY}"), true);
        let got = run(&f, &[], &[]);
        assert_eq!(
            got.modified_clsids,
            [ModifiedClsid {
                id: PROXY.into(),
                reason: ModifiedClsidReason::WindowsOwned
            }]
        );
    }

    #[test]
    fn com_ids_follow_the_server_path() {
        const OURS: &str = "{11111111-2222-3333-4444-555555555555}";
        const OURS_32: &str = "{11111111-2222-3333-4444-666666666666}";
        const LOCAL: &str = "{11111111-2222-3333-4444-777777777777}";
        const THEIRS: &str = "{99999999-2222-3333-4444-555555555555}";
        const APPID: &str = "{AAAAAAAA-2222-3333-4444-555555555555}";
        const TLB: &str = "{BBBBBBBB-2222-3333-4444-555555555555}";
        const TLB_OTHER: &str = "{CCCCCCCC-2222-3333-4444-555555555555}";
        let clsid = r"HKLM\SOFTWARE\Classes\CLSID";
        let f = Fixture::builder()
            .sz(
                &format!(r"{clsid}\{OURS}\InprocServer32"),
                "",
                r"C:\Program Files\App\helper.dll",
            )
            .sz(&format!(r"{clsid}\{OURS}"), "AppID", APPID)
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{OURS_32}\InprocServer32"),
                "",
                r#""C:\Program Files\App\bin\x86.dll""#,
            )
            .sz(
                &format!(r"HKU\{SID}_Classes\CLSID\{LOCAL}\LocalServer32"),
                "",
                r#""C:\Program Files\App\App.exe" -Embedding"#,
            )
            .sz(
                &format!(r"{clsid}\{THEIRS}\InprocServer32"),
                "",
                r"C:\Windows\System32\shell32.dll",
            )
            .sz(
                &format!(r"{clsid}\NotAGuid\InprocServer32"),
                "",
                r"C:\Program Files\App\helper.dll",
            )
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\TypeLib\{TLB}\1.0\0\win64"),
                "",
                r"C:\Program Files\App\app.tlb",
            )
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\TypeLib\{TLB_OTHER}\1.0\0\win32"),
                "",
                r"C:\Windows\System32\stdole2.tlb",
            )
            .build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(got.anchors.clsids, [OURS, OURS_32, LOCAL]);
        assert_eq!(got.anchors.appids, [APPID]);
        assert_eq!(got.anchors.typelibs, [TLB]);
        assert!(got.anchors.progids.is_empty());
    }

    #[test]
    fn aumids_come_from_classes_shortcuts_and_registrations() {
        const ACTIVATOR: &str = "{11111111-2222-3333-4444-555555555555}";
        let f = Fixture::builder()
            // References the app by its icon.
            .sz(
                r"HKLM\SOFTWARE\Classes\AppUserModelId\AppToast-0011223344556677",
                "IconUri",
                r"C:\Program Files\App\toast.png",
            )
            // References the app only through its activator class.
            .sz(
                &format!(r"HKU\{SID}_Classes\AppUserModelId\App.Notifier"),
                "CustomActivator",
                ACTIVATOR,
            )
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\CLSID\{ACTIVATOR}\InprocServer32"),
                "",
                r"C:\Program Files\App\helper.dll",
            )
            // Somebody else's.
            .sz(
                r"HKLM\SOFTWARE\Classes\AppUserModelId\Other.Toast",
                "IconUri",
                r"C:\Program Files\Other\toast.png",
            )
            .known_folder(
                KnownFolder::CommonStartMenu,
                r"C:\ProgramData\Microsoft\Windows\Start Menu",
            )
            .known_folder(KnownFolder::Desktop, r"C:\Users\tester\Desktop")
            .shortcut(
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\App\App.lnk",
                ShortcutInfo {
                    raw_path: Some(r"C:\Program Files\App\App.exe".into()),
                    args: None,
                    workdir: None,
                    aumid: Some("Vendor.App".into()),
                },
            )
            .shortcut(
                r"C:\Users\tester\Desktop\Other.lnk",
                ShortcutInfo {
                    raw_path: Some(r"C:\Program Files\Other\other.exe".into()),
                    args: None,
                    workdir: None,
                    aumid: Some("Vendor.Other".into()),
                },
            )
            // A shortcut to the app without an AUMID adds nothing.
            .shortcut(
                r"C:\Users\tester\Desktop\App.lnk",
                ShortcutInfo {
                    raw_path: Some(r"C:\Program Files\App\App.exe".into()),
                    args: None,
                    workdir: None,
                    aumid: None,
                },
            )
            .build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(
            got.anchors.aumids,
            ["App.Notifier", "AppToast-0011223344556677", "Vendor.App"]
        );
        assert_eq!(got.foreign_names, ["Other.Toast"]);
    }

    #[test]
    fn run_entries_point_into_the_app() {
        let user_run = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run");
        let f = Fixture::builder()
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "AppTray",
                r#""C:\Program Files\App\App.exe" --tray"#,
            )
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "SecurityHealth",
                r"%windir%\system32\SecurityHealthSystray.exe",
            )
            .sz(
                &user_run,
                "AppUpdate",
                r"C:\Program Files\App\App.exe /update",
            )
            .sz(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                "Other",
                r#""C:\Program Files\Other\other.exe""#,
            )
            .build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(
            got.anchors.run_entries,
            [
                RunEntry {
                    key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
                    name: "AppTray".into(),
                    data: r#""C:\Program Files\App\App.exe" --tray"#.into(),
                },
                RunEntry {
                    key: user_run,
                    name: "AppUpdate".into(),
                    data: r"C:\Program Files\App\App.exe /update".into(),
                },
            ]
        );
    }

    #[test]
    fn an_inferred_root_gives_anchors_only_through_its_main_exe() {
        let mut b = Fixture::builder();
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Tool.File",
            "open",
            r#""C:\Tools\Portable\tool.exe" "%1""#,
        );
        // Another program in the same guessed directory is not the app's.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Stranger.File",
            "open",
            r#""C:\Tools\Portable\stranger.exe" "%1""#,
        );
        let f = b.build();
        let roots = [root(r"C:\Tools\Portable", RootSource::UninstallerDir)];
        let exes = [exe(r"C:\Tools\Portable\tool.exe", true)];
        let got = harvest(&f, &roots, &exes);
        assert_eq!(got.anchors.progids, ["Tool.File"]);
        assert_eq!(got.foreign_names, ["Stranger.File"]);

        // Without an install root and without an exe nothing is attributed, and the harvest says so.
        let got = harvest(&f, &roots, &[]);
        assert_eq!(got.anchors, Anchors::default());
        assert!(got.foreign_names.is_empty());
        assert_eq!(got.warnings.len(), 1);
    }

    /// Regression: a ProgID or COM server of another program that only passes one of the app's files
    /// as an argument (a sandbox, a launcher) is that program's. It is never in P and never one of
    /// the app's CLSIDs, and its name counts as foreign.
    #[test]
    fn a_foreign_program_wrapping_the_app_does_not_own_the_registration() {
        const WRAPPED: &str = "{11111111-2222-3333-4444-888888888888}";
        const HOSTED: &str = "{11111111-2222-3333-4444-999999999999}";
        let mut b = Fixture::builder();
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Sandbox.Wrapped",
            "open",
            r#""C:\Program Files\Sandbox\Start.exe" /box:1 "C:\Program Files\App\App.exe" "%1""#,
        );
        // The same wrapper next to a verb of the app itself: modified, not owned.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Mixed.File",
            "open",
            r#""C:\Program Files\App\App.exe" "%1""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Mixed.File",
            "sandboxed",
            r#"C:\Tools\wrap.exe "C:\Program Files\App\App.exe" "%1""#,
        );
        // Hosts that Windows ships, by full path and by bare name, do run the app.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\App.Script",
            "open",
            r#""C:\Windows\System32\cmd.exe" /c "C:\Program Files\App\run.cmd" "%1""#,
        );
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\App.Hosted",
            "open",
            r#"rundll32.exe "C:\Program Files\App\helper.dll",Open %1"#,
        );
        b = b
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\CLSID\{WRAPPED}\LocalServer32"),
                "",
                r#""C:\Program Files\Sandbox\Start.exe" "C:\Program Files\App\App.exe" -Embedding"#,
            )
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\CLSID\{HOSTED}\LocalServer32"),
                "",
                r#"C:\Windows\System32\rundll32.exe "C:\Program Files\App\helper.dll",Serve"#,
            )
            // The loose test still applies to Run entries.
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "Wrapped",
                r#""C:\Program Files\Sandbox\Start.exe" "C:\Program Files\App\App.exe""#,
            );
        let f = b.build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(got.anchors.progids, ["App.Hosted", "App.Script"]);
        assert_eq!(
            got.modified_progids,
            [ModifiedProgId {
                name: "Mixed.File".into(),
                reason: ModifiedReason::ForeignCommand,
            }]
        );
        assert!(got.foreign_names.contains(&"Sandbox.Wrapped".to_owned()));
        assert_eq!(got.anchors.clsids, [HOSTED]);
        assert_eq!(got.anchors.run_entries.len(), 1);
    }

    /// Regression: without a baseline, a class or URL scheme Windows ships that the app took over
    /// completely (`http` of an old browser) is still not in P.
    #[test]
    fn well_known_shared_classes_are_never_in_p() {
        let mut b = Fixture::builder();
        for name in ["http", "HTTPS", "mailto", "htmlfile"] {
            b = command(
                b,
                &format!(r"HKLM\SOFTWARE\Classes\{name}"),
                "open",
                r#""C:\Program Files\App\App.exe" -url "%1""#,
            );
        }
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\AppURL",
            "open",
            r#""C:\Program Files\App\App.exe" -url "%1""#,
        );
        let f = b.build();
        let (roots, exes) = app_roots();
        let got = harvest(&f, &roots, &exes);
        assert_eq!(got.anchors.progids, ["AppURL"]);
        let modified: Vec<(&str, &ModifiedReason)> = got
            .modified_progids
            .iter()
            .map(|m| (m.name.as_str(), &m.reason))
            .collect();
        assert_eq!(
            modified,
            [
                ("htmlfile", &ModifiedReason::WellKnownShared),
                ("http", &ModifiedReason::WellKnownShared),
                ("HTTPS", &ModifiedReason::WellKnownShared),
                ("mailto", &ModifiedReason::WellKnownShared),
            ]
        );
        assert!(got.foreign_names.is_empty(), "{:?}", got.foreign_names);
    }

    #[test]
    fn the_well_known_list_is_sorted_and_free_of_duplicates() {
        let folded: Vec<String> = WELL_KNOWN_SHARED.iter().map(|n| n.to_lowercase()).collect();
        let mut sorted = folded.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(folded, sorted);
    }
}
