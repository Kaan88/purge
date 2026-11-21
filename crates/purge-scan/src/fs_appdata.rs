//! FS-APPDATA (ENGINE_PLAN.md §5.6): app folders under `%APPDATA%`, `%LOCALAPPDATA%`, LocalLow,
//! `%PROGRAMDATA%` and VirtualStore, depth <= 2.
//!
//! # What is looked at
//!
//! For the interactive user, each directory directly under one of the four bases and, below a directory
//! named after one of the app's vendors, each of its subdirectories. A handful of containers that are
//! never an app's folder (`Microsoft`, `Packages`, `Temp`, `Programs`…) are skipped. Below a directory
//! that is the app's, a vendor's or mentions either, directories named exactly like a harvested token are
//! searched one level deeper (`ProgramData\Mozilla-<guid>\updates\<hash>`). Paths the Inno uninstall log
//! names inside a base are looked at wherever they are, and so is the VirtualStore copy of each
//! InstallRoot.
//!
//! # Attribution (carry-over rule, §5.5)
//!
//! A directory is offered only on evidence about itself:
//!
//! - `InstallerManifest`: the Inno log names exactly this path (Tier A);
//! - `HarvestedToken`: its name **is** a harvested token (Tier A). Only that directory is offered, never
//!   its parent;
//! - `ExactFullName` or `NameTokenExact` for a directory directly under a base, and
//!   `ProductSubfolderOfVendor` for `<Vendor>\<Product>`;
//! - `ExactFullName` for a directory directly under a base that carries the file name of one of the app's
//!   **main exes**, when that name is one the harvest accepted for the app and is made of distinctive
//!   tokens (`%APPDATA%\Code` of `Code.exe`). The matcher alone gives a short name nothing; the exe set
//!   is what corroborates it here (see `Scan::main_exe_name`);
//! - `ReferencedByApp` is added when the directory is a referenced data directory, but never suffices:
//!   such a directory is not a whole-directory target on that ground alone (§5.2 "Root kinds").
//!
//! # Category
//!
//! Unknown folders are user data: every attributed folder is `Category::UserData` with the `UserData`
//! soft blocker, so it is offered unchecked whatever its evidence (a planted document, a profile, unsaved
//! backups). The exceptions are regenerable: a subdirectory with a known cache name (`Cache`, `GPUCache`,
//! `Code Cache`, `CachedData`, `logs`, `crashpad`) of an attributed folder, and a token-named directory
//! directly under an `updates` directory (an updater's per-install staging area). These are
//! `Category::Cache`, and still need Tier A evidence of their own to be offered at all.
//!
//! Name-attributed folders also get the negatives `ExecutablesPresent`, `ManyFiles` and `GenericName`.
//!
//! # A folder a family shares
//!
//! A `<Vendor>\<Product>` folder whose product name another app that stays installed carries as well
//! (`Mozilla\Firefox` beside Firefox ESR or Firefox Developer Edition) holds that app's live data: it
//! gets the hard blocker `ReferencedByOtherApp` naming that app, so it is listed as kept and never
//! offered for removal (`Scan::other_app_named`).

use purge_guard::prefix;
use purge_identity::identity::IdentityMatch;
use purge_identity::kbdata::Kb;
use purge_identity::tokenizer::{full_name_key, significant_tokens};
use purge_model::{
    Action, AnchorKind, Blocker, Candidate, CandidateId, Category, EvidenceKind, Facts,
    InnoRecordKind, RootKind, Target, Tier,
};
use purge_source::types::FileMeta;

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{
    Places, contains_delimited, emit, has_dot_segment, is_plain_dir, join, list, measure, sized,
};

/// The scanner's catalog id.
pub const ID: &str = "FS-APPDATA";

/// The locations the scanner reads. Token-named directories are searched one level below the two the
/// name rules use.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%APPDATA%", Some(3)),
    RootSpec::fs(r"%LOCALAPPDATA%", Some(3)),
    RootSpec::fs(r"%USERPROFILE%\AppData\LocalLow", Some(3)),
    RootSpec::fs(r"%ProgramData%", Some(3)),
    RootSpec::fs(r"%LOCALAPPDATA%\VirtualStore", None),
];

/// Subdirectories of an app folder that hold regenerable data.
const CACHE_DIR_NAMES: &[&str] = &[
    "Cache",
    "GPUCache",
    "Code Cache",
    "CachedData",
    "logs",
    "crashpad",
];

/// Directories whose token-named children are an updater's per-install staging areas.
const TOKEN_CACHE_PARENTS: &[&str] = &["updates"];

/// Directories directly under a base that are containers of Windows or of many apps, never one app's
/// folder.
const SKIPPED: &[&str] = &[
    "Microsoft",
    "Windows",
    "Packages",
    "Temp",
    "Programs",
    "VirtualStore",
    "Package Cache",
    "Application Data",
    "Desktop",
    "Documents",
    "Start Menu",
    "Templates",
    "Favorites",
];

/// More files than this in a name-attributed folder is the `ManyFiles` negative.
const MANY_FILES: u32 = 1_000;

/// A directory named after a main exe needs a name longer than this (§5.3 `ExactFullName`: "length > 3").
const EXACT_NAME_MIN_CHARS: usize = 3;

/// How deep below a base a token-named directory is looked for.
const TOKEN_DEPTH: u32 = 3;

/// The FS-APPDATA scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsAppData;

impl Scanner for FsAppData {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let places = Places::of(ctx);
        let mut scan = Scan {
            ctx,
            app,
            places: &places,
            out: Vec::new(),
        };
        for base in places.appdata_bases() {
            scan.base(base);
        }
        scan.virtual_store();
        scan.inno_records();
        scan.out
    }
}

/// How a path is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An app folder (or a file the installer declared): user data unless proven otherwise.
    Folder,
    /// A cache-named subdirectory of an attributed folder.
    Cache,
}

struct Scan<'a, 'c> {
    ctx: &'a ScanCtx<'c>,
    app: &'a AppIdentityView,
    places: &'a Places,
    out: Vec<Candidate>,
}

impl Scan<'_, '_> {
    /// Looks at the directories directly under `base` and at the product folders of vendor directories.
    fn base(&mut self, base: &str) {
        let Some(entries) = list(self.ctx, base) else {
            return;
        };
        for entry in &entries {
            if !is_plain_dir(&entry.meta) || is_named(&entry.name, SKIPPED) {
                continue;
            }
            let path = join(base, &entry.name);
            if self.in_app_root(&path) {
                continue;
            }
            let mut names = self.name_matches(&entry.name);
            // A short name is no evidence alone; the app's own main exe carrying it is the corroboration.
            if names.iter().all(|m| m.needs_tier_ab_neighbour)
                && let Some(m) = self.main_exe_name(&entry.name)
            {
                names = vec![m];
            }
            let vendor = self.app.identity.matches_vendor(&entry.name).is_some();
            let related = vendor || !names.is_empty() || self.mentions_app(&entry.name);
            let offered = self.offer(&path, &entry.meta, &names, Kind::Folder);
            if vendor && !offered {
                self.vendor_children(&path, &entry.name);
            }
            if related && !self.ctx.fp.tokens.is_empty() {
                self.token_dirs(&path, 2);
            }
        }
    }

    /// `<Vendor>\<Product>`: the subdirectories of a vendor directory that match the app's name.
    fn vendor_children(&mut self, vendor_dir: &str, vendor_name: &str) {
        let Some(entries) = list(self.ctx, vendor_dir) else {
            return;
        };
        for entry in &entries {
            if !is_plain_dir(&entry.meta) {
                continue;
            }
            let path = join(vendor_dir, &entry.name);
            if self.in_app_root(&path) {
                continue;
            }
            let names: Vec<IdentityMatch> = self
                .app
                .identity
                .matches_product_subfolder(vendor_name, &entry.name)
                .into_iter()
                .collect();
            self.offer(&path, &entry.meta, &names, Kind::Folder);
        }
    }

    /// Offers the directories below `dir` (itself at `depth - 1` below a base) whose name is a harvested
    /// token, down to [`TOKEN_DEPTH`].
    fn token_dirs(&mut self, dir: &str, depth: u32) {
        let Some(entries) = list(self.ctx, dir) else {
            return;
        };
        for entry in &entries {
            if !is_plain_dir(&entry.meta) {
                continue;
            }
            let path = join(dir, &entry.name);
            if self.in_app_root(&path) {
                continue;
            }
            if self.token_named(&entry.name).is_some() {
                self.offer(&path, &entry.meta, &[], Kind::Folder);
            } else if depth < TOKEN_DEPTH {
                self.token_dirs(&path, depth + 1);
            }
        }
    }

    /// The VirtualStore copy of each InstallRoot (`%LOCALAPPDATA%\VirtualStore\Program Files\App`).
    fn virtual_store(&mut self) {
        let Some(local) = self.places.local.as_deref() else {
            return;
        };
        let store = join(local, "VirtualStore");
        for root in &self.ctx.fp.roots {
            if root.kind != RootKind::InstallRoot {
                continue;
            }
            // `C:\Program Files\App` -> `Program Files\App`.
            let mut segments = prefix::segments(&root.path);
            if !segments.next().is_some_and(|drive| drive.ends_with(':')) {
                continue;
            }
            let rest: Vec<&str> = segments.collect();
            if rest.is_empty() {
                continue;
            }
            let path = join(&store, &rest.join("\\"));
            let Ok(meta) = self.ctx.fs.metadata(&path) else {
                continue;
            };
            if !is_plain_dir(&meta) {
                continue;
            }
            let names = self.name_matches(rest[rest.len() - 1]);
            self.offer(&path, &meta, &names, Kind::Folder);
        }
    }

    /// The paths the Inno log names inside a base, wherever they are.
    fn inno_records(&mut self) {
        let bases = self.places.appdata_bases();
        for record in &self.ctx.fp.inno {
            let Target::Path { path } = &record.target else {
                continue;
            };
            if !matches!(
                record.kind,
                InnoRecordKind::DeleteFile | InnoRecordKind::DeleteDirOrFiles
            ) || record.existed_before
                || record.shared
                || has_dot_segment(path)
            {
                continue;
            }
            let Some(below) = bases
                .iter()
                .find_map(|base| prefix::strip_prefix(path, base).filter(|rest| !rest.is_empty()))
            else {
                continue;
            };
            let first = prefix::segments(below).next().unwrap_or("");
            if is_named(first, SKIPPED)
                || self.places.in_shortcut_dir(path)
                || self.in_app_root(path)
            {
                continue;
            }
            let Ok(meta) = self.ctx.fs.metadata(path) else {
                continue;
            };
            if meta.is_reparse_point() {
                continue;
            }
            let cache = meta.is_dir()
                && prefix::depth(below) >= 2
                && prefix::leaf(path).is_some_and(|leaf| is_named(leaf, CACHE_DIR_NAMES));
            let kind = if cache { Kind::Cache } else { Kind::Folder };
            self.offer(path, &meta, &[], kind);
        }
    }

    /// Builds the candidate for `path` from the evidence about the path itself and emits it when there
    /// is any. Returns whether it was offered.
    fn offer(&mut self, path: &str, meta: &FileMeta, names: &[IdentityMatch], kind: Kind) -> bool {
        let ctx = self.ctx;
        let leaf = prefix::leaf(path).unwrap_or("");
        let token = self.token_named(leaf);
        let staging = token.is_some()
            && prefix::parent(path)
                .and_then(prefix::leaf)
                .is_some_and(|parent| is_named(parent, TOKEN_CACHE_PARENTS));
        let category = if kind == Kind::Cache || staging {
            Category::Cache
        } else {
            Category::UserData
        };
        let mut b = ctx.candidate(
            ID,
            Target::Path {
                path: path.to_owned(),
            },
            Action::Quarantine,
            category,
        );
        // Tier A and B first: a short-name match needs such a neighbour.
        if self.manifest_names(path, meta.is_dir()) {
            b.installer_manifest();
        }
        if let Some(token) = token {
            // The token names this install and nothing else (weight 7, Tier A). The folder's own age
            // is the second, independent observation: created within the install's window. Only the
            // creation time counts. A last-write time says nothing about age: the uninstaller itself
            // touches such folders, so on a source without creation times every token-named folder
            // would pass. Asked only next to the token: a time alone attributes nothing.
            if b.harvested_token(token) {
                if let Some(created) = meta.times.created {
                    b.time_window(created);
                }
            }
        }
        if category == Category::UserData {
            b.referenced_by_app();
        }
        for m in names {
            b.name_match(m);
        }
        let attributed = b
            .evidence()
            .iter()
            .any(|e| e.weight > 0 && e.kind != EvidenceKind::ReferencedByApp);
        if !attributed {
            return false;
        }
        if category == Category::UserData {
            b.blocker(Blocker::UserData);
        }
        let measured = measure(ctx, path, meta);
        sized(&mut b, &measured);
        let tier_a = b
            .evidence()
            .iter()
            .any(|e| e.weight > 0 && e.tier == Tier::A);
        if meta.is_dir() && !tier_a {
            let fact = |n: u32| Facts::new().with("path", path).with("count", n.to_string());
            if measured.executables > 0 {
                b.negative(EvidenceKind::ExecutablesPresent, fact(measured.executables));
            }
            if measured.files > MANY_FILES {
                b.negative(EvidenceKind::ManyFiles, fact(measured.files));
            }
            if Kb::shipped().generic.contains(&prefix::fold(leaf)) {
                b.negative(EvidenceKind::GenericName, Facts::new().with("name", leaf));
            }
        }
        // `<Vendor>\<Product>` does not single this app out when a product that stays installed
        // carries the name too: products of one family keep their data in one folder
        // (`Mozilla\Firefox` of Firefox, of Firefox ESR and of Firefox Developer Edition). The
        // folder then holds a live profile and is kept.
        let family = names
            .iter()
            .any(|m| m.kind == EvidenceKind::ProductSubfolderOfVendor)
            .then(|| self.other_app_named(leaf))
            .flatten();
        if let Some(app) = family {
            b.blocker(Blocker::ReferencedByOtherApp { app });
        }
        b.common_blockers();
        if kind == Kind::Folder && meta.is_dir() {
            for id in self.cache_children(path) {
                b.child(id);
            }
        }
        emit(&mut self.out, b)
    }

    /// Offers the cache-named subdirectories of an attributed folder and returns the ids of those that
    /// had evidence of their own.
    fn cache_children(&mut self, folder: &str) -> Vec<CandidateId> {
        let Some(entries) = list(self.ctx, folder) else {
            return Vec::new();
        };
        let mut ids = Vec::new();
        for entry in &entries {
            if !is_plain_dir(&entry.meta) || !is_named(&entry.name, CACHE_DIR_NAMES) {
                continue;
            }
            let path = join(folder, &entry.name);
            if self.offer(&path, &entry.meta, &[], Kind::Cache)
                && let Some(candidate) = self.out.last()
            {
                ids.push(candidate.id.clone());
            }
        }
        ids
    }

    /// The identity match of a directory name directly under a base: the full name when it is one,
    /// otherwise a whole-token match.
    fn name_matches(&self, segment: &str) -> Vec<IdentityMatch> {
        let identity = &self.app.identity;
        identity
            .matches_full_name(segment)
            .or_else(|| identity.matches_name(segment))
            .into_iter()
            .collect()
    }

    /// `ExactFullName` for a directory directly under a base that is named exactly like one of the app's
    /// main exes (`%APPDATA%\Code` of `Code.exe`).
    ///
    /// The matcher gives such a name no evidence by itself when it is short (§5.4 step 8) or, under a
    /// mega-vendor, has a single distinctive token (step 6): a short word alone names nothing. Here the
    /// word is corroborated by the harvested exe set, so the match stands when all of these hold:
    ///
    /// - a **main** exe of the fingerprint has exactly this file name (without `.exe`, ignoring case);
    /// - the harvest accepted that file name as a name of the app: it shares a product token with the
    ///   registry names and is not another installed app's name (§5.4 "Names");
    /// - every significant token of it is a distinctive token of the app, so not generic and not common
    ///   among the installed apps (steps 4 and 5), and there is at least one;
    /// - it is longer than 3 characters, the bound of the §5.3 `ExactFullName` row;
    /// - no other installed app carries the name or has an exe of that file name: the exe name must be
    ///   unique to this app, or the folder may be the profile of an install that stays (a per-user and
    ///   a machine-wide copy of one product share `%APPDATA%\<Name>`).
    ///
    /// The folder is still user data: listed, never preselected.
    fn main_exe_name(&self, segment: &str) -> Option<IdentityMatch> {
        let identity = &self.app.identity;
        if full_name_key(segment).chars().count() <= EXACT_NAME_MIN_CHARS {
            return None;
        }
        let is_main_exe = self.ctx.fp.main_exes().any(|exe| {
            prefix::leaf(&exe.path)
                .and_then(exe_stem)
                .is_some_and(|stem| prefix::eq_ci(stem, segment))
        });
        if !is_main_exe || self.other_app_shares_name(segment) {
            return None;
        }
        let name = identity
            .names()
            .iter()
            .find(|name| prefix::eq_ci(name, segment))?;
        let distinctive = identity.tokens();
        let tokens = significant_tokens(name, &Kb::shipped().generic);
        if tokens.is_empty() || !tokens.iter().all(|t| distinctive.contains(t)) {
            return None;
        }
        let kind = EvidenceKind::ExactFullName;
        Some(IdentityMatch {
            kind,
            tier: kind.default_tier(),
            weight: kind.default_weight(),
            needs_tier_ab_neighbour: false,
            matched: name.clone(),
            distance: 0,
        })
    }

    /// Whether another installed app is called `name` or has an exe (a file its records point at, or an
    /// exe anchor) of that file name.
    fn other_app_shares_name(&self, name: &str) -> bool {
        let key = full_name_key(name);
        let is_exe = |path: &str| {
            prefix::leaf(path)
                .and_then(exe_stem)
                .is_some_and(|stem| prefix::eq_ci(stem, name))
        };
        self.ctx.other_apps.apps().iter().any(|other| {
            full_name_key(&other.name) == key
                || other.files.iter().any(|file| is_exe(file))
                || other
                    .anchors
                    .iter()
                    .any(|a| a.kind == AnchorKind::Exe && is_exe(&a.text))
        })
    }

    /// The display name of another installed app whose name holds every significant token of the
    /// directory name `leaf` (the app's own vendor words aside): `Firefox` beside an installed
    /// `Firefox Developer Edition` or `Mozilla Firefox ESR`. Such a folder may hold that app's data
    /// whatever this app's name says.
    fn other_app_named(&self, leaf: &str) -> Option<String> {
        let generic = &Kb::shipped().generic;
        let vendors: Vec<&str> = self
            .app
            .identity
            .vendor_aliases()
            .iter()
            .flat_map(|alias| alias.split(' '))
            .collect();
        let wanted: Vec<String> = significant_tokens(leaf, generic)
            .into_iter()
            .filter(|t| !vendors.contains(&t.as_str()))
            .collect();
        if wanted.is_empty() {
            return None;
        }
        self.ctx.other_apps.apps().iter().find_map(|other| {
            let theirs = significant_tokens(&other.name, generic);
            wanted
                .iter()
                .all(|t| theirs.contains(t))
                .then(|| other.name.clone())
        })
    }

    /// Whether a directory name holds one of the app's vendor aliases or name tokens as a delimited
    /// part (`Mozilla-1de4eec8-…`). Only widens where token-named directories are searched.
    fn mentions_app(&self, name: &str) -> bool {
        let identity = &self.app.identity;
        identity
            .vendor_aliases()
            .iter()
            .any(|alias| contains_delimited(name, alias))
            || identity
                .tokens()
                .iter()
                .any(|token| contains_delimited(name, token))
    }

    /// The harvested token `name` is equal to, if any.
    fn token_named(&self, name: &str) -> Option<&str> {
        let ctx: &ScanCtx<'_> = self.ctx;
        ctx.fp
            .tokens
            .iter()
            .find(|t| prefix::eq_ci(&t.token, name))
            .map(|t| t.token.as_str())
    }

    /// Whether the Inno log has a record that makes exactly this path the installer's: any path record
    /// for a file, a directory record for a directory (a file record on what is a directory does not
    /// own the tree).
    fn manifest_names(&self, path: &str, is_dir: bool) -> bool {
        self.ctx.fp.inno.iter().any(|r| {
            let kind_fits = match r.kind {
                InnoRecordKind::DeleteDirOrFiles => true,
                InnoRecordKind::DeleteFile => !is_dir,
                _ => false,
            };
            kind_fits
                && !r.existed_before
                && !r.shared
                && matches!(&r.target, Target::Path { path: p } if prefix::is_same(p, path))
        })
    }

    /// Whether `path` is one of the app's install or inferred roots or lies in one: FS-INSTALLDIR's.
    fn in_app_root(&self, path: &str) -> bool {
        self.ctx.fp.roots.iter().any(|r| {
            r.kind != RootKind::ReferencedDataDir && prefix::is_same_or_inside(path, &r.path)
        })
    }
}

/// The file name of an executable without its `.exe`; `None` for any other file name.
fn exe_stem(file_name: &str) -> Option<&str> {
    let (stem, ext) = file_name.rsplit_once('.')?;
    (ext.eq_ignore_ascii_case("exe") && !stem.is_empty()).then_some(stem)
}

/// Whether `name` is one of `names`, ignoring case.
fn is_named(name: &str, names: &[&str]) -> bool {
    names.iter().any(|n| prefix::eq_ci(n, name))
}

#[cfg(test)]
mod tests {
    //! The main-exe name rule. The scanner's golden fixtures are in `tests/fs/appdata.rs`.

    use std::collections::BTreeMap;

    use purge_guard::canon::GuardEnv;
    use purge_index::baseline::Baseline;
    use purge_model::{
        Anchors, AppRef, ExeFile, FileTime, Fingerprint, FingerprintSchema, IdentitySnapshot,
        OsInfo, ProgramId, Root, RootSource, ScanMode, SourceTrust, TimeWindow, VerifyGone, View,
    };
    use purge_source::fixture::{Fixture, FixtureBuilder};

    use super::*;
    use crate::framework::{OtherApp, OtherApps, ScanExt, ScanLimits};

    const ROAMING: &str = r"C:\Users\tester\AppData\Roaming";
    const LOCAL: &str = r"C:\Users\tester\AppData\Local";
    const CODE_EXE: &str = r"C:\Program Files\Microsoft VS Code\Code.exe";
    const SERIAL: u32 = 0x1234_5678;
    const T_INSTALL: u64 = 134_000_000_000_000_000;

    fn machine() -> FixtureBuilder {
        Fixture::builder()
            .volume("C:\\", Some(SERIAL), true, "NTFS")
            .dir(r"C:\Program Files")
            .dir(r"C:\ProgramData")
            .dir(r"C:\Windows\System32")
            .dir(ROAMING)
            .dir(LOCAL)
            .dir(r"C:\Users\tester\AppData\LocalLow")
    }

    /// A machine-wide app with this identity, installed in `root`, with these exes (path, main).
    fn fingerprint(
        names: &[&str],
        vendor: &str,
        tokens: &[&str],
        root: &str,
        exes: &[(&str, bool)],
    ) -> Fingerprint {
        let strings = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        Fingerprint {
            baseline_view: None,
            schema: FingerprintSchema,
            app: AppRef {
                program_id: ProgramId::machine(View::K64, "Fixture App_is1")
                    .expect("a valid key name"),
                display_name: names[0].to_owned(),
            },
            identity: IdentitySnapshot {
                names: strings(names),
                vendors: strings(&[vendor]),
                tokens: strings(tokens),
                mega_vendor: Kb::shipped().mega_vendors.is_mega(vendor),
            },
            roots: vec![Root {
                path: root.to_owned(),
                kind: RootKind::InstallRoot,
                source: RootSource::ArpInstallLocation,
                trust: SourceTrust::AdminOnly,
                volume_serial: Some(SERIAL),
                parent_existed: true,
            }],
            exes: exes
                .iter()
                .map(|(path, main)| ExeFile {
                    path: (*path).to_owned(),
                    main: *main,
                })
                .collect(),
            outside_root_files: Vec::new(),
            uninstallers: Vec::new(),
            older_keys: Vec::new(),
            anchors: Anchors::default(),
            tokens: Vec::new(),
            inno: Vec::new(),
            ref_snapshot: Vec::new(),
            subtrees: Vec::new(),
            ext_journal: Vec::new(),
            co_removed: Vec::new(),
            msi: Vec::new(),
            burn: None,
            sys: Default::default(),
            os: OsInfo {
                edition: "Professional".into(),
                build: 26340,
                ubr: 9882,
            },
            user_sid: GuardEnv::SAMPLE_SID.into(),
            window: TimeWindow {
                install_time: Some(FileTime(T_INSTALL)),
                t_start: Some(FileTime(T_INSTALL + 1_000)),
                t_end: Some(FileTime(T_INSTALL + 2_000)),
            },
            verify_gone: Some(VerifyGone::new(true, true, true)),
            warnings: Vec::new(),
        }
    }

    /// Visual Studio Code as the harvest sees it: a mega-vendor app whose main exe is `Code.exe`.
    fn vscode_fp() -> Fingerprint {
        fingerprint(
            &["Microsoft Visual Studio Code", "Code"],
            "Microsoft Corporation",
            &["code", "studio", "visual"],
            r"C:\Program Files\Microsoft VS Code",
            &[
                (CODE_EXE, true),
                (
                    r"C:\Program Files\Microsoft VS Code\bin\code-tunnel.exe",
                    false,
                ),
            ],
        )
    }

    /// The profile VS Code leaves behind, next to folders that are not its own.
    fn vscode_machine() -> Fixture {
        machine()
            .file(
                r"C:\Users\tester\AppData\Roaming\Code\User\settings.json",
                300,
            )
            .file(
                r"C:\Users\tester\AppData\Roaming\Code\Backups\untitled-1",
                2_000,
            )
            .file(
                r"C:\Users\tester\AppData\Roaming\Code\Cache\Cache_Data\data_0",
                8_192,
            )
            .file(r"C:\Users\tester\AppData\Roaming\Code\logs\main.log", 100)
            // Not VS Code's.
            .file(r"C:\Users\tester\AppData\Roaming\Codex\config.toml", 10)
            .file(
                r"C:\Users\tester\AppData\Roaming\Code Compare\settings.xml",
                10,
            )
            .file(
                r"C:\Users\tester\AppData\Roaming\code-tunnel\state.json",
                10,
            )
            .file(r"C:\Users\tester\AppData\Roaming\Studio\x.bin", 10)
            .file(r"C:\Users\tester\AppData\Roaming\Microsoft\Code\x.bin", 10)
            .file(r"C:\Users\tester\AppData\Roaming\Other\Code\x.bin", 10)
            .file(r"C:\Users\tester\AppData\Local\Programs\Code\x.bin", 10)
            .build()
    }

    fn scan(fixture: &Fixture, fp: &Fingerprint) -> Vec<Candidate> {
        scan_beside(fixture, fp, Vec::new())
    }

    /// The scan with these other apps still installed.
    fn scan_beside(fixture: &Fixture, fp: &Fingerprint, others: Vec<OtherApp>) -> Vec<Candidate> {
        let env: BTreeMap<String, String> = [
            ("SYSTEMDRIVE", "C:"),
            ("WINDIR", r"C:\Windows"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("PROGRAMFILES", r"C:\Program Files"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("PUBLIC", r"C:\Users\Public"),
            ("USERPROFILE", r"C:\Users\tester"),
            ("APPDATA", ROAMING),
            ("LOCALAPPDATA", LOCAL),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let baseline =
            Baseline::from_bytes(b"#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n")
                .expect("the baseline parses");
        let guard = GuardEnv::sample();
        let other_apps = OtherApps::new(others);
        let ctx = ScanCtx {
            reg: fixture,
            fs: fixture,
            sys: fixture,
            fp,
            baseline: Some(&baseline),
            mode: ScanMode::Post,
            verify_gone: Some(VerifyGone::new(true, true, true)),
            env: &env,
            guard: &guard,
            other_apps: &other_apps,
            limits: ScanLimits::default(),
            ext: ScanExt::none(),
        };
        let app = AppIdentityView::from_fingerprint(fp, &env);
        FsAppData.scan(&ctx, &app)
    }

    fn paths(found: &[Candidate]) -> Vec<&str> {
        found
            .iter()
            .filter_map(|c| match &c.target {
                Target::Path { path } => Some(path.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn folder_named_after_the_main_exe_is_listed_as_user_data() {
        let found = scan(&vscode_machine(), &vscode_fp());
        // Only the profile folder: no look-alike, nothing deeper, and no cache child (a cache needs
        // Tier A evidence of its own).
        assert_eq!(paths(&found), [format!(r"{ROAMING}\Code")]);
        let code = &found[0];
        assert_eq!(code.category, Category::UserData);
        assert_eq!(code.action, Action::Quarantine);
        assert!(code.blockers.contains(&Blocker::UserData));
        let positive: Vec<_> = code.evidence.iter().filter(|e| e.weight > 0).collect();
        assert_eq!(positive.len(), 1, "{:?}", code.evidence);
        assert_eq!(positive[0].kind, EvidenceKind::ExactFullName);
        assert_eq!(positive[0].tier, Tier::B);
        assert!(code.children.is_empty());
    }

    #[test]
    fn the_match_ignores_case_but_not_spelling() {
        let fixture = machine()
            .file(
                r"C:\Users\tester\AppData\Roaming\code\User\settings.json",
                300,
            )
            .file(r"C:\Users\tester\AppData\Local\Code 2\x.bin", 1)
            .file(r"C:\Users\tester\AppData\Local\Code.exe\x.bin", 1)
            .build();
        let found = scan(&fixture, &vscode_fp());
        assert_eq!(paths(&found), [format!(r"{ROAMING}\code")]);
    }

    #[test]
    fn without_a_main_exe_of_that_name_a_short_name_matches_nothing() {
        let fixture = vscode_machine();
        // No exe at all (the harvest saw none).
        let mut fp = vscode_fp();
        fp.exes.clear();
        assert!(scan(&fixture, &fp).is_empty());
        // The exe is in the set but is not a main exe.
        let mut fp = vscode_fp();
        fp.exes[0].main = false;
        assert!(scan(&fixture, &fp).is_empty());
        // A helper is the main exe; its name was never accepted as a name of the app.
        let mut fp = vscode_fp();
        fp.exes[0].main = false;
        fp.exes[1].main = true;
        assert!(scan(&fixture, &fp).is_empty());
    }

    #[test]
    fn an_exe_name_the_harvest_did_not_accept_as_a_name_matches_nothing() {
        let mut fp = vscode_fp();
        fp.identity.names = vec!["Microsoft Visual Studio Code".to_owned()];
        assert!(scan(&vscode_machine(), &fp).is_empty());
    }

    #[test]
    fn a_common_or_generic_exe_name_matches_nothing() {
        // `code` is common among the installed apps: it is not one of the app's distinctive tokens.
        let mut fp = vscode_fp();
        fp.identity.tokens = vec!["studio".to_owned(), "visual".to_owned()];
        assert!(scan(&vscode_machine(), &fp).is_empty());
        // Name matching is disabled altogether.
        let mut fp = vscode_fp();
        fp.identity.tokens.clear();
        assert!(scan(&vscode_machine(), &fp).is_empty());
        // A generic word is never a name, whatever the exe is called.
        let fixture = machine()
            .file(r"C:\Users\tester\AppData\Roaming\Launcher\x.bin", 1)
            .file(r"C:\Users\tester\AppData\Local\Update\x.bin", 1)
            .build();
        for word in ["Launcher", "Update"] {
            let exe = format!(r"C:\Program Files\Acme Quill\{word}.exe");
            let fp = fingerprint(
                &["Acme Quill", word],
                "Acme",
                &["quill"],
                r"C:\Program Files\Acme Quill",
                &[(&exe, true)],
            );
            assert!(scan(&fixture, &fp).is_empty(), "{word}");
        }
    }

    #[test]
    fn an_exe_name_another_installed_app_shares_matches_nothing() {
        let fixture = vscode_machine();
        let fp = vscode_fp();
        let user_exe = r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe";
        // A per-user copy of the same product stays installed: its record points at its own Code.exe.
        let by_file = OtherApp {
            name: "Microsoft Visual Studio Code (User)".into(),
            files: vec![user_exe.into()],
            ..OtherApp::default()
        };
        // The same, known through an exe anchor (a full path or a bare file name).
        let by_anchor = |text: &str| OtherApp {
            name: "Some Editor".into(),
            anchors: vec![purge_model::AnchorRef {
                kind: AnchorKind::Exe,
                text: text.into(),
            }],
            ..OtherApp::default()
        };
        // Another app is itself called like the folder.
        let by_name = OtherApp {
            name: "Code".into(),
            ..OtherApp::default()
        };
        for other in [by_file, by_anchor(user_exe), by_anchor("code.exe"), by_name] {
            let name = other.name.clone();
            assert!(scan_beside(&fixture, &fp, vec![other]).is_empty(), "{name}");
        }
        // An unrelated app changes nothing.
        let unrelated = OtherApp {
            name: "Code Compare".into(),
            files: vec![r"C:\Program Files\Devart\Code Compare\CodeCompare.exe".into()],
            anchors: vec![purge_model::AnchorRef {
                kind: AnchorKind::Token,
                text: "Code".into(),
            }],
            ..OtherApp::default()
        };
        let found = scan_beside(&fixture, &fp, vec![unrelated]);
        assert_eq!(paths(&found), [format!(r"{ROAMING}\Code")]);
        // Nor does its name keep a folder directly under a base: only a product folder below the
        // vendor's is one a family shares.
        assert_eq!(found[0].blockers, [Blocker::UserData]);
    }

    /// `<Vendor>\<Product>` is one folder for a family of products: Firefox, Firefox Developer
    /// Edition and Firefox ESR all keep their profiles in `Mozilla\Firefox`. While one of them stays
    /// installed the folder's name does not single out the app being removed.
    #[test]
    fn a_product_folder_another_installed_app_is_named_after_is_kept() {
        let fixture = machine()
            .file(&format!(r"{ROAMING}\Mozilla\Firefox\profiles.ini"), 10)
            .file(
                &format!(r"{LOCAL}\Mozilla\Firefox\Profiles\x\cache.bin"),
                10,
            )
            .build();
        let fp = fingerprint(
            &["Mozilla Firefox"],
            "Mozilla",
            &["firefox"],
            r"C:\Program Files\Mozilla Firefox",
            &[(r"C:\Program Files\Mozilla Firefox\firefox.exe", true)],
        );
        let other = |name: &str| OtherApp {
            name: name.into(),
            ..OtherApp::default()
        };
        let shared = |found: &[Candidate]| -> Vec<(String, Option<String>)> {
            found
                .iter()
                .filter(|c| {
                    c.evidence
                        .iter()
                        .any(|e| e.kind == EvidenceKind::ProductSubfolderOfVendor)
                })
                .map(|c| {
                    let Target::Path { path } = &c.target else {
                        panic!("a path target");
                    };
                    let app = c.blockers.iter().find_map(|b| match b {
                        Blocker::ReferencedByOtherApp { app } => Some(app.clone()),
                        _ => None,
                    });
                    (path.clone(), app)
                })
                .collect()
        };
        let folders = [
            format!(r"{ROAMING}\Mozilla\Firefox"),
            format!(r"{LOCAL}\Mozilla\Firefox"),
        ];
        let expect = |app: Option<&str>| -> Vec<(String, Option<String>)> {
            folders
                .iter()
                .map(|f| (f.clone(), app.map(str::to_owned)))
                .collect()
        };
        // Alone, and beside products that are not named after the folder.
        assert_eq!(shared(&scan(&fixture, &fp)), expect(None));
        for name in [
            "Mozilla Thunderbird (x64 en-US)",
            "Mozilla Maintenance Service",
            "Waterfox",
            "Fire Fox Tools",
        ] {
            let found = scan_beside(&fixture, &fp, vec![other(name)]);
            assert_eq!(shared(&found), expect(None), "{name}");
        }
        // Beside a product of the same family.
        for name in [
            "Firefox Developer Edition (x64 en-US)",
            "Mozilla Firefox ESR (x64 en-US)",
            "Firefox",
        ] {
            let found = scan_beside(&fixture, &fp, vec![other("Unrelated"), other(name)]);
            assert_eq!(shared(&found), expect(Some(name)), "{name}");
        }
    }

    #[test]
    fn a_name_of_three_characters_stays_short() {
        let fixture = machine()
            .file(r"C:\Users\tester\AppData\Roaming\Git\x.bin", 1)
            .build();
        let fp = fingerprint(
            &["Git"],
            "The Git Development Community",
            &["git"],
            r"C:\Program Files\Git",
            &[(r"C:\Program Files\Git\cmd\git.exe", true)],
        );
        assert!(scan(&fixture, &fp).is_empty());
    }

    #[test]
    fn exe_stem_wants_an_exe() {
        assert_eq!(exe_stem("Code.exe"), Some("Code"));
        assert_eq!(exe_stem("notepad++.EXE"), Some("notepad++"));
        assert_eq!(exe_stem("Code.dll"), None);
        assert_eq!(exe_stem("Code"), None);
        assert_eq!(exe_stem(".exe"), None);
    }
}
