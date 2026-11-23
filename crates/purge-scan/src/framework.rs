//! The scanner framework (ENGINE_PLAN.md §5.6, §5.3, §5.5): the [`Scanner`] trait, the [`ScanCtx`] every
//! scanner reads through, and the [`CandidateBuilder`] every scanner emits through.
//!
//! # Rules the framework enforces
//!
//! - **Scanners never decide a band.** A candidate leaves this crate with `decision: None`; `purge-plan`
//!   runs the guard and `purge-policy` over it.
//! - **Scanners never invent numbers.** Evidence is added through the typed constructors of
//!   [`CandidateBuilder`]. Tier, weight and allowed scope come from the §5.3 table in `purge-model`, the
//!   trust comes from the fingerprint record the evidence rests on ([`app_trust`], [`Root::trust`]), and
//!   each constructor re-checks the part of the row's "verified by" column that can be checked from the
//!   context (the path really lies under an InstallRoot, the value really is in the reference snapshot,
//!   the token really is a harvested one…). A constructor returns `false` and adds nothing when its
//!   condition does not hold.
//! - **Carry-over rule (§5.5).** Evidence on a directory or key never extends to descendants that are not
//!   themselves attributed. The constructors therefore test the candidate's own target (its leaf segment,
//!   its exact key, its exact value), never an ancestor. The one exception is `InsideInstallRoot`, which
//!   holds for everything under a validated InstallRoot.
//! - **A reference does not make a registration the app's (§5.3, "reference evidence").** That a value
//!   points at the app's files says what the value is about, not who put it there: another program's
//!   setting, a `Run` entry or an environment variable the user made, all name the app's files without
//!   being the app's. `InPreUninstallRefSnapshot`, `PointsIntoInstallRoot` and `DanglingRef` on a
//!   registry value are therefore Tier A only where the registration itself is the app's
//!   ([`ScanCtx::owns_registration`]); everywhere else the constructors lower them to Tier B, so the
//!   value is listed but never preselected on them.
//! - **All reads go through `purge-source`** ([`ScanCtx::reg`], [`ScanCtx::fs`], [`ScanCtx::sys`]), so a
//!   scanner runs unchanged over the live system, a JSON fixture or a rig snapshot.
//!
//! # Paths
//!
//! Helpers expect canonical input (`purge-guard` canonicalisation): backslash-separated absolute file
//! paths, and registry keys spelled `HKLM\…`, `HKU\<SID>\…`, `HKU\<SID>_Classes\…`. Comparisons are
//! case-insensitive and separator-aware (`purge_guard::prefix`). `HKLM\SYSTEM\CurrentControlSet` and the
//! `ControlSet00N` the [`GuardEnv`] names as current are treated as the same key.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_guard::prefix::{self, Relation};
use purge_identity::identity::{AppIdentity, IdentityMatch};
use purge_index::baseline::Baseline;
use purge_index::baseline_view::{Absence, BaselineView};
use purge_index::matcher::{AnchorSet, MatchHow, RefMatcher};
use purge_model::exec::op::FileIdHex;
use purge_model::{
    Action, AnchorKind, AnchorRef, AppRef, BaselineTrust, Blocker, Candidate, CandidateId,
    Category, Evidence, EvidenceKind, Facts, FileTime, Fingerprint, Harm, InnoRecord,
    InnoRecordKind, MAX_NEIGHBOURS, MAX_RESIDUE_ITEMS, ManifestKind, Origin, RefSnapEntry,
    ResidueBaselineView, ResidueDoc, ResidueItem, ResidueOwner, ResidueSchema, ResidueShape,
    ResidueWhy, ResidueWritten, Reversibility, Root, RootKind, RootSource, ScanMode, Scope,
    SourceTrust, Target, Tier, VerifyGone, item_fp_text,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{ExistsState, RegData};

use crate::skeleton;

mod absence;
mod m1b;

pub use absence::{
    BASELINE_FACT, BASELINE_FACT_NONE, BASELINE_NEIGHBOURS_FACT, BASELINE_TRUST_FACT,
    WINDOWS_BUILD_FACT, claims_absence,
};
pub use m1b::{PathStore, ScanExt, inventory_lists_product, product_known_in};

// ---------------------------------------------------------------------------------------------------------
// Scanner trait and root specs
// ---------------------------------------------------------------------------------------------------------

/// Whether a [`RootSpec`] names a registry location or a filesystem location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootSpecKind {
    /// A registry key pattern.
    Reg,
    /// A filesystem path pattern.
    Fs,
}

/// One location a scanner reads, declared so that `xtask scanner-coverage` can check that the VM rig
/// captures it (§5.6: "a scanner without rig coverage cannot emit Safe").
///
/// The pattern syntax is the one of the `purge-guard` deny-list (`purge_guard::deny`):
///
/// - Registry: starts with `HKLM\`, `HKU\*\` (any user hive), `*\` (either) or `HKCR\` (the Classes root of
///   the machine or of any user); `*` is one segment, `[*]` the literal key `*`; view-agnostic, so
///   `WOW6432Node` is never spelled; `CurrentControlSet` stands for the current control set.
/// - Filesystem: starts with one of [`RootSpec::FS_TOKENS`]; `*` is one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootSpec {
    /// Registry or filesystem.
    pub kind: RootSpecKind,
    /// The location, in the syntax described on the type.
    pub pattern: &'static str,
    /// How deep below the location the scanner reads: `Some(0)` is the item itself (a value container),
    /// `Some(n)` is `n` levels of children, `None` is the whole subtree.
    pub depth: Option<u32>,
}

impl RootSpec {
    /// The tokens a filesystem pattern may start with. `%PROFILES%` is the profiles directory
    /// (`C:\Users`); the last three name the folder of every profile.
    pub const FS_TOKENS: &'static [&'static str] = &[
        "%ProgramFiles%",
        "%ProgramData%",
        "%PROFILES%",
        "%USERPROFILE%",
        "%APPDATA%",
        "%LOCALAPPDATA%",
    ];

    /// The prefixes a registry pattern may start with.
    pub const REG_PREFIXES: &'static [&'static str] = &[r"HKLM\", r"HKU\*\", r"*\", r"HKCR\"];

    /// A registry location.
    pub const fn reg(pattern: &'static str, depth: Option<u32>) -> Self {
        Self {
            kind: RootSpecKind::Reg,
            pattern,
            depth,
        }
    }

    /// A filesystem location.
    pub const fn fs(pattern: &'static str, depth: Option<u32>) -> Self {
        Self {
            kind: RootSpecKind::Fs,
            pattern,
            depth,
        }
    }

    /// Whether the pattern follows the syntax described on the type: a known prefix or token, no empty
    /// segment, no trailing separator and, for keys, no `WOW6432Node` segment.
    pub fn is_well_formed(&self) -> bool {
        let p = self.pattern;
        if p.is_empty() || p.ends_with(prefix::SEP) || p.contains(r"\\") || p.contains('/') {
            return false;
        }
        match self.kind {
            RootSpecKind::Reg => {
                Self::REG_PREFIXES
                    .iter()
                    .any(|pre| p.len() > pre.len() && starts_with_ci(p, pre))
                    && !prefix::segments(p).any(|s| s.eq_ignore_ascii_case("WOW6432Node"))
            }
            RootSpecKind::Fs => Self::FS_TOKENS.iter().any(|token| {
                starts_with_ci(p, token)
                    && (p.len() == token.len() || p[token.len()..].starts_with(prefix::SEP))
            }),
        }
    }
}

fn starts_with_ci(s: &str, pre: &str) -> bool {
    s.get(..pre.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(pre))
}

/// A leftover scanner (§5.6).
///
/// A scanner turns the fingerprint's anchors and what the sources show now into candidates. It builds
/// them with [`ScanCtx::candidate`] and never sets a band.
pub trait Scanner: Send + Sync {
    /// The catalog id, e.g. `REG-SOFTWARE`.
    fn id(&self) -> &'static str;

    /// Every location the scanner reads. Checked against the rig's capture roots by
    /// `xtask scanner-coverage`.
    fn captured_roots(&self) -> &[RootSpec];

    /// The keys the scanner reads single values from. Each must be an entry of
    /// `purge_guard::containers::VALUE_CONTAINERS`, spelled exactly as there: such a key is structural
    /// and is never deleted as a key (§5.10).
    fn value_containers(&self) -> &[&'static str] {
        &[]
    }

    /// Whether the scanner asks for the hits of the scan's one reference walk, or for its
    /// completeness (`ScanExt::ref_hits_for`, `ScanExt::ref_walk_complete`, the helpers built on
    /// them). The pipeline runs the scanners that do not while the walk is still reading, and the
    /// others when it is done; the candidates are put together in catalog order either way. The
    /// answer only orders the work: a scanner that says `false` and asks all the same waits for
    /// the walk and gets the same hits.
    fn reads_ref_walk(&self) -> bool {
        false
    }

    /// Finds the app's leftovers.
    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate>;
}

// ---------------------------------------------------------------------------------------------------------
// The app as scanners see it
// ---------------------------------------------------------------------------------------------------------

/// The identity of the app being cleaned, rebuilt from the fingerprint so that the scan matches names and
/// references exactly as the harvest did, without asking the (now uninstalled) system.
#[derive(Debug, Clone)]
pub struct AppIdentityView {
    /// The app.
    pub app: AppRef,
    /// Name and vendor matching (§5.4), from the fingerprint's identity snapshot.
    pub identity: AppIdentity,
    /// The app's anchors: roots, exe set, ProgIDs, CLSIDs, AUMIDs and tokens.
    pub anchors: AnchorSet,
    /// The reference matcher over [`AppIdentityView::anchors`], with the interactive user's environment.
    pub refs: RefMatcher,
}

impl AppIdentityView {
    /// Builds the view of `fp`'s app. `env` is the interactive user's environment (names upper-cased), as
    /// in [`ScanCtx::env`].
    pub fn from_fingerprint(fp: &Fingerprint, env: &BTreeMap<String, String>) -> Self {
        let anchors = AnchorSet::from_fingerprint(fp);
        let refs = RefMatcher::with_env(&anchors, env.iter());
        Self {
            app: fp.app.clone(),
            identity: AppIdentity::from_snapshot(&fp.identity),
            anchors,
            refs,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Other apps
// ---------------------------------------------------------------------------------------------------------

/// What one other installed app owns or refers to, as far as the inventory and its harvest know.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtherApp {
    /// Display name (or program id) for the blocker text.
    pub name: String,
    /// Its root directories (canonical paths).
    pub roots: Vec<String>,
    /// Files its records point at: the uninstaller of `UninstallString`, the `DisplayIcon` target, service
    /// and task images (canonical paths).
    pub files: Vec<String>,
    /// Registry keys that are its own (canonical keys), e.g. its ARP key and `Software\<Vendor>\<Product>`.
    pub keys: Vec<String>,
    /// Its anchors: ProgIDs, CLSIDs, AUMIDs, tokens, exe names.
    pub anchors: Vec<AnchorRef>,
}

/// The roots and anchors of every other current inventory entry (§5.5 ownership index, M1a part), for the
/// `InsideOtherApp`, `ContainsOtherApp` and `ReferencedByOtherApp` checks.
///
/// The pipeline builds it from the inventory **after** the uninstall, without the app being cleaned and
/// without its co-removed products.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtherApps {
    apps: Vec<OtherApp>,
}

impl OtherApps {
    /// The index over `apps`.
    pub fn new(apps: Vec<OtherApp>) -> Self {
        Self { apps }
    }

    /// The other apps.
    pub fn apps(&self) -> &[OtherApp] {
        &self.apps
    }

    /// The blockers a file or directory target earns, each kind at most once per app:
    ///
    /// - `InsideOtherApp` when the path is another app's root or lies inside one;
    /// - `ContainsOtherApp` when another app's root or referenced file lies inside the path;
    /// - `ReferencedByOtherApp` when the path is a file another app's records point at.
    pub fn path_blockers(&self, path: &str) -> Vec<Blocker> {
        let mut out = Vec::new();
        for app in &self.apps {
            let name = || app.name.clone();
            let roots = |wanted: &[Relation]| {
                app.roots
                    .iter()
                    .any(|root| wanted.contains(&prefix::relation(path, root)))
            };
            if roots(&[Relation::Same, Relation::Inside]) {
                out.push(Blocker::InsideOtherApp { app: name() });
            }
            if roots(&[Relation::Ancestor])
                || app.files.iter().any(|file| prefix::is_ancestor(path, file))
            {
                out.push(Blocker::ContainsOtherApp { app: name() });
            }
            if app.files.iter().any(|file| prefix::is_same(path, file)) {
                out.push(Blocker::ReferencedByOtherApp { app: name() });
            }
        }
        out
    }

    /// [`OtherApps::key_blockers`] with the caller's way of relating two keys.
    fn key_blockers_with(
        &self,
        key: &str,
        relation: impl Fn(&str, &str) -> Relation,
    ) -> Vec<Blocker> {
        let mut out = Vec::new();
        for app in &self.apps {
            let any = |wanted: &[Relation]| {
                app.keys
                    .iter()
                    .any(|other| wanted.contains(&relation(key, other)))
            };
            if any(&[Relation::Same, Relation::Inside]) {
                out.push(Blocker::InsideOtherApp {
                    app: app.name.clone(),
                });
            }
            if any(&[Relation::Ancestor]) {
                out.push(Blocker::ContainsOtherApp {
                    app: app.name.clone(),
                });
            }
        }
        out
    }

    /// The blockers a registry key earns: `InsideOtherApp` when it is another app's key or lies inside
    /// one, `ContainsOtherApp` when another app's key lies inside it.
    pub fn key_blockers(&self, key: &str) -> Vec<Blocker> {
        self.key_blockers_with(key, prefix::relation)
    }

    /// The other app that has this anchor (compared case-insensitively), if any. Scanners use it for
    /// "the exe name is not claimed by another app", "the ProgID is still another app's" and the
    /// `HarvestedToken` rule "absent from all other apps' anchors".
    pub fn claimant(&self, kind: AnchorKind, text: &str) -> Option<&OtherApp> {
        self.apps.iter().find(|app| {
            app.anchors
                .iter()
                .any(|a| a.kind == kind && prefix::eq_ci(&a.text, text))
        })
    }

    /// [`Blocker::ReferencedByOtherApp`] when another app has this anchor.
    pub fn anchor_blocker(&self, kind: AnchorKind, text: &str) -> Option<Blocker> {
        self.claimant(kind, text)
            .map(|app| Blocker::ReferencedByOtherApp {
                app: app.name.clone(),
            })
    }
}

// ---------------------------------------------------------------------------------------------------------
// Scan context
// ---------------------------------------------------------------------------------------------------------

/// Bounds on what one scanner reads, so that a pathological directory or key cannot stall a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanLimits {
    /// Most entries read from one directory listing; a larger directory is treated as not enumerable.
    pub max_dir_entries: usize,
    /// Most files and directories visited by one recursive walk (size and count of a candidate).
    pub max_walk_entries: usize,
    /// Most subkeys and values read from one key.
    pub max_key_children: usize,
    /// Deepest nesting followed below a key or directory.
    pub max_depth: u32,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_dir_entries: 20_000,
            max_walk_entries: 200_000,
            max_key_children: 5_000,
            max_depth: 32,
        }
    }
}

/// Everything a scanner may read (§5.6).
#[derive(Clone, Copy)]
pub struct ScanCtx<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The filesystem.
    pub fs: &'a dyn FileSystemSource,
    /// Machine and session facts.
    pub sys: &'a dyn SystemSource,
    /// What the harvest learned about the app before its uninstaller ran.
    pub fp: &'a Fingerprint,
    /// The baseline view: what the scan knows about "Windows' own" (BASELINE_LOCAL_DESIGN.md §4).
    /// Presence is asked of it directly, at every trust ([`ScanCtx::in_baseline`], `has_*`). Absence
    /// is asked only through [`ScanCtx::key_absence`] and the two gates beside it
    /// ([`ScanCtx::has_exact_baseline`]): only an Exact view, the clean-Windows baseline of exactly
    /// this (edition, build.ubr), proves a key "not Windows' own"; below Exact the work is values-only
    /// (§5.7.1 step 3). A scan without any baseline passes [`BaselineView::empty`].
    pub baseline: &'a BaselineView,
    /// The scan mode (§5.1).
    pub mode: ScanMode,
    /// The verify-gone result of the uninstall; `None` when no uninstall was observed.
    pub verify_gone: Option<VerifyGone>,
    /// The interactive user's environment, names upper-cased ([`SystemSource::env`]).
    pub env: &'a BTreeMap<String, String>,
    /// The machine layout for `purge-guard` canonicalisation and container checks.
    pub guard: &'a GuardEnv,
    /// What the other installed apps own.
    pub other_apps: &'a OtherApps,
    /// Read bounds.
    pub limits: ScanLimits,
    /// What the pipeline read once for every scanner (M1b, C-SCANEXT): the reference walk, the MSI
    /// ownership index and the system objects. [`ScanExt::none`] everywhere but the pipeline.
    pub ext: &'a ScanExt,
}

/// Proof that a path is a dangling reference (§5.3 `DanglingRef`). Only [`ScanCtx::dangling`] makes one,
/// so `DanglingRef` evidence cannot be added without the check having run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dangling<'a> {
    root: &'a Root,
    path: String,
    serial: u32,
    nearest: String,
}

impl<'a> Dangling<'a> {
    /// The InstallRoot the missing path belongs to.
    pub fn root(&self) -> &'a Root {
        self.root
    }

    /// The missing path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The serial of the volume, equal to the one recorded for the root at harvest.
    pub fn volume_serial(&self) -> u32 {
        self.serial
    }

    /// The nearest ancestor of the path that still exists.
    pub fn nearest_existing_ancestor(&self) -> &str {
        &self.nearest
    }

    /// Whether the root itself is gone, i.e. the nearest existing ancestor is the root's parent. Always
    /// `true` for a value made by [`ScanCtx::dangling`]: the rule (§5.3) accepts nothing else.
    pub fn root_gone(&self) -> bool {
        !prefix::is_same_or_inside(&self.nearest, &self.root.path)
    }
}

impl<'a> ScanCtx<'a> {
    /// Whether the uninstall was observed and the app is verified gone.
    pub fn verify_gone_passed(&self) -> bool {
        self.verify_gone.is_some_and(|v| v.is_passed())
    }

    /// The validated **InstallRoot** `path` is, or lies under; the deepest one when roots nest.
    /// Inferred roots and referenced data directories never qualify (§5.2 "Root kinds").
    pub fn inside_install_root(&self, path: &str) -> Option<&'a Root> {
        install_root_of(&self.fp.roots, path)
    }

    /// Whether `path` is a file of the app's exe set or one its installer declares outside the roots.
    pub fn is_app_file(&self, path: &str) -> bool {
        self.fp.exes.iter().any(|e| prefix::is_same(&e.path, path))
            || self
                .fp
                .outside_root_files
                .iter()
                .any(|f| prefix::is_same(&f.path, path))
    }

    /// Whether `path` is a file that outlived the uninstall without the installer's log naming it.
    ///
    /// The exe set is every program file found in the InstallRoots at harvest, so it also holds what
    /// the user or another product put there (a tool of their own in the app's folder). After an
    /// uninstall such a file is told apart by what happened to it: the uninstaller removed the app's
    /// files and left this one. A file that is still there (or whose state cannot be read) and that
    /// no file record of the log names is therefore not shown to be the app's, and a registration
    /// that leads to it (`App Paths\<name>`) is not shown to be the app's either. A logged file that
    /// survived (it was locked) stays the app's. Nothing is concluded when no uninstaller ran
    /// ([`ScanMode::Forced`]).
    pub fn survived_unproven(&self, path: &str) -> bool {
        if self.mode == ScanMode::Forced || self.fs.exists(path).is_absent() {
            return false;
        }
        !self.installer_logged_file(path)
    }

    /// Whether the harvest found `key` to be older than the install (`Fingerprint::older_keys`):
    /// somebody made it before the app was installed, so it is no skeleton of the app.
    pub fn predates_install(&self, key: &str) -> bool {
        self.fp.older_keys.iter().any(|k| self.same_key(k, key))
    }

    /// Whether a file record of the installer's log names `path` as a file the installer created
    /// (not one that existed before, not a shared one).
    pub fn installer_logged_file(&self, path: &str) -> bool {
        self.fp.inno.iter().any(|r| {
            r.kind == InnoRecordKind::DeleteFile
                && !r.existed_before
                && !r.shared
                && matches!(&r.target, Target::Path { path: p } if prefix::is_same(p, path))
        })
    }

    /// Whether `key` is, or lies in, the key of a COM registration (`…\CLSID\{id}`, `…\TypeLib\{id}`,
    /// `…\AppID\{id}`) that the fingerprint does not list among the app's own.
    ///
    /// The harvest takes such a registration for the app's only when it is the app's own
    /// (`purge-harvest` `anchors`: not in the baseline, not older than the install, for a class its
    /// server not shipped by another installed app). One it left out is somebody else's, or one the
    /// app only re-pointed at its own files: a value in it is a modification of that registration,
    /// not a leftover of the app, however plainly it names the app's files, and a subkey of it that
    /// held nothing but such a value is part of the other product's registration. The scanners offer
    /// nothing in such a key: no value, and no key either (REF-ANY's attributed keys,
    /// `ProvenOwnedSkeleton`).
    pub fn in_unowned_com_class(&self, key: &str) -> bool {
        com_registration_of(key).is_some_and(|(kind, id)| {
            let own = match kind {
                ComKind::Class => &self.fp.anchors.clsids,
                ComKind::TypeLib => &self.fp.anchors.typelibs,
                ComKind::AppId => &self.fp.anchors.appids,
            };
            !own.iter().any(|own| prefix::eq_ci(own, id))
        })
    }

    /// Whether the registration a value of `key` named `name` makes is the app's **own**: the installer
    /// recorded it, or it sits in a place that belongs to the app by what that place is. Only there is
    /// a reference to the app's files Tier A evidence (see the module documentation).
    ///
    /// The registration is the app's own when one of these holds:
    ///
    /// 1. **The installer's record** ([`ScanCtx::installer_recorded_value`]). The Inno log has a
    ///    record on exactly this value, or, with a baseline of this Windows, a delete-the-whole-key
    ///    record on exactly its key (records flagged as older than the install or as shared do not
    ///    count).
    /// 2. **The app's own COM registration, ProgID, AUMID, client registration or Uninstall key.** The
    ///    key is, or lies in, a `CLSID`/`TypeLib`/`AppID` key, a ProgID key of the Classes, a
    ///    `Classes\AppUserModelId\<id>` key, a `Software\Clients\<kind>\<registered name>` key or the
    ///    Uninstall key that the fingerprint lists as the app's (the harvest takes no id that predates
    ///    the install, that Windows ships or that another product shares).
    /// 3. **The `App Paths` or `Classes\Applications` key of one of the app's programs**:
    ///    `App Paths\<name>` and `Applications\<name>` where `<name>` is the file name of a file of the
    ///    exe set.
    /// 4. **The app's own settings key.** The first key below `Software` is a vendor alias of the app
    ///    (never for a mega-vendor, never `Microsoft`) or carries the app's full name, or the first two
    ///    are `<vendor>\<product>` of the app.
    ///
    /// Everything else is a shared place: another vendor's key, `Run`, `Environment`, a list of recent
    /// files. A value there may have been written by anyone, and it is the app's only when (1) says so.
    ///
    /// A store that Windows keeps as a ring or list of numbered slots (`…\CurrentVersion\UFH\SHC`,
    /// an MRU list) is a shared place too, although only Windows writes it: the value's name is a slot
    /// number, not the app's, Windows reuses a slot for the next program (on a machine with history
    /// the slot held another product's record before the install), and taking the value out leaves a
    /// hole in a structure Windows manages. What the slot holds now is the app's record; whose the
    /// slot is, nothing shows.
    ///
    /// M1b (C-PATHSTORES): in a path-keyed store (`SharedDLLs`, `MuiCache`, `UserAssist`, …,
    /// [`ScanCtx::path_keyed_store`]) the value is the app's registration only when its name, decoded
    /// as the store requires, is a full path inside an InstallRoot of the app or one of its exe paths
    /// ([`ScanCtx::path_from_value_name`]); nothing else above counts there.
    pub fn owns_registration(&self, key: &str, name: &str) -> bool {
        if let Some(store) = self.path_keyed_store(key) {
            return self.path_store_value_is_apps(store, name);
        }
        // 1. The installer's record.
        self.installer_recorded_value(key, name) || self.owns_place(key, true)
    }

    /// Whether `key` is the app's **own place** for what a value in it holds: the key belongs to
    /// the app by what it is (2 to 4 of [`ScanCtx::owns_registration`]), or the installer's log
    /// deletes exactly this key whole. A record on a value does not count here. It says that the
    /// installer wrote (to) the value, not what the value holds now, and not which entry of a
    /// list is the installer's: in another product's search path the app's entry stands next to
    /// entries of others.
    ///
    /// A structural value container is never the app's place by such a record.
    ///
    /// The settings key (4) counts only when it is named after the **product**
    /// (`Software\<product>`, `Software\<vendor>\<product>`), not anywhere below the vendor's key.
    /// `Software\Mozilla\Thunderbird\Paths` is a sibling product's key, and nothing protects it:
    /// another installed app is known to the scan by its Uninstall key, its roots and its
    /// anchors, not by its settings key, so a sibling's key reads like any other key below the
    /// vendor whether or not the sibling is in the inventory.
    ///
    /// Outside the own place the data of a value must be wholly the app's
    /// ([`ScanCtx::value_content_unproven`]).
    pub fn owns_list_entry(&self, key: &str) -> bool {
        // A key that only holds other parties' single values (`Run`, `Environment`,
        // `RegisteredApplications`) is nobody's place, whatever a log says about deleting it. So
        // is every key that starts programs at logon, whether or not a scanner reads it.
        (self.installer_recorded(key, None)
            && !purge_guard::containers::is_value_container(key, self.guard)
            && !is_start_place(key))
            || self.owns_place(key, false)
    }

    /// Reads one entry of a list value (an entry of `Path`, a string of a `REG_MULTI_SZ` list,
    /// one `;` part of a search path) with `prefix::ListEntry::read`, as written and expanded.
    /// Such an entry may be a file as well as a directory. It is the app's only when the path it
    /// is, taken whole, lies at or under an InstallRoot or is a file of the app: a reference
    /// somewhere inside other text (a token in somebody else's path, an argument of somebody
    /// else's command line) is none.
    pub fn entry_standing(&self, entry: &str) -> EntryStanding {
        let Some(read) = prefix::ListEntry::read(entry, self.env) else {
            return EntryStanding::NotOnePath;
        };
        if read.indirect {
            return EntryStanding::Unproven("the entry is a reference to another variable");
        }
        if read.ambiguous {
            return EntryStanding::Unproven(
                "the entry holds a comma or a second path start and may be two entries",
            );
        }
        let own = [read.bare, read.expanded.as_str()]
            .into_iter()
            .any(|path| self.inside_install_root(path).is_some() || self.is_app_file(path));
        if !own {
            return EntryStanding::Unproven("the entry is not a path of the app");
        }
        EntryStanding::Plain
    }

    /// **The one rule about what a value holds.** Why the data of the registry value (or the
    /// entry of one) that `target` names is not wholly the app's; `None` when it is, and for a
    /// target that is no value.
    ///
    /// Deleting a value deletes everything in it, and editing an entry out of a list takes the
    /// entry's whole text. Evidence says who the value refers to; it does not say that nothing
    /// else is in it. A search path another product keeps, a start entry, a list of recent files
    /// can hold the app's path **next to** somebody else's text (the product rewrote its list,
    /// the user edited the command), and the installer's record on the value says who made the
    /// value, not what it holds now. So, outside the app's own place
    /// ([`ScanCtx::owns_list_entry`]), the data must be the app's and nothing else:
    ///
    /// - **An entry of a list** (`RegMultiSzSegment`): the entry is exactly one path of the app
    ///   ([`ScanCtx::entry_standing`]) or exactly one of its ids.
    /// - **A whole value** (`RegValue`), by what the place is:
    ///   - a command line (a `Run`/`RunOnce` value, the value of a `command` key): the program
    ///     it starts is the app's. The first token, unquoted and expanded, is exactly one path of
    ///     the app and named like a program file (`prefix::is_program_file`); what follows are
    ///     that program's arguments. A launcher of Windows or of
    ///     somebody else in front (`cmd /c`, `powershell -File`, another tool with a file of
    ///     the app as an argument) makes the command somebody else's;
    ///   - a registration (`RegisteredApplications`): the data names one key below `Software`
    ///     and nothing else. Whose that key is, is the scanner's question (CLS-REGAPPS reads
    ///     the `Capabilities` key it names); the rule here is only that nothing stands next
    ///     to it;
    ///   - anything else is read as its entries: the strings of a `REG_MULTI_SZ` value, each
    ///     split at its `;` (`prefix::list_entries`). Every entry is exactly one path of the app
    ///     (an icon or resource reference `path,-101` / `@path,-101` is one path), exactly one
    ///     of its ids (a ProgID, CLSID, AUMID or harvested token; not a root or a file, which
    ///     must lie in an InstallRoot or be a file of the app to count as a path), or exactly one
    ///     registry key that is the app's own place (`Software\Clients\Mail\<name>\Capabilities`,
    ///     as a registration names it). One entry of anything else, and the value is not the
    ///     app's alone.
    ///
    ///   A number (`REG_DWORD`, `REG_QWORD`) and an empty string pass: there is nothing of
    ///   anybody's in them. Data of any other type that is no string (`REG_BINARY`, `REG_NONE`)
    ///   is read for its runs of UTF-16 text as the scanners read it; a run shaped like a path
    ///   (a drive path, a UNC path) must be exactly one path of the app, other runs are not
    ///   judged, and data too large to read does not pass. Text that was not read in full does
    ///   not pass, and neither does a string with text after its terminating NUL.
    /// - **In the app's own place** only a `;`-string of two or more entries is read (a list is
    ///   a list wherever it stands); a single string and a `REG_MULTI_SZ` value are the app's
    ///   with their key.
    /// - **A value named after the app** is the app's by its name, whatever it holds: the whole
    ///   value name is exactly one path at or under an InstallRoot or of a file of the app
    ///   (`…\MuiCache | <app>\x.exe.FriendlyAppName`; `<app>\x.exe user text` and
    ///   `<app>\x.exe;C:\tools` are not), or the name carries one of the app's ids as a delimited
    ///   part (`RegisteredApplications | <id>`, `<ProgID>_.ext`). **Not in a command place**:
    ///   there the value starts a program whatever it is called, and the command rule decides.
    ///
    /// The verdict depends on the target and on what the registry holds, never on the scanner
    /// that asks. It is applied twice, by [`CandidateBuilder::build`] to every candidate a
    /// scanner finishes and by [`ScanCtx::run`] to every candidate a scanner returns: all copies
    /// of one target that different scanners emit get the same cap, so the union the plan makes
    /// of them cannot bring Tier A back.
    pub fn value_content_unproven(&self, target: &Target) -> Option<&'static str> {
        self.content_unproven(target)
    }

    /// Runs `scanner` and returns what it found, **with the rule about what a value holds
    /// applied to every candidate** ([`ScanCtx::seal`]). The engine runs its scanners through
    /// this and nothing else, so no scanner can offer a value on Tier A evidence the rule
    /// refuses: not by building a candidate by hand, and not by adding evidence to one after
    /// [`CandidateBuilder::build`].
    ///
    /// It also records the scan-time identity of every path item ([`ScanCtx::record_item_fp`]).
    ///
    /// M1b (C-SCANEXT) adds, for every candidate of every scanner, M1a scanners included:
    ///
    /// - a candidate on a service, task or firewall rule without a well-formed `object_fp` of its
    ///   kind is dropped, and so is one whose object the system-object index does not hold with that
    ///   digest, and a candidate that carries `OwnedSystemObject` on a target that is not a system
    ///   object; each drop is a scanner fault ([`ScanExt::take_faults`]); the guard's object rules are
    ///   applied to every system object here, from the index ([`ScanCtx::object_guard`]);
    ///   `OwnedSystemObject` that no harvest record backs is lowered to Tier B
    ///   ([`ScanCtx::seal_object`]);
    /// - after the rule about what a value holds, the MSI blockers of the target
    ///   ([`ScanCtx::msi_blockers`]).
    ///
    /// The baseline trust cap is sealed here too: with a view of trust Merged or Local a key candidate
    /// whose evidence claims baseline absence without the `BaselineInferred` blocker is dropped as a
    /// scanner fault ([`ScanCtx::baseline_cap_missing`]).
    pub fn run(&self, scanner: &dyn Scanner, app: &AppIdentityView) -> Vec<Candidate> {
        self.ext.begin_site(scanner.id());
        let found = scanner.scan(self, app);
        self.ext.end_site();
        let mut sealed = Vec::with_capacity(found.len());
        // Compiled once per run, and only when a system object needs the guard's object rules.
        let deny = std::cell::OnceCell::new();
        for mut candidate in found {
            self.record_item_fp(&mut candidate);
            // A candidate of a co-removed product is judged as that product's: its paths and
            // ids are the product's, not the app's (`reg_software::common::for_each_app`).
            let owner = (candidate.owner != self.fp.app)
                .then(|| {
                    self.fp
                        .co_removed
                        .iter()
                        .filter(|product| product.app == candidate.owner)
                        .find_map(|product| product.fingerprint.as_deref())
                })
                .flatten();
            let ctx = match owner {
                Some(fp) => ScanCtx { fp, ..*self },
                None => *self,
            };
            if !ctx.seal_object(scanner.id(), &mut candidate, &deny) {
                continue;
            }
            ctx.seal(&mut candidate);
            // The trust cap (BASELINE_LOCAL_DESIGN.md §4.4 layer 2). Nothing reaches it today: no
            // scanner is handed an inferred absence (`framework/absence.rs`).
            if ctx.baseline_cap_missing(&candidate) {
                let line = format!(
                    "{}: dropped {:?}: its evidence rests on inferred baseline absence (trust {}) \
                     without the BaselineInferred cap",
                    scanner.id(),
                    candidate.target,
                    ctx.baseline.trust()
                );
                self.ext.fault(line.clone());
                debug_assert!(false, "{line}");
                continue;
            }
            for blocker in ctx.msi_blockers(&candidate.target) {
                if !candidate.blockers.contains(&blocker) {
                    candidate.blockers.push(blocker);
                }
            }
            sealed.push(candidate);
        }
        sealed
    }

    /// Records the identity a path item has now, as `Candidate::item_fp` (ENGINE_PLAN.md §5.10 G1:
    /// the executor's `FileIdInfo` must equal the scan's). The identity is the file id and volume serial
    /// of one [`FileSystemSource::metadata`] read, which opens the path itself and never follows a
    /// reparse point (a junction or link is identified as the link). Nothing is recorded for other
    /// targets, for a path that cannot be read, or when the source does not know both numbers (rig
    /// snapshots and fixtures without them), so such scans give the same documents as before.
    ///
    /// The cost is one handle open per path item (directory listings carry no file id); the items are
    /// a small fraction of the entries a scan reads.
    pub fn record_item_fp(&self, candidate: &mut Candidate) {
        let Target::Path { path } = &candidate.target else {
            return;
        };
        if let Ok(meta) = self.fs.metadata(path)
            && let (Some(file_id), Some(volume_serial)) = (meta.file_id, meta.volume_serial)
        {
            candidate.set_item_fp(FileIdHex(file_id.to_le_bytes()), volume_serial);
        }
    }

    /// Builds the residue of this scan (BASELINE_LOCAL_DESIGN.md §7): the candidates that carry
    /// [`Blocker::BaselineInferred`], plus every `Unknown` answer A sites gave (`answers` from
    /// [`ScanExt::take_unknown`]), each with why and a value-free shape.
    ///
    /// Items are unique by (scanner, case-folded key), sorted by that pair, and capped at
    /// [`MAX_RESIDUE_ITEMS`]; the rest is counted in [`ResidueDoc::omitted`]. A candidate's id and
    /// `item_fp` are kept; a key with no candidate gets the id its candidate would have
    /// ([`candidate_id`]) and an empty `item_fp`.
    #[must_use]
    pub fn residue_doc(
        &self,
        scan_id: &str,
        candidates: &[Candidate],
        answers: Vec<(String, String, ResidueWhy)>,
    ) -> ResidueDoc {
        use std::collections::btree_map::Entry;
        let mut items: BTreeMap<(String, String), ResidueItem> = BTreeMap::new();
        for candidate in candidates
            .iter()
            .filter(|c| c.blockers.contains(&Blocker::BaselineInferred))
        {
            let Some(key) = residue_key(&candidate.target) else {
                continue;
            };
            let folded = prefix::fold(key);
            if let Entry::Vacant(slot) = items.entry((candidate.scanner.clone(), folded)) {
                let shape = self.residue_shape(key);
                slot.insert(ResidueItem {
                    id: candidate.id.0.clone(),
                    item_fp: item_fp_text(candidate.item_fp.as_ref()),
                    key: key.to_owned(),
                    area: self.baseline.area_of(key).map(str::to_owned),
                    why: ResidueWhy::InferredAbsent,
                    site: candidate.scanner.clone(),
                    shape,
                });
            }
        }
        for (site, key, why) in answers {
            let folded = prefix::fold(&key);
            if let Entry::Vacant(slot) = items.entry((site.clone(), folded)) {
                let shape = self.residue_shape(&key);
                slot.insert(ResidueItem {
                    id: candidate_id(&Target::RegKey { path: key.clone() }).0,
                    item_fp: String::new(),
                    area: self.baseline.area_of(&key).map(str::to_owned),
                    key,
                    why,
                    site,
                    shape,
                });
            }
        }
        let total = items.len();
        let mut items: Vec<ResidueItem> = items.into_values().collect();
        items.truncate(MAX_RESIDUE_ITEMS);
        ResidueDoc {
            schema: ResidueSchema,
            scan_id: scan_id.to_owned(),
            baseline_view: ResidueBaselineView {
                name: self.baseline.name(),
                trust: self.baseline.trust(),
            },
            omitted: u32::try_from(total.saturating_sub(items.len())).unwrap_or(u32::MAX),
            items,
        }
    }

    /// What the scan could read about a residue key without its values: counts, owner, last-write time
    /// against the uninstall window, and the parent's and siblings' presence in the view. `in_local` and
    /// `in_neighbours` are `false` throughout: a set that held the key would have answered `Present`.
    fn residue_shape(&self, key: &str) -> ResidueShape {
        let info = self.reg.key_info(key).ok();
        let values = info.as_ref().map_or(0, |i| i.n_values);
        let subkeys = info.as_ref().map_or(0, |i| i.n_subkeys);
        let owner = match info.as_ref().and_then(|i| i.ti_owned) {
            Some(true) => ResidueOwner::Ti,
            Some(false) | None => ResidueOwner::Other,
        };
        let written = self.residue_written(info.as_ref().map(|i| i.lwt));
        let parent_in_view =
            prefix::parent(key).is_some_and(|parent| self.baseline.has_key(parent));
        let siblings_in_view = if subkeys == 0 {
            0
        } else {
            let base = key.trim_end_matches(prefix::SEP);
            self.reg
                .subkeys(key)
                .map(|names| {
                    names
                        .iter()
                        .filter(|name| self.baseline.has_key(&format!("{base}\\{name}")))
                        .count()
                })
                .unwrap_or(0)
                .try_into()
                .unwrap_or(u32::MAX)
        };
        ResidueShape {
            values,
            subkeys,
            owner,
            written,
            parent_in_view,
            siblings_in_view,
            siblings: subkeys,
            in_local: false,
            in_neighbours: vec![false; self.baseline.neighbour_names().len().min(MAX_NEIGHBOURS)],
        }
    }

    /// When `lwt` falls against the fingerprint's uninstall window.
    fn residue_written(&self, lwt: Option<FileTime>) -> ResidueWritten {
        let window = &self.fp.window;
        match (lwt, window.install_time, window.t_end) {
            (Some(when), Some(install), Some(end)) if when.0 != 0 => {
                if when < install {
                    ResidueWritten::BeforeInstall
                } else if when <= end {
                    ResidueWritten::InWindow
                } else {
                    ResidueWritten::AfterUninstall
                }
            }
            _ => ResidueWritten::Unknown,
        }
    }

    /// Applies [`ScanCtx::value_content_unproven`] to a candidate: when the data of its value
    /// is not wholly the app's, its positive Tier A evidence is lowered to Tier B and says why
    /// (`unproven`). Applying it twice changes nothing, given the context of the candidate's
    /// owner (the app, or the co-removed product the candidate belongs to).
    pub fn seal(&self, candidate: &mut Candidate) {
        let tier_a = |e: &Evidence| e.weight > 0 && e.tier == Tier::A;
        if !candidate.evidence.iter().any(tier_a) {
            return;
        }
        if let Some(why) = self.content_unproven(&candidate.target) {
            for e in candidate.evidence.iter_mut().filter(|e| tier_a(e)) {
                e.tier = Tier::B;
                e.detail = std::mem::take(&mut e.detail).with("unproven", why);
            }
        }
    }

    fn content_unproven(&self, target: &Target) -> Option<&'static str> {
        match target {
            Target::RegMultiSzSegment {
                path,
                name,
                segment,
                ..
            } => {
                if self.owns_list_entry(path) {
                    return None;
                }
                let why = self.entry_unproven(segment)?;
                (!self.named_after_app(name)).then_some(why)
            }
            Target::RegValue { path, name } => match self.reg.value(path, name) {
                Ok(data) => self.data_unproven(path, name, &data),
                // Nothing is there to delete; what is offered is a record of the harvest.
                Err(purge_source::types::SourceError::NotFound) => None,
                Err(_)
                    if self.owns_list_entry(path)
                        || (!is_command_place(path) && self.named_after_app(name)) =>
                {
                    None
                }
                Err(_) => Some("the value could not be read"),
            },
            _ => None,
        }
    }

    /// [`ScanCtx::value_content_unproven`] for data at hand: the value `name` of `key` holding
    /// `data` (the value as read, or as the harvest recorded it).
    pub fn data_unproven(&self, key: &str, name: &str, data: &RegData) -> Option<&'static str> {
        let own = self.owns_list_entry(key);
        let command = is_command_place(key);
        let (strings, string) = match data.string() {
            Some(text) => (vec![text], true),
            None => match data.multi_sz() {
                Some(strings) => (strings, false),
                None => (Vec::new(), false),
            },
        };
        let text_type = string || data.multi_sz().is_some();
        let why = if !data.is_complete() {
            (!own).then_some("the data was not read in full")
        } else if string && data.has_text_after_nul() {
            // `C:\App\bin` NUL `C:\Users\me\tools`: the string ends at the NUL and the data
            // does not.
            (!own).then_some("the data holds text after the end of its string")
        } else if !text_type {
            // Not a string type. A number holds no text. Anything else (`REG_BINARY`,
            // `REG_NONE`, an unknown type) is read for the text in it as the scanners read it
            // (`RegData::binary_utf16_strings`): a run of text that is shaped like a path must
            // be exactly one path of the app, like an entry of a list. Runs that are no path
            // (a switch, a counter, a timestamp) say nothing about anybody.
            // A number is four or eight bytes of its type; a "number" of any other length is
            // data like any other, whatever its type says.
            let number = data.dword().is_some() || data.qword().is_some();
            if number || own {
                None
            } else if data.bytes.len() > purge_source::types::BINARY_UTF16_SCAN_MAX {
                Some("the data is too large to be read for text")
            } else {
                binary_path_runs(data)
                    .iter()
                    .find_map(|run| self.entry_unproven(resource_path(run.trim())))
            }
        } else if string && !own && command {
            let whole = strings.first().map_or("", String::as_str);
            match program_of(whole) {
                None if whole.trim().is_empty() => None,
                None => Some("the command line names no program"),
                // A folder of the app in front (`"<app>\bin" "C:\tools"`) is no program: the
                // text is a list written like a command.
                Some(program) if !prefix::is_program_file(program) => {
                    Some("the command line does not start with a program file")
                }
                Some(program) => match self.entry_standing(program) {
                    EntryStanding::Plain => None,
                    _ => Some("the command starts a program that is not the app's"),
                },
            }
        } else if string && !own && is_registration_place(key) {
            let whole = strings.first().map_or("", String::as_str);
            (!is_software_key_path(whole))
                .then_some("the registration does not name one key below Software")
        } else {
            let parts: Vec<&str> = strings
                .iter()
                .flat_map(|text| prefix::list_entries(text))
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .collect();
            let list = string && parts.len() >= 2;
            if own && !list {
                None
            } else {
                parts
                    .into_iter()
                    .find_map(|part| self.entry_unproven(resource_path(part)))
            }
        };
        let why = why?;
        // In a command place the name decides nothing: the value starts a program, and which
        // one is in the data.
        (command || !self.named_after_app(name)).then_some(why)
    }

    /// Why `entry` is neither exactly one path of the app nor exactly one of its ids.
    fn entry_unproven(&self, entry: &str) -> Option<&'static str> {
        let why = match self.entry_standing(entry) {
            EntryStanding::Plain => return None,
            EntryStanding::NotOnePath => "the data holds more than one path of the app",
            EntryStanding::Unproven(why) => why,
        };
        // Exactly one registry key of the app, as registrations name one
        // (`RegisteredApplications | <name> = Software\Clients\Mail\<name>\Capabilities`).
        if self.names_own_key(entry) {
            return None;
        }
        // Exactly an id of the app. A root or a file that is an anchor is judged as the path
        // it is, above: a referenced data directory is an anchor and not the app's alone.
        let id = self.app_refs().find_all(entry).iter().any(|m| {
            m.how == MatchHow::Whole && !matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
        });
        (!id).then_some(why)
    }

    /// Whether `entry` is the path of a key below `Software` (as values spell it, without a hive)
    /// that is the app's own place in the machine's hive or in a scanned user's.
    fn names_own_key(&self, entry: &str) -> bool {
        let entry = entry.trim().trim_end_matches(prefix::SEP);
        if !is_software_key_path(entry) {
            return false;
        }
        let mut hives = vec!["HKLM".to_owned()];
        hives.extend(
            [
                Some(self.fp.user_sid.as_str()),
                self.fp.app.program_id.hive_sid(),
            ]
            .into_iter()
            .flatten()
            .map(|sid| format!(r"HKU\{}", sid.trim())),
        );
        hives
            .iter()
            .any(|hive| self.owns_place(&format!(r"{hive}\{entry}"), false))
    }

    /// Whether a value name is the app's: a path of the app or one of its ids and nothing else
    /// around it, or a name that carries an id of the app as a delimited part.
    fn named_after_app(&self, name: &str) -> bool {
        if name.trim().is_empty() {
            return false;
        }
        // The whole name is one path of the app (`<app>\x.exe`, `<app>\x.exe.FriendlyAppName`):
        // nothing after it, no second path.
        if self.entry_standing(name) == EntryStanding::Plain {
            return true;
        }
        // An id of the app with at most something attached to it (`<ProgID>_.ext`, `<hash>`): the
        // matcher finds an id only at a boundary that fits its kind, never inside a word. A
        // sentence or a path that has the id somewhere in it (`my <hash> thing`,
        // `C:\tools\<hash>\notes.txt`) is somebody's text, not the app's name.
        is_id_shaped(name)
            && self.app_refs().find_all(name).iter().any(|m| {
                !m.name_only && !matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
            })
    }

    /// The app's anchors as a matcher, for the content rule. Built on demand: the rule needs it
    /// only for a value whose data is not plainly a path of the app.
    fn app_refs(&self) -> RefMatcher {
        RefMatcher::with_env(&AnchorSet::from_fingerprint(self.fp), self.env.iter())
    }

    /// 2 to 4 of [`ScanCtx::owns_registration`]: the key belongs to the app by what it is.
    /// `vendor_wide`: a key anywhere below a vendor alias of the app counts for (4); without it
    /// only a key named after the product does.
    fn owns_place(&self, key: &str, vendor_wide: bool) -> bool {
        let fp = self.fp;
        // 2. The app's own COM registration, ProgID or Uninstall key.
        if com_registration_of(key).is_some() {
            return !self.in_unowned_com_class(key);
        }
        // A program of that name that the uninstaller left behind without the log naming it is
        // not shown to be the app's (`survived_unproven`).
        let own_program = |exe: &str| {
            fp.exes
                .iter()
                .map(|e| e.path.as_str())
                .chain(fp.outside_root_files.iter().map(|f| f.path.as_str()))
                .any(|path| {
                    prefix::leaf(path).is_some_and(|leaf| prefix::eq_ci(leaf, exe))
                        && !self.survived_unproven(path)
                })
        };
        let own_aumid = |id: &str| fp.anchors.aumids.iter().any(|a| prefix::eq_ci(a, id));
        if let Some(below) = below_classes(key) {
            let Some(class) = below.first() else {
                return false;
            };
            if prefix::eq_ci(class, "AppUserModelId") {
                return below.get(1).is_some_and(|id| own_aumid(id));
            }
            if prefix::eq_ci(class, "Applications") {
                return below.get(1).is_some_and(|exe| own_program(exe));
            }
            return fp.anchors.progids.iter().any(|p| prefix::eq_ci(p, class));
        }
        if matches!(
            self.key_relation(key, &fp.app.program_id.key_path()),
            Relation::Same | Relation::Inside
        ) {
            return true;
        }
        let Some(below) = below_software(key) else {
            return false;
        };
        let is = |i: usize, want: &str| below.get(i).is_some_and(|s| prefix::eq_ci(s, want));
        if is(0, "Microsoft") {
            let current_version = is(1, "Windows") && is(2, "CurrentVersion");
            // 3. `App Paths\<name of one of the app's programs>`.
            if current_version && is(3, "App Paths") {
                return below.get(4).is_some_and(|exe| own_program(exe));
            }
            // Everything else under `Microsoft` is Windows' or another Microsoft product's, the
            // numbered-slot stores Windows keeps about programs (`UFH\SHC`) included.
            return false;
        }
        // `Clients\<kind>\<the name the app is registered under>`: the app's full name, one of its
        // ids, or a name that carries one of its harvested tokens (`Firefox-<hash>`).
        if is(0, "Clients") {
            let identity = AppIdentity::from_snapshot(&fp.identity);
            return below.get(2).is_some_and(|name| {
                own_aumid(name)
                    || identity.matches_full_name(name).is_some()
                    || fp.tokens.iter().any(|t| {
                        contains_delimited(name, &t.token)
                            && self
                                .other_apps
                                .claimant(AnchorKind::Token, &t.token)
                                .is_none()
                            && !self.baseline.has_token(&t.token)
                    })
            });
        }
        if is(0, "RegisteredApplications") || is(0, "Policies") {
            return false;
        }
        // 4. The app's own settings key.
        let identity = AppIdentity::from_snapshot(&fp.identity);
        let Some(first) = below.first() else {
            return false;
        };
        (vendor_wide && !identity.mega_vendor() && identity.matches_vendor(first).is_some())
            || identity.matches_full_name(first).is_some()
            || below
                .get(1)
                .is_some_and(|second| identity.matches_product_subfolder(first, second).is_some())
    }

    /// Whether the installer's log covers the value `name` of `key`: it has a record on exactly this
    /// value, or a delete-the-whole-key record on exactly this key and a baseline of this Windows is
    /// at hand. Records flagged `existed_before` or `shared` do not count.
    ///
    /// The key record is read narrowly on purpose, and the same way everywhere it is asked:
    ///
    /// - **Only "delete the whole key".** `RegDeleteKeyIfEmpty` also carries `key_create`, but it is
    ///   what installers put on shared keys they merely add to, and says nothing about the values.
    /// - **Only the key itself, not a key above it.** The record says the uninstaller takes the key
    ///   with everything below; it does not say the installer made what is below. A subkey somebody
    ///   added later (a verb of the user's under the app's menu entry) is not the installer's, and a
    ///   record far up (`…\Classes\<name>`) would otherwise vouch for every value under it.
    /// - **Only with a baseline that does not have the key.** Installers put this record on keys
    ///   they share as well (`.sh`, a vendor key). A key of the baseline is Windows' own, and a
    ///   value in it is not the installer's because the installer would delete the key; without a
    ///   baseline the record is a strong hint and no proof, exactly as for the key itself
    ///   ([`CandidateBuilder::installer_manifest`]).
    pub fn installer_recorded_value(&self, key: &str, name: &str) -> bool {
        self.installer_recorded(key, Some(name))
    }

    /// [`ScanCtx::installer_recorded_value`]; without a `name` only the record on the key counts.
    fn installer_recorded(&self, key: &str, name: Option<&str>) -> bool {
        self.fp
            .inno
            .iter()
            .filter(|r| !r.existed_before && !r.shared)
            .any(|r| match &r.target {
                Target::RegValue { path, name: n } => {
                    name.is_some_and(|name| self.same_key(path, key) && prefix::eq_ci(n, name))
                }
                Target::RegKey { path } => {
                    self.key_record_covers(key)
                        && r.key_create
                        && r.kind == InnoRecordKind::RegDeleteEntireKey
                        && self.same_key(path, key)
                }
                _ => false,
            })
    }

    /// **A.** Whether a delete-the-whole-key record on `key` vouches for the values in it as far as
    /// the baseline goes: a baseline whose absence is proof is at hand ([`ScanCtx::has_exact_baseline`])
    /// and it does not have the key inside the scope it captures. Outside that scope the baseline
    /// cannot object, as before the view. Below Exact: never (values-only work).
    fn key_record_covers(&self, key: &str) -> bool {
        match self.key_absence(key) {
            Absence::Proven => true,
            Absence::Present | Absence::Unknown => {
                self.has_exact_baseline() && !Baseline::key_in_scope(key)
            }
            Absence::Inferred(_) => false,
        }
    }

    /// The canonical spelling of `key` when it is a 32-bit-view spelling of a key of the machine's
    /// Classes that both views share, and the source confirms that the two spellings are one key.
    ///
    /// `HKLM\SOFTWARE\Classes` is shared between the 64-bit and the 32-bit view ("Registry Keys Affected
    /// by WOW64"); only a few of its subkeys are redirected and exist a second time under
    /// `Classes\WOW6432Node` ([`CLASSES_REDIRECTED`]). `HKLM\SOFTWARE\WOW6432Node\Classes` is a link to
    /// `HKLM\SOFTWARE\Classes\WOW6432Node`, and below it Windows resolves every name that is not
    /// redirected to the shared key: `…\WOW6432Node\Classes\.txt` opens `…\Classes\.txt`. Such a path
    /// is a second name of the same key, not a second key, and an item on it duplicates the item on
    /// the canonical path.
    ///
    /// The rule above is not trusted alone (older Windows versions reflected instead of sharing): the
    /// spelling is folded only when both keys can be read now and agree in last-write time and in
    /// their value and subkey counts. `None` for every other key.
    pub fn shared_classes_alias(&self, key: &str) -> Option<String> {
        let canonical = classes_alias_target(key)?;
        let info = |k: &str| self.reg.key_info(k).ok().filter(|i| !i.is_link);
        let (alias, shared) = (info(key)?, info(&canonical)?);
        (alias.lwt.0 != 0
            && alias.lwt == shared.lwt
            && alias.n_values == shared.n_values
            && alias.n_subkeys == shared.n_subkeys)
            .then_some(canonical)
    }

    /// The full `DanglingRef` rule (§5.3) for a path under one of the fingerprint's InstallRoots.
    /// See [`ScanCtx::dangling_in`].
    pub fn dangling(&self, path: &str) -> Option<Dangling<'a>> {
        self.dangling_in(path, &self.fp.roots)
    }

    /// The full `DanglingRef` rule (§5.3) against `roots` (e.g. those of a co-removed product). `Some`
    /// only when all of these hold:
    ///
    /// 1. `path` is, or lies under, an InstallRoot whose volume serial was recorded at harvest and whose
    ///    parent directory existed then;
    /// 2. the source proves the path absent ([`ExistsState::Absent`]: not found, never "access denied",
    ///    "not captured" or a reparse point on the way);
    /// 3. the volume is a fixed NTFS or ReFS volume and its serial equals the recorded one;
    /// 4. the nearest existing ancestor of the path is exactly the root's recorded parent: the whole root
    ///    is gone and nothing above it is. Anything higher up means more than the app's own tree is
    ///    missing (a moved library, a different disk under the same letter). Anything lower means the
    ///    root still exists: the app may still be (partly) installed and a file that is missing inside it
    ///    (an optional component, an update in progress) proves nothing; such a reference is left to
    ///    `PointsIntoInstallRoot`. An ancestor whose state is unknown ends the check.
    pub fn dangling_in(&self, path: &str, roots: &'a [Root]) -> Option<Dangling<'a>> {
        let root = install_root_of(roots, path)?;
        let recorded = root.volume_serial?;
        if !root.parent_existed {
            return None;
        }
        let parent = prefix::parent(&root.path)?;
        if !self.fs.exists(path).is_absent() {
            return None;
        }
        let mut nearest = None;
        for ancestor in prefix::ancestors(path) {
            match self.fs.exists(ancestor) {
                ExistsState::Present => {
                    nearest = Some(ancestor);
                    break;
                }
                ExistsState::Absent => {}
                ExistsState::Unknown => return None,
            }
        }
        let nearest = nearest?;
        if !prefix::is_same(nearest, parent) {
            return None;
        }
        let volume = self.fs.volume_info(nearest).ok()?;
        if !volume.proves_absence() || volume.serial != Some(recorded) {
            return None;
        }
        Some(Dangling {
            root,
            path: path.to_owned(),
            serial: recorded,
            nearest: nearest.to_owned(),
        })
    }

    /// **P.** Whether Windows itself has the target (key, value, file or directory): some set of the
    /// baseline view has it, at any trust. `false` for a segment of a list value (the value itself is
    /// expected to exist), and, but for the one case below, when the view holds nothing.
    ///
    /// **A slot of a user's numbered-slot store** ([`USER_SLOT_STORES`]) is Windows' own whenever the
    /// scan has no exact baseline of this Windows ([`ScanCtx::has_exact_baseline`]), whatever the view
    /// holds. Its name is a number Windows chose, and which slots a profile had before the install
    /// only a capture of that Windows after its first logon shows; the local baseline has the default
    /// user's template and nothing a profile gets at its first logon or later, and a neighbour's
    /// slots are another machine's history. Unknown is taken as present, the safe side of a presence
    /// answer (L1): the slot is withheld or Blocked below Exact, as the exact view withholds or blocks
    /// the slots its capture holds (BL-GATE S1; DECISIONS 2026-11-22). The rule depends on no data of
    /// the view, so every view below Exact, and no view at all, answers alike (L5).
    pub fn in_baseline(&self, target: &Target) -> bool {
        let baseline = self.baseline;
        match target {
            Target::Path { path } => baseline.has_path(path),
            Target::RegKey { path } => baseline.has_key(path),
            Target::RegValue { path, name } => {
                baseline.has_value(path, name)
                    || (is_user_slot_store(path) && !self.has_exact_baseline())
            }
            _ => false,
        }
    }

    /// A key folded for comparison, with the current `ControlSet00N` spelled `CurrentControlSet`:
    /// the definition of [`ScanCtx::same_key`] (the folded keys are equal) and of
    /// [`ScanCtx::key_relation`] (`prefix::relation` of the folded keys). Both compare two keys
    /// segment by segment instead of building the two strings; the tests hold them to this.
    fn key_norm(&self, key: &str) -> String {
        let current = self.guard.control_set_name();
        let mut out = String::with_capacity(key.len());
        for (i, seg) in prefix::segments(key).enumerate() {
            if i > 0 {
                out.push(prefix::SEP);
            }
            let is_current_set = i == 2
                && out == r"hklm\system\"
                && current
                    .as_deref()
                    .is_some_and(|name| prefix::eq_ci(name, seg));
            if is_current_set {
                out.push_str("currentcontrolset");
            } else {
                out.push_str(&prefix::fold(seg));
            }
        }
        out
    }

    /// Whether two canonical key paths name the same key.
    pub fn same_key(&self, a: &str, b: &str) -> bool {
        self.key_compare(a, b, false) == Relation::Same
    }

    /// How key `a` relates to key `b`, with the control-set alias applied.
    pub fn key_relation(&self, a: &str, b: &str) -> Relation {
        self.key_compare(a, b, true)
    }

    /// The relation of two keys as their folded forms have it, where the current `ControlSet00N` as
    /// the third segment of `HKLM\SYSTEM` counts as `CurrentControlSet`. The keys are compared as
    /// they are walked, without folding either into a string: a scan asks this for every candidate
    /// against every record of the fingerprint, and most pairs differ in one of their first
    /// segments.
    ///
    /// Two segments are equal when their folds are ([`prefix::eq_ci`]). With `refold` they are
    /// equal when `prefix::eq_ci` calls their folds equal, which is how `prefix::relation` reads
    /// two folded keys; for ASCII segments the two are the same test.
    fn key_compare(&self, a: &str, b: &str, refold: bool) -> Relation {
        const CURRENT: &str = "CurrentControlSet";
        let eq = |x: &str, y: &str| {
            if !refold || (x.is_ascii() && y.is_ascii()) {
                prefix::eq_ci(x, y)
            } else {
                prefix::eq_ci(&prefix::fold(x), &prefix::fold(y))
            }
        };
        // Whether `seg`, the third segment of a key below `HKLM\SYSTEM`, names the current control
        // set.
        let is_current_set = |seg: &str| {
            self.guard
                .control_set_name()
                .as_deref()
                .is_some_and(|name| prefix::eq_ci(name, seg))
        };
        let mut left = prefix::segments(a);
        let mut right = prefix::segments(b);
        // Whether the segments so far spell `HKLM\SYSTEM`, on each side.
        let (mut a_system, mut b_system) = (true, true);
        let mut index = 0usize;
        loop {
            match (left.next(), right.next()) {
                (None, None) => return Relation::Same,
                (None, Some(_)) => return Relation::Ancestor,
                (Some(_), None) => return Relation::Inside,
                (Some(x), Some(y)) => {
                    let same = if index == 2 && (a_system || b_system) {
                        match (a_system && is_current_set(x), b_system && is_current_set(y)) {
                            (true, true) => true,
                            (true, false) => eq(CURRENT, y),
                            (false, true) => eq(x, CURRENT),
                            (false, false) => eq(x, y),
                        }
                    } else {
                        eq(x, y)
                    };
                    if !same {
                        return Relation::Unrelated;
                    }
                    if index < 2 {
                        let want = ["HKLM", "SYSTEM"][index];
                        a_system &= prefix::eq_ci(x, want);
                        b_system &= prefix::eq_ci(y, want);
                    }
                    index += 1;
                }
            }
        }
    }

    /// Whether two targets name the same item. A segment's `index` is compared only when both have one.
    pub fn same_target(&self, a: &Target, b: &Target) -> bool {
        match (a, b) {
            (Target::Path { path: p }, Target::Path { path: q }) => prefix::is_same(p, q),
            (Target::RegKey { path: p }, Target::RegKey { path: q }) => self.same_key(p, q),
            (Target::RegValue { path: p, name: n }, Target::RegValue { path: q, name: m }) => {
                self.same_key(p, q) && prefix::eq_ci(n, m)
            }
            (
                Target::RegMultiSzSegment {
                    path: p,
                    name: n,
                    segment: s,
                    index: i,
                },
                Target::RegMultiSzSegment {
                    path: q,
                    name: m,
                    segment: t,
                    index: j,
                },
            ) => {
                self.same_key(p, q)
                    && prefix::eq_ci(n, m)
                    && prefix::eq_ci(
                        s.trim_end_matches(prefix::SEP),
                        t.trim_end_matches(prefix::SEP),
                    )
                    && (i.is_none() || j.is_none() || i == j)
            }
            (Target::AppxPackage { full_name: p }, Target::AppxPackage { full_name: q }) => {
                prefix::eq_ci(p, q)
            }
            _ => false,
        }
    }

    /// Starts a candidate of scanner `scanner` (its catalog id) on `target`.
    ///
    /// The id is a stable hash of the target ([`candidate_id`]), the owner is the fingerprint's app, the
    /// origin is `Scanner`, the harm is the default of (`category`, `action`) and the reversibility is
    /// `Full` (`None` for a package removal). Nothing else is set: the scanner adds evidence and blockers
    /// through the builder.
    pub fn candidate(
        &self,
        scanner: &str,
        target: Target,
        action: Action,
        category: Category,
    ) -> CandidateBuilder<'_> {
        let ctx: &ScanCtx<'_> = self;
        CandidateBuilder {
            ctx,
            inferred: None,
            candidate: Candidate {
                id: candidate_id(&target),
                target,
                action,
                owner: self.fp.app.clone(),
                origin: Origin::Scanner,
                scanner: scanner.to_owned(),
                category,
                evidence: Vec::new(),
                blockers: Vec::new(),
                harm: default_harm(category, action),
                reversibility: if action == Action::RemovePackage {
                    Reversibility::None
                } else {
                    Reversibility::Full
                },
                children: Vec::new(),
                size_bytes: None,
                child_count: None,
                decision: None,
                // Filled in by `ScanCtx::run` for path items, after the scanner is done.
                item_fp: None,
                object_fp: None,
                // Display-only details of services, tasks and firewall rules: the engine fills them
                // after the scanners (M3-ENGINE-OUT).
                display_name: None,
                owner_program: None,
            },
        }
    }
}

/// The numbered-slot stores Windows keeps in every user's hive, as keys below the hive's root
/// (`HKU\<sid>\…`). Windows names their values (slot numbers) and fills them from the profile's first
/// logon on: the exact baselines of both rig VMs hold `UFH\SHC` slot `0`, Clean-Pro's also `1` and
/// `2`. Whether a slot predates the install, only an exact baseline of this Windows tells
/// ([`ScanCtx::in_baseline`]).
pub const USER_SLOT_STORES: &[&str] = &[r"Software\Microsoft\Windows\CurrentVersion\UFH\SHC"];

/// Whether `key` is one of the [`USER_SLOT_STORES`] of a user hive (`HKU\<sid>\…`, not the user's
/// Classes hive, or `HKCU\…`).
pub fn is_user_slot_store(key: &str) -> bool {
    let mut segments = prefix::segments(key);
    let Some(hive) = segments.next() else {
        return false;
    };
    if prefix::eq_ci(hive, "HKU") {
        match segments.next() {
            Some(sid) if !sid.to_ascii_lowercase().ends_with("_classes") => {}
            _ => return false,
        }
    } else if !prefix::eq_ci(hive, "HKCU") {
        return false;
    }
    let rest: Vec<&str> = segments.collect();
    USER_SLOT_STORES.iter().any(|store| {
        let want: Vec<&str> = prefix::segments(store).collect();
        want.len() == rest.len() && want.iter().zip(&rest).all(|(a, b)| prefix::eq_ci(a, b))
    })
}

/// The segments of `key` below the `Software` key of the machine or of a user hive, in either view
/// (`HKLM\SOFTWARE\WOW6432Node\X\Y` gives `[X, Y]`). `None` for a key that is not below one, and for
/// the Classes (see [`below_classes`]).
fn below_software(key: &str) -> Option<Vec<&str>> {
    let mut segments = prefix::segments(key);
    let hive = segments.next()?;
    if prefix::eq_ci(hive, "HKU") {
        let sid = segments.next()?;
        if sid.to_ascii_lowercase().ends_with("_classes") {
            return None;
        }
    } else if !prefix::eq_ci(hive, "HKLM") {
        return None;
    }
    if !prefix::eq_ci(segments.next()?, "SOFTWARE") {
        return None;
    }
    let mut below: Vec<&str> = segments.collect();
    if below
        .first()
        .is_some_and(|s| prefix::eq_ci(s, "WOW6432Node"))
    {
        below.remove(0);
    }
    (!below.first().is_some_and(|s| prefix::eq_ci(s, "Classes"))).then_some(below)
}

/// The segments of `key` below a Classes root: `HKLM\SOFTWARE\Classes`, its 32-bit node in both
/// spellings, `HKU\<sid>_Classes` and `HKU\<sid>\Software\Classes`. `None` for any other key.
fn below_classes(key: &str) -> Option<Vec<&str>> {
    let mut segments = prefix::segments(key);
    let hive = segments.next()?;
    let mut rest: Vec<&str>;
    if prefix::eq_ci(hive, "HKU") {
        let sid = segments.next()?;
        rest = segments.collect();
        if !sid.to_ascii_lowercase().ends_with("_classes") {
            if !rest.first().is_some_and(|s| prefix::eq_ci(s, "SOFTWARE")) {
                return None;
            }
            rest.remove(0);
            if rest
                .first()
                .is_some_and(|s| prefix::eq_ci(s, "WOW6432Node"))
            {
                rest.remove(0);
            }
            if !rest.first().is_some_and(|s| prefix::eq_ci(s, "Classes")) {
                return None;
            }
            rest.remove(0);
        }
    } else if prefix::eq_ci(hive, "HKLM") {
        rest = segments.collect();
        if !rest.first().is_some_and(|s| prefix::eq_ci(s, "SOFTWARE")) {
            return None;
        }
        rest.remove(0);
        if rest
            .first()
            .is_some_and(|s| prefix::eq_ci(s, "WOW6432Node"))
        {
            rest.remove(0);
        }
        if !rest.first().is_some_and(|s| prefix::eq_ci(s, "Classes")) {
            return None;
        }
        rest.remove(0);
    } else {
        return None;
    }
    if rest
        .first()
        .is_some_and(|s| prefix::eq_ci(s, "WOW6432Node"))
    {
        rest.remove(0);
    }
    Some(rest)
}

/// How one entry of a list value stands as something of the app's ([`ScanCtx::entry_standing`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStanding {
    /// Not one plainly written path (`prefix::ListEntry::read`): more than the app's path may
    /// be in it.
    NotOnePath,
    /// One path, but not provably the app's entry: Tier B at most, with the reason.
    Unproven(&'static str),
    /// One path at or under an InstallRoot, or a file of the app, written out in the entry.
    Plain,
}

/// Whether the string values of `key` are command lines: a start place ([`is_start_place`]) or a
/// `command` key (a shell verb).
fn is_command_place(key: &str) -> bool {
    prefix::leaf(key).is_some_and(|leaf| prefix::eq_ci(leaf, "command")) || is_start_place(key)
}

/// Whether `key` holds the programs Windows starts at logon, in any hive and view:
/// `CurrentVersion\Run`, `RunOnce`, `RunServices`, `RunServicesOnce`, `Policies\Explorer\Run`,
/// and `CurrentVersion\RunOnceEx` with the keys below it, which hold its entries. Every party
/// writes its own value there, so the key is nobody's place.
fn is_start_place(key: &str) -> bool {
    let parts: Vec<&str> = prefix::segments(key).collect();
    let from_end = |n: usize| parts.len().checked_sub(n).map_or("", |i| parts[i]);
    let (leaf, above, third) = (from_end(1), from_end(2), from_end(3));
    (["Run", "RunOnce", "RunServices", "RunServicesOnce"]
        .iter()
        .any(|run| prefix::eq_ci(leaf, run))
        && prefix::eq_ci(above, "CurrentVersion"))
        || (prefix::eq_ci(leaf, "Run")
            && prefix::eq_ci(above, "Explorer")
            && prefix::eq_ci(third, "Policies"))
        || parts.windows(2).any(|pair| {
            prefix::eq_ci(pair[0], "CurrentVersion") && prefix::eq_ci(pair[1], "RunOnceEx")
        })
}

/// Whether a value name can be an id of the app with at most something attached to it
/// (`<ProgID>_.ext`, `<hash>`), as against a sentence or a path that has one in it: no blank, no
/// path separator, no drive colon, no variable, no list, quote or redirection character.
fn is_id_shaped(name: &str) -> bool {
    !name.trim().chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '\\' | '/' | ':' | ';' | ',' | '"' | '|' | '<' | '>' | '*' | '?' | '%'
            )
    })
}

/// The runs of text in binary data that may be paths: the UTF-16 runs the scanners read
/// (`RegData::binary_utf16_strings`) that are [`is_path_shaped`], and the runs of one byte per
/// character ([`ansi_runs`]) that hold a drive or UNC path.
fn binary_path_runs(data: &purge_source::types::RegData) -> Vec<String> {
    let mut runs: Vec<String> = data
        .binary_utf16_strings()
        .unwrap_or_default()
        .into_iter()
        .filter(|run| is_path_shaped(run))
        .collect();
    runs.extend(
        ansi_runs(&data.bytes)
            .into_iter()
            .filter(|run| holds_drive_or_unc_path(run)),
    );
    runs
}

/// Whether a run of UTF-16 text read from binary data is shaped like a path: it holds a
/// separator (`\`, `/`: a drive, UNC, rooted or relative path, with whatever stands before it)
/// or a variable (`%NAME%`).
fn is_path_shaped(run: &str) -> bool {
    run.contains(['\\', '/']) || run.matches('%').count() >= 2
}

/// Whether a run of 8-bit text holds a drive path (`X:\`, `X:/`) or a UNC start (`\\`). Bytes
/// that happen to be printable are everywhere in binary data (a timestamp's `\`), so a
/// separator alone says nothing here.
fn holds_drive_or_unc_path(run: &str) -> bool {
    run.contains("\\\\")
        || run
            .as_bytes()
            .windows(3)
            .any(|w| w[0].is_ascii_alphabetic() && w[1] == b':' && matches!(w[2], b'\\' | b'/'))
}

/// Text stored one byte per character in binary data: the runs of at least
/// [`purge_source::types::BINARY_UTF16_MIN_CHARS`] printable ASCII characters within the first
/// [`purge_source::types::BINARY_UTF16_SCAN_MAX`] bytes. UTF-16 text has a NUL in every second
/// byte and yields no run here.
fn ansi_runs(bytes: &[u8]) -> Vec<String> {
    let window = &bytes[..bytes.len().min(purge_source::types::BINARY_UTF16_SCAN_MAX)];
    window
        .split(|b| !(0x20..=0x7e).contains(b))
        .filter(|run| run.len() >= purge_source::types::BINARY_UTF16_MIN_CHARS)
        .map(|run| run.iter().map(|b| char::from(*b)).collect())
        .collect()
}

/// Whether the values of `key` are registrations that name a key: `RegisteredApplications`
/// directly below a `Software` key.
fn is_registration_place(key: &str) -> bool {
    let mut up = prefix::segments(key).rev();
    let (leaf, above) = (up.next().unwrap_or(""), up.next().unwrap_or(""));
    prefix::eq_ci(leaf, "RegisteredApplications")
        && (prefix::eq_ci(above, "SOFTWARE") || prefix::eq_ci(above, "WOW6432Node"))
}

/// Whether `text` is the path of one key below `Software`, written without a hive as
/// registrations write it (`Software\Clients\Mail\<name>\Capabilities`), and nothing else.
fn is_software_key_path(text: &str) -> bool {
    let text = text.trim();
    text.get(..9)
        .is_some_and(|head| head.eq_ignore_ascii_case(r"Software\"))
        && prefix::is_one_path(text)
        && !prefix::steps_back(text)
        && !text.contains(['%', ',', '/'])
        && text
            .split(prefix::SEP)
            .all(|segment| segment == segment.trim())
}

/// The program a command line starts, as written: what stands between the quotes when the
/// command starts with one; otherwise the text up to the first executable extension that ends a
/// word (so that `C:\Program Files\App\x.exe /s` keeps its blank), or up to the first blank.
/// `None` for an empty command and for a quote that is never closed.
fn program_of(command: &str) -> Option<&str> {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        let program = rest[..rest.find('"')?].trim();
        return (!program.is_empty()).then_some(program);
    }
    let lower = command.to_ascii_lowercase();
    let end = lower
        .match_indices('.')
        .filter_map(|(at, _)| {
            let end = [".exe", ".com", ".bat", ".cmd"]
                .iter()
                .find(|ext| lower[at..].starts_with(**ext))
                .map(|ext| at + ext.len())?;
            let ends_word = command[end..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || c == '"' || c == '/');
            (ends_word && command.is_char_boundary(end)).then_some(end)
        })
        .next()
        .or_else(|| command.find(char::is_whitespace))
        .unwrap_or(command.len());
    let program = command[..end].trim();
    (!program.is_empty()).then_some(program)
}

/// The path of an icon or resource reference (`C:\App\x.exe,0`, `@C:\App\x.dll,-101`); any other
/// text as it is.
fn resource_path(entry: &str) -> &str {
    let is_index = |index: &str| {
        let digits = index.strip_prefix('-').unwrap_or(index);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    };
    let text = entry.strip_prefix('@').unwrap_or(entry);
    match text.rsplit_once(',') {
        Some((path, index)) if is_index(index.trim()) => path.trim(),
        _ => entry,
    }
}

/// The deepest InstallRoot `path` is, or lies under. A path with a `..` segment lies under none:
/// the containment test compares segments and does not resolve it, so
/// `<root>\..\..\Users\me\tools` would pass for a path of the app.
fn install_root_of<'r>(roots: &'r [Root], path: &str) -> Option<&'r Root> {
    if prefix::steps_back(path) {
        return None;
    }
    roots
        .iter()
        .filter(|r| r.kind == RootKind::InstallRoot && prefix::is_same_or_inside(path, &r.path))
        .max_by_key(|r| prefix::depth(&r.path))
}

// ---------------------------------------------------------------------------------------------------------
// Trust, ids, harm
// ---------------------------------------------------------------------------------------------------------

/// The weaker of two trusts: `UserWritable` if either is.
pub fn weakest(a: SourceTrust, b: SourceTrust) -> SourceTrust {
    if a == SourceTrust::UserWritable || b == SourceTrust::UserWritable {
        SourceTrust::UserWritable
    } else {
        SourceTrust::AdminOnly
    }
}

/// Who could have written the app's own registration: `AdminOnly` for an `HKLM` ARP entry, `UserWritable`
/// for an `HKU` one. Evidence that rests on the app's anchors as a whole (names, ProgIDs, tokens) carries
/// this trust, so that under Rule T a per-user registration never attributes machine-scope targets at
/// Tier A.
pub fn app_trust(fp: &Fingerprint) -> SourceTrust {
    if fp.app.program_id.hive().is_machine() {
        SourceTrust::AdminOnly
    } else {
        SourceTrust::UserWritable
    }
}

/// The trust of the Inno Setup uninstall log: the weakest of the app's registration and of every root
/// read from the Inno record (the log lives in the app directory).
pub fn inno_trust(fp: &Fingerprint) -> SourceTrust {
    fp.roots
        .iter()
        .filter(|r| r.source == RootSource::InnoApp)
        .fold(app_trust(fp), |trust, root| weakest(trust, root.trust))
}

/// The trust of evidence that rests on one anchor: the trust of the root for a root or a file under one,
/// the app's own trust otherwise.
pub fn anchor_trust(fp: &Fingerprint, anchor: &AnchorRef) -> SourceTrust {
    let of_path = |path: &str| {
        fp.roots
            .iter()
            .filter(|r| prefix::is_same_or_inside(path, &r.path))
            .max_by_key(|r| prefix::depth(&r.path))
            .map(|r| r.trust)
    };
    match anchor.kind {
        AnchorKind::Root | AnchorKind::Exe => {
            of_path(&anchor.text).unwrap_or_else(|| app_trust(fp))
        }
        AnchorKind::ProgId | AnchorKind::Clsid | AnchorKind::Aumid | AnchorKind::Token => {
            app_trust(fp)
        }
    }
}

/// The registry key a residue item speaks about: a key, value or list segment target's key. `None` for
/// every other target (a residue is about registry keys).
fn residue_key(target: &Target) -> Option<&str> {
    match target {
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => Some(path),
        Target::Path { .. }
        | Target::Service { .. }
        | Target::Task { .. }
        | Target::FirewallRule { .. }
        | Target::AppxPackage { .. } => None,
    }
}

/// The id of the candidate for `target`: `c-` and the 64-bit FNV-1a hash (16 hex digits) of the target's
/// type and case-folded fields. Two scanners that find the same target produce the same id; `purge-plan`
/// merges them.
///
/// The hash is not collision resistant. A scan whose candidate set holds one id on two different targets
/// is not served: `purge-plan::decide::merge` drops every candidate of that id, and the pipeline reports
/// them (review M3-R1 M2).
pub fn candidate_id(target: &Target) -> CandidateId {
    let fold_path = |s: &str| prefix::fold(s.trim_end_matches(prefix::SEP));
    let parts: Vec<String> = match target {
        Target::Path { path } => vec!["path".into(), fold_path(path)],
        Target::RegKey { path } => vec!["key".into(), fold_path(path)],
        Target::RegValue { path, name } => {
            vec!["value".into(), fold_path(path), prefix::fold(name)]
        }
        Target::RegValueChanged { path, name, .. } => {
            vec!["changed".into(), fold_path(path), prefix::fold(name)]
        }
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => vec![
            "segment".into(),
            fold_path(path),
            prefix::fold(name),
            prefix::fold(segment),
            index.map(|i| i.to_string()).unwrap_or_default(),
        ],
        Target::Service { name } => vec!["service".into(), prefix::fold(name)],
        Target::Task { path } => vec!["task".into(), fold_path(path)],
        Target::FirewallRule { id } => vec!["firewall".into(), prefix::fold(id)],
        Target::AppxPackage { full_name } => vec!["package".into(), prefix::fold(full_name)],
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.join("\u{1f}").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    CandidateId(format!("c-{hash:016x}"))
}

/// The default harm of removing an item of `category` through `action` (§5.8.5).
///
/// This is the table of `purge_policy::harm::default_harm`, repeated here because `purge-scan` does not
/// depend on `purge-policy`; the two must stay equal.
pub fn default_harm(category: Category, action: Action) -> Harm {
    if action == Action::RemoveDirIfEmpty {
        return Harm::None;
    }
    match category {
        Category::System => Harm::Critical,
        Category::UserData => Harm::High,
        Category::AppData => Harm::Medium,
        Category::AppFiles
        | Category::Cache
        | Category::Registration
        | Category::Association
        | Category::ShellCom
        | Category::Startup
        | Category::Privacy
        | Category::Package => match action {
            Action::EditSegment | Action::RemovePackage => Harm::Medium,
            _ => Harm::Low,
        },
    }
}

// ---------------------------------------------------------------------------------------------------------
// The EmptyAfterPlan pending marker
// ---------------------------------------------------------------------------------------------------------

/// Detail key of the marker that asks `purge-plan` for the emptiness check of a vendor container. Equal
/// to `purge_plan::empty_after::PENDING_KEY`.
pub const PENDING_KEY: &str = "empty_after_plan";
/// Detail value of the pending marker. Equal to `purge_plan::empty_after::PENDING_VALUE`.
pub const PENDING_VALUE: &str = "pending";
/// Detail key of the child listing: a JSON array of names, `\`-terminated for subdirectories and subkeys.
/// Equal to `purge_plan::empty_after::CHILDREN_KEY`.
pub const CHILDREN_KEY: &str = "children";

/// One direct child of a container, as listed for the emptiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerChild<'a> {
    /// A file, or a value of a key (`""` is the default value).
    Leaf(&'a str),
    /// A subdirectory or subkey.
    Container(&'a str),
}

/// The listing as a JSON array of strings, in the form `purge-plan` reads.
fn children_json<'a>(children: impl IntoIterator<Item = ContainerChild<'a>>) -> String {
    let mut out = String::from("[");
    for (i, child) in children.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let (name, container) = match child {
            ContainerChild::Leaf(name) => (name, false),
            ContainerChild::Container(name) => (name, true),
        };
        out.push('"');
        for c in name.chars().chain(container.then_some(prefix::SEP)) {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

// ---------------------------------------------------------------------------------------------------------
// COM classes and the shared Classes key
// ---------------------------------------------------------------------------------------------------------

/// Whether `s` has the shape of a braced GUID (`{8-4-4-4-12}` hex digits).
fn is_braced_guid(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) else {
        return false;
    };
    let groups: Vec<&str> = inner.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The kinds of COM registration keyed by a GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComKind {
    /// `CLSID\{id}`.
    Class,
    /// `TypeLib\{id}`.
    TypeLib,
    /// `AppID\{id}`.
    AppId,
}

/// The COM registration a registry key belongs to: the kind and `{id}` of the first `CLSID\{id}`,
/// `TypeLib\{id}` or `AppID\{id}` pair of its path.
pub fn com_registration_of(key: &str) -> Option<(ComKind, &str)> {
    let mut segments = prefix::segments(key).peekable();
    while let Some(segment) = segments.next() {
        let kind = if prefix::eq_ci(segment, "CLSID") {
            ComKind::Class
        } else if prefix::eq_ci(segment, "TypeLib") {
            ComKind::TypeLib
        } else if prefix::eq_ci(segment, "AppID") {
            ComKind::AppId
        } else {
            continue;
        };
        if let Some(id) = segments.peek().copied().filter(|id| is_braced_guid(id)) {
            return Some((kind, id));
        }
    }
    None
}

/// The COM class a registry key belongs to: the `{id}` of its `CLSID\{id}` pair, when that is the
/// first COM registration its path names.
pub fn com_class_of(key: &str) -> Option<&str> {
    com_registration_of(key)
        .filter(|(kind, _)| *kind == ComKind::Class)
        .map(|(_, id)| id)
}

/// The subkeys of `HKLM\SOFTWARE\Classes` that WOW64 redirects: each exists once per view, the 32-bit
/// one under `Classes\WOW6432Node` (Microsoft, "Registry Keys Affected by WOW64"; the rig snapshots of
/// Windows 11 26100 show exactly these as real keys there, next to links for `AppID`, `PROTOCOLS` and
/// `TypeLib`). Everything else in Classes is one key for both views.
pub const CLASSES_REDIRECTED: [&str; 5] = [
    "CLSID",
    "DirectShow",
    "Interface",
    "Media Type",
    "MediaFoundation",
];

/// For a path through the 32-bit node of the machine's Classes (`HKLM\SOFTWARE\WOW6432Node\Classes\X\…`
/// or `HKLM\SOFTWARE\Classes\WOW6432Node\X\…`) whose `X` is not redirected: the path of the shared key,
/// `HKLM\SOFTWARE\Classes\X\…`. `None` for every other path, the 32-bit node itself included.
///
/// This is the naming rule only; [`ScanCtx::shared_classes_alias`] checks it against the source.
pub fn classes_alias_target(key: &str) -> Option<String> {
    let segments: Vec<&str> = prefix::segments(key).collect();
    let is = |i: usize, name: &str| segments.get(i).is_some_and(|s| prefix::eq_ci(s, name));
    if !(is(0, "HKLM") && is(1, "SOFTWARE")) {
        return None;
    }
    let through_node =
        (is(2, "WOW6432Node") && is(3, "Classes")) || (is(2, "Classes") && is(3, "WOW6432Node"));
    let first = segments.get(4)?;
    if !through_node
        || CLASSES_REDIRECTED.iter().any(|r| prefix::eq_ci(r, first))
        || prefix::eq_ci(first, "WOW6432Node")
    {
        return None;
    }
    Some(format!(
        r"HKLM\SOFTWARE\Classes\{}",
        segments[4..].join("\\")
    ))
}

// ---------------------------------------------------------------------------------------------------------
// Candidate builder
// ---------------------------------------------------------------------------------------------------------

/// Ticks of one day in `FILETIME` units.
const DAY_TICKS: u64 = 24 * 60 * 60 * 10_000_000;

/// Detail key that marks reference evidence lowered because the value is in a shared place. Equal to
/// `purge_policy::explain::SHARED_PLACE_KEY`.
pub const SHARED_PLACE_KEY: &str = "place";
/// Detail value of [`SHARED_PLACE_KEY`].
pub const SHARED_PLACE_VALUE: &str = "shared";

/// Builds one [`Candidate`]. Made by [`ScanCtx::candidate`].
///
/// Evidence constructors return whether the evidence was added; they add nothing when the row's condition
/// does not hold for this candidate's target. Blocker helpers and setters return the builder.
pub struct CandidateBuilder<'c> {
    ctx: &'c ScanCtx<'c>,
    candidate: Candidate,
    /// The weakest inferred trust handed to [`CandidateBuilder::absence`], if any.
    inferred: Option<BaselineTrust>,
}

impl CandidateBuilder<'_> {
    // ---- reading -----------------------------------------------------------------------------------------

    /// The candidate's target.
    pub fn target(&self) -> &Target {
        &self.candidate.target
    }

    /// The evidence added so far.
    pub fn evidence(&self) -> &[Evidence] {
        &self.candidate.evidence
    }

    /// Whether any positive evidence has been added.
    pub fn has_positive_evidence(&self) -> bool {
        self.candidate.evidence.iter().any(|e| e.weight > 0)
    }

    /// Whether any Tier A or Tier B evidence has been added: what a short-name match needs next to it
    /// (`IdentityMatch::needs_tier_ab_neighbour`, §5.4 step 8).
    pub fn has_tier_ab_evidence(&self) -> bool {
        self.candidate
            .evidence
            .iter()
            .any(|e| e.weight > 0 && matches!(e.tier, Tier::A | Tier::B))
    }

    fn scope(&self) -> Option<Scope> {
        Scope::of(&self.candidate.target)
    }

    /// The key of a registry target.
    fn key(&self) -> Option<&str> {
        match &self.candidate.target {
            Target::RegKey { path }
            | Target::RegValue { path, .. }
            | Target::RegValueChanged { path, .. }
            | Target::RegMultiSzSegment { path, .. } => Some(path),
            _ => None,
        }
    }

    fn path(&self) -> Option<&str> {
        match &self.candidate.target {
            Target::Path { path } => Some(path),
            _ => None,
        }
    }

    /// Whether the target is a registry value (or an entry of one) in a place that is not the app's
    /// own ([`ScanCtx::owns_registration`]): reference evidence on it is then no proof of ownership.
    fn in_shared_place(&self) -> bool {
        match &self.candidate.target {
            Target::RegValue { path, name }
            | Target::RegValueChanged { path, name, .. }
            | Target::RegMultiSzSegment { path, name, .. } => {
                !self.ctx.owns_registration(path, name)
            }
            _ => false,
        }
    }

    /// Adds reference evidence of `kind` ("the value points at the app"): with the table's tier where
    /// the registration is the app's own, lowered to Tier B in a shared place.
    fn push_reference(
        &mut self,
        kind: EvidenceKind,
        scope: Option<Scope>,
        trust: SourceTrust,
        source: String,
        detail: Facts,
    ) -> bool {
        let Some(mut evidence) = scope.and_then(|scope| Evidence::new(kind, scope, trust, source))
        else {
            return false;
        };
        let mut detail = detail;
        if self.in_shared_place() {
            evidence.tier = evidence.tier.at_most(Tier::B);
            detail = detail.with(SHARED_PLACE_KEY, SHARED_PLACE_VALUE);
        }
        self.push_evidence(evidence.with_detail(detail))
    }

    // ---- evidence ----------------------------------------------------------------------------------------

    fn push_evidence(&mut self, evidence: Evidence) -> bool {
        if !self.candidate.evidence.contains(&evidence) {
            self.candidate.evidence.push(evidence);
        }
        true
    }

    /// Adds evidence of `kind` with the table's tier and weight; refuses a scope the table does not allow.
    fn push(
        &mut self,
        kind: EvidenceKind,
        scope: Option<Scope>,
        trust: SourceTrust,
        source: String,
        detail: Facts,
    ) -> bool {
        let Some(evidence) = scope.and_then(|scope| Evidence::new(kind, scope, trust, source))
        else {
            return false;
        };
        self.push_evidence(evidence.with_detail(detail))
    }

    /// `InsideInstallRoot`: the target is a path at or under a validated InstallRoot of the fingerprint.
    pub fn inside_install_root(&mut self) -> bool {
        let Some(root) = self.path().and_then(|p| self.ctx.inside_install_root(p)) else {
            return false;
        };
        let detail = Facts::new().with("root", root.path.clone());
        self.push(
            EvidenceKind::InsideInstallRoot,
            Some(Scope::Path),
            root.trust,
            format!("root:{}", root.path),
            detail,
        )
    }

    /// `InstallerManifest(Inno)`: the fingerprint's Inno log has a record on exactly this target.
    ///
    /// A key-create record gives Key scope for that key; a value record gives Value scope for that value
    /// (or for a segment of it); a file or directory record gives Path scope for that path. A key
    /// record is Tier A only with a baseline of this Windows, Tier B without one. Records
    /// flagged `existed_before` or `shared` do not count: the item is not the app's alone. Neither do
    /// `IniDeleteEntry`, `IniDeleteSection` and `DecrementSharedCount` records: their target is the file
    /// the uninstaller edits or counts, which the installer need not own (`win.ini`).
    pub fn installer_manifest(&mut self) -> bool {
        let fp = self.ctx.fp;
        let Some((record, scope)) = fp
            .inno
            .iter()
            .filter(|r| !r.existed_before && !r.shared)
            .find_map(|r| self.record_scope(r).map(|scope| (r, scope)))
        else {
            return false;
        };
        let mut detail = Facts::new().with("record", format!("{:?}", record.kind));
        let Some(mut evidence) = Evidence::new(
            EvidenceKind::InstallerManifest(ManifestKind::Inno),
            scope,
            inno_trust(fp),
            "inno:log".to_owned(),
        ) else {
            return false;
        };
        // A key record says that the installer asked for the key to be deleted on uninstall, not
        // that it created the key: the log has no "existed before" flag for the registry, and scripts
        // do put such a record on keys they share (`.sh`, a vendor key). With a baseline of this
        // Windows the key is at least shown not to be Windows' own; without one nothing shows that,
        // and the work is values-only (§5.7.1 step 3): the record is then a strong hint, no proof.
        // A: only an Exact view is "a baseline of this Windows"; below it the record is the hint.
        if scope == Scope::Key && !self.ctx.has_exact_baseline() {
            evidence.tier = evidence.tier.at_most(Tier::B);
            detail = detail.with(BASELINE_FACT, BASELINE_FACT_NONE);
        }
        self.push_evidence(evidence.with_detail(detail))
    }

    /// The scope an Inno record proves for this candidate's target, if it speaks about it at all.
    fn record_scope(&self, record: &InnoRecord) -> Option<Scope> {
        let ctx = self.ctx;
        match (&record.target, &self.candidate.target) {
            (Target::RegKey { path: p }, Target::RegKey { path: q }) => {
                (record.key_create && ctx.same_key(p, q)).then_some(Scope::Key)
            }
            (Target::RegValue { path: p, name: n }, Target::RegValue { path: q, name: m })
            | (
                Target::RegValue { path: p, name: n },
                Target::RegMultiSzSegment {
                    path: q, name: m, ..
                },
            ) => (ctx.same_key(p, q) && prefix::eq_ci(n, m)).then_some(Scope::Value),
            // A record that edits an INI file or a shared-file count names the file it touches, not a
            // file the installer owns.
            (Target::Path { path: p }, Target::Path { path: q }) => (!matches!(
                record.kind,
                InnoRecordKind::IniDeleteEntry
                    | InnoRecordKind::IniDeleteSection
                    | InnoRecordKind::DecrementSharedCount
            ) && prefix::is_same(p, q))
            .then_some(Scope::Path),
            _ => None,
        }
    }

    /// The reference-snapshot entry for exactly this target, if the harvest recorded one.
    fn ref_snap_entry(&self) -> Option<&RefSnapEntry> {
        self.ctx
            .fp
            .ref_snapshot
            .iter()
            .find(|e| self.ctx.same_target(&e.target, &self.candidate.target))
    }

    /// `InPreUninstallRefSnapshot`: the harvest recorded exactly this value (or segment) referencing one
    /// of the app's anchors. A root anchor counts only when it is an InstallRoot (or lies in one); a
    /// reference to an inferred root or to a referenced data directory is refused. The scanner is responsible for re-reading the value when it matters that it
    /// still says the same.
    ///
    /// Tier A only where the registration is the app's own ([`ScanCtx::owns_registration`]); Tier B
    /// in a shared place.
    pub fn in_ref_snapshot(&mut self) -> bool {
        let fp = self.ctx.fp;
        let Some(entry) = self.ref_snap_entry() else {
            return false;
        };
        // An inferred root is Tier B only and a referenced data directory gives at most
        // `ReferencedByApp` (§5.2 "Root kinds"): a reference to one is no Tier A fact.
        if entry.anchor.kind == AnchorKind::Root
            && self.ctx.inside_install_root(&entry.anchor.text).is_none()
        {
            return false;
        }
        let trust = anchor_trust(fp, &entry.anchor);
        let mut detail = Facts::new().with("anchor", entry.anchor.text.clone());
        let source = match &entry.target {
            Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
                format!("refsnap:{path}|{name}")
            }
            _ => "refsnap".to_owned(),
        };
        // An id is a name, not a location: that a value mentioned the app's ProgID, CLSID, AUMID
        // or harvested token before the uninstall does not show who wrote the value (three interface keys of another
        // product name a proxy class the app re-pointed at its own DLL). Such an entry is a strong
        // hint only, unless the installer's own record covers the value or the key that holds it.
        let id_only = matches!(
            entry.anchor.kind,
            AnchorKind::ProgId | AnchorKind::Clsid | AnchorKind::Aumid | AnchorKind::Token
        ) && !self.manifest_covers_value();
        if id_only {
            detail = detail.with("anchor_kind", "id");
        }
        let Some(mut evidence) = Evidence::new(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            trust,
            source,
        ) else {
            return false;
        };
        if id_only {
            evidence.tier = evidence.tier.at_most(Tier::B);
        }
        // That the value pointed at the app's files before the uninstall does not show who wrote it.
        // (An id anchor is judged above: it names a registration of the app, not a location.)
        let path_anchor = matches!(entry.anchor.kind, AnchorKind::Root | AnchorKind::Exe);
        if path_anchor && self.in_shared_place() {
            evidence.tier = evidence.tier.at_most(Tier::B);
            detail = detail.with(SHARED_PLACE_KEY, SHARED_PLACE_VALUE);
        }
        self.push_evidence(evidence.with_detail(detail))
    }

    /// Whether the installer's log covers this candidate's value
    /// ([`ScanCtx::installer_recorded_value`]): the corroboration an id-anchored snapshot entry
    /// needs for Tier A.
    fn manifest_covers_value(&self) -> bool {
        match &self.candidate.target {
            Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
                self.ctx.installer_recorded_value(path, name)
            }
            _ => false,
        }
    }

    /// `ProvenOwnedSkeleton`: the target is a key that [`skeleton::proven_owned_skeleton`] accepts.
    pub fn proven_owned_skeleton(&mut self) -> bool {
        let Target::RegKey { path } = &self.candidate.target else {
            return false;
        };
        match skeleton::proven_owned_skeleton(self.ctx, path) {
            Some(evidence) => self.push_evidence(evidence),
            None => false,
        }
    }

    /// `DanglingRef`: the value (or segment) points at `dangling`, which [`ScanCtx::dangling`] proved
    /// missing. Value scope only. Tier B in a shared place ([`ScanCtx::owns_registration`]).
    pub fn dangling_ref(&mut self, dangling: &Dangling<'_>) -> bool {
        let detail = Facts::new()
            .with("root", dangling.root.path.clone())
            .with("path", dangling.path.clone());
        self.push_reference(
            EvidenceKind::DanglingRef,
            self.scope(),
            dangling.root.trust,
            format!("dangling:{}", dangling.path),
            detail,
        )
    }

    /// `PointsIntoInstallRoot`: the value's data or name resolves to `referenced`, which is at or under
    /// an InstallRoot or is a file of the exe set. Value scope only. The scanner resolves the reference
    /// (expansion, quotes, arguments); this checks where it lands. Tier B in a shared place
    /// ([`ScanCtx::owns_registration`]).
    pub fn points_into_install_root(&mut self, referenced: &str) -> bool {
        let fp = self.ctx.fp;
        let (trust, root) = match self.ctx.inside_install_root(referenced) {
            Some(root) => (root.trust, Some(root.path.clone())),
            None if self.ctx.is_app_file(referenced) => (
                anchor_trust(
                    fp,
                    &AnchorRef {
                        kind: AnchorKind::Exe,
                        text: referenced.to_owned(),
                    },
                ),
                None,
            ),
            None => return false,
        };
        let mut detail = Facts::new().with("path", referenced);
        if let Some(root) = root {
            detail = detail.with("root", root);
        }
        self.push_reference(
            EvidenceKind::PointsIntoInstallRoot,
            self.scope(),
            trust,
            format!("points:{referenced}"),
            detail,
        )
    }

    /// `HarvestedToken`: `token` is one of the fingerprint's tokens and occurs as a delimited part of the
    /// target's own name (the last segment of a path or key, the name of a value, the text of a segment),
    /// no other app has it as an anchor, and the baseline (when there is one) does not know it. Without a
    /// baseline a key target gets no token evidence (values-only work, §5.7.1 step 3).
    pub fn harvested_token(&mut self, token: &str) -> bool {
        let ctx = self.ctx;
        let Some(harvested) = ctx
            .fp
            .tokens
            .iter()
            .find(|t| prefix::eq_ci(&t.token, token))
        else {
            return false;
        };
        let own_name = match &self.candidate.target {
            Target::Path { path } | Target::RegKey { path } => prefix::leaf(path),
            Target::RegValue { name, .. } => Some(name.as_str()),
            Target::RegMultiSzSegment { segment, .. } => Some(segment.as_str()),
            _ => None,
        };
        if !own_name.is_some_and(|name| contains_delimited(name, token))
            || ctx.other_apps.claimant(AnchorKind::Token, token).is_some()
            || ctx.baseline.has_token(token)
        {
            return false;
        }
        // A: without a baseline whose absence is proof (an Exact view) "absent from the baseline" is
        // unchecked, and no key is proven not to be Windows' own (§5.7.1 step 3: values only).
        if !ctx.has_exact_baseline() && matches!(self.candidate.target, Target::RegKey { .. }) {
            return false;
        }
        let detail = Facts::new().with("token", harvested.token.clone());
        self.push(
            EvidenceKind::HarvestedToken,
            self.scope(),
            app_trust(ctx.fp),
            format!("token:{}", harvested.source.0),
            detail,
        )
    }

    /// `AppNamedKeyWithRootRef`: the target is a key holding a value that points to `value_path`, which is
    /// at or under an InstallRoot. The other conditions of the row (token match, depth, no foreign
    /// reference, not older than the install) are the scanner's to establish before calling.
    pub fn app_named_key_with_root_ref(&mut self, value_path: &str) -> bool {
        let Some(root) = self.ctx.inside_install_root(value_path) else {
            return false;
        };
        let Some(key) = self.key().map(str::to_owned) else {
            return false;
        };
        let detail = Facts::new()
            .with("root", root.path.clone())
            .with("path", value_path);
        self.push(
            EvidenceKind::AppNamedKeyWithRootRef,
            self.scope(),
            root.trust,
            format!("software-key:{key}"),
            detail,
        )
    }

    /// `UninstallerArtifact`: the target is the app's own ARP key or one of its uninstaller's files.
    /// `what` names the record it was recognised by (e.g. `UninstallString`) for the explanation.
    pub fn uninstaller_artifact(&mut self, what: &str) -> bool {
        let trust = match self.path().and_then(|p| self.ctx.inside_install_root(p)) {
            Some(root) => weakest(root.trust, app_trust(self.ctx.fp)),
            None => app_trust(self.ctx.fp),
        };
        self.push(
            EvidenceKind::UninstallerArtifact,
            self.scope(),
            trust,
            format!("arp:{what}"),
            Facts::new().with("anchor", what),
        )
    }

    /// Lowers the positive evidence gathered so far to Tier B at most and notes why (`unproven`).
    /// For a target that is the app's by its place and its name only, where neither is the app's
    /// alone: it stays listed and can never be preselected on that evidence.
    pub fn cap_at_tier_b(&mut self, why: &str) -> &mut Self {
        for e in &mut self.candidate.evidence {
            if e.weight > 0 && e.tier == Tier::A {
                e.tier = Tier::B;
                e.detail = std::mem::take(&mut e.detail).with("unproven", why);
            }
        }
        self
    }

    /// `AppxExternalLocation`: the target is a package whose full name or family the harvest linked to
    /// the app.
    pub fn appx_external_location(&mut self) -> bool {
        let Target::AppxPackage { full_name } = &self.candidate.target else {
            return false;
        };
        let anchors = &self.ctx.fp.anchors;
        let by_full_name = anchors
            .package_full_names
            .iter()
            .any(|n| prefix::eq_ci(n, full_name));
        let family = anchors
            .package_families
            .iter()
            .find(|family| family_matches(family, full_name));
        if !by_full_name && family.is_none() {
            return false;
        }
        let anchor = family.cloned().unwrap_or_else(|| full_name.clone());
        self.push(
            EvidenceKind::AppxExternalLocation,
            Some(Scope::Package),
            app_trust(self.ctx.fp),
            "appx:link".to_owned(),
            Facts::new().with("anchor", anchor),
        )
    }

    /// `ChainedRef`: the target refers to `anchor`, something the app owns with `anchor_tier` (§5.3: the
    /// evidence is never stronger than its anchor). Value or Key scope.
    pub fn chained_ref(&mut self, anchor_tier: Tier, anchor: &str) -> bool {
        let Some(evidence) = self.scope().and_then(|scope| {
            Evidence::chained(
                anchor_tier,
                scope,
                app_trust(self.ctx.fp),
                format!("chain:{anchor}"),
            )
        }) else {
            return false;
        };
        self.push_evidence(evidence.with_detail(Facts::new().with("anchor", anchor)))
    }

    /// `ReferencedByApp`: the target is a path at or under a referenced data directory of the
    /// fingerprint. Such a target is always user data; set the category accordingly.
    pub fn referenced_by_app(&mut self) -> bool {
        let Some(path) = self.path() else {
            return false;
        };
        let Some(root) = self
            .ctx
            .fp
            .roots
            .iter()
            .filter(|r| {
                r.kind == RootKind::ReferencedDataDir && prefix::is_same_or_inside(path, &r.path)
            })
            .max_by_key(|r| prefix::depth(&r.path))
        else {
            return false;
        };
        let (trust, source) = (root.trust, format!("root:{}", root.path));
        let detail = Facts::new().with("root", root.path.clone());
        self.push(
            EvidenceKind::ReferencedByApp,
            Some(Scope::Path),
            trust,
            source,
            detail,
        )
    }

    /// A name match from `AppIdentity` (`NameTokenExact`, `ExactFullName` or
    /// `ProductSubfolderOfVendor`). The scanner must have matched the target's own last segment.
    ///
    /// A short-name match (`needs_tier_ab_neighbour`) is added only when the candidate already carries
    /// Tier A or Tier B evidence, so add the stronger evidence first.
    pub fn name_match(&mut self, m: &IdentityMatch) -> bool {
        let is_name_kind = matches!(
            m.kind,
            EvidenceKind::NameTokenExact
                | EvidenceKind::ExactFullName
                | EvidenceKind::ProductSubfolderOfVendor
        );
        if !is_name_kind || (m.needs_tier_ab_neighbour && !self.has_tier_ab_evidence()) {
            return false;
        }
        self.push(
            m.kind,
            self.scope(),
            app_trust(self.ctx.fp),
            format!("identity:{}", m.matched),
            Facts::new().with("name", m.matched.clone()),
        )
    }

    fn vendor_evidence(&mut self, m: &IdentityMatch, detail: Facts) -> bool {
        if m.kind != EvidenceKind::VendorContainer
            || self.candidate.action != Action::RemoveDirIfEmpty
        {
            return false;
        }
        let Some(mut evidence) = self.scope().and_then(|scope| {
            Evidence::new(
                EvidenceKind::VendorContainer,
                scope,
                app_trust(self.ctx.fp),
                format!("identity:{}", m.matched),
            )
        }) else {
            return false;
        };
        if m.weight == EvidenceKind::MEGA_VENDOR_WEIGHT {
            evidence.weight = EvidenceKind::MEGA_VENDOR_WEIGHT;
        }
        self.push_evidence(evidence.with_detail(detail.with("vendor", m.matched.clone())))
    }

    /// `VendorContainer`: the target is named after a vendor alias. Only for delete-if-empty candidates
    /// (`Action::RemoveDirIfEmpty`); a mega-vendor match weighs 0.
    pub fn vendor_container(&mut self, m: &IdentityMatch) -> bool {
        self.vendor_evidence(m, Facts::new())
    }

    /// `VendorContainer` with the pending `EmptyAfterPlan` marker and the complete listing of the
    /// container's direct children, for `purge-plan`'s emptiness check (§5.6 FS-VENDORPARENT). List every
    /// child: one that is left out would make a non-empty container look empty.
    pub fn vendor_container_pending<'n>(
        &mut self,
        m: &IdentityMatch,
        children: impl IntoIterator<Item = ContainerChild<'n>>,
    ) -> bool {
        let detail = Facts::new()
            .with(PENDING_KEY, PENDING_VALUE)
            .with(CHILDREN_KEY, children_json(children));
        self.vendor_evidence(m, detail)
    }

    /// `TimeWindow`: `when` (the target's creation or last-write time) lies within
    /// `[install − 1 day, t_end]`. Needs both ends of the window in the fingerprint.
    pub fn time_window(&mut self, when: FileTime) -> bool {
        let window = &self.ctx.fp.window;
        let (Some(install), Some(end)) = (window.install_time, window.t_end) else {
            return false;
        };
        if when.0 < install.0.saturating_sub(DAY_TICKS) || when > end {
            return false;
        }
        self.push(
            EvidenceKind::TimeWindow,
            self.scope(),
            app_trust(self.ctx.fp),
            "window".to_owned(),
            Facts::new(),
        )
    }

    /// One of the negative rows (`ExecutablesPresent`, `ManyFiles`, `GenericName`, `NameFuzzy`,
    /// `ModifiedAfterUninstall`), with `detail` for the explanation. Refuses every other kind.
    pub fn negative(&mut self, kind: EvidenceKind, detail: Facts) -> bool {
        if !kind.is_negative() {
            return false;
        }
        self.push(
            kind,
            self.scope(),
            app_trust(self.ctx.fp),
            "scan".to_owned(),
            detail,
        )
    }

    // ---- blockers ----------------------------------------------------------------------------------------

    /// Adds `blocker` unless an equal one is already there.
    pub fn blocker(&mut self, blocker: Blocker) -> &mut Self {
        if !self.candidate.blockers.contains(&blocker) {
            self.candidate.blockers.push(blocker);
        }
        self
    }

    /// `WindowsBaseline` when the clean Windows of this build has the target ([`ScanCtx::in_baseline`]).
    pub fn baseline_blocker(&mut self) -> &mut Self {
        if self.ctx.in_baseline(&self.candidate.target) {
            self.blocker(Blocker::WindowsBaseline);
        }
        self
    }

    /// `TrustedInstallerOwned` when the target's key is TrustedInstaller-owned now or was at harvest, and
    /// `RegLink` when it is a registry link. Registry targets only.
    pub fn owner_blockers(&mut self) -> &mut Self {
        let ctx = self.ctx;
        let Some(key) = self.key().map(str::to_owned) else {
            return self;
        };
        let live = ctx.reg.key_info(&key).ok();
        let fp = ctx.fp;
        let ti = live.as_ref().is_some_and(|i| i.ti_owned == Some(true))
            || fp
                .subtrees
                .iter()
                .any(|s| s.ti_owned && ctx.same_key(&s.key, &key))
            || fp
                .ext_journal
                .iter()
                .any(|e| e.ti_owned && ctx.same_key(&e.key, &key));
        if ti {
            self.blocker(Blocker::TrustedInstallerOwned);
        }
        if live.is_some_and(|i| i.is_link) {
            self.blocker(Blocker::RegLink);
        }
        self
    }

    /// `ExistedBeforeInstall` when the Inno log flags a record on exactly this target as having existed
    /// before the install.
    pub fn existed_before_blocker(&mut self) -> &mut Self {
        let ctx = self.ctx;
        let target = &self.candidate.target;
        let existed = ctx.fp.inno.iter().filter(|r| r.existed_before).any(|r| {
            ctx.same_target(&r.target, target)
                || matches!(
                    (&r.target, target),
                    (
                        Target::RegValue { path: p, name: n },
                        Target::RegMultiSzSegment { path: q, name: m, .. },
                    ) if ctx.same_key(p, q) && prefix::eq_ci(n, m)
                )
        });
        if existed {
            self.blocker(Blocker::ExistedBeforeInstall);
        }
        self
    }

    /// `InsideOtherApp`, `ContainsOtherApp` and `ReferencedByOtherApp` from [`ScanCtx::other_apps`]: for
    /// a path, against the other apps' roots and referenced files; for a key target, against their keys.
    /// A value or segment is `InsideOtherApp` when its key is one of another app's own keys
    /// ([`OtherApp::keys`]) or lies inside one: that app's settings are not this app's leftovers, even
    /// when they mention it. A value in a key that merely holds entries of several apps (`Run`, an
    /// `OpenWithProgids`) is not blocked.
    pub fn other_app_blockers(&mut self) -> &mut Self {
        let ctx = self.ctx;
        let blockers = match &self.candidate.target {
            Target::Path { path } => ctx.other_apps.path_blockers(path),
            Target::RegKey { path } => ctx
                .other_apps
                .key_blockers_with(path, |a, b| ctx.key_relation(a, b)),
            // A value has no descendants: only "inside" applies.
            Target::RegValue { path, .. }
            | Target::RegValueChanged { path, .. }
            | Target::RegMultiSzSegment { path, .. } => ctx
                .other_apps
                .key_blockers_with(path, |a, b| ctx.key_relation(a, b))
                .into_iter()
                .filter(|b| matches!(b, Blocker::InsideOtherApp { .. }))
                .collect(),
            _ => Vec::new(),
        };
        for blocker in blockers {
            self.blocker(blocker);
        }
        self
    }

    /// The blockers every scanner applies: [`baseline_blocker`](Self::baseline_blocker),
    /// [`owner_blockers`](Self::owner_blockers), [`existed_before_blocker`](Self::existed_before_blocker)
    /// and [`other_app_blockers`](Self::other_app_blockers).
    pub fn common_blockers(&mut self) -> &mut Self {
        self.baseline_blocker()
            .owner_blockers()
            .existed_before_blocker()
            .other_app_blockers()
    }

    /// `NotGone` unless the app is verified gone ([`ScanCtx::verify_gone_passed`]). For candidates whose
    /// evidence only holds once the app is really uninstalled (FS-INSTALLDIR).
    pub fn require_verify_gone(&mut self) -> &mut Self {
        if !self.ctx.verify_gone_passed() {
            self.blocker(Blocker::NotGone);
        }
        self
    }

    // ---- other fields ------------------------------------------------------------------------------------

    /// Overrides the default harm.
    pub fn harm(&mut self, harm: Harm) -> &mut Self {
        self.candidate.harm = harm;
        self
    }

    /// Overrides the default reversibility.
    pub fn reversibility(&mut self, reversibility: Reversibility) -> &mut Self {
        self.candidate.reversibility = reversibility;
        self
    }

    /// Records the measured size on disk.
    pub fn size_bytes(&mut self, bytes: u64) -> &mut Self {
        self.candidate.size_bytes = Some(bytes);
        self
    }

    /// Records the number of files or values inside.
    pub fn child_count(&mut self, count: u32) -> &mut Self {
        self.candidate.child_count = Some(count);
        self
    }

    /// Records a candidate nested inside this one.
    pub fn child(&mut self, id: CandidateId) -> &mut Self {
        if !self.candidate.children.contains(&id) {
            self.candidate.children.push(id);
        }
        self
    }

    /// Adds `evidence` gathered elsewhere (on the entries of the value) after what is there.
    pub(crate) fn evidence_also(&mut self, evidence: impl IntoIterator<Item = Evidence>) {
        for evidence in evidence {
            self.push_evidence(evidence);
        }
    }

    /// Puts `evidence` in front of what has been gathered (the record a candidate rests on goes
    /// first); what is already there is not added twice.
    pub(crate) fn evidence_first(&mut self, evidence: impl IntoIterator<Item = Evidence>) {
        let mut all: Vec<Evidence> = evidence.into_iter().collect();
        for built in std::mem::take(&mut self.candidate.evidence) {
            if !all.contains(&built) {
                all.push(built);
            }
        }
        self.candidate.evidence = all;
    }

    /// The finished candidate, undecided.
    ///
    /// The rule about what a value holds is applied here ([`ScanCtx::seal`]): a value, or an
    /// entry of one, whose data is not wholly the app's keeps no Tier A evidence, whatever the
    /// scanner gathered and whatever the installer recorded. [`ScanCtx::run`] applies it again
    /// to what the scanner returns, for evidence a scanner adds after this. `purge-plan` only
    /// merges candidates on one target, which all passed there, and adds `EmptyAfterPlan` to
    /// containers, never to a value.
    pub fn build(mut self) -> Candidate {
        self.mark_inferred();
        self.ctx.seal(&mut self.candidate);
        self.candidate
    }
}

/// Whether `token` occurs in `name` as a delimited part: not directly preceded or followed by a letter or
/// digit. Case-insensitive.
fn contains_delimited(name: &str, token: &str) -> bool {
    let (name, token) = (prefix::fold(name), prefix::fold(token));
    if token.is_empty() {
        return false;
    }
    name.match_indices(&token).any(|(at, hit)| {
        let before = name[..at].chars().next_back();
        let after = name[at + hit.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// Whether a package full name (`Name_Version_Arch_ResourceId_PublisherId`) belongs to a family
/// (`Name_PublisherId`).
fn family_matches(family: &str, full_name: &str) -> bool {
    let Some((name, publisher)) = family.rsplit_once('_') else {
        return false;
    };
    let (full, name, publisher) = (
        prefix::fold(full_name),
        prefix::fold(name),
        prefix::fold(publisher),
    );
    !name.is_empty()
        && !publisher.is_empty()
        && full.len() > name.len() + publisher.len() + 2
        && full.starts_with(&format!("{name}_"))
        && full.ends_with(&format!("_{publisher}"))
}

// ---------------------------------------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------------------------------------

/// Fixtures shared by the unit tests of this crate.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use purge_index::baseline_view::fixture;
    use purge_model::{
        Anchors, FingerprintSchema, IdentitySnapshot, OsInfo, ProgramId, TimeWindow, View,
    };
    use purge_source::fixture::Fixture;

    pub(crate) const EDITION: &str = "Professional";
    pub(crate) const BUILD: u32 = 26340;
    pub(crate) const UBR: u32 = 9882;
    pub(crate) const SERIAL: u32 = 0x1234_5678;
    pub(crate) const GIT_ROOT: &str = r"C:\Program Files\Git";

    /// A machine-wide Git fingerprint with one Inno InstallRoot and nothing else.
    pub(crate) fn fingerprint() -> Fingerprint {
        Fingerprint {
            baseline_view: None,
            schema: FingerprintSchema,
            app: AppRef {
                program_id: ProgramId::machine(View::K64, "Git_is1").unwrap(),
                display_name: "Git".into(),
            },
            identity: IdentitySnapshot {
                names: vec!["Git".into()],
                vendors: vec!["The Git Development Community".into()],
                tokens: vec!["git".into()],
                mega_vendor: false,
            },
            roots: vec![Root {
                path: GIT_ROOT.into(),
                kind: RootKind::InstallRoot,
                source: RootSource::InnoApp,
                trust: SourceTrust::AdminOnly,
                volume_serial: Some(SERIAL),
                parent_existed: true,
            }],
            exes: Vec::new(),
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
                edition: EDITION.into(),
                build: BUILD,
                ubr: UBR,
            },
            user_sid: GuardEnv::SAMPLE_SID.into(),
            window: TimeWindow::default(),
            verify_gone: None,
            warnings: Vec::new(),
        }
    }

    /// The Exact view over a baseline of this test Windows holding `keys`.
    pub(crate) fn baseline(edition: &str, keys: &[&str]) -> BaselineView {
        BaselineView::exact(shipped(edition, BUILD, UBR, keys))
    }

    /// A shipped baseline of (`edition`, `build`.`ubr`) holding `keys`.
    pub(crate) fn shipped(edition: &str, build: u32, ubr: u32, keys: &[&str]) -> Baseline {
        fixture::shipped(edition, build, ubr, keys)
    }

    /// A view of trust Merged for this test Windows: a complete local baseline holding `local_keys`
    /// and one shipped neighbour (the next build) holding `neighbour_keys`, with rules that accept
    /// inferred absence everywhere under `HKLM\SOFTWARE` and `HKU` (so the view itself would answer
    /// `Inferred` wherever a scanner could ask).
    pub(crate) fn merged_view(local_keys: &[&str], neighbour_keys: &[&str]) -> BaselineView {
        fixture::merged_view(EDITION, BUILD, UBR, local_keys, neighbour_keys)
    }

    /// A view of trust Local for this test Windows: a complete local baseline holding `keys`, no
    /// neighbour, the same open rules.
    pub(crate) fn local_view(keys: &[&str]) -> BaselineView {
        fixture::local_view(EDITION, BUILD, UBR, keys)
    }

    /// A view of trust None that holds one shipped neighbour with `keys`: presence only.
    pub(crate) fn none_view(keys: &[&str]) -> BaselineView {
        fixture::none_view(EDITION, BUILD, UBR, keys)
    }

    /// Everything a [`ScanCtx`] borrows, owned in one place.
    pub(crate) struct World {
        pub(crate) fixture: Fixture,
        pub(crate) fp: Fingerprint,
        pub(crate) baseline: Option<BaselineView>,
        pub(crate) env: BTreeMap<String, String>,
        pub(crate) guard: GuardEnv,
        pub(crate) other_apps: OtherApps,
        pub(crate) verify_gone: Option<VerifyGone>,
    }

    impl World {
        /// A world over `fixture` with the Git fingerprint and an empty matching baseline.
        pub(crate) fn new(fixture: Fixture) -> Self {
            Self {
                fixture,
                fp: fingerprint(),
                baseline: Some(baseline(EDITION, &[])),
                env: BTreeMap::new(),
                guard: GuardEnv::sample(),
                other_apps: OtherApps::default(),
                verify_gone: Some(VerifyGone::new(true, true, true)),
            }
        }

        pub(crate) fn ctx(&self) -> ScanCtx<'_> {
            ScanCtx {
                reg: &self.fixture,
                fs: &self.fixture,
                sys: &self.fixture,
                fp: &self.fp,
                baseline: BaselineView::or_empty(self.baseline.as_ref()),
                mode: ScanMode::Post,
                verify_gone: self.verify_gone,
                env: &self.env,
                guard: &self.guard,
                other_apps: &self.other_apps,
                limits: ScanLimits::default(),
                ext: ScanExt::none(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use purge_model::{HarvestedToken, InnoRecordKind, RefCarrier, SubtreeBaseline, View};
    use purge_model::{MAX_RESIDUE_ITEMS, ResidueWhy};
    use purge_source::fixture::Fixture;

    const SID: &str = GuardEnv::SAMPLE_SID;

    fn key(path: &str) -> Target {
        Target::RegKey { path: path.into() }
    }

    /// Which runs of binary data are read as paths. A switch or timestamp whose bytes happen to
    /// be printable is none (a disabled `StartupApproved` entry with 0x5C in its time; UTF-16
    /// text with U+5C3A, whose bytes are `:\`).
    #[test]
    fn binary_runs_read_as_paths() {
        use purge_source::types::RegData;
        let utf16 =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let runs = |bytes: Vec<u8>| binary_path_runs(&RegData::from_binary(bytes));
        for switch in [
            vec![0x03, 0, 0, 0, 0x5c, 0x41, 0x7b, 0x9a, 0x22, 0xdc, 0x31, 0],
            vec![0x03, 0, 0, 0, 0x5c, 0x41, 0x7b, 0x3a, 0x22, 0x2f, 0x31, 0],
            vec![0x02, 0, 0, 0, 0x5c, 0x5c, 0x41, 0xe9, 0xff, 0x80, 0x90, 0],
            utf16("settings \u{5c3a} of the window\0"),
            utf16("version 12.5 (64-bit)\0"),
            b"plain text, 50% done\0\0".to_vec(),
            b"tools\\x.exe and /usr/bin\0".to_vec(),
        ] {
            assert_eq!(runs(switch.clone()), Vec::<String>::new(), "{switch:02x?}");
        }
        for (text, wide) in [
            (r"C:\Users\me\tool.exe", true),
            (r"\\server\share\tool.exe", true),
            (r"\Users\me\tool.exe", true),
            (r"%USERPROFILE%\tool.exe", true),
            (r"tools\my tool.exe", true),
            (r"2\Users\me\tool.exe", true),
            ("/Users/me/tool.exe", true),
            ("%MYTOOL%", true),
            (r"C:\Users\me\tool.exe", false),
            ("x=D:/tools/tool.exe", false),
            (r"\\server\share\tool.exe", false),
        ] {
            let bytes = if wide {
                utf16(&format!("{text}\0"))
            } else {
                let mut bytes = text.as_bytes().to_vec();
                bytes.push(0);
                bytes
            };
            assert_eq!(runs(bytes), vec![text.to_owned()], "{text} wide={wide}");
        }
    }

    fn value(path: &str, name: &str) -> Target {
        Target::RegValue {
            path: path.into(),
            name: name.into(),
        }
    }

    fn path(path: &str) -> Target {
        Target::Path { path: path.into() }
    }

    /// `C:\Program Files` exists on the recorded fixed NTFS volume; Git's directory is gone.
    fn uninstalled() -> Fixture {
        Fixture::builder()
            .dir(r"C:\Program Files")
            .volume(r"C:\", Some(SERIAL), true, "NTFS")
            .os(EDITION, BUILD, UBR)
            .build()
    }

    fn identity_match(kind: EvidenceKind, weight: i8) -> IdentityMatch {
        IdentityMatch {
            kind,
            tier: kind.default_tier(),
            weight,
            needs_tier_ab_neighbour: false,
            matched: "Git".into(),
            distance: 0,
        }
    }

    // ---- scan-time identity (item_fp) ------------------------------------------------------------------

    /// Emits a fixed list of targets, each as a bare candidate.
    struct Emit(Vec<(Target, Action)>);

    impl Scanner for Emit {
        fn id(&self) -> &'static str {
            "TEST-EMIT"
        }

        fn captured_roots(&self) -> &[RootSpec] {
            &[]
        }

        fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
            self.0
                .iter()
                .map(|(target, action)| {
                    ctx.candidate("TEST-EMIT", target.clone(), *action, Category::AppFiles)
                        .build()
                })
                .collect()
        }
    }

    #[test]
    fn run_records_the_identity_of_path_items_only() {
        use purge_source::types::{FILE_ATTRIBUTE_ARCHIVE, FileMeta, FileTimes};
        let file = r"C:\Program Files\Git\git.exe";
        let link = r"C:\Program Files\Git\link";
        let no_serial = r"C:\Program Files\Git\no-serial.dll";
        let listed_only = r"C:\Program Files\Git\listed.txt";
        let meta = |file_id: u128, volume_serial: Option<u64>, reparse_tag: u32| FileMeta {
            size: 1,
            attrs: FILE_ATTRIBUTE_ARCHIVE,
            times: FileTimes::default(),
            reparse_tag,
            file_id: Some(file_id),
            volume_serial,
        };
        let fixture = Fixture::builder()
            .dir(GIT_ROOT)
            .volume(r"C:\", Some(SERIAL), true, "NTFS")
            .os(EDITION, BUILD, UBR)
            .file(listed_only, 3)
            .with(|f| {
                f.set_meta(
                    file,
                    meta(0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100, Some(77), 0),
                );
                f.set_meta(link, meta(5, Some(77), 0xA000_000C));
                f.set_meta(no_serial, meta(6, None, 0));
            })
            .build();
        let world = World::new(fixture);
        let ctx = world.ctx();
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        let found = ctx.run(
            &Emit(vec![
                (path(file), Action::Quarantine),
                (path(link), Action::Quarantine),
                (path(no_serial), Action::Quarantine),
                (path(listed_only), Action::Quarantine),
                (path(r"C:\Program Files\Git\gone.exe"), Action::Quarantine),
                (path(GIT_ROOT), Action::RemoveDirIfEmpty),
                (key(r"HKLM\SOFTWARE\GitForWindows"), Action::DeleteKey),
            ]),
            &app,
        );
        let fp = |p: &str| {
            found
                .iter()
                .find(|c| matches!(&c.target, Target::Path { path } if path == p))
                .unwrap_or_else(|| panic!("{p}"))
                .item_fp
        };
        // The bytes in the order Windows returns them (the source keeps the id as a little-endian u128).
        let id = FileIdHex([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert!(fp(file).is_some_and(|f| f.matches(&id, 77)));
        // A reparse point is identified as itself, not as what it points to.
        assert!(fp(link).is_some_and(|f| f.matches(&FileIdHex(5u128.to_le_bytes()), 77)));
        // Half an identity, no identity: nothing is recorded.
        assert_eq!(fp(no_serial), None);
        assert_eq!(fp(listed_only), None);
        assert_eq!(fp(r"C:\Program Files\Git\gone.exe"), None);
        assert_eq!(fp(GIT_ROOT), None);
        let key_item = found
            .iter()
            .find(|c| matches!(c.target, Target::RegKey { .. }))
            .unwrap();
        assert_eq!(key_item.item_fp, None);
        // The candidates are otherwise what the scanner built.
        let mut bare = found.clone();
        for c in &mut bare {
            c.item_fp = None;
        }
        let built: Vec<Candidate> = Emit(vec![(path(file), Action::Quarantine)]).scan(&ctx, &app);
        assert_eq!(bare[0], built[0]);
    }

    // ---- root specs --------------------------------------------------------------------------------------

    #[test]
    fn root_spec_syntax() {
        for good in [
            RootSpec::reg(r"*\SOFTWARE\Classes", None),
            RootSpec::reg(r"HKU\*\Environment", Some(0)),
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Services", Some(1)),
            RootSpec::reg(r"HKCR\Applications", Some(1)),
            RootSpec::fs("%ProgramFiles%", Some(1)),
            RootSpec::fs(r"%APPDATA%\Microsoft\Windows\Start Menu", None),
        ] {
            assert!(good.is_well_formed(), "{good:?}");
        }
        for bad in [
            RootSpec::reg(r"HKCU\Software", None),
            RootSpec::reg(r"HKLM\", None),
            RootSpec::reg(r"HKLM\SOFTWARE\WOW6432Node\X", None),
            RootSpec::reg(r"HKLM\SOFTWARE\", None),
            RootSpec::fs(r"C:\Program Files", None),
            RootSpec::fs(r"%ProgramFiles%Extra", None),
            RootSpec::fs(r"%TEMP%\x", None),
            RootSpec::fs("", None),
        ] {
            assert!(!bad.is_well_formed(), "{bad:?}");
        }
    }

    // ---- builder defaults --------------------------------------------------------------------------------

    #[test]
    fn builder_fills_the_fixed_fields() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let target = key(r"HKLM\SOFTWARE\GitForWindows");
        let c = ctx
            .candidate(
                "REG-SOFTWARE",
                target.clone(),
                Action::DeleteKey,
                Category::Registration,
            )
            .build();
        assert_eq!(c.id, candidate_id(&target));
        assert_eq!(c.scanner, "REG-SOFTWARE");
        assert_eq!(c.owner, world.fp.app);
        assert_eq!(c.origin, Origin::Scanner);
        assert_eq!(
            (c.action, c.category),
            (Action::DeleteKey, Category::Registration)
        );
        assert_eq!((c.harm, c.reversibility), (Harm::Low, Reversibility::Full));
        assert!(c.evidence.is_empty() && c.blockers.is_empty() && c.children.is_empty());
        // Scanners never set a band.
        assert_eq!(c.decision, None);

        let package = ctx
            .candidate(
                "SYS-APPX",
                Target::AppxPackage {
                    full_name: "X_1.0.0.0_x64__abc".into(),
                },
                Action::RemovePackage,
                Category::Package,
            )
            .build();
        assert_eq!(
            (package.harm, package.reversibility),
            (Harm::Medium, Reversibility::None)
        );
    }

    #[test]
    fn candidate_id_is_stable_and_case_insensitive() {
        let a = candidate_id(&key(r"HKLM\SOFTWARE\Classes\sh_auto_file"));
        assert_eq!(
            a,
            candidate_id(&key(r"hklm\software\classes\SH_AUTO_FILE\"))
        );
        assert!(a.0.starts_with("c-") && a.0.len() == 18, "{a:?}");
        // Pinned: ids must not change between runs or builds.
        assert_eq!(candidate_id(&path(r"C:\X")), candidate_id(&path(r"c:\x")));
        assert_eq!(candidate_id(&path(r"C:\X")).0, "c-e8c9048655ff3422");
        let distinct = [
            candidate_id(&key(r"HKLM\SOFTWARE\X")),
            candidate_id(&path(r"HKLM\SOFTWARE\X")),
            candidate_id(&value(r"HKLM\SOFTWARE\X", "")),
            candidate_id(&value(r"HKLM\SOFTWARE\X", "a")),
            candidate_id(&value(r"HKLM\SOFTWARE", "X")),
        ];
        for (i, x) in distinct.iter().enumerate() {
            for y in &distinct[i + 1..] {
                assert_ne!(x, y);
            }
        }
    }

    #[test]
    fn default_harm_table() {
        use Action::*;
        use Category::*;
        assert_eq!(default_harm(UserData, RemoveDirIfEmpty), Harm::None);
        assert_eq!(default_harm(System, DeleteKey), Harm::Critical);
        assert_eq!(default_harm(UserData, Quarantine), Harm::High);
        assert_eq!(default_harm(AppData, Quarantine), Harm::Medium);
        assert_eq!(default_harm(Registration, EditSegment), Harm::Medium);
        assert_eq!(default_harm(Package, RemovePackage), Harm::Medium);
        for category in [
            AppFiles,
            Cache,
            Registration,
            Association,
            ShellCom,
            Startup,
            Privacy,
        ] {
            assert_eq!(
                default_harm(category, DeleteValue),
                Harm::Low,
                "{category:?}"
            );
        }
    }

    // ---- evidence equals the model table -----------------------------------------------------------------

    /// Every typed constructor yields the tier, weight and scope of the §5.3 table.
    #[test]
    fn builder_evidence_equals_the_model_table() {
        let mut world = World::new(uninstalled());
        let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let progid = r"HKLM\SOFTWARE\Classes\GitBash.Document";
        let token = "308046B0AF4A39CB";
        world.fp.inno = vec![
            InnoRecord {
                kind: InnoRecordKind::RegDeleteEntireKey,
                target: key(progid),
                view: Some(View::K64),
                user_hive: false,
                existed_before: false,
                shared: false,
                key_create: true,
            },
            InnoRecord {
                kind: InnoRecordKind::RegDeleteValue,
                target: value(run, "GitTray"),
                view: Some(View::K64),
                user_hive: false,
                existed_before: false,
                shared: false,
                key_create: false,
            },
        ];
        world.fp.ref_snapshot = vec![RefSnapEntry {
            target: value(run, "GitTray"),
            carrier: RefCarrier::Data,
            anchor: AnchorRef {
                kind: AnchorKind::Root,
                text: GIT_ROOT.into(),
            },
            parent_values: 3,
            parent_subkeys: 0,
            data_hash: None,
        }];
        world.fp.tokens = vec![HarvestedToken {
            token: token.into(),
            source: "arp:key".into(),
        }];
        world.fp.roots.push(Root {
            path: r"D:\GitData".into(),
            kind: RootKind::ReferencedDataDir,
            source: RootSource::Referenced,
            trust: SourceTrust::UserWritable,
            volume_serial: None,
            parent_existed: true,
        });
        world.fp.anchors.package_families = vec!["Vendor.Git_abc123".into()];
        world.fp.window.install_time = Some(FileTime(DAY_TICKS * 10));
        world.fp.window.t_end = Some(FileTime(DAY_TICKS * 20));
        world.fp.subtrees = vec![SubtreeBaseline {
            key: r"HKLM\SOFTWARE\Classes\sh_auto_file".into(),
            values: Vec::new(),
            subkeys: Vec::new(),
            lwt: FileTime(1),
            ti_owned: false,
            fully_attributed: true,
        }];
        world.fixture.add_key(r"HKLM\SOFTWARE\Classes\sh_auto_file");
        let ctx = world.ctx();
        let exe = format!(r"{GIT_ROOT}\git-bash.exe");
        let dangling = ctx.dangling(&exe).expect("the exe is dangling");

        type Add = fn(&mut CandidateBuilder<'_>, &Dangling<'_>) -> bool;
        let rows: Vec<(EvidenceKind, Target, Action, Add)> = vec![
            (
                EvidenceKind::InsideInstallRoot,
                path(&format!(r"{GIT_ROOT}\etc")),
                Action::Quarantine,
                |b, _| b.inside_install_root(),
            ),
            (
                EvidenceKind::InstallerManifest(ManifestKind::Inno),
                key(progid),
                Action::DeleteKey,
                |b, _| b.installer_manifest(),
            ),
            (
                EvidenceKind::InstallerManifest(ManifestKind::Inno),
                value(run, "GitTray"),
                Action::DeleteValue,
                |b, _| b.installer_manifest(),
            ),
            (
                EvidenceKind::InPreUninstallRefSnapshot,
                value(run, "GitTray"),
                Action::DeleteValue,
                |b, _| b.in_ref_snapshot(),
            ),
            (
                EvidenceKind::ProvenOwnedSkeleton,
                key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
                Action::DeleteKey,
                |b, _| b.proven_owned_skeleton(),
            ),
            (
                EvidenceKind::DanglingRef,
                value(run, "GitTray"),
                Action::DeleteValue,
                |b, d| b.dangling_ref(d),
            ),
            (
                EvidenceKind::PointsIntoInstallRoot,
                value(run, "GitTray"),
                Action::DeleteValue,
                |b, d| b.points_into_install_root(d.path()),
            ),
            (
                EvidenceKind::HarvestedToken,
                path(r"C:\ProgramData\Mozilla-1de4eec8\updates\308046B0AF4A39CB"),
                Action::Quarantine,
                |b, _| b.harvested_token("308046b0af4a39cb"),
            ),
            (
                EvidenceKind::AppNamedKeyWithRootRef,
                key(r"HKLM\SOFTWARE\GitForWindows"),
                Action::DeleteKey,
                |b, d| b.app_named_key_with_root_ref(d.path()),
            ),
            (
                EvidenceKind::UninstallerArtifact,
                path(&format!(r"{GIT_ROOT}\unins000.dat")),
                Action::Quarantine,
                |b, _| b.uninstaller_artifact("UninstallString"),
            ),
            (
                EvidenceKind::AppxExternalLocation,
                Target::AppxPackage {
                    full_name: "Vendor.Git_2.47.0.0_x64__abc123".into(),
                },
                Action::RemovePackage,
                |b, _| b.appx_external_location(),
            ),
            (
                EvidenceKind::ChainedRef,
                value(r"HKLM\SOFTWARE\Classes\.sh\OpenWithProgids", "sh_auto_file"),
                Action::DeleteValue,
                |b, _| b.chained_ref(Tier::A, "sh_auto_file"),
            ),
            (
                EvidenceKind::ReferencedByApp,
                path(r"D:\GitData\repos"),
                Action::Quarantine,
                |b, _| b.referenced_by_app(),
            ),
            (
                EvidenceKind::ProductSubfolderOfVendor,
                path(r"C:\ProgramData\Vendor\Git"),
                Action::Quarantine,
                |b, _| b.name_match(&identity_match(EvidenceKind::ProductSubfolderOfVendor, 3)),
            ),
            (
                EvidenceKind::ExactFullName,
                key(r"HKLM\SOFTWARE\Git"),
                Action::DeleteKey,
                |b, _| b.name_match(&identity_match(EvidenceKind::ExactFullName, 4)),
            ),
            (
                EvidenceKind::NameTokenExact,
                path(r"C:\ProgramData\Git"),
                Action::Quarantine,
                |b, _| b.name_match(&identity_match(EvidenceKind::NameTokenExact, 3)),
            ),
            (
                EvidenceKind::VendorContainer,
                path(r"C:\ProgramData\Vendor"),
                Action::RemoveDirIfEmpty,
                |b, _| b.vendor_container(&identity_match(EvidenceKind::VendorContainer, 2)),
            ),
            (
                EvidenceKind::TimeWindow,
                path(r"C:\ProgramData\Git"),
                Action::Quarantine,
                |b, _| b.time_window(FileTime(DAY_TICKS * 9 + 1)),
            ),
            (
                EvidenceKind::ExecutablesPresent,
                path(r"C:\ProgramData\Git"),
                Action::Quarantine,
                |b, _| b.negative(EvidenceKind::ExecutablesPresent, Facts::new()),
            ),
            (
                EvidenceKind::ManyFiles,
                path(r"C:\ProgramData\Git"),
                Action::Quarantine,
                |b, _| b.negative(EvidenceKind::ManyFiles, Facts::new()),
            ),
            (
                EvidenceKind::GenericName,
                path(r"C:\ProgramData\Git"),
                Action::Quarantine,
                |b, _| b.negative(EvidenceKind::GenericName, Facts::new()),
            ),
            (
                EvidenceKind::NameFuzzy,
                key(r"HKLM\SOFTWARE\Gitt"),
                Action::DeleteKey,
                |b, _| b.negative(EvidenceKind::NameFuzzy, Facts::new()),
            ),
            (
                EvidenceKind::ModifiedAfterUninstall,
                path(&format!(r"{GIT_ROOT}\etc")),
                Action::Quarantine,
                |b, _| b.negative(EvidenceKind::ModifiedAfterUninstall, Facts::new()),
            ),
        ];
        let mut seen = Vec::new();
        for (kind, target, action, add) in rows {
            let scope = Scope::of(&target).unwrap();
            let mut b = ctx.candidate("TEST", target.clone(), action, Category::Registration);
            assert!(add(&mut b, &dangling), "{kind:?} on {target:?} was refused");
            let c = b.build();
            assert_eq!(c.evidence.len(), 1, "{kind:?}");
            let e = &c.evidence[0];
            assert_eq!(e.kind, kind);
            assert_eq!(e.tier, kind.default_tier(), "{kind:?} tier");
            assert_eq!(e.weight, kind.default_weight(), "{kind:?} weight");
            assert_eq!(e.scope, scope, "{kind:?} scope");
            assert!(
                kind.scope().contains(e.scope),
                "{kind:?} scope not in the table"
            );
            seen.push(kind);
        }
        // Every kind a scanner may state is covered; `EmptyAfterPlan` belongs to purge-plan and
        // `ComKeyOwnership` to the M1b COM scanners.
        for kind in EvidenceKind::ALL {
            let expected = !matches!(
                kind,
                EvidenceKind::EmptyAfterPlan
                    | EvidenceKind::ComKeyOwnership
                    // Stated through the by-value M1b constructor
                    // `CandidateBuilder::owned_system_object` (tested in `framework::m1b`).
                    | EvidenceKind::OwnedSystemObject
                    // Made by the advice mapping of `purge-model`, never by a scanner.
                    | EvidenceKind::Ai
            );
            assert_eq!(seen.contains(&kind), expected, "{kind:?}");
        }
    }

    #[test]
    fn evidence_is_refused_when_its_condition_does_not_hold() {
        let mut world = World::new(uninstalled());
        let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::RegDeleteValue,
            target: value(run, "GitTray"),
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: false,
        }];
        world.fp.tokens = vec![HarvestedToken {
            token: "308046B0AF4A39CB".into(),
            source: "arp:key".into(),
        }];
        world.fp.roots.push(Root {
            path: r"C:\Tools\GitExtras".into(),
            kind: RootKind::InferredRoot,
            source: RootSource::DisplayIcon,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(SERIAL),
            parent_existed: true,
        });
        let ctx = world.ctx();
        let on = |target: Target, action: Action| {
            ctx.candidate("TEST", target, action, Category::Registration)
        };

        // A path outside every InstallRoot; a sibling whose name merely starts like the root; an inferred
        // root.
        for outside in [
            r"C:\Program Files\GitHub",
            r"C:\Program Files",
            r"C:\Tools\GitExtras\x",
        ] {
            assert!(
                !on(path(outside), Action::Quarantine).inside_install_root(),
                "{outside}"
            );
        }
        assert!(!on(key(run), Action::DeleteKey).inside_install_root());
        // A value record proves nothing about its key, nor about another value.
        assert!(!on(key(run), Action::DeleteKey).installer_manifest());
        assert!(!on(value(run, "Other"), Action::DeleteValue).installer_manifest());
        assert!(!on(value(run, "Other"), Action::DeleteValue).in_ref_snapshot());
        // Value-scope kinds refuse a key target.
        let exe = format!(r"{GIT_ROOT}\git.exe");
        let dangling = ctx.dangling(&exe).unwrap();
        assert!(!on(key(run), Action::DeleteKey).dangling_ref(&dangling));
        assert!(!on(key(run), Action::DeleteKey).points_into_install_root(&exe));
        assert!(
            !on(value(run, "x"), Action::DeleteValue)
                .points_into_install_root(r"C:\Windows\System32\notepad.exe")
        );
        assert!(
            !on(key(r"HKLM\SOFTWARE\Git"), Action::DeleteKey)
                .app_named_key_with_root_ref(r"C:\Windows\notepad.exe")
        );
        // A token must be harvested, and must be in the target's own name: not in an ancestor's
        // (carry-over rule), and not as part of a longer hex run.
        let token = "308046B0AF4A39CB";
        assert!(
            !on(
                path(r"C:\ProgramData\X\deadbeefdeadbeef"),
                Action::Quarantine
            )
            .harvested_token("deadbeefdeadbeef")
        );
        assert!(
            !on(
                path(r"C:\ProgramData\308046B0AF4A39CB\child"),
                Action::Quarantine
            )
            .harvested_token(token)
        );
        assert!(
            !on(
                path(r"C:\ProgramData\A308046B0AF4A39CB"),
                Action::Quarantine
            )
            .harvested_token(token)
        );
        assert!(
            on(
                key(r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
                Action::DeleteKey
            )
            .harvested_token(token)
        );
        // A name kind is not a vendor kind and the other way round; a vendor container is only ever
        // delete-if-empty; `negative` takes negatives only.
        let vendor = identity_match(EvidenceKind::VendorContainer, 2);
        let name = identity_match(EvidenceKind::NameTokenExact, 3);
        let dir = path(r"C:\ProgramData\Vendor");
        assert!(!on(dir.clone(), Action::Quarantine).vendor_container(&vendor));
        assert!(!on(dir.clone(), Action::RemoveDirIfEmpty).vendor_container(&name));
        assert!(!on(dir.clone(), Action::RemoveDirIfEmpty).name_match(&vendor));
        assert!(
            !on(dir.clone(), Action::Quarantine)
                .negative(EvidenceKind::InsideInstallRoot, Facts::new())
        );
        // No window in the fingerprint: no TimeWindow evidence.
        assert!(!on(dir.clone(), Action::Quarantine).time_window(FileTime(5)));
        // Name evidence cannot support a value.
        assert!(!on(value(run, "Git"), Action::DeleteValue).name_match(&name));
        assert!(!on(dir, Action::Quarantine).appx_external_location());
        assert!(!on(path(r"C:\Elsewhere"), Action::Quarantine).referenced_by_app());
    }

    /// An INI-entry or shared-count record names the file the uninstaller touches (`win.ini`, a shared
    /// DLL), not a file the installer owns: no Path evidence, whatever the flags say.
    #[test]
    fn ini_and_shared_count_records_do_not_attribute_the_file() {
        let mut world = World::new(uninstalled());
        let file = r"C:\ProgramData\Shared\settings.ini";
        let ctx_with = |world: &mut World, kind: InnoRecordKind| {
            world.fp.inno = vec![InnoRecord {
                kind,
                target: path(file),
                view: None,
                user_hive: false,
                existed_before: false,
                shared: false,
                key_create: false,
            }];
        };
        for kind in [
            InnoRecordKind::IniDeleteEntry,
            InnoRecordKind::IniDeleteSection,
            InnoRecordKind::DecrementSharedCount,
        ] {
            ctx_with(&mut world, kind);
            let ctx = world.ctx();
            let mut b = ctx.candidate("T", path(file), Action::Quarantine, Category::AppData);
            assert!(!b.installer_manifest(), "{kind:?}");
            assert!(b.evidence().is_empty(), "{kind:?}");
        }
        for kind in [InnoRecordKind::DeleteFile, InnoRecordKind::DeleteDirOrFiles] {
            ctx_with(&mut world, kind);
            let ctx = world.ctx();
            let mut b = ctx.candidate("T", path(file), Action::Quarantine, Category::AppData);
            assert!(b.installer_manifest(), "{kind:?}");
        }
    }

    /// §5.2: an inferred root is Tier B only and a referenced data directory gives at most
    /// `ReferencedByApp`. A harvested reference to either is not Tier A snapshot evidence.
    #[test]
    fn ref_snapshot_needs_an_install_root_anchor() {
        let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        for (kind, source) in [
            (RootKind::InferredRoot, RootSource::DisplayIcon),
            (RootKind::ReferencedDataDir, RootSource::Referenced),
        ] {
            let mut world = World::new(uninstalled());
            world.fp.roots.push(Root {
                path: r"D:\Library".into(),
                kind,
                source,
                trust: SourceTrust::AdminOnly,
                volume_serial: None,
                parent_existed: true,
            });
            let entry = |anchor: AnchorRef| RefSnapEntry {
                target: value(run, "Lib"),
                carrier: RefCarrier::Data,
                anchor,
                parent_values: 1,
                parent_subkeys: 0,
                data_hash: None,
            };
            world.fp.ref_snapshot = vec![entry(AnchorRef {
                kind: AnchorKind::Root,
                text: r"D:\Library".into(),
            })];
            let ctx = world.ctx();
            let mut b = ctx.candidate(
                "T",
                value(run, "Lib"),
                Action::DeleteValue,
                Category::Startup,
            );
            assert!(!b.in_ref_snapshot(), "{kind:?}");
            assert!(b.evidence().is_empty(), "{kind:?}");
            // The same value recorded against the InstallRoot, or against a ProgID, counts.
            for anchor in [
                AnchorRef {
                    kind: AnchorKind::Root,
                    text: GIT_ROOT.to_lowercase(),
                },
                AnchorRef {
                    kind: AnchorKind::ProgId,
                    text: "GitBash.Document".into(),
                },
            ] {
                world.fp.ref_snapshot = vec![entry(anchor.clone())];
                let ctx = world.ctx();
                let mut b = ctx.candidate(
                    "T",
                    value(run, "Lib"),
                    Action::DeleteValue,
                    Category::Startup,
                );
                assert!(b.in_ref_snapshot(), "{anchor:?}");
            }
        }
    }

    /// §5.7.1 step 3: without a baseline no key is proven not to be Windows' own, so a token gives no
    /// key-level evidence; values and paths keep theirs.
    #[test]
    fn harvested_token_on_a_key_needs_a_baseline() {
        // Every view below Exact takes the no-baseline path (presence-only, design L5).
        for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
            let token = "308046B0AF4A39CB";
            let mut world = World::new(uninstalled());
            world.fp.tokens = vec![HarvestedToken {
                token: token.into(),
                source: "arp:key".into(),
            }];
            let named = format!(r"HKLM\SOFTWARE\Classes\FirefoxHTML-{token}");
            let add = |world: &World, target: Target, action: Action| {
                let ctx = world.ctx();
                ctx.candidate("T", target, action, Category::Registration)
                    .harvested_token(token)
            };
            assert!(add(&world, key(&named), Action::DeleteKey));
            world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
            assert!(!add(&world, key(&named), Action::DeleteKey));
            assert!(add(
                &world,
                value(r"HKLM\SOFTWARE\RegisteredApplications", &named),
                Action::DeleteValue
            ));
            // A token Windows itself uses is nobody's, on any target.
            let shipped = format!(r"HKLM\SOFTWARE\Microsoft\Shipped\{token}");
            world.baseline = Some(baseline(EDITION, &[&shipped]));
            assert!(!add(&world, key(&named), Action::DeleteKey));
            assert!(!add(
                &world,
                value(r"HKLM\SOFTWARE\RegisteredApplications", &named),
                Action::DeleteValue
            ));
        }
    }

    #[test]
    fn short_name_match_needs_a_tier_ab_neighbour() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let mut short = identity_match(EvidenceKind::ExactFullName, 4);
        short.needs_tier_ab_neighbour = true;
        let target = path(&format!(r"{GIT_ROOT}\Git"));
        let mut alone = ctx.candidate(
            "T",
            path(r"C:\ProgramData\Git"),
            Action::Quarantine,
            Category::AppData,
        );
        assert!(!alone.name_match(&short));
        let mut next_to_a = ctx.candidate("T", target, Action::Quarantine, Category::AppFiles);
        assert!(next_to_a.inside_install_root());
        assert!(next_to_a.has_tier_ab_evidence());
        assert!(next_to_a.name_match(&short));
    }

    #[test]
    fn trust_comes_from_the_fingerprint() {
        let mut world = World::new(uninstalled());
        world.fp.roots[0].trust = SourceTrust::UserWritable;
        {
            let ctx = world.ctx();
            let mut b = ctx.candidate(
                "T",
                path(&format!(r"{GIT_ROOT}\bin")),
                Action::Quarantine,
                Category::AppFiles,
            );
            assert!(b.inside_install_root());
            assert_eq!(b.evidence()[0].trust, SourceTrust::UserWritable);
            // The Inno log lives in the user-writable root.
            assert_eq!(inno_trust(&world.fp), SourceTrust::UserWritable);
            assert_eq!(app_trust(&world.fp), SourceTrust::AdminOnly);
        }
        // A per-user registration: name evidence is UserWritable.
        world.fp.app.program_id = purge_model::ProgramId::user(SID, View::K64, "Git_is1").unwrap();
        let ctx = world.ctx();
        let mut b = ctx.candidate(
            "T",
            key(r"HKLM\SOFTWARE\Git"),
            Action::DeleteKey,
            Category::Registration,
        );
        assert!(b.name_match(&identity_match(EvidenceKind::ExactFullName, 4)));
        assert_eq!(b.evidence()[0].trust, SourceTrust::UserWritable);
        assert_eq!(
            anchor_trust(
                &world.fp,
                &AnchorRef {
                    kind: AnchorKind::ProgId,
                    text: "x".into()
                }
            ),
            SourceTrust::UserWritable
        );
    }

    #[test]
    fn vendor_container_marker_and_mega_vendor_weight() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let mut b = ctx.candidate(
            "FS-VENDORPARENT",
            path(r"C:\ProgramData\Vendor"),
            Action::RemoveDirIfEmpty,
            Category::AppData,
        );
        let children = [
            ContainerChild::Container("Git"),
            ContainerChild::Leaf("desktop.ini"),
            ContainerChild::Leaf("a\"b\\c\td"),
        ];
        assert!(
            b.vendor_container_pending(&identity_match(EvidenceKind::VendorContainer, 0), children)
        );
        let c = b.build();
        assert_eq!(c.harm, Harm::None);
        let e = &c.evidence[0];
        // A mega-vendor container weighs nothing.
        assert_eq!(
            (e.kind, e.tier, e.weight),
            (EvidenceKind::VendorContainer, Tier::C, 0)
        );
        assert_eq!(e.detail.get(PENDING_KEY), Some(PENDING_VALUE));
        assert_eq!(
            e.detail.get(CHILDREN_KEY),
            Some(r#"["Git\\","desktop.ini","a\"b\\c\u0009d"]"#)
        );
        assert_eq!(e.detail.get("vendor"), Some("Git"));
    }

    // ---- dangling ----------------------------------------------------------------------------------------

    #[test]
    fn dangling_holds_on_the_recorded_fixed_volume() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let exe = format!(r"{GIT_ROOT}\cmd\git.exe");
        let d = ctx.dangling(&exe).expect("dangling");
        assert_eq!(d.path(), exe);
        assert_eq!(d.root().path, GIT_ROOT);
        assert_eq!(d.volume_serial(), SERIAL);
        assert_eq!(d.nearest_existing_ancestor(), r"C:\Program Files");
        assert!(d.root_gone());
        // The root itself is a dangling path too.
        assert!(ctx.dangling(GIT_ROOT).is_some());
        // Outside every root: never.
        assert!(ctx.dangling(r"C:\Program Files\Other\x.exe").is_none());
        assert!(ctx.dangling(r"C:\Program Files\GitHub\x.exe").is_none());
    }

    /// §5.3: the nearest existing ancestor must be the root's recorded parent. While the root (or any
    /// part of it) still exists the app may still be installed, and a missing file inside it is not a
    /// dangling reference.
    #[test]
    fn nothing_is_dangling_inside_a_surviving_root() {
        let mut fixture = uninstalled();
        fixture.add_dir(&format!(r"{GIT_ROOT}\etc"));
        let world = World::new(fixture);
        let ctx = world.ctx();
        assert!(ctx.dangling(&format!(r"{GIT_ROOT}\cmd\git.exe")).is_none());
        assert!(
            ctx.dangling(&format!(r"{GIT_ROOT}\etc\gitconfig"))
                .is_none()
        );
        // What exists is not dangling.
        assert!(ctx.dangling(&format!(r"{GIT_ROOT}\etc")).is_none());
        // An empty root directory left behind is still a root that exists.
        let mut fixture = uninstalled();
        fixture.add_dir(GIT_ROOT);
        let world = World::new(fixture);
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
    }

    #[test]
    fn removable_volume_is_never_dangling() {
        for (fixed, fs) in [(false, "NTFS"), (true, "FAT32"), (true, "exFAT")] {
            let fixture = Fixture::builder()
                .dir(r"C:\Program Files")
                .volume(r"C:\", Some(SERIAL), fixed, fs)
                .build();
            let world = World::new(fixture);
            assert!(
                world
                    .ctx()
                    .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                    .is_none(),
                "fixed={fixed} fs={fs}"
            );
        }
    }

    #[test]
    fn serial_mismatch_is_never_dangling() {
        for serial in [Some(SERIAL + 1), None] {
            let fixture = Fixture::builder()
                .dir(r"C:\Program Files")
                .volume(r"C:\", serial, true, "NTFS")
                .build();
            let world = World::new(fixture);
            assert!(
                world
                    .ctx()
                    .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                    .is_none(),
                "{serial:?}"
            );
        }
        // No serial recorded at harvest: nothing to compare with.
        let mut world = World::new(uninstalled());
        world.fp.roots[0].volume_serial = None;
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
    }

    #[test]
    fn dangling_needs_the_recorded_parent_to_be_the_nearest_ancestor() {
        // `C:\Program Files` itself is missing: more than the app's tree is gone.
        let fixture = Fixture::builder()
            .dir(r"C:\Users")
            .volume(r"C:\", Some(SERIAL), true, "NTFS")
            .build();
        let world = World::new(fixture);
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
        // The parent did not exist at harvest.
        let mut world = World::new(uninstalled());
        world.fp.roots[0].parent_existed = false;
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
        // An unreadable location proves nothing.
        let fixture = Fixture::builder()
            .dir(r"C:\Program Files")
            .volume(r"C:\", Some(SERIAL), true, "NTFS")
            .denied(GIT_ROOT)
            .build();
        let world = World::new(fixture);
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
        // An inferred root gives no Tier A dangling evidence.
        let mut world = World::new(uninstalled());
        world.fp.roots[0].kind = RootKind::InferredRoot;
        assert!(
            world
                .ctx()
                .dangling(&format!(r"{GIT_ROOT}\git.exe"))
                .is_none()
        );
    }

    // ---- helpers -----------------------------------------------------------------------------------------

    #[test]
    fn inside_install_root_picks_the_deepest_install_root() {
        let mut world = World::new(uninstalled());
        world.fp.roots.push(Root {
            path: format!(r"{GIT_ROOT}\mingw64"),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::UserWritable,
            volume_serial: None,
            parent_existed: true,
        });
        let ctx = world.ctx();
        assert_eq!(ctx.inside_install_root(GIT_ROOT).unwrap().path, GIT_ROOT);
        assert_eq!(
            ctx.inside_install_root(r"c:\program files\git\MINGW64\bin\x.dll")
                .unwrap()
                .path,
            format!(r"{GIT_ROOT}\mingw64")
        );
        assert!(
            ctx.inside_install_root(r"C:\Program Files\GitHub")
                .is_none()
        );
        assert!(ctx.inside_install_root(r"C:\Program Files").is_none());
    }

    #[test]
    fn control_set_spellings_are_the_same_key() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let env = r"Control\Session Manager\Environment";
        assert!(ctx.same_key(
            &format!(r"HKLM\SYSTEM\CurrentControlSet\{env}"),
            &format!(r"hklm\system\ControlSet001\{env}")
        ));
        assert!(!ctx.same_key(
            &format!(r"HKLM\SYSTEM\CurrentControlSet\{env}"),
            &format!(r"HKLM\SYSTEM\ControlSet002\{env}")
        ));
        let seg = |path: String, index| Target::RegMultiSzSegment {
            path,
            name: "Path".into(),
            segment: format!(r"{GIT_ROOT}\cmd"),
            index,
        };
        assert!(ctx.same_target(
            &seg(format!(r"HKLM\SYSTEM\CurrentControlSet\{env}"), Some(7)),
            &seg(format!(r"HKLM\SYSTEM\ControlSet001\{env}"), None)
        ));
        assert!(!ctx.same_target(
            &seg(format!(r"HKLM\SYSTEM\ControlSet001\{env}"), Some(7)),
            &seg(format!(r"HKLM\SYSTEM\ControlSet001\{env}"), Some(8))
        ));
        assert!(!ctx.same_target(&key(r"HKLM\SOFTWARE\X"), &path(r"HKLM\SOFTWARE\X")));
    }

    /// `same_key` and `key_relation` walk the two keys; their definition is the folded key
    /// (`key_norm`): equal strings, and `prefix::relation` of the two.
    #[test]
    fn key_comparisons_equal_the_folded_keys() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let keys = [
            "",
            "HKLM",
            r"HKLM\SYSTEM",
            r"hklm\system",
            r"HKLM\SYSTEM\CurrentControlSet",
            r"HKLM\SYSTEM\currentcontrolset\Services",
            r"HKLM\SYSTEM\ControlSet001",
            r"hklm\System\controlset001\Services",
            r"HKLM\SYSTEM\ControlSet001\Services\Git",
            r"HKLM\SYSTEM\CurrentControlSet\Services\git",
            r"HKLM\SYSTEM\ControlSet002\Services\Git",
            r"HKLM\SYSTEM\ControlSet0010\Services",
            r"HKLM\SYSTEM\Select",
            // The alias holds only as the third segment of `HKLM\SYSTEM`.
            r"HKLM\SOFTWARE\ControlSet001",
            r"HKLM\SOFTWARE\CurrentControlSet",
            r"HKU\SYSTEM\ControlSet001",
            r"HKU\SYSTEM\CurrentControlSet",
            r"HKLM\SYSTEM\X\ControlSet001",
            r"HKLM\SYSTEM\X\CurrentControlSet",
            r"HKLM\SOFTWARE\Git",
            r"HKLM\SOFTWARE\\Git\",
            r"HKLM\software\GIT\Sub",
            r"HKLM\SOFTWARE\Gitx",
            // Names that are not ASCII: folded, and some Windows keeps apart.
            r"HKLM\SOFTWARE\Ärger",
            r"HKLM\SOFTWARE\ärger",
            r"HKLM\SOFTWARE\ÄRGER\Sub",
            r"HKLM\SOFTWARE\Straße",
            r"HKLM\SOFTWARE\STRASSE",
            "HKLM\\SOFTWARE\\\u{212A}elvin",
            r"HKLM\SOFTWARE\kelvin",
            "HKLM\\SOFTWARE\\\u{130}stanbul",
            r"HKLM\SOFTWARE\istanbul",
            "HKLM\\SOFTWARE\\\u{1F600}",
            "HKLM\\SYSTEM\\ControlSet00\u{661}",
        ];
        for a in keys {
            for b in keys {
                let (na, nb) = (ctx.key_norm(a), ctx.key_norm(b));
                assert_eq!(ctx.same_key(a, b), na == nb, "{a:?} {b:?}");
                assert_eq!(
                    ctx.key_relation(a, b),
                    prefix::relation(&na, &nb),
                    "{a:?} {b:?}"
                );
            }
        }
    }

    // ---- blockers ----------------------------------------------------------------------------------------

    #[test]
    fn common_blockers() {
        let shell = r"HKLM\SOFTWARE\Classes\Directory\shell";
        let ours = r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell";
        let ti_key = r"HKLM\SOFTWARE\Classes\.txt";
        let fixture = Fixture::builder()
            .key(shell)
            .key(ours)
            .key(ti_key)
            .ti_owned(ti_key, true)
            .link(
                r"HKLM\SOFTWARE\Linked",
                r"\Registry\Machine\SOFTWARE\Elsewhere",
            )
            .build();
        let mut world = World::new(fixture);
        world.baseline = Some(baseline(EDITION, &[shell, ti_key]));
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::RegDeleteValue,
            target: value(r"HKLM\SOFTWARE\Old", "Setting"),
            view: Some(View::K64),
            user_hive: false,
            existed_before: true,
            shared: false,
            key_create: false,
        }];
        world.other_apps = OtherApps::new(vec![OtherApp {
            name: "Mozilla Thunderbird".into(),
            roots: vec![r"C:\Program Files\Mozilla Thunderbird".into()],
            files: vec![r"C:\Program Files\Shared\uninstall\helper.exe".into()],
            keys: vec![r"HKLM\SOFTWARE\Mozilla\Thunderbird".into()],
            anchors: vec![AnchorRef {
                kind: AnchorKind::ProgId,
                text: "ThunderbirdEML".into(),
            }],
        }]);
        let ctx = world.ctx();
        let blockers = |target: Target, action: Action| {
            let mut b = ctx.candidate("T", target, action, Category::Registration);
            b.common_blockers();
            b.build().blockers
        };
        let other = || "Mozilla Thunderbird".to_owned();

        assert_eq!(
            blockers(key(shell), Action::DeleteKey),
            [Blocker::WindowsBaseline]
        );
        // A child of a baseline key may still go.
        assert!(blockers(key(ours), Action::DeleteKey).is_empty());
        assert_eq!(
            blockers(key(ti_key), Action::DeleteKey),
            [Blocker::WindowsBaseline, Blocker::TrustedInstallerOwned]
        );
        assert_eq!(
            blockers(value(ti_key, "x"), Action::DeleteValue),
            [Blocker::TrustedInstallerOwned]
        );
        assert_eq!(
            blockers(key(r"HKLM\SOFTWARE\Linked"), Action::DeleteKey),
            [Blocker::RegLink]
        );
        assert_eq!(
            blockers(value(r"hklm\software\old", "setting"), Action::DeleteValue),
            [Blocker::ExistedBeforeInstall]
        );
        assert_eq!(
            blockers(key(r"HKLM\SOFTWARE\Mozilla"), Action::RemoveDirIfEmpty),
            [Blocker::ContainsOtherApp { app: other() }]
        );
        assert_eq!(
            blockers(
                key(r"HKLM\SOFTWARE\Mozilla\Thunderbird\Main"),
                Action::DeleteKey
            ),
            [Blocker::InsideOtherApp { app: other() }]
        );
        // A value in another app's own key, or below it, is that app's.
        for inside in [
            r"HKLM\SOFTWARE\Mozilla\Thunderbird",
            r"hklm\software\mozilla\thunderbird\Main",
        ] {
            assert_eq!(
                blockers(value(inside, "x"), Action::DeleteValue),
                [Blocker::InsideOtherApp { app: other() }],
                "{inside}"
            );
            let segment = Target::RegMultiSzSegment {
                path: inside.into(),
                name: "Path".into(),
                segment: r"C:\Program Files\Git\cmd".into(),
                index: None,
            };
            assert_eq!(
                blockers(segment, Action::EditSegment),
                [Blocker::InsideOtherApp { app: other() }],
                "{inside}"
            );
        }
        // A value in a key that only contains another app's key is not blocked for that.
        assert!(blockers(value(r"HKLM\SOFTWARE\Mozilla", "x"), Action::DeleteValue).is_empty());
        assert_eq!(
            blockers(
                path(r"C:\Program Files\Mozilla Thunderbird\defaults"),
                Action::Quarantine
            ),
            [Blocker::InsideOtherApp { app: other() }]
        );
        assert_eq!(
            blockers(path(r"C:\Program Files\Shared"), Action::Quarantine),
            [Blocker::ContainsOtherApp { app: other() }]
        );
        assert_eq!(
            blockers(
                path(r"c:\program files\shared\uninstall\HELPER.exe"),
                Action::Quarantine
            ),
            [Blocker::ReferencedByOtherApp { app: other() }]
        );
        assert!(
            blockers(
                path(r"C:\Program Files\Mozilla Firefox"),
                Action::Quarantine
            )
            .is_empty()
        );
        assert_eq!(
            ctx.other_apps
                .anchor_blocker(AnchorKind::ProgId, "thunderbirdeml"),
            Some(Blocker::ReferencedByOtherApp { app: other() })
        );
        assert_eq!(
            ctx.other_apps
                .anchor_blocker(AnchorKind::Aumid, "ThunderbirdEML"),
            None
        );
    }

    #[test]
    fn not_gone_follows_verify_gone() {
        let mut world = World::new(uninstalled());
        let build = |world: &World| {
            let ctx = world.ctx();
            let mut b = ctx.candidate(
                "FS-INSTALLDIR",
                path(GIT_ROOT),
                Action::Quarantine,
                Category::AppFiles,
            );
            b.require_verify_gone();
            b.build().blockers
        };
        assert!(build(&world).is_empty());
        world.verify_gone = Some(VerifyGone::new(true, true, false));
        assert_eq!(build(&world), [Blocker::NotGone]);
        world.verify_gone = None;
        assert_eq!(build(&world), [Blocker::NotGone]);
    }

    #[test]
    fn identity_view_is_built_from_the_fingerprint() {
        let world = World::new(uninstalled());
        let view = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        assert_eq!(view.app, world.fp.app);
        assert!(
            view.refs
                .is_match(&format!(r#""{GIT_ROOT}\cmd\git.exe" --version"#))
        );
        assert!(!view.refs.is_match(r"C:\Program Files\GitHub\x.exe"));
    }

    // ---- whose a registration is ---------------------------------------------------------------------------

    fn recorded_value(key: &str, name: &str) -> InnoRecord {
        InnoRecord {
            kind: InnoRecordKind::RegDeleteValue,
            target: value(key, name),
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: false,
        }
    }

    fn recorded_key(key: &str) -> InnoRecord {
        InnoRecord {
            kind: InnoRecordKind::RegDeleteEntireKey,
            target: self::key(key),
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: true,
        }
    }

    /// A file the log names counts only when the record says the installer created it.
    #[test]
    fn a_logged_file_that_existed_before_or_is_shared_is_not_the_installers() {
        let lnk = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\Git Tray.lnk";
        let record = |existed_before: bool, shared: bool| InnoRecord {
            kind: InnoRecordKind::DeleteFile,
            target: Target::Path { path: lnk.into() },
            view: None,
            user_hive: false,
            existed_before,
            shared,
            key_create: false,
        };
        let mut world = World::new(uninstalled());
        for (existed_before, shared, logged) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
        ] {
            world.fp.inno = vec![record(existed_before, shared)];
            assert_eq!(
                world.ctx().installer_logged_file(&lnk.to_uppercase()),
                logged,
                "existed_before={existed_before} shared={shared}"
            );
        }
        // A record of another kind on the path is no file record.
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::DeleteDirOrFiles,
            ..record(false, false)
        }];
        assert!(!world.ctx().installer_logged_file(lnk));
    }

    /// The VM campaign's rows (x0-git-userstate, x0-git-toolsdir): values the user or another program
    /// wrote, which only point at Git.
    #[test]
    fn a_value_that_points_at_the_app_is_not_the_apps_registration() {
        // Every view below Exact takes the no-baseline path (presence-only, design L5).
        for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
            let user = format!(r"HKU\{SID}");
            let mut world = World::new(uninstalled());
            world.fp.exes = vec![purge_model::ExeFile {
                path: format!(r"{GIT_ROOT}\git-bash.exe"),
                main: true,
            }];
            world.fp.anchors.progids = vec!["GitBash.Document".into()];
            world.fp.inno = vec![
                recorded_value(
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "GitTray",
                ),
                recorded_key(r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell"),
            ];
            let ctx = world.ctx();
            let foreign = [
                (format!(r"{user}\Software\TortoiseGit"), "MSysGit"),
                (
                    format!(r"{user}\Software\ContosoTools\Settings"),
                    "GitExecutable",
                ),
                (
                    format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\Run"),
                    "GitAutoFetch",
                ),
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_owned(),
                    "Backup",
                ),
                (format!(r"{user}\Environment"), "Path"),
                (format!(r"{user}\Environment"), "GIT_SSH"),
                (
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment".to_owned(),
                    "Path",
                ),
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\rg.exe".to_owned(),
                    "",
                ),
                (
                    format!(r"{user}\Software\Microsoft\RestartManager\Session0000"),
                    "RegFiles0000",
                ),
                (
                    r"HKLM\SOFTWARE\Classes\Directory\shell\my_verb\command".to_owned(),
                    "",
                ),
                // Below a key the installer deletes whole: the record is about that key, and does not
                // say who made the subkey.
                (
                    r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell\command".to_owned(),
                    "",
                ),
                (
                    r"HKLM\SOFTWARE\Classes\txtfile\shell\open\command".to_owned(),
                    "",
                ),
                (r"HKLM\SOFTWARE\RegisteredApplications".to_owned(), "Git"),
                (r"HKLM\SOFTWARE\Policies\Git".to_owned(), "Path"),
            ];
            for (key, name) in &foreign {
                assert!(!ctx.owns_registration(key, name), "{key}|{name}");
            }
            let own = [
                // The installer's record: the value itself, or the key it deletes whole.
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_owned(),
                    "GitTray",
                ),
                (
                    r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell".to_owned(),
                    "Icon",
                ),
                // The app's own ProgID, Uninstall key, App Paths key and settings key.
                (
                    r"HKLM\SOFTWARE\Classes\GitBash.Document\shell\open\command".to_owned(),
                    "",
                ),
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1".to_owned(),
                    "InstallLocation",
                ),
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\git-bash.exe"
                        .to_owned(),
                    "",
                ),
                (
                    r"HKLM\SOFTWARE\The Git Development Community\Settings".to_owned(),
                    "Path",
                ),
            ];
            // Dirty-base runs f0d-git, f0d-npp, f0d-vlc: slot 15 of Windows' ring of new Start-menu
            // shortcuts held another product's record before the install reused it.
            assert!(!ctx.owns_registration(
                &format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\UFH\SHC"),
                "15"
            ));
            for (key, name) in &own {
                assert!(ctx.owns_registration(key, name), "{key}|{name}");
            }
            // A key of the baseline is Windows' own: the record on it vouches for no value in it.
            let git_shell = r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell";
            world.baseline = Some(baseline(EDITION, &[git_shell]));
            assert!(!world.ctx().owns_registration(git_shell, "Icon"));
            // Without a baseline the key record is a hint, no proof; the value record stays.
            world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
            let ctx = world.ctx();
            assert!(
                !ctx.owns_registration(r"HKLM\SOFTWARE\Classes\Directory\shell\git_shell", "Icon")
            );
            assert!(ctx.owns_registration(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "GitTray"
            ));
        }
    }

    /// Reference evidence keeps its Tier A in the app's own key and drops to Tier B, marked, anywhere
    /// else: whoever wrote the value, it cannot make the candidate Safe.
    #[test]
    fn reference_evidence_in_a_shared_place_is_tier_b() {
        let user = format!(r"HKU\{SID}");
        let git = format!(r"{GIT_ROOT}\cmd\git.exe");
        let theirs = value(&format!(r"{user}\Software\TortoiseGit"), "MSysGit");
        let own = value(
            r"HKLM\SOFTWARE\The Git Development Community",
            "InstallPath",
        );
        let mut world = World::new(uninstalled());
        world.fp.ref_snapshot = [&theirs, &own]
            .into_iter()
            .map(|target| RefSnapEntry {
                target: target.clone(),
                carrier: RefCarrier::Data,
                anchor: AnchorRef {
                    kind: AnchorKind::Root,
                    text: GIT_ROOT.into(),
                },
                parent_values: 1,
                parent_subkeys: 0,
                data_hash: None,
            })
            .collect();
        let ctx = world.ctx();
        let build = |target: &Target| {
            let mut b = ctx.candidate(
                "T",
                target.clone(),
                Action::DeleteValue,
                Category::Registration,
            );
            assert!(b.in_ref_snapshot());
            assert!(b.points_into_install_root(&git));
            assert!(b.dangling_ref(&ctx.dangling(&git).unwrap()));
            b.build()
        };
        let c = build(&theirs);
        assert_eq!(c.evidence.len(), 3);
        for e in &c.evidence {
            assert_eq!(e.tier, Tier::B, "{:?}", e.kind);
            assert_eq!(e.detail.get(SHARED_PLACE_KEY), Some(SHARED_PLACE_VALUE));
        }
        let c = build(&own);
        for e in &c.evidence {
            assert_eq!(e.tier, Tier::A, "{:?}", e.kind);
            assert_eq!(e.detail.get(SHARED_PLACE_KEY), None);
        }
    }

    /// VM run x0-nb-git: `HKLM\SOFTWARE\Classes\sh_auto_file` went Safe on the installer's key record
    /// alone, on a Windows without a matching baseline.
    #[test]
    fn a_key_record_without_a_baseline_is_tier_b() {
        // Every view below Exact takes the no-baseline path (presence-only, design L5).
        for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
            let sh = r"HKLM\SOFTWARE\Classes\sh_auto_file";
            let mut world = World::new(uninstalled());
            world.fp.inno = vec![
                recorded_key(sh),
                recorded_value(r"HKLM\SOFTWARE\Classes\.sh", "Content Type"),
            ];
            let manifest = |world: &World, target: Target, action: Action| {
                let ctx = world.ctx();
                let mut b = ctx.candidate("T", target, action, Category::Registration);
                assert!(b.installer_manifest());
                b.build().evidence.remove(0)
            };
            let e = manifest(&world, key(sh), Action::DeleteKey);
            assert_eq!((e.tier, e.scope), (Tier::A, Scope::Key));
            assert_eq!(e.detail.get("baseline"), None);

            world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
            let e = manifest(&world, key(sh), Action::DeleteKey);
            assert_eq!((e.tier, e.scope), (Tier::B, Scope::Key));
            assert_eq!(e.detail.get("baseline"), Some("none"));
            // A value record names the value the installer wrote: it needs no baseline.
            let e = manifest(
                &world,
                value(r"HKLM\SOFTWARE\Classes\.sh", "Content Type"),
                Action::DeleteValue,
            );
            assert_eq!((e.tier, e.scope), (Tier::A, Scope::Value));
        }
    }

    // ---- the baseline view: presence, the capped path, the carrier, the seal -------------------------

    const SH_AUTO: &str = r"HKLM\SOFTWARE\Classes\sh_auto_file";
    const WINDOWS_KEY: &str = r"HKLM\SOFTWARE\Classes\Windows.Document";

    /// The band and the tick the real policy gives `c` after an uninstall that verified gone.
    fn band_of(c: &Candidate, trust: BaselineTrust) -> (purge_model::Band, bool) {
        use purge_policy::band::{PolicyCtx, TargetScope, decide};
        let d = decide(
            c,
            &PolicyCtx {
                baseline_trust: trust,
                mode: ScanMode::Post,
                verify_gone: VerifyGone::new(true, true, true),
                target_scope: TargetScope::Machine,
            },
        );
        (d.band, d.preselected)
    }

    /// `ProvenOwnedSkeleton` on a key, as a site that took absence for proof would add it.
    fn skeleton_evidence(key: &str) -> Evidence {
        Evidence::new(
            EvidenceKind::ProvenOwnedSkeleton,
            Scope::Key,
            SourceTrust::AdminOnly,
            format!("subtree:{key}"),
        )
        .expect("a key-scope skeleton")
        .with_detail(Facts::new().with("key", key).with("via", "subtree"))
    }

    /// Every view below Exact, each holding [`WINDOWS_KEY`] in one of its sets, with its trust.
    fn views_below_exact() -> Vec<(BaselineView, BaselineTrust)> {
        vec![
            (merged_view(&[WINDOWS_KEY], &[]), BaselineTrust::Merged),
            (merged_view(&[], &[WINDOWS_KEY]), BaselineTrust::Merged),
            (local_view(&[WINDOWS_KEY]), BaselineTrust::Local),
            (none_view(&[WINDOWS_KEY]), BaselineTrust::None),
        ]
    }

    /// L3 and the presence-only rule at the one door: an Exact view proves, a view below Exact never
    /// hands out absence (although the view itself infers it under the open test rules), and
    /// presence blocks at every trust.
    #[test]
    fn the_capped_path_never_hands_out_inferred_absence() {
        let mut world = World::new(uninstalled());

        // Exact: what the baseline itself says.
        world.baseline = Some(baseline(EDITION, &[WINDOWS_KEY]));
        let ctx = world.ctx();
        assert_eq!(ctx.key_absence(SH_AUTO), Absence::Proven);
        assert_eq!(ctx.key_absence(WINDOWS_KEY), Absence::Present);
        assert_eq!(
            ctx.key_absence(r"HKLM\SYSTEM\CurrentControlSet\Enum\X"),
            Absence::Unknown,
            "outside the capture scope"
        );
        assert!(ctx.has_exact_baseline() && ctx.has_matching_exact_baseline());
        assert_eq!(ctx.absence_trust(), BaselineTrust::Exact);

        // An exact baseline of another Windows proves nothing here (review BL-R1 S2): both gates are
        // false, absence is unknown, the policy is handed no trust. What it has is still presence.
        world.baseline = Some(baseline("EnterpriseS", &[WINDOWS_KEY]));
        let ctx = world.ctx();
        assert_eq!(ctx.baseline.trust(), BaselineTrust::Exact);
        assert_eq!(ctx.baseline.key_absent(SH_AUTO), Absence::Proven);
        assert!(!ctx.has_exact_baseline() && !ctx.has_matching_exact_baseline());
        assert!(ctx.has_foreign_exact_baseline());
        assert_eq!(ctx.key_absence(SH_AUTO), Absence::Unknown);
        assert_eq!(ctx.key_absence(WINDOWS_KEY), Absence::Present);
        assert_eq!(ctx.absence_trust(), BaselineTrust::None);
        assert!(!ctx.key_record_covers(SH_AUTO));
        assert!(!ctx.key_record_covers(r"HKLM\SYSTEM\CurrentControlSet\Enum\X"));
        assert!(ctx.in_baseline(&key(WINDOWS_KEY)));
        // The same baseline for its own Windows: the gates are true and it proves.
        world.baseline = Some(baseline(EDITION, &[WINDOWS_KEY]));
        let ctx = world.ctx();
        assert!(!ctx.has_foreign_exact_baseline());
        assert!(ctx.key_record_covers(SH_AUTO));
        assert!(ctx.key_record_covers(r"HKLM\SYSTEM\CurrentControlSet\Enum\X"));

        for (view, trust) in views_below_exact() {
            // The view itself: inferred where its trust and the (open) rules allow.
            let own = view.key_absent(SH_AUTO);
            if trust.is_inferred() {
                assert_eq!(own, Absence::Inferred(trust));
            } else {
                assert_eq!(own, Absence::Unknown);
            }
            world.baseline = Some(view);
            let ctx = world.ctx();
            // A: nothing below Exact.
            assert_eq!(ctx.key_absence(SH_AUTO), Absence::Unknown, "{trust}");
            assert!(!ctx.has_exact_baseline() && !ctx.has_matching_exact_baseline());
            assert_eq!(ctx.absence_trust(), BaselineTrust::None);
            // P: the union, at every trust.
            assert_eq!(ctx.key_absence(WINDOWS_KEY), Absence::Present, "{trust}");
            assert!(ctx.in_baseline(&key(WINDOWS_KEY)), "{trust}");
            assert!(!ctx.in_baseline(&key(SH_AUTO)));
            let mut b = ctx.candidate(
                "T",
                key(WINDOWS_KEY),
                Action::DeleteKey,
                Category::Registration,
            );
            b.baseline_blocker();
            assert_eq!(b.build().blockers, [Blocker::WindowsBaseline], "{trust}");
        }

        // No baseline at all.
        world.baseline = None;
        let ctx = world.ctx();
        assert_eq!(ctx.key_absence(SH_AUTO), Absence::Unknown);
        assert!(!ctx.in_baseline(&key(WINDOWS_KEY)));
        assert_eq!(ctx.absence_trust(), BaselineTrust::None);
    }

    /// BL-GATE S1 (frozen runs `7zip`, `git`, `m1bcp-7zip`, local view): a slot of a user's
    /// numbered-slot store is Windows' own below Exact, whatever the view holds and with no view at
    /// all; the exact baseline of this Windows still tells a new slot from one its capture holds.
    #[test]
    fn a_user_slot_is_windows_own_below_exact() {
        let user = format!(r"HKU\{}", GuardEnv::SAMPLE_SID);
        let shc = format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\UFH\SHC");
        assert!(is_user_slot_store(&shc));
        assert!(is_user_slot_store(
            r"hkcu\software\microsoft\windows\currentversion\ufh\shc"
        ));
        assert!(is_user_slot_store(
            r"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\UFH\SHC"
        ));
        for other in [
            format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\UFH"),
            format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\UFH\SHC\0"),
            format!(r"{user}_Classes\Software\Microsoft\Windows\CurrentVersion\UFH\SHC"),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\SHC".to_owned(),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\ARP".to_owned(),
        ] {
            assert!(!is_user_slot_store(&other), "{other}");
        }
        let slot = |name: &str| Target::RegValue {
            path: shc.clone(),
            name: name.into(),
        };
        let held = purge_index::baseline_view::fixture::value_entry(&shc, "0");
        let mut world = World::new(uninstalled());
        // Exact: the capture's slot is Windows' own, a slot it lacks is not.
        world.baseline = Some(baseline(EDITION, &[&held]));
        let ctx = world.ctx();
        assert!(ctx.in_baseline(&slot("0")));
        assert!(!ctx.in_baseline(&slot("1")));
        // Below Exact, another Windows' baseline and no baseline: every slot, nothing else.
        let mut below: Vec<Option<BaselineView>> = views_below_exact()
            .into_iter()
            .map(|(v, _)| Some(v))
            .collect();
        below.extend([
            Some(local_view(&[])),
            Some(merged_view(&[], &[&held])),
            Some(baseline("EnterpriseS", &[&held])),
            None,
        ]);
        for view in below {
            world.baseline = view;
            let ctx = world.ctx();
            for name in ["0", "1", "15"] {
                assert!(ctx.in_baseline(&slot(name)), "{}", ctx.baseline.name());
            }
            assert!(!ctx.in_baseline(&Target::RegValue {
                path: format!(r"{user}\Software\Microsoft\Windows\CurrentVersion\Run"),
                name: "0".into(),
            }));
            assert!(!ctx.in_baseline(&Target::RegMultiSzSegment {
                path: shc.clone(),
                name: "0".into(),
                segment: r"C:\Program Files\Git\git-bash.exe".into(),
                index: None,
            }));
            let mut b = ctx.candidate("T", slot("1"), Action::DeleteValue, Category::Privacy);
            b.baseline_blocker();
            assert_eq!(b.build().blockers, [Blocker::WindowsBaseline]);
        }
    }

    /// The A sites of the framework below Exact, with the view saying the key is Windows' own or
    /// saying nothing: the key record vouches for no value, is Tier B itself, and a token names no
    /// key. A token a set of the view knows is nobody's on any target (presence).
    #[test]
    fn framework_sites_below_exact_take_the_no_baseline_path() {
        let token = "308046B0AF4A39CB";
        let named = format!(r"HKLM\SOFTWARE\Classes\FirefoxHTML-{token}");
        let shipped = format!(r"HKLM\SOFTWARE\Microsoft\Shipped\{token}");
        let views = vec![
            merged_view(&[], &[]),
            merged_view(&[SH_AUTO], &[]),
            local_view(&[]),
            none_view(&[SH_AUTO]),
        ];
        for view in views {
            let mut world = World::new(uninstalled());
            world.fp.inno = vec![recorded_key(SH_AUTO)];
            world.fp.tokens = vec![HarvestedToken {
                token: token.into(),
                source: "arp:key".into(),
            }];
            // With the exact baseline the record covers the value and the token names the key.
            assert!(world.ctx().installer_recorded_value(SH_AUTO, "x"));
            world.baseline = Some(view);
            let ctx = world.ctx();
            assert!(!ctx.installer_recorded_value(SH_AUTO, "x"));
            let mut b = ctx.candidate("T", key(SH_AUTO), Action::DeleteKey, Category::Registration);
            assert!(b.installer_manifest());
            let c = b.build();
            assert_eq!(c.evidence[0].tier, Tier::B);
            assert_eq!(
                c.evidence[0].detail.get(BASELINE_FACT),
                Some(BASELINE_FACT_NONE)
            );
            assert!(
                !ctx.baseline_cap_missing(&c),
                "the no-baseline form claims nothing"
            );
            let mut b = ctx.candidate("T", key(&named), Action::DeleteKey, Category::Registration);
            assert!(!b.harvested_token(token));
            let mut b = ctx.candidate(
                "T",
                value(r"HKLM\SOFTWARE\RegisteredApplications", &named),
                Action::DeleteValue,
                Category::Registration,
            );
            assert!(b.harvested_token(token));
        }
        // Presence: the local baseline or a neighbour knows the token.
        for view in [
            merged_view(&[&shipped], &[]),
            merged_view(&[], &[&shipped]),
            local_view(&[&shipped]),
            none_view(&[&shipped]),
        ] {
            let mut world = World::new(uninstalled());
            world.fp.tokens = vec![HarvestedToken {
                token: token.into(),
                source: "arp:key".into(),
            }];
            world.baseline = Some(view);
            let ctx = world.ctx();
            let mut b = ctx.candidate(
                "T",
                value(r"HKLM\SOFTWARE\RegisteredApplications", &named),
                Action::DeleteValue,
                Category::Registration,
            );
            assert!(!b.harvested_token(token));
        }
    }

    /// The carrier (§4.4 layer 1): an inferred answer adds the soft blocker and the facts to the
    /// absence-dependent evidence, whichever comes first; the evidence keeps its tier; the item is
    /// Likely and not ticked, with the backstop on or off. Any other answer changes nothing.
    #[test]
    fn the_carrier_caps_inferred_absence() {
        let mut world = World::new(uninstalled());
        world.baseline = Some(merged_view(&[], &[]));
        let ctx = world.ctx();
        let inferred = ctx.baseline.key_absent(SH_AUTO);
        assert_eq!(inferred, Absence::Inferred(BaselineTrust::Merged));

        for absence_first in [false, true] {
            let mut b = ctx.candidate("T", key(SH_AUTO), Action::DeleteKey, Category::Registration);
            if absence_first {
                b.absence(inferred);
            }
            b.push_evidence(skeleton_evidence(SH_AUTO));
            if !absence_first {
                b.absence(inferred);
            }
            let c = b.build();
            assert_eq!(c.blockers, [Blocker::BaselineInferred]);
            let e = &c.evidence[0];
            assert_eq!(
                (e.kind, e.tier),
                (EvidenceKind::ProvenOwnedSkeleton, Tier::A)
            );
            assert_eq!(
                e.detail.get(BASELINE_FACT),
                Some("local-Professional-26340.9882+1")
            );
            assert_eq!(e.detail.get(BASELINE_TRUST_FACT), Some("merged"));
            assert_eq!(
                e.detail.get(BASELINE_NEIGHBOURS_FACT),
                Some("Professional-26341.9882")
            );
            assert_eq!(e.detail.get(WINDOWS_BUILD_FACT), Some("26340.9882"));
            assert_eq!(
                e.detail.get("via"),
                Some("subtree"),
                "the site's facts stay"
            );
            assert!(!c.lacks_baseline_cap() && !ctx.baseline_cap_missing(&c));
            for trust in [
                BaselineTrust::None,
                BaselineTrust::Merged,
                BaselineTrust::Exact,
            ] {
                assert_eq!(
                    band_of(&c, trust),
                    (purge_model::Band::Likely, false),
                    "{trust}"
                );
            }
        }

        // The same evidence from proof is Safe and ticked: the cap is what the carrier adds.
        let mut b = ctx.candidate("T", key(SH_AUTO), Action::DeleteKey, Category::Registration);
        b.push_evidence(skeleton_evidence(SH_AUTO));
        for answer in [Absence::Proven, Absence::Present, Absence::Unknown] {
            b.absence(answer);
        }
        let c = b.build();
        assert!(c.blockers.is_empty());
        assert_eq!(c.evidence, [skeleton_evidence(SH_AUTO)]);
        assert_eq!(
            band_of(&c, BaselineTrust::Exact),
            (purge_model::Band::Safe, true)
        );
        // The policy backstop alone (P-BL-1) already refuses it under an inferred trust.
        assert_ne!(
            band_of(&c, BaselineTrust::Merged).0,
            purge_model::Band::Safe
        );

        // Evidence that does not rest on absence gets no fact, and a value target no blocker-less
        // surprise: the blocker is the candidate's, the facts are the key evidence's.
        let mut b = ctx.candidate(
            "T",
            value(SH_AUTO, "x"),
            Action::DeleteValue,
            Category::Registration,
        );
        b.absence(Absence::Inferred(BaselineTrust::Local));
        b.push_evidence(
            Evidence::new(
                EvidenceKind::InPreUninstallRefSnapshot,
                Scope::Value,
                SourceTrust::AdminOnly,
                "refsnap".to_owned(),
            )
            .expect("value-scope evidence"),
        );
        let c = b.build();
        assert_eq!(c.blockers, [Blocker::BaselineInferred]);
        assert_eq!(c.evidence[0].detail.get(BASELINE_TRUST_FACT), None);
    }

    /// What the seal looks at (§4.4 layer 2): under a view of trust Merged or Local, a key candidate
    /// whose evidence claims baseline absence and that lacks the blocker. The forms the no-baseline
    /// paths make claim nothing; neither does anything under an Exact view or a view of trust None.
    #[test]
    fn the_seal_tells_a_claimed_absence_from_the_no_baseline_forms() {
        let mut world = World::new(uninstalled());
        let ev = |kind: EvidenceKind, scope: Scope, facts: Facts| {
            Evidence::new(kind, scope, SourceTrust::AdminOnly, "t".to_owned())
                .expect("the scope is allowed")
                .with_detail(facts)
        };
        let none_fact = || Facts::new().with(BASELINE_FACT, BASELINE_FACT_NONE);
        let inno = EvidenceKind::InstallerManifest(ManifestKind::Inno);
        let msi = EvidenceKind::InstallerManifest(ManifestKind::Msi);
        // (evidence, claims absence on a key)
        let cases = vec![
            (
                ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key, Facts::new()),
                true,
            ),
            (
                ev(EvidenceKind::HarvestedToken, Scope::Key, Facts::new()),
                true,
            ),
            (
                ev(EvidenceKind::ComKeyOwnership, Scope::Key, Facts::new()),
                true,
            ),
            (
                ev(EvidenceKind::ComKeyOwnership, Scope::Key, none_fact()),
                false,
            ),
            (ev(inno, Scope::Key, Facts::new()), true),
            (ev(inno, Scope::Key, none_fact()), false),
            // The carrier's fact without the blocker: a claim, whatever the kind says.
            (
                ev(
                    inno,
                    Scope::Key,
                    none_fact().with(BASELINE_TRUST_FACT, "merged"),
                ),
                true,
            ),
            // Sites that never ask the baseline.
            (ev(msi, Scope::Key, Facts::new()), false),
            (
                ev(EvidenceKind::ChainedRef, Scope::Key, Facts::new()),
                false,
            ),
            (
                ev(
                    EvidenceKind::InPreUninstallRefSnapshot,
                    Scope::Value,
                    Facts::new(),
                ),
                false,
            ),
        ];
        let candidate = |world: &World, target: Target, e: &Evidence, capped: bool| {
            let ctx = world.ctx();
            let mut b = ctx.candidate("T", target, Action::DeleteKey, Category::Registration);
            b.push_evidence(e.clone());
            if capped {
                b.blocker(Blocker::BaselineInferred);
            }
            b.build()
        };
        for (e, claims) in &cases {
            assert_eq!(claims_absence(e, &key(SH_AUTO)), *claims, "{e:?}");
            // Never on a value: absence is a fact about keys.
            assert!(!claims_absence(e, &value(SH_AUTO, "x")), "{e:?}");

            for (view, trust) in views_below_exact() {
                world.baseline = Some(view);
                let c = candidate(&world, key(SH_AUTO), e, false);
                assert_eq!(
                    world.ctx().baseline_cap_missing(&c),
                    *claims && trust.is_inferred(),
                    "{trust}: {e:?}"
                );
                let capped = candidate(&world, key(SH_AUTO), e, true);
                assert!(!world.ctx().baseline_cap_missing(&capped), "{trust}: {e:?}");
            }
            // Exact: the claim is proof; no baseline: there is no claim to make.
            for exact in [Some(baseline(EDITION, &[])), None] {
                world.baseline = exact;
                let c = candidate(&world, key(SH_AUTO), e, false);
                assert!(!world.ctx().baseline_cap_missing(&c), "{e:?}");
            }
        }
    }

    /// Emits one key candidate with `ProvenOwnedSkeleton`, with or without the carrier.
    struct ClaimsAbsence {
        carried: bool,
    }

    impl Scanner for ClaimsAbsence {
        fn id(&self) -> &'static str {
            "TEST-CLAIMS-ABSENCE"
        }

        fn captured_roots(&self) -> &[RootSpec] {
            &[]
        }

        fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
            let mut b = ctx.candidate(
                self.id(),
                key(SH_AUTO),
                Action::DeleteKey,
                Category::Registration,
            );
            b.push_evidence(skeleton_evidence(SH_AUTO));
            if self.carried {
                b.absence(ctx.baseline.key_absent(SH_AUTO));
            }
            vec![b.build()]
        }
    }

    /// The seal in [`ScanCtx::run`]: with the carrier the candidate leaves the scan capped; under an
    /// Exact view and without a baseline the seal does not act.
    #[test]
    fn run_lets_a_capped_or_proven_key_through() {
        let mut world = World::new(uninstalled());
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        world.baseline = Some(merged_view(&[], &[]));
        let found = world.ctx().run(&ClaimsAbsence { carried: true }, &app);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].blockers, [Blocker::BaselineInferred]);
        for baseline in [Some(baseline(EDITION, &[])), None, Some(none_view(&[]))] {
            world.baseline = baseline;
            let found = world.ctx().run(&ClaimsAbsence { carried: false }, &app);
            assert_eq!(found.len(), 1);
            assert!(found[0].blockers.is_empty());
        }
    }

    /// The seal in [`ScanCtx::run`]: a key that claims absence under a Merged view without the
    /// carrier is dropped and reported as a scanner fault. A debug build fails on it outright.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "without the BaselineInferred cap")
    )]
    fn run_drops_a_key_that_claims_absence_without_the_cap() {
        let mut world = World::new(uninstalled());
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        world.baseline = Some(merged_view(&[], &[]));
        let found = world.ctx().run(&ClaimsAbsence { carried: false }, &app);
        // Release builds: dropped, with the fault for the scan's warnings.
        assert!(found.is_empty());
        let faults = ScanExt::none().take_faults();
        assert!(
            faults
                .iter()
                .any(|f| f.starts_with("TEST-CLAIMS-ABSENCE: dropped")
                    && f.contains("trust merged")
                    && f.contains("without the BaselineInferred cap")),
            "{faults:?}"
        );
    }

    /// Asks `key_absence` for each key and emits nothing. The answer is only recorded for the residue
    /// while `ScanCtx::run` attributes the calls to this scanner.
    struct AskKeys(Vec<String>);

    impl Scanner for AskKeys {
        fn id(&self) -> &'static str {
            "TEST-RESIDUE"
        }

        fn captured_roots(&self) -> &[RootSpec] {
            &[]
        }

        fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
            for key in &self.0 {
                let _ = ctx.key_absence(key);
            }
            Vec::new()
        }
    }

    /// Design §7: every `Unknown` an A site gets is in the residue once, with the site and the reason;
    /// the output is capped and the rest is counted.
    #[test]
    fn residue_collects_unknown_answers_per_site_and_caps_them() {
        let mut world = World::new(uninstalled());
        world.baseline = None;
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        let ext = ScanExt::new(
            purge_index::ownership::OwnershipIndex::default(),
            purge_index::sysobj::SysObjectIndex::default(),
        );
        let ctx = ScanCtx {
            ext: &ext,
            ..world.ctx()
        };
        let keys = vec![
            SH_AUTO.to_owned(),
            r"HKLM\SOFTWARE\GitForWindows".to_owned(),
        ];
        ctx.run(&AskKeys(keys.clone()), &app);
        ctx.run(&AskKeys(keys), &app);
        let doc = ctx.residue_doc("scan-1", &[], ext.take_unknown());
        doc.validate().unwrap();
        assert_eq!(doc.scan_id, "scan-1");
        assert_eq!(doc.items.len(), 2, "{doc:#?}");
        assert_eq!(doc.omitted, 0);
        for item in &doc.items {
            assert_eq!(item.site, "TEST-RESIDUE");
            assert_eq!(item.why, ResidueWhy::NoView);
            assert!(item.id.starts_with("c-"), "{item:?}");
            assert!(item.item_fp.is_empty());
            assert!(!item.shape.in_local);
            assert!(item.shape.in_neighbours.is_empty());
        }

        let many: Vec<(String, String, ResidueWhy)> = (0..MAX_RESIDUE_ITEMS + 5)
            .map(|i| {
                (
                    "TEST-RESIDUE".to_owned(),
                    format!(r"HKLM\SOFTWARE\Vendor{i}"),
                    ResidueWhy::OutOfScope,
                )
            })
            .collect();
        let doc = ctx.residue_doc("scan-1", &[], many);
        assert_eq!(doc.items.len(), MAX_RESIDUE_ITEMS);
        assert_eq!(doc.omitted, 5);
    }

    /// The four reasons of design §7 are told apart at the one door.
    #[test]
    fn residue_why_distinguishes_no_view_scope_area_and_inference() {
        let ask = |world: &World, key: &'static str| {
            let ext = ScanExt::new(
                purge_index::ownership::OwnershipIndex::default(),
                purge_index::sysobj::SysObjectIndex::default(),
            );
            let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
            let ctx = ScanCtx {
                ext: &ext,
                ..world.ctx()
            };
            let scanner = AskKeys(vec![key.to_owned()]);
            ctx.run(&scanner, &app);
            let doc = ctx.residue_doc("s", &[], ext.take_unknown());
            doc.items.first().map(|item| item.why)
        };

        let mut world = World::new(uninstalled());
        world.baseline = None;
        assert_eq!(ask(&world, SH_AUTO), Some(ResidueWhy::NoView));

        world.baseline = Some(merged_view(&[], &[]));
        assert_eq!(ask(&world, SH_AUTO), Some(ResidueWhy::InferredAbsent));
        assert_eq!(
            ask(&world, r"HKLM\HARDWARE\X"),
            Some(ResidueWhy::OutOfScope)
        );
        world.baseline = Some(baseline(EDITION, &[]));
        assert_eq!(ask(&world, SH_AUTO), None, "Proven is no residue");
        world.baseline = Some(baseline("EnterpriseS", &[]));
        assert_eq!(ask(&world, SH_AUTO), Some(ResidueWhy::NoView));
    }

    /// A candidate that carries `BaselineInferred` is in the residue even when no site asked, with its
    /// own id and `item_fp`; a key no site asked about keeps its reason.
    #[test]
    fn residue_lists_baseline_inferred_candidates() {
        let world = World::new(uninstalled());
        let ctx = world.ctx();
        let mut b = ctx.candidate(
            "TEST",
            key(SH_AUTO),
            Action::DeleteKey,
            Category::Registration,
        );
        b.blocker(Blocker::BaselineInferred);
        let candidate = b.build();
        let doc = ctx.residue_doc(
            "s",
            std::slice::from_ref(&candidate),
            vec![(
                "TEST".to_owned(),
                r"HKLM\SOFTWARE\Other".to_owned(),
                ResidueWhy::AreaNotAccepted,
            )],
        );
        assert_eq!(doc.items.len(), 2);
        let carried = doc
            .items
            .iter()
            .find(|item| item.id == candidate.id.0)
            .expect("the candidate is listed");
        assert_eq!(carried.why, ResidueWhy::InferredAbsent);
        assert_eq!(
            carried.key.to_lowercase(),
            SH_AUTO.to_lowercase(),
            "{carried:?}"
        );
        assert!(
            doc.items
                .iter()
                .any(|item| item.why == ResidueWhy::AreaNotAccepted)
        );
    }
}
