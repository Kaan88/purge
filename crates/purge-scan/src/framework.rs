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
use purge_index::matcher::{AnchorSet, RefMatcher};
use purge_model::{
    Action, AnchorKind, AnchorRef, AppRef, Blocker, Candidate, CandidateId, Category, Evidence,
    EvidenceKind, Facts, FileTime, Fingerprint, Harm, InnoRecord, InnoRecordKind, ManifestKind,
    Origin, RefSnapEntry, Reversibility, Root, RootKind, RootSource, ScanMode, Scope, SourceTrust,
    Target, Tier, VerifyGone,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::ExistsState;

use crate::skeleton;

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
    /// The clean-Windows baseline of exactly this (edition, build.ubr), when one is shipped. `None` means
    /// values-only work: no key is proven "not Windows' own" (§5.7.1 step 3).
    pub baseline: Option<&'a Baseline>,
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

    /// Whether the clean Windows of this build has the target (key, value, file or directory). `false`
    /// without a baseline, and for a segment of a list value (the value itself is expected to exist).
    pub fn in_baseline(&self, target: &Target) -> bool {
        let Some(baseline) = self.baseline else {
            return false;
        };
        match target {
            Target::Path { path } => baseline.has_path(path),
            Target::RegKey { path } => baseline.has_key(path),
            Target::RegValue { path, name } => baseline.has_value(path, name),
            _ => false,
        }
    }

    /// A key folded for comparison, with the current `ControlSet00N` spelled `CurrentControlSet`.
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
        self.key_norm(a) == self.key_norm(b)
    }

    /// How key `a` relates to key `b`, with the control-set alias applied.
    pub fn key_relation(&self, a: &str, b: &str) -> Relation {
        prefix::relation(&self.key_norm(a), &self.key_norm(b))
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
            },
        }
    }
}

fn install_root_of<'r>(roots: &'r [Root], path: &str) -> Option<&'r Root> {
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

/// The id of the candidate for `target`: `c-` and the 64-bit FNV-1a hash (16 hex digits) of the target's
/// type and case-folded fields. Two scanners that find the same target produce the same id; `purge-plan`
/// merges them.
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
// Candidate builder
// ---------------------------------------------------------------------------------------------------------

/// Ticks of one day in `FILETIME` units.
const DAY_TICKS: u64 = 24 * 60 * 60 * 10_000_000;

/// Builds one [`Candidate`]. Made by [`ScanCtx::candidate`].
///
/// Evidence constructors return whether the evidence was added; they add nothing when the row's condition
/// does not hold for this candidate's target. Blocker helpers and setters return the builder.
pub struct CandidateBuilder<'c> {
    ctx: &'c ScanCtx<'c>,
    candidate: Candidate,
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
    /// (or for a segment of it); a file or directory record gives Path scope for that path. Records
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
        let detail = Facts::new().with("record", format!("{:?}", record.kind));
        self.push(
            EvidenceKind::InstallerManifest(ManifestKind::Inno),
            Some(scope),
            inno_trust(fp),
            "inno:log".to_owned(),
            detail,
        )
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
        let detail = Facts::new().with("anchor", entry.anchor.text.clone());
        let source = match &entry.target {
            Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
                format!("refsnap:{path}|{name}")
            }
            _ => "refsnap".to_owned(),
        };
        self.push(
            EvidenceKind::InPreUninstallRefSnapshot,
            Some(Scope::Value),
            trust,
            source,
            detail,
        )
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
    /// missing. Value scope only.
    pub fn dangling_ref(&mut self, dangling: &Dangling<'_>) -> bool {
        let detail = Facts::new()
            .with("root", dangling.root.path.clone())
            .with("path", dangling.path.clone());
        self.push(
            EvidenceKind::DanglingRef,
            self.scope(),
            dangling.root.trust,
            format!("dangling:{}", dangling.path),
            detail,
        )
    }

    /// `PointsIntoInstallRoot`: the value's data or name resolves to `referenced`, which is at or under
    /// an InstallRoot or is a file of the exe set. Value scope only. The scanner resolves the reference
    /// (expansion, quotes, arguments); this checks where it lands.
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
        self.push(
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
            || ctx.baseline.is_some_and(|b| b.has_token(token))
        {
            return false;
        }
        // Without a baseline "absent from the baseline" is unchecked, and no key is proven not to be
        // Windows' own (§5.7.1 step 3: values only).
        if ctx.baseline.is_none() && matches!(self.candidate.target, Target::RegKey { .. }) {
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

    /// The finished candidate, undecided.
    pub fn build(self) -> Candidate {
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
            anchors: Anchors::default(),
            tokens: Vec::new(),
            inno: Vec::new(),
            ref_snapshot: Vec::new(),
            subtrees: Vec::new(),
            ext_journal: Vec::new(),
            co_removed: Vec::new(),
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

    /// A baseline of this test Windows holding `keys`.
    pub(crate) fn baseline(edition: &str, keys: &[&str]) -> Baseline {
        let mut text = format!("#purge-baseline 1\tT\tPC\t{edition}\t{BUILD}.{UBR}\n");
        for key in keys {
            text.push_str(&format!("K\t{}\t0\t0\t0\n", key.replace('\\', "\\\\")));
        }
        Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
    }

    /// Everything a [`ScanCtx`] borrows, owned in one place.
    pub(crate) struct World {
        pub(crate) fixture: Fixture,
        pub(crate) fp: Fingerprint,
        pub(crate) baseline: Option<Baseline>,
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
                baseline: self.baseline.as_ref(),
                mode: ScanMode::Post,
                verify_gone: self.verify_gone,
                env: &self.env,
                guard: &self.guard,
                other_apps: &self.other_apps,
                limits: ScanLimits::default(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use purge_model::{HarvestedToken, InnoRecordKind, RefCarrier, SubtreeBaseline, View};
    use purge_source::fixture::Fixture;

    const SID: &str = GuardEnv::SAMPLE_SID;

    fn key(path: &str) -> Target {
        Target::RegKey { path: path.into() }
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
                EvidenceKind::EmptyAfterPlan | EvidenceKind::ComKeyOwnership
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
        world.baseline = None;
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
}
