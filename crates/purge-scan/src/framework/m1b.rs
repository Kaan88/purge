//! M1b additions to the scanner framework (contracts C-SCANEXT and C-PATHSTORES, ENGINE_PLAN.md §5.6,
//! §5.3, §5.5).
//!
//! # Shared scan data
//!
//! [`ScanExt`] is what the pipeline reads once per scan, before the first scanner, and hands to every
//! scanner through [`ScanCtx::ext`]:
//!
//! - the **one reference walk** (`ref_hits`): the walk REF-ANY runs, with the same scope, options and
//!   prune list (`ref_any::walk`). REF-ANY reads it instead of walking again, and the M1b scanners look
//!   into it with [`ScanCtx::ref_hits_under`] instead of walking a subtree of their own;
//! - the **MSI ownership index** (`purge_index::ownership`): which installed product owns which file,
//!   key, value or component;
//! - the **system objects** (`purge_index::sysobj`): services, firewall rules and tasks.
//!
//! Every construction site other than the pipeline passes [`ScanExt::none`]: no hits (REF-ANY then walks
//! itself), an empty index and no objects, which adds nothing to M1a behaviour.
//!
//! # Path-keyed stores
//!
//! A path-keyed store is a key whose value **names** are full paths ([`PathStore`]). A value there is the
//! app's only when its name, decoded as the store requires ([`ScanCtx::path_from_value_name`]), is a
//! full drive path inside an InstallRoot of the app or one of its exe paths. A bare file name, a UNC or
//! relative name, a resource reference and a value's data never count.
//!
//! # Sealing
//!
//! [`ScanCtx::run`] applies [`ScanCtx::seal_object`] and [`ScanCtx::msi_blockers`] to every candidate of
//! every scanner, after the M1a rules. A scanner cannot opt out.

use std::borrow::Cow;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

use purge_guard::canon::{CanonKey, GuardEnv, canon_key, canon_path};
use purge_guard::containers::value_container;
use purge_guard::prefix::{self, Relation};
use purge_index::ownership::{
    OwnershipIndex, OwnershipInput, OwnershipLimits, TableCache, area, pack_guid, unpack_guid,
};
use purge_index::refscan::RefHit;
use purge_index::sysobj::{self, ProgramRef, SERVICES_KEY, SysObjectIndex};
use purge_model::{
    Blocker, Candidate, EvidenceKind, Facts, Fingerprint, Hive, InventoryEntry, ManifestKind,
    MsiFacts, MsiKeyPath, ObjectFp, ObjectKind, ObjectWhy, ProgramId, Scope, Target, Tier,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::KnownFolder;

use super::{AppIdentityView, CandidateBuilder, ScanCtx, app_trust};

// ---------------------------------------------------------------------------------------------------------
// Shared scan data
// ---------------------------------------------------------------------------------------------------------

/// What the pipeline reads once per scan for every scanner (C-SCANEXT). See the module documentation.
///
/// The fields are public so that tests can put an index of their own in place; the reference hits
/// belong to one app and are set with [`ScanExt::with_ref_hits`], which records that app.
#[derive(Debug)]
pub struct ScanExt {
    /// The hits of the one reference walk, in walk order; `None` when the walk was not run (then
    /// REF-ANY runs it itself). Readers go through [`ScanExt::ref_hits_for`] or
    /// [`ScanCtx::ref_hits_under`], which give them only for the app the walk was run for.
    pub ref_hits: Option<Vec<RefHit>>,
    /// The MSI ownership index of the machine.
    pub ownership: OwnershipIndex,
    /// The services, firewall rules and tasks of the machine. A non-empty `errors` means "not all
    /// objects are known" (dependents unknown, for instance).
    pub sysobj: SysObjectIndex,
    /// The app whose anchors and hives the walk of `ref_hits` used.
    hits_app: Option<ProgramId>,
    /// Scanner faults found while sealing, for the scan's warnings.
    faults: Mutex<Vec<String>>,
}

/// Writes a `PURGE_TIMING` phase line when a source meter is installed (the format of
/// `purge_index::ownership`).
struct Phase {
    name: &'static str,
    started: Instant,
    before: Option<purge_source::metered::MeterSnapshot>,
}

impl Phase {
    fn start(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            before: purge_source::metered::installed().map(|m| m.snapshot()),
        }
    }

    fn end(self) {
        if let (Some(meter), Some(before)) = (purge_source::metered::installed(), self.before) {
            let calls = meter.snapshot().since(&before).summary();
            eprintln!(
                "timing:   phase {} {:.3}s; {}",
                self.name,
                self.started.elapsed().as_secs_f64(),
                calls
            );
        }
    }
}

impl ScanExt {
    /// No hits, an empty ownership index, no system objects: the M1a context.
    pub fn none() -> &'static ScanExt {
        static NONE: OnceLock<ScanExt> = OnceLock::new();
        NONE.get_or_init(|| ScanExt::new(OwnershipIndex::default(), SysObjectIndex::default()))
    }

    /// Shared data without reference hits.
    pub fn new(ownership: OwnershipIndex, sysobj: SysObjectIndex) -> ScanExt {
        ScanExt {
            ref_hits: None,
            ownership,
            sysobj,
            hits_app: None,
            faults: Mutex::new(Vec::new()),
        }
    }

    /// The same data with `hits`, the result of the reference walk run for the app `app`
    /// (`ref_any::walk` with that app's fingerprint and anchors).
    #[must_use]
    pub fn with_ref_hits(mut self, app: &ProgramId, hits: Vec<RefHit>) -> ScanExt {
        self.ref_hits = Some(hits);
        self.hits_app = Some(app.clone());
        self
    }

    /// The reference hits when the walk was run for `app`; `None` otherwise (no walk, or the walk of
    /// another app: a co-removed product's pass walks with its own anchors and hives).
    pub fn ref_hits_for(&self, app: &ProgramId) -> Option<&[RefHit]> {
        match (&self.ref_hits, &self.hits_app) {
            (Some(hits), Some(owner)) if owner == app => Some(hits),
            _ => None,
        }
    }

    /// Reads the shared data (C-SCANEXT): runs the one reference walk for `app` (the walk REF-ANY makes,
    /// same scope, options and prune list), builds the ownership index over `inventory` and the
    /// system-object index. Writes the `PURGE_TIMING` phases `refscan`, `ownership.components`,
    /// `ownership.tables` (from the index) and `ext.sysobj`. Never fails: what cannot be read is
    /// recorded in the index statistics and errors.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        reg: &dyn RegistrySource,
        fs: &dyn FileSystemSource,
        sys: &dyn SystemSource,
        fp: &Fingerprint,
        app: &AppIdentityView,
        inventory: &[InventoryEntry],
        cache: Option<&dyn TableCache>,
        limits: OwnershipLimits,
    ) -> ScanExt {
        let phase = Phase::start("refscan");
        // REF-ANY makes no walk for an app without anchors; nothing can refer to it.
        let hits = if app.anchors.is_empty() {
            Vec::new()
        } else {
            crate::ref_any::walk(reg, fp, &app.refs).hits
        };
        phase.end();
        let ownership = OwnershipIndex::build_with_limits(
            &OwnershipInput {
                reg,
                fs,
                sys,
                products: inventory,
                cache,
                threads: 0,
            },
            limits,
        );
        let phase = Phase::start("ext.sysobj");
        let sysobj = sysobj::build(reg, sys);
        phase.end();
        ScanExt::new(ownership, sysobj).with_ref_hits(&fp.app.program_id, hits)
    }

    /// Records a scanner fault.
    fn fault(&self, line: String) {
        self.faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    /// The scanner faults recorded so far (candidates the sealing dropped), emptied.
    pub fn take_faults(&self) -> Vec<String> {
        std::mem::take(&mut *self.faults.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether some MSI ownership is unknown: a product's package could not be read, or the component
    /// clients, the rows or the SharedDLLs counts were not read completely. Unknown is never "none".
    fn ownership_unknown(&self) -> bool {
        let stats = self.ownership.stats();
        !self.ownership.unreadable().is_empty()
            || [area::COMPONENTS, area::ROWS, area::SHARED_DLLS]
                .iter()
                .any(|a| !stats.complete(a))
    }
}

// ---------------------------------------------------------------------------------------------------------
// Path-keyed stores (C-PATHSTORES)
// ---------------------------------------------------------------------------------------------------------

/// A key whose value names are full file or directory paths (C-PATHSTORES).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathStore {
    /// `...\CurrentVersion\SharedDLLs` (both views): name = file path.
    SharedDlls,
    /// `...\CurrentVersion\Installer\Folders`: name = directory path, usually with a trailing `\`.
    InstallerFolders,
    /// `...\AppCompatFlags\Layers` (machine and users): name = file path.
    AppCompatLayers,
    /// `...\AppCompatFlags\Compatibility Assistant\Store`: name = file path.
    PcaStore,
    /// `...\AppCompatFlags\Compatibility Assistant\Persisted`: name = file path.
    PcaPersisted,
    /// `...\Shell\MuiCache` of a user's Classes: name = file path + `.FriendlyAppName` or
    /// `.ApplicationCompany`.
    MuiCache,
    /// `...\Explorer\UserAssist\{GUID}\Count`: name = ROT13 of a path that may start with a
    /// known-folder GUID.
    UserAssist,
    /// `...\Explorer\FeatureUsage\{AppBadgeUpdated, AppLaunch, AppSwitched, ShowJumpView}`: name = file
    /// path or AUMID.
    FeatureUsage,
}

/// The guard's container pattern of each store (entries of
/// `purge_guard::containers::M1B_VALUE_CONTAINERS`, spelled exactly as there). The guard's pattern
/// match canonicalises the key, so every spelling of a store (`WOW6432Node`, `HKU\<sid>_Classes`,
/// `HKU\<sid>\Software\Classes`, any `ControlSet`) is recognised the same way.
const PATH_STORES: &[(&str, PathStore)] = &[
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        PathStore::SharedDlls,
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
        PathStore::InstallerFolders,
    ),
    (
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        PathStore::AppCompatLayers,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        PathStore::PcaStore,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
        PathStore::PcaPersisted,
    ),
    (
        r"HKU\*\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        PathStore::MuiCache,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count",
        PathStore::UserAssist,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
        PathStore::FeatureUsage,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
        PathStore::FeatureUsage,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        PathStore::FeatureUsage,
    ),
    (
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
        PathStore::FeatureUsage,
    ),
];

/// The suffixes of a `MuiCache` value name.
const MUICACHE_SUFFIXES: [&str; 2] = [".FriendlyAppName", ".ApplicationCompany"];

/// The `KNOWNFOLDERID`s a `UserAssist` name may start with, and the known folder each stands for in the
/// 64-bit Explorer that writes them (`FOLDERID_ProgramFilesX64` and `FOLDERID_ProgramFiles` are both
/// `C:\Program Files` there). Values from `KnownFolders.h`.
const KNOWN_FOLDER_GUIDS: &[(&str, KnownFolder)] = &[
    (
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}",
        KnownFolder::Windows,
    ),
    (
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}",
        KnownFolder::System,
    ),
    (
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}",
        KnownFolder::SystemX86,
    ),
    ("{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}", KnownFolder::Fonts),
    (
        "{905E63B6-C1BF-494E-B29C-65B732D3D21A}",
        KnownFolder::ProgramFiles,
    ),
    (
        "{6D809377-6AF0-444B-8957-A3773F02200E}",
        KnownFolder::ProgramFiles,
    ),
    (
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}",
        KnownFolder::ProgramFilesX86,
    ),
    (
        "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}",
        KnownFolder::ProgramFilesCommon,
    ),
    (
        "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}",
        KnownFolder::ProgramFilesCommon,
    ),
    (
        "{DE974D24-D9C6-4D3E-BF91-F4455120B917}",
        KnownFolder::ProgramFilesCommonX86,
    ),
    (
        "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}",
        KnownFolder::ProgramData,
    ),
    (
        "{DFDF76A2-C82A-4D63-906A-5644AC457385}",
        KnownFolder::Public,
    ),
    (
        "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}",
        KnownFolder::PublicDesktop,
    ),
    (
        "{A4115719-D62E-491D-AA7C-E74B8BE3B067}",
        KnownFolder::CommonStartMenu,
    ),
    (
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}",
        KnownFolder::CommonPrograms,
    ),
    (
        "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}",
        KnownFolder::CommonStartup,
    ),
    (
        "{5E6C858F-0E22-4760-9AFE-EA3317B67173}",
        KnownFolder::Profile,
    ),
    (
        "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}",
        KnownFolder::RoamingAppData,
    ),
    (
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}",
        KnownFolder::LocalAppData,
    ),
    (
        "{A520A1A4-1780-4FF6-BD18-167343C5AF16}",
        KnownFolder::LocalAppDataLow,
    ),
    (
        "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}",
        KnownFolder::UserProgramFiles,
    ),
    (
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
        KnownFolder::Desktop,
    ),
    (
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
        KnownFolder::Documents,
    ),
    (
        "{374DE290-123F-4565-9164-39C4925E467B}",
        KnownFolder::Downloads,
    ),
    (
        "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}",
        KnownFolder::StartMenu,
    ),
    (
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}",
        KnownFolder::Programs,
    ),
    (
        "{B97D20BB-F46A-4C97-BA10-5E3608430854}",
        KnownFolder::Startup,
    ),
    (
        "{A63293E8-664E-48DB-A079-DF759E0509F7}",
        KnownFolder::Templates,
    ),
    (
        "{8983036C-27C0-404B-8F08-102D10DCFD74}",
        KnownFolder::SendTo,
    ),
];

/// ROT13 of the ASCII letters of `text`; every other character is kept.
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from((c as u8 - b'a' + 13) % 26 + b'a'),
            'A'..='Z' => char::from((c as u8 - b'A' + 13) % 26 + b'A'),
            _ => c,
        })
        .collect()
}

/// `text` without `suffix` at its end, compared ignoring ASCII case.
fn strip_suffix_ci<'t>(text: &'t str, suffix: &str) -> Option<&'t str> {
    let cut = text.len().checked_sub(suffix.len())?;
    (text.is_char_boundary(cut) && text[cut..].eq_ignore_ascii_case(suffix)).then(|| &text[..cut])
}

/// Whether `text` starts with a drive letter, a colon and a backslash (`X:\`).
fn is_drive_absolute(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

// ---------------------------------------------------------------------------------------------------------
// Scan context
// ---------------------------------------------------------------------------------------------------------

/// `row_key` with a literal "any user" segment (`HKU\*`, `HKU\*_Classes`, a per-user row of a
/// per-machine product) bound to the user of `key` when `key` is in the same kind of user hive.
fn bind_any_user<'r>(row_key: &'r str, key: &str) -> Cow<'r, str> {
    let mut row = row_key.splitn(3, prefix::SEP);
    let (Some(hive), Some(user)) = (row.next(), row.next()) else {
        return Cow::Borrowed(row_key);
    };
    let rest = row.next().unwrap_or("");
    let any_classes = prefix::eq_ci(user, "*_Classes");
    if !prefix::eq_ci(hive, "HKU") || !(user == "*" || any_classes) {
        return Cow::Borrowed(row_key);
    }
    let mut target = key.splitn(3, prefix::SEP);
    match (target.next(), target.next()) {
        (Some(h), Some(u))
            if prefix::eq_ci(h, "HKU")
                && strip_suffix_ci(u, "_Classes").is_some() == any_classes =>
        {
            Cow::Owned(if rest.is_empty() {
                format!(r"HKU\{u}")
            } else {
                format!(r"HKU\{u}\{rest}")
            })
        }
        _ => Cow::Borrowed(row_key),
    }
}

/// The packed form of a product code given as `{GUID}` or packed (32 hex digits), upper case.
fn packed_code(code: &str) -> Option<String> {
    let code = code.trim();
    pack_guid(code).or_else(|| {
        (code.len() == 32 && code.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| code.to_ascii_uppercase())
    })
}

impl<'a> ScanCtx<'a> {
    /// The hits of the one reference walk at `key_prefix` or below it, in walk order. The comparison is
    /// separator-aware (`HKLM\A` does not hold `HKLM\AB`), folds case with the guard's fold and treats
    /// `CurrentControlSet` and the current `ControlSet00N` as one key. Empty when the context holds no
    /// walk for this context's app (see [`ScanExt::ref_hits_for`]).
    pub fn ref_hits_under(&self, key_prefix: &str) -> impl Iterator<Item = &'a RefHit> + use<'a> {
        let ctx = *self;
        let want = ctx.key_norm(key_prefix);
        let hits: &'a [RefHit] = ctx.ext.ref_hits_for(&ctx.fp.app.program_id).unwrap_or(&[]);
        hits.iter().filter(move |hit| {
            matches!(
                prefix::relation(&ctx.key_norm(&hit.key), &want),
                Relation::Same | Relation::Inside
            )
        })
    }

    /// The path-keyed store `key` is (C-PATHSTORES), recognised through the guard's canonical form of
    /// the key, so that every spelling of a store gives the same answer. `None` for any other key, a
    /// key below a store included, and for a key that does not canonicalise (`HKCR`, the merged view,
    /// never does).
    pub fn path_keyed_store(&self, key: &str) -> Option<PathStore> {
        // Cheap test first: a store's key ends in the last segment of its pattern.
        let leaf = prefix::leaf(key)?;
        if !PATH_STORES
            .iter()
            .any(|(pattern, _)| prefix::leaf(pattern).is_some_and(|l| prefix::eq_ci(l, leaf)))
        {
            return None;
        }
        let pattern = value_container(key, self.guard)?;
        PATH_STORES
            .iter()
            .find(|(p, _)| *p == pattern)
            .map(|(_, store)| *store)
    }

    /// The path a value of `store` is named after, decoded as the store requires, in canonical form;
    /// `None` unless the decoded name is an absolute drive path (`X:\...`) after expansion.
    ///
    /// - `MuiCache`: the `.FriendlyAppName` / `.ApplicationCompany` suffix is stripped; a name with
    ///   neither, and a resource reference (`@...`), give `None`.
    /// - `UserAssist`: ROT13 of the ASCII letters, then a leading `{KNOWNFOLDERID}` is replaced by that
    ///   folder's path from the source's known folders; an unknown GUID gives `None`, and so does any
    ///   name that does not decode to a path (`UEME_...` counters, AUMIDs).
    /// - `InstallerFolders`: the trailing separator of the directory is dropped.
    /// - every store: `%NAME%` references are expanded with the context's environment.
    ///
    /// UNC paths, device paths, relative names, bare file names and names with an 8.3 segment the
    /// guard cannot vouch for give `None`.
    pub fn path_from_value_name(&self, store: PathStore, name: &str) -> Option<String> {
        if name.starts_with('@') {
            return None;
        }
        let decoded: Cow<'_, str> = match store {
            PathStore::MuiCache => Cow::Borrowed(
                MUICACHE_SUFFIXES
                    .iter()
                    .find_map(|suffix| strip_suffix_ci(name, suffix))?,
            ),
            PathStore::UserAssist => Cow::Owned(self.known_folder_expanded(&rot13(name))?),
            PathStore::SharedDlls
            | PathStore::InstallerFolders
            | PathStore::AppCompatLayers
            | PathStore::PcaStore
            | PathStore::PcaPersisted
            | PathStore::FeatureUsage => Cow::Borrowed(name),
        };
        let expanded = if decoded.contains('%') {
            Cow::Owned(prefix::expand_env(&decoded, self.env))
        } else {
            decoded
        };
        if !is_drive_absolute(&expanded) || expanded.contains('%') {
            return None;
        }
        let canon = canon_path(&expanded, self.guard, None).ok()?;
        (!canon.needs_long_name && is_drive_absolute(&canon.path)).then_some(canon.path)
    }

    /// A `UserAssist` name (already ROT13-decoded) with its leading known-folder GUID replaced by the
    /// folder's path; the name unchanged when it starts with no brace; `None` for an unknown GUID or a
    /// folder the source cannot name.
    fn known_folder_expanded(&self, decoded: &str) -> Option<String> {
        let Some(after_brace) = decoded.strip_prefix('{') else {
            return Some(decoded.to_owned());
        };
        let end = after_brace.find('}')? + 2;
        let (guid, rest) = decoded.split_at(end);
        let folder = KNOWN_FOLDER_GUIDS
            .iter()
            .find(|(g, _)| g.eq_ignore_ascii_case(guid))
            .map(|(_, folder)| *folder)?;
        if !(rest.is_empty() || rest.starts_with(prefix::SEP)) {
            return None;
        }
        let folders = self.sys.known_folders().ok()?;
        let base = folders.get(&folder)?.trim().trim_end_matches(prefix::SEP);
        (!base.is_empty()).then(|| format!("{base}{rest}"))
    }

    /// The path-store rule of [`ScanCtx::owns_registration`]: the value's decoded name is a full path
    /// inside an InstallRoot of the app or one of its exe paths.
    pub(super) fn path_store_value_is_apps(&self, store: PathStore, name: &str) -> bool {
        self.path_from_value_name(store, name).is_some_and(|path| {
            self.inside_install_root(&path).is_some()
                || self.fp.exes.iter().any(|e| prefix::is_same(&e.path, &path))
        })
    }

    /// Why an object's program makes the object the app's: `Some` only for [`ProgramRef::File`] whose
    /// file, in the guard's canonical form, lies inside an InstallRoot of the app
    /// ([`ObjectWhy::ProgramInRoot`]) or is one of its exe or outside-root files
    /// ([`ObjectWhy::ProgramIsAppExe`]). An unresolved program and no program give `None`.
    pub fn object_owner(&self, program: &ProgramRef) -> Option<ObjectWhy> {
        let ProgramRef::File(file) = program else {
            return None;
        };
        let canon = canon_path(file, self.guard, None).ok()?;
        if canon.needs_long_name {
            return None;
        }
        let file = canon.path.as_str();
        if self.inside_install_root(file).is_some() {
            return Some(ObjectWhy::ProgramInRoot);
        }
        let fp = self.fp;
        let own = fp.exes.iter().any(|e| prefix::is_same(&e.path, file))
            || fp
                .outside_root_files
                .iter()
                .any(|f| prefix::is_same(&f.path, file));
        own.then_some(ObjectWhy::ProgramIsAppExe)
    }

    /// Whether Windows Installer positively knows the product (`{GUID}` or packed) in no context:
    /// [`SystemSource::msi_product_state_all`] answers with at least one context and all are unknown.
    /// A source error, an empty answer and a code that is no GUID are "not gone".
    pub fn product_gone(&self, product_code: &str) -> bool {
        let Some(code) = packed_code(product_code).and_then(|p| unpack_guid(&p)) else {
            return false;
        };
        match self.sys.msi_product_state_all(&code) {
            Ok(states) => !states.is_empty() && states.iter().all(|s| s.state.is_unknown()),
            Err(_) => false,
        }
    }

    /// The app's MSI product (of `fp.msi`) with this code (`{GUID}` or packed).
    fn own_msi(&self, product_code: &str) -> Option<&'a MsiFacts> {
        let packed = packed_code(product_code)?;
        let fp: &'a Fingerprint = self.fp;
        fp.msi
            .iter()
            .find(|m| packed_code(&m.packed_code).as_deref() == Some(packed.as_str()))
    }

    /// The blockers the MSI ownership index gives a target (C-SCANEXT):
    ///
    /// - a **path**: for every component whose key path is the file, or lies in or is the directory,
    ///   each client that is not a product of the app's fingerprint (an installed product, a stale
    ///   registration, the permanent marker: any other client counts) gives `OwnedByInstalledMsi`
    ///   with the row `Component:<id>`; `SharedRefcount` when SharedDLLs counts the file more often
    ///   than the app's own components keyed on it explain;
    /// - a **value** (or an entry of one): `OwnedByInstalledMsi` for every row that owns it, or that
    ///   owns its key whole;
    /// - a **key**: `OwnedByInstalledMsi` for every row at the key or below it, and every whole-key row
    ///   above it;
    /// - a **service**: the same as its key under `Services`.
    ///
    /// A client or row of one of the app's own products that Windows still lists as installed gives
    /// `MsiProductStillRegistered` instead. While some ownership is unknown (an unreadable package, an
    /// incomplete component, row or SharedDLLs read), a registry target under a `SOFTWARE\Classes` root
    /// and a path under a Program Files directory get the soft `MsiPackageUnreadable`.
    ///
    /// One blocker per product (the first row found names it). Empty for [`ScanExt::none`].
    pub fn msi_blockers(&self, target: &Target) -> Vec<Blocker> {
        let ix = &self.ext.ownership;
        let mut out: Vec<Blocker> = Vec::new();
        let mut push = |blocker: Blocker| {
            let duplicate = out.iter().any(|b| match (b, &blocker) {
                (
                    Blocker::OwnedByInstalledMsi { product: p, .. },
                    Blocker::OwnedByInstalledMsi { product: q, .. },
                ) => p == q,
                (b, blocker) => b == blocker,
            });
            if !duplicate {
                out.push(blocker);
            }
        };
        let mut in_classes = false;
        let mut in_program_files = false;
        match target {
            Target::Path { path } => {
                // The index takes canonical paths only (its lookups refuse anything else).
                let canonical = canon_path(path, &GuardEnv::default(), None)
                    .ok()
                    .filter(|c| !c.needs_long_name)
                    .map(|c| c.path);
                let at = canonical.as_deref().unwrap_or(path);
                in_program_files = [
                    Some(&self.guard.program_files),
                    self.guard.program_files_x86.as_ref(),
                ]
                .into_iter()
                .flatten()
                .filter(|pf| !pf.trim().is_empty())
                .any(|pf| prefix::is_same_or_inside(at, pf));
                if let Some(path) = canonical.as_deref() {
                    let owners = ix
                        .file_owners(path)
                        .into_iter()
                        .chain(ix.dir_components(path));
                    for owner in owners {
                        for client in owner.clients {
                            if let Some(blocker) = self.client_blocker(client, owner.component_id) {
                                push(blocker);
                            }
                        }
                    }
                    if let Some(count) = ix.shared_dll_count(path)
                        && count > 0
                        && u64::from(count) > self.own_components_keyed_on(path)
                    {
                        push(Blocker::SharedRefcount);
                    }
                }
            }
            Target::RegValue { path, name }
            | Target::RegValueChanged { path, name, .. }
            | Target::RegMultiSzSegment { path, name, .. } => {
                if let Some(key) = self.canonical_key(path) {
                    in_classes = in_classes_root(&key);
                    for row in ix.reg_owners(&key.key_path(), Some(name)) {
                        push(self.row_blocker(&row));
                    }
                }
            }
            Target::RegKey { path } => {
                if let Some(key) = self.canonical_key(path) {
                    in_classes = in_classes_root(&key);
                    for row in ix.key_owners(&key.key_path()) {
                        push(self.row_blocker(&row));
                    }
                }
            }
            Target::Service { name } => {
                if let Some(key) = self.canonical_key(&format!(r"{SERVICES_KEY}\{name}")) {
                    for row in ix.key_owners(&key.key_path()) {
                        push(self.row_blocker(&row));
                    }
                }
            }
            Target::Task { .. } | Target::FirewallRule { .. } | Target::AppxPackage { .. } => {}
        }
        if (in_classes || in_program_files) && self.ext.ownership_unknown() {
            push(Blocker::MsiPackageUnreadable);
        }
        out
    }

    /// The blocker a component client gives: none of the app's products is `OwnedByInstalledMsi`; one
    /// of them that is still installed is `MsiProductStillRegistered`.
    /// A stale client of one of the app's own products gives nothing: the component is the app's.
    fn client_blocker(&self, client: &str, component: &str) -> Option<Blocker> {
        let installed = self.ext.ownership.installed(client);
        if self.own_msi(client).is_some() {
            return installed.map(|_| Blocker::MsiProductStillRegistered);
        }
        Some(Blocker::OwnedByInstalledMsi {
            product: installed
                .map(|p| p.product_code.clone())
                .or_else(|| unpack_guid(client))
                .unwrap_or_else(|| client.to_owned()),
            row: format!("Component:{component}"),
        })
    }

    /// The blocker an MSI row gives.
    fn row_blocker(&self, row: &purge_index::ownership::RowOwner<'_>) -> Blocker {
        if self.own_msi(&row.product.packed_code).is_some() {
            return Blocker::MsiProductStillRegistered;
        }
        Blocker::OwnedByInstalledMsi {
            product: row.product.product_code.clone(),
            row: format!("{}:{}", row.table, row.row),
        }
    }

    /// How many components of the app's MSI products have the file `path` as their key path.
    fn own_components_keyed_on(&self, path: &str) -> u64 {
        let n = self
            .fp
            .msi
            .iter()
            .flat_map(|m| &m.components)
            .filter(
                |c| matches!(&c.key_path, MsiKeyPath::File { path: p } if prefix::is_same(p, path)),
            )
            .count();
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// The guard's canonical form of a registry key; `None` when it does not canonicalise.
    fn canonical_key(&self, key: &str) -> Option<CanonKey> {
        canon_key(key, None, self.guard, None).ok()
    }

    /// Whether the harvest recorded the object `target` with the digest `object_fp` (`fp.sys`). A
    /// `ServiceInstall` row of the app's MSI with the service's name is not enough (R2a S3): the harvest
    /// records such a service in `fp.sys` with its digest when its program is the app's.
    fn object_backed(&self, target: &Target, object_fp: Option<&ObjectFp>) -> bool {
        let fp = self.fp;
        let same = |recorded: ObjectFp| object_fp == Some(&recorded);
        match target {
            Target::Service { name } => fp
                .sys
                .services
                .iter()
                .any(|s| prefix::eq_ci(&s.identity.name, name) && same(s.identity.fp())),
            Target::Task { path } => fp
                .sys
                .tasks
                .iter()
                .any(|t| prefix::eq_ci(&t.identity.path, path) && same(t.identity.fp())),
            Target::FirewallRule { id } => fp
                .sys
                .firewall_rules
                .iter()
                .any(|r| r.identity.id == *id && same(r.identity.fp())),
            _ => false,
        }
    }

    /// The object checks of the sealing (C-SCANEXT); `false` drops the candidate, recorded as a fault
    /// of `scanner`:
    ///
    /// - a candidate on a service, task or firewall rule must carry a well-formed `object_fp` of the
    ///   target's kind;
    /// - `OwnedSystemObject` may only stand on such a target, with Object scope.
    ///
    /// `OwnedSystemObject` that no harvest record backs (the object recorded with the same digest) is
    /// lowered to Tier B and says why: a scanner that states it by
    /// hand cannot make an object Safe.
    pub(super) fn seal_object(&self, scanner: &str, candidate: &mut Candidate) -> bool {
        let kind = ObjectKind::of(&candidate.target);
        if let Some(kind) = kind {
            let ok = candidate
                .object_fp
                .as_ref()
                .is_some_and(|fp| fp.kind == kind && fp.is_well_formed());
            if !ok {
                self.ext.fault(format!(
                    "{scanner}: dropped {:?}: a system object without a valid object fingerprint",
                    candidate.target
                ));
                return false;
            }
        }
        let owned = |e: &purge_model::Evidence| e.kind == EvidenceKind::OwnedSystemObject;
        if !candidate.evidence.iter().any(owned) {
            return true;
        }
        let misplaced = kind.is_none()
            || candidate
                .evidence
                .iter()
                .any(|e| owned(e) && e.scope != Scope::Object);
        if misplaced {
            self.ext.fault(format!(
                "{scanner}: dropped {:?}: OwnedSystemObject on a target that is not a system object",
                candidate.target
            ));
            return false;
        }
        if !self.object_backed(&candidate.target, candidate.object_fp.as_ref()) {
            for e in candidate.evidence.iter_mut().filter(|e| owned(e)) {
                if e.tier == Tier::A {
                    e.tier = Tier::B;
                    e.detail = std::mem::take(&mut e.detail)
                        .with("unproven", "no harvest record of this object");
                }
            }
        }
        true
    }
}

/// Whether a canonical key lies under a `SOFTWARE\Classes` root (the machine's, either view, or a
/// user's Classes hive).
fn in_classes_root(key: &CanonKey) -> bool {
    match &key.hive {
        Hive::HkuClasses(_) => true,
        Hive::Hku(_) => false,
        Hive::Hklm => {
            let mut segments = prefix::segments(&key.path);
            segments
                .next()
                .is_some_and(|s| prefix::eq_ci(s, "SOFTWARE"))
                && segments.next().is_some_and(|s| prefix::eq_ci(s, "Classes"))
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Candidate builder
// ---------------------------------------------------------------------------------------------------------

/// The serialised name of an [`ObjectWhy`].
fn why_name(why: ObjectWhy) -> &'static str {
    match why {
        ObjectWhy::ProgramInRoot => "program_in_root",
        ObjectWhy::ProgramIsAppExe => "program_is_app_exe",
        ObjectWhy::MsiServiceRow => "msi_service_row",
    }
}

impl CandidateBuilder<'_> {
    /// `OwnedSystemObject` for a service, task or firewall rule whose program makes it the app's
    /// (`why`, from [`ScanCtx::object_owner`] or an MSI `ServiceInstall` row).
    ///
    /// Granted only when the harvest recorded the object (`recorded_at_harvest`, the scanner having
    /// compared the digests), whatever `why` is: an MSI `ServiceInstall` row names a service, it does
    /// not show that the service found now is the one it installed (R2a S3). Otherwise the object is the
    /// app's by its program alone, and it gets `PointsIntoInstallRoot` with Value scope: weight 6 that
    /// does not match an Object target, so it can never make the object Safe. The sealing checks the
    /// harvest record again. Nothing for a target that is not a system object.
    #[must_use]
    pub fn owned_system_object(mut self, why: ObjectWhy, recorded_at_harvest: bool) -> Self {
        if ObjectKind::of(&self.candidate.target).is_none() {
            return self;
        }
        let name = why_name(why);
        let detail = Facts::new()
            .with("why", name)
            .with("recorded_at_harvest", recorded_at_harvest.to_string());
        let trust = app_trust(self.ctx.fp);
        let source = format!("sysobj:{name}");
        if recorded_at_harvest {
            self.push(
                EvidenceKind::OwnedSystemObject,
                Some(Scope::Object),
                trust,
                source,
                detail,
            );
        } else {
            self.push(
                EvidenceKind::PointsIntoInstallRoot,
                Some(Scope::Value),
                trust,
                source,
                detail,
            );
        }
        self
    }

    /// `InstallerManifest(Msi)`: the target is a Windows Installer registration (`store` names which)
    /// of `product_code`, one of the app's MSI products (`fp.msi`). Nothing for another product.
    #[must_use]
    pub fn msi_registration(mut self, product_code: &str, store: &'static str) -> Self {
        let Some(msi) = self.ctx.own_msi(product_code) else {
            return self;
        };
        let detail = Facts::new()
            .with("product", msi.product_code.clone())
            .with("store", store);
        self.push(
            EvidenceKind::InstallerManifest(ManifestKind::Msi),
            self.scope(),
            app_trust(self.ctx.fp),
            format!("msi:{}:{store}", msi.product_code),
            detail,
        );
        self
    }

    /// `InstallerManifest(Msi)`: a row of the package of `product_code` (one of the app's MSI products)
    /// writes the target. Checked against the rows the harvest recorded:
    ///
    /// - `Registry`: the row `row` of `fp.msi[].registry_rows` writes exactly this value, or removes
    ///   this key (or a key above it) whole; a per-user row of a per-machine product (`HKU\*`) matches
    ///   the key in any user's hive;
    /// - `ServiceInstall`: the target is the service `row` names, and the product installs it.
    ///
    /// Rows of the other tables are not in the fingerprint and give nothing.
    #[must_use]
    pub fn msi_row(mut self, product_code: &str, table: &'static str, row: &str) -> Self {
        let Some(msi) = self.ctx.own_msi(product_code) else {
            return self;
        };
        let ctx = self.ctx;
        let matches = match (table, &self.candidate.target) {
            ("Registry", target) => msi.registry_rows.iter().any(|r| {
                if r.row != row {
                    return false;
                }
                match target {
                    Target::RegValue { path, name } => {
                        let key = bind_any_user(&r.key, path);
                        let at_key = ctx.same_key(path, &key);
                        let same_value = match (&r.name, name.as_str()) {
                            (None, "") => true,
                            (Some(n), name) => prefix::eq_ci(n, name),
                            (None, _) => false,
                        };
                        (at_key && same_value && !r.whole_key)
                            || (r.whole_key
                                && matches!(
                                    ctx.key_relation(path, &key),
                                    Relation::Same | Relation::Inside
                                ))
                    }
                    Target::RegKey { path } => {
                        let key = bind_any_user(&r.key, path);
                        r.whole_key
                            && matches!(
                                ctx.key_relation(path, &key),
                                Relation::Same | Relation::Inside
                            )
                    }
                    _ => false,
                }
            }),
            ("ServiceInstall", Target::Service { name }) => {
                prefix::eq_ci(name, row) && msi.services.iter().any(|s| prefix::eq_ci(&s.name, row))
            }
            _ => false,
        };
        if !matches {
            return self;
        }
        let detail = Facts::new()
            .with("product", msi.product_code.clone())
            .with("row", format!("{table}:{row}"));
        self.push(
            EvidenceKind::InstallerManifest(ManifestKind::Msi),
            self.scope(),
            app_trust(self.ctx.fp),
            format!("msi:{}:{table}:{row}", msi.product_code),
            detail,
        );
        self
    }

    /// `InstallerManifest(Burn)`: the target is a registration (`what` names which) of the app's Burn
    /// bundle `bundle_id` (`fp.burn`: its bundle id or its provider key). Nothing for another bundle.
    #[must_use]
    pub fn burn_registration(mut self, bundle_id: &str, what: &'static str) -> Self {
        let Some(burn) = self.ctx.fp.burn.as_ref() else {
            return self;
        };
        let own = prefix::eq_ci(&burn.bundle_id, bundle_id)
            || burn
                .provider_key
                .as_deref()
                .is_some_and(|p| prefix::eq_ci(p, bundle_id));
        if !own || bundle_id.trim().is_empty() {
            return self;
        }
        let detail = Facts::new()
            .with("bundle", burn.bundle_id.clone())
            .with("what", what);
        self.push(
            EvidenceKind::InstallerManifest(ManifestKind::Burn),
            self.scope(),
            app_trust(self.ctx.fp),
            format!("burn:{}:{what}", burn.bundle_id),
            detail,
        );
        self
    }

    /// For a value of the path-keyed store `store` named after a path of the app
    /// ([`ScanCtx::path_from_value_name`]): `PointsIntoInstallRoot`, plus `DanglingRef` when
    /// `file_missing` and the full dangling rule holds for that path ([`ScanCtx::dangling`]: the whole
    /// root gone, absence proven on the recorded volume). Nothing for a target that is not a value of
    /// that store, or whose name is not a path of the app.
    #[must_use]
    pub fn path_named_value(mut self, store: PathStore, file_missing: bool) -> Self {
        let ctx = self.ctx;
        let Target::RegValue { path, name } = &self.candidate.target else {
            return self;
        };
        if ctx.path_keyed_store(path) != Some(store) {
            return self;
        }
        let Some(named) = ctx.path_from_value_name(store, name) else {
            return self;
        };
        if !self.points_into_install_root(&named) {
            return self;
        }
        if file_missing && let Some(dangling) = ctx.dangling(&named) {
            self.dangling_ref(&dangling);
        }
        self
    }

    /// Records the object's scan-time digest (C-OBJECT). Refused (nothing recorded, and the sealing then
    /// drops the candidate) when the target is not a system object of the digest's kind or the digest
    /// is not 64 lower-case hex digits.
    #[must_use]
    pub fn object_fp(mut self, fp: ObjectFp) -> Self {
        if ObjectKind::of(&self.candidate.target) == Some(fp.kind) && fp.is_well_formed() {
            self.candidate.object_fp = Some(fp);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every store pattern is a guard value container spelled exactly as the guard spells it, so that
    /// `path_keyed_store` can find the store from the guard's answer.
    #[test]
    fn path_store_patterns_are_guard_containers() {
        for (pattern, _) in PATH_STORES {
            assert!(
                purge_guard::containers::M1B_VALUE_CONTAINERS.contains(pattern),
                "{pattern}"
            );
        }
    }

    #[test]
    fn known_folder_guids_are_braced_upper_case_and_unique() {
        for (i, (guid, _)) in KNOWN_FOLDER_GUIDS.iter().enumerate() {
            assert_eq!(guid.len(), 38, "{guid}");
            assert!(guid.starts_with('{') && guid.ends_with('}'), "{guid}");
            assert_eq!(*guid, guid.to_ascii_uppercase(), "{guid}");
            assert!(
                KNOWN_FOLDER_GUIDS[i + 1..].iter().all(|(g, _)| g != guid),
                "{guid}"
            );
        }
    }

    #[test]
    fn rot13_round_trips_and_keeps_non_letters() {
        assert_eq!(
            rot13(r"P:\Cebtenz Svyrf\7-Mvc\7mSZ.rkr"),
            r"C:\Program Files\7-Zip\7zFM.exe"
        );
        assert_eq!(rot13(&rot13("Ünïcode {1}")), "Ünïcode {1}");
    }

    #[test]
    fn bind_any_user_binds_only_the_same_hive_kind() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            bind_any_user(r"HKU\*\Software\X", &format!(r"HKU\{sid}\Software\X")),
            format!(r"HKU\{sid}\Software\X")
        );
        assert_eq!(
            bind_any_user(r"HKU\*\Software\X", &format!(r"HKU\{sid}_Classes\X")),
            r"HKU\*\Software\X"
        );
        assert_eq!(
            bind_any_user(r"HKU\*_Classes\X", &format!(r"HKU\{sid}_Classes\X")),
            format!(r"HKU\{sid}_Classes\X")
        );
        assert_eq!(
            bind_any_user(r"HKLM\SOFTWARE\X", r"HKU\S\X"),
            r"HKLM\SOFTWARE\X"
        );
    }
}
