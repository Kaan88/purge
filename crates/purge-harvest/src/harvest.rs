//! The harvest orchestrator: one inventory entry in, one `purge.fp/0` fingerprint out (ENGINE_PLAN.md
//! §5.2 "Fingerprint", §6.1, §3.4 `purge-engine harvest … -o fp.json`).
//!
//! The harvest runs **before** the app's uninstaller and only reads. Its order is fixed, because each
//! step feeds the next:
//!
//! 1. machine facts: Windows edition and build, the interactive user, the environment, the guard facts;
//!    then the two M1b indexes: the ownership index of `purge-index` (only for an MSI or Burn entry)
//!    and the system-object index (services, tasks, firewall rules), which a second thread reads
//!    while steps 1 to 6 run (it depends on the machine alone and is first used in step 7; with a
//!    source meter installed, `PURGE_TIMING`, step 7 reads it, so each phase counts its own reads);
//! 2. the Inno Setup uninstall log, when the entry has one ([`crate::inno_map`]);
//! 3. the identity (`purge-identity`): names, vendors, tokens, proposed main exes; then the MSI facts
//!    ([`crate::msi`]) of an MSI entry, or the Burn facts ([`crate::burn`]) of a bundle and the MSI
//!    facts of the packages that are the bundle's alone;
//! 4. the validated roots ([`crate::roots`]), with the MSI component roots where the entry's own
//!    records leave room ([`msi::component_roots`]), and the exe set under them ([`crate::exes`]);
//! 5. the registry anchors ([`crate::anchors`]), the anchors of the app's own MSI tables
//!    ([`msi::table_anchors`]) and the harvested tokens ([`crate::tokens`]);
//! 6. the files the installer declares outside the roots (Inno log, MSI key paths), and the linked
//!    sparse packages ([`crate::appx_link`]);
//! 7. with all anchors known: the reference snapshot ([`crate::refsnap`]), the subtree baselines
//!    ([`crate::subtree`]), the file-association journal ([`crate::assoc`]) and the co-product
//!    candidates ([`crate::coproducts`]); then the system objects that are the app's
//!    ([`crate::sysobj`]);
//! 8. the stamps: Windows, user SID, install time.
//!
//! An entry that is neither MSI nor Burn and owns no service, task or firewall rule gives the same
//! document as before M1b, byte for byte.
//!
//! Nothing here fails. A fact that cannot be read becomes a line in the fingerprint's `warnings` and
//! the harvest goes on with less: fewer anchors only ever mean fewer findings.
//!
//! The output is deterministic: the same sources give a byte-identical document ([`to_json`]).
//!
//! # What the uninstall step adds later
//!
//! `window.t_start`, `window.t_end`, `verify_gone` and `co_removed` stay empty here. The co-product
//! *candidates* are returned in the [`HarvestReport`]; which of them really disappeared is known only
//! after the uninstaller ran.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use purge_guard::prefix;
use purge_identity::identity::{AppIdentity, IdentityHints};
use purge_identity::kbdata::Kb;
use purge_identity::tokenizer::vendor_key;
use purge_index::baseline_view::{BaselineTrust, BaselineView};
use purge_index::matcher::AnchorSet;
use purge_index::ownership::{
    OwnershipIndex, OwnershipInput, OwnershipStats, TableCache, area as ownership_area, pack_guid,
};
use purge_index::sysobj as sysobj_index;
use purge_model::{
    AppRef, ExeFile, FileTime, Fingerprint, FingerprintSchema, InstallerKind, InventoryDoc,
    InventoryEntry, OsInfo, RootKind, SysObjects, TimeWindow,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;

use crate::anchors::{self, AnchorInput, ModifiedClsid, ModifiedProgId};
use crate::appx_link::{self, LinkedPackage};
use crate::assoc;
use crate::burn;
use crate::coproducts::{self, CoProductPre};
use crate::exes::{self, ExeLimits};
use crate::inno_map::{self, UserBinding};
use crate::msi;
use crate::refsnap::{self, HarvestCtx};
use crate::roots::{self, InnoRootFacts, RejectedRoot, RootEnv, env_map};
use crate::shared_root;
use crate::subtree::{self, SubtreeOptions};
use crate::sysobj;
use crate::tokens::{self, DroppedToken, TokenInput};

/// The time before which a registry key is older than the app ([`anchors::ComCutoff`]).
///
/// The cutoff is only ever used one way: a key older than it is not the app's. A cutoff that is too
/// early therefore lets things through and never takes the app's own keys for older, and of two
/// candidates the later one is the stricter guard as long as it is not later than the install.
///
/// - A shared root: the start of the install as the walk found it (the earliest file the log
///   names). The directory's own creation time says nothing about an install into an existing
///   folder.
/// - Otherwise the inventory's hints: the creation time of the install directory (exact), else
///   the earliest other hint (a day of slack).
/// - A root the installer did not create and that was judged the app's alone (a folder the user
///   made beforehand, a reinstall into a leftover folder) has an install start from the walk too.
///   When that is later than the directory's creation it is the cutoff: the folder is older than
///   the install by as much as the user made it earlier.
///
/// What stays too early, and so unguarded for the time between: an upgrade (the directory and the
/// overwritten files keep the times of the first install, and what the user made between the
/// first install and the upgrade is younger than the cutoff), and every app without an Inno log
/// that was updated in place.
fn install_cutoff(
    demoted: &shared_root::Demoted,
    hints: &[purge_model::InstallTimeEvidence],
) -> Option<anchors::ComCutoff> {
    if let Some(time) = demoted.shared.iter().map(|s| s.install_start).min() {
        return Some(anchors::ComCutoff { time, exact: true });
    }
    let hinted = anchors::ComCutoff::of(hints);
    match (hinted, demoted.own_start) {
        (Some(cutoff), Some(start)) if cutoff.exact && cutoff.time >= start => Some(cutoff),
        (_, Some(start)) => Some(anchors::ComCutoff {
            time: start,
            exact: true,
        }),
        (hinted, None) => hinted,
    }
}

/// The value of an Inno Setup Uninstall key that names the app directory.
const INNO_APP_PATH: &str = "Inno Setup: App Path";

/// The three sources a harvest reads.
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The file system.
    pub fs: &'a dyn FileSystemSource,
    /// Machine and session facts.
    pub sys: &'a dyn SystemSource,
}

impl<'a> Sources<'a> {
    /// The sources of one object that implements all three (a fixture, the live machine).
    pub fn of<S>(source: &'a S) -> Self
    where
        S: RegistrySource + FileSystemSource + SystemSource,
    {
        Self {
            reg: source,
            fs: source,
            sys: source,
        }
    }
}

/// What the Inno Setup log gave, in numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InnoSummary {
    /// Canonical path of the log, when the entry has an Inno uninstaller.
    pub log_path: Option<String>,
    /// The log was read and parsed.
    pub parsed: bool,
    /// Records in the log, of every type.
    pub raw_records: usize,
    /// Records in the fingerprint.
    pub records: usize,
}

/// A fingerprint with the facts the document has no field for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestReport {
    /// The fingerprint.
    pub fingerprint: Fingerprint,
    /// Root claims that did not pass validation.
    pub rejected_roots: Vec<RejectedRoot>,
    /// Pre-existing or shared ProgIDs the app added verbs to; not in P.
    pub modified_progids: Vec<ModifiedProgId>,
    /// COM classes pointed at the app's files that are not its own registration; not anchors.
    pub modified_clsids: Vec<ModifiedClsid>,
    /// Candidate tokens that were not kept.
    pub dropped_tokens: Vec<DroppedToken>,
    /// The linked sparse packages, with their locations.
    pub linked_packages: Vec<LinkedPackage>,
    /// The Inno Setup log.
    pub inno: InnoSummary,
    /// Entries that may be removed together with the app.
    pub co_candidates: Vec<CoProductPre>,
    /// The reference scan read every key of its scope.
    pub refsnap_complete: bool,
    /// What the system-object index could not read (lists left empty, objects left out). A system
    /// object that was not read is not recorded; the fingerprint holds no warning for it, since an
    /// object that is not recorded is never offered as the app's.
    pub sysobj_errors: Vec<String>,
    /// What the ownership index read; `None` when the entry is neither MSI nor Burn and no index was
    /// built.
    pub ownership: Option<OwnershipStats>,
}

/// Harvests `entry`: see the module documentation. `baseline` is the baseline view
/// ([`BaselineView::empty`] without one); an Exact view is used only when it is for exactly the Windows
/// the sources describe. `kb` supplies vendor aliases.
pub fn harvest(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: &BaselineView,
    kb: &Kb,
) -> Fingerprint {
    harvest_report(entry, inventory, sources, baseline, kb).fingerprint
}

/// The vendor keys the knowledge base lists for the entry's publisher, when it is a mega-vendor.
fn kb_aliases(entry: &InventoryEntry, kb: &Kb) -> Vec<String> {
    let Some(publisher) = entry.publisher.as_deref() else {
        return Vec::new();
    };
    let key = vendor_key(publisher);
    if key.is_empty() {
        return Vec::new();
    }
    let at_boundary = |name: &str| {
        key.strip_prefix(name)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
    };
    kb.mega_vendors
        .entries()
        .iter()
        .find(|v| {
            std::iter::once(&v.vendor)
                .chain(&v.aliases)
                .any(|n| at_boundary(n))
        })
        .map(|v| {
            std::iter::once(&v.vendor)
                .chain(&v.aliases)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The known accounts as (name, SID): the profile directory names, and the interactive user.
fn known_users(
    sys: &dyn SystemSource,
    env: &BTreeMap<String, String>,
    user_sid: &str,
) -> Vec<(String, String)> {
    let mut users: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, sid: &str| {
        let name = name.trim();
        if !name.is_empty()
            && !sid.is_empty()
            && !users
                .iter()
                .any(|(n, s)| n.eq_ignore_ascii_case(name) && s.eq_ignore_ascii_case(sid))
        {
            users.push((name.to_owned(), sid.to_owned()));
        }
    };
    if let Some(name) = env.get("USERNAME") {
        add(name, user_sid);
    }
    for profile in sys.profiles().unwrap_or_default() {
        if let Some(name) = prefix::leaf(profile.path.trim_end_matches('\\')) {
            add(name, &profile.sid);
        }
    }
    users
}

/// The earliest of the entry's install-time hints.
fn install_time(entry: &InventoryEntry) -> Option<FileTime> {
    entry.install_time_evidence.iter().map(|e| e.time).min()
}

/// Options of [`harvest_report_with`].
#[derive(Clone, Copy, Default)]
pub struct HarvestOpts<'a> {
    /// A cache of MSI tables for the ownership index and the app's own packages; `None` reads every
    /// package from the source. Not used when [`HarvestOpts::shared`] is given: its cache is.
    pub table_cache: Option<&'a dyn TableCache>,
    /// The machine-wide indexes of the engine call, when the caller already has them; `None` makes
    /// the harvest set up its own from its arguments.
    pub shared: Option<&'a SharedIndexes<'a>>,
}

/// What one engine call reads of the whole machine at most once, shared by the target's harvest and
/// the harvests of its co-product candidates ([`crate::coproducts`]): the MSI table cache, the
/// ownership index and the system-object index. Each index is built when it is first asked for, from
/// the sources and the inventory given here, exactly as a harvest of its own would build it; a later
/// harvest gets the same index instead of building another one.
///
/// The ownership index is built from the whole inventory given here, `msi_only` included (R2a S8). A
/// co-product candidate's harvest used to build one from the entries alone.
pub struct SharedIndexes<'a> {
    sources: Sources<'a>,
    inventory: &'a InventoryDoc,
    table_cache: Option<&'a dyn TableCache>,
    ownership: OnceCell<OwnershipIndex>,
    sysobj: OnceCell<sysobj_index::SysObjectIndex>,
}

impl<'a> SharedIndexes<'a> {
    /// Nothing built yet; `table_cache` as in [`HarvestOpts::table_cache`].
    pub fn new(
        sources: Sources<'a>,
        inventory: &'a InventoryDoc,
        table_cache: Option<&'a dyn TableCache>,
    ) -> Self {
        Self {
            sources,
            inventory,
            table_cache,
            ownership: OnceCell::new(),
            sysobj: OnceCell::new(),
        }
    }

    /// The MSI table cache.
    pub fn table_cache(&self) -> Option<&'a dyn TableCache> {
        self.table_cache
    }

    /// The ownership index, built on the first call.
    pub fn ownership(&self) -> &OwnershipIndex {
        self.ownership.get_or_init(|| {
            OwnershipIndex::build(&OwnershipInput {
                reg: self.sources.reg,
                fs: self.sources.fs,
                sys: self.sources.sys,
                products: &self.inventory.entries,
                msi_only: &self.inventory.msi_only,
                cache: self.table_cache,
                threads: 0,
            })
        })
    }

    /// Whether the ownership index has been built.
    pub fn ownership_built(&self) -> bool {
        self.ownership.get().is_some()
    }

    /// The system-object index, built on the first call.
    pub fn sysobj(&self) -> &sysobj_index::SysObjectIndex {
        self.sysobj
            .get_or_init(|| sysobj_index::build(self.sources.reg, self.sources.sys))
    }

    /// Whether the system-object index has been built.
    pub fn sysobj_built(&self) -> bool {
        self.sysobj.get().is_some()
    }

    /// [`SharedIndexes::sysobj`], taking the index from `warm` when it is not built yet: a thread
    /// that is building it from the same sources ([`sysobj_index::build`]), so the index is the one
    /// the first call would have built.
    fn sysobj_from(
        &self,
        warm: Option<std::thread::ScopedJoinHandle<'_, sysobj_index::SysObjectIndex>>,
    ) -> &sysobj_index::SysObjectIndex {
        self.sysobj
            .get_or_init(|| match warm.map(std::thread::ScopedJoinHandle::join) {
                Some(Ok(index)) => index,
                Some(Err(panic)) => std::panic::resume_unwind(panic),
                None => sysobj_index::build(self.sources.reg, self.sources.sys),
            })
    }
}

/// What the fingerprint records about the view it was harvested with (BASELINE_LOCAL_DESIGN.md §4.5).
///
/// - An Exact view and a view that holds nothing record **nothing**: such a fingerprint is, byte for
///   byte, what it was before the field existed, and reads back as Exact with the matching shipped
///   baseline in hand and as None otherwise (`Fingerprint::harvest_trust`), which is what it is (L3).
/// - A view below Exact that holds a set records its name and local id, and as trust the trust of the
///   absence facts the harvest made with it. The local baseline is presence-only (DECISIONS.md,
///   Post-M1b, 2026-11-21), so that is `None` whatever the view's own trust
///   (`BaselineTrust::presence_only`): the harvest took "this is Windows' own" from the view and no
///   absence.
pub fn baseline_view_ref(view: &BaselineView) -> Option<purge_model::BaselineViewRef> {
    if view.trust() == BaselineTrust::Exact || view.holds_nothing() {
        return None;
    }
    Some(purge_model::BaselineViewRef {
        name: view.name(),
        trust: view.trust().presence_only(),
        local_id: view.local_id().map(str::to_owned),
    })
}

/// Like [`harvest`], with the facts the fingerprint has no field for.
pub fn harvest_report(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: &BaselineView,
    kb: &Kb,
) -> HarvestReport {
    harvest_report_with(
        entry,
        inventory,
        sources,
        baseline,
        kb,
        &HarvestOpts::default(),
    )
}

/// Whether the entry's installer is one the M1b MSI and Burn steps read.
/// At most this many notes of one M1b step go into the warnings; the rest are counted.
const MAX_NOTES: usize = 20;

/// Adds the notes of an M1b step to the warnings, at most [`MAX_NOTES`] of them.
fn push_notes(warnings: &mut Vec<String>, notes: &[String]) {
    warnings.extend(notes.iter().take(MAX_NOTES).cloned());
    if notes.len() > MAX_NOTES {
        warnings.push(format!("msi: and {} more notes", notes.len() - MAX_NOTES));
    }
}

fn reads_msi(entry: &InventoryEntry) -> bool {
    matches!(
        entry.installer_kind,
        InstallerKind::Msi | InstallerKind::Burn
    )
}

/// [`harvest_report`] with options: see the module documentation for the steps.
pub fn harvest_report_with(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: &BaselineView,
    kb: &Kb,
    opts: &HarvestOpts<'_>,
) -> HarvestReport {
    // The two M1b indexes, once per engine call: the caller's, or this harvest's own, which the
    // harvests of the co-product candidates then share.
    let own_shared;
    let shared: &SharedIndexes<'_> = match opts.shared {
        Some(shared) => shared,
        None => {
            own_shared = SharedIndexes::new(sources, inventory, opts.table_cache);
            &own_shared
        }
    };
    // With a source meter installed (`PURGE_TIMING`) nothing is read on a second thread: every
    // phase line then counts its own reads and no others, as in `ScanExt::build`, so the phase
    // lines of a harvest and of a scan compare.
    if shared.sysobj_built() || purge_source::metered::installed().is_some() {
        return harvest_report_shared(entry, inventory, sources, baseline, kb, shared, None);
    }
    // The system-object index (services, tasks, firewall rules) is read from the machine alone and
    // is first needed in step 7: it is built on a second thread while steps 1 to 6 run. When the
    // system refuses the thread, step 7 builds it.
    std::thread::scope(|scope| {
        let warm = std::thread::Builder::new()
            .spawn_scoped(scope, || sysobj_index::build(sources.reg, sources.sys))
            .ok();
        harvest_report_shared(entry, inventory, sources, baseline, kb, shared, warm)
    })
}

/// Writes a `PURGE_TIMING` phase line when a source meter is installed (the format of
/// `purge_index::ownership`): `timing:   phase harvest.<step> <seconds>s; <source calls>`.
struct Phase {
    name: &'static str,
    started: std::time::Instant,
    before: Option<purge_source::metered::MeterSnapshot>,
}

impl Phase {
    fn start(name: &'static str) -> Self {
        Self {
            name,
            started: std::time::Instant::now(),
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

/// [`harvest_report_with`] with the indexes of the engine call in hand; `warm` is the thread that is
/// building the system-object index, when one was started.
fn harvest_report_shared(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: &BaselineView,
    kb: &Kb,
    shared: &SharedIndexes<'_>,
    warm: Option<std::thread::ScopedJoinHandle<'_, sysobj_index::SysObjectIndex>>,
) -> HarvestReport {
    let Sources { reg, fs, sys } = sources;
    let mut warnings: Vec<String> = Vec::new();

    let phase = Phase::start("harvest.facts");
    // 1. Machine facts.
    let os = sys.os_info().unwrap_or_else(|e| {
        warnings.push(format!(
            "harvest: the Windows edition and build could not be read ({e}); no baseline is used"
        ));
        OsInfo {
            edition: String::new(),
            build: 0,
            ubr: 0,
        }
    });
    let user_sid = sys.user_sid().unwrap_or_else(|e| {
        warnings.push(format!(
            "harvest: the interactive user could not be determined ({e}); per-user registrations are not read"
        ));
        String::new()
    });
    let env_vars = sys.env().unwrap_or_else(|e| {
        warnings.push(format!("harvest: the environment could not be read ({e})"));
        BTreeMap::new()
    });
    let env = env_map(&env_vars);
    let (root_env, root_warnings) = RootEnv::from_sources(reg, sys, entry, inventory);
    warnings.extend(root_warnings);
    let guard = root_env.guard();

    let mut user_sids: Vec<String> = Vec::new();
    for sid in std::iter::once(&user_sid).chain(entry.hive_sid.as_ref()) {
        if !sid.is_empty() && !user_sids.iter().any(|s| s.eq_ignore_ascii_case(sid)) {
            user_sids.push(sid.clone());
        }
    }
    // The view the harvest asks "is this Windows' own?" (presence, at any trust). An Exact view of
    // another Windows says nothing about this machine and is not used at all.
    let mismatched = baseline.trust() == BaselineTrust::Exact
        && !baseline.is_exact_for(&os.edition, os.build, os.ubr);
    if mismatched {
        warnings.push(format!(
            "harvest: the baseline is for {}, not for this Windows ({}); it is not used",
            baseline.name(),
            os.baseline_name()
        ));
    }
    let matching_baseline: &BaselineView = if mismatched {
        BaselineView::empty()
    } else {
        baseline
    };
    // The ownership index (component clients, MSI rows, Burn dependents) is read only for an MSI or
    // Burn entry: nothing else of the harvest asks it.
    let table_cache = shared.table_cache();
    let ownership = reads_msi(entry).then(|| shared.ownership());

    phase.end();
    let phase = Phase::start("harvest.inno");
    // 2. The Inno Setup uninstall log.
    let binding = UserBinding {
        hive_sid: entry.hive_sid.clone(),
        users: known_users(sys, &env_vars, &user_sid),
    };
    let inno = inno_map::read(fs, entry, &binding, &env, guard);
    warnings.extend(inno.warnings.iter().cloned());

    phase.end();
    let phase = Phase::start("harvest.identity");
    // 3. Identity.
    let hints = IdentityHints {
        inno_app_name: inno.app_name.clone(),
        kb_aliases: kb_aliases(entry, kb),
        env: env_vars.clone(),
        ..IdentityHints::default()
    }
    .with_arp_urls(reg, entry);
    let identity = AppIdentity::resolve_with(entry, &inventory.entries, fs, &hints);
    warnings.extend(identity.warnings().iter().cloned());

    phase.end();
    let phase = Phase::start("harvest.msi");
    // 3b. MSI facts and Burn facts.
    let mut msi_harvests: Vec<msi::MsiHarvest> = Vec::new();
    let mut burn_harvest: Option<burn::BurnHarvest> = None;
    let mut components_complete = true;
    if let Some(ix) = &ownership {
        let read = msi::ReadCtx {
            ownership: ix,
            sys,
            fs,
            cache: table_cache,
            current_control_set: guard.current_control_set,
            env: &env,
            guard,
        };
        let mut products: Vec<msi::ProductInput> = Vec::new();
        match entry.installer_kind {
            InstallerKind::Burn => {
                let b = burn::harvest(reg, entry, ix, &env, guard);
                warnings.extend(b.warnings.iter().cloned());
                for packed in &b.children {
                    let child = inventory.entries.iter().find(|e| {
                        e.product_code
                            .as_deref()
                            .and_then(|c| pack_guid(c.trim()))
                            .is_some_and(|p| p == *packed)
                    });
                    match child.and_then(msi::ProductInput::of_entry) {
                        Some(mut product) => {
                            // Rule T follows the bundle's own entry too.
                            product.user_writable |= entry.hive_sid.is_some();
                            products.push(product);
                        }
                        None => warnings.push(format!(
                            "burn: the package {packed} has no inventory entry; it is not harvested"
                        )),
                    }
                }
                burn_harvest = Some(b);
            }
            _ => match msi::ProductInput::of_entry(entry) {
                Some(product) => products.push(product),
                None => warnings.push(
                    "msi: the entry has no ProductCode in GUID form; no MSI facts are read".into(),
                ),
            },
        }
        for product in &products {
            let h = msi::harvest_product(&read, product);
            warnings.extend(h.warnings.iter().cloned());
            msi_harvests.push(h);
        }
        let stats = ix.stats();
        components_complete = stats.complete(ownership_area::COMPONENTS);
        if !products.is_empty() && !components_complete {
            warnings.push(format!(
                "msi: the component registrations could not be read completely ({}); the MSI root \
                 rule is not applied",
                stats
                    .errors
                    .iter()
                    .take(MAX_NOTES)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    let own_codes: Vec<String> = msi_harvests
        .iter()
        .map(|h| h.facts.packed_code.clone())
        .collect();

    phase.end();
    let phase = Phase::start("harvest.roots");
    // 4. Roots and the exe set.
    let inno_facts = InnoRootFacts {
        app_path: reg
            .value(&entry.key_path, INNO_APP_PATH)
            .ok()
            .and_then(|d| d.string())
            .filter(|s| !s.trim().is_empty()),
        log_app_dirs: inno.app_dirs.clone(),
    };
    let mut root_set = roots::collect(fs, entry, &inno_facts, &env, &root_env);
    warnings.extend(root_set.rejected.iter().map(|r| format!("roots: {r}")));
    // A directory that held other things before the app was installed into it is not the app's alone
    // (`shared_root`): it is kept as an inferred root.
    let demoted = if inno.parsed {
        shared_root::demote(fs, &mut root_set.roots, &inno.records, &inno.created_dirs)
    } else {
        shared_root::Demoted::default()
    };
    for unjudged in &demoted.unjudged {
        warnings.push(format!(
            "roots: {} existed before the install and it cannot be shown that everything in it is \
             the app's ({}); it is treated as a shared folder, not as the app's own directory",
            unjudged.path, unjudged.why
        ));
    }
    for shared in &demoted.shared {
        warnings.push(format!(
            "roots: {} existed before the install and holds {} file(s) older than it that the \
             uninstall log does not name (first: {}); it is treated as a shared folder, not as the \
             app's own directory",
            shared.path, shared.foreign, shared.first
        ));
    }
    // MSI component roots (R-MSI): only where the M1a roots leave room, never wider.
    if let (Some(ix), true) = (&ownership, components_complete) {
        for h in msi_harvests.iter().filter(|h| !h.components_cut) {
            let product = &h.facts;
            let found = msi::component_roots(&msi::ComponentRootInput {
                fs,
                env: &root_env,
                ownership: ix,
                own_codes: &own_codes,
                components: &product.components,
                corroboration: &h.folder_dirs,
                existing: &root_set.roots,
                user_writable: h.user_writable,
            });
            warnings.extend(found.rejected.iter().map(|r| format!("roots: {r}")));
            push_notes(&mut warnings, &found.notes);
            root_set.rejected.extend(found.rejected);
            root_set.roots.extend(found.roots);
        }
        // Install roots first; the order is kept inside each kind.
        root_set
            .roots
            .sort_by_key(|r| u8::from(r.kind != RootKind::InstallRoot));
    }
    if root_set.roots.is_empty() {
        warnings
            .push("roots: the app has no validated root; nothing can be attributed by path".into());
    }
    phase.end();
    let phase = Phase::start("harvest.exes");
    let mut exe_set = exes::collect(
        fs,
        &root_set.roots,
        identity.main_exes(),
        ExeLimits::default(),
    );
    warnings.extend(exe_set.warnings.iter().cloned());
    // In a shared folder a program is the app's by the installer's record, not by where it lies.
    for path in shared_root::declared_code_files(fs, &demoted, &inno.records) {
        if !exe_set
            .files
            .iter()
            .any(|f| prefix::is_same(&f.path, &path))
        {
            exe_set.files.push(ExeFile { path, main: false });
        }
    }
    exe_set.files.sort_by_key(|f| prefix::fold(&f.path));
    let cutoff = install_cutoff(&demoted, &entry.install_time_evidence);

    phase.end();
    let phase = Phase::start("harvest.anchors");
    // 5. Anchors and tokens.
    let mut anchor_harvest = anchors::collect(AnchorInput {
        reg,
        fs,
        sys,
        roots: &root_set.roots,
        exes: &exe_set.files,
        guard,
        env: &env_vars,
        user_sids: &user_sids,
        baseline: matching_baseline,
        other_dirs: root_env.other_dirs(),
        other_files: root_env.other_files(),
        install_time: cutoff,
    });
    warnings.extend(anchor_harvest.warnings.iter().cloned());
    for class in &anchor_harvest.modified_clsids {
        warnings.push(format!(
            "anchors: the COM class {} points at the app's files but is not the app's own registration \
             ({:?}); it is not used as an anchor",
            class.id, class.reason
        ));
    }
    phase.end();
    let phase = Phase::start("harvest.tokens");
    // Anchors from the app's own MSI tables.
    if let (Some(ix), false) = (&ownership, msi_harvests.is_empty()) {
        let foreign: Vec<String> = anchor_harvest
            .foreign_names
            .iter()
            .cloned()
            .chain(
                anchor_harvest
                    .modified_progids
                    .iter()
                    .map(|m| m.name.clone()),
            )
            .chain(anchor_harvest.modified_clsids.iter().map(|m| m.id.clone()))
            .collect();
        let found = msi::table_anchors(
            &msi_harvests,
            &msi::TableAnchorInput {
                ownership: ix,
                own_codes: &own_codes,
                baseline: matching_baseline,
                foreign: &foreign,
            },
        );
        push_notes(&mut warnings, &found.notes);
        let a = &mut anchor_harvest.anchors;
        msi::merge_names(&mut a.clsids, &found.clsids);
        msi::merge_names(&mut a.progids, &found.progids);
        msi::merge_names(&mut a.typelibs, &found.typelibs);
        msi::merge_names(&mut a.appids, &found.appids);
    }
    let token_harvest = tokens::harvest(TokenInput {
        entry,
        inventory: &inventory.entries,
        progids: &anchor_harvest.anchors.progids,
        aumids: &anchor_harvest.anchors.aumids,
        inno_app_id: inno.app_id.as_deref(),
        foreign_names: &anchor_harvest.foreign_names,
        baseline: matching_baseline,
    });

    phase.end();
    let phase = Phase::start("harvest.outside");
    // 6. Files outside the roots, and the sparse packages.
    let mut outside_root_files = inno
        .log_path
        .as_deref()
        .map(|log| inno_map::outside_root_files(&inno.records, &root_set.roots, log))
        .unwrap_or_default();
    for h in &msi_harvests {
        for file in msi::outside_root_files(&h.facts, &root_set.roots) {
            if !outside_root_files
                .iter()
                .any(|f| prefix::is_same(&f.path, &file.path))
            {
                outside_root_files.push(file);
            }
        }
    }
    // The app's own uninstaller: what its uninstall commands run, and the Inno log next to it.
    let mut uninstallers: Vec<String> = [&entry.uninstall_string, &entry.quiet_uninstall_string]
        .into_iter()
        .flatten()
        .filter(|command| !purge_inventory::kind::is_msiexec(command))
        .filter_map(|command| roots::command_exe(command, &env, guard))
        .filter(|exe| !prefix::is_same_or_inside(exe, &guard.windir))
        .collect();
    if let Some(log) = &inno.log_path {
        uninstallers.push(log.clone());
        if let Some(stem) = log.strip_suffix(".dat") {
            uninstallers.push(format!("{stem}.msg"));
        }
    }
    uninstallers.sort_by_key(|path| prefix::fold(path));
    uninstallers.dedup_by(|a, b| prefix::is_same(a, b));
    let appx = appx_link::link(sys, &root_set.roots, guard);
    warnings.extend(appx.warnings.iter().cloned());
    let mut fp_anchors = anchor_harvest.anchors;
    fp_anchors.package_full_names = appx.full_names();
    fp_anchors.package_families = appx.families();

    let inno_summary = InnoSummary {
        log_path: inno.log_path.clone(),
        parsed: inno.parsed,
        raw_records: inno.raw_records,
        records: inno.records.len(),
    };
    let mut fp = Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: entry.program_id.clone(),
            display_name: entry.display_name.clone(),
        },
        identity: identity.snapshot(),
        roots: root_set.roots,
        exes: exe_set.files,
        outside_root_files,
        uninstallers,
        older_keys: Vec::new(),
        anchors: fp_anchors,
        tokens: token_harvest.tokens,
        inno: inno.records,
        ref_snapshot: Vec::new(),
        subtrees: Vec::new(),
        ext_journal: Vec::new(),
        co_removed: Vec::new(),
        msi: msi_harvests.iter().map(|h| h.facts.clone()).collect(),
        burn: burn_harvest.map(|b| b.facts),
        sys: SysObjects::default(),
        baseline_view: baseline_view_ref(matching_baseline),
        os,
        user_sid,
        window: TimeWindow {
            install_time: install_time(entry),
            t_start: None,
            t_end: None,
        },
        verify_gone: None,
        warnings: Vec::new(),
    };

    // 7. Everything that needs the full anchor set. The system-object index is in hand first: the
    // harvests of the co-product candidates ask the shared indexes for it.
    phase.end();
    let phase = Phase::start("harvest.sysobj_index");
    let sys_index = shared.sysobj_from(warm);
    phase.end();
    let anchor_set = AnchorSet::from_fingerprint(&fp);
    let ctx = HarvestCtx {
        reg,
        fs,
        sys,
        anchors: &anchor_set,
        roots: &fp.roots,
        inno: &fp.inno,
        baseline,
        inventory: &inventory.entries,
        target: entry,
        cutoff,
        shared: Some(shared),
    };
    let (snapshot, subtrees, journal, co_candidates) = if anchor_set.is_empty() {
        warnings.push(
            "harvest: the app has no anchor; the reference snapshot, the subtree baselines and the \
             association journal are empty"
                .into(),
        );
        (
            refsnap::RefSnap {
                complete: true,
                ..refsnap::RefSnap::default()
            },
            subtree::SubtreeCapture::default(),
            assoc::AssocJournal::default(),
            coproducts::candidates(&ctx),
        )
    } else {
        let phase = Phase::start("harvest.refsnap");
        let snapshot = refsnap::capture_report(&ctx);
        phase.end();
        let phase = Phase::start("harvest.subtree");
        let keys = subtree::keys(&ctx, &snapshot.entries);
        let subtrees = subtree::capture_with(&ctx, &keys, &SubtreeOptions::default());
        phase.end();
        let phase = Phase::start("harvest.assoc");
        let journal = assoc::capture_detailed(&ctx);
        phase.end();
        let phase = Phase::start("harvest.coproducts");
        let co = coproducts::candidates(&ctx);
        phase.end();
        (snapshot, subtrees, journal, co)
    };
    warnings.extend(snapshot.warnings.iter().cloned());
    warnings.extend(subtrees.warnings.iter().cloned());
    warnings.extend(journal.warnings.iter().cloned());
    let refsnap_complete = snapshot.complete;

    fp.ref_snapshot = snapshot.entries;
    fp.subtrees = subtrees.subtrees;
    fp.ext_journal = journal.records.into_iter().map(|r| r.entry).collect();
    let phase = Phase::start("harvest.older_keys");
    let candidates = subtree::older_key_candidates(&fp.subtrees, &fp.ext_journal, &fp.inno);
    fp.older_keys = subtree::older_keys(&ctx, candidates);

    phase.end();
    let phase = Phase::start("harvest.sysobj");
    // 7b. The system objects the app registered.
    let msi_services: Vec<String> = fp
        .msi
        .iter()
        .flat_map(|m| m.services.iter().map(|s| s.name.clone()))
        .collect();
    let sys_env = sysobj_index::Env::new(env_vars.iter().map(|(k, v)| (k, v.clone())));
    let objects = sysobj::record(&sysobj::SysInput {
        index: sys_index,
        roots: &fp.roots,
        exes: &fp.exes,
        outside: &fp.outside_root_files,
        msi_services: &msi_services,
        clsids: &fp.anchors.clsids,
        deny: root_env.deny(),
        baseline: matching_baseline,
        env: &sys_env,
    });
    phase.end();
    warnings.extend(objects.warnings);
    fp.sys = objects.objects;
    fp.warnings = warnings;

    HarvestReport {
        fingerprint: fp,
        rejected_roots: root_set.rejected,
        modified_progids: anchor_harvest.modified_progids,
        modified_clsids: anchor_harvest.modified_clsids,
        dropped_tokens: token_harvest.dropped,
        linked_packages: appx.packages,
        inno: inno_summary,
        co_candidates,
        refsnap_complete,
        sysobj_errors: sys_index.errors.clone(),
        ownership: ownership.map(|ix| ix.stats().clone()),
    }
}

/// The fingerprint as the text of an `fp.json` file: pretty-printed JSON with a final newline. The same
/// fingerprint always gives the same bytes.
pub fn to_json(fp: &Fingerprint) -> String {
    let mut text = serde_json::to_string_pretty(fp).expect("a fingerprint serialises to JSON");
    text.push('\n');
    text
}

/// Writes the fingerprint to `path` ([`to_json`]).
pub fn write(fp: &Fingerprint, path: &Path) -> io::Result<()> {
    std::fs::write(path, to_json(fp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::ModifiedReason;
    use crate::inno_map::testlog;
    use purge_guard::canon::GuardEnv;
    use purge_model::{InnoRecordKind, RootKind, RootSource, SourceTrust, Target};
    use purge_source::fixture::{Fixture, FixtureBuilder};
    use purge_source::types::{KnownFolder, PackageInfo, PackageSignatureKind};

    const SID: &str = GuardEnv::SAMPLE_SID;
    const CODE: &str = r"C:\Program Files\Microsoft VS Code";
    const CODE_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{EA457B21-F73E-494C-ACAB-524FDE069978}_is1";
    const CODE_GUID: &str = "EA457B21-F73E-494C-ACAB-524FDE069978";
    const CODE_PKG: &str = "Microsoft.VisualStudioCode_1.106.0.0_x64__8wekyb3d8bbwe";
    const EDGE_PKG: &str = "Microsoft.MicrosoftEdge.Stable_142.0.3595.65_neutral__8wekyb3d8bbwe";

    fn machine() -> FixtureBuilder {
        Fixture::builder()
            .os("Professional", 26100, 1742)
            .user_sid(SID)
            .profile(SID, r"C:\Users\tester")
            .env("USERNAME", "tester")
            .env("SYSTEMDRIVE", "C:")
            .env("WINDIR", r"C:\Windows")
            .env("SYSTEMROOT", r"C:\Windows")
            .env("PROGRAMFILES", r"C:\Program Files")
            .env("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            .env("PROGRAMDATA", r"C:\ProgramData")
            .env("PUBLIC", r"C:\Users\Public")
            .env("APPDATA", r"C:\Users\tester\AppData\Roaming")
            .env("LOCALAPPDATA", r"C:\Users\tester\AppData\Local")
            .known_folder(KnownFolder::Documents, r"C:\Users\tester\Documents")
            .admin_only_roots(&[
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\Windows",
            ])
            .volume(r"C:\", Some(0xAABB_CCDD), true, "NTFS")
            .key(r"HKLM\SYSTEM\ControlSet001\Services")
            .now(134_000_000_000_000_000)
    }

    fn sparse(full_name: &str, family: &str, external: &str) -> PackageInfo {
        PackageInfo {
            full_name: full_name.into(),
            family: family.into(),
            install_location: None,
            external_location: Some(external.into()),
            sparse: true,
            users: vec![SID.into()],
            is_framework: false,
            is_resource: false,
            signature_kind: PackageSignatureKind::Developer,
        }
    }

    fn command(b: FixtureBuilder, key: &str, verb: &str, command: &str) -> FixtureBuilder {
        b.sz(&format!(r"{key}\shell\{verb}\command"), "", command)
    }

    /// A machine with VS Code (system installer), Notepad and Edge.
    fn vscode_machine() -> Fixture {
        let code_exe = format!(r#""{CODE}\Code.exe" "%1""#);
        let log = testlog::build(
            "{{EA457B21-F73E-494C-ACAB-524FDE069978}",
            "Microsoft Visual Studio Code",
            crate::inno::MAX_SUPPORTED_VERSION,
            testlog::ADMIN,
            true,
            &[
                (testlog::START, 0, &["PC", "tester", CODE, ""]),
                (
                    testlog::FILE,
                    0,
                    &[r"C:\Program Files\Microsoft VS Code\Code.exe"],
                ),
                (testlog::DIR, 2, &[r"C:\Program Files\Microsoft VS Code"]),
                (testlog::KEY, testlog::HKCR, &["VSCode.txt"]),
                (
                    testlog::KEY,
                    testlog::HKLM,
                    &[r"Software\Classes\VSCodeSourceFile"],
                ),
                (
                    testlog::VALUE,
                    testlog::HKCU,
                    &["Environment", "VSCODE_TEST"],
                ),
                (testlog::END, 0, &[]),
            ],
        );
        let mut b = machine()
            // The Uninstall key, as Inno Setup writes it.
            .sz(CODE_KEY, "DisplayName", "Microsoft Visual Studio Code")
            .sz(CODE_KEY, "DisplayVersion", "1.106.0")
            .sz(CODE_KEY, "Publisher", "Microsoft Corporation")
            .sz(
                CODE_KEY,
                "InstallLocation",
                r"C:\Program Files\Microsoft VS Code\",
            )
            .sz(CODE_KEY, "Inno Setup: App Path", CODE)
            .sz(
                CODE_KEY,
                "DisplayIcon",
                r"C:\Program Files\Microsoft VS Code\Code.exe",
            )
            .sz(
                CODE_KEY,
                "UninstallString",
                r#""C:\Program Files\Microsoft VS Code\unins000.exe""#,
            )
            .sz(CODE_KEY, "URLInfoAbout", "https://code.visualstudio.com/")
            .key_lwt(CODE_KEY, 133_900_000_000_000_000)
            // Its files.
            .file(&format!(r"{CODE}\Code.exe"), 150_000_000)
            .file(&format!(r"{CODE}\unins000.exe"), 3_000_000)
            .file(&format!(r"{CODE}\ffmpeg.dll"), 2_000_000)
            .file(&format!(r"{CODE}\bin\rg.exe"), 20_000_000)
            .file(&format!(r"{CODE}\resources\app\package.json"), 100)
            .file_content(&format!(r"{CODE}\unins000.dat"), log)
            // Another app.
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other",
                "DisplayName",
                "Other Editor",
            )
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other",
                "UninstallString",
                r#""C:\Program Files\Other\uninstall.exe""#,
            )
            .file(r"C:\Program Files\Other\uninstall.exe", 10)
            .file(r"C:\Program Files\Other\other.exe", 10)
            // References to the app.
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Code.exe",
                "",
                r"C:\Program Files\Microsoft VS Code\Code.exe",
            )
            .sz(r"HKLM\SOFTWARE\Classes\.txt", "", "txtfile")
            .sz(
                r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids",
                "VSCode.txt",
                "",
            )
            .sz(
                r"HKLM\SOFTWARE\Classes\VSCode.txt\DefaultIcon",
                "",
                r"C:\Program Files\Microsoft VS Code\resources\app\resources\win32\default.ico",
            )
            .sz(
                &format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "Code Updater",
                r#""C:\Program Files\Microsoft VS Code\bin\rg.exe" --update"#,
            )
            .package(sparse(
                CODE_PKG,
                "Microsoft.VisualStudioCode_8wekyb3d8bbwe",
                r"C:\Program Files\Microsoft VS Code\69047191fc\appx",
            ))
            .package(sparse(
                EDGE_PKG,
                "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application",
            ));
        // The app's ProgIDs, machine-wide and (the URL protocol) per-user.
        for progid in ["VSCode.txt", "VSCode.json", "VSCodeSourceFile"] {
            b = command(
                b,
                &format!(r"HKLM\SOFTWARE\Classes\{progid}"),
                "open",
                &code_exe,
            );
        }
        b = command(
            b,
            &format!(r"HKU\{SID}_Classes\vscode"),
            "open",
            &format!(r#""{CODE}\Code.exe" --open-url -- "%1""#),
        );
        // `txtfile` ships with Windows; the app added a verb to it.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\txtfile",
            "open",
            r"%SystemRoot%\system32\NOTEPAD.EXE %1",
        );
        b = command(b, r"HKLM\SOFTWARE\Classes\txtfile", "VSCode", &code_exe);
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Other.Document",
            "open",
            r#""C:\Program Files\Other\other.exe" "%1""#,
        );
        b.build()
    }

    fn inventory_of(f: &Fixture) -> InventoryDoc {
        purge_inventory::arp::inventory(f, f, f, 0).doc
    }

    fn entry_named<'a>(doc: &'a InventoryDoc, name: &str) -> &'a InventoryEntry {
        doc.entries
            .iter()
            .find(|e| e.display_name == name)
            .unwrap_or_else(|| panic!("no entry {name:?} in {:?}", doc.entries))
    }

    #[test]
    fn vscode_shaped_fixture_gives_a_complete_fingerprint() {
        let f = vscode_machine();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Microsoft Visual Studio Code");
        let report = harvest_report(
            entry,
            &doc,
            Sources::of(&f),
            BaselineView::empty(),
            Kb::shipped(),
        );
        let fp = &report.fingerprint;

        // Roots: one InstallRoot, admin-only, with its volume.
        assert_eq!(fp.roots.len(), 1, "{:?}", fp.roots);
        assert_eq!(fp.roots[0].path, CODE);
        assert_eq!(fp.roots[0].kind, RootKind::InstallRoot);
        assert_eq!(fp.roots[0].trust, SourceTrust::AdminOnly);
        assert_eq!(fp.roots[0].volume_serial, Some(0xAABB_CCDD));
        assert!(fp.roots[0].parent_existed);
        // The app's own uninstaller: the program of the `UninstallString` and the log that was read,
        // with the message file of the same number.
        assert_eq!(
            fp.uninstallers,
            [
                r"C:\Program Files\Microsoft VS Code\unins000.dat",
                r"C:\Program Files\Microsoft VS Code\unins000.exe",
                r"C:\Program Files\Microsoft VS Code\unins000.msg",
            ]
        );
        assert!(
            report.rejected_roots.is_empty(),
            "{:?}",
            report.rejected_roots
        );

        // The exe set, with Code.exe as the main exe.
        let exes: Vec<(&str, bool)> = fp.exes.iter().map(|e| (e.path.as_str(), e.main)).collect();
        assert_eq!(
            exes,
            [
                (r"C:\Program Files\Microsoft VS Code\bin\rg.exe", false),
                (r"C:\Program Files\Microsoft VS Code\Code.exe", true),
                (r"C:\Program Files\Microsoft VS Code\ffmpeg.dll", false),
                (r"C:\Program Files\Microsoft VS Code\unins000.exe", false),
            ]
        );

        // P: the VSCode ProgIDs and the protocol; `txtfile` was only modified.
        assert_eq!(
            fp.anchors.progids,
            ["vscode", "VSCode.json", "VSCode.txt", "VSCodeSourceFile"]
        );
        assert_eq!(
            report.modified_progids,
            [ModifiedProgId {
                name: "txtfile".into(),
                reason: ModifiedReason::ForeignCommand
            }]
        );
        assert_eq!(fp.anchors.run_entries.len(), 1);
        assert_eq!(fp.anchors.run_entries[0].name, "Code Updater");

        // The linked sparse package is VS Code's, never Edge's.
        assert_eq!(fp.anchors.package_full_names, [CODE_PKG]);
        assert_eq!(
            fp.anchors.package_families,
            ["Microsoft.VisualStudioCode_8wekyb3d8bbwe"]
        );

        // Tokens: the AppId GUID, without braces.
        assert_eq!(fp.tokens.len(), 1, "{:?}", fp.tokens);
        assert_eq!(fp.tokens[0].token, CODE_GUID);
        assert_eq!(fp.tokens[0].source.0, "arp:key");

        // The Inno records: HKCU bound to the installing user, key-create on the keys.
        assert!(report.inno.parsed);
        assert_eq!(report.inno.raw_records, 7);
        assert_eq!(report.inno.records, fp.inno.len());
        let key_creates: Vec<&Target> = fp
            .inno
            .iter()
            .filter(|r| r.key_create)
            .map(|r| &r.target)
            .collect();
        assert_eq!(
            key_creates,
            [
                &Target::RegKey {
                    path: r"HKLM\SOFTWARE\Classes\VSCode.txt".into()
                },
                &Target::RegKey {
                    path: r"HKLM\SOFTWARE\Classes\VSCodeSourceFile".into()
                },
            ]
        );
        let user_value = fp
            .inno
            .iter()
            .find(|r| r.kind == InnoRecordKind::RegDeleteValue)
            .expect("the HKCU value record");
        assert!(user_value.user_hive);
        assert_eq!(
            user_value.target,
            Target::RegValue {
                path: format!(r"HKU\{SID}\Environment"),
                name: "VSCODE_TEST".into()
            }
        );

        // The second half ran: references, subtrees, journal.
        assert!(report.refsnap_complete);
        assert!(
            fp.ref_snapshot.iter().any(|e| matches!(
                &e.target,
                Target::RegValue { path, .. } if path.ends_with(r"App Paths\Code.exe")
            )),
            "{:?}",
            fp.ref_snapshot
        );
        assert!(
            fp.subtrees
                .iter()
                .any(|s| s.key.ends_with(r"Classes\VSCode.txt"))
        );
        assert!(
            fp.ext_journal
                .iter()
                .any(|j| j.ext == ".txt" && j.openwith_ours == ["VSCode.txt"])
        );

        // The stamps.
        assert_eq!(fp.os.baseline_name(), "Professional-26100.1742");
        assert_eq!(fp.user_sid, SID);
        assert!(fp.window.install_time.is_some());
        assert_eq!((fp.window.t_start, fp.window.t_end), (None, None));
        assert!(fp.verify_gone.is_none() && fp.co_removed.is_empty());
        assert!(fp.identity.mega_vendor);
        assert!(
            fp.identity
                .names
                .iter()
                .any(|n| n == "Microsoft Visual Studio Code")
        );
        // A fixture records no key owners, which the subtree harvest reports; nothing else is amiss.
        assert!(
            fp.warnings.iter().all(|w| w.starts_with("subtree:")),
            "{:?}",
            fp.warnings
        );

        // `harvest` is the fingerprint of the report.
        assert_eq!(
            &harvest(
                entry,
                &doc,
                Sources::of(&f),
                BaselineView::empty(),
                Kb::shipped()
            ),
            fp
        );
    }

    #[test]
    fn the_same_fixture_gives_byte_identical_json() {
        let first = {
            let f = vscode_machine();
            let doc = inventory_of(&f);
            let entry = entry_named(&doc, "Microsoft Visual Studio Code");
            to_json(&harvest(
                entry,
                &doc,
                Sources::of(&f),
                BaselineView::empty(),
                Kb::shipped(),
            ))
        };
        let second = {
            let f = vscode_machine();
            let doc = inventory_of(&f);
            let entry = entry_named(&doc, "Microsoft Visual Studio Code");
            to_json(&harvest(
                entry,
                &doc,
                Sources::of(&f),
                BaselineView::empty(),
                Kb::shipped(),
            ))
        };
        assert_eq!(first, second);
        assert!(
            first.starts_with("{\n  \"schema\": \"purge.fp/0\""),
            "{}",
            &first[..60]
        );
        assert!(first.ends_with("}\n"));
        // It is a valid fingerprint document and survives a round trip unchanged.
        let parsed: Fingerprint = serde_json::from_str(&first).unwrap();
        assert_eq!(to_json(&parsed), first);

        // And it reaches the disk as the same bytes.
        let dir = std::env::temp_dir().join(format!("purge-harvest-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fp.json");
        write(&parsed, &path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rule_t_a_per_user_entry_gives_user_writable_roots() {
        let app = r"C:\Users\tester\AppData\Local\Programs\Tool";
        let key = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall\Tool");
        let log = testlog::build(
            "Tool",
            "Tool",
            crate::inno::MAX_SUPPORTED_VERSION,
            0,
            true,
            &[
                (testlog::START, 0, &["PC", "somebody-else", app, ""]),
                (
                    testlog::KEY,
                    testlog::HKCU,
                    &[r"Software\Classes\Tool.File"],
                ),
                (testlog::END, 0, &[]),
            ],
        );
        let f = command(
            machine()
                .sz(&key, "DisplayName", "Tool")
                .sz(&key, "InstallLocation", app)
                .sz(&key, "UninstallString", &format!(r#""{app}\unins000.exe""#))
                .file(&format!(r"{app}\Tool.exe"), 1_000)
                .file(&format!(r"{app}\unins000.exe"), 1_000)
                .file_content(&format!(r"{app}\unins000.dat"), log)
                // Even a directory only administrators can write is not trusted through an HKU entry.
                .admin_only_writable(app, true),
            &format!(r"HKU\{SID}_Classes\Tool.File"),
            "open",
            &format!(r#""{app}\Tool.exe" "%1""#),
        )
        .build();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Tool");
        assert_eq!(entry.hive_sid.as_deref(), Some(SID));
        let report = harvest_report(
            entry,
            &doc,
            Sources::of(&f),
            BaselineView::empty(),
            Kb::shipped(),
        );
        let fp = &report.fingerprint;
        assert_eq!(
            fp.roots.len(),
            1,
            "{:?} / {:?}",
            fp.roots,
            report.rejected_roots
        );
        assert_eq!(fp.roots[0].path, app);
        assert_eq!(fp.roots[0].source, RootSource::ArpInstallLocation);
        assert_eq!(fp.roots[0].trust, SourceTrust::UserWritable);
        assert_eq!(fp.anchors.progids, ["Tool.File"]);
        // The log's HKCU record is bound to the hive of the entry, whatever account the log names.
        assert_eq!(
            fp.inno.iter().map(|r| &r.target).collect::<Vec<_>>(),
            [&Target::RegKey {
                path: format!(r"HKU\{SID}_Classes\Tool.File")
            }]
        );
        assert!(fp.inno[0].user_hive && fp.inno[0].key_create);
    }

    /// The cutoff "older than this is not the app's": see `install_cutoff`.
    #[test]
    fn the_install_cutoff_is_the_latest_time_known_not_to_be_after_the_install() {
        use purge_model::{FileTime, InstallTimeEvidence, InstallTimeSource};
        let hint = |source, time| InstallTimeEvidence {
            source,
            time: FileTime(time),
        };
        let dir = [
            hint(InstallTimeSource::InstallDirCreation, 1_000),
            hint(InstallTimeSource::ArpInstallDate, 900),
        ];
        let exact = |time| {
            Some(anchors::ComCutoff {
                time: FileTime(time),
                exact: true,
            })
        };
        let none = shared_root::Demoted::default();
        assert_eq!(install_cutoff(&none, &dir), exact(1_000));
        // Without the directory's time: the earliest other hint, not exact.
        assert_eq!(
            install_cutoff(&none, &dir[1..]),
            Some(anchors::ComCutoff {
                time: FileTime(900),
                exact: false
            })
        );
        assert_eq!(install_cutoff(&none, &[]), None);
        // A shared root: the start of the install as the walk found it, not the folder's time.
        let shared = shared_root::Demoted {
            shared: vec![shared_root::SharedRoot {
                path: r"C:\Tools".into(),
                install_start: FileTime(5_000),
                foreign: 1,
                first: r"C:\Tools\x".into(),
            }],
            ..shared_root::Demoted::default()
        };
        assert_eq!(install_cutoff(&shared, &dir), exact(5_000));
        // A folder made before the install and judged the app's alone: the later of the two.
        let own = |start| shared_root::Demoted {
            own_start: Some(FileTime(start)),
            ..shared_root::Demoted::default()
        };
        assert_eq!(install_cutoff(&own(5_000), &dir), exact(5_000));
        assert_eq!(install_cutoff(&own(500), &dir), exact(1_000));
        assert_eq!(install_cutoff(&own(500), &dir[1..]), exact(500));
        // A root that could not be judged changes nothing: the folder's time is early at worst.
        let unjudged = shared_root::Demoted {
            unjudged: vec![shared_root::UnjudgedRoot {
                path: r"C:\Tools".into(),
                why: "x".into(),
            }],
            ..shared_root::Demoted::default()
        };
        assert_eq!(install_cutoff(&unjudged, &dir), exact(1_000));
    }

    #[test]
    fn an_entry_without_a_usable_root_still_gives_a_document() {
        // InstallLocation is Program Files itself; the uninstaller sits in the Windows directory.
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Broken";
        let f = machine()
            .sz(key, "DisplayName", "Broken App")
            .sz(key, "InstallLocation", r"C:\Program Files\")
            .sz(key, "UninstallString", r"C:\Windows\uninst.exe /S")
            .file(r"C:\Windows\uninst.exe", 10)
            .dir(r"C:\Program Files")
            .build();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Broken App");
        let report = harvest_report(
            entry,
            &doc,
            Sources::of(&f),
            BaselineView::empty(),
            Kb::shipped(),
        );
        let fp = &report.fingerprint;
        assert!(fp.roots.is_empty(), "{:?}", fp.roots);
        assert!(!report.rejected_roots.is_empty());
        assert!(fp.exes.is_empty() && fp.anchors.progids.is_empty());
        // A program in the Windows directory is nobody's own uninstaller.
        assert!(fp.uninstallers.is_empty(), "{:?}", fp.uninstallers);
        assert!(fp.ref_snapshot.is_empty() && fp.subtrees.is_empty());
        assert!(
            fp.warnings.iter().any(|w| w.contains("rejected")),
            "{:?}",
            fp.warnings
        );
        assert!(fp.warnings.iter().any(|w| w.contains("no validated root")));
        assert_eq!(fp.app.display_name, "Broken App");
        serde_json::from_str::<Fingerprint>(&to_json(fp)).unwrap();
    }

    #[test]
    fn kb_aliases_come_from_the_mega_vendor_entry_of_the_publisher() {
        let mut entry = crate::roots::tests_support::entry("X", "X");
        assert!(kb_aliases(&entry, Kb::shipped()).is_empty());
        entry.publisher = Some("Microsoft Corporation".into());
        let aliases = kb_aliases(&entry, Kb::shipped());
        assert!(aliases.iter().any(|a| a == "microsoft"), "{aliases:?}");
        entry.publisher = Some("Nobody In Particular Ltd".into());
        assert!(kb_aliases(&entry, Kb::shipped()).is_empty());
    }

    // -----------------------------------------------------------------------------------------------------
    // Real rig snapshots
    // -----------------------------------------------------------------------------------------------------

    fn run_main_key(run_json: &Path) -> Option<String> {
        let text = std::fs::read_to_string(run_json).ok()?;
        let value: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
        value
            .get("main")
            .and_then(|m| m.get("key"))
            .and_then(|k| k.as_str())
            .map(str::to_owned)
    }

    /// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): harvests VS Code, Git, Firefox and Notepad++ from their
    /// post-install snapshots and prints a summary. `PURGE_OVERLAY_DIR`, when set, holds one directory
    /// per app with file contents the snapshot lacks (`<overlay>\<app>\C\Program Files\…\unins000.dat`).
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode, git, firefox and npp runs"]
    fn harvests_the_rig_snapshots() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let overlay_root = std::env::var_os("PURGE_OVERLAY_DIR").map(std::path::PathBuf::from);
        let baselines = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines");

        // (run, a word of the DisplayName, the family prefix of the sparse package it must link)
        let apps: [(&str, &str, Option<&str>); 4] = [
            (
                "vscode",
                "Visual Studio Code",
                Some("Microsoft.VisualStudioCode_"),
            ),
            ("git", "Git", None),
            ("firefox", "Firefox", None),
            ("npp", "Notepad++", Some("NotepadPlusPlus_")),
        ];
        for (app, name_part, package) in apps {
            let dir = Path::new(&runs).join(app);
            let snap = dir.join(format!("snap-{app}-1.tsv.gz"));
            let lists = dir.join(format!("lists-{app}-1.json"));
            let overlay = overlay_root
                .as_ref()
                .map(|o| o.join(app))
                .filter(|o| o.is_dir());
            let started = std::time::Instant::now();
            let f = Fixture::from_snap(
                &snap,
                lists.is_file().then_some(lists.as_path()),
                overlay.as_deref(),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", snap.display()));
            let loaded = started.elapsed();

            let doc = inventory_of(&f);
            let main_key = run_main_key(&dir.join("run.json"));
            let entry = main_key
                .as_deref()
                .and_then(|key| {
                    doc.entries.iter().find(|e| {
                        prefix::eq_ci(&e.key_path, key)
                            || prefix::leaf(&e.key_path)
                                .zip(prefix::leaf(key))
                                .is_some_and(|(a, b)| prefix::eq_ci(a, b))
                    })
                })
                .or_else(|| {
                    doc.entries
                        .iter()
                        .find(|e| e.display_name.contains(name_part))
                })
                .unwrap_or_else(|| panic!("{app}: no inventory entry for {name_part:?}"));

            use purge_source::system::SystemSource;
            let os = f.os_info().unwrap();
            let baseline =
                purge_index::baseline::Baseline::select(&baselines, &os.edition, os.build, os.ubr)
                    .map(BaselineView::exact);
            let started = std::time::Instant::now();
            let report = harvest_report(
                entry,
                &doc,
                Sources::of(&f),
                BaselineView::or_empty(baseline.as_ref()),
                Kb::shipped(),
            );
            let took = started.elapsed();
            let fp = &report.fingerprint;

            eprintln!("== {app}: {} ({})", fp.app.display_name, fp.app.program_id);
            eprintln!(
                "   fixture loaded in {loaded:?}, harvested in {took:?}; baseline {}: {}",
                os.baseline_name(),
                if baseline.is_some() { "loaded" } else { "none" }
            );
            for root in &fp.roots {
                eprintln!(
                    "   root {:?} {:?} {:?} {}",
                    root.kind, root.source, root.trust, root.path
                );
            }
            for rejected in &report.rejected_roots {
                eprintln!("   rejected: {rejected}");
            }
            eprintln!(
                "   exes {} ({} main), |P| {}, modified ProgIDs {}, CLSIDs {}, AppIDs {}, TypeLibs {}, AUMIDs {}, Run {}",
                fp.exes.len(),
                fp.main_exes().count(),
                fp.anchors.progids.len(),
                report.modified_progids.len(),
                fp.anchors.clsids.len(),
                fp.anchors.appids.len(),
                fp.anchors.typelibs.len(),
                fp.anchors.aumids.len(),
                fp.anchors.run_entries.len()
            );
            eprintln!("   P: {:?}", fp.anchors.progids);
            eprintln!("   modified: {:?}", report.modified_progids);
            eprintln!("   AUMIDs: {:?}", fp.anchors.aumids);
            eprintln!(
                "   tokens: {:?}; dropped: {:?}",
                fp.tokens
                    .iter()
                    .map(|t| (&t.token, &t.source.0))
                    .collect::<Vec<_>>(),
                report.dropped_tokens
            );
            eprintln!(
                "   inno: log {:?}, parsed {}, {} raw record(s), {} mapped; {} file(s) outside the roots",
                report.inno.log_path,
                report.inno.parsed,
                report.inno.raw_records,
                report.inno.records,
                fp.outside_root_files.len()
            );
            eprintln!(
                "   refsnap {} (complete {}), subtrees {}, ext journal {}, co-product candidates {:?}",
                fp.ref_snapshot.len(),
                report.refsnap_complete,
                fp.subtrees.len(),
                fp.ext_journal.len(),
                report
                    .co_candidates
                    .iter()
                    .map(|c| &c.app.display_name)
                    .collect::<Vec<_>>()
            );
            eprintln!("   packages: {:?}", fp.anchors.package_full_names);
            for warning in &fp.warnings {
                eprintln!("   warning: {warning}");
            }

            // The linked sparse packages are exactly the app's own.
            match package {
                Some(prefix) => {
                    assert_eq!(
                        fp.anchors.package_full_names.len(),
                        1,
                        "{app}: {:?}",
                        fp.anchors.package_full_names
                    );
                    assert!(
                        fp.anchors.package_full_names[0].starts_with(prefix),
                        "{app}: {:?}",
                        fp.anchors.package_full_names
                    );
                }
                None => assert!(
                    fp.anchors.package_full_names.is_empty(),
                    "{app}: {:?}",
                    fp.anchors.package_full_names
                ),
            }
            assert!(
                fp.anchors
                    .package_full_names
                    .iter()
                    .all(|p| !p.to_ascii_lowercase().contains("edge")),
                "{app}: the Edge sparse package must never be linked"
            );
            assert!(!fp.roots.is_empty(), "{app}: no root");
            if app == "vscode" {
                assert!(fp.anchors.progids.iter().any(|p| p.starts_with("VSCode.")));
                assert!(
                    !fp.anchors
                        .progids
                        .iter()
                        .any(|p| p.eq_ignore_ascii_case("txtfile"))
                );
            }
            if app == "firefox" {
                assert!(
                    fp.tokens.iter().any(|t| t.token == "308046B0AF4A39CB"),
                    "firefox: {:?} / {:?}",
                    fp.tokens,
                    report.dropped_tokens
                );
            }
            // Deterministic on real data too.
            let again = harvest(
                entry,
                &doc,
                Sources::of(&f),
                BaselineView::or_empty(baseline.as_ref()),
                Kb::shipped(),
            );
            assert_eq!(to_json(&again), to_json(fp), "{app}: not deterministic");
        }
    }

    /// §4.5: what the fingerprint records about its view. An Exact view and an empty one record
    /// nothing (the document is what it was before the field existed, L3); a view below Exact that
    /// holds a set records its name and local id, and the trust of the absence facts made with it,
    /// which is None while the local baseline is presence-only.
    #[test]
    fn the_fingerprint_records_a_view_below_exact_as_presence_only() {
        use purge_index::baseline_view::fixture;
        use purge_model::{BaselineTrust, BaselineViewRef};
        let (e, b, u) = ("Professional", 26100, 1742);
        assert_eq!(
            baseline_view_ref(&BaselineView::exact(fixture::shipped(e, b, u, &[]))),
            None
        );
        assert_eq!(baseline_view_ref(BaselineView::empty()), None);
        let merged = fixture::merged_view(e, b, u, &[], &[]);
        assert_eq!(merged.trust(), BaselineTrust::Merged);
        assert_eq!(
            baseline_view_ref(&merged),
            Some(BaselineViewRef {
                name: "local-Professional-26100.1742+1".into(),
                trust: BaselineTrust::None,
                local_id: Some("0123456789abcdef".into()),
            })
        );
        assert_eq!(
            baseline_view_ref(&fixture::local_view(e, b, u, &[])),
            Some(BaselineViewRef {
                name: "local-Professional-26100.1742".into(),
                trust: BaselineTrust::None,
                local_id: Some("0123456789abcdef".into()),
            })
        );
        assert_eq!(
            baseline_view_ref(&fixture::none_view(e, b, u, &[])),
            Some(BaselineViewRef {
                name: "none+1".into(),
                trust: BaselineTrust::None,
                local_id: None,
            })
        );

        // A whole harvest: with a view below Exact that holds nothing the app touches, the fingerprint
        // is the no-baseline fingerprint plus the field; the recorded trust caps nothing at scan time.
        let f = vscode_machine();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Microsoft Visual Studio Code");
        let os = {
            use purge_source::system::SystemSource;
            f.os_info().unwrap()
        };
        let none = harvest(
            entry,
            &doc,
            Sources::of(&f),
            BaselineView::empty(),
            Kb::shipped(),
        );
        assert_eq!(none.baseline_view, None);
        assert!(!to_json(&none).contains("baseline_view"));
        for which in 1..fixture::BELOW_EXACT {
            let view = fixture::below_exact(which, &os).unwrap();
            let mut fp = harvest(entry, &doc, Sources::of(&f), &view, Kb::shipped());
            let recorded = fp.baseline_view.take().expect("the view is recorded");
            assert_eq!(recorded.name, view.name());
            assert_eq!(recorded.trust, BaselineTrust::None);
            assert_eq!(to_json(&fp), to_json(&none), "{}", view.name());
            fp.baseline_view = Some(recorded);
            for exact_shipped in [false, true] {
                assert_eq!(fp.harvest_trust(exact_shipped), BaselineTrust::None);
            }
            let back: Fingerprint = serde_json::from_str(&to_json(&fp)).unwrap();
            assert_eq!(back, fp);
        }

        // An exact baseline of another Windows is not used at all, as before the view.
        let other = BaselineView::exact(fixture::shipped("EnterpriseS", os.build, os.ubr, &[]));
        let fp = harvest(entry, &doc, Sources::of(&f), &other, Kb::shipped());
        assert_eq!(fp.baseline_view, None);
        assert!(
            fp.warnings
                .iter()
                .any(|w| w.contains("harvest: the baseline is for EnterpriseS-")
                    && w.contains("it is not used")),
            "{:?}",
            fp.warnings
        );
    }
}
