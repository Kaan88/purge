//! Harvest of MSI package facts: components, key paths, registry rows, services, and the install folder
//! derived from component key paths (M1b, contract C-FP, design rule R-MSI).
//!
//! Everything here comes from two places and nothing else: the ownership index of `purge-index`
//! (component clients and key paths, read once from `Installer\UserData\<sid>\Components`) and the app's
//! own cached package (`LocalPackage`), resolved by the one row resolver
//! [`purge_index::ownership::msi_rows::resolve`]. No registry or file walk is made.
//!
//! # The install folder of an MSI app (R-MSI)
//!
//! Many MSI packages register no `InstallLocation` and no `DisplayIcon` (the 7-Zip MSI), so the M1a root
//! logic finds no root. [`component_roots`] derives one from the file key paths of the product's
//! components:
//!
//! 1. Only components whose only client is the product count (`other_clients` empty): a component with
//!    any other client — another product, a stale registration, the permanent marker — contributes
//!    nothing at all.
//! 2. Key paths under `%SystemRoot%`, under a Package Cache root, under `Common Files\microsoft shared`,
//!    and key paths for which [`validate_root`] rejects every ancestor are dropped.
//! 3. The rest are grouped by their *top*: the highest ancestor directory [`validate_root`] accepts.
//!    Tops are never nested (an accepted ancestor of one top would be a higher accepted ancestor of
//!    every file under it), so groups never overlap.
//! 4. A group gives a root only with at least two distinct key-path files, or with one whose directory
//!    is corroborated: the directory of an `InstallLocation`/`ARPINSTALLLOCATION`/`INSTALLDIR`-style
//!    value of the product, or of a shortcut target the caller already harvested.
//! 5. The root is the lowest common ancestor directory of the group's files. It must pass
//!    [`resolve_root`] (so [`validate_root`] too), must not be at or inside a directory another
//!    installed app declares (its `InstallLocation`, or the directory of its uninstaller, icon or
//!    service image), and no component with a key path at or below it may have a client that is not
//!    one of the app's own products (stale clients count as others).
//! 6. A candidate at, inside or above an existing root (the M1a roots) adds nothing: R-MSI never widens
//!    or replaces a root.
//!
//! Key-path files of the app's own components that fall in no root are recorded as
//! [`AppFileOutsideRoot`] ([`outside_root_files`]); they are never roots.
//!
//! # Limits
//!
//! At most [`MAX_COMPONENTS`] components and [`MAX_REGISTRY_ROWS`] registry rows are recorded per
//! product. Beyond that the list is cut, a warning names the cut, and for components the root rule is
//! not applied at all: a partial component list could hide a foreign client.

use std::collections::BTreeMap;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::prefix;
use purge_index::baseline_view::BaselineView;
use purge_index::ownership::msi_rows::{self, ResolvedRow, RowContext};
use purge_index::ownership::{CacheKey, OwnershipIndex, TableCache, pack_guid, unpack_guid};
use purge_model::{
    AppFileOutsideRoot, InventoryEntry, MsiComponentFact, MsiContext, MsiFacts, MsiKeyPath, Root,
    SourceId,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::sysobj::MsiTables;
use purge_source::system::SystemSource;
use purge_win::env::EnvMap;

use crate::roots::{
    RejectedRoot, RootEnv, canon_file, clean_value, package_cache_roots, parent_dir, resolve_root,
    validate_root,
};
use purge_model::RootSource;

/// Most components recorded per product. Beyond it the list is cut and the root rule is not applied.
pub const MAX_COMPONENTS: usize = 5_000;

/// Most registry rows recorded per product.
pub const MAX_REGISTRY_ROWS: usize = 20_000;

/// The words of the warning for a product whose cached package could not be read.
pub const UNREADABLE: &str = "msi package unreadable";

/// The `Property` table entries whose value, when it is an absolute path, names the product's install
/// folder and so corroborates a single-file group.
pub const FOLDER_PROPERTIES: [&str; 6] = [
    "ARPINSTALLLOCATION",
    "INSTALLDIR",
    "INSTALLLOCATION",
    "INSTALLFOLDER",
    "APPLICATIONFOLDER",
    "APPDIR",
];

/// `{GUID}` in upper case, or `None` when `text` is not a braced GUID.
pub fn braced_upper(text: &str) -> Option<String> {
    pack_guid(text.trim()).and_then(|packed| unpack_guid(&packed))
}

/// One MSI product of the app, as the harvest reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductInput {
    /// ProductCode, `{GUID}` in upper case.
    pub product_code: String,
    /// Its packed form.
    pub packed_code: String,
    /// UpgradeCode from the inventory, when known.
    pub upgrade_code: Option<String>,
    /// The installation context.
    pub context: MsiContext,
    /// The user of a per-user product.
    pub user_sid: Option<String>,
    /// The cached package.
    pub local_package: Option<String>,
    /// The entry's `InstallLocation`, as written.
    pub install_location: Option<String>,
    /// The claim was read from a user hive, or the product is per-user (Rule T).
    pub user_writable: bool,
}

impl ProductInput {
    /// The product of an inventory entry: `None` when the entry has no ProductCode in GUID form. An
    /// entry Windows Installer does not list keeps the context its hive implies and has no package.
    pub fn of_entry(entry: &InventoryEntry) -> Option<Self> {
        let packed = pack_guid(entry.product_code.as_deref()?.trim())?;
        let product_code = unpack_guid(&packed)?;
        let (context, local_package) = match &entry.msi {
            Some(msi) => (msi.context, msi.local_package.clone()),
            None if entry.hive_sid.is_some() => (MsiContext::UserUnmanaged, None),
            None => (MsiContext::Machine, None),
        };
        let user_sid = match context {
            MsiContext::Machine => None,
            _ => entry.hive_sid.clone(),
        };
        Some(Self {
            product_code,
            packed_code: packed,
            upgrade_code: entry.upgrade_code.as_deref().and_then(braced_upper),
            context,
            user_writable: entry.hive_sid.is_some() || context != MsiContext::Machine,
            user_sid,
            local_package: local_package.filter(|p| !p.trim().is_empty()),
            install_location: entry.install_location.clone(),
        })
    }
}

/// What the harvest read about one product.
#[derive(Debug, Clone)]
pub struct MsiHarvest {
    /// The facts for the fingerprint.
    pub facts: MsiFacts,
    /// The component list was cut at [`MAX_COMPONENTS`]: the root rule is not applied.
    pub components_cut: bool,
    /// The `Class`, `ProgId`, `TypeLib` and `AppId` rows of the package, resolved.
    pub anchor_rows: Vec<ResolvedRow>,
    /// The package's `Component` table: table key to `ComponentId` (`{GUID}` upper).
    pub component_ids: BTreeMap<String, String>,
    /// Directories the package names as its install folder ([`FOLDER_PROPERTIES`]) and the entry's
    /// `InstallLocation`, canonical.
    pub folder_dirs: Vec<String>,
    /// Rule T for roots derived from the product ([`ProductInput::user_writable`]).
    pub user_writable: bool,
    /// What the fingerprint's warnings get.
    pub warnings: Vec<String>,
}

/// Reads one package's tables, from `cache` when it has them (keyed as the ownership index keys them),
/// else from the source; a complete read is put into the cache.
pub fn read_tables(
    sys: &dyn SystemSource,
    fs: &dyn FileSystemSource,
    cache: Option<&dyn TableCache>,
    local_package: &str,
) -> Result<MsiTables, String> {
    let canonical = canon_path(local_package, &GuardEnv::default(), None)
        .map(|c| c.path)
        .unwrap_or_else(|_| local_package.to_owned());
    let key = fs.metadata(&canonical).ok().and_then(|m| {
        m.times.modified.map(|t| CacheKey {
            local_package: canonical.clone(),
            size: m.size,
            mtime: t.0,
        })
    });
    if let (Some(cache), Some(key)) = (cache, &key) {
        if let Some(tables) = cache.get(key) {
            return Ok(tables);
        }
    }
    let tables = sys.msi_tables(local_package).map_err(|e| e.to_string())?;
    if let (Some(cache), Some(key), false) = (cache, &key, tables.truncated) {
        cache.put(key, &tables);
    }
    Ok(tables)
}

/// The component facts of a product from the ownership index: one fact per (component, key path),
/// sorted by component id, then key path. `other_clients` is every client but `packed`, as found.
pub fn components(ix: &OwnershipIndex, packed: &str) -> Vec<MsiComponentFact> {
    let mut out: Vec<MsiComponentFact> = Vec::new();
    for (id, key_path) in ix.components_of(packed) {
        let mut other_clients: Vec<String> = ix
            .clients_of(id)
            .iter()
            .filter(|c| !c.eq_ignore_ascii_case(packed))
            .cloned()
            .collect();
        other_clients.sort();
        other_clients.dedup();
        let shared_dll = match key_path {
            MsiKeyPath::File { path } => ix
                .file_owners(path)
                .iter()
                .any(|o| o.component_id == id && o.shared_dll),
            _ => false,
        };
        let fact = MsiComponentFact {
            component_id: id.to_owned(),
            key_path: key_path.clone(),
            other_clients,
            shared_dll,
        };
        if !out.contains(&fact) {
            out.push(fact);
        }
    }
    out.sort_by(|a, b| {
        (a.component_id.as_str(), key_path_order(&a.key_path))
            .cmp(&(b.component_id.as_str(), key_path_order(&b.key_path)))
    });
    out
}

fn key_path_order(kp: &MsiKeyPath) -> (u8, String, String) {
    match kp {
        MsiKeyPath::File { path } => (0, prefix::fold(path), String::new()),
        MsiKeyPath::Registry { key, name } => (
            1,
            prefix::fold(key),
            name.as_deref().map(prefix::fold).unwrap_or_default(),
        ),
        MsiKeyPath::None => (2, String::new(), String::new()),
    }
}

/// The canonical directory a path-like value names, when it is one absolute local directory.
fn folder_dir(raw: &str, env: &EnvMap, guard: &GuardEnv) -> Option<String> {
    let cleaned = clean_value(raw, env)?;
    if cleaned.contains(['[', ']', '%']) {
        return None;
    }
    canon_file(cleaned.trim_end_matches('\\'), guard).filter(|p| prefix::depth(p) >= 2)
}

/// What [`harvest_product`] reads from.
#[derive(Clone, Copy)]
pub struct ReadCtx<'a> {
    /// The ownership index.
    pub ownership: &'a OwnershipIndex,
    /// The MSI tables.
    pub sys: &'a dyn SystemSource,
    /// Package metadata, for the cache key.
    pub fs: &'a dyn FileSystemSource,
    /// The table cache.
    pub cache: Option<&'a dyn TableCache>,
    /// `N` of `ControlSet00N` (`ServiceInstall` rows).
    pub current_control_set: u32,
    /// The interactive user's environment (folder values).
    pub env: &'a EnvMap,
    /// The guard's facts (canonical forms).
    pub guard: &'a GuardEnv,
}

/// Harvests one product: its components from the index, its rows from its own package.
pub fn harvest_product(ctx: &ReadCtx<'_>, product: &ProductInput) -> MsiHarvest {
    let ReadCtx {
        ownership: ix,
        sys,
        fs,
        cache,
        current_control_set,
        env,
        guard,
    } = *ctx;
    let code = &product.product_code;
    let mut warnings: Vec<String> = Vec::new();

    let mut comps = components(ix, &product.packed_code);
    let components_cut = comps.len() > MAX_COMPONENTS;
    if components_cut {
        warnings.push(format!(
            "msi: {code}: {} components, more than {MAX_COMPONENTS}; the list is cut and the MSI root \
             rule is not applied",
            comps.len()
        ));
        comps.truncate(MAX_COMPONENTS);
    }

    let mut folder_dirs: Vec<String> = Vec::new();
    let mut push_dir = |dir: Option<String>| {
        if let Some(dir) = dir {
            if !folder_dirs.iter().any(|d| prefix::is_same(d, &dir)) {
                folder_dirs.push(dir);
            }
        }
    };
    push_dir(
        product
            .install_location
            .as_deref()
            .and_then(|l| folder_dir(l, env, guard)),
    );

    let tables = match product.local_package.as_deref() {
        None => Err("no LocalPackage is registered".to_owned()),
        Some(lp) => match read_tables(sys, fs, cache, lp) {
            Ok(t) if t.truncated => Err(format!("{lp}: the tables are truncated")),
            Ok(t) => Ok(t),
            Err(e) => Err(format!("{lp}: {e}")),
        },
    };
    let mut facts = MsiFacts {
        product_code: code.clone(),
        packed_code: product.packed_code.clone(),
        upgrade_code: product.upgrade_code.clone(),
        context: product.context,
        user_sid: product.user_sid.clone(),
        local_package: product.local_package.clone(),
        package_readable: false,
        components: comps,
        registry_rows: Vec::new(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    };
    let mut anchor_rows = Vec::new();
    let mut component_ids = BTreeMap::new();
    match tables {
        Err(why) => warnings.push(format!("msi: {code}: {UNREADABLE} ({why})")),
        Ok(tables) => {
            facts.package_readable = true;
            facts.custom_actions = tables.custom_action_count;
            if let Some(upgrade) = tables
                .properties
                .iter()
                .find(|(name, _)| name == "UpgradeCode")
                .and_then(|(_, value)| braced_upper(value))
            {
                facts.upgrade_code = Some(upgrade);
            }
            for name in FOLDER_PROPERTIES {
                for (_, value) in tables.properties.iter().filter(|(n, _)| n == name) {
                    push_dir(folder_dir(value, env, guard));
                }
            }
            for row in &tables.components {
                if let Some(id) = row.component_id.as_deref().and_then(braced_upper) {
                    component_ids.insert(row.component.clone(), id);
                }
            }
            let ctx = RowContext {
                product_code: code,
                context: product.context,
                user_sid: product.user_sid.as_deref(),
                current_control_set,
            };
            let resolved = msi_rows::resolve(&tables, &ctx);
            facts.unresolved_rows = resolved.unresolved;
            facts.services = resolved.services;
            let mut rows: Vec<_> = resolved
                .rows
                .iter()
                .filter_map(ResolvedRow::to_reg_row)
                .collect();
            if rows.len() > MAX_REGISTRY_ROWS {
                warnings.push(format!(
                    "msi: {code}: {} registry rows, more than {MAX_REGISTRY_ROWS}; the list is cut",
                    rows.len()
                ));
                rows.truncate(MAX_REGISTRY_ROWS);
            }
            facts.registry_rows = rows;
            anchor_rows = resolved
                .rows
                .into_iter()
                .filter(|r| matches!(r.table, "Class" | "ProgId" | "TypeLib" | "AppId"))
                .collect();
        }
    }
    MsiHarvest {
        facts,
        components_cut,
        anchor_rows,
        component_ids,
        folder_dirs,
        user_writable: product.user_writable,
        warnings,
    }
}

// ---------------------------------------------------------------------------------------------------------
// R-MSI: roots from component key paths
// ---------------------------------------------------------------------------------------------------------

/// What [`component_roots`] works from.
#[derive(Clone, Copy)]
pub struct ComponentRootInput<'a> {
    /// The file system (the root must exist and must not be a reparse point).
    pub fs: &'a dyn FileSystemSource,
    /// The validation environment.
    pub env: &'a RootEnv,
    /// The ownership index.
    pub ownership: &'a OwnershipIndex,
    /// The packed codes of the app's own products (the product itself; for a Burn bundle, every
    /// harvested package). A component with any other client in a candidate root drops it.
    pub own_codes: &'a [String],
    /// The product's components.
    pub components: &'a [MsiComponentFact],
    /// Directories that corroborate a single-file group: the product's install-folder values and the
    /// directories of shortcut targets already harvested; canonical.
    pub corroboration: &'a [String],
    /// The roots already known (M1a, and roots of other products of the app).
    pub existing: &'a [Root],
    /// Rule T: the claim comes from a user hive or a per-user product.
    pub user_writable: bool,
}

/// What [`component_roots`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentRoots {
    /// New roots, all [`RootSource::MsiComponent`].
    pub roots: Vec<Root>,
    /// Candidates [`resolve_root`] refused.
    pub rejected: Vec<RejectedRoot>,
    /// Candidates dropped for any other reason, one line each.
    pub notes: Vec<String>,
}

/// The folded segments of a canonical path.
fn segments(path: &str) -> Vec<&str> {
    path.split('\\').filter(|s| !s.is_empty()).collect()
}

/// The lowest common ancestor directory of `dirs` (canonical); `None` when it is a drive.
fn common_dir(dirs: &[&str]) -> Option<String> {
    let first = segments(dirs.first()?);
    let mut len = first.len();
    for dir in &dirs[1..] {
        let segs = segments(dir);
        len = len.min(segs.len());
        let same = first
            .iter()
            .zip(&segs)
            .take(len)
            .take_while(|(a, b)| prefix::eq_ci(a, b))
            .count();
        len = same;
    }
    (len >= 2).then(|| first[..len].join("\\"))
}

/// The highest ancestor directory of `dir` (itself included) that [`validate_root`] accepts.
fn top_of(dir: &str, env: &RootEnv) -> Option<String> {
    let segs = segments(dir);
    (2..=segs.len())
        .map(|n| segs[..n].join("\\"))
        .find(|candidate| validate_root(candidate, RootSource::MsiComponent, env).is_ok())
}

/// Why a key-path file is never part of a root, or `None` when it may be.
fn excluded(path: &str, env: &RootEnv) -> Option<&'static str> {
    let guard = env.guard();
    if !guard.windir.is_empty() && prefix::is_same_or_inside(path, &guard.windir) {
        return Some("under %SystemRoot%");
    }
    if package_cache_roots(guard)
        .iter()
        .any(|c| prefix::is_same_or_inside(path, c))
    {
        return Some("under a Package Cache");
    }
    if env
        .common_files()
        .iter()
        .any(|cf| prefix::is_same_or_inside(path, &format!("{cf}\\microsoft shared")))
    {
        return Some(r"under Common Files\microsoft shared");
    }
    None
}

/// Derives the install roots of one product from its component key paths. See the module documentation
/// for the rule. Pure apart from the file-system checks of [`resolve_root`].
pub fn component_roots(inp: &ComponentRootInput<'_>) -> ComponentRoots {
    let mut out = ComponentRoots::default();
    let env = inp.env;
    // Top (folded) -> the group's files.
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for comp in inp.components {
        if !comp.other_clients.is_empty() {
            continue;
        }
        let MsiKeyPath::File { path } = &comp.key_path else {
            continue;
        };
        if excluded(path, env).is_some() {
            continue;
        }
        let Some(dir) = parent_dir(path) else {
            continue;
        };
        let Some(top) = top_of(&dir, env) else {
            continue;
        };
        let files = groups.entry(prefix::fold(&top)).or_default();
        if !files.iter().any(|f| prefix::is_same(f, path)) {
            files.push(path.as_str());
        }
    }

    for files in groups.into_values() {
        let dirs: Vec<String> = files.iter().filter_map(|f| parent_dir(f)).collect();
        let dir_refs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        let Some(lca) = common_dir(&dir_refs) else {
            continue;
        };
        if files.len() < 2 && !inp.corroboration.iter().any(|c| prefix::is_same(c, &lca)) {
            out.notes.push(format!(
                "msi: {lca} holds one key-path file of the product and nothing corroborates it as the \
                 install folder; it is not a root"
            ));
            continue;
        }
        if let Some(have) = inp
            .existing
            .iter()
            .find(|r| prefix::is_same_or_inside(&lca, &r.path) || prefix::is_inside(&r.path, &lca))
        {
            if !prefix::is_same_or_inside(&lca, &have.path) {
                out.notes.push(format!(
                    "msi: {lca} would widen the root {}; it is not a root",
                    have.path
                ));
            }
            continue;
        }
        if let Some(other) = env
            .other_dirs()
            .iter()
            .find(|o| prefix::is_same_or_inside(&lca, &o.path))
        {
            out.notes.push(format!(
                "msi: {lca} lies in a directory of another app ({}: {}); it is not a root",
                other.app, other.path
            ));
            continue;
        }
        if let Some(other) = env
            .other_files()
            .iter()
            .find(|o| parent_dir(&o.path).is_some_and(|dir| prefix::is_same_or_inside(&lca, &dir)))
        {
            out.notes.push(format!(
                "msi: {lca} lies in the directory of a file of another app ({}: {}); it is not a root",
                other.app, other.path
            ));
            continue;
        }
        let root = match resolve_root(
            inp.fs,
            &lca,
            RootSource::MsiComponent,
            inp.user_writable,
            env,
        ) {
            Ok(root) => root,
            Err(reason) => {
                out.rejected.push(RejectedRoot {
                    path: lca,
                    source: RootSource::MsiComponent,
                    reason,
                });
                continue;
            }
        };
        let foreign = inp
            .ownership
            .dir_components(&root.path)
            .into_iter()
            .find(|o| {
                o.clients
                    .iter()
                    .any(|c| !inp.own_codes.iter().any(|own| own.eq_ignore_ascii_case(c)))
            });
        if let Some(owner) = foreign {
            out.notes.push(format!(
                "msi: {} holds the component {} of another client ({}); it is not a root",
                root.path,
                owner.component_id,
                owner.clients.join(", ")
            ));
            continue;
        }
        if out.roots.iter().any(|r| {
            prefix::is_same_or_inside(&root.path, &r.path) || prefix::is_inside(&r.path, &root.path)
        }) {
            continue;
        }
        out.roots.push(root);
    }
    out
}

/// The key-path files of the product's own components (no other client) that lie in no root, as
/// records of the product. Files under `%SystemRoot%` are among them; they are never roots.
pub fn outside_root_files(facts: &MsiFacts, roots: &[Root]) -> Vec<AppFileOutsideRoot> {
    let source = SourceId(format!("msi:{}", facts.product_code));
    let mut out: Vec<AppFileOutsideRoot> = Vec::new();
    for comp in &facts.components {
        if !comp.other_clients.is_empty() {
            continue;
        }
        let MsiKeyPath::File { path } = &comp.key_path else {
            continue;
        };
        if roots.iter().any(|r| prefix::is_inside(path, &r.path)) {
            continue;
        }
        if !out.iter().any(|f| prefix::is_same(&f.path, path)) {
            out.push(AppFileOutsideRoot {
                path: path.clone(),
                source: source.clone(),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// Anchors from the app's own tables
// ---------------------------------------------------------------------------------------------------------

/// The anchors the app's own `Class`, `ProgId`, `TypeLib` and `AppId` rows give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableAnchors {
    /// CLSIDs (`{GUID}` upper).
    pub clsids: Vec<String>,
    /// ProgIDs, as the package spells them.
    pub progids: Vec<String>,
    /// Type library ids (`{GUID}` upper).
    pub typelibs: Vec<String>,
    /// AppIDs (`{GUID}` upper).
    pub appids: Vec<String>,
    /// Rows that were not taken, one line each.
    pub notes: Vec<String>,
}

/// What [`table_anchors`] checks the rows against.
#[derive(Clone, Copy)]
pub struct TableAnchorInput<'a> {
    /// The ownership index.
    pub ownership: &'a OwnershipIndex,
    /// The packed codes of the app's own products.
    pub own_codes: &'a [String],
    /// The baseline view of this Windows ([`BaselineView::empty`] without one). Presence only: a row
    /// whose key some set of it has gives no anchor.
    pub baseline: &'a BaselineView,
    /// Names the M1a anchor harvest found registered by something else, or only modified by the app.
    pub foreign: &'a [String],
}

/// The anchors of the app's own MSI rows. A row is taken only when
///
/// - its id is a GUID (`Class`, `TypeLib`, `AppId`) or a ProgID name that is not a structural Classes
///   name nor one Windows ships ([`crate::anchors::WELL_KNOWN_SHARED`]) (`ProgId`);
/// - a `Class` row's component is registered with the app's products as its only clients;
/// - no row of another installed product claims any of its keys;
/// - its key is not in the Windows baseline;
/// - the M1a anchor harvest did not find the name registered by something else or only modified.
pub fn table_anchors(harvests: &[MsiHarvest], inp: &TableAnchorInput<'_>) -> TableAnchors {
    let mut out = TableAnchors::default();
    let own = |code: &str| inp.own_codes.iter().any(|c| c.eq_ignore_ascii_case(code));
    for harvest in harvests {
        for row in &harvest.anchor_rows {
            let name = match row.table {
                "ProgId" => {
                    let n = row.row.trim();
                    let shared = crate::anchors::WELL_KNOWN_SHARED
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(n));
                    if n.is_empty() || shared || crate::anchors::is_structural(n) || n.contains('*')
                    {
                        out.notes.push(format!(
                            "msi: ProgId {n}: a structural or Windows-shared name"
                        ));
                        continue;
                    }
                    n.to_owned()
                }
                _ => match braced_upper(&row.row) {
                    Some(id) => id,
                    None => {
                        out.notes
                            .push(format!("msi: {} {}: not a GUID", row.table, row.row));
                        continue;
                    }
                },
            };
            if row.table == "Class" {
                let comp_id = row
                    .component
                    .as_deref()
                    .and_then(|c| harvest.component_ids.get(c));
                let only_ours = comp_id.is_some_and(|id| {
                    let clients = inp.ownership.clients_of(id);
                    !clients.is_empty() && clients.iter().all(|c| own(c))
                });
                if !only_ours {
                    out.notes.push(format!(
                        "msi: Class {name}: its component is not the app's alone"
                    ));
                    continue;
                }
            }
            let foreign_row = row.keys.iter().find_map(|key| {
                inp.ownership
                    .key_owners(key)
                    .into_iter()
                    .find(|o| !own(&o.product.packed_code))
                    .map(|o| o.product.name.clone())
            });
            if let Some(other) = foreign_row {
                out.notes
                    .push(format!("msi: {} {name}: also a row of {other}", row.table));
                continue;
            }
            if inp.baseline.has_key(row.key()) {
                out.notes.push(format!(
                    "msi: {} {name}: in the Windows baseline",
                    row.table
                ));
                continue;
            }
            if inp.foreign.iter().any(|f| prefix::eq_ci(f, &name)) {
                out.notes.push(format!(
                    "msi: {} {name}: registered by something else",
                    row.table
                ));
                continue;
            }
            let list = match row.table {
                "Class" => &mut out.clsids,
                "ProgId" => &mut out.progids,
                "TypeLib" => &mut out.typelibs,
                _ => &mut out.appids,
            };
            if !list.iter().any(|have| prefix::eq_ci(have, &name)) {
                list.push(name);
            }
        }
    }
    out
}

/// Adds `names` to the fold-sorted, duplicate-free `list`, keeping it so.
pub fn merge_names(list: &mut Vec<String>, names: &[String]) {
    let mut map: BTreeMap<String, String> = list.drain(..).map(|n| (prefix::fold(&n), n)).collect();
    for name in names {
        map.entry(prefix::fold(name))
            .or_insert_with(|| name.clone());
    }
    list.extend(map.into_values());
}
