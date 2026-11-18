//! Scanner SYS-BURNDEPS (ENGINE_PLAN.md §5.6, §5.7.2): the dependency registration a removed WiX Burn
//! bundle left behind, and the related products that are still installed.
//!
//! Burn links a bundle to its packages only through dependency records:
//! `<Classes>\Installer\Dependencies\<P>\Dependents\<B>`, where `P` is a package's provider key and `B`
//! the bundle id or the bundle's own provider key, and `<Classes>` is `HKLM\SOFTWARE\Classes` or a user's
//! Classes (`HKU\<sid>\Software\Classes`, canonically `HKU\<sid>_Classes`). The harvest recorded the
//! bundle and its packages (`fp.burn`); this scanner looks only at the provider keys recorded there and
//! never lists `Installer\Dependencies` itself.
//!
//! # When anything is offered
//!
//! Only when the bundle is **gone** ([`bundle_gone`]): the verify-gone result says the app's ARP entry is
//! gone, and no entry of the fresh inventory (the other apps) has an Uninstall key named after the bundle
//! id. Otherwise the scanner emits nothing at all.
//!
//! # What is offered
//!
//! For every recorded provider key `P` (each package's, and the bundle's own), in the bundle's own roots
//! ([`dependency_roots`], R3a S4: the machine's Classes, and for a per-user bundle its own user's; a
//! machine bundle also reads every loaded user's Classes, but only to find other dependents there):
//!
//! - **(a)** each subkey `Dependents\<B>` of a package's `P` whose name is the bundle id or the bundle's
//!   provider key: `RegKey`, `DeleteKey`, `Category::Registration`, `InstallerManifest(Burn)` (Tier A,
//!   Key scope).
//! - **(b)** `P` itself, only when no dependent other than the bundle's own entries is left anywhere (every
//!   root read now, and the ownership index's merged list), `P` holds no subkey other than `Dependents`,
//!   and either `P` is the bundle's own provider key or Windows Installer knows the package's product in
//!   no context ([`ScanCtx::product_gone`]). A `P` that other bundles still depend on gets nothing; the
//!   bundle's own `Dependents` entry under it is still offered by (a).
//! - **(c)** a package whose product is still installed, that no dependent other than the bundle keeps,
//!   and whose provider key is not a shared component of `kb/shared-components.json` (the Visual C++
//!   runtime, .NET): one `ReportOnly` candidate on the product's Uninstall key (from the fresh inventory),
//!   whose evidence carries the fact `suggest_uninstall = <product name>`. Never a deleting action. A
//!   package another dependent still keeps (the Python Launcher while another Python is installed) gets
//!   no suggestion.
//! - **(c) without a provider record**: a shared component the bundle installed without writing a
//!   dependency provider record for it (`fp.burn.linked`, kb `burn_link`: the Python Launcher of the real
//!   CPython bundles, which register only their own provider key). The same `ReportOnly` suggestion on
//!   the product's Uninstall key, only when the product is still installed and it is known that no
//!   bundle of the family the kb entry names (`CPython-*`) is left: the ownership index's Burn area is
//!   complete, the index holds no provider key of the family other than this bundle's own, and every
//!   profile of the machine has its hive loaded (another user's bundle registers in that user's
//!   Classes). Anything not known gives no suggestion.
//!
//! # Unknown is never "none"
//!
//! A root that cannot be read (anything but "not found"), loaded user hives that cannot be listed, and an
//! ownership index whose Burn area is incomplete make the dependents of a provider unknown: (b) and (c)
//! are then not offered for it. (a) is still offered where it was read. Each such spot adds one scan
//! warning (`ScanExt::warn`); the index also records its own read errors.
//!
//! # Reads
//!
//! Per recorded provider key and root: one `subkeys()` of `P` and, when `P` has a `Dependents` subkey,
//! one `subkeys()` of it. Once per scan, for a machine bundle: the loaded user hives; with a linked
//! component, the loaded user hives once more. The candidates' common blockers add one `key_info()`
//! each. Everything else (the other apps, the MSI ownership index, the product state) needs no key
//! open.

use purge_guard::canon::canon_key;
use purge_guard::deny::{BurnLink, SharedComponents};
use purge_guard::prefix;
use purge_index::ownership::{MACHINE_DEPENDENCIES, area, pack_guid};
use purge_model::{
    Action, BurnFacts, BurnLinked, BurnPackage, Candidate, Category, Evidence, EvidenceKind, Facts,
    Harm, ManifestKind, Scope, Target,
};
use purge_source::types::SourceError;

use crate::com_class::warn_unread;
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner, app_trust};

/// The scanner's catalog id.
pub const ID: &str = "SYS-BURNDEPS";

/// What the scanner reads: provider keys, their `Dependents` key and its subkey names, in the machine's
/// and the users' Classes.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"*\SOFTWARE\Classes\Installer\Dependencies",
    Some(3),
)];

/// The name of the dependents subkey of a provider key.
const DEPENDENTS: &str = "Dependents";

/// The fact a related-product suggestion carries.
pub const SUGGEST_UNINSTALL: &str = "suggest_uninstall";

/// The SYS-BURNDEPS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysBurnDeps;

impl Scanner for SysBurnDeps {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let fp = ctx.fp;
        let Some(burn) = fp.burn.as_ref() else {
            return Vec::new();
        };
        if !bundle_gone(ctx, burn) {
            return Vec::new();
        }
        let roots = dependency_roots(ctx);
        let mut out: Vec<Candidate> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut push = |out: &mut Vec<Candidate>, c: Candidate| {
            let key = match &c.target {
                Target::RegKey { path } => prefix::fold(path),
                _ => String::new(),
            };
            if !seen.contains(&key) {
                seen.push(key);
                out.push(c);
            }
        };

        // The bundle's own provider key: (b) only.
        if let Some(own) = burn.provider_key.as_deref().filter(|p| valid_name(p)) {
            let state = provider_state(ctx, burn, &roots, own);
            for root in state.offerable_provider_roots() {
                push(
                    &mut out,
                    provider_candidate(ctx, burn, &root.provider_key, "bundle_provider"),
                );
            }
        }

        let shared = SharedComponents::compile(ctx.guard).ok();
        for package in &burn.packages {
            let provider = package.provider_key.as_str();
            if !valid_name(provider) || is_ours(burn, provider) {
                continue;
            }
            let state = provider_state(ctx, burn, &roots, provider);
            // (a) The bundle's own entries under the package's provider key.
            for root in &state.roots {
                for key in &root.ours {
                    let mut b = ctx.candidate(
                        ID,
                        Target::RegKey { path: key.clone() },
                        Action::DeleteKey,
                        Category::Registration,
                    );
                    b = b.burn_registration(&burn.bundle_id, "dependent");
                    b.harm(Harm::Low).common_blockers();
                    push(&mut out, b.build());
                }
            }
            // (b) The provider key itself, once nothing depends on it and its product is gone.
            let gone = package
                .product_code
                .as_deref()
                .is_some_and(|code| ctx.product_gone(code));
            if gone {
                for root in state.offerable_provider_roots() {
                    push(
                        &mut out,
                        provider_candidate(ctx, burn, &root.provider_key, "package_provider"),
                    );
                }
            } else if state.known_orphan()
                && let Some(c) = related_product(ctx, burn, package, shared.as_ref())
            {
                // (c) The product is still installed and nothing keeps it any more.
                push(&mut out, c);
            }
        }

        // (c) for a shared component installed without a provider record.
        for linked in &burn.linked {
            if let Some(c) = linked_product(ctx, burn, linked, shared.as_ref()) {
                push(&mut out, c);
            }
        }
        out
    }
}

/// Whether the app's Burn bundle is gone: the verify-gone result says the app's ARP entry is gone, and no
/// other entry of the fresh inventory has an Uninstall key named after the bundle id. No verify-gone
/// result (no uninstall observed) is "not gone".
pub(crate) fn bundle_gone(ctx: &ScanCtx<'_>, burn: &BurnFacts) -> bool {
    let id = burn.bundle_id.trim();
    if !valid_name(id) || !ctx.verify_gone.is_some_and(|v| v.arp_gone) {
        return false;
    }
    !ctx.other_apps.apps().iter().any(|app| {
        app.keys
            .iter()
            .any(|key| prefix::leaf(key).is_some_and(|leaf| prefix::eq_ci(leaf, id)))
    })
}

/// Whether `name` is the bundle id or the bundle's own provider key (compared ignoring case).
pub(crate) fn is_ours(burn: &BurnFacts, name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && (prefix::eq_ci(name, burn.bundle_id.trim())
            || burn
                .provider_key
                .as_deref()
                .is_some_and(|p| prefix::eq_ci(name, p.trim())))
}

/// A key name usable as one segment: not empty, no separator, no wildcard, not made of dots, no control
/// character. A recorded name that is not one (a hostile or broken record) is never looked up.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.trim().is_empty()
        && !name.contains(['\\', '/', '*'])
        && !name.chars().all(|c| c == '.')
        && !name.chars().any(char::is_control)
}

/// The dependents of `provider` other than the bundle's own entries, according to the ownership index
/// (merged over the machine and every loaded user, read once per scan); `None` when the index could not
/// read its Burn area completely.
pub(crate) fn index_other_dependents(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    provider: &str,
) -> Option<Vec<String>> {
    let ix = &ctx.ext.ownership;
    if !ix.stats().complete(area::BURN) {
        return None;
    }
    Some(
        ix.burn_dependents(provider)
            .iter()
            .filter(|d| !is_ours(burn, d))
            .cloned()
            .collect(),
    )
}

/// One dependency root looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DepRoot {
    /// The root in the guard's canonical spelling; `Err` for a root that is not known (the user hives
    /// could not be listed, or a user root does not canonicalise).
    path: Result<String, String>,
    /// Whether the bundle's records there may be offered. A root read only to find other dependents
    /// (another user's, for a machine bundle) never is: an entry named after the bundle there is that
    /// user's own install, and counts as another dependent.
    offer: bool,
}

/// The dependency roots (R3a S4), in the guard's canonical spelling:
///
/// - a **per-user** bundle (its entry in a user's hive): the machine's and that user's own, both offered;
///   no other user's hive is read (another user's records of the same bundle are that user's install);
/// - a **machine** bundle: the machine's, offered; then the Classes of every loaded user hive, read only
///   to find other dependents.
fn dependency_roots(ctx: &ScanCtx<'_>) -> Vec<DepRoot> {
    let user_root = |sid: &str, offer: bool| {
        let input = format!(r"HKU\{sid}\Software\Classes\Installer\Dependencies");
        DepRoot {
            path: canon_key(&input, None, ctx.guard, None)
                .map(|k| k.key_path())
                .map_err(|e| format!("{input}: {e}")),
            offer,
        }
    };
    let mut roots = vec![DepRoot {
        path: Ok(MACHINE_DEPENDENCIES.to_owned()),
        offer: true,
    }];
    if let Some(own) = ctx.fp.app.program_id.hive_sid() {
        roots.push(user_root(own.trim(), true));
        return roots;
    }
    match ctx.reg.loaded_user_sids() {
        Ok(sids) => roots.extend(sids.iter().map(|sid| user_root(sid, false))),
        Err(e) => roots.push(DepRoot {
            path: Err(format!("loaded user hives: {e}")),
            offer: false,
        }),
    }
    roots
}

/// What one root holds of a provider key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootState {
    /// The provider key in this root (`<root>\<P>`, `P` as recorded).
    provider_key: String,
    /// The bundle's own entries: `<root>\<P>\Dependents\<B>`, the last two segments as found.
    ours: Vec<String>,
    /// `P` has a subkey other than `Dependents`.
    other_subkeys: bool,
}

/// What the scan knows of one provider key in every root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ProviderState {
    /// The roots where the provider key exists.
    roots: Vec<RootState>,
    /// Dependents other than the bundle's own entries, in any root or in the ownership index.
    others: Vec<String>,
    /// Some root, or the index, could not be read: the dependents are not known.
    unknown: bool,
}

impl ProviderState {
    /// Whether it is known that no dependent other than the bundle's own entries is left.
    fn known_orphan(&self) -> bool {
        !self.unknown && self.others.is_empty()
    }

    /// The roots whose provider key may be offered itself (rule (b), less the product test): no other
    /// dependent anywhere, and nothing in the key but `Dependents`.
    fn offerable_provider_roots(&self) -> Vec<&RootState> {
        if !self.known_orphan() {
            return Vec::new();
        }
        self.roots.iter().filter(|r| !r.other_subkeys).collect()
    }
}

/// Reads `provider` in every root (see the module documentation for the reads).
fn provider_state(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    roots: &[DepRoot],
    provider: &str,
) -> ProviderState {
    let mut state = ProviderState::default();
    let note_other = |others: &mut Vec<String>, name: &str| {
        if !others.iter().any(|o| prefix::eq_ci(o, name)) {
            others.push(name.to_owned());
        }
    };
    for DepRoot { path, offer } in roots {
        let root = match path {
            Ok(root) => root,
            Err(why) => {
                ctx.ext.warn(
                    ID,
                    format!(
                        "a dependency root is unknown ({why}); no package provider key and no \
                         Dependents key is offered"
                    ),
                );
                state.unknown = true;
                continue;
            }
        };
        let provider_key = format!(r"{root}\{provider}");
        let children = match ctx.reg.subkeys(&provider_key) {
            Ok(children) => children,
            Err(SourceError::NotFound) => continue,
            Err(e) => {
                warn_unread(ctx, ID, &provider_key, &e);
                state.unknown = true;
                continue;
            }
        };
        let mut here = RootState {
            provider_key,
            ours: Vec::new(),
            other_subkeys: children.iter().any(|c| !prefix::eq_ci(c, DEPENDENTS)),
        };
        if let Some(dependents) = children.iter().find(|c| prefix::eq_ci(c, DEPENDENTS)) {
            let key = format!(r"{}\{dependents}", here.provider_key);
            match ctx.reg.subkeys(&key) {
                Ok(entries) => {
                    for entry in entries {
                        if *offer && is_ours(burn, &entry) && valid_name(&entry) {
                            here.ours.push(format!(r"{key}\{entry}"));
                        } else {
                            note_other(&mut state.others, &entry);
                        }
                    }
                }
                Err(SourceError::NotFound) => {}
                Err(e) => {
                    warn_unread(ctx, ID, &key, &e);
                    state.unknown = true;
                }
            }
        }
        // A root read only for other dependents: its key is never offered.
        if *offer {
            state.roots.push(here);
        }
    }
    match index_other_dependents(ctx, burn, provider) {
        Some(others) => {
            for other in others {
                note_other(&mut state.others, &other);
            }
        }
        None => {
            ctx.ext.warn(
                ID,
                format!(
                    "the MSI ownership index could not tell the dependents of {provider}; neither it \
                     nor its Dependents key is offered"
                ),
            );
            state.unknown = true;
        }
    }
    state
}

/// The candidate for a provider key itself (rule (b)).
fn provider_candidate(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    key: &str,
    what: &'static str,
) -> Candidate {
    let mut b = ctx.candidate(
        ID,
        Target::RegKey {
            path: key.to_owned(),
        },
        Action::DeleteKey,
        Category::Registration,
    );
    b = b.burn_registration(&burn.bundle_id, what);
    b.harm(Harm::Low).common_blockers();
    b.build()
}

/// The related-product suggestion for `package` (rule (c)), when its product is installed, has an
/// Uninstall key in the fresh inventory, and its provider key is not a shared component. The caller has
/// established that nothing but the bundle depended on it.
fn related_product(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    package: &BurnPackage,
    shared: Option<&SharedComponents>,
) -> Option<Candidate> {
    let code = package.product_code.as_deref()?.trim();
    let packed = pack_guid(code)?;
    if !product_installed(ctx, code, &packed) {
        return None;
    }
    // A runtime many products share is never suggested; without the shared-component list nothing is.
    let shared = shared?;
    let provider_target = Target::RegKey {
        path: format!(r"{MACHINE_DEPENDENCIES}\{}", package.provider_key),
    };
    if shared.find(&provider_target).is_some() {
        return None;
    }
    suggestion(
        ctx,
        burn,
        code,
        Facts::new().with("provider", package.provider_key.clone()),
    )
}

/// The `ReportOnly` suggestion to uninstall the product `code` (rule (c)): on its Uninstall key in the
/// fresh inventory, with the fact [`SUGGEST_UNINSTALL`] = its name; `None` when the fresh inventory has
/// no Uninstall key for it. `link` says how the bundle was tied to the product.
fn suggestion(ctx: &ScanCtx<'_>, burn: &BurnFacts, code: &str, link: Facts) -> Option<Candidate> {
    let (arp_key, name) = uninstall_entry(ctx, code)?;
    let detail = link
        .with("bundle", burn.bundle_id.clone())
        .with("what", "related_product")
        .with("product", code.to_owned())
        .with(SUGGEST_UNINSTALL, name);
    let evidence = Evidence::new(
        EvidenceKind::InstallerManifest(ManifestKind::Burn),
        Scope::Key,
        app_trust(ctx.fp),
        format!("burn:{}:related_product", burn.bundle_id),
    )?
    .with_detail(detail);
    let mut b = ctx.candidate(
        ID,
        Target::RegKey { path: arp_key },
        Action::ReportOnly,
        Category::Registration,
    );
    b.evidence_also([evidence]);
    Some(b.build())
}

/// The suggestion for a shared component the bundle installed without a provider record (rule (c),
/// `fp.burn.linked`): its product is installed and it is known that no bundle of the family its kb
/// entry names is left ([`family_left`]). Without the shared-component list, or when the kb entry has
/// no link any more, nothing is suggested.
fn linked_product(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    linked: &BurnLinked,
    shared: Option<&SharedComponents>,
) -> Option<Candidate> {
    let component = shared?
        .components()
        .iter()
        .find(|c| c.id == linked.component)?;
    let link = component.burn_link.as_ref()?;
    let code = linked.product_code.trim();
    let packed = pack_guid(code)?;
    if !product_installed(ctx, code, &packed) {
        return None;
    }
    if family_left(ctx, burn, link, &component.id) != Some(false) {
        return None;
    }
    suggestion(
        ctx,
        burn,
        code,
        Facts::new()
            .with("component", component.id.clone())
            .with("cache_dir", linked.cache_dir.clone()),
    )
}

/// Whether a bundle of the family `link` names, other than this one, is still registered: `Some(true)`
/// when the ownership index holds a provider key of the family other than the bundle's own (with or
/// without dependents: a key that is there is not known to be unused), or the bundle's own provider
/// key with anything but this bundle's own records in its own hive (another bundle depending on it,
/// another user's install of the same bundle, or no dependent at all, whose hive cannot be told);
/// `Some(false)` when there is none and the index saw every place one could be; `None` (with a scan
/// warning) when it did not: its Burn area is incomplete, the loaded user hives cannot be listed, or a
/// profile of the machine has no hive loaded (a bundle that user installed registers in that user's
/// Classes, which nobody read).
fn family_left(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    link: &BurnLink,
    component: &str,
) -> Option<bool> {
    let unknown = |why: String| {
        ctx.ext.warn(
            ID,
            format!(
                "{why}; it is not known whether {component} is still used, it is not suggested"
            ),
        );
        None
    };
    let ix = &ctx.ext.ownership;
    if !ix.stats().complete(area::BURN) {
        return unknown("the MSI ownership index could not read every dependency record".into());
    }
    let loaded = match ctx.reg.loaded_user_sids() {
        Ok(loaded) => loaded,
        Err(e) => return unknown(format!("the loaded user hives cannot be listed ({e})")),
    };
    if ctx.guard.profiles.is_empty() {
        return unknown("the machine's profiles are not known".into());
    }
    if let Some(profile) = ctx.guard.profiles.iter().find(|p| {
        !loaded
            .iter()
            .any(|sid| prefix::eq_ci(sid.trim(), p.sid.trim()))
    }) {
        return unknown(format!(
            "the hive of the profile {} is not loaded",
            profile.sid
        ));
    }
    // The hive of the bundle's own records: the machine's for a machine bundle, else its user's.
    let own_hive = ctx.fp.app.program_id.hive_sid().map(str::trim);
    let own_record = |(dependent, hive): &(String, Option<String>)| {
        is_ours(burn, dependent)
            && match (hive.as_deref(), own_hive) {
                (None, None) => true,
                (Some(hive), Some(own)) => prefix::eq_ci(hive.trim(), own),
                _ => false,
            }
    };
    Some(
        ix.burn_providers()
            .filter(|(provider, _)| link.bundle_matches(provider))
            .any(|(provider, records)| {
                // Another bundle of the family; or this bundle's own provider key that another
                // bundle depends on, that the same bundle registered in another hive (another
                // user's install of the same Python), or whose hive cannot be told (no dependent).
                !is_ours(burn, provider) || records.is_empty() || !records.iter().all(own_record)
            }),
    )
}

/// Whether the product is installed: the ownership index lists it, or Windows Installer knows it in
/// some context.
fn product_installed(ctx: &ScanCtx<'_>, code: &str, packed: &str) -> bool {
    ctx.ext.ownership.installed(packed).is_some()
        || ctx
            .sys
            .msi_product_state_all(code)
            .is_ok_and(|states| states.iter().any(|s| !s.state.is_unknown()))
}

/// The Uninstall key (`...\Uninstall\{ProductCode}`) and display name of the product in the fresh
/// inventory (the other apps).
fn uninstall_entry(ctx: &ScanCtx<'_>, code: &str) -> Option<(String, String)> {
    ctx.other_apps.apps().iter().find_map(|app| {
        app.keys
            .iter()
            .find(|key| {
                prefix::leaf(key).is_some_and(|leaf| prefix::eq_ci(leaf, code))
                    && prefix::parent(key)
                        .and_then(prefix::leaf)
                        .is_some_and(|parent| prefix::eq_ci(parent, "Uninstall"))
            })
            .map(|key| (key.clone(), app.name.clone()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
    }

    #[test]
    fn names_that_are_not_one_segment_are_refused() {
        for bad in ["", "  ", r"a\b", "a/b", "*", "..", ".", "a\u{1}b"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        for good in [
            "{0A1B2C3D-0000-1111-2222-333344445555}",
            "CPython-3.12",
            "VC,redist.x64",
        ] {
            assert!(valid_name(good), "{good:?}");
        }
    }

    #[test]
    fn ours_is_the_bundle_id_or_its_provider_key() {
        let burn = BurnFacts {
            bundle_id: "{B}".into(),
            provider_key: Some("CPython-3.12".into()),
            cache_path: None,
            packages: Vec::new(),
            dependents_at_harvest: Vec::new(),
            linked: Vec::new(),
        };
        assert!(is_ours(&burn, "{b}"));
        assert!(is_ours(&burn, "cpython-3.12"));
        assert!(!is_ours(&burn, "CPython-3.13"));
        assert!(!is_ours(&burn, ""));
    }
}
