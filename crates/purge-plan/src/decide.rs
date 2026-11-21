//! DECIDE (ENGINE_PLAN.md §3.6 step 6, §5.8, §5.10): scanner candidates in, decided candidates out.
//!
//! [`decide`] runs, in this order:
//!
//! 1. **Merge** ([`merge`]). Candidates of one app on the same target are folded into one. Targets are
//!    compared in canonical form, case-insensitively. The merged candidate keeps the id and scanner of the
//!    first candidate in input order; evidence taken from another scanner gets that scanner's id in its
//!    detail under [`SCANNER_KEY`]. Evidence is united without changing source ids, so the
//!    independent-source bonus of §5.8.1 counts exactly the distinct records. When the candidates disagree
//!    on the action, the strongest action wins (a removal over delete-if-empty over report-only) and only
//!    evidence recorded for that action is kept: a `VendorContainer` hint that was offered for
//!    delete-if-empty never adds to the score of a whole-key delete. Blockers are always united, the
//!    category, harm, reversibility and origin take the most restrictive value.
//!    `EmptyAfterPlan` evidence found in the input is dropped: only this crate may state it
//!    ([`crate::empty_after`]).
//! 2. **Guard** ([`guard_and_policy`]). The target is canonicalised (`purge_guard::canon`); one that does
//!    not canonicalise gets the hard blocker `DenyListed { rule: "canon.<code>" }` and keeps its spelling.
//!    The deny-list is checked with the exemptions the evidence earns ([`exemptions`]), a key delete of a
//!    value container gets `StructuralContainer`, and the blast-radius limits ([`Limits`]) add the soft
//!    blocker `TooLarge`.
//! 3. **Policy.** `purge_policy::band::decide` with the target scope from [`target_scope`].
//! 4. **EmptyAfterPlan** ([`crate::empty_after::apply`]) for containers carrying the pending marker, which
//!    re-runs steps 2 and 3 for a container that the rest of the plan empties. A delete-if-empty container
//!    on a Windows Installer client list (`...\Installer\UpgradeCodes\<U>`, `...\Components\<C>`) is then
//!    offered only when the plan empties it and the guard lets it through; otherwise it is left out of the
//!    plan ([`installer_client_list`]).
//!
//! # M1b: system facts and typed objects
//!
//! The guard's three M1b exemption lists (gone MSI products, gone Package Cache directories, gone Burn
//! names) come from [`DecideCtx::m1b`], which only [`M1bDecide::from_facts`] fills: from the fingerprint
//! and a fresh query of Windows Installer and the bundle inventory, never from a candidate. They are
//! computed once per plan and handed to the guard for every candidate ([`exemptions`]).
//!
//! Typed objects (services, tasks, firewall rules) merge like any other equal target, but every candidate
//! of the group must carry the same `object_fp`; otherwise two scanners saw two different objects under
//! one name and the merged candidate gets the hard blocker `ObjectChangedSinceHarvest`. A typed candidate
//! has no children ([`merge`] clears any it was given) and never nests ([`crate::collapse`]).
//!
//! Canonical registry keys spell the current control set `ControlSet00N`. The rig scorer folds that
//! spelling onto `CurrentControlSet` itself (vm/rigtool `canon.rs`), so plans are emitted in canonical
//! form.

use std::collections::{BTreeSet, HashMap};

use purge_guard::canon::{GuardEnv, canon_key, canon_target};
use purge_guard::deny::{DenyList, Exemptions, ObjectGuardFacts};
use purge_guard::{containers, prefix};
use purge_model::{
    Action, Band, BaselineTrust, Blocker, Candidate, CandidateId, Category, Evidence, EvidenceKind,
    Fingerprint, Hive, InventoryEntry, MsiContext, ObjectKind, Origin, ProgramId, Reversibility,
    ScanMode, Scope, SourceTrust, Target, Tier, VerifyGone,
};
use purge_policy::band::{self, PolicyCtx, TargetScope};
use purge_policy::score::effective_weight;

use crate::empty_after;

/// Detail key naming the scanner a merged-in piece of evidence came from, when it is not the scanner the
/// merged candidate is listed under.
pub const SCANNER_KEY: &str = "scanner";

/// The blast-radius limits (§5.10, §5.3). A whole removal above a limit gets the soft blocker `TooLarge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Most items (subkeys and values) a key delete may hold: 50 (§5.10).
    pub max_key_items: u32,
    /// Most files a directory quarantine may hold: 5,000 (§5.10).
    pub max_files: u32,
    /// Most files a quarantine of a proven install root may hold: 50,000 (§5.3). A manifest-backed,
    /// verified-gone InstallRoot is the one place a large tree is expected.
    pub max_root_files: u32,
    /// Largest size of any quarantine: 2 GB (§5.3).
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_key_items: 50,
            max_files: 5_000,
            max_root_files: 50_000,
            max_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// The M1b exemption lists of one plan (C-GUARD): which MSI products, Package Cache directories and Burn
/// bundles and packages are gone. [`Default`] has all three empty, which keeps every exemption they open
/// closed.
///
/// The fields are private: the only way to fill them is [`M1bDecide::from_facts`], from the fingerprint
/// and a fresh query of the system. Nothing a scanner writes into a candidate (facts, evidence, its id)
/// is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct M1bDecide {
    gone_msi_products: Vec<String>,
    /// The gone products by the SID their registration is filed under (R3a B1): `(folded SID, packed
    /// codes)`, `s-1-5-18` for a per-machine product, the user's for a per-user one; a per-user product
    /// whose user is not recorded is under no SID.
    gone_msi_by_sid: Vec<(String, Vec<String>)>,
    gone_cache_dirs: Vec<String>,
    gone_burn: Vec<String>,
}

/// The `UserData` SID of the machine context.
const MACHINE_SID: &str = "S-1-5-18";

impl M1bDecide {
    /// The lists for the app of `fp`, judged by two fresh queries the caller makes now (after the
    /// uninstall), not at harvest:
    ///
    /// - `product_known(product_code)`: whether Windows Installer knows the ProductCode (`{GUID}`) in
    ///   some context (`Some(true)`), in none (`Some(false)`), or its state could not be read (`None`: a
    ///   source error, no data);
    /// - `bundle_known(bundle_id)`: the same for a Burn bundle id, against the fresh inventory.
    ///
    /// Only `Some(false)` makes anything gone; unknown keeps it out. The lists are:
    ///
    /// - `gone_msi_products`: the packed code of each `fp.msi` entry (Burn MSI children are recorded there
    ///   too) whose product is known absent. An entry whose recorded packed code is not the packed form of
    ///   its ProductCode is left out.
    /// - `gone_burn`: when the bundle is known absent, its bundle id and, if no other bundle depended on it
    ///   at harvest, its provider key; plus the provider key of each package whose product is known absent
    ///   and that has no other dependents.
    /// - `gone_cache_dirs`: when the bundle is known absent, its Package Cache folder; plus the Package
    ///   Cache folder of each package whose product is known absent and that has no other dependents.
    ///
    /// Each list is sorted and free of duplicates and empty entries (packed codes upper-cased), so the
    /// result depends on the facts only, not on their order.
    #[must_use]
    pub fn from_facts(
        fp: &Fingerprint,
        product_known: &dyn Fn(&str) -> Option<bool>,
        bundle_known: &dyn Fn(&str) -> Option<bool>,
    ) -> M1bDecide {
        let gone = |known: Option<bool>| known == Some(false);
        let mut out = M1bDecide::default();
        for msi in &fp.msi {
            let Some(packed) = pack_guid(&msi.product_code) else {
                continue;
            };
            if packed.eq_ignore_ascii_case(&msi.packed_code)
                && gone(product_known(&msi.product_code))
            {
                let sid = match msi.context {
                    MsiContext::Machine => Some(MACHINE_SID),
                    MsiContext::UserManaged | MsiContext::UserUnmanaged => msi
                        .user_sid
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty()),
                };
                if let Some(sid) = sid {
                    let sid = prefix::fold(sid);
                    match out.gone_msi_by_sid.iter_mut().find(|(s, _)| *s == sid) {
                        Some((_, list)) => list.push(packed.clone()),
                        None => out.gone_msi_by_sid.push((sid, vec![packed.clone()])),
                    }
                }
                out.gone_msi_products.push(packed);
            }
        }
        if let Some(burn) = &fp.burn {
            let bundle_id = burn.bundle_id.as_str();
            if !bundle_id.trim().is_empty() && gone(bundle_known(bundle_id)) {
                out.gone_burn.push(bundle_id.to_owned());
                if burn.dependents_at_harvest.is_empty() {
                    out.gone_burn.extend(burn.provider_key.iter().cloned());
                }
                out.gone_cache_dirs.extend(burn.cache_path.iter().cloned());
            }
            for package in &burn.packages {
                let product_gone = package
                    .product_code
                    .as_deref()
                    .is_some_and(|code| gone(product_known(code)));
                if product_gone && package.other_dependents.is_empty() {
                    out.gone_burn.push(package.provider_key.clone());
                    out.gone_cache_dirs
                        .extend(package.cache_dir.iter().cloned());
                }
            }
        }
        for list in [
            &mut out.gone_msi_products,
            &mut out.gone_cache_dirs,
            &mut out.gone_burn,
        ] {
            list.retain(|s| !s.trim().is_empty());
            list.sort();
            list.dedup();
        }
        for (_, list) in &mut out.gone_msi_by_sid {
            list.sort();
            list.dedup();
        }
        out.gone_msi_by_sid.sort();
        out
    }

    /// Packed codes (32 upper-case hex digits) of the app's MSI products that Windows Installer no longer
    /// knows in any context.
    #[must_use]
    pub fn gone_msi_products(&self) -> &[String] {
        &self.gone_msi_products
    }

    /// The gone MSI products the guard may let through for `target` (R3a B1, defence in depth behind
    /// REG-ARP-MSI). A Windows Installer registration filed under a SID
    /// (`HKLM\...\Installer\UserData\<sid>\...`, `HKU\<sid>\Software\Microsoft\Installer\...`) is let
    /// through only for the products whose own context is that SID (`S-1-5-18` for a per-machine
    /// product, the user's for a per-user one): the same ProductCode under another SID is another user's
    /// install, which "gone" says nothing about. Every other target gets [`M1bDecide::gone_msi_products`].
    /// `env` and `user_sid` canonicalise the key as the guard does. The executor journals both lists
    /// ([`M1bDecide::gone_msi_by_sid`]) and its gate makes the same choice per op with
    /// [`installer_registration_sid`] (R4 S8).
    #[must_use]
    pub fn gone_msi_products_for(
        &self,
        target: &Target,
        env: &GuardEnv,
        user_sid: Option<&str>,
    ) -> &[String] {
        match installer_registration_sid(target, env, user_sid) {
            Some(sid) => self
                .gone_msi_by_sid
                .iter()
                .find(|(s, _)| *s == sid)
                .map_or(&[], |(_, list)| list.as_slice()),
            None => &self.gone_msi_products,
        }
    }

    /// The gone MSI products by the folded SID of their own install context (`s-1-5-18` for a
    /// per-machine product), each list sorted: what [`M1bDecide::gone_msi_products_for`] gives a
    /// registration filed under that SID. A product whose user is not recorded is under no SID.
    #[must_use]
    pub fn gone_msi_by_sid(&self) -> &[(String, Vec<String>)] {
        &self.gone_msi_by_sid
    }

    /// Package Cache directories, as the fingerprint recorded them, of gone bundles and packages.
    #[must_use]
    pub fn gone_cache_dirs(&self) -> &[String] {
        &self.gone_cache_dirs
    }

    /// Bundle ids and provider keys of gone Burn bundles and packages.
    #[must_use]
    pub fn gone_burn(&self) -> &[String] {
        &self.gone_burn
    }

    /// Whether all three lists are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.gone_msi_products.is_empty()
            && self.gone_cache_dirs.is_empty()
            && self.gone_burn.is_empty()
    }
}

/// The SID (folded) a Windows Installer registration target is filed under: the `<sid>` of
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\<sid>\...` (either view), or the
/// user of `HKU\<sid>\Software\Microsoft\Installer\...`. Compared in the guard's canonical form; `None`
/// for every other target and for a key that does not canonicalise (the guard denies those anyway).
/// The executor's gate uses it to pick the journalled per-SID list for an op (R4 S8).
#[must_use]
pub fn installer_registration_sid(
    target: &Target,
    env: &GuardEnv,
    user_sid: Option<&str>,
) -> Option<String> {
    let path = match target {
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => path,
        _ => return None,
    };
    let key = canon_key(path, None, env, user_sid).ok()?;
    let folded: Vec<String> = prefix::segments(&key.path).map(prefix::fold).collect();
    let segs: Vec<&str> = folded.iter().map(String::as_str).collect();
    match &key.hive {
        Hive::Hklm => match segs.as_slice() {
            [
                "software",
                "microsoft",
                "windows",
                "currentversion",
                "installer",
                "userdata",
                sid,
                ..,
            ] => Some((*sid).to_owned()),
            _ => None,
        },
        Hive::Hku(sid) => matches!(segs.as_slice(), ["software", "microsoft", "installer", ..])
            .then(|| prefix::fold(sid)),
        Hive::HkuClasses(_) => None,
    }
}

/// The `bundle_known` of [`M1bDecide::from_facts`] (R2a S9): whether the Burn bundle `bundle_id` is in the
/// fresh inventory `entries`, for the bundle whose own entry was `home` (the fingerprint's app).
///
/// - `Some(true)`: some entry's key is named `bundle_id` (Burn registers a bundle under its bundle id),
///   in any hive and view, compared ignoring case.
/// - `Some(false)`: no such entry, and the Uninstall keys of the bundle's own hive were read completely
///   (`hive_read(None)` for a per-machine bundle, `hive_read(Some(sid))` for a bundle of the user
///   `sid`): the hive is loaded and no Uninstall key of it failed to list.
/// - `None` otherwise: an id that is not a `{GUID}`, a hive that is not loaded (a per-user bundle of a
///   user who is not logged on) or was not read completely. Unknown keeps the bundle out of every list.
#[must_use]
pub fn bundle_known(
    bundle_id: &str,
    home: &ProgramId,
    entries: &[InventoryEntry],
    hive_read: &dyn Fn(Option<&str>) -> bool,
) -> Option<bool> {
    let id = bundle_id.trim();
    pack_guid(id)?;
    if entries
        .iter()
        .any(|e| e.program_id.key_name().trim().eq_ignore_ascii_case(id))
    {
        return Some(true);
    }
    hive_read(home.hive_sid()).then_some(false)
}

/// `{GUID}` (braces required, any case) to the packed form Windows Installer stores in the registry: 32
/// upper-case hex digits. `None` for anything else.
fn pack_guid(guid: &str) -> Option<String> {
    let inner = guid.strip_prefix('{')?.strip_suffix('}')?;
    let well_formed = inner.len() == 36
        && inner.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    if !well_formed {
        return None;
    }
    let hex: Vec<u8> = inner
        .bytes()
        .filter(|&b| b != b'-')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let mut out: Vec<u8> = Vec::with_capacity(32);
    out.extend(hex[0..8].iter().rev());
    out.extend(hex[8..12].iter().rev());
    out.extend(hex[12..16].iter().rev());
    for pair in hex[16..32].chunks(2) {
        out.push(pair[1]);
        out.push(pair[0]);
    }
    String::from_utf8(out).ok()
}

/// What deciding needs besides the candidates. One per scan.
#[derive(Debug, Clone)]
pub struct DecideCtx<'a> {
    /// The deny-list compiled for this scan's `GuardEnv`.
    pub deny: &'a DenyList,
    /// The scan mode.
    pub mode: ScanMode,
    /// The verify-gone result of the run.
    pub verify_gone: VerifyGone,
    /// The SID of the user the app is cleaned for. It binds `HKCU` and per-user environment tokens, and
    /// only paths inside this user's profile are per-user for Rule T. `None`: every path is machine scope
    /// and an `HKCU` spelling is refused.
    pub user_sid: Option<&'a str>,
    /// Every path candidate was read from the file system in long form (no 8.3 names). Set it only when
    /// that is true: it switches the guard's short-name refusal off.
    pub long_names_resolved: bool,
    /// The blast-radius limits.
    pub limits: Limits,
    /// The M1b exemption lists of this plan ([`M1bDecide::from_facts`]). The default, all empty, keeps
    /// the Windows Installer, Package Cache and Burn exemptions closed.
    pub m1b: M1bDecide,
    /// The trust of the baseline view the candidates were found with, handed to the policy as
    /// `PolicyCtx::baseline_trust` (P-BL-1, BASELINE_LOCAL_DESIGN.md §4.4). A scan whose view is below
    /// Exact must set it (`BaselineTrust::for_policy`): Merged and Local cap absence-dependent evidence
    /// on registry keys; Exact and None decide as policy `m1b.1` did.
    pub baseline_trust: BaselineTrust,
}

impl<'a> DecideCtx<'a> {
    /// A context with the default limits, no user, unresolved long names, empty M1b lists and baseline
    /// trust Exact (the M1b behaviour; a scan with any other view sets
    /// [`DecideCtx::baseline_trust`]).
    pub fn new(deny: &'a DenyList, mode: ScanMode, verify_gone: VerifyGone) -> Self {
        Self {
            deny,
            mode,
            verify_gone,
            user_sid: None,
            long_names_resolved: false,
            limits: Limits::default(),
            m1b: M1bDecide::default(),
            baseline_trust: BaselineTrust::Exact,
        }
    }

    fn env(&self) -> &GuardEnv {
        self.deny.env()
    }
}

/// Decides the candidates of one scan: merge, guard, policy, then `EmptyAfterPlan`. The result has one
/// candidate per distinct target, each with a decision, in the order of first appearance, except the
/// Windows Installer client-list containers the plan does not offer ([`installer_client_list`]).
#[must_use]
pub fn decide(candidates: Vec<Candidate>, ctx: &DecideCtx<'_>) -> Vec<Candidate> {
    let merged = merge(candidates, ctx);
    let mut decided: Vec<Candidate> = merged
        .iter()
        .map(|c| guard_and_policy(c.clone(), ctx))
        .collect();
    empty_after::apply(&mut decided, |index, evidence| {
        let mut candidate = merged[index].clone();
        candidate.evidence.push(evidence);
        guard_and_policy(candidate, ctx)
    });
    decided.retain(|c| !unoffered_installer_container(c, ctx));
    decided
}

/// Whether `candidate` is a delete-if-empty container on a Windows Installer client list
/// ([`installer_client_list`]) that the plan does not offer: one the rest of the plan does not empty (no
/// `EmptyAfterPlan`: some value of it is not an allowed item of the plan), or one the guard does not let
/// through. Such a key holds the values of other products. An empty one left behind is accepted; a listed
/// one would only suggest that the shared key is the app's to remove.
fn unoffered_installer_container(candidate: &Candidate, ctx: &DecideCtx<'_>) -> bool {
    if candidate.action != Action::RemoveDirIfEmpty {
        return false;
    }
    let Target::RegKey { path } = &candidate.target else {
        return false;
    };
    if !installer_client_list(path, ctx) {
        return false;
    }
    let emptied = candidate
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::EmptyAfterPlan);
    let blocked = candidate
        .decision
        .as_ref()
        .is_none_or(|d| d.band == Band::Blocked)
        || candidate
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::DenyListed { .. }));
    !emptied || blocked
}

/// Whether the key is one of Windows Installer's per-product client lists: an `UpgradeCodes\<U>` key
/// (its values are named by packed product codes) or a `Components\<C>` key (its values are named by the
/// packed codes of the component's clients), under the machine Installer data
/// (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer`, with `UserData\<sid>\Components\<C>`), a
/// user's Installer data (`HKU\<sid>\Software\Microsoft\Installer`) or a Classes `Installer` key, in either
/// WOW64 view. The key is compared in the guard's canonical form, segment by folded segment; a key that
/// does not canonicalise is not one (the guard blocks it anyway).
#[must_use]
pub fn installer_client_list(key_path: &str, ctx: &DecideCtx<'_>) -> bool {
    let Ok(key) = canon_key(key_path, None, ctx.env(), ctx.user_sid) else {
        return false;
    };
    let folded: Vec<String> = prefix::segments(&key.path).map(prefix::fold).collect();
    let segs: Vec<&str> = folded.iter().map(String::as_str).collect();
    const MACHINE: &[&str] = &[
        "software",
        "microsoft",
        "windows",
        "currentversion",
        "installer",
    ];
    const USER: &[&str] = &["software", "microsoft", "installer"];
    const CLASSES: &[&str] = &["software", "classes", "installer"];
    let roots: &[&[&str]] = match key.hive {
        Hive::Hklm => &[MACHINE, CLASSES],
        Hive::Hku(_) => &[USER, MACHINE, CLASSES],
        Hive::HkuClasses(_) => &[&["installer"]],
    };
    roots.iter().any(|root| {
        segs.strip_prefix(*root).is_some_and(|rest| {
            matches!(rest, ["upgradecodes" | "components", _])
                || matches!(rest, ["userdata", _, "components", _])
        })
    })
}

/// Whether a target is machine-wide or per-user, for Rule T (§5.3).
///
/// Registry targets follow their hive. A path is per-user only when it lies strictly inside the profile
/// (root, roaming or local AppData) of `ctx.user_sid`; Program Files, ProgramData and other users' profiles
/// are machine scope. Packages, services, tasks and firewall rules are machine scope.
#[must_use]
pub fn target_scope(target: &Target, ctx: &DecideCtx<'_>) -> TargetScope {
    target_scope_in(target, ctx.env(), ctx.user_sid)
}

/// [`target_scope`] with its two inputs given directly: the machine layout and the SID of the user the
/// app is cleaned for (`DecideCtx::user_sid`). Pure.
#[must_use]
pub fn target_scope_in(target: &Target, env: &GuardEnv, user_sid: Option<&str>) -> TargetScope {
    match target {
        Target::Path { path } => {
            let profile = user_sid.and_then(|sid| env.profile(sid));
            let inside = profile.is_some_and(|p| {
                [&p.root, &p.appdata, &p.local_appdata]
                    .into_iter()
                    .any(|dir| !dir.is_empty() && prefix::is_inside(path, dir))
            });
            if inside {
                TargetScope::PerUser
            } else {
                TargetScope::Machine
            }
        }
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => match canon_key(path, None, env, user_sid) {
            Ok(key) => TargetScope::of_hive(&key.hive),
            Err(_) => TargetScope::Machine,
        },
        Target::Service { .. }
        | Target::Task { .. }
        | Target::FirewallRule { .. }
        | Target::AppxPackage { .. } => TargetScope::Machine,
    }
}

/// The exemptions the decide step checks the deny-list with (§5.10): what the candidate's evidence earns
/// ([`deny_exemptions`], with the context's machine layout, user and long-name flag) plus the plan's M1b
/// lists ([`DecideCtx::m1b`]), the same for every candidate. The scan mode, verify-gone result and limits
/// of the context are not consulted.
#[must_use]
pub fn exemptions<'c>(candidate: &Candidate, ctx: &'c DecideCtx<'_>) -> Exemptions<'c> {
    Exemptions {
        gone_burn: ctx.m1b.gone_burn(),
        gone_msi_products: ctx.m1b.gone_msi_products_for(
            &candidate.target,
            ctx.env(),
            ctx.user_sid,
        ),
        gone_cache_dirs: ctx.m1b.gone_cache_dirs(),
        ..deny_exemptions(candidate, ctx.env(), ctx.user_sid, ctx.long_names_resolved)
    }
}

/// The deny-list exemptions (§5.10) the decide step derives for a candidate, from exactly the inputs it
/// uses: the candidate (target, action, evidence), the machine layout of the scan (`DenyList::env`), the
/// SID of the user the app is cleaned for and whether every path was read in long form. Pure: the same
/// inputs always give the same exemptions. [`guard_and_policy`] calls it (through [`exemptions`]) on the
/// canonical target, and checks the deny-list with the result.
///
/// A caller that re-checks a plan item against the deny-list later (the executor's gate) gets the plan's
/// verdict back by passing the item as the plan holds it (its target is already canonical) with the
/// scan's `GuardEnv`, `user_sid` and `long_names_resolved`.
///
/// - `proven_owned_skeleton`: a key target with Tier A, Key-scope `ProvenOwnedSkeleton` evidence.
/// - `environment_segment_edit`: a segment edit of a list value.
/// - `tier_a_start_menu_entry`: a `.lnk` file with Tier A Path-scope evidence, or a delete-if-empty folder
///   that carries `EmptyAfterPlan` (every item in it is a Safe item of the plan). The guard cannot tell a
///   file from a folder, so nothing else below the all-users Start Menu is exempted.
/// - `long_names_resolved`: as passed.
/// - `shared_com_value` (R2a S10): a whole-value delete whose Value-scope evidence (a pre-uninstall
///   reference to the app, a reference into its InstallRoot, a dangling reference) counts at Tier A or B
///   after Rule T and comes from an admin-only source (or from any source on a per-user target): the
///   value's data was the app's. It lifts only the shared-COM rules, for that value.
///
/// The three M1b lists are left empty: no evidence earns them; they come from the plan's system facts
/// ([`M1bDecide`]) and [`exemptions`] adds them.
///
/// Tier A is judged after Rule T ([`target_scope_in`]): user-writable evidence earns nothing on a
/// machine-scope target.
#[must_use]
pub fn deny_exemptions(
    candidate: &Candidate,
    env: &GuardEnv,
    user_sid: Option<&str>,
    long_names_resolved: bool,
) -> Exemptions<'static> {
    let scope = target_scope_in(&candidate.target, env, user_sid);
    let tier_a = |e: &Evidence, wanted: Scope| {
        e.scope == wanted && band::effective_tier(e, scope) == Tier::A && effective_weight(e) > 0
    };
    let is_key = matches!(candidate.target, Target::RegKey { .. });
    let proven_owned_skeleton = is_key
        && candidate
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::ProvenOwnedSkeleton && tier_a(e, Scope::Key));
    let environment_segment_edit = candidate.action == Action::EditSegment
        && matches!(candidate.target, Target::RegMultiSzSegment { .. });
    let tier_a_start_menu_entry = match &candidate.target {
        Target::Path { path } => {
            let is_lnk = prefix::leaf(path).is_some_and(|leaf| {
                leaf.len() > 4
                    && leaf
                        .get(leaf.len() - 4..)
                        .is_some_and(|ext| ext.eq_ignore_ascii_case(".lnk"))
            });
            let any_tier_a = candidate.evidence.iter().any(|e| tier_a(e, Scope::Path));
            let emptied = candidate.action == Action::RemoveDirIfEmpty
                && candidate
                    .evidence
                    .iter()
                    .any(|e| e.kind == EvidenceKind::EmptyAfterPlan && tier_a(e, Scope::Path));
            (is_lnk && any_tier_a && candidate.action == Action::Quarantine) || emptied
        }
        _ => false,
    };
    let shared_com_value = candidate.action == Action::DeleteValue
        && matches!(candidate.target, Target::RegValue { .. })
        && candidate.evidence.iter().any(|e| {
            matches!(
                e.kind,
                EvidenceKind::InPreUninstallRefSnapshot
                    | EvidenceKind::PointsIntoInstallRoot
                    | EvidenceKind::DanglingRef
            ) && e.scope == Scope::Value
                && (e.trust == SourceTrust::AdminOnly || scope == TargetScope::PerUser)
                && matches!(band::effective_tier(e, scope), Tier::A | Tier::B)
                && effective_weight(e) > 0
        });
    Exemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
        shared_com_value,
        // M1b: the three lists come from the plan's system facts, not from evidence (`exemptions`).
        ..Exemptions::default()
    }
}

/// Steps 2 and 3 of the module docs for one candidate: canonicalise, apply the guard and the blast-radius
/// limits, then let the policy decide. Any decision already stored is replaced.
///
/// The function only ever adds blockers, so it is meant to be called on the scanner's candidate (as
/// [`decide`] does), not on its own output after the evidence changed.
#[must_use]
pub fn guard_and_policy(mut candidate: Candidate, ctx: &DecideCtx<'_>) -> Candidate {
    let env = ctx.env();
    match canon_target(&candidate.target, env, ctx.user_sid) {
        Ok(canon) => {
            candidate.target = canon.target;
            let ex = exemptions(&candidate, ctx);
            if let Some(blocker) = ctx.deny.check(&candidate.target, &ex) {
                push_blocker(&mut candidate, blocker);
            }
            if let Some(blocker) = containers::check(&candidate.target, env) {
                push_blocker(&mut candidate, blocker);
            }
            if let Some(blocker) = object_rules(&candidate, ctx) {
                push_blocker(&mut candidate, blocker);
            }
        }
        Err(error) => push_blocker(
            &mut candidate,
            Blocker::DenyListed {
                rule: format!("canon.{}", error.code()),
            },
        ),
    }
    if too_large(&candidate, ctx) {
        push_blocker(&mut candidate, Blocker::TooLarge);
    }
    redecide(&mut candidate, ctx);
    candidate
}

/// The rule id of a typed object that reaches the plan without a well-formed digest of its kind.
pub const OBJECT_NO_FP: &str = "object.no-fp";

/// The object rules the plan applies itself to a system object (R2a S2), on top of the blockers the
/// scan's sealing added from the system-object index (`purge_scan` `ScanCtx::object_guard`), which
/// the plan cannot read:
///
/// - the candidate must carry a well-formed `object_fp` of the target's kind, else the hard
///   `DenyListed { rule: "object.no-fp" }` (the act would be bound to nothing);
/// - a task's path is judged by `DenyList::check_object` (`sys.task.windows` for the folders of
///   Windows, Office and Edge's updater), the one object rule the target alone decides.
///
/// `None` for a target that is no system object.
fn object_rules(candidate: &Candidate, ctx: &DecideCtx<'_>) -> Option<Blocker> {
    let kind = ObjectKind::of(&candidate.target)?;
    let bound = candidate
        .object_fp
        .as_ref()
        .is_some_and(|fp| fp.kind == kind && fp.is_well_formed());
    if !bound {
        return Some(Blocker::DenyListed {
            rule: OBJECT_NO_FP.to_owned(),
        });
    }
    match &candidate.target {
        Target::Task { path } => ctx.deny.check_object(
            ObjectKind::Task,
            &ObjectGuardFacts {
                name_or_path_or_id: path,
                ..ObjectGuardFacts::default()
            },
        ),
        _ => None,
    }
}

/// Runs the policy over `candidate` as it stands and stores the decision. The target must already be
/// canonical. Used after a blocker was added to a decided candidate ([`crate::collapse`]).
pub fn redecide(candidate: &mut Candidate, ctx: &DecideCtx<'_>) {
    let policy = PolicyCtx {
        mode: ctx.mode,
        verify_gone: ctx.verify_gone,
        target_scope: target_scope(&candidate.target, ctx),
        baseline_trust: ctx.baseline_trust,
    };
    candidate.decision = Some(band::decide(candidate, &policy));
}

/// Adds `blocker` unless the candidate already has an equal one.
pub fn push_blocker(candidate: &mut Candidate, blocker: Blocker) {
    if !candidate.blockers.contains(&blocker) {
        candidate.blockers.push(blocker);
    }
}

/// Whether a whole removal is above the blast-radius limits. Value edits and delete-if-empty never are.
fn too_large(candidate: &Candidate, ctx: &DecideCtx<'_>) -> bool {
    let limits = &ctx.limits;
    let count = candidate.child_count.unwrap_or(0);
    match (&candidate.target, candidate.action) {
        (Target::RegKey { .. }, Action::DeleteKey) => count > limits.max_key_items,
        (Target::Path { .. }, Action::Quarantine) => {
            let scope = target_scope(&candidate.target, ctx);
            let proven_root = candidate.evidence.iter().any(|e| {
                e.kind == EvidenceKind::InsideInstallRoot
                    && e.scope == Scope::Path
                    && band::effective_tier(e, scope) == Tier::A
                    && effective_weight(e) > 0
            });
            let max_files = if proven_root {
                limits.max_root_files
            } else {
                limits.max_files
            };
            count > max_files || candidate.size_bytes.unwrap_or(0) > limits.max_bytes
        }
        _ => false,
    }
}

/// How strongly an action removes: a removal, then delete-if-empty, then report-only.
fn action_strength(action: Action) -> u8 {
    match action {
        Action::Quarantine
        | Action::DeleteKey
        | Action::DeleteValue
        | Action::EditSegment
        | Action::RemovePackage => 2,
        Action::RemoveDirIfEmpty => 1,
        Action::ReportOnly => 0,
    }
}

/// The key candidates are merged on: the owner and the canonical target, folded for comparison. A target
/// that does not canonicalise is keyed by its own spelling.
fn merge_key(candidate: &Candidate, ctx: &DecideCtx<'_>) -> Vec<String> {
    let target = canon_target(&candidate.target, ctx.env(), ctx.user_sid)
        .map_or_else(|_| candidate.target.clone(), |canon| canon.target);
    let fold = |s: &str| prefix::fold(s.trim_end_matches(prefix::SEP));
    let owner = serde_json::to_string(&candidate.owner.program_id).unwrap_or_default();
    // The parts stay separate strings. Joined with any separator character, a key or value name holding
    // that character (registry names may hold anything but a backslash) could make two different targets
    // read as one, and the evidence of one would then count for the other.
    let mut parts: Vec<String> = match &target {
        Target::Path { path } => vec!["path".into(), fold(path)],
        Target::RegKey { path } => vec!["key".into(), fold(path)],
        Target::RegValue { path, name } => vec!["value".into(), fold(path), prefix::fold(name)],
        Target::RegValueChanged { path, name, .. } => {
            vec!["changed".into(), fold(path), prefix::fold(name)]
        }
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => vec![
            "segment".into(),
            fold(path),
            prefix::fold(name),
            prefix::fold(segment),
            index.map(|i| i.to_string()).unwrap_or_default(),
        ],
        Target::Service { name } => vec!["service".into(), prefix::fold(name)],
        Target::Task { path } => vec!["task".into(), fold(path)],
        Target::FirewallRule { id } => vec!["firewall".into(), prefix::fold(id)],
        Target::AppxPackage { full_name } => vec!["package".into(), prefix::fold(full_name)],
    };
    parts.insert(0, owner);
    parts
}

/// The candidate ids that name more than one merge target (folded owner and canonical target, as
/// [`merge_key`]): an id collision in a scan (review M3-R1 M2).
///
/// Two candidates of one id on the same target are one item and merge; on different targets the id
/// cannot select exactly one of them, so [`merge`] drops all of that id's candidates. The pipeline
/// reports each dropped id as a warning.
#[must_use]
pub fn colliding_ids(candidates: &[Candidate], ctx: &DecideCtx<'_>) -> BTreeSet<CandidateId> {
    let mut first: HashMap<&CandidateId, Vec<String>> = HashMap::new();
    let mut out = BTreeSet::new();
    for candidate in candidates {
        let key = merge_key(candidate, ctx);
        match first.get(&candidate.id) {
            Some(seen) if *seen != key => {
                out.insert(candidate.id.clone());
            }
            Some(_) => {}
            None => {
                first.insert(&candidate.id, key);
            }
        }
    }
    out
}

/// Step 1 of the module docs: folds candidates on the same target into one, in order of first appearance.
/// Stored decisions and any `EmptyAfterPlan` evidence are dropped.
///
/// A typed object (service, task, firewall rule) keeps the `object_fp` of the first candidate. When the
/// candidates of its group do not all carry the same one (absent included), it gets the hard blocker
/// `ObjectChangedSinceHarvest`. Its children are cleared, whoever listed them.
///
/// A candidate whose id names more than one target ([`colliding_ids`]) is dropped, all of that id: an id
/// that cannot select exactly one target is not a usable key (review M3-R1 M2).
#[must_use]
pub fn merge(candidates: Vec<Candidate>, ctx: &DecideCtx<'_>) -> Vec<Candidate> {
    let colliding = colliding_ids(&candidates, ctx);
    let mut groups: Vec<Vec<Candidate>> = Vec::new();
    let mut index: HashMap<Vec<String>, usize> = HashMap::new();
    for mut candidate in candidates {
        if colliding.contains(&candidate.id) {
            continue;
        }
        candidate.decision = None;
        candidate
            .evidence
            .retain(|e| e.kind != EvidenceKind::EmptyAfterPlan);
        let slot = *index.entry(merge_key(&candidate, ctx)).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[slot].push(candidate);
    }
    groups.into_iter().map(merge_group).collect()
}

fn merge_group(group: Vec<Candidate>) -> Candidate {
    // C-OBJECT: every candidate on one typed target must have seen the same object. An absent digest is a
    // value of its own, so a digest and no digest disagree too.
    let typed = group
        .first()
        .is_some_and(|c| ObjectKind::of(&c.target).is_some());
    let one_object = group
        .windows(2)
        .all(|pair| pair[0].object_fp == pair[1].object_fp);
    let strongest = group
        .iter()
        .map(|c| action_strength(c.action))
        .max()
        .unwrap_or(0);
    // The action of the first candidate among those with the strongest action.
    let action = group
        .iter()
        .find(|c| action_strength(c.action) == strongest)
        .map_or(Action::ReportOnly, |c| c.action);
    let mut rest = group.into_iter();
    let Some(mut merged) = rest.next() else {
        unreachable!("a merge group holds at least one candidate");
    };
    if merged.action != action {
        // Evidence recorded for a weaker action says nothing about the stronger one.
        merged.evidence.clear();
        merged.action = action;
    }
    dedupe(&mut merged.evidence);
    for other in rest {
        if other.action == action {
            for mut evidence in other.evidence {
                if merged.evidence.contains(&evidence) {
                    continue;
                }
                if other.scanner != merged.scanner && evidence.detail.get(SCANNER_KEY).is_none() {
                    evidence
                        .detail
                        .0
                        .insert(SCANNER_KEY.to_owned(), other.scanner.clone());
                }
                if !merged.evidence.contains(&evidence) {
                    merged.evidence.push(evidence);
                }
            }
        }
        for blocker in other.blockers {
            push_blocker(&mut merged, blocker);
        }
        for child in other.children {
            if !merged.children.contains(&child) {
                merged.children.push(child);
            }
        }
        merged.category = stricter_category(merged.category, other.category);
        merged.harm = merged.harm.max(other.harm);
        merged.reversibility = worse_reversibility(merged.reversibility, other.reversibility);
        merged.origin = stricter_origin(merged.origin, other.origin);
        merged.size_bytes = merged.size_bytes.max(other.size_bytes);
        merged.child_count = merged.child_count.max(other.child_count);
    }
    if typed {
        if !one_object {
            push_blocker(&mut merged, Blocker::ObjectChangedSinceHarvest);
        }
        // An object is removed through its own API, alone: it holds no plan items.
        merged.children.clear();
    }
    merged
}

fn dedupe(evidence: &mut Vec<Evidence>) {
    let mut seen: Vec<Evidence> = Vec::with_capacity(evidence.len());
    evidence.retain(|e| {
        let new = !seen.contains(e);
        if new {
            seen.push(e.clone());
        }
        new
    });
}

/// `UserData` and `System` are never preselected (§5.8.2), so they win over any other category.
fn stricter_category(a: Category, b: Category) -> Category {
    let rank = |c: Category| match c {
        Category::UserData => 2,
        Category::System => 1,
        _ => 0,
    };
    if rank(b) > rank(a) { b } else { a }
}

fn worse_reversibility(a: Reversibility, b: Reversibility) -> Reversibility {
    let rank = |r: Reversibility| match r {
        Reversibility::Full => 0,
        Reversibility::Partial => 1,
        Reversibility::None => 2,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// An agent proposal is never preselected and a signature is capped at Likely (§5.8.2), so they win.
fn stricter_origin(a: Origin, b: Origin) -> Origin {
    let rank = |o: Origin| match o {
        Origin::Scanner => 0,
        Origin::ManualUser => 1,
        Origin::Signature => 2,
        Origin::ProbeAgent => 3,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// Builders shared by the tests of this crate.
#[cfg(test)]
pub(crate) mod testkit {
    use purge_guard::canon::GuardEnv;
    use purge_guard::deny::DenyList;
    use purge_model::{
        Action, AppRef, Candidate, CandidateId, Category, Evidence, EvidenceKind, Harm, Origin,
        ProgramId, Reversibility, ScanMode, Scope, SourceTrust, Target, VerifyGone, View,
    };

    use super::DecideCtx;

    pub(crate) const SID: &str = GuardEnv::SAMPLE_SID;

    pub(crate) fn deny() -> DenyList {
        DenyList::compile(&GuardEnv::sample())
    }

    /// Post mode, verify-gone passed, the sample user, long names resolved.
    pub(crate) fn ctx(deny: &DenyList) -> DecideCtx<'_> {
        DecideCtx {
            user_sid: Some(SID),
            long_names_resolved: true,
            ..DecideCtx::new(deny, ScanMode::Post, VerifyGone::new(true, true, true))
        }
    }

    pub(crate) fn path(p: &str) -> Target {
        Target::Path { path: p.into() }
    }

    pub(crate) fn key(p: &str) -> Target {
        Target::RegKey { path: p.into() }
    }

    pub(crate) fn value(p: &str, name: &str) -> Target {
        Target::RegValue {
            path: p.into(),
            name: name.into(),
        }
    }

    pub(crate) fn ev(kind: EvidenceKind, scope: Scope, source: &str) -> Evidence {
        Evidence::new(kind, scope, SourceTrust::AdminOnly, source).expect("scope fits the kind")
    }

    /// A candidate with the usual action for its target and no evidence.
    pub(crate) fn cand(id: &str, target: Target, scanner: &str) -> Candidate {
        let action = match &target {
            Target::Path { .. } => Action::Quarantine,
            Target::RegKey { .. } => Action::DeleteKey,
            Target::RegMultiSzSegment { .. } => Action::EditSegment,
            Target::AppxPackage { .. } => Action::RemovePackage,
            _ => Action::DeleteValue,
        };
        Candidate {
            id: CandidateId(id.into()),
            target,
            action,
            owner: AppRef {
                program_id: ProgramId::machine(View::K64, "App_is1").expect("valid key name"),
                display_name: "App".into(),
            },
            origin: Origin::Scanner,
            scanner: scanner.into(),
            category: Category::Registration,
            evidence: Vec::new(),
            blockers: Vec::new(),
            harm: Harm::Low,
            reversibility: Reversibility::Full,
            children: Vec::new(),
            size_bytes: None,
            child_count: None,
            decision: None,
            item_fp: None,
            object_fp: None,
        }
    }

    /// A Safe-capable file candidate under an install root.
    pub(crate) fn owned_path(id: &str, p: &str) -> Candidate {
        let mut c = cand(id, path(p), "FS-INSTALLDIR");
        c.category = Category::AppFiles;
        c.evidence
            .push(ev(EvidenceKind::InsideInstallRoot, Scope::Path, "arp"));
        c
    }

    /// A Safe-capable key candidate.
    pub(crate) fn owned_key(id: &str, p: &str) -> Candidate {
        let mut c = cand(id, key(p), "REG-SOFTWARE");
        c.evidence.push(ev(
            EvidenceKind::InstallerManifest(purge_model::ManifestKind::Inno),
            Scope::Key,
            "inno",
        ));
        c
    }

    /// A Safe-capable value candidate.
    pub(crate) fn owned_value(id: &str, p: &str, name: &str) -> Candidate {
        let mut c = cand(id, value(p, name), "REF-ANY");
        c.evidence.push(ev(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            "refsnap",
        ));
        c
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use purge_model::{Band, CandidateId, Harm, SourceTrust};

    fn band(c: &Candidate) -> Band {
        c.decision.as_ref().expect("decided").band
    }

    fn one(c: Candidate, ctx: &DecideCtx<'_>) -> Candidate {
        let mut out = decide(vec![c], ctx);
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    fn deny_rule(c: &Candidate) -> Option<&str> {
        c.blockers.iter().find_map(|b| match b {
            Blocker::DenyListed { rule } => Some(rule.as_str()),
            _ => None,
        })
    }

    #[test]
    fn allowed_target_is_canonicalised_and_safe() {
        let deny = deny();
        let ctx = ctx(&deny);
        let c = one(
            owned_key("c1", r"HKEY_LOCAL_MACHINE\Software\Vendor\App\"),
            &ctx,
        );
        assert_eq!(c.target, key(r"HKLM\SOFTWARE\Vendor\App"));
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        let d = c.decision.as_ref().unwrap();
        assert_eq!((d.band, d.preselected), (Band::Safe, true));

        let c = one(
            owned_value("c2", r"HKCU\Software\Vendor\App", "InstallDir"),
            &ctx,
        );
        assert_eq!(
            c.target,
            value(&format!(r"HKU\{SID}\Software\Vendor\App"), "InstallDir")
        );
        assert_eq!(band(&c), Band::Safe);
    }

    /// BL-POLICY: the context's baseline trust reaches the policy (P-BL-1). A key that is Safe on an
    /// installer key record is Likely and unticked with an inferred view, with or without the carrier
    /// blocker; `new` keeps the M1b behaviour; a value and a file are not touched by the cap.
    #[test]
    fn baseline_trust_reaches_the_policy() {
        let deny = deny();
        let exact = ctx(&deny);
        assert_eq!(exact.baseline_trust, BaselineTrust::Exact);
        let verdict = |c: Candidate, ctx: &DecideCtx<'_>| {
            let c = one(c, ctx);
            let d = c.decision.expect("decided");
            (d.band, d.preselected)
        };
        let key_c = || owned_key("k", r"HKLM\SOFTWARE\Vendor\App");
        let carried = || {
            let mut c = key_c();
            c.blockers.push(Blocker::BaselineInferred);
            c
        };
        for trust in [BaselineTrust::Exact, BaselineTrust::None] {
            let ctx = DecideCtx {
                baseline_trust: trust,
                ..exact.clone()
            };
            assert_eq!(verdict(key_c(), &ctx), (Band::Safe, true), "{trust:?}");
            assert_eq!(verdict(carried(), &ctx), (Band::Likely, false), "{trust:?}");
        }
        for trust in [BaselineTrust::Merged, BaselineTrust::Local] {
            let ctx = DecideCtx {
                baseline_trust: trust,
                ..exact.clone()
            };
            assert_eq!(verdict(key_c(), &ctx), (Band::Likely, false), "{trust:?}");
            assert_eq!(verdict(carried(), &ctx), (Band::Likely, false), "{trust:?}");
            let value = owned_value("v", r"HKLM\SOFTWARE\Vendor\App", "InstallDir");
            assert_eq!(verdict(value, &ctx), (Band::Safe, true), "{trust:?}");
            let file = owned_path("p", r"C:\Program Files\App");
            assert_eq!(verdict(file, &ctx), (Band::Safe, true), "{trust:?}");
            // Two scanners on one key: the carrier of one caps the merged item.
            let merged = decide(vec![key_c(), carried()], &ctx);
            assert_eq!(merged.len(), 1);
            assert!(merged[0].blockers.contains(&Blocker::BaselineInferred));
            // A redecision (after a blocker was added to a decided candidate) keeps the cap.
            let mut again = one(key_c(), &ctx);
            again.decision = None;
            redecide(&mut again, &ctx);
            let d = again.decision.expect("decided");
            assert_eq!((d.band, d.preselected), (Band::Likely, false), "{trust:?}");
        }
    }

    #[test]
    fn target_that_does_not_canonicalise_is_blocked() {
        let deny = deny();
        let ctx = ctx(&deny);
        for (target, rule) in [
            (path(r"C:\Program Files\App\..\Other"), "canon.dot-segment"),
            (path(r"\\server\share\App"), "canon.unc"),
            (path(r"relative\App"), "canon.relative"),
            (key(r"HKCR\App.Document"), "canon.hkcr"),
            (key(r"HKU\not-a-sid\Software\App"), "canon.bad-sid"),
        ] {
            let mut c = owned_path("c", "x");
            c.target = target.clone();
            let c = one(c, &ctx);
            assert_eq!(c.target, target, "the spelling is kept");
            assert_eq!(deny_rule(&c), Some(rule));
            let d = c.decision.as_ref().unwrap();
            assert_eq!((d.band, d.preselected), (Band::Blocked, false));
        }
        // HKCU cannot be bound without a user.
        let mut unbound = ctx;
        unbound.user_sid = None;
        let c = one(owned_key("c", r"HKCU\Software\Vendor\App"), &unbound);
        assert_eq!(deny_rule(&c), Some("canon.no-profile"));
        assert_eq!(band(&c), Band::Blocked);
    }

    #[test]
    fn deny_listed_target_is_blocked_whatever_the_evidence() {
        let deny = deny();
        let ctx = ctx(&deny);
        for target in [
            path(r"C:\Windows\System32\drivers"),
            path(r"C:\Program Files"),
            key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"),
            key(r"HKLM\SYSTEM\CurrentControlSet\Services"),
        ] {
            let mut c = owned_path("c", "x");
            c.target = target.clone();
            c.action = match target {
                Target::Path { .. } => Action::Quarantine,
                _ => Action::DeleteKey,
            };
            c.evidence = vec![
                ev(EvidenceKind::InsideInstallRoot, Scope::Path, "a"),
                ev(
                    EvidenceKind::InstallerManifest(purge_model::ManifestKind::Inno),
                    Scope::Key,
                    "b",
                ),
            ];
            let c = one(c, &ctx);
            assert!(deny_rule(&c).is_some(), "{target:?} must be denied");
            let d = c.decision.as_ref().unwrap();
            assert_eq!(
                (d.band, d.preselected),
                (Band::Blocked, false),
                "{target:?}"
            );
        }
    }

    #[test]
    fn short_names_are_refused_unless_resolved() {
        let deny = deny();
        let mut ctx = ctx(&deny);
        ctx.long_names_resolved = false;
        for short in [r"C:\PROGRA~1\App\app.exe", r"C:\Apps\LONGNA~1\app.exe"] {
            let c = one(owned_path("c", short), &ctx);
            assert!(deny_rule(&c).is_some(), "{short}");
            assert_eq!(band(&c), Band::Blocked, "{short}");
        }
        // Only a caller that really read long names from the file system may say so.
        ctx.long_names_resolved = true;
        let c = one(owned_path("c", r"C:\Apps\LONGNA~1\app.exe"), &ctx);
        assert_eq!(band(&c), Band::Safe, "{:?}", c.blockers);
    }

    #[test]
    fn value_container_key_is_structural_but_its_values_pass() {
        let deny = deny();
        let ctx = ctx(&deny);
        let run = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run");
        let c = one(owned_key("k", &run), &ctx);
        assert!(c.blockers.contains(&Blocker::StructuralContainer));
        assert_eq!(band(&c), Band::Blocked);
        let mut empty = owned_key("k", &run);
        empty.action = Action::RemoveDirIfEmpty;
        assert_eq!(band(&one(empty, &ctx)), Band::Blocked);
        let c = one(owned_value("v", &run, "App"), &ctx);
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        assert_eq!(band(&c), Band::Safe);
    }

    #[test]
    fn skeleton_exemption_needs_the_evidence() {
        let deny = deny();
        let ctx = ctx(&deny);
        let shell = r"HKLM\SOFTWARE\Classes\Directory\shell";
        let plain = one(owned_key("k", shell), &ctx);
        assert_eq!(band(&plain), Band::Blocked, "{:?}", plain.blockers);
        let mut proven = cand("k", key(shell), "CLS-VERBS");
        proven
            .evidence
            .push(ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key, "subtree"));
        assert!(exemptions(&proven, &ctx).proven_owned_skeleton);
        let proven = one(proven, &ctx);
        assert!(deny_rule(&proven).is_none(), "{:?}", proven.blockers);
        // Rule T: a user-writable record does not earn the exemption for a machine key.
        let mut weak = cand("k", key(shell), "CLS-VERBS");
        let mut e = ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key, "subtree");
        e.trust = SourceTrust::UserWritable;
        weak.evidence.push(e);
        assert!(!exemptions(&weak, &ctx).proven_owned_skeleton);
        assert_eq!(band(&one(weak, &ctx)), Band::Blocked);
    }

    #[test]
    fn environment_segment_edit_is_exempt_and_whole_value_is_not() {
        let deny = deny();
        let ctx = ctx(&deny);
        let env_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
        let mut segment = cand(
            "s",
            Target::RegMultiSzSegment {
                path: env_key.into(),
                name: "Path".into(),
                segment: r"C:\Program Files\App\bin".into(),
                index: None,
            },
            "REG-ENV",
        );
        segment.harm = Harm::Medium;
        segment.evidence.push(ev(
            EvidenceKind::InstallerManifest(purge_model::ManifestKind::Inno),
            Scope::Value,
            "inno",
        ));
        let segment = one(segment, &ctx);
        assert!(segment.blockers.is_empty(), "{:?}", segment.blockers);
        assert_eq!(band(&segment), Band::Safe);
        match &segment.target {
            Target::RegMultiSzSegment { path, .. } => assert_eq!(
                path,
                r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment"
            ),
            other => panic!("{other:?}"),
        }
        let whole = one(owned_value("v", env_key, "Path"), &ctx);
        assert_eq!(band(&whole), Band::Blocked);
    }

    #[test]
    fn start_menu_exemption_is_for_tier_a_shortcuts_only() {
        let deny = deny();
        let ctx = ctx(&deny);
        let programs = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";
        let lnk = one(owned_path("l", &format!(r"{programs}\App\App.lnk")), &ctx);
        assert_eq!(band(&lnk), Band::Safe, "{:?}", lnk.blockers);
        // Name evidence is not Tier A.
        let mut named = cand(
            "n",
            path(&format!(r"{programs}\App\App.lnk")),
            "FS-SHORTCUTS",
        );
        named
            .evidence
            .push(ev(EvidenceKind::ExactFullName, Scope::Path, "name"));
        assert_eq!(band(&one(named, &ctx)), Band::Blocked);
        // A folder is not exempt on plain Tier A evidence.
        let folder = one(owned_path("f", &format!(r"{programs}\App")), &ctx);
        assert_eq!(band(&folder), Band::Blocked);
    }

    /// Candidates for which each exemption is earned, or nearly earned, and some for which none is.
    fn exemption_cases() -> Vec<Candidate> {
        let programs = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";
        let shell = r"HKLM\SOFTWARE\Classes\Directory\shell";
        let env_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
        let mut proven = cand("proven", key(shell), "CLS-VERBS");
        proven
            .evidence
            .push(ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key, "subtree"));
        let mut user_written = proven.clone();
        user_written.id = CandidateId("user-written".into());
        user_written.evidence[0].trust = SourceTrust::UserWritable;
        let segment = |id: &str, action: Action| {
            let mut c = cand(
                id,
                Target::RegMultiSzSegment {
                    path: env_key.into(),
                    name: "Path".into(),
                    segment: r"C:\Program Files\App\bin".into(),
                    index: None,
                },
                "REG-ENV",
            );
            c.action = action;
            c
        };
        let mut named_lnk = cand("named-lnk", path(&format!(r"{programs}\App\App.lnk")), "X");
        named_lnk
            .evidence
            .push(ev(EvidenceKind::ExactFullName, Scope::Path, "name"));
        let mut emptied = cand("emptied", path(&format!(r"{programs}\App")), "X");
        emptied.action = Action::RemoveDirIfEmpty;
        emptied
            .evidence
            .push(ev(EvidenceKind::EmptyAfterPlan, Scope::Path, "plan"));
        let mut user_lnk = owned_path("user-lnk", &format!(r"{programs}\App\Other.lnk"));
        user_lnk.evidence[0].trust = SourceTrust::UserWritable;
        let mut report_lnk = owned_path("report-lnk", &format!(r"{programs}\App\Report.lnk"));
        report_lnk.action = Action::ReportOnly;
        vec![
            proven,
            user_written,
            owned_key("plain-shell", shell),
            segment("segment", Action::EditSegment),
            segment("segment-report", Action::ReportOnly),
            owned_value("whole-path", env_key, "Path"),
            owned_path("lnk", &format!(r"{programs}\App\App.lnk")),
            named_lnk,
            user_lnk,
            report_lnk,
            owned_path("folder", &format!(r"{programs}\App")),
            emptied,
            owned_path("short", r"C:\PROGRA~1\App\app.exe"),
            owned_path("app", r"C:\Program Files\Vendor\App\app.exe"),
            owned_key("app-key", r"HKLM\SOFTWARE\Vendor\App"),
            Candidate {
                object_fp: Some(purge_model::ObjectFp {
                    kind: ObjectKind::Service,
                    sha256: "a".repeat(64),
                }),
                ..cand(
                    "svc",
                    Target::Service {
                        name: "AppSvc".into(),
                    },
                    "SYS",
                )
            },
        ]
    }

    /// R2a S2: a typed object without a well-formed digest of its kind is `object.no-fp`; a task path
    /// under Windows' own task folder is denied by the object rules in the plan itself.
    #[test]
    fn object_rules_bind_and_judge_typed_targets() {
        let deny = deny();
        let ctx = ctx(&deny);
        let rule = |c: &Candidate| {
            c.blockers
                .iter()
                .filter_map(|b| match b {
                    Blocker::DenyListed { rule } => Some(rule.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let fp = |kind, sha: &str| {
            Some(purge_model::ObjectFp {
                kind,
                sha256: sha.into(),
            })
        };
        let svc = || {
            cand(
                "svc",
                Target::Service {
                    name: "AppSvc".into(),
                },
                "SYS",
            )
        };
        for bad in [
            None,
            fp(ObjectKind::Service, "A".repeat(64).as_str()),
            fp(ObjectKind::Task, "a".repeat(64).as_str()),
        ] {
            let c = guard_and_policy(
                Candidate {
                    object_fp: bad.clone(),
                    ..svc()
                },
                &ctx,
            );
            assert_eq!(rule(&c), vec![OBJECT_NO_FP.to_owned()], "{bad:?}");
        }
        let good = guard_and_policy(
            Candidate {
                object_fp: fp(ObjectKind::Service, &"a".repeat(64)),
                ..svc()
            },
            &ctx,
        );
        assert!(rule(&good).is_empty());
        let task = |path: &str| {
            guard_and_policy(
                Candidate {
                    object_fp: fp(ObjectKind::Task, &"b".repeat(64)),
                    ..cand("task", Target::Task { path: path.into() }, "SYS")
                },
                &ctx,
            )
        };
        assert!(!rule(&task(r"\Microsoft\Windows\Defrag\ScheduledDefrag")).is_empty());
        assert!(rule(&task(r"\VendorAppUpdate")).is_empty());
    }

    /// `deny_exemptions` is `exemptions` with the inputs spelled out: equal under every context, whatever
    /// the mode, verify-gone result and limits (which it does not read).
    #[test]
    fn deny_exemptions_equals_the_decide_step_derivation() {
        let deny = deny();
        let base = ctx(&deny);
        let mut contexts = Vec::new();
        for mode in [ScanMode::Post, ScanMode::External, ScanMode::Forced] {
            for verify_gone in [
                VerifyGone::new(true, true, true),
                VerifyGone::new(false, true, false),
            ] {
                for user_sid in [Some(SID), None] {
                    for long_names_resolved in [true, false] {
                        contexts.push(DecideCtx {
                            mode,
                            verify_gone,
                            user_sid,
                            long_names_resolved,
                            limits: Limits {
                                max_key_items: 1,
                                ..Limits::default()
                            },
                            ..base.clone()
                        });
                    }
                }
            }
        }
        let mut earned = [false; 3];
        for ctx in &contexts {
            for c in exemption_cases() {
                // As the decide step sees it: on the canonical target.
                let canonical = match canon_target(&c.target, ctx.env(), ctx.user_sid) {
                    Ok(canon) => Candidate {
                        target: canon.target,
                        ..c.clone()
                    },
                    Err(_) => c.clone(),
                };
                for c in [&c, &canonical] {
                    let ex = deny_exemptions(c, deny.env(), ctx.user_sid, ctx.long_names_resolved);
                    assert_eq!(ex, exemptions(c, ctx), "{}", c.id.0);
                    assert_eq!(ex.long_names_resolved, ctx.long_names_resolved);
                    earned[0] |= ex.proven_owned_skeleton;
                    earned[1] |= ex.environment_segment_edit;
                    earned[2] |= ex.tier_a_start_menu_entry;
                }
            }
        }
        assert_eq!(earned, [true; 3], "every exemption is exercised");
    }

    /// Pinned to the decide step's result: the deny-list verdict on a decided candidate is exactly
    /// `deny.check(target, deny_exemptions(...))` on its canonical target, and the exemptions decide it
    /// (without them the same targets are denied).
    #[test]
    fn deny_exemptions_reproduce_the_decide_step_verdict() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut lifted = Vec::new();
        for c in exemption_cases() {
            let decided = guard_and_policy(c.clone(), &ctx);
            let canonical = Candidate {
                target: decided.target.clone(),
                ..c.clone()
            };
            let ex = deny_exemptions(
                &canonical,
                deny.env(),
                ctx.user_sid,
                ctx.long_names_resolved,
            );
            let verdict = deny.check(&decided.target, &ex);
            let denied: Vec<&Blocker> = decided
                .blockers
                .iter()
                .filter(|b| matches!(b, Blocker::DenyListed { .. }))
                .collect();
            assert_eq!(denied, verdict.iter().collect::<Vec<_>>(), "{}", c.id.0);
            let without = Exemptions {
                long_names_resolved: ex.long_names_resolved,
                ..Exemptions::default()
            };
            if verdict.is_none() && deny.check(&decided.target, &without).is_some() {
                lifted.push(c.id.0.clone());
            }
        }
        assert_eq!(lifted, ["proven", "segment", "lnk", "emptied"]);
    }

    #[test]
    fn blast_radius_adds_too_large() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut big_key = owned_key("k", r"HKLM\SOFTWARE\Vendor\App");
        big_key.child_count = Some(51);
        let big_key = one(big_key, &ctx);
        assert!(big_key.blockers.contains(&Blocker::TooLarge));
        let d = big_key.decision.as_ref().unwrap();
        assert_eq!((d.band, d.preselected), (Band::Likely, false));
        let mut ok_key = owned_key("k", r"HKLM\SOFTWARE\Vendor\App");
        ok_key.child_count = Some(50);
        assert_eq!(band(&one(ok_key, &ctx)), Band::Safe);

        // A directory that is not a proven install root: 5,000 files.
        let mut dir = cand("d", path(r"C:\ProgramData\Vendor\App"), "FS-APPDATA");
        dir.evidence
            .push(ev(EvidenceKind::HarvestedToken, Scope::Path, "token"));
        dir.evidence
            .push(ev(EvidenceKind::UninstallerArtifact, Scope::Path, "unins"));
        dir.child_count = Some(5_001);
        assert!(one(dir.clone(), &ctx).blockers.contains(&Blocker::TooLarge));
        dir.child_count = Some(5_000);
        assert_eq!(band(&one(dir, &ctx)), Band::Safe);

        // A proven install root: 50,000 files or 2 GB.
        let mut root = owned_path("r", r"C:\Program Files\App");
        root.child_count = Some(30_000);
        root.size_bytes = Some(1 << 30);
        assert_eq!(band(&one(root.clone(), &ctx)), Band::Safe);
        root.child_count = Some(50_001);
        assert!(
            one(root.clone(), &ctx)
                .blockers
                .contains(&Blocker::TooLarge)
        );
        root.child_count = Some(10);
        root.size_bytes = Some((2 << 30) + 1);
        let root = one(root, &ctx);
        assert_eq!(
            root.blockers
                .iter()
                .filter(|b| **b == Blocker::TooLarge)
                .count(),
            1
        );
        assert_eq!(band(&root), Band::Likely);

        // Delete-if-empty and value targets are never too large.
        let mut empty = owned_key("e", r"HKLM\SOFTWARE\Vendor\App");
        empty.action = Action::RemoveDirIfEmpty;
        empty.child_count = Some(500);
        assert!(!one(empty, &ctx).blockers.contains(&Blocker::TooLarge));
    }

    #[test]
    fn target_scope_classes() {
        let deny = deny();
        let ctx = ctx(&deny);
        let scope = |t: &Target| target_scope(t, &ctx);
        assert_eq!(
            scope(&path(r"C:\Users\tester\AppData\Roaming\App")),
            TargetScope::PerUser
        );
        assert_eq!(scope(&path(r"C:\Users\tester")), TargetScope::Machine);
        assert_eq!(
            scope(&path(r"C:\Users\other\AppData")),
            TargetScope::Machine
        );
        assert_eq!(scope(&path(r"C:\Program Files\App")), TargetScope::Machine);
        assert_eq!(scope(&path(r"C:\ProgramData\App")), TargetScope::Machine);
        assert_eq!(scope(&key(r"HKLM\SOFTWARE\App")), TargetScope::Machine);
        assert_eq!(
            scope(&key(&format!(r"HKU\{SID}\Software\App"))),
            TargetScope::PerUser
        );
        assert_eq!(scope(&key(r"HKCU\Software\App")), TargetScope::PerUser);
        assert_eq!(
            scope(&key(r"HKU\.DEFAULT\Software\App")),
            TargetScope::Machine
        );
        let mut nobody = ctx.clone();
        nobody.user_sid = None;
        assert_eq!(
            target_scope(&path(r"C:\Users\tester\AppData\Roaming\App"), &nobody),
            TargetScope::Machine
        );
        // Rule T through the whole decision: user-writable proof of a machine path is not Safe.
        let mut c = owned_path("c", r"C:\Program Files\App\app.exe");
        c.evidence[0].trust = SourceTrust::UserWritable;
        assert_eq!(band(&one(c, &ctx)), Band::Likely);
        let mut c = owned_path("c", r"C:\Users\tester\AppData\Local\App\app.exe");
        c.evidence[0].trust = SourceTrust::UserWritable;
        assert_eq!(band(&one(c, &ctx)), Band::Safe);
    }

    #[test]
    fn duplicates_merge_with_evidence_union() {
        let deny = deny();
        let ctx = ctx(&deny);
        let run = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run");
        let mut a = cand("a", value(&run, "App"), "REG-RUN");
        a.evidence
            .push(ev(EvidenceKind::PointsIntoInstallRoot, Scope::Value, "run"));
        let mut b = cand(
            "b",
            value(
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                "app",
            ),
            "REF-ANY",
        );
        b.evidence.push(ev(
            EvidenceKind::PointsIntoInstallRoot,
            Scope::Value,
            "refsnap",
        ));
        b.evidence
            .push(ev(EvidenceKind::PointsIntoInstallRoot, Scope::Value, "run"));
        b.blockers.push(Blocker::InUse);
        b.harm = Harm::Medium;
        let other = owned_value("o", &run, "Other");

        // Alone, each is Likely on its score (6); merged, the second source adds the bonus but the soft
        // blocker and the harm of the second candidate come along.
        assert_eq!(
            decide(vec![a.clone()], &ctx)[0]
                .decision
                .as_ref()
                .unwrap()
                .score,
            6
        );
        let out = decide(vec![a.clone(), other.clone(), b.clone()], &ctx);
        assert_eq!(out.len(), 2);
        let m = &out[0];
        assert_eq!((m.id.0.as_str(), m.scanner.as_str()), ("a", "REG-RUN"));
        assert_eq!(m.evidence.len(), 2, "equal evidence is kept once");
        assert_eq!(m.evidence[0].detail.get(SCANNER_KEY), None);
        assert_eq!(m.evidence[1].detail.get(SCANNER_KEY), Some("REF-ANY"));
        assert_eq!(m.evidence[1].source.0, "refsnap");
        assert_eq!(
            m.decision.as_ref().unwrap().score,
            7,
            "6 + 1 independent source"
        );
        assert_eq!(m.blockers, vec![Blocker::InUse]);
        assert_eq!(m.harm, Harm::Medium);
        assert_eq!(out[1].id.0, "o");

        // Without the blocker the merged pair reaches what neither reaches alone only through evidence
        // both recorded for the same action.
        b.blockers.clear();
        b.harm = Harm::Low;
        b.evidence.push(ev(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            "refsnap",
        ));
        let out = decide(vec![a, b], &ctx);
        assert_eq!(band(&out[0]), Band::Safe);
    }

    #[test]
    fn merge_never_mixes_evidence_of_different_actions() {
        let deny = deny();
        let ctx = ctx(&deny);
        let target = key(r"HKLM\SOFTWARE\Vendor");
        let mut container = cand("v", target.clone(), "REG-SOFTWARE");
        container.action = Action::RemoveDirIfEmpty;
        container
            .evidence
            .push(ev(EvidenceKind::VendorContainer, Scope::Key, "vendor"));
        container.blockers.push(Blocker::OlderThanInstall);
        let mut product = cand("p", target, "REF-ANY");
        product
            .evidence
            .push(ev(EvidenceKind::AppNamedKeyWithRootRef, Scope::Key, "name"));
        for order in [
            vec![container.clone(), product.clone()],
            vec![product.clone(), container.clone()],
        ] {
            let first = order[0].id.clone();
            let out = decide(order, &ctx);
            assert_eq!(out.len(), 1);
            let m = &out[0];
            assert_eq!(m.id, first);
            assert_eq!(m.action, Action::DeleteKey);
            assert_eq!(m.evidence.len(), 1);
            assert_eq!(m.evidence[0].kind, EvidenceKind::AppNamedKeyWithRootRef);
            assert_eq!(m.decision.as_ref().unwrap().score, 7);
            assert_eq!(m.blockers, vec![Blocker::OlderThanInstall]);
        }
    }

    #[test]
    fn merge_takes_the_most_restrictive_fields() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut a = owned_path("a", r"C:\Users\tester\AppData\Roaming\App\data");
        a.size_bytes = Some(10);
        let mut b = owned_path("b", r"c:\users\TESTER\appdata\roaming\app\data\");
        b.category = Category::UserData;
        b.reversibility = Reversibility::Partial;
        b.origin = Origin::ProbeAgent;
        b.child_count = Some(3);
        b.children.push(purge_model::CandidateId("x".into()));
        let out = decide(vec![a, b], &ctx);
        assert_eq!(out.len(), 1);
        let m = &out[0];
        assert_eq!(m.category, Category::UserData);
        assert_eq!(m.reversibility, Reversibility::Partial);
        assert_eq!(m.origin, Origin::ProbeAgent);
        assert_eq!((m.size_bytes, m.child_count), (Some(10), Some(3)));
        assert_eq!(m.children.len(), 1);
        assert_ne!(band(m), Band::Safe);
        // Different owners never merge.
        let a = owned_path("a", r"C:\Program Files\App\a.dll");
        let mut b = a.clone();
        b.id = purge_model::CandidateId("b".into());
        b.owner.program_id =
            purge_model::ProgramId::machine(purge_model::View::K64, "Other").unwrap();
        assert_eq!(decide(vec![a, b], &ctx).len(), 2);
    }

    #[test]
    fn merge_drops_every_candidate_of_a_colliding_id() {
        let deny = deny();
        let ctx = ctx(&deny);
        // Two different targets, one id: neither can be selected by that id. Both go (M3-R1 M2).
        let a = cand(
            "c-0000000000000001",
            key(r"HKLM\SOFTWARE\A"),
            "REG-SOFTWARE",
        );
        let b = cand(
            "c-0000000000000001",
            key(r"HKLM\SOFTWARE\B"),
            "REG-SOFTWARE",
        );
        assert_eq!(
            colliding_ids(&[a.clone(), b.clone()], &ctx),
            BTreeSet::from([CandidateId("c-0000000000000001".into())])
        );
        assert!(merge(vec![a.clone(), b.clone()], &ctx).is_empty());
        // A second scanner on the same target is not a collision: it is the item it merges into.
        let same = cand("c-0000000000000001", key(r"HKLM\SOFTWARE\A"), "REF-ANY");
        assert!(colliding_ids(&[a.clone(), same.clone()], &ctx).is_empty());
        let out = merge(vec![a, same], &ctx);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id.0, "c-0000000000000001");
    }

    #[test]
    fn names_holding_control_characters_never_merge_two_targets() {
        let deny = deny();
        let ctx = ctx(&deny);
        // Joined with a separator character these two would read the same.
        let a = owned_value("a", "HKLM\\SOFTWARE\\Vendor\\K", "a\u{1f}b");
        let b = owned_value("b", "HKLM\\SOFTWARE\\Vendor\\K\u{1f}a", "b");
        assert_ne!(merge_key(&a, &ctx), merge_key(&b, &ctx));
        let out = merge(vec![a, b], &ctx);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c.evidence.len() == 1));
    }

    #[test]
    fn scanner_supplied_empty_after_plan_and_decisions_are_dropped() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut c = cand("v", path(r"C:\Program Files\Vendor"), "FS-VENDORPARENT");
        c.action = Action::RemoveDirIfEmpty;
        c.evidence
            .push(ev(EvidenceKind::VendorContainer, Scope::Path, "vendor"));
        c.evidence
            .push(ev(EvidenceKind::EmptyAfterPlan, Scope::Path, "forged"));
        c.decision = Some(purge_model::Decision {
            band: Band::Safe,
            preselected: true,
            score: 99,
            explanation: String::new(),
        });
        let c = one(c, &ctx);
        assert!(
            c.evidence
                .iter()
                .all(|e| e.kind != EvidenceKind::EmptyAfterPlan)
        );
        let d = c.decision.as_ref().unwrap();
        assert_eq!((d.band, d.preselected, d.score), (Band::Weak, false, 2));
    }

    #[test]
    fn mode_and_verify_gone_reach_the_policy() {
        let deny = deny();
        let mut ctx = ctx(&deny);
        ctx.mode = ScanMode::Forced;
        assert_eq!(
            band(&one(owned_key("k", r"HKLM\SOFTWARE\Vendor\App"), &ctx)),
            Band::Likely
        );
        ctx.mode = ScanMode::Post;
        // An inconsistent `passed` flag is not believed.
        ctx.verify_gone = VerifyGone {
            arp_gone: false,
            msi_unknown_all_ctx: true,
            main_exes_gone: true,
            passed: true,
        };
        let c = one(owned_key("k", r"HKLM\SOFTWARE\Vendor\App"), &ctx);
        let d = c.decision.as_ref().unwrap();
        assert_eq!((d.band, d.preselected), (Band::Likely, false));
    }
}
