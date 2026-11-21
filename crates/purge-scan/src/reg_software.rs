//! REG-SOFTWARE (ENGINE_PLAN.md §5.6): `Software[\WOW6432Node]\<Vendor>\<Product>` and
//! `Software[\WOW6432Node]\<Product>` keys and their values, in `HKLM` and `HKU\<SID>`.
//!
//! # What is offered
//!
//! **Product keys** (depth 1 and 2 below a `Software` base) as `DeleteKey`, when the key carries at
//! least one of:
//!
//! - `InstallerManifest(Inno)`: a key-create record of the uninstall log on exactly this key. A
//!   `RegDeleteKeyIfEmpty` record (which Inno scripts commonly put on shared vendor keys) that is the
//!   key's only Tier A evidence makes the candidate delete-if-empty instead of `DeleteKey`;
//! - `ProvenOwnedSkeleton`;
//! - `HarvestedToken`: a harvested token is a delimited part of the key's own name;
//! - `AppNamedKeyWithRootRef`: the key's name matches the app (full name, name token or
//!   `<VendorAlias>\<Product>`), a value in the key's subtree points into an InstallRoot now or did at
//!   harvest, nothing in the subtree refers to another app's anchors (the whole subtree was read), the
//!   key is not a structural container, not under `SOFTWARE\Microsoft` and not older than the install
//!   (when the install time is unknown that last test cannot be made and is skipped). A key that is
//!   also a vendor alias gets it only when its name is the app's full name (`ExactFullName`);
//!   otherwise it stays a delete-if-empty vendor container. One exception: a vendor-alias key whose
//!   name is the app's full name, and which no other installed app's name contains, is the product's
//!   own key (`Software\Notepad++`, `Software\7-Zip`). It is offered whole on its name like any
//!   product key, unticked, instead of as a container that its own values keep from ever being empty;
//! - a name match alone (`ExactFullName`, `ProductSubfolderOfVendor`, `NameTokenExact`), which never
//!   reaches Tier A and leaves the key Likely or Weak. `ProductSubfolderOfVendor` also holds for a key
//!   directly below a vendor key that is named like the app without its vendor ([`vendor_product`]):
//!   "Mozilla Maintenance Service" is `Mozilla\MaintenanceService`, although both of its words are
//!   generic ones that no token match is made on.
//!
//! Under `SOFTWARE\Microsoft` a key is offered only with `InstallerManifest` or `ProvenOwnedSkeleton`.
//!
//! **Vendor keys** (`Software\<VendorAlias>`, and a vendor-alias key directly below one, such as
//! `mozilla.org\Mozilla`) only as delete-if-empty containers with the pending `EmptyAfterPlan` marker
//! and the complete listing of their direct children. A vendor key the deny-list or the baseline
//! protects (`HKLM\SOFTWARE\Mozilla`) is not emitted at all; its product subkeys still are.
//!
//! **Values** in the subtree of a vendor or product key whose name or data points into an InstallRoot:
//! `DeleteValue` (or a segment edit for one entry of a list) with `PointsIntoInstallRoot`,
//! `InPreUninstallRefSnapshot` and `DanglingRef` as they apply. Value evidence never makes the key that
//! holds the value a candidate.
//!
//! # Vendor-name variants (`HKLM\SOFTWARE\mozilla.org`)
//!
//! A vendor often names its key after its domain: the vendor is `Mozilla`, the key `mozilla.org`. A
//! key whose name is a vendor alias followed by one or two domain labels (`.org`, `.com`, `.co.uk`;
//! compared without regard to case) is treated as a vendor key of that alias ([`vendor_variant`]).
//! The name gives it exactly what a vendor key gets and no more: the delete-if-empty container offer
//! with the pending marker, which acts only if the plan empties the key. It is never offered whole on
//! its name. Anything stronger must come from the key's content, by the rules above: a value in its
//! subtree that points into an InstallRoot is offered as a value, and a key-create record of the
//! installer or a fully attributed subtree baseline on the key makes it a product key.
//!
//! Firefox leaves `mozilla.org\Mozilla` with one version value and no reference to the app, and its
//! NSIS uninstaller has no log, so no Tier A evidence exists for it. Its evidence is `VendorContainer`
//! once, for its name, plus `TimeWindow` when its last write lies in the session's window: 2 + 1 = 3,
//! Weak. The name is not counted a second time for the subkey `Mozilla` being a vendor alias too: that
//! is the same observation, and two of them made the key Likely on a name. The offer turns Safe only
//! if the plan empties the key; while `Mozilla` holds a value that nothing claims, the plan cannot,
//! and purge-plan leaves both containers out (`empty_after::unemptiable`).
//!
//! # Co-removed products
//!
//! The scan runs once for the app and once for every co-removed product that was pre-harvested
//! (`Fingerprint::co_removed`), each with its own fingerprint, so `Mozilla\MaintenanceService` is
//! attributed through the Maintenance Service's own roots and names. [`common::for_each_app`] does this
//! for the other registry scanners of this package too. A co-removed product was harvested before the
//! uninstaller ran, so its fingerprint carries no session window; the pass uses the window of the
//! uninstall that removed it, which is the app's.

use std::collections::HashSet;

use purge_guard::containers;
use purge_guard::deny::{DenyList, Exemptions};
use purge_guard::prefix;
use purge_identity::identity::IdentityMatch;
use purge_identity::kbdata::Kb;
use purge_identity::matcher::SHORT_NAME_MAX_CHARS;
use purge_identity::tokenizer::full_name_key;
use purge_model::{
    Action, AnchorKind, Blocker, Candidate, CandidateId, Category, EvidenceKind, InnoRecordKind,
    Target,
};

use crate::framework::{AppIdentityView, ContainerChild, RootSpec, ScanCtx, Scanner};

use self::common::{Foreign, KeyWalk};

/// The scanner's catalog id.
pub const ID: &str = "REG-SOFTWARE";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(r"*\SOFTWARE", Some(2))];

/// Direct children of a `Software` base that are not vendor or product keys: the Classes root (the CLS
/// scanners' ground) and the 32-bit view, which is a base of its own.
const NOT_VENDORS: [&str; 2] = ["Classes", "WOW6432Node"];

/// One day in `FILETIME` ticks: the slack of the "not older than the install" test.
const DAY_TICKS: u64 = 24 * 60 * 60 * 10_000_000;

/// The REG-SOFTWARE scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegSoftware;

impl Scanner for RegSoftware {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        common::for_each_app(ctx, app, |ctx, app| scan_app(ctx, app, &mut out));
        common::dedupe(out)
    }
}

/// What looking at one key came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Nothing attributes the key, or it was not emitted.
    Nothing,
    /// Emitted on a name match only.
    Named,
    /// Emitted with Tier A key evidence.
    Owned,
}

/// The state of one app's scan.
struct Pass<'s, 'a> {
    ctx: &'s ScanCtx<'a>,
    app: &'s AppIdentityView,
    deny: DenyList,
    foreign: Foreign,
    /// Folded paths of the keys the fingerprint has a key-level record for: Inno key-create records
    /// and fully attributed subtree baselines.
    recorded: HashSet<String>,
}

fn scan_app(ctx: &ScanCtx<'_>, app: &AppIdentityView, out: &mut Vec<Candidate>) {
    let pass = Pass {
        ctx,
        app,
        deny: DenyList::compile(ctx.guard),
        foreign: Foreign::new(ctx),
        recorded: recorded_keys(ctx),
    };
    let most = ctx.limits.max_key_children;
    for base in common::software_bases(ctx) {
        let Ok(level1) = ctx.reg.subkeys(&base) else {
            continue;
        };
        for vendor in level1.iter().take(most) {
            if NOT_VENDORS.iter().any(|n| prefix::eq_ci(n, vendor)) {
                continue;
            }
            let key1 = format!(r"{base}\{vendor}");
            let microsoft = prefix::eq_ci(vendor, "Microsoft");
            let vendor_match = if microsoft {
                None
            } else {
                vendor_alias(app, vendor)
            };
            if !microsoft {
                // A key that is both a vendor alias and app-named goes whole only with Tier A
                // evidence, or, on its name, when that name is the product's own
                // (`Pass::product_named`); otherwise it is a vendor container.
                let emit_named = vendor_match.is_none() || pass.product_named(vendor);
                let outcome = pass.product_key(&key1, vendor, None, false, emit_named, out);
                if let Some(m) = &vendor_match {
                    if outcome == Outcome::Nothing {
                        pass.vendor_container(&key1, m, out);
                    }
                    let walk = common::walk(ctx, &key1);
                    pass.offer_values(&walk, out);
                }
            }
            let Ok(level2) = ctx.reg.subkeys(&key1) else {
                continue;
            };
            for product in level2.iter().take(most) {
                let key2 = format!(r"{key1}\{product}");
                let alias = vendor_match
                    .as_ref()
                    .and_then(|_| vendor_alias(app, product));
                let outcome = pass.product_key(
                    &key2,
                    product,
                    Some(vendor),
                    microsoft,
                    alias.is_none(),
                    out,
                );
                if let (Some(m), true) = (&alias, outcome != Outcome::Owned) {
                    pass.vendor_container(&key2, m, out);
                }
            }
        }
    }
}

/// The shortest and longest label that is taken for a part of a domain suffix (`io`, `com`, `museum`).
const DOMAIN_LABEL_LEN: std::ops::RangeInclusive<usize> = 2..=6;

/// The most labels a domain suffix has (`.co.uk`).
const DOMAIN_LABELS_MAX: usize = 2;

/// The vendor alias `name` is a domain-style variant of: `name` without its last one or two labels
/// is a vendor alias of the app (`mozilla.org` for the vendor `Mozilla`), compared as the identity
/// compares vendors, without regard to case. The match is reported under the key's own name, since
/// that is what was found.
///
/// This is a statement about the name only. Like every vendor match it supports a delete-if-empty
/// container offer and nothing else.
fn vendor_variant(app: &AppIdentityView, name: &str) -> Option<IdentityMatch> {
    let name = name.trim();
    let mut stem = name;
    for _ in 0..DOMAIN_LABELS_MAX {
        let (head, label) = stem.rsplit_once('.')?;
        let is_label = DOMAIN_LABEL_LEN.contains(&label.len())
            && label.chars().all(|c| c.is_ascii_alphabetic());
        if !is_label || head.is_empty() || head.ends_with(|c: char| c == '.' || c.is_whitespace()) {
            return None;
        }
        stem = head;
        if let Some(mut m) = app.identity.matches_vendor(stem) {
            m.matched = prefix::fold(name);
            return Some(m);
        }
    }
    None
}

/// The vendor match of a key name: a vendor alias itself, or a domain-style variant of one.
fn vendor_alias(app: &AppIdentityView, name: &str) -> Option<IdentityMatch> {
    app.identity
        .matches_vendor(name)
        .or_else(|| vendor_variant(app, name))
}

/// `<VendorAlias>\<Product>` where the product is one of the app's names without the vendor in front:
/// below the vendor's own key the vendor's name is not repeated, so "Mozilla Maintenance Service" is
/// `Mozilla\MaintenanceService`. The key's name must be that whole remainder (compared by full-name
/// keys, without regard to case or spacing), longer than a short name, and not one generic word
/// (`Update`, `Service`). Nothing is matched for a mega-vendor, whose key is everybody's.
///
/// This is `ProductSubfolderOfVendor`: name evidence, which never reaches Tier A by itself.
fn vendor_product(app: &AppIdentityView, parent: &str, leaf: &str) -> Option<IdentityMatch> {
    let identity = &app.identity;
    if identity.mega_vendor() || leaf.contains(prefix::SEP) {
        return None;
    }
    let vendor = vendor_alias(app, parent)?;
    let leaf_key = full_name_key(leaf).replace(' ', "");
    if leaf_key.chars().count() <= SHORT_NAME_MAX_CHARS {
        return None;
    }
    let generic = &Kb::shipped().generic;
    let aliases = identity.vendor_aliases();
    let name = identity.names().iter().find(|name| {
        let key = full_name_key(name);
        aliases.iter().any(|alias| {
            let Some(product) = key
                .strip_prefix(alias.as_str())
                .and_then(|rest| rest.strip_prefix(' '))
            else {
                return false;
            };
            let one_generic_word = !product.contains(' ') && generic.contains(product);
            !one_generic_word && product.replace(' ', "") == leaf_key
        })
    })?;
    let kind = EvidenceKind::ProductSubfolderOfVendor;
    Some(IdentityMatch {
        kind,
        tier: kind.default_tier(),
        weight: kind.default_weight(),
        needs_tier_ab_neighbour: false,
        matched: name.clone(),
        distance: vendor.distance,
    })
}

/// The keys the fingerprint holds a key-level record for, folded.
fn recorded_keys(ctx: &ScanCtx<'_>) -> HashSet<String> {
    let inno = ctx
        .fp
        .inno
        .iter()
        .filter(|r| r.key_create)
        .filter_map(|r| match &r.target {
            Target::RegKey { path } => Some(path.as_str()),
            _ => None,
        });
    let subtrees = ctx
        .fp
        .subtrees
        .iter()
        .filter(|s| s.fully_attributed)
        .map(|s| s.key.as_str());
    inno.chain(subtrees)
        .map(|key| prefix::fold(key.trim_end_matches(prefix::SEP)))
        .collect()
}

impl Pass<'_, '_> {
    /// Whether a key directly below `Software` that is a vendor alias is named after the product
    /// itself: `Software\Notepad++` of Notepad++, `Software\7-Zip` of 7-Zip. Vendor and product
    /// carry one name, so the key is the product's settings key, not a vendor's namespace for several
    /// products, and it is judged like any other product key: offered whole on the evidence it has
    /// (its name alone never reaches Tier A, so it is listed unticked).
    ///
    /// It needs the key's name to be the app's full name (every word, versions and architecture tags
    /// aside), and no other installed app to carry that name in its own: with "Notepad++ Plugin
    /// Manager" installed the key may be shared, and it stays a delete-if-empty vendor container.
    fn product_named(&self, leaf: &str) -> bool {
        if self.app.identity.matches_full_name(leaf).is_none() {
            return false;
        }
        let name = format!(" {} ", full_name_key(leaf));
        !self
            .ctx
            .other_apps
            .apps()
            .iter()
            .any(|other| format!(" {} ", full_name_key(&other.name)).contains(&name))
    }

    /// Looks at one key of depth 1 (`parent` is `None`) or 2 as a product key and emits it when
    /// something attributes it. A key with name evidence only is emitted when `emit_named` is set.
    fn product_key(
        &self,
        key: &str,
        leaf: &str,
        parent: Option<&str>,
        microsoft: bool,
        emit_named: bool,
        out: &mut Vec<Candidate>,
    ) -> Outcome {
        let ctx = self.ctx;
        let fp = ctx.fp;
        let identity = &self.app.identity;
        let recorded = self.recorded.contains(&prefix::fold(key));
        let (tokens, names): (Vec<&str>, Vec<IdentityMatch>) = if microsoft {
            (Vec::new(), Vec::new())
        } else {
            let folded = prefix::fold(leaf);
            let tokens = fp
                .tokens
                .iter()
                .map(|t| t.token.as_str())
                .filter(|t| !t.is_empty() && folded.contains(&prefix::fold(t)))
                .collect();
            let names = [
                identity.matches_full_name(leaf),
                parent.and_then(|p| {
                    identity
                        .matches_product_subfolder(p, leaf)
                        .or_else(|| vendor_product(self.app, p, leaf))
                }),
                identity.matches_name(leaf),
            ]
            .into_iter()
            .flatten()
            .collect();
            (tokens, names)
        };
        if !recorded && tokens.is_empty() && names.is_empty() {
            return Outcome::Nothing;
        }
        if containers::is_value_container(key, ctx.guard) {
            return Outcome::Nothing;
        }
        let Ok(info) = ctx.reg.key_info(key) else {
            return Outcome::Nothing;
        };
        let walk = common::walk(ctx, key);
        let foreign = self.foreign.in_walk(&self.app.refs, &walk);
        let older = !names.is_empty()
            && fp.window.install_time.is_some_and(|install| {
                info.lwt.0 != 0 && info.lwt.0 < install.0.saturating_sub(DAY_TICKS)
            });
        // A key that is a vendor alias as well (`emit_named` is unset for it) may hold products that
        // are not installed apps of their own and so are invisible to the foreign-reference test. A
        // token match is not enough to take it whole: its name must be the app's full name.
        let named_enough =
            emit_named || names.iter().any(|m| m.kind == EvidenceKind::ExactFullName);
        let root_ref =
            if names.is_empty() || !named_enough || foreign.is_some() || older || !walk.complete {
                None
            } else {
                self.root_ref(key, &walk)
            };
        // A `RegDeleteKeyIfEmpty` record says the installer wanted the key gone once it is empty, no
        // more: alone it supports a delete-if-empty offer only.
        let only_if_empty = {
            let mut records = fp.inno.iter().filter(|r| {
                r.key_create
                    && !r.existed_before
                    && !r.shared
                    && matches!(&r.target, Target::RegKey { path } if ctx.same_key(path, key))
            });
            let mut any = false;
            let all = records.all(|r| {
                any = true;
                r.kind == InnoRecordKind::RegDeleteKeyIfEmpty
            });
            any && all
        };

        let build = |action: Action| {
            let mut b = ctx.candidate(
                ID,
                Target::RegKey {
                    path: key.to_owned(),
                },
                action,
                Category::Registration,
            );
            let manifest = b.installer_manifest();
            let mut owned = b.proven_owned_skeleton();
            for token in &tokens {
                owned |= b.harvested_token(token);
            }
            if let Some(path) = &root_ref {
                owned |= b.app_named_key_with_root_ref(path);
            }
            let mut named = false;
            for m in &names {
                named |= b.name_match(m);
            }
            if info.lwt.0 != 0 {
                b.time_window(info.lwt);
            }
            if let Some(app) = &foreign {
                b.blocker(Blocker::ReferencedByOtherApp { app: app.clone() });
            }
            if older {
                b.blocker(Blocker::OlderThanInstall);
            }
            b.child_count(walk.count());
            b.common_blockers();
            (b, manifest, owned, named)
        };
        let (mut b, manifest, owned, named) = build(Action::DeleteKey);
        if manifest && only_if_empty && !owned {
            b = build(Action::RemoveDirIfEmpty).0;
        }
        let outcome = if manifest || owned {
            Outcome::Owned
        } else if named && emit_named {
            Outcome::Named
        } else {
            return Outcome::Nothing;
        };
        if !microsoft {
            for id in self.offer_values(&walk, out) {
                b.child(id);
            }
        }
        out.push(b.build());
        outcome
    }

    /// A path into an InstallRoot that a value of the key's subtree names now, or named at harvest.
    fn root_ref(&self, key: &str, walk: &KeyWalk) -> Option<String> {
        let ctx = self.ctx;
        let live = walk.values.iter().find_map(|(_, value)| {
            common::value_matches(&self.app.refs, value)
                .into_iter()
                .filter(|m| !m.name_only)
                .filter_map(|m| m.path)
                .find(|path| ctx.inside_install_root(path).is_some())
        });
        live.or_else(|| {
            ctx.fp.ref_snapshot.iter().find_map(|entry| {
                let at = match &entry.target {
                    Target::RegValue { path, .. } | Target::RegMultiSzSegment { path, .. } => path,
                    _ => return None,
                };
                let below = matches!(
                    ctx.key_relation(at, key),
                    prefix::Relation::Same | prefix::Relation::Inside
                );
                let into_root = matches!(entry.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
                    && ctx.inside_install_root(&entry.anchor.text).is_some();
                (below && into_root).then(|| entry.anchor.text.clone())
            })
        })
    }

    /// Offers every value of the walk that refers to the app; returns the ids of what was emitted.
    fn offer_values(&self, walk: &KeyWalk, out: &mut Vec<Candidate>) -> Vec<CandidateId> {
        let mut ids = Vec::new();
        for (key, value) in &walk.values {
            ids.extend(common::offer_value(
                self.ctx,
                self.app,
                &self.foreign,
                ID,
                key,
                value,
                Category::Registration,
                out,
            ));
        }
        ids
    }

    /// Emits a vendor key as a delete-if-empty container with the pending marker. Nothing is emitted
    /// for a structural container, a key of the baseline, a key the deny-list protects, a key that
    /// holds another app's own key, or a key whose children could not all be listed.
    fn vendor_container(&self, key: &str, m: &IdentityMatch, out: &mut Vec<Candidate>) {
        let ctx = self.ctx;
        let target = Target::RegKey {
            path: key.to_owned(),
        };
        // Another app's own key inside it means it can never become empty.
        let holds_other_app = ctx
            .other_apps
            .apps()
            .iter()
            .flat_map(|app| &app.keys)
            .any(|other| {
                matches!(
                    ctx.key_relation(other, key),
                    prefix::Relation::Same | prefix::Relation::Inside
                )
            });
        // The exact-view query, not `ctx.in_baseline`: a vendor key directly under
        // `HKLM\SOFTWARE\WOW6432Node` is a separate key from its 64-bit namesake, so clean Windows having
        // `HKLM\SOFTWARE\<Vendor>` says nothing about it. Classes and shared keys stay folded there.
        let in_baseline = ctx.baseline.has_key_exact_view(key);
        if holds_other_app
            || containers::is_value_container(key, ctx.guard)
            || in_baseline
            || self.deny.check(&target, &Exemptions::default()).is_some()
        {
            return;
        }
        let (Ok(info), Ok(subkeys), Ok(values)) = (
            ctx.reg.key_info(key),
            ctx.reg.subkeys(key),
            ctx.reg.values(key),
        ) else {
            return;
        };
        let count = subkeys.len() + values.len();
        if info.is_link || count > ctx.limits.max_key_children {
            return;
        }
        let mut b = ctx.candidate(ID, target, Action::RemoveDirIfEmpty, Category::Registration);
        let children = values
            .iter()
            .map(|v| ContainerChild::Leaf(&v.name))
            .chain(subkeys.iter().map(|s| ContainerChild::Container(s)));
        if !b.vendor_container_pending(m, children) {
            return;
        }
        // The name is the only thing this offer rests on, and it counts once. That every subkey is
        // again named after the vendor is the same observation made one level down, not a second
        // source: counted twice it lifted `mozilla.org` to Likely on its name alone.
        if info.lwt.0 != 0 {
            b.time_window(info.lwt);
        }
        b.child_count(u32::try_from(count).unwrap_or(u32::MAX));
        // `common_blockers` without its view-folding baseline blocker: the exact-view check above
        // stands in for it.
        b.owner_blockers()
            .existed_before_blocker()
            .other_app_blockers();
        out.push(b.build());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use purge_model::{CoRemovedProduct, FileTime, Fingerprint, IdentitySnapshot, TimeWindow};
    use purge_source::fixture::Fixture;

    use super::*;
    use crate::framework::testkit::{self, World};

    const ROOT: &str = r"C:\Program Files\Zorblat Player";
    const SERVICE_ROOT: &str = r"C:\Program Files (x86)\Zorblat Update Service";
    const INSTALL: u64 = 1_000_000_000_000;
    const IN_WINDOW: u64 = 1_000_100_000_000;

    fn identity(names: &[&str]) -> IdentitySnapshot {
        IdentitySnapshot {
            names: names.iter().map(|s| (*s).to_owned()).collect(),
            vendors: vec!["Zorblat".into()],
            tokens: Vec::new(),
            mega_vendor: false,
        }
    }

    /// "Zorblat Player" by the vendor "Zorblat", uninstalled in a session with a full window.
    fn player() -> Fingerprint {
        let mut fp = testkit::fingerprint();
        fp.app.display_name = "Zorblat Player".into();
        fp.identity = identity(&["Zorblat Player", "Player"]);
        fp.roots[0].path = ROOT.into();
        fp.window = TimeWindow {
            install_time: Some(FileTime(INSTALL)),
            t_start: Some(FileTime(INSTALL + 500_000_000)),
            t_end: Some(FileTime(INSTALL + 600_000_000)),
        };
        fp
    }

    /// The vendor's update service as harvested before the uninstall: no session window of its own.
    fn service() -> Fingerprint {
        let mut fp = testkit::fingerprint();
        fp.app.display_name = "Zorblat Update Service".into();
        fp.identity = identity(&["Zorblat Update Service", "ZorblatUpdateService"]);
        fp.roots[0].path = SERVICE_ROOT.into();
        fp.window.install_time = Some(FileTime(INSTALL));
        fp
    }

    fn scan(fixture: Fixture, fp: Fingerprint) -> Vec<Candidate> {
        let mut world = World::new(fixture);
        world.fp = fp;
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        RegSoftware.scan(&world.ctx(), &app)
    }

    fn on_key<'c>(found: &'c [Candidate], path: &str) -> Option<&'c Candidate> {
        found
            .iter()
            .find(|c| matches!(&c.target, Target::RegKey { path: p } if prefix::eq_ci(p, path)))
    }

    fn kinds(c: &Candidate) -> Vec<EvidenceKind> {
        c.evidence.iter().map(|e| e.kind).collect()
    }

    #[test]
    fn a_vendor_alias_with_a_domain_suffix_is_a_vendor_variant() {
        let fp = player();
        let app = AppIdentityView::from_fingerprint(&fp, &BTreeMap::new());
        for name in [
            "zorblat.org",
            "ZORBLAT.COM",
            "Zorblat.co.uk",
            " zorblat.io ",
        ] {
            let m = vendor_variant(&app, name).unwrap_or_else(|| panic!("{name} is a variant"));
            assert_eq!(m.kind, EvidenceKind::VendorContainer, "{name}");
            assert_eq!(m.matched, prefix::fold(name.trim()), "{name}");
            assert!(vendor_alias(&app, name).is_some(), "{name}");
        }
        for name in [
            // The alias itself is not a variant of itself.
            "Zorblat",
            // Another vendor's domain, and a longer or shorter word that only starts alike.
            "other.org",
            "zorblatt.org",
            "zorbla.org",
            "notzorblat.org",
            // Not a domain suffix: digits, one letter, a long word, an empty label, three labels.
            "zorblat.2",
            "zorblat.x",
            "zorblat.organization",
            "zorblat..org",
            "zorblat .org",
            "zorblat.a.co.uk",
            ".org",
            "org",
            "",
        ] {
            assert_eq!(vendor_variant(&app, name), None, "{name:?}");
        }
        assert!(vendor_alias(&app, "Zorblat").is_some());
        assert!(vendor_alias(&app, "other.org").is_none());
    }

    #[test]
    fn a_product_key_below_the_vendor_key_is_named_without_the_vendor() {
        let view = |fp: &Fingerprint| AppIdentityView::from_fingerprint(fp, &BTreeMap::new());
        let app = view(&service());
        for (parent, leaf) in [
            ("Zorblat", "UpdateService"),
            ("zorblat", "update service"),
            ("Zorblat", "Update Service"),
            ("zorblat.org", "UpdateService"),
        ] {
            let m = vendor_product(&app, parent, leaf)
                .unwrap_or_else(|| panic!(r"{parent}\{leaf} is the service's"));
            assert_eq!(m.kind, EvidenceKind::ProductSubfolderOfVendor);
            assert_eq!(m.matched, "Zorblat Update Service");
            assert!(!m.needs_tier_ab_neighbour);
        }
        for (parent, leaf) in [
            // Not below a vendor key.
            ("Other", "UpdateService"),
            ("Software", "UpdateService"),
            // Part of the name, more than the name, or the name with the vendor.
            ("Zorblat", "Update"),
            ("Zorblat", "Service"),
            ("Zorblat", "UpdateServiceHelper"),
            ("Zorblat", "Zorblat Update Service"),
            ("Zorblat", ""),
        ] {
            assert_eq!(vendor_product(&app, parent, leaf), None, r"{parent}\{leaf}");
        }

        // One generic word is nobody's name, and a short one is not matched either.
        let mut fp = service();
        fp.identity = identity(&["Zorblat Update", "Zorblat Hub"]);
        let app = view(&fp);
        assert_eq!(vendor_product(&app, "Zorblat", "Update"), None);
        assert_eq!(vendor_product(&app, "Zorblat", "Hub"), None);
        // A mega-vendor's key is everybody's.
        let mut fp = service();
        fp.identity.mega_vendor = true;
        assert_eq!(vendor_product(&view(&fp), "Zorblat", "UpdateService"), None);
    }

    #[test]
    fn a_vendor_variant_key_is_only_a_delete_if_empty_container_on_its_name() {
        let fixture = Fixture::builder()
            .sz(
                r"HKLM\SOFTWARE\zorblat.org\Zorblat",
                "CurrentVersion",
                "1.0",
            )
            .key_lwt(r"HKLM\SOFTWARE\zorblat.org", IN_WINDOW)
            .sz(
                r"HKLM\SOFTWARE\zorblatt.org\Zorblat",
                "CurrentVersion",
                "1.0",
            )
            .sz(r"HKLM\SOFTWARE\other.org\Thing", "CurrentVersion", "1.0")
            .build();
        let found = scan(fixture, player());

        let org = on_key(&found, r"HKLM\SOFTWARE\zorblat.org").expect("the variant key is listed");
        assert_eq!(org.action, Action::RemoveDirIfEmpty);
        // Its name, once, and the window: no Tier A, and the pending marker with the full listing,
        // so the plan decides by emptiness.
        assert_eq!(
            kinds(org),
            vec![EvidenceKind::VendorContainer, EvidenceKind::TimeWindow]
        );
        assert_eq!(
            org.evidence[0].detail.get("empty_after_plan"),
            Some("pending")
        );
        assert_eq!(
            org.evidence[0].detail.get("children"),
            Some(r#"["Zorblat\\"]"#)
        );
        // Nothing else is offered: not the version value, and no key of a name that is not a variant.
        assert!(
            found.iter().all(|c| c.action == Action::RemoveDirIfEmpty),
            "{found:#?}"
        );
        assert!(on_key(&found, r"HKLM\SOFTWARE\zorblatt.org").is_none());
        assert!(on_key(&found, r"HKLM\SOFTWARE\zorblatt.org\Zorblat").is_none());
        assert!(on_key(&found, r"HKLM\SOFTWARE\other.org").is_none());
    }

    /// The exact-view baseline check of a vendor container: only a vendor key below the 32-bit view
    /// root of the machine is judged apart from its 64-bit namesake. A key the baseline records under
    /// its own spelling is never offered, in either view, and what is offered is delete-if-empty with
    /// the pending marker and nothing stronger.
    #[test]
    fn a_vendor_container_is_withheld_by_the_baseline_of_its_own_view() {
        const K64: &str = r"HKLM\SOFTWARE\Zorblat";
        const K32: &str = r"HKLM\SOFTWARE\WOW6432Node\Zorblat";
        const ORG64: &str = r"HKLM\SOFTWARE\zorblat.org\Zorblat";
        const ORG32: &str = r"HKLM\SOFTWARE\WOW6432Node\zorblat.org\Zorblat";
        let fixture = || {
            let mut b = Fixture::builder();
            for key in [K64, K32, ORG64, ORG32] {
                b = b.sz(&format!(r"{key}\Settings"), "Language", "en");
            }
            b.build()
        };
        let scan_with = |keys: &[&str]| {
            let mut world = World::new(fixture());
            world.fp = player();
            world.baseline = Some(testkit::baseline(testkit::EDITION, keys));
            let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
            RegSoftware.scan(&world.ctx(), &app)
        };
        let offered = |found: &[Candidate], key: &str| {
            let Some(c) = on_key(found, key) else {
                return false;
            };
            // Whatever is offered here is a delete-if-empty container that waits for the plan.
            assert_eq!(c.action, Action::RemoveDirIfEmpty, "{key}");
            assert_eq!(
                c.evidence[0].detail.get("empty_after_plan"),
                Some("pending"),
                "{key}"
            );
            assert_eq!(
                c.evidence[0].detail.get("children"),
                Some(r#"["Settings\\"]"#),
                "{key}"
            );
            assert!(c.blockers.is_empty(), "{key}: {:?}", c.blockers);
            true
        };

        // The 64-bit keys are Windows' own: they stay out, their 32-bit namesakes do not.
        let found = scan_with(&[K64, ORG64, r"HKLM\SOFTWARE\zorblat.org"]);
        assert!(!offered(&found, K64));
        assert!(!offered(&found, ORG64));
        assert!(on_key(&found, r"HKLM\SOFTWARE\zorblat.org").is_none());
        assert!(offered(&found, K32));
        assert!(offered(&found, ORG32));
        // Nothing but containers comes of it: no key is offered whole, no value at all.
        assert!(
            found.iter().all(|c| c.action == Action::RemoveDirIfEmpty),
            "{found:#?}"
        );

        // The 32-bit keys are Windows' own: they stay out, and the twin rule never runs backwards.
        let found = scan_with(&[K32, ORG32]);
        assert!(!offered(&found, K32));
        assert!(!offered(&found, ORG32));
        assert!(offered(&found, K64));
        assert!(offered(&found, ORG64));

        // Both views recorded: nothing.
        let found = scan_with(&[K64, K32, ORG64, ORG32]);
        for key in [K64, K32, ORG64, ORG32] {
            assert!(!offered(&found, key), "{key}");
        }
    }

    #[test]
    fn a_vendor_variant_key_yields_its_values_that_point_into_the_root() {
        let exe = format!(r"{ROOT}\player.exe");
        let fixture = Fixture::builder()
            .sz(r"HKLM\SOFTWARE\zorblat.com\Settings", "Program", &exe)
            .sz(r"HKLM\SOFTWARE\zorblat.com\Settings", "Language", "en")
            .build();
        let found = scan(fixture, player());

        let value = found
            .iter()
            .find(|c| matches!(&c.target, Target::RegValue { name, .. } if name == "Program"))
            .expect("the value that names the root is offered");
        assert_eq!(value.action, Action::DeleteValue);
        assert!(kinds(value).contains(&EvidenceKind::PointsIntoInstallRoot));
        // The reference makes the value the app's, not the key: the key stays a container offer.
        let vendor = on_key(&found, r"HKLM\SOFTWARE\zorblat.com").expect("the variant key");
        assert_eq!(vendor.action, Action::RemoveDirIfEmpty);
        assert_eq!(kinds(vendor), vec![EvidenceKind::VendorContainer]);
        assert!(on_key(&found, r"HKLM\SOFTWARE\zorblat.com\Settings").is_none());
        assert!(
            !found
                .iter()
                .any(|c| matches!(&c.target, Target::RegValue { name, .. } if name == "Language"))
        );
    }

    #[test]
    fn a_co_removed_product_is_scanned_with_its_own_identity_in_the_apps_window() {
        let key = r"HKLM\SOFTWARE\Zorblat\UpdateService";
        let fixture = || {
            Fixture::builder()
                .dword(key, "Attempted", 1)
                .key_lwt(key, IN_WINDOW)
                .build()
        };
        // The app's own identity does not name the service's key.
        assert!(on_key(&scan(fixture(), player()), key).is_none());

        let mut fp = player();
        fp.co_removed = vec![CoRemovedProduct {
            app: service().app,
            fingerprint: Some(Box::new(service())),
        }];
        let found = scan(fixture(), fp.clone());
        let leftover = on_key(&found, key).expect("the service's key is listed");
        assert_eq!(leftover.owner.display_name, "Zorblat Update Service");
        assert_eq!(leftover.action, Action::DeleteKey);
        // Its name under the vendor key, and the window of the uninstall that removed it.
        assert!(kinds(leftover).contains(&EvidenceKind::ProductSubfolderOfVendor));
        assert!(kinds(leftover).contains(&EvidenceKind::TimeWindow));
        assert!(!kinds(leftover).contains(&EvidenceKind::AppNamedKeyWithRootRef));

        // A product that was not pre-harvested cannot be attributed.
        fp.co_removed[0].fingerprint = None;
        assert!(on_key(&scan(fixture(), fp), key).is_none());
    }

    /// The app's verify-gone result gates the Safe band but says nothing about a co-removed product:
    /// one whose main exe or Uninstall key is still there gets no pass, so nothing that points into
    /// its directory is offered.
    #[test]
    fn a_co_removed_product_that_is_not_gone_is_not_scanned() {
        let key = r"HKLM\SOFTWARE\Zorblat\UpdateService";
        let exe = format!(r"{SERVICE_ROOT}\updateservice.exe");
        let arp = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZorblatUpdateService";
        let harvested = || {
            let mut fp = service();
            fp.app.program_id =
                purge_model::ProgramId::machine(purge_model::View::K64, "ZorblatUpdateService")
                    .unwrap();
            fp.exes = vec![purge_model::ExeFile {
                path: exe.clone(),
                main: true,
            }];
            fp
        };
        let with = |fixture: Fixture| {
            let mut fp = player();
            fp.co_removed = vec![CoRemovedProduct {
                app: harvested().app,
                fingerprint: Some(Box::new(harvested())),
            }];
            scan(fixture, fp)
        };
        let leftovers = || {
            Fixture::builder()
                .sz(key, "Path", &exe)
                .key_lwt(key, IN_WINDOW)
        };
        let of_service = |found: &[Candidate]| {
            found
                .iter()
                .filter(|c| c.owner.display_name == "Zorblat Update Service")
                .count()
        };

        // Gone: the key that names its directory is the service's, and so is the value.
        let found = with(leftovers().build());
        assert_eq!(of_service(&found), 2, "{found:#?}");
        let whole = on_key(&found, key).expect("the service's key");
        assert!(kinds(whole).contains(&EvidenceKind::AppNamedKeyWithRootRef));

        // Its main exe is still there.
        let found = with(leftovers().file(&exe, 250_000).build());
        assert_eq!(of_service(&found), 0, "{found:#?}");
        assert!(on_key(&found, key).is_none());
        // Its Uninstall key is back (or never went).
        let found = with(
            leftovers()
                .sz(arp, "DisplayName", "Zorblat Update Service")
                .build(),
        );
        assert_eq!(of_service(&found), 0, "{found:#?}");
        assert!(on_key(&found, key).is_none());
    }
}

/// What the registry scanners of this package share: where they look, how a value is tested against the
/// app's anchors and against other apps', and how a referencing value becomes a candidate.
pub(crate) mod common {
    use std::collections::{BTreeMap, HashSet};

    use purge_guard::prefix;
    use purge_index::matcher::{AnchorSet, RefMatch, RefMatcher};
    use purge_model::{
        Action, AnchorKind, Blocker, Candidate, CandidateId, Category, Fingerprint, Target,
    };
    use purge_source::types::{BINARY_UTF16_SCAN_MAX, RegValue};

    use crate::framework::{AppIdentityView, CandidateBuilder, EntryStanding, ScanCtx};

    /// `Microsoft\Windows\CurrentVersion`, below a `Software` base.
    pub(crate) const CURRENT_VERSION: &str = r"Microsoft\Windows\CurrentVersion";

    /// Runs `f` for the app of the context and then for every co-removed product that has a
    /// fingerprint of its own, with that fingerprint as the context's.
    ///
    /// A co-removed product was harvested before the uninstaller ran and has no session of its own:
    /// it went in the app's uninstall, so the start and end of that uninstall are its window's too.
    /// Its install time stays its own.
    ///
    /// The Safe band is gated by the verify-gone result of the app, which says nothing about the
    /// co-removed product. So its pass runs only when the product is positively gone now
    /// ([`co_product_gone`]): otherwise references into its still-present directory would be banded
    /// as if it had been verified gone.
    pub(crate) fn for_each_app(
        ctx: &ScanCtx<'_>,
        app: &AppIdentityView,
        mut f: impl FnMut(&ScanCtx<'_>, &AppIdentityView),
    ) {
        f(ctx, app);
        for product in &ctx.fp.co_removed {
            if let Some(harvested) = product.fingerprint.as_deref() {
                if !co_product_gone(ctx, harvested) {
                    continue;
                }
                let mut fp = harvested.clone();
                fp.window.t_start = fp.window.t_start.or(ctx.fp.window.t_start);
                fp.window.t_end = fp.window.t_end.or(ctx.fp.window.t_end);
                let fp = &fp;
                let sub = ScanCtx { fp, ..*ctx };
                let view = AppIdentityView::from_fingerprint(fp, ctx.env);
                f(&sub, &view);
            }
        }
    }

    /// Whether a co-removed product is positively gone, by the parts of verify-gone a scan can
    /// establish (ENGINE_PLAN.md §4.4): its Uninstall key is absent and so is every main exe of its
    /// fingerprint. "Unknown" (access denied, not captured) is not gone.
    pub(crate) fn co_product_gone(ctx: &ScanCtx<'_>, harvested: &Fingerprint) -> bool {
        ctx.reg
            .key_exists(&harvested.app.program_id.key_path())
            .is_absent()
            && harvested
                .main_exes()
                .all(|exe| ctx.fs.exists(&exe.path).is_absent())
    }

    /// Drops later candidates on a target an earlier one already names.
    pub(crate) fn dedupe(candidates: Vec<Candidate>) -> Vec<Candidate> {
        let mut seen = HashSet::new();
        candidates
            .into_iter()
            .filter(|c| seen.insert(c.id.clone()))
            .collect()
    }

    /// The user hives the scan looks into: the interactive user's of the fingerprint, and the hive of
    /// a per-user registration.
    pub(crate) fn user_sids(ctx: &ScanCtx<'_>) -> Vec<String> {
        let mut sids: Vec<String> = Vec::new();
        let own = ctx.fp.app.program_id.hive_sid();
        for sid in [Some(ctx.fp.user_sid.as_str()), own].into_iter().flatten() {
            let sid = sid.trim();
            if !sid.is_empty()
                && !sid.contains(prefix::SEP)
                && !sids.iter().any(|s| prefix::eq_ci(s, sid))
            {
                sids.push(sid.to_owned());
            }
        }
        sids
    }

    /// The `Software` keys of both views: of the machine, then of each user hive.
    pub(crate) fn software_bases(ctx: &ScanCtx<'_>) -> Vec<String> {
        let mut bases = vec![
            r"HKLM\SOFTWARE".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node".to_owned(),
        ];
        for sid in user_sids(ctx) {
            bases.push(format!(r"HKU\{sid}\Software"));
            bases.push(format!(r"HKU\{sid}\Software\WOW6432Node"));
        }
        bases
    }

    /// Whether a `Software` base is the 32-bit view.
    pub(crate) fn is_wow(base: &str) -> bool {
        prefix::leaf(base).is_some_and(|leaf| prefix::eq_ci(leaf, "WOW6432Node"))
    }

    /// `s` with every `%NAME%` the environment knows replaced (names are upper-cased in `env`).
    pub(crate) fn expand_env(s: &str, env: &BTreeMap<String, String>) -> String {
        prefix::expand_env(s, env)
    }

    // ---- reading a subtree -------------------------------------------------------------------------------

    /// The values and subkeys of one key's subtree, as far as the scan limits allow.
    #[derive(Debug, Default)]
    pub(crate) struct KeyWalk {
        /// Every value read, with the path of its key.
        pub(crate) values: Vec<(String, RegValue)>,
        /// The full path of every subkey seen.
        pub(crate) subkeys: Vec<String>,
        /// Everything was read: no error, no link, no limit hit. Only then does the walk prove that
        /// something is absent.
        pub(crate) complete: bool,
    }

    impl KeyWalk {
        /// The number of values and subkeys, for a candidate's `child_count`.
        pub(crate) fn count(&self) -> u32 {
            u32::try_from(self.values.len() + self.subkeys.len()).unwrap_or(u32::MAX)
        }
    }

    /// Reads the subtree of `key`. Links are not followed and make the walk incomplete.
    pub(crate) fn walk(ctx: &ScanCtx<'_>, key: &str) -> KeyWalk {
        let mut out = KeyWalk {
            complete: true,
            ..KeyWalk::default()
        };
        let budget = ctx.limits.max_key_children;
        let mut stack = vec![(key.to_owned(), 0u32)];
        while let Some((at, depth)) = stack.pop() {
            match ctx.reg.key_info(&at) {
                Ok(info) if !info.is_link => {}
                _ => {
                    out.complete = false;
                    continue;
                }
            }
            let (Ok(values), Ok(subkeys)) = (ctx.reg.values(&at), ctx.reg.subkeys(&at)) else {
                out.complete = false;
                continue;
            };
            if out.values.len() + out.subkeys.len() + values.len() + subkeys.len() > budget {
                out.complete = false;
                break;
            }
            out.values
                .extend(values.into_iter().map(|v| (at.clone(), v)));
            for name in subkeys.iter().rev() {
                let child = format!(r"{at}\{name}");
                if depth + 1 > ctx.limits.max_depth {
                    out.complete = false;
                } else {
                    stack.push((child.clone(), depth + 1));
                }
                out.subkeys.push(child);
            }
        }
        out
    }

    // ---- testing a value ---------------------------------------------------------------------------------

    /// The strings of a value's data that can be tested: the string, the segments of a `REG_MULTI_SZ`,
    /// or the UTF-16 runs of anything else. Nothing for data that is cut short or unknown.
    fn data_strings(value: &RegValue) -> Vec<String> {
        let data = &value.data;
        if !data.is_complete() {
            return Vec::new();
        }
        data.string()
            .map(|s| vec![s])
            .or_else(|| data.multi_sz())
            .or_else(|| {
                (data.bytes.len() <= BINARY_UTF16_SCAN_MAX)
                    .then(|| data.binary_utf16_strings())
                    .flatten()
            })
            .unwrap_or_default()
    }

    /// Whether the value's data names a path of any kind: a drive path, a UNC path or one below a
    /// `%NAME%` reference. Data that may hold one unseen counts: cut short or unknown, binary data
    /// too large to be read for text, a string with text after its end.
    pub(crate) fn names_a_path(value: &RegValue) -> bool {
        let data = &value.data;
        let text_type = data.string().is_some() || data.multi_sz().is_some();
        !data.is_complete()
            || (!text_type && data.bytes.len() > BINARY_UTF16_SCAN_MAX)
            || (data.string().is_some() && data.has_text_after_nul())
            || data_strings(value).iter().any(|s| {
                s.contains(":\\") || s.contains(":/") || s.contains("\\\\") || s.contains("%\\")
            })
    }

    /// Every anchor of `refs` the value's name or (complete) data refers to.
    pub(crate) fn value_matches(refs: &RefMatcher, value: &RegValue) -> Vec<RefMatch> {
        let mut found = refs.find_all(&value.name);
        for s in data_strings(value) {
            found.extend(refs.find_all(&s));
        }
        found
    }

    /// One entry of a list value that refers to the app.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Segment {
        /// Zero-based position in the list, empty entries counted.
        pub(crate) index: u32,
        /// The entry as written, trimmed.
        pub(crate) text: String,
        /// The anchors it refers to.
        pub(crate) matches: Vec<RefMatch>,
    }

    /// How a value refers to the app.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ValueRefs {
        /// The value as a whole is about the app: its name refers to it, or its data does and holds
        /// nothing else.
        Whole(Vec<RefMatch>),
        /// Some entries of a list do, others do not: only those entries are the app's.
        Segments(Vec<Segment>),
    }

    /// Whether `entry` starts like a path: a drive path, a UNC path or a `%NAME%` reference.
    fn looks_like_path(entry: &str) -> bool {
        let entry = entry.trim().trim_start_matches('"');
        let bytes = entry.as_bytes();
        entry.starts_with('%')
            || entry.starts_with(r"\\")
            || (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
    }

    /// The entries of a `;`-separated list of paths, or the string itself when it is not one (a
    /// command line may hold a `;` too).
    pub(crate) fn split_list(s: &str) -> Vec<&str> {
        let parts: Vec<&str> = prefix::list_entries(s);
        let mut entries = parts.iter().filter(|p| !p.trim().is_empty());
        let is_list = entries.clone().count() >= 2 && entries.all(|e| looks_like_path(e));
        if is_list { parts } else { vec![s] }
    }

    /// Tests one value against the app's anchors. Data that is cut short or unknown is not tested;
    /// binary data never makes a value the app's by itself (it may list many apps).
    pub(crate) fn classify(refs: &RefMatcher, value: &RegValue) -> Option<ValueRefs> {
        let mut in_name = refs.find_all(&value.name);
        let data = &value.data;
        let text = data.string().filter(|_| data.is_complete());
        let parts: Vec<String> = match &text {
            Some(s) => split_list(s).into_iter().map(str::to_owned).collect(),
            None if data.is_complete() => data.multi_sz().unwrap_or_default(),
            None => Vec::new(),
        };
        let mut segments = Vec::new();
        let mut entries = 0usize;
        for (index, part) in parts.iter().enumerate() {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            entries += 1;
            let matches = refs.find_all(part);
            if !matches.is_empty() {
                segments.push(Segment {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                    text: part.to_owned(),
                    matches,
                });
            }
        }
        if !in_name.is_empty() || (entries > 0 && segments.len() == entries) {
            in_name.extend(segments.into_iter().flat_map(|s| s.matches));
            return Some(ValueRefs::Whole(in_name));
        }
        (!segments.is_empty()).then_some(ValueRefs::Segments(segments))
    }

    // ---- other apps --------------------------------------------------------------------------------------

    /// The anchors of every other installed app, for "nothing in here refers to another app".
    pub(crate) struct Foreign {
        matcher: Option<RefMatcher>,
        /// Folded anchor text and the app it belongs to.
        owners: Vec<(String, String)>,
    }

    fn anchor_key(text: &str) -> String {
        prefix::fold(
            text.trim()
                .trim_end_matches(['\\', '/'])
                .trim_start_matches('{')
                .trim_end_matches('}'),
        )
    }

    impl Foreign {
        /// The index over `ctx.other_apps`, matching with the interactive user's environment.
        pub(crate) fn new(ctx: &ScanCtx<'_>) -> Self {
            let mut set = AnchorSet::new();
            let mut owners = Vec::new();
            for app in ctx.other_apps.apps() {
                let mut own = |added: bool, text: &str| {
                    if added {
                        owners.push((anchor_key(text), app.name.clone()));
                    }
                };
                for root in &app.roots {
                    own(set.add_root(root), root);
                }
                for file in &app.files {
                    own(set.add_exe_path(file), file);
                }
                for anchor in &app.anchors {
                    let text = anchor.text.as_str();
                    let added = match anchor.kind {
                        AnchorKind::Root => set.add_root(text),
                        AnchorKind::Exe if text.contains(['\\', '/']) => set.add_exe_path(text),
                        AnchorKind::Exe => set.add_exe_name(text),
                        AnchorKind::ProgId => set.add_progid(text),
                        AnchorKind::Clsid => set.add_clsid(text),
                        AnchorKind::Aumid => set.add_aumid(text),
                        AnchorKind::Token => set.add_token(text),
                    };
                    own(added, text);
                }
            }
            let matcher = (!set.is_empty()).then(|| RefMatcher::with_env(&set, ctx.env.iter()));
            Self { matcher, owners }
        }

        /// The other app `s` refers to, if any. A bare exe name of another app does not count when the
        /// string names a path of this app (`own`): two apps may ship a file of the same name.
        pub(crate) fn in_text(&self, own: &RefMatcher, s: &str) -> Option<String> {
            let hits = self.matcher.as_ref()?.find_all(s);
            if hits.is_empty() {
                return None;
            }
            let own_path = own.find_all(s).iter().any(|m| {
                !m.name_only && matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
            });
            let hit = hits.iter().find(|m| !(m.name_only && own_path))?;
            let key = anchor_key(&hit.anchor.text);
            Some(
                self.owners
                    .iter()
                    .find(|(text, _)| *text == key)
                    .map_or_else(|| "another app".to_owned(), |(_, app)| app.clone()),
            )
        }

        /// The other app the value's name or data refers to, if any.
        pub(crate) fn in_value(&self, own: &RefMatcher, value: &RegValue) -> Option<String> {
            self.matcher.as_ref()?;
            self.in_text(own, &value.name).or_else(|| {
                data_strings(value)
                    .iter()
                    .find_map(|s| self.in_text(own, s))
            })
        }

        /// The other app anything in the walk refers to: a value, or the name of a subkey.
        pub(crate) fn in_walk(&self, own: &RefMatcher, walk: &KeyWalk) -> Option<String> {
            self.matcher.as_ref()?;
            walk.values
                .iter()
                .find_map(|(_, value)| self.in_value(own, value))
                .or_else(|| {
                    walk.subkeys
                        .iter()
                        .filter_map(|key| prefix::leaf(key))
                        .find_map(|name| self.in_text(own, name))
                })
        }
    }

    // ---- value candidates --------------------------------------------------------------------------------

    /// Adds the value-level evidence the matches support, then the common blockers:
    ///
    /// - `InstallerManifest` and `InPreUninstallRefSnapshot` when the fingerprint has the record;
    /// - `PointsIntoInstallRoot` for a path at or under an InstallRoot (or a file of the exe set), and
    ///   `DanglingRef` when that path is proven gone;
    /// - `HarvestedToken` for a token in the target's own name;
    /// - `ReferencedByOtherApp` when another app has the matched ProgID, CLSID, AUMID, token or bare
    ///   exe name as an anchor of its own, and when `foreign` is the other app the value's own name
    ///   or data refers to (see [`Foreign::in_value`]): a value that names this app next to another
    ///   one (another program's command line with a file of this app as an argument, a setting of
    ///   another program) is not this app's leftover alone.
    ///
    /// Returns whether any evidence was added.
    pub(crate) fn add_value_evidence(
        ctx: &ScanCtx<'_>,
        b: &mut CandidateBuilder<'_>,
        matches: &[RefMatch],
        foreign: Option<String>,
    ) -> bool {
        if let Some(app) = foreign {
            b.blocker(Blocker::ReferencedByOtherApp { app });
        }
        let mut any = b.installer_manifest();
        any |= b.in_ref_snapshot();
        for m in matches {
            let kind = m.anchor.kind;
            let is_path = matches!(kind, AnchorKind::Root | AnchorKind::Exe) && !m.name_only;
            if is_path {
                if let Some(path) = &m.path {
                    any |= b.points_into_install_root(path);
                    if let Some(dangling) = ctx.dangling(path) {
                        any |= b.dangling_ref(&dangling);
                    }
                }
            } else {
                if kind == AnchorKind::Token {
                    any |= b.harvested_token(&m.anchor.text);
                }
                if let Some(blocker) = ctx.other_apps.anchor_blocker(kind, &m.anchor.text) {
                    b.blocker(blocker);
                }
            }
        }
        b.common_blockers();
        any
    }

    /// Offers `value` of `key` when it refers to the app: the whole value, or the entries of a list
    /// that do. Returns the ids of the candidates pushed to `out`. Nothing is offered inside a COM
    /// class the fingerprint does not attribute to the app.
    ///
    /// An entry of a list is offered only when it is one path (`ScanCtx::entry_standing`), and it
    /// is Tier A only in a list that is the app's by where it is (`ScanCtx::owns_list_entry`): the
    /// installer's record on a value of another product says nothing about one entry of it. What
    /// a value offered whole holds is judged where every candidate is finished
    /// (`ScanCtx::value_content_unproven`, applied by `CandidateBuilder::build`).
    // One parameter per thing the three callers vary; a struct would only rename them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn offer_value(
        ctx: &ScanCtx<'_>,
        app: &AppIdentityView,
        foreign: &Foreign,
        scanner: &str,
        key: &str,
        value: &RegValue,
        category: Category,
        out: &mut Vec<Candidate>,
    ) -> Vec<CandidateId> {
        let mut ids = Vec::new();
        // A value in a COM class that is not the app's own registration is a modification of that
        // registration, not a leftover (see `ScanCtx::in_unowned_com_class`).
        if ctx.in_unowned_com_class(key) {
            return ids;
        }
        let mut emit = |target: Target,
                        action: Action,
                        matches: &[RefMatch],
                        other: Option<String>,
                        unproven: Option<&'static str>| {
            let mut b = ctx.candidate(scanner, target, action, category);
            if !add_value_evidence(ctx, &mut b, matches, other) {
                return;
            }
            if let Some(why) = unproven {
                b.cap_at_tier_b(why);
            }
            let candidate = b.build();
            ids.push(candidate.id.clone());
            out.push(candidate);
        };
        match classify(&app.refs, value) {
            None => {}
            Some(ValueRefs::Whole(matches)) => emit(
                Target::RegValue {
                    path: key.to_owned(),
                    name: value.name.clone(),
                },
                Action::DeleteValue,
                &matches,
                // The whole value goes: nothing in its name or data may be another app's.
                foreign.in_value(&app.refs, value),
                None,
            ),
            Some(ValueRefs::Segments(segments)) => {
                let by_place = ctx.owns_list_entry(key);
                for (n, segment) in segments.iter().enumerate() {
                    // An entry edit takes the entry's whole text out. An entry that is not one
                    // path holds something next to the app's (a second path, another program's
                    // command line with a file of the app as an argument): it is not offered.
                    let unproven = match ctx.entry_standing(&segment.text) {
                        EntryStanding::NotOnePath => continue,
                        EntryStanding::Unproven(why) => Some(why),
                        // The installer's record on the value names the list, not its entries.
                        EntryStanding::Plain if !by_place => {
                            Some("the list is not the app's own and nothing records its entries")
                        }
                        EntryStanding::Plain => None,
                    };
                    // The index tells a repeated entry from its first occurrence; the first needs none.
                    let repeated = segments[..n]
                        .iter()
                        .any(|s| prefix::eq_ci(&s.text, &segment.text));
                    emit(
                        Target::RegMultiSzSegment {
                            path: key.to_owned(),
                            name: value.name.clone(),
                            segment: segment.text.clone(),
                            index: repeated.then_some(segment.index),
                        },
                        Action::EditSegment,
                        &segment.matches,
                        // Only this entry goes: the other entries of the list stay as they are.
                        foreign.in_text(&app.refs, &segment.text),
                        unproven,
                    );
                }
            }
        }
        ids
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use purge_source::types::RegData;

        fn value(name: &str, data: RegData) -> RegValue {
            RegValue {
                name: name.into(),
                data,
            }
        }

        fn matcher() -> RefMatcher {
            let mut set = AnchorSet::new();
            assert!(set.add_root(r"C:\Program Files\Git"));
            RefMatcher::new(&set)
        }

        /// The same entries as the harvest and REG-ENV see (`prefix::list_entries`): a `;` inside
        /// quotes does not cut an entry in two.
        #[test]
        fn split_list_keeps_a_quoted_semicolon() {
            assert_eq!(
                split_list(r#"C:\a;"C:\Program Files\Git;x\bin";C:\d"#),
                [r"C:\a", r#""C:\Program Files\Git;x\bin""#, r"C:\d"]
            );
            assert_eq!(split_list(r"C:\a;C:\b"), [r"C:\a", r"C:\b"]);
            // Not a list of paths: the string itself.
            assert_eq!(split_list("a;b"), ["a;b"]);
        }

        #[test]
        fn expand_env_replaces_known_names_only() {
            let env = BTreeMap::from([("PROGRAMFILES".to_owned(), r"C:\Program Files".to_owned())]);
            assert_eq!(
                expand_env(r"%ProgramFiles%\Git\cmd", &env),
                r"C:\Program Files\Git\cmd"
            );
            assert_eq!(expand_env(r"%NOPE%\x;50%", &env), r"%NOPE%\x;50%");
            assert_eq!(expand_env("%%", &env), "%%");
            assert_eq!(expand_env("plain", &env), "plain");
        }

        #[test]
        fn a_list_is_a_list_of_paths() {
            assert_eq!(split_list(r"C:\a;D:\b;"), vec![r"C:\a", r"D:\b", ""]);
            assert_eq!(split_list(r"%X%\a;\\srv\b"), vec![r"%X%\a", r"\\srv\b"]);
            // One entry, and a command line holding a `;`, are not lists.
            assert_eq!(split_list(r"C:\a;"), vec![r"C:\a;"]);
            assert_eq!(
                split_list(r#""C:\a\x.exe" -e "a;b""#),
                vec![r#""C:\a\x.exe" -e "a;b""#]
            );
        }

        #[test]
        fn classify_tells_whole_values_from_list_entries() {
            let refs = matcher();
            let whole = |v: &RegValue| matches!(classify(&refs, v), Some(ValueRefs::Whole(_)));
            assert!(whole(&value(
                "Icon",
                RegData::from_sz(r#""C:\Program Files\Git\git-bash.exe",0"#)
            )));
            // The name alone carries the reference.
            assert!(whole(&value(
                r"C:\Program Files\Git\git-bash.exe",
                RegData::from_dword(1)
            )));
            assert!(whole(&value(
                "All",
                RegData::from_multi_sz(&[r"C:\Program Files\Git\a", r"C:\Program Files\Git\b"])
            )));
            let path = value(
                "Path",
                RegData::from_expand_sz(
                    r"C:\Windows;C:\Program Files\Git\cmd;;C:\Program Files\Git\cmd",
                ),
            );
            let Some(ValueRefs::Segments(segments)) = classify(&refs, &path) else {
                panic!("a list with other entries is edited, not deleted");
            };
            assert_eq!(
                segments.iter().map(|s| s.index).collect::<Vec<_>>(),
                vec![1, 3]
            );
            assert_eq!(segments[0].text, r"C:\Program Files\Git\cmd");
            assert_eq!(
                classify(&refs, &value("x", RegData::from_sz(r"C:\Else"))),
                None
            );
            // Binary data alone never makes the value the app's.
            let blob: Vec<u8> = r"C:\Program Files\Git\x"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            assert_eq!(
                classify(&refs, &value("blob", RegData::from_binary(blob.clone()))),
                None
            );
            assert_eq!(
                value_matches(&refs, &value("blob", RegData::from_binary(blob))).len(),
                1
            );
        }
    }
}
