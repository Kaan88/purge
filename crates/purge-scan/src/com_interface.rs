//! Scanner COM-INTERFACE (ENGINE_PLAN.md §5.6, §5.7.2; M1b package M1B-S-COM): `Interface\{IID}` keys
//! that only served the app.
//!
//! # Which interfaces
//!
//! Nothing is walked. The interfaces looked at are those the one reference walk of the pipeline found
//! naming one of the app's ids (an `Interface\{IID}\ProxyStubClsid32`, `ProxyStubClsid` or `TypeLib`
//! default that is one of the app's CLSIDs or tokens), and those the app's own installer records name
//! (rows of its MSI `Registry` table, Inno registry records), each together with its twin in the other
//! registry view. Each is read in place: its subkeys, the proxy value and the `TypeLib` value.
//!
//! An interface is considered only when its proxy is a class of the app that COM-CLASS offers under (a)
//! or (b) ([`crate::com_class`]) or its `TypeLib` names one of the app's type libraries. A proxy listed
//! in `kb/shared-iids.json` as a shared proxy (`oleaut32`'s `PSOAInterface`, ...) says nothing about who
//! registered the interface: such an interface is considered only through its `TypeLib`.
//!
//! # What it gets
//!
//! `DeleteKey`, `Category::ShellCom`, harm Low, full undo, with `ChainedRef` to the proxy class or the
//! type library. Hard blocks: an IID listed in `kb/shared-iids.json` (`SharedIid`), a key Windows has
//! (`WindowsBaseline` and `com.system-class`), a proxy that is another product's existing class
//! (`ReferencedByOtherApp`), and the MSI blockers the sealing adds.
//!
//! Safe only when all of these hold; otherwise every Tier A fact is lowered and the key is Likely:
//!
//! - the proxy is a class of the app offered under (a) with its dangling proof (the interface then
//!   carries that proof: the server the interface needs is gone);
//! - a row of the app's own MSI writes the key (a whole-key row at or above it, or a value row at or
//!   below it), or the type library it names is offered whole (every version);
//! - the same IID in the other view is absent or meets these rules as well.

use std::collections::HashMap;

use purge_guard::prefix;
use purge_index::refscan::RefHit;
use purge_model::{Action, Blocker, Candidate, Category, Evidence, Target, Tier};
use purge_source::types::SourceError;

use crate::com_class::{
    ClassCache, ClassState, NO_KB, NO_WALK, Offer, Place, TypeLibScan, classes_roots,
    foreign_class_owner, is_anchor, is_braced_guid, scan_typelib, shared_iids, split_classes,
    walk_hits, walked_user_sids, warn_unread,
};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "COM-INTERFACE";

/// The locations the scanner reads: `Interface\{IID}` with its proxy and `TypeLib` subkeys, and the
/// class and type-library keys COM-CLASS reads for the proxies and type libraries named.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"HKCR\Interface", Some(2)),
    RootSpec::reg(r"HKCR\CLSID", Some(3)),
    RootSpec::reg(r"HKCR\TypeLib", Some(4)),
];

/// The proxy subkeys of an interface, in the order COM reads them.
const PROXY_SUBKEYS: [&str; 2] = ["ProxyStubClsid32", "ProxyStubClsid"];

/// The COM-INTERFACE scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComInterface;

impl Scanner for ComInterface {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let Some(hits) = walk_hits(ctx) else {
            ctx.ext.warn(ID, NO_WALK);
            return Vec::new();
        };
        let Some(kb) = shared_iids() else {
            ctx.ext.warn(ID, NO_KB);
            return Vec::new();
        };
        let mut classes = ClassCache::new(hits, kb);
        let mut typelibs: HashMap<String, TypeLibScan> = HashMap::new();
        let mut views: Vec<IfaceView> = Vec::new();
        for (place, iid) in locations(ctx, hits) {
            let view = judge(ctx, &mut classes, &mut typelibs, &place, &iid);
            views.push(view);
        }
        let mut out = Vec::new();
        for view in &views {
            let Some(mut builder) = view.build(ctx) else {
                continue;
            };
            let twin = views
                .iter()
                .find(|v| v.place.same(&view.place.twin()) && prefix::eq_ci(&v.iid, &view.iid));
            let twin_ok = match twin.map(|t| &t.read) {
                Some(Read::Absent) => true,
                Some(Read::Present { .. }) => twin.is_some_and(|t| t.safe_here),
                // Unreadable, or never looked at: not shown to be harmless.
                Some(Read::Unreadable) | None => false,
            };
            if view.safe_here && twin_ok {
                builder.evidence_also(view.dangling.iter().cloned());
            } else {
                builder.cap(view.why_not_safe(twin_ok));
            }
            out.push(builder.finish());
        }
        out
    }
}

/// The interfaces to look at, each view once, each with its twin: from the walk's hits and from the
/// app's installer records.
fn locations(ctx: &ScanCtx<'_>, hits: &[RefHit]) -> Vec<(Place, String)> {
    let roots = classes_roots(ctx);
    let fp = ctx.fp;
    let mut found: Vec<(Place, String)> = Vec::new();
    let mut add = |place: Place, iid: &str| {
        if !is_braced_guid(iid) || !roots.iter().any(|r| prefix::eq_ci(r, &place.root)) {
            return;
        }
        for p in [place.clone(), place.twin()] {
            if !found
                .iter()
                .any(|(q, i)| q.same(&p) && prefix::eq_ci(i, iid))
            {
                found.push((p, iid.to_owned()));
            }
        }
    };
    let is_kind = |rest: &[&str]| rest.first().is_some_and(|k| prefix::eq_ci(k, "Interface"));
    // A value of the interface naming an id of the app.
    for hit in hits {
        let Some(at) = split_classes(&hit.key) else {
            continue;
        };
        let leaf_ok = at.rest.len() == 3
            && PROXY_SUBKEYS
                .iter()
                .chain(std::iter::once(&"TypeLib"))
                .any(|w| prefix::eq_ci(w, at.rest[2]));
        if is_kind(&at.rest) && leaf_ok && hit.value_name.is_empty() {
            add(at.place.clone(), at.rest[1]);
        }
    }
    // The app's installer records: rows of its MSI `Registry` tables (a per-user row of a per-machine
    // product in every walked user's hive), and Inno registry records.
    let users = walked_user_sids(ctx);
    let mut keys: Vec<String> = Vec::new();
    for row in fp.msi.iter().flat_map(|m| &m.registry_rows) {
        keys.extend(bound_keys(&row.key, &users));
    }
    for record in fp.inno.iter().filter(|r| !r.existed_before && !r.shared) {
        if let Target::RegKey { path } | Target::RegValue { path, .. } = &record.target {
            keys.push(path.clone());
        }
    }
    for key in keys {
        if let Some(at) = split_classes(&key)
            && is_kind(&at.rest)
            && let Some(iid) = at.rest.get(1)
        {
            add(at.place.clone(), iid);
        }
    }
    found
}

/// `key` with a literal "any user" segment (`HKU\*`, `HKU\*_Classes`) bound to each of `users`; `key`
/// itself otherwise.
fn bound_keys(key: &str, users: &[String]) -> Vec<String> {
    let mut parts = key.splitn(3, prefix::SEP);
    let (Some(hive), Some(user), rest) = (parts.next(), parts.next(), parts.next()) else {
        return vec![key.to_owned()];
    };
    if !prefix::eq_ci(hive, "HKU") || !(user == "*" || prefix::eq_ci(user, "*_Classes")) {
        return vec![key.to_owned()];
    }
    let suffix = if user == "*" { "" } else { "_Classes" };
    users
        .iter()
        .map(|sid| match rest {
            Some(rest) => format!(r"HKU\{sid}{suffix}\{rest}"),
            None => format!(r"HKU\{sid}{suffix}"),
        })
        .collect()
}

/// What reading an interface key gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Absent,
    Unreadable,
    Present {
        /// The proxy CLSID, when the proxy value is one.
        proxy: Option<String>,
        /// The type library id, when the `TypeLib` value is one.
        typelib: Option<String>,
    },
}

/// One view of one interface, judged on its own.
struct IfaceView {
    place: Place,
    iid: String,
    key: String,
    read: Read,
    /// Why it is considered: `ChainedRef` anchors (the proxy class key or the type-library key) with
    /// their tier. Empty: not considered.
    chains: Vec<(Tier, String)>,
    blockers: Vec<Blocker>,
    /// The rules of a Safe interface hold for this view (the twin is not looked at here).
    safe_here: bool,
    /// The dangling proof of the proxy's server.
    dangling: Vec<Evidence>,
    /// Why it is not Safe on its own, when it is not.
    why: &'static str,
}

impl IfaceView {
    /// The candidate builder of a considered interface; `None` when it is not considered.
    fn build<'c>(&self, ctx: &'c ScanCtx<'c>) -> Option<Builder<'c>> {
        if self.chains.is_empty() {
            return None;
        }
        let mut b = ctx.candidate(
            ID,
            Target::RegKey {
                path: self.key.clone(),
            },
            Action::DeleteKey,
            Category::ShellCom,
        );
        for (tier, anchor) in &self.chains {
            b.chained_ref(*tier, anchor);
        }
        for blocker in &self.blockers {
            b.blocker(blocker.clone());
        }
        if ctx.predates_install(&self.key) {
            b.blocker(Blocker::ExistedBeforeInstall);
        }
        b.common_blockers();
        Some(Builder(b))
    }

    /// Why the interface is not Safe.
    fn why_not_safe(&self, twin_ok: bool) -> &'static str {
        if self.safe_here && !twin_ok {
            "the interface in the other registry view is not shown to be the app's alone"
        } else {
            self.why
        }
    }
}

/// A candidate under construction.
struct Builder<'c>(crate::framework::CandidateBuilder<'c>);

impl Builder<'_> {
    fn evidence_also(&mut self, evidence: impl IntoIterator<Item = Evidence>) {
        self.0.evidence_also(evidence);
    }

    fn cap(&mut self, why: &str) {
        self.0.cap_at_tier_b(why);
    }

    fn finish(self) -> Candidate {
        self.0.build()
    }
}

/// Reads one interface key.
fn read(ctx: &ScanCtx<'_>, key: &str) -> Read {
    let names = match ctx.reg.subkeys(key) {
        Ok(names) => names,
        Err(SourceError::NotFound) => return Read::Absent,
        Err(e) => {
            warn_unread(ctx, ID, key, &e);
            return Read::Unreadable;
        }
    };
    let guid_of = |sub: &str| -> Result<Option<String>, ()> {
        let Some(name) = names.iter().find(|n| prefix::eq_ci(n, sub)) else {
            return Ok(None);
        };
        let sub_key = format!(r"{key}\{name}");
        match ctx.reg.value(&sub_key, "") {
            Ok(data) => Ok(data
                .string()
                .map(|s| s.trim().to_owned())
                .filter(|s| is_braced_guid(s))),
            Err(SourceError::NotFound) => Ok(None),
            Err(e) => {
                warn_unread(ctx, ID, &sub_key, &e);
                Err(())
            }
        }
    };
    let mut proxy = None;
    for sub in PROXY_SUBKEYS {
        match guid_of(sub) {
            Ok(Some(found)) => {
                proxy = Some(found);
                break;
            }
            Ok(None) => {}
            Err(()) => return Read::Unreadable,
        }
    }
    let Ok(typelib) = guid_of("TypeLib") else {
        return Read::Unreadable;
    };
    Read::Present { proxy, typelib }
}

/// Reads and judges one view of one interface.
fn judge(
    ctx: &ScanCtx<'_>,
    classes: &mut ClassCache<'_>,
    typelibs: &mut HashMap<String, TypeLibScan>,
    place: &Place,
    iid: &str,
) -> IfaceView {
    let key = place.key("Interface", iid);
    let mut view = IfaceView {
        place: place.clone(),
        iid: iid.to_owned(),
        key: key.clone(),
        read: read(ctx, &key),
        chains: Vec::new(),
        blockers: Vec::new(),
        safe_here: false,
        dangling: Vec::new(),
        why: "",
    };
    let Read::Present { proxy, typelib } = view.read.clone() else {
        return view;
    };
    let Some(kb) = shared_iids() else {
        return view;
    };
    let fp = ctx.fp;
    // The proxy.
    let mut proxy_dangling: Option<Vec<Evidence>> = None;
    if let Some(proxy) = &proxy
        && !kb.is_shared_proxy_clsid(proxy)
    {
        let own = is_anchor(&fp.anchors.clsids, proxy);
        let class = if own {
            Some(classes.resolve(ctx, place, proxy))
        } else {
            None
        };
        match class {
            // The app's class, (a) or (b). A class blocked itself (a shared IID names it, another
            // class emulates it) still attributes the interface, so that it is listed with its own
            // blockers; it only never makes it Safe.
            Some(class) if matches!(class.state, ClassState::Own(_)) => {
                let tier = if class.offer.is_some() {
                    Tier::A
                } else {
                    Tier::B
                };
                view.chains.push((tier, class.key.clone()));
                if class.offer == Some(Offer::Dangling) && !class.dangling.is_empty() {
                    proxy_dangling = Some(class.dangling.clone());
                }
            }
            Some(class) if matches!(class.state, ClassState::Foreign(_)) => {
                view.blockers.push(Blocker::ReferencedByOtherApp {
                    app: foreign_class_owner(ctx, proxy),
                });
            }
            Some(_) => {}
            None => {
                // Another product's class: when it exists where COM looks for it, the interface is
                // that product's to use.
                let here = place.key("CLSID", proxy);
                let machine = place.machine().key("CLSID", proxy);
                let exists = |k: &str| ctx.reg.key_exists(k).is_present();
                if exists(&here) || (!place.is_machine() && exists(&machine)) {
                    view.blockers.push(Blocker::ReferencedByOtherApp {
                        app: foreign_class_owner(ctx, proxy),
                    });
                }
            }
        }
    }
    // The type library.
    let mut typelib_whole = false;
    if let Some(typelib) = &typelib
        && is_anchor(&fp.anchors.typelibs, typelib)
    {
        let tl_place = Place {
            root: place.root.clone(),
            wow: false,
        };
        let map_key = format!(
            "{}|{}",
            prefix::fold(&tl_place.root),
            typelib.to_ascii_lowercase()
        );
        let scan = typelibs
            .entry(map_key)
            .or_insert_with(|| scan_typelib(ctx, &tl_place, typelib));
        typelib_whole = scan.whole_offered;
        view.chains.push((Tier::A, scan.key.clone()));
    }
    if view.chains.is_empty() {
        return view;
    }
    if kb.is_shared_iid(iid) {
        view.blockers.push(Blocker::SharedIid);
    }
    if ctx.in_baseline(&Target::RegKey { path: key.clone() }) {
        view.blockers.push(Blocker::DenyListed {
            rule: purge_guard::deny::ids::COM_SYSTEM_CLASS.to_owned(),
        });
    }
    let msi_row = own_msi_row_writes(ctx, place, iid);
    view.why = if proxy_dangling.is_none() {
        "the proxy is not a class of the app whose server is proven gone"
    } else if !(msi_row || typelib_whole) {
        "neither a row of the app's MSI nor its whole type library declares the interface"
    } else {
        ""
    };
    let blocked = view.blockers.iter().any(Blocker::is_hard)
        || ctx
            .msi_blockers(&Target::RegKey { path: key.clone() })
            .iter()
            .any(Blocker::is_hard);
    if let Some(dangling) = proxy_dangling
        && (msi_row || typelib_whole)
        && !blocked
    {
        view.safe_here = true;
        view.dangling = dangling;
    } else if view.why.is_empty() {
        view.why = "the interface is blocked";
    }
    view
}

/// Whether a `Registry` row of one of the app's MSI products writes `Interface\{iid}` of `place`: a
/// whole-key row at the key or above it, or a value row at the key or below it.
fn own_msi_row_writes(ctx: &ScanCtx<'_>, place: &Place, iid: &str) -> bool {
    let users = walked_user_sids(ctx);
    ctx.fp.msi.iter().flat_map(|m| &m.registry_rows).any(|row| {
        bound_keys(&row.key, &users).iter().any(|key| {
            let Some(at) = split_classes(key) else {
                return false;
            };
            if !at.place.same(place) {
                return false;
            }
            let rest = &at.rest;
            let interface = rest.first().is_some_and(|k| prefix::eq_ci(k, "Interface"));
            match rest.len() {
                // `Interface` itself, removed whole: covers every interface below it.
                1 => interface && row.whole_key,
                _ => interface && prefix::eq_ci(rest[1], iid),
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        for root in ROOTS {
            assert!(root.is_well_formed(), "{root:?}");
        }
    }

    #[test]
    fn bound_keys_bind_only_any_user_rows() {
        let users = vec!["S-1-5-21-1-2-3-1001".to_owned()];
        assert_eq!(
            bound_keys(r"HKU\*\Software\Classes\Interface\{x}", &users),
            vec![r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\Interface\{x}".to_owned()]
        );
        assert_eq!(
            bound_keys(r"HKU\*_Classes\Interface\{x}", &users),
            vec![r"HKU\S-1-5-21-1-2-3-1001_Classes\Interface\{x}".to_owned()]
        );
        assert_eq!(
            bound_keys(r"HKLM\SOFTWARE\Classes\Interface\{x}", &users),
            vec![r"HKLM\SOFTWARE\Classes\Interface\{x}".to_owned()]
        );
    }
}
