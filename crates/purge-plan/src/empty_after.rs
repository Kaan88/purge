//! `EmptyAfterPlan` (ENGINE_PLAN.md §5.6 FS-VENDORPARENT, §7.1): a vendor container may go once the plan
//! has emptied it.
//!
//! # The pending marker
//!
//! A scanner that offers a container (a vendor folder or vendor key) emits a candidate with
//! `Action::RemoveDirIfEmpty` and a `VendorContainer` evidence whose detail carries
//!
//! - [`PENDING_KEY`] = [`PENDING_VALUE`], and
//! - [`CHILDREN_KEY`] = the complete listing of the container's direct children as a JSON array of names
//!   ([`mark_pending`] writes both). A name ending in `\` is a subdirectory or subkey; any other name is a
//!   file or, for a key, a value (the default value is the empty name).
//!
//! A marker without a readable listing means "not empty".
//!
//! # The rule
//!
//! The container is empty after the plan when every listed child is either
//!
//! - a file named `desktop.ini` or `Thumbs.db` (directories only), or
//! - the exact target of a decided candidate that is Safe **and** preselected and removes it whole
//!   (`Quarantine`, `DeleteKey`, `DeleteValue`), or of a delete-if-empty candidate that this module has
//!   itself found empty.
//!
//! A child that is merely *under* some Safe item's parent, or that has Safe items inside it, does not
//! count: only what the plan removes entirely is gone. Containers are visited deepest first, so a vendor
//! folder holding an emptied product folder is found empty in the same pass.
//!
//! For an empty container, [`apply`] hands an `EmptyAfterPlan` evidence (Tier A, weight 8, scope of the
//! target) to the caller's `redecide` function, which decides the container again with it. A container
//! that is not empty is left as decided: `VendorContainer` alone weighs 2, so it stays Weak.
//!
//! `EmptyAfterPlan` alone reaches the Safe score, so this computation is the only safeguard for removing
//! a vendor container. It therefore fails closed everywhere: no listing, an unparsable listing, a child
//! the plan does not remove, or an action other than delete-if-empty all mean no evidence.

use purge_guard::prefix;
use purge_model::{
    Action, Band, Candidate, Evidence, EvidenceKind, Facts, Scope, SourceTrust, Target, Tier,
};

/// Detail key of the pending marker.
pub const PENDING_KEY: &str = "empty_after_plan";
/// Detail value of the pending marker.
pub const PENDING_VALUE: &str = "pending";
/// Detail key of the child listing: a JSON array of names, `\`-terminated for subdirectories and subkeys.
pub const CHILDREN_KEY: &str = "children";
/// Source id of the evidence this module adds.
pub const SOURCE: &str = "plan:empty-after";

/// Files that do not keep a directory from counting as empty (§5.6).
const IGNORED_FILES: [&str; 2] = ["desktop.ini", "Thumbs.db"];

/// One direct child of a container, as scanners list it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Child<'a> {
    /// A file, or a value of a key (`""` is the default value).
    Leaf(&'a str),
    /// A subdirectory or subkey.
    Container(&'a str),
}

/// Adds the pending marker and the listing of `children` to `facts`. For scanners.
#[must_use]
pub fn mark_pending<'a>(facts: Facts, children: impl IntoIterator<Item = Child<'a>>) -> Facts {
    let names: Vec<String> = children
        .into_iter()
        .map(|child| match child {
            Child::Leaf(name) => name.to_owned(),
            Child::Container(name) => format!("{name}\\"),
        })
        .collect();
    let listing = serde_json::to_string(&names).unwrap_or_else(|_| "null".to_owned());
    facts
        .with(PENDING_KEY, PENDING_VALUE)
        .with(CHILDREN_KEY, listing)
}

/// The listing stored by the pending marker of `candidate`, if it has one that can be read.
///
/// `None` when no `VendorContainer` evidence carries the marker or its listing is missing or malformed.
/// With several markers (merged scanners) the listings are united.
#[must_use]
pub fn pending_children(candidate: &Candidate) -> Option<Vec<String>> {
    let mut all: Option<Vec<String>> = None;
    for evidence in &candidate.evidence {
        if evidence.kind != EvidenceKind::VendorContainer
            || evidence.detail.get(PENDING_KEY) != Some(PENDING_VALUE)
        {
            continue;
        }
        let names: Vec<String> = serde_json::from_str(evidence.detail.get(CHILDREN_KEY)?).ok()?;
        let list = all.get_or_insert_with(Vec::new);
        for name in names {
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }
    all
}

/// Whether `candidate` is a container waiting for the emptiness check: delete-if-empty on a path or key,
/// with the pending marker.
#[must_use]
pub fn is_pending(candidate: &Candidate) -> bool {
    candidate.action == Action::RemoveDirIfEmpty
        && matches!(
            candidate.target,
            Target::Path { .. } | Target::RegKey { .. }
        )
        && candidate.evidence.iter().any(|e| {
            e.kind == EvidenceKind::VendorContainer
                && e.detail.get(PENDING_KEY) == Some(PENDING_VALUE)
        })
}

/// Whether the plan removes the candidate's target entirely: Safe, preselected, and either a whole
/// removal or a delete-if-empty that carries `EmptyAfterPlan`.
fn removes_whole(candidate: &Candidate) -> bool {
    let safe = candidate
        .decision
        .as_ref()
        .is_some_and(|d| d.band == Band::Safe && d.preselected);
    safe && match candidate.action {
        Action::Quarantine | Action::DeleteKey | Action::DeleteValue => true,
        Action::RemoveDirIfEmpty => candidate
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::EmptyAfterPlan),
        Action::EditSegment | Action::RemovePackage | Action::ReportOnly => false,
    }
}

/// The outcome of the emptiness check of one container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emptiness {
    /// Indexes (into the decided list) of the candidates that remove the children.
    pub covered_by: Vec<usize>,
    /// How many children were `desktop.ini` / `Thumbs.db`.
    pub ignored: usize,
}

/// Checks whether the container at `index` is empty once the Safe, preselected items of `decided` have
/// run. `None` when it is not a pending container or would not be empty.
#[must_use]
pub fn emptiness(decided: &[Candidate], index: usize) -> Option<Emptiness> {
    let container = decided.get(index)?;
    if !is_pending(container) {
        return None;
    }
    let children = pending_children(container)?;
    let mut result = Emptiness {
        covered_by: Vec::new(),
        ignored: 0,
    };
    for child in &children {
        let (name, is_container) = match child.strip_suffix(prefix::SEP) {
            Some(name) => (name, true),
            None => (child.as_str(), false),
        };
        // A name is one segment. Anything else is not a listing this module understands.
        if name.contains(prefix::SEP) || (is_container && name.is_empty()) {
            return None;
        }
        let cover = match &container.target {
            Target::Path { path } => {
                if name.is_empty() {
                    return None;
                }
                if !is_container && IGNORED_FILES.iter().any(|f| prefix::eq_ci(f, name)) {
                    result.ignored += 1;
                    continue;
                }
                let child_path = format!("{}\\{name}", path.trim_end_matches(prefix::SEP));
                find(
                    decided,
                    index,
                    |t| matches!(t, Target::Path { path } if prefix::is_same(path, &child_path)),
                )
            }
            Target::RegKey { path } if is_container => {
                let child_key = format!("{}\\{name}", path.trim_end_matches(prefix::SEP));
                find(
                    decided,
                    index,
                    |t| matches!(t, Target::RegKey { path } if prefix::is_same(path, &child_key)),
                )
            }
            Target::RegKey { path } => find(decided, index, |t| {
                matches!(t, Target::RegValue { path: key, name: value }
                    if prefix::is_same(key, path) && prefix::eq_ci(value, name))
            }),
            _ => return None,
        };
        result.covered_by.push(cover?);
    }
    Some(result)
}

/// The index of a candidate other than `skip` that removes a target accepted by `is_child`.
fn find(decided: &[Candidate], skip: usize, is_child: impl Fn(&Target) -> bool) -> Option<usize> {
    decided
        .iter()
        .enumerate()
        .find(|(i, c)| *i != skip && is_child(&c.target) && removes_whole(c))
        .map(|(i, _)| i)
}

/// The `EmptyAfterPlan` evidence for a container found empty.
///
/// It is as trustworthy as what empties the container: admin-only when every covering item has Tier A
/// evidence from an admin-only source (or nothing needed covering), user-writable otherwise, so that
/// Rule T and the external-mode rule see through the container to its contents.
fn evidence_for(
    decided: &[Candidate],
    container: &Candidate,
    found: &Emptiness,
) -> Option<Evidence> {
    let admin_backed = |c: &Candidate| {
        c.evidence
            .iter()
            .any(|e| e.trust == SourceTrust::AdminOnly && e.tier == Tier::A && e.weight > 0)
    };
    let trust = if found.covered_by.iter().all(|&i| admin_backed(&decided[i])) {
        SourceTrust::AdminOnly
    } else {
        SourceTrust::UserWritable
    };
    let scope = Scope::of(&container.target)?;
    let detail = Facts::new()
        .with("removed_children", found.covered_by.len().to_string())
        .with("ignored_files", found.ignored.to_string());
    Some(Evidence::new(EvidenceKind::EmptyAfterPlan, scope, trust, SOURCE)?.with_detail(detail))
}

fn depth(candidate: &Candidate) -> usize {
    match &candidate.target {
        Target::Path { path } | Target::RegKey { path } => prefix::depth(path),
        _ => 0,
    }
}

/// Runs the emptiness check over every pending container of `decided`, deepest first.
///
/// For each container found empty, `redecide(index, evidence)` must return the candidate at `index`
/// decided again with `evidence` added; the result replaces `decided[index]`. Containers that are not
/// empty, and every other candidate, are left untouched. Returns the indexes that were replaced.
pub fn apply(
    decided: &mut [Candidate],
    mut redecide: impl FnMut(usize, Evidence) -> Candidate,
) -> Vec<usize> {
    let mut pending: Vec<usize> = (0..decided.len())
        .filter(|&i| is_pending(&decided[i]))
        .collect();
    // Deepest first; the index keeps the order stable among equals.
    pending.sort_by_key(|&i| (std::cmp::Reverse(depth(&decided[i])), i));
    let mut replaced = Vec::new();
    for index in pending {
        if decided[index]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::EmptyAfterPlan)
        {
            continue;
        }
        let Some(found) = emptiness(decided, index) else {
            continue;
        };
        let Some(evidence) = evidence_for(decided, &decided[index], &found) else {
            continue;
        };
        decided[index] = redecide(index, evidence);
        replaced.push(index);
    }
    replaced
}

/// Takes `EmptyAfterPlan` back from every container that the plan no longer empties, deepest first.
///
/// [`apply`] judges emptiness on the decisions of the first pass. A later step can withdraw one of them
/// ([`crate::collapse`] unticks a parent that holds something protected), and a container that relied on
/// that item would then be listed Safe although the plan leaves it non-empty. For each such container the
/// evidence is removed and `redecide(candidate)` must return it decided again, guard included (the Start
/// Menu exemption hangs on this evidence). Returns the indexes that were replaced.
pub fn revalidate(
    decided: &mut [Candidate],
    mut redecide: impl FnMut(Candidate) -> Candidate,
) -> Vec<usize> {
    let mut granted: Vec<usize> = (0..decided.len())
        .filter(|&i| {
            decided[i]
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::EmptyAfterPlan)
        })
        .collect();
    // Deepest first, so that a container whose inner container was just revoked is revoked too.
    granted.sort_by_key(|&i| (std::cmp::Reverse(depth(&decided[i])), i));
    let mut revoked = Vec::new();
    for index in granted {
        if emptiness(decided, index).is_some() {
            continue;
        }
        let mut candidate = decided[index].clone();
        candidate
            .evidence
            .retain(|e| e.kind != EvidenceKind::EmptyAfterPlan);
        decided[index] = redecide(candidate);
        revoked.push(index);
    }
    revoked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::testkit::*;
    use crate::decide::{DecideCtx, decide};
    use purge_model::Category;

    fn container(id: &str, target: Target, children: &[Child<'_>]) -> Candidate {
        let scope = Scope::of(&target).unwrap();
        let mut c = cand(id, target, "FS-VENDORPARENT");
        c.action = Action::RemoveDirIfEmpty;
        c.category = Category::AppFiles;
        c.evidence.push(
            ev(EvidenceKind::VendorContainer, scope, "vendor")
                .with_detail(mark_pending(Facts::new(), children.iter().copied())),
        );
        c
    }

    fn verdict(c: &Candidate) -> (Band, bool) {
        let d = c.decision.as_ref().unwrap();
        (d.band, d.preselected)
    }

    fn by_id<'a>(list: &'a [Candidate], id: &str) -> &'a Candidate {
        list.iter().find(|c| c.id.0 == id).unwrap()
    }

    fn has_empty_after(c: &Candidate) -> bool {
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::EmptyAfterPlan)
    }

    const VENDOR: &str = r"C:\Program Files\Vendor";

    #[test]
    fn marker_round_trips() {
        let facts = mark_pending(
            Facts::new().with("vendor", "Vendor"),
            [
                Child::Container("App"),
                Child::Leaf("desktop.ini"),
                Child::Leaf(""),
            ],
        );
        assert_eq!(facts.get(PENDING_KEY), Some(PENDING_VALUE));
        assert_eq!(
            facts.get(CHILDREN_KEY),
            Some(r#"["App\\","desktop.ini",""]"#)
        );
        assert_eq!(facts.get("vendor"), Some("Vendor"));
        let c = container("v", path(VENDOR), &[Child::Container("App")]);
        assert!(is_pending(&c));
        assert_eq!(pending_children(&c), Some(vec![r"App\".to_owned()]));
        let mut quarantine = c.clone();
        quarantine.action = Action::Quarantine;
        assert!(!is_pending(&quarantine));
        let plain = owned_path("p", VENDOR);
        assert!(!is_pending(&plain));
        assert_eq!(pending_children(&plain), None);
    }

    #[test]
    fn container_emptied_by_safe_items_becomes_safe() {
        let deny = deny();
        let ctx = ctx(&deny);
        let out = decide(
            vec![
                container(
                    "v",
                    path(VENDOR),
                    &[Child::Container("App"), Child::Leaf("readme.txt")],
                ),
                owned_path("app", r"C:\Program Files\Vendor\App"),
                owned_path("readme", r"c:\program files\vendor\README.TXT"),
            ],
            &ctx,
        );
        let v = by_id(&out, "v");
        assert_eq!(verdict(v), (Band::Safe, true), "{:?}", v.decision);
        let e = v
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::EmptyAfterPlan)
            .unwrap();
        assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Scope::Path));
        assert_eq!(e.trust, SourceTrust::AdminOnly);
        assert_eq!(e.source.0, SOURCE);
        assert_eq!(e.detail.get("removed_children"), Some("2"));
        assert_eq!(v.action, Action::RemoveDirIfEmpty);
    }

    #[test]
    fn container_with_an_unremoved_child_stays_weak() {
        let deny = deny();
        let ctx = ctx(&deny);
        // `Other` is not in the plan at all.
        let out = decide(
            vec![
                container(
                    "v",
                    path(VENDOR),
                    &[Child::Container("App"), Child::Container("Other")],
                ),
                owned_path("app", r"C:\Program Files\Vendor\App"),
            ],
            &ctx,
        );
        let v = by_id(&out, "v");
        assert!(!has_empty_after(v));
        assert_eq!(verdict(v), (Band::Weak, false));

        // The child is in the plan but only Likely (name evidence), or Safe but only partly removed.
        let mut likely = cand("app", path(r"C:\Program Files\Vendor\App"), "FS-APPDATA");
        likely
            .evidence
            .push(ev(EvidenceKind::ExactFullName, Scope::Path, "name"));
        let inner = owned_path("inner", r"C:\Program Files\Vendor\Other\a.dll");
        let out = decide(
            vec![
                container(
                    "v",
                    path(VENDOR),
                    &[Child::Container("App"), Child::Container("Other")],
                ),
                likely,
                inner,
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "app")).0, Band::Likely);
        assert_eq!(verdict(by_id(&out, "inner")).0, Band::Safe);
        assert_eq!(verdict(by_id(&out, "v")), (Band::Weak, false));
    }

    #[test]
    fn desktop_ini_and_thumbs_db_count_as_empty() {
        let deny = deny();
        let ctx = ctx(&deny);
        let roaming = r"C:\Users\tester\AppData\Roaming\Vendor";
        let out = decide(
            vec![container(
                "v",
                path(roaming),
                &[Child::Leaf("Desktop.ini"), Child::Leaf("thumbs.db")],
            )],
            &ctx,
        );
        let v = &out[0];
        assert_eq!(verdict(v), (Band::Safe, true), "{:?}", v.decision);
        let e = v
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::EmptyAfterPlan)
            .unwrap();
        assert_eq!(e.detail.get("ignored_files"), Some("2"));
        // An already empty container.
        let out = decide(vec![container("v", path(roaming), &[])], &ctx);
        assert_eq!(verdict(&out[0]), (Band::Safe, true));
        // A directory of that name, or any other file, is not ignored.
        for children in [
            [Child::Container("desktop.ini")],
            [Child::Leaf("desktop.ini.bak")],
        ] {
            let out = decide(vec![container("v", path(roaming), &children)], &ctx);
            assert_eq!(verdict(&out[0]), (Band::Weak, false));
        }
    }

    #[test]
    fn missing_or_malformed_listing_is_not_empty() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut no_listing = container("v", path(VENDOR), &[]);
        no_listing.evidence[0].detail.0.remove(CHILDREN_KEY);
        let mut garbage = container("v", path(VENDOR), &[]);
        garbage.evidence[0]
            .detail
            .0
            .insert(CHILDREN_KEY.into(), "App, Other".into());
        let nested = container("v", path(VENDOR), &[Child::Leaf(r"App\file.txt")]);
        let unnamed = container("v", path(VENDOR), &[Child::Leaf("")]);
        for c in [no_listing, garbage, nested, unnamed] {
            let out = decide(vec![c], &ctx);
            assert!(!has_empty_after(&out[0]));
            assert_eq!(verdict(&out[0]), (Band::Weak, false));
        }
        // Only delete-if-empty candidates are ever marked.
        let mut whole = container("v", path(VENDOR), &[]);
        whole.action = Action::Quarantine;
        let out = decide(vec![whole], &ctx);
        assert!(!has_empty_after(&out[0]));
        assert_ne!(verdict(&out[0]).0, Band::Safe);
    }

    #[test]
    fn registry_container_needs_values_and_subkeys_removed() {
        let deny = deny();
        let ctx = ctx(&deny);
        let vendor = format!(r"HKU\{SID}\Software\Vendor");
        let children = [
            Child::Container("App"),
            Child::Leaf("InstallDir"),
            Child::Leaf(""),
        ];
        let items = || {
            vec![
                container("v", key(&vendor), &children),
                owned_key("app", &format!(r"{vendor}\App")),
                owned_value("dir", &vendor, "installdir"),
                owned_value("default", &vendor, ""),
            ]
        };
        let out = decide(items(), &ctx);
        let v = by_id(&out, "v");
        assert_eq!(verdict(v), (Band::Safe, true), "{:?}", v.decision);
        assert_eq!(
            v.evidence
                .iter()
                .find(|e| e.kind == EvidenceKind::EmptyAfterPlan)
                .unwrap()
                .scope,
            Scope::Key
        );
        // Without the default value's removal the key keeps a value.
        let mut fewer = items();
        fewer.pop();
        let out = decide(fewer, &ctx);
        assert_eq!(verdict(by_id(&out, "v")), (Band::Weak, false));
        // A value does not stand in for a subkey of the same name.
        let out = decide(
            vec![
                container("v", key(&vendor), &[Child::Container("App")]),
                owned_value("app", &vendor, "App"),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "v")), (Band::Weak, false));
    }

    /// M1A_REPLAY.md, firefox item 4: the 32-bit vendor key holds only the product key the plan removes,
    /// so it goes with it. The 64-bit vendor key is on the deny-list (clean Windows has it: Defender's
    /// native-messaging host) and stays, whatever its listing says.
    #[test]
    fn vendor_key_of_the_32_bit_view_goes_and_the_denied_64_bit_one_stays() {
        let deny = deny();
        let ctx = ctx(&deny);
        let wow = r"HKLM\SOFTWARE\WOW6432Node\Mozilla";
        let native = r"HKLM\SOFTWARE\Mozilla";
        let out = decide(
            vec![
                container("wow", key(wow), &[Child::Container("Firefox")]),
                owned_key("wow-ff", &format!(r"{wow}\Firefox")),
                container("native", key(native), &[Child::Container("Firefox")]),
                owned_key("native-ff", &format!(r"{native}\Firefox")),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "wow-ff")), (Band::Safe, true));
        let v = by_id(&out, "wow");
        assert_eq!(verdict(v), (Band::Safe, true), "{:?}", v.decision);
        assert_eq!(v.action, Action::RemoveDirIfEmpty);
        assert_eq!(verdict(by_id(&out, "native-ff")), (Band::Safe, true));
        let v = by_id(&out, "native");
        assert_eq!(verdict(v), (Band::Blocked, false), "{:?}", v.blockers);

        // The product key of one view does not empty the vendor key of the other.
        let out = decide(
            vec![
                container("wow", key(wow), &[Child::Container("Firefox")]),
                owned_key("native-ff", &format!(r"{native}\Firefox")),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "wow")), (Band::Weak, false));
        // Another product's key in the listing keeps the vendor key.
        let out = decide(
            vec![
                container(
                    "wow",
                    key(wow),
                    &[Child::Container("Firefox"), Child::Container("Thunderbird")],
                ),
                owned_key("wow-ff", &format!(r"{wow}\Firefox")),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "wow")), (Band::Weak, false));
    }

    /// M1A_REPLAY.md, firefox item 5: `ProgramData\Mozilla-<guid>` holds files and `updates\<hash>`.
    /// The vendor folder goes only when the files, and `updates` through its own emptiness, all go.
    #[test]
    fn vendor_folder_goes_through_its_empty_parents() {
        let deny = deny();
        let ctx = ctx(&deny);
        let vendor = r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38";
        let updates = format!(r"{vendor}\updates");
        let hash = format!(r"{updates}\308046B0AF4A39CB");
        let file = format!(r"{vendor}\profile_count_308046B0AF4A39CB.json");
        let containers = |in_updates: &[Child<'_>]| {
            vec![
                container(
                    "vendor",
                    path(vendor),
                    &[
                        Child::Leaf("profile_count_308046B0AF4A39CB.json"),
                        Child::Leaf("desktop.ini"),
                        Child::Container("updates"),
                    ],
                ),
                container("updates", path(&updates), in_updates),
            ]
        };
        let ours = [Child::Container("308046B0AF4A39CB")];

        // Everything in the tree is a Safe item of the plan.
        let mut items = containers(&ours);
        items.push(owned_path("hash", &hash));
        items.push(owned_path("file", &file));
        let out = decide(items, &ctx);
        for id in ["hash", "file", "updates", "vendor"] {
            let c = by_id(&out, id);
            assert_eq!(verdict(c), (Band::Safe, true), "{id}: {:?}", c.decision);
        }
        let e = by_id(&out, "vendor")
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::EmptyAfterPlan)
            .unwrap();
        assert_eq!(e.detail.get("removed_children"), Some("2"));
        assert_eq!(e.detail.get("ignored_files"), Some("1"));

        // The file is not offered: `updates` goes, the vendor folder stays.
        let mut items = containers(&ours);
        items.push(owned_path("hash", &hash));
        let out = decide(items, &ctx);
        assert_eq!(verdict(by_id(&out, "updates")), (Band::Safe, true));
        assert_eq!(verdict(by_id(&out, "vendor")), (Band::Weak, false));

        // The token-named directory is offered but not Safe (the replay's state): nothing goes.
        let mut likely = cand("hash", path(&hash), "FS-APPDATA");
        likely
            .evidence
            .push(ev(EvidenceKind::ExactFullName, Scope::Path, "name"));
        let mut items = containers(&ours);
        items.push(likely);
        items.push(owned_path("file", &file));
        let out = decide(items, &ctx);
        assert_eq!(verdict(by_id(&out, "hash")).0, Band::Likely);
        assert_eq!(verdict(by_id(&out, "updates")), (Band::Weak, false));
        assert_eq!(verdict(by_id(&out, "vendor")), (Band::Weak, false));

        // Another product's staging directory sits next to ours: `updates` and the vendor folder stay.
        let shared = [
            Child::Container("308046B0AF4A39CB"),
            Child::Container("D78BF5DD33499EC2"),
        ];
        let mut items = containers(&shared);
        items.push(owned_path("hash", &hash));
        items.push(owned_path("file", &file));
        let out = decide(items, &ctx);
        assert_eq!(verdict(by_id(&out, "hash")), (Band::Safe, true));
        assert_eq!(verdict(by_id(&out, "updates")), (Band::Weak, false));
        assert_eq!(verdict(by_id(&out, "vendor")), (Band::Weak, false));
    }

    #[test]
    fn nested_containers_resolve_deepest_first() {
        let deny = deny();
        let ctx = ctx(&deny);
        let out = decide(
            vec![
                container("vendor", path(VENDOR), &[Child::Container("Suite")]),
                container(
                    "suite",
                    path(r"C:\Program Files\Vendor\Suite"),
                    &[Child::Container("App")],
                ),
                owned_path("app", r"C:\Program Files\Vendor\Suite\App"),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "suite")), (Band::Safe, true));
        assert_eq!(verdict(by_id(&out, "vendor")), (Band::Safe, true));
        // A delete-if-empty child that was not found empty does not count, even when Safe otherwise.
        let mut proven = owned_path("suite", r"C:\Program Files\Vendor\Suite");
        proven.action = Action::RemoveDirIfEmpty;
        let out = decide(
            vec![
                container("vendor", path(VENDOR), &[Child::Container("Suite")]),
                proven,
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "suite")), (Band::Safe, true));
        assert_eq!(verdict(by_id(&out, "vendor")), (Band::Weak, false));
    }

    #[test]
    fn blocked_or_unverified_containers_do_not_become_safe() {
        let deny = deny();
        let ctx = ctx(&deny);
        // The deny-list still wins over an empty container.
        let out = decide(vec![container("v", path(r"C:\Program Files"), &[])], &ctx);
        assert_eq!(verdict(&out[0]), (Band::Blocked, false));
        // Forced mode: nothing is preselected, so nothing empties the container.
        let forced = DecideCtx {
            mode: purge_model::ScanMode::Forced,
            ..ctx
        };
        let out = decide(
            vec![
                container("v", path(VENDOR), &[Child::Container("App")]),
                owned_path("app", r"C:\Program Files\Vendor\App"),
            ],
            &forced,
        );
        assert_eq!(verdict(by_id(&out, "app")), (Band::Likely, false));
        assert_eq!(verdict(by_id(&out, "v")), (Band::Weak, false));
    }

    #[test]
    fn start_menu_vendor_folder_is_exempt_once_emptied() {
        let deny = deny();
        let ctx = ctx(&deny);
        let folder = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Vendor";
        let lnk = owned_path("lnk", &format!(r"{folder}\App.lnk"));
        let out = decide(
            vec![
                container("v", path(folder), &[Child::Leaf("App.lnk")]),
                lnk.clone(),
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "lnk")), (Band::Safe, true));
        let v = by_id(&out, "v");
        assert_eq!(verdict(v), (Band::Safe, true), "{:?}", v.blockers);
        assert!(v.blockers.is_empty());
        // With another entry left in it, the folder stays protected.
        let out = decide(
            vec![
                container(
                    "v",
                    path(folder),
                    &[Child::Leaf("App.lnk"), Child::Leaf("Other.lnk")],
                ),
                lnk,
            ],
            &ctx,
        );
        assert_eq!(verdict(by_id(&out, "v")), (Band::Blocked, false));
    }

    #[test]
    fn start_menu_roots_and_startup_stay_protected_even_when_empty() {
        let deny = deny();
        let ctx = ctx(&deny);
        let start_menu = r"C:\ProgramData\Microsoft\Windows\Start Menu";
        for folder in [
            start_menu.to_owned(),
            format!(r"{start_menu}\Programs"),
            format!(r"{start_menu}\Programs\Startup"),
            r"C:\ProgramData\Microsoft".to_owned(),
            r"C:\ProgramData\Microsoft\Vendor".to_owned(),
        ] {
            let out = decide(vec![container("v", path(&folder), &[])], &ctx);
            assert_eq!(verdict(&out[0]), (Band::Blocked, false), "{folder}");
        }
    }

    #[test]
    fn revalidate_takes_unfounded_evidence_back() {
        let deny = deny();
        let ctx = ctx(&deny);
        let mut decided = decide(
            vec![
                container("v", path(VENDOR), &[Child::Container("App")]),
                owned_path("app", r"C:\Program Files\Vendor\App"),
            ],
            &ctx,
        );
        assert!(has_empty_after(&decided[0]));
        let again = |c: Candidate| crate::decide::guard_and_policy(c, &ctx);
        assert!(revalidate(&mut decided, again).is_empty());
        // The covering item is no longer ticked.
        decided[1].decision.as_mut().unwrap().preselected = false;
        assert_eq!(revalidate(&mut decided, again), [0]);
        assert!(!has_empty_after(&decided[0]));
        assert_eq!(verdict(&decided[0]), (Band::Weak, false));
        // Evidence on a candidate without a marker is taken back as well.
        let mut forged = owned_path("f", VENDOR);
        forged.action = Action::RemoveDirIfEmpty;
        forged.evidence = vec![ev(EvidenceKind::EmptyAfterPlan, Scope::Path, "forged")];
        let mut decided = vec![crate::decide::guard_and_policy(forged, &ctx)];
        assert_eq!(verdict(&decided[0]), (Band::Safe, true));
        assert_eq!(revalidate(&mut decided, again), [0]);
        assert_ne!(verdict(&decided[0]).0, Band::Safe);
    }

    #[test]
    fn trust_follows_the_covering_items() {
        let deny = deny();
        let ctx = ctx(&deny);
        let roaming = r"C:\Users\tester\AppData\Roaming\Vendor";
        let mut app = owned_path("app", &format!(r"{roaming}\App"));
        app.evidence[0].trust = SourceTrust::UserWritable;
        let out = decide(
            vec![
                container("v", path(roaming), &[Child::Container("App")]),
                app,
            ],
            &ctx,
        );
        let v = by_id(&out, "v");
        let e = v
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::EmptyAfterPlan)
            .unwrap();
        assert_eq!(e.trust, SourceTrust::UserWritable);
        // Per-user target: Rule T does not apply, so it is still Safe in post mode ...
        assert_eq!(verdict(v), (Band::Safe, true));
        // ... but not in external mode, where only admin-only evidence carries Safe.
        let external = DecideCtx {
            mode: purge_model::ScanMode::External,
            ..ctx
        };
        let mut app = owned_path("app", &format!(r"{roaming}\App"));
        app.evidence[0].trust = SourceTrust::UserWritable;
        let out = decide(
            vec![
                container("v", path(roaming), &[Child::Container("App")]),
                app,
            ],
            &external,
        );
        assert_ne!(verdict(by_id(&out, "v")).0, Band::Safe);
    }
}
