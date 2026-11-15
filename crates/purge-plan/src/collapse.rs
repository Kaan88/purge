//! Nesting collapse (ENGINE_PLAN.md §7.1, lesson L6): a plan never lists an item under a parent that
//! already removes it, and never removes a parent whose contents were not all cleared for removal.
//!
//! A candidate *nests* in another when its target lies inside the other's: a path below a directory, a
//! key below a key, a value or value segment in or below a key. Paths and registry targets never nest in
//! each other, and API objects (services, tasks, firewall rules, packages) never nest.
//!
//! # Rules
//!
//! Only an **absorbing parent** takes descendants: a candidate that is Safe **and** preselected (an agent
//! proposal can be Safe but unticked) and whose action removes the whole tree (`Quarantine`, `DeleteKey`).
//! A delete-if-empty parent removes nothing but itself, so it absorbs nothing.
//!
//! 1. **Objections first.** A would-be absorbing parent is checked against every descendant at any depth:
//!    - a **Blocked** descendant whose blocker names another owner (`ReferencedByOtherApp`,
//!      `InsideOtherApp`, `ContainsOtherApp`, `OwnedByInstalledMsi`) gives the parent the hard blocker
//!      `ContainsOtherApp`, so the parent is Blocked too;
//!    - any other Blocked descendant, and any descendant the policy held back for a reason of its own (a
//!      soft blocker, no way to undo it, category `UserData` or `System`, harm above Low), gives the parent the soft blocker
//!      `UnmatchedChildren { n }` with the number of such descendants, so the parent is Likely and
//!      unticked.
//!
//!    The first of these holds for **every** parent whose action removes the whole tree, ticked or
//!    not (Likely, Weak, Safe but unticked): an item the user may tick must not take with it what the
//!    engine keeps for another owner (the URL-scheme key of a product that stays installed, offered
//!    as a key while the command value below it is kept, x2-vscode-with-user).
//!
//!    The parent is then decided again. Removing it would have removed what the engine itself refused or
//!    left unticked, so it must not stay preselected. A delete-if-empty container that counted on the
//!    parent being removed loses its `EmptyAfterPlan` again ([`crate::empty_after::revalidate`]).
//! 2. **Absorb.** Every candidate that still has an absorbing ancestor moves under its outermost absorbing
//!    ancestor: its id is appended to that ancestor's `children` and it leaves the top level. What is
//!    absorbed is Safe itself, or merely short of evidence of its own (Likely or Weak on score alone); the
//!    parent's proof of the whole tree covers it.
//!
//!    Before that, a delete-if-empty container that holds something the plan does not list at all
//!    (another product's key or folder, a value nobody claimed) is left out of the plan
//!    ([`crate::empty_after::unemptiable`]): its action could never succeed.
//! 3. A parent that is not absorbing **never absorbs**: it and its descendants all stay top-level items
//!    (the BCU nested-delete regression: parent Likely + child Safe gives two items, and the order puts the
//!    child first).

use purge_guard::prefix::{self, Relation};
use purge_model::{Action, Band, Blocker, Candidate, Category, Harm, Reversibility, Target};

use crate::decide::{DecideCtx, guard_and_policy, push_blocker, redecide};
use crate::empty_after;

/// The outcome of [`collapse`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Collapsed {
    /// The items of the plan: every candidate that no parent absorbed, in input order.
    pub top: Vec<Candidate>,
    /// The candidates absorbed by a parent in `top` (listed in that parent's `children`), in input order.
    pub absorbed: Vec<Candidate>,
}

/// The two families of nestable targets with the container path of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place<'a> {
    /// A file or directory.
    Fs(&'a str),
    /// A registry key.
    Key(&'a str),
    /// A value or value segment in the key.
    InKey(&'a str),
}

fn place(target: &Target) -> Option<Place<'_>> {
    match target {
        Target::Path { path } => Some(Place::Fs(path)),
        Target::RegKey { path } => Some(Place::Key(path)),
        Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => Some(Place::InKey(path)),
        Target::Service { .. }
        | Target::Task { .. }
        | Target::FirewallRule { .. }
        | Target::AppxPackage { .. } => None,
    }
}

/// Whether `child` lies inside `parent` (strictly, except that a value lies inside its own key).
#[must_use]
pub fn nests_in(child: &Target, parent: &Target) -> bool {
    match (place(child), place(parent)) {
        (Some(Place::Fs(c)), Some(Place::Fs(p))) | (Some(Place::Key(c)), Some(Place::Key(p))) => {
            prefix::relation(c, p) == Relation::Inside
        }
        (Some(Place::InKey(c)), Some(Place::Key(p))) => {
            matches!(prefix::relation(c, p), Relation::Inside | Relation::Same)
        }
        _ => false,
    }
}

fn band(candidate: &Candidate) -> Option<Band> {
    candidate.decision.as_ref().map(|d| d.band)
}

/// Whether the candidate's action removes everything below its target.
fn removes_whole(candidate: &Candidate) -> bool {
    matches!(
        (&candidate.target, candidate.action),
        (Target::Path { .. }, Action::Quarantine) | (Target::RegKey { .. }, Action::DeleteKey)
    )
}

/// Whether the candidate would take its descendants with it: Safe, preselected, whole-tree removal.
fn is_absorbing(candidate: &Candidate) -> bool {
    candidate
        .decision
        .as_ref()
        .is_some_and(|d| d.band == Band::Safe && d.preselected)
        && removes_whole(candidate)
}

/// Whether the candidate is offered (in any band but Blocked) with an action that removes the whole
/// tree.
fn is_offered_whole(candidate: &Candidate) -> bool {
    removes_whole(candidate) && band(candidate).is_some_and(|b| b != Band::Blocked)
}

/// What a descendant means for a parent that would remove it.
enum Objection {
    /// Nothing: Safe, or short of evidence only.
    None,
    /// The descendant belongs to, or is used by, the named other owner.
    OtherApp(String),
    /// The descendant is protected or was held back.
    Unmatched,
}

fn objection(descendant: &Candidate) -> Objection {
    match band(descendant) {
        Some(Band::Safe) => Objection::None,
        Some(Band::Blocked) => descendant
            .blockers
            .iter()
            .find_map(|b| match b {
                Blocker::ReferencedByOtherApp { app }
                | Blocker::InsideOtherApp { app }
                | Blocker::ContainsOtherApp { app } => Some(app.clone()),
                Blocker::OwnedByInstalledMsi { product, .. } => Some(product.clone()),
                _ => None,
            })
            .map_or(Objection::Unmatched, Objection::OtherApp),
        Some(Band::Likely | Band::Weak) => {
            // The same reasons the policy keeps an item from Safe whatever its evidence (§5.8.2).
            let held_back = descendant.has_soft_blocker()
                || descendant.reversibility == Reversibility::None
                || matches!(descendant.category, Category::UserData | Category::System)
                || descendant.harm > Harm::Low;
            if held_back {
                Objection::Unmatched
            } else {
                Objection::None
            }
        }
        // An undecided candidate was never cleared for removal.
        None => Objection::Unmatched,
    }
}

/// Rule 1: the blockers each parent earns from its descendants, by index of the parent. An absorbing
/// parent earns both kinds; any other parent offered with a whole-tree action earns only the
/// other-owner blocker.
fn objections(decided: &[Candidate]) -> Vec<(usize, Vec<Blocker>)> {
    let mut demotions: Vec<(usize, Vec<Blocker>)> = Vec::new();
    for (pi, parent) in decided.iter().enumerate() {
        let absorbing = is_absorbing(parent);
        if !absorbing && !is_offered_whole(parent) {
            continue;
        }
        let mut unmatched: u32 = 0;
        let mut blockers: Vec<Blocker> = Vec::new();
        for (ci, child) in decided.iter().enumerate() {
            if ci == pi || !nests_in(&child.target, &parent.target) {
                continue;
            }
            match objection(child) {
                Objection::None => {}
                Objection::OtherApp(app) => {
                    let blocker = Blocker::ContainsOtherApp { app };
                    if !blockers.contains(&blocker) {
                        blockers.push(blocker);
                    }
                }
                Objection::Unmatched => unmatched = unmatched.saturating_add(1),
            }
        }
        if unmatched > 0 && absorbing {
            blockers.push(Blocker::UnmatchedChildren { n: unmatched });
        }
        // Only what the parent does not carry yet is an objection: the caller repeats this pass until
        // it finds none, so a blocker must never be reported twice, whatever band it led to.
        blockers.retain(|new| {
            !parent.blockers.iter().any(|old| match (old, new) {
                (Blocker::UnmatchedChildren { .. }, Blocker::UnmatchedChildren { .. }) => true,
                _ => old == new,
            })
        });
        if !blockers.is_empty() {
            demotions.push((pi, blockers));
        }
    }
    demotions
}

/// Collapses nested candidates. `decided` is the output of [`crate::decide::decide`]; `ctx` is the same
/// context, used to decide a parent again after it received a blocker.
#[must_use]
pub fn collapse(mut decided: Vec<Candidate>, ctx: &DecideCtx<'_>) -> Collapsed {
    // Rule 1. One pass over the decisions as they came in finds every objection: whatever makes a parent
    // object is itself a descendant of the parents above it. The pass is repeated only because a demotion
    // can leave a delete-if-empty container non-empty (its `EmptyAfterPlan` is then taken back, and a
    // container that loses the Start Menu exemption with it becomes Blocked). Every round turns at least
    // one Safe item into something else or gives a parent a blocker it did not have (a blocker a
    // parent already carries is never reported again), so the loop ends.
    loop {
        let demotions = objections(&decided);
        let demoted = !demotions.is_empty();
        for (index, blockers) in demotions {
            let parent = &mut decided[index];
            for blocker in blockers {
                push_blocker(parent, blocker);
            }
            redecide(parent, ctx);
        }
        let revoked = empty_after::revalidate(&mut decided, |c| guard_and_policy(c, ctx));
        if !demoted && revoked.is_empty() {
            break;
        }
    }

    // A delete-if-empty container holding something the plan does not list can never be emptied: it is
    // not offered. Judged on the final decisions, so a child that became Blocked above no longer counts.
    let unemptiable = empty_after::unemptiable(&decided);
    if !unemptiable.is_empty() {
        let mut index = 0;
        decided.retain(|_| {
            index += 1;
            !unemptiable.contains(&(index - 1))
        });
    }

    // Rule 2: the outermost absorbing ancestor of each candidate, if any.
    let absorber: Vec<Option<usize>> = decided
        .iter()
        .enumerate()
        .map(|(ci, child)| {
            decided
                .iter()
                .enumerate()
                .filter(|(pi, parent)| {
                    *pi != ci && is_absorbing(parent) && nests_in(&child.target, &parent.target)
                })
                .min_by_key(|(_, parent)| depth(&parent.target))
                .map(|(pi, _)| pi)
        })
        .collect();
    for (ci, parent) in absorber.iter().enumerate() {
        if let Some(pi) = *parent {
            let id = decided[ci].id.clone();
            if !decided[pi].children.contains(&id) {
                decided[pi].children.push(id);
            }
        }
    }
    let mut out = Collapsed::default();
    for (candidate, parent) in decided.into_iter().zip(absorber) {
        if parent.is_some() {
            out.absorbed.push(candidate);
        } else {
            out.top.push(candidate);
        }
    }
    out
}

fn depth(target: &Target) -> usize {
    match place(target) {
        Some(Place::Fs(p) | Place::Key(p) | Place::InKey(p)) => prefix::depth(p),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::decide;
    use crate::decide::testkit::*;
    use purge_model::{EvidenceKind, Origin, Scope};

    const ROOT: &str = r"C:\Program Files\App";

    fn run(candidates: Vec<Candidate>) -> Collapsed {
        let deny = deny();
        let ctx = ctx(&deny);
        collapse(decide(candidates, &ctx), &ctx)
    }

    fn ids(list: &[Candidate]) -> Vec<&str> {
        list.iter().map(|c| c.id.0.as_str()).collect()
    }

    fn verdict(c: &Candidate) -> (Band, bool) {
        let d = c.decision.as_ref().unwrap();
        (d.band, d.preselected)
    }

    /// A candidate that is Likely on name evidence alone, with no reason against it.
    fn named(id: &str, p: &str) -> Candidate {
        let mut c = cand(id, path(p), "FS-APPDATA");
        c.evidence
            .push(ev(EvidenceKind::ExactFullName, Scope::Path, "name"));
        c
    }

    #[test]
    fn nesting_relation() {
        let k = key(r"HKLM\SOFTWARE\Vendor");
        assert!(nests_in(&key(r"HKLM\SOFTWARE\Vendor\App"), &k));
        assert!(nests_in(&value(r"hklm\software\vendor", "v"), &k));
        assert!(nests_in(&value(r"HKLM\SOFTWARE\Vendor\App", "v"), &k));
        assert!(!nests_in(&k, &k));
        assert!(!nests_in(&key(r"HKLM\SOFTWARE\Vendor2"), &k));
        assert!(!nests_in(&k, &value(r"HKLM\SOFTWARE", "Vendor")));
        assert!(nests_in(&path(r"C:\A\b.txt"), &path(r"c:\a")));
        assert!(!nests_in(&path(r"C:\A (x86)\b"), &path(r"C:\A")));
        assert!(!nests_in(&path(r"C:\A\b"), &key(r"C:\A")));
        let pkg = Target::AppxPackage {
            full_name: "p".into(),
        };
        assert!(!nests_in(&pkg, &path(r"C:\A")));
    }

    /// §10.1, the BCU nested-delete sequence: a parent that is not Safe never absorbs.
    #[test]
    fn likely_parent_and_safe_child_are_both_listed() {
        let out = run(vec![
            named("parent", ROOT),
            owned_path("child", r"C:\Program Files\App\app.exe"),
        ]);
        assert_eq!(ids(&out.top), ["parent", "child"]);
        assert!(out.absorbed.is_empty());
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[1]), (Band::Safe, true));
        assert!(out.top[0].children.is_empty());
        assert!(out.top[0].blockers.is_empty());
    }

    #[test]
    fn safe_parent_absorbs_its_descendants() {
        let out = run(vec![
            owned_path("child", r"C:\Program Files\App\app.exe"),
            owned_path("parent", ROOT),
            named("weak", r"C:\Program Files\App\data"),
            owned_path("deep", r"C:\Program Files\App\bin\x64\tool.exe"),
            owned_path("sub", r"C:\Program Files\App\bin"),
            owned_path("elsewhere", r"C:\Program Files\Other\x.dll"),
        ]);
        assert_eq!(ids(&out.top), ["parent", "elsewhere"]);
        assert_eq!(ids(&out.absorbed), ["child", "weak", "deep", "sub"]);
        let parent = &out.top[0];
        assert_eq!(verdict(parent), (Band::Safe, true));
        let children: Vec<&str> = parent.children.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(children, ["child", "weak", "deep", "sub"]);
        // The inner Safe directory did not take `deep` for itself.
        assert!(out.absorbed.iter().all(|c| c.children.is_empty()));
    }

    #[test]
    fn safe_key_absorbs_subkeys_and_values() {
        let app = r"HKLM\SOFTWARE\Vendor\App";
        let out = run(vec![
            owned_value("v", app, "InstallDir"),
            owned_key("k", app),
            owned_key("sub", r"HKLM\SOFTWARE\Vendor\App\Settings"),
            owned_value("deepv", r"HKLM\SOFTWARE\Vendor\App\Settings", ""),
            owned_value("other", r"HKLM\SOFTWARE\Vendor\App2", "x"),
        ]);
        assert_eq!(ids(&out.top), ["k", "other"]);
        assert_eq!(ids(&out.absorbed), ["v", "sub", "deepv"]);
        assert_eq!(out.top[0].children.len(), 3);
    }

    #[test]
    fn blocked_child_keeps_the_parent_from_being_safe() {
        // A child the engine refuses for a reason of its own: the parent becomes Likely.
        let mut protected = owned_path("child", r"C:\Program Files\App\shared.dll");
        protected.blockers.push(Blocker::MicrosoftSystemTarget);
        let mut second = owned_path("child2", r"C:\Program Files\App\sub\link");
        second.blockers.push(Blocker::ReparseMismatch);
        let out = run(vec![owned_path("parent", ROOT), protected.clone(), second]);
        assert_eq!(ids(&out.top), ["parent", "child", "child2"]);
        assert!(out.absorbed.is_empty());
        let parent = &out.top[0];
        assert_eq!(parent.blockers, vec![Blocker::UnmatchedChildren { n: 2 }]);
        assert_eq!(verdict(parent), (Band::Likely, false));
        assert!(parent.children.is_empty());
        assert_eq!(verdict(&out.top[1]), (Band::Blocked, false));

        // A child that belongs to another app: the parent is Blocked.
        let mut foreign = owned_path("child", r"C:\Program Files\App\plugin");
        foreign.blockers.push(Blocker::InsideOtherApp {
            app: "Other App".into(),
        });
        let out = run(vec![owned_path("parent", ROOT), foreign, protected]);
        let parent = &out.top[0];
        assert_eq!(
            parent.blockers,
            vec![
                Blocker::ContainsOtherApp {
                    app: "Other App".into()
                },
                Blocker::UnmatchedChildren { n: 1 }
            ]
        );
        assert_eq!(verdict(parent), (Band::Blocked, false));
        assert_eq!(out.top.len(), 3);
    }

    /// x2-vscode-with-user: the URL-scheme key was offered Likely (unticked) as a whole key while the
    /// command value below it was kept for the install that stays. Ticking the key would have taken
    /// the kept value with it.
    #[test]
    fn a_child_kept_for_another_owner_blocks_an_unticked_parent_too() {
        let scheme = r"HKLM\SOFTWARE\Vendor\App\scheme";
        let parent = || {
            let mut c = cand("parent", key(scheme), "CLS-PROTOCOL");
            c.evidence
                .push(ev(EvidenceKind::ExactFullName, Scope::Key, "name"));
            c
        };
        let child = |blocker: Option<Blocker>| {
            let mut c = owned_value("child", &format!(r"{scheme}\shell\open\command"), "");
            c.blockers.extend(blocker);
            c
        };
        // Nothing kept below it: Likely, as decided.
        let out = run(vec![parent(), child(None)]);
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert!(out.top[0].blockers.is_empty());
        // A value kept for the other install: the key is kept too, and says for whom.
        let kept = Blocker::ReferencedByOtherApp {
            app: "VS Code (User)".into(),
        };
        let out = run(vec![parent(), child(Some(kept))]);
        assert_eq!(ids(&out.top), ["parent", "child"]);
        assert_eq!(
            out.top[0].blockers,
            vec![Blocker::ContainsOtherApp {
                app: "VS Code (User)".into()
            }]
        );
        assert_eq!(verdict(&out.top[0]), (Band::Blocked, false));
        // A child the engine refuses for a reason of its own says nothing about another owner: an
        // unticked parent stays as it is.
        let out = run(vec![parent(), child(Some(Blocker::TrustedInstallerOwned))]);
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert!(out.top[0].blockers.is_empty());
        // A parent that is kept for a reason of its own is not offered: nothing is added to it.
        let mut own_reason = parent();
        own_reason.blockers.push(Blocker::TrustedInstallerOwned);
        let kept = Blocker::ReferencedByOtherApp {
            app: "VS Code (User)".into(),
        };
        let out = run(vec![own_reason, child(Some(kept))]);
        assert_eq!(out.top[0].blockers, vec![Blocker::TrustedInstallerOwned]);
        // A parent that removes nothing but itself is not concerned.
        let mut if_empty = parent();
        if_empty.action = Action::RemoveDirIfEmpty;
        let kept = Blocker::ReferencedByOtherApp {
            app: "VS Code (User)".into(),
        };
        let out = run(vec![if_empty, child(Some(kept))]);
        assert!(
            out.top
                .iter()
                .all(|c| !matches!(c.blockers[..], [Blocker::ContainsOtherApp { .. }]))
        );
    }

    #[test]
    fn held_back_child_keeps_the_parent_from_being_safe() {
        let mut data = owned_path("data", r"C:\Program Files\App\profiles");
        data.category = Category::UserData;
        data.blockers.push(Blocker::UserData);
        let out = run(vec![
            owned_path("parent", ROOT),
            data,
            owned_path("exe", r"C:\Program Files\App\app.exe"),
        ]);
        assert_eq!(ids(&out.top), ["parent", "data", "exe"]);
        assert_eq!(
            out.top[0].blockers,
            vec![Blocker::UnmatchedChildren { n: 1 }]
        );
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[1]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[2]), (Band::Safe, true));
        // Harm above Low counts the same way.
        let mut config = owned_path("config", r"C:\Program Files\App\settings.ini");
        config.harm = Harm::Medium;
        let out = run(vec![owned_path("parent", ROOT), config]);
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert_eq!(out.top.len(), 2);
    }

    /// A vendor container (and the one above it) that was found empty because a Safe root would go.
    fn vendor_chain() -> Vec<Candidate> {
        use crate::empty_after::{Child, mark_pending};
        use purge_model::Facts;
        let container = |id: &str, p: &str, child: &str| {
            let mut c = cand(id, path(p), "FS-VENDORPARENT");
            c.action = Action::RemoveDirIfEmpty;
            c.category = Category::AppFiles;
            c.evidence.push(
                ev(EvidenceKind::VendorContainer, Scope::Path, "vendor")
                    .with_detail(mark_pending(Facts::new(), [Child::Container(child)])),
            );
            c
        };
        vec![
            container("outer", r"C:\Program Files\Vendor", "Suite"),
            container("inner", r"C:\Program Files\Vendor\Suite", "App"),
            owned_path("root", r"C:\Program Files\Vendor\Suite\App"),
        ]
    }

    #[test]
    fn container_loses_empty_after_plan_when_its_child_is_demoted() {
        let has_empty_after = |c: &Candidate| {
            c.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::EmptyAfterPlan)
        };
        // Nothing objects: the root goes, so both containers are emptied.
        let out = run(vendor_chain());
        assert_eq!(ids(&out.top), ["outer", "inner", "root"]);
        assert!(out.top.iter().all(|c| verdict(c) == (Band::Safe, true)));
        assert!(has_empty_after(&out.top[0]) && has_empty_after(&out.top[1]));

        // The root holds user data: it is unticked, so the plan leaves both containers non-empty and
        // neither may be listed Safe.
        let mut data = owned_path("data", r"C:\Program Files\Vendor\Suite\App\profiles");
        data.category = Category::UserData;
        let mut all = vendor_chain();
        all.push(data);
        let out = run(all);
        assert_eq!(ids(&out.top), ["outer", "inner", "root", "data"]);
        assert_eq!(verdict(&out.top[2]), (Band::Likely, false));
        for container in &out.top[..2] {
            assert!(!has_empty_after(container), "{:?}", container.id);
            assert_eq!(verdict(container), (Band::Weak, false));
        }
    }

    /// M1A_REPLAY.md, firefox item 4: a vendor key whose only subkey is the product key the plan removes.
    #[test]
    fn vendor_key_follows_its_product_key() {
        use crate::empty_after::{Child, mark_pending};
        use purge_model::Facts;
        let vendor_key = r"HKLM\SOFTWARE\WOW6432Node\Mozilla";
        let product_key = format!(r"{vendor_key}\Firefox");
        let items = || {
            let mut vendor = cand("vendor", key(vendor_key), "REG-SOFTWARE");
            vendor.action = Action::RemoveDirIfEmpty;
            vendor.evidence.push(
                ev(EvidenceKind::VendorContainer, Scope::Key, "vendor")
                    .with_detail(mark_pending(Facts::new(), [Child::Container("Firefox")])),
            );
            vec![
                vendor,
                owned_key("product", &product_key),
                owned_value("ids", &format!(r"{product_key}\TaskBarIDs"), "path"),
            ]
        };
        // The product key takes its value with it; the vendor key is a delete-if-empty item of its own.
        let out = run(items());
        assert_eq!(ids(&out.top), ["vendor", "product"]);
        assert_eq!(ids(&out.absorbed), ["ids"]);
        assert_eq!(verdict(&out.top[0]), (Band::Safe, true));
        assert_eq!(out.top[0].action, Action::RemoveDirIfEmpty);
        assert!(out.top[0].children.is_empty());

        // Something protected inside the product key: the key is unticked, so the vendor key would not
        // be empty and is not listed Safe either.
        let mut held = owned_value("held", &product_key, "Settings");
        held.blockers.push(Blocker::InUse);
        let mut all = items();
        all.push(held);
        let out = run(all);
        assert_eq!(ids(&out.top), ["vendor", "product", "ids", "held"]);
        assert_eq!(verdict(&out.top[1]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[0]), (Band::Weak, false));
    }

    #[test]
    fn start_menu_folder_is_protected_again_when_it_is_no_longer_emptied() {
        use crate::empty_after::{Child, mark_pending};
        use purge_model::Facts;
        // A hand-built list in which the folder carries `EmptyAfterPlan` but nothing removes its entry.
        let deny = deny();
        let ctx = ctx(&deny);
        let folder = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Vendor";
        let mut v = cand("v", path(folder), "FS-VENDORPARENT");
        v.action = Action::RemoveDirIfEmpty;
        v.evidence.push(
            ev(EvidenceKind::VendorContainer, Scope::Path, "vendor")
                .with_detail(mark_pending(Facts::new(), [Child::Leaf("App.lnk")])),
        );
        let lnk = owned_path("lnk", &format!(r"{folder}\App.lnk"));
        let mut decided = decide(vec![v, lnk], &ctx);
        assert_eq!(verdict(&decided[0]), (Band::Safe, true));
        // The shortcut is withdrawn after the first pass.
        decided[1].blockers.push(Blocker::InUse);
        redecide(&mut decided[1], &ctx);
        let out = collapse(decided, &ctx);
        assert_eq!(verdict(&out.top[1]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[0]), (Band::Blocked, false));
    }

    #[test]
    fn irreversible_child_keeps_the_parent_from_being_safe() {
        let mut child = owned_path("child", r"C:\Program Files\App\state.db");
        child.reversibility = Reversibility::None;
        let out = run(vec![owned_path("parent", ROOT), child]);
        assert_eq!(ids(&out.top), ["parent", "child"]);
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
    }

    #[test]
    fn objections_reach_every_ancestor() {
        let mut protected = owned_path("leaf", r"C:\Program Files\App\bin\keep.dll");
        protected.blockers.push(Blocker::HardLinkOutsidePlan);
        let out = run(vec![
            owned_path("root", ROOT),
            owned_path("bin", r"C:\Program Files\App\bin"),
            protected,
            owned_path("doc", r"C:\Program Files\App\doc"),
            owned_path("page", r"C:\Program Files\App\doc\index.html"),
        ]);
        // `root` and `bin` both hold the protected file; `doc` is untouched and still absorbs.
        assert_eq!(ids(&out.top), ["root", "bin", "leaf", "doc"]);
        assert_eq!(ids(&out.absorbed), ["page"]);
        assert_eq!(verdict(&out.top[0]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[1]), (Band::Likely, false));
        assert_eq!(verdict(&out.top[3]), (Band::Safe, true));
        assert_eq!(
            out.top[0].blockers,
            vec![Blocker::UnmatchedChildren { n: 1 }]
        );
    }

    #[test]
    fn delete_if_empty_and_unticked_parents_do_not_absorb() {
        let mut empty_dir = owned_path("parent", ROOT);
        empty_dir.action = Action::RemoveDirIfEmpty;
        let out = run(vec![
            empty_dir,
            owned_path("child", r"C:\Program Files\App\app.exe"),
        ]);
        assert_eq!(verdict(&out.top[0]), (Band::Safe, true));
        assert_eq!(ids(&out.top), ["parent", "child"]);
        // Safe but proposed by an agent: not preselected, so it takes nothing with it.
        let mut agent = owned_path("parent", ROOT);
        agent.origin = Origin::ProbeAgent;
        let out = run(vec![
            agent,
            owned_path("child", r"C:\Program Files\App\app.exe"),
        ]);
        assert_eq!(verdict(&out.top[0]), (Band::Safe, false));
        assert_eq!(ids(&out.top), ["parent", "child"]);
        assert!(out.top[0].children.is_empty());
    }

    fn pending(id: &str, target: Target, children: &[crate::empty_after::Child<'_>]) -> Candidate {
        use crate::empty_after::mark_pending;
        use purge_model::Facts;
        let scope = Scope::of(&target).unwrap();
        let mut c = cand(id, target, "REG-SOFTWARE");
        c.action = Action::RemoveDirIfEmpty;
        c.evidence.push(
            ev(EvidenceKind::VendorContainer, scope, "vendor")
                .with_detail(mark_pending(Facts::new(), children.iter().copied())),
        );
        c
    }

    /// The gate case: Firefox is removed, Thunderbird stays. `Software\Mozilla` still holds
    /// `Thunderbird`, which is nothing the plan lists, so the vendor key is not offered at all.
    #[test]
    fn vendor_key_holding_another_products_key_is_not_offered() {
        use crate::empty_after::Child;
        let vendor = r"HKLM\SOFTWARE\WOW6432Node\Vendor";
        let out = run(vec![
            pending(
                "vendor",
                key(vendor),
                &[Child::Container("App"), Child::Container("Other")],
            ),
            owned_key("app", &format!(r"{vendor}\App")),
        ]);
        assert_eq!(ids(&out.top), ["app"]);
        assert!(out.absorbed.is_empty());
        // The same listing without the other product: the key is emptied and goes.
        let out = run(vec![
            pending("vendor", key(vendor), &[Child::Container("App")]),
            owned_key("app", &format!(r"{vendor}\App")),
        ]);
        assert_eq!(ids(&out.top), ["vendor", "app"]);
        assert_eq!(verdict(&out.top[0]), (Band::Safe, true));
    }

    /// The file-system equivalent: a vendor folder that still holds a sibling product's folder.
    #[test]
    fn vendor_folder_holding_another_products_folder_is_not_offered() {
        use crate::empty_after::Child;
        let out = run(vec![
            pending(
                "vendor",
                path(r"C:\Program Files\Vendor"),
                &[Child::Container("App"), Child::Container("Mail")],
            ),
            owned_path("app", r"C:\Program Files\Vendor\App"),
        ]);
        assert_eq!(ids(&out.top), ["app"]);
    }

    /// A container that holds a value nobody claimed can never be deleted-if-empty, and neither can the
    /// container above it (`HKLM\SOFTWARE\mozilla.org\Mozilla` with `CurrentVersion`).
    #[test]
    fn container_holding_an_unclaimed_value_is_not_offered_and_neither_is_its_parent() {
        use crate::empty_after::Child;
        let out = run(vec![
            pending(
                "outer",
                key(r"HKLM\SOFTWARE\vendor.org"),
                &[Child::Container("Vendor")],
            ),
            pending(
                "inner",
                key(r"HKLM\SOFTWARE\vendor.org\Vendor"),
                &[Child::Leaf("CurrentVersion")],
            ),
        ]);
        assert!(out.top.is_empty(), "{:?}", ids(&out.top));
    }

    /// A child that is in the plan but not ticked keeps the container listed: ticking the child makes
    /// the container's action possible (`Roaming\Mozilla` above the profile folder).
    #[test]
    fn container_whose_children_are_all_listed_stays_even_when_they_are_unticked() {
        use crate::empty_after::Child;
        let out = run(vec![
            pending(
                "vendor",
                path(r"C:\ProgramData\Vendor"),
                &[Child::Container("App"), Child::Leaf("desktop.ini")],
            ),
            named("app", r"C:\ProgramData\Vendor\App"),
        ]);
        assert_eq!(ids(&out.top), ["vendor", "app"]);
        assert_eq!(verdict(&out.top[0]), (Band::Weak, false));
        // A Blocked child is not something the user can tick.
        let mut blocked = named("app", r"C:\ProgramData\Vendor\App");
        blocked.blockers.push(Blocker::ExistedBeforeInstall);
        let out = run(vec![
            pending(
                "vendor",
                path(r"C:\ProgramData\Vendor"),
                &[Child::Container("App")],
            ),
            blocked,
        ]);
        assert_eq!(ids(&out.top), ["app"]);
    }

    #[test]
    fn unrelated_candidates_pass_through() {
        let pkg = cand(
            "pkg",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            "SYS-APPX",
        );
        let out = run(vec![
            owned_key("k", r"HKLM\SOFTWARE\Vendor\App"),
            owned_path("p", ROOT),
            pkg,
        ]);
        assert_eq!(ids(&out.top), ["k", "p", "pkg"]);
        assert!(out.absorbed.is_empty());
        assert!(run(Vec::new()).top.is_empty());
    }
}
