//! Bands, Rule T, mode rules and preselection: the policy's decision (ENGINE_PLAN.md §5.3, §5.8). Pure.
//!
//! [`decide`] turns one [`Candidate`] and a [`PolicyCtx`] into a [`Decision`]. It reads nothing but its
//! arguments, so the same input always gives the same output, and [`POLICY_VERSION`] names the rule set.
//!
//! # Rules, in the order they are applied
//!
//! 1. **Effective tier** ([`effective_tier`]). A stored tier is never trusted above the §5.3 table, and
//!    evidence whose scope the table does not allow for its kind is at most Tier B. **Rule T:** for a
//!    machine-scope target, evidence from a `UserWritable` source is at most Tier B. `ChainedRef` keeps the
//!    (anchor's) tier its producer recorded through `Evidence::chained`.
//! 2. **Blocked** if any hard blocker is present.
//! 3. **Safe** iff all of these hold:
//!    - some evidence is Tier A after step 1 and its scope equals the scope of the target (Value evidence
//!      never supports a key; services, tasks and firewall rules have no M1a evidence scope). `EmptyAfterPlan`
//!      supports only a `RemoveDirIfEmpty` action;
//!    - S ≥ 8 (see `score`);
//!    - no soft blocker, and the removal can be undone: `Reversibility::None` and `Action::RemovePackage`
//!      (§7.8: a package removal has no inverse) count as the `ReversibilityNone` soft blocker even when the
//!      producer did not attach it;
//!    - harm ≤ Low, where a declared `PATH` segment edit counts as Low (see `harm`);
//!    - the category is neither `UserData` nor `System`;
//!    - the action fits the target and is not `ReportOnly`.
//! 4. Otherwise **Likely** iff Tier A evidence exists together with a soft blocker (stated or implied, see
//!    above) or a (stored) harm ≥ Medium, or S ≥ 4, or `ExactFullName` is present, or the item is the
//!    app's own data folder named after the product (a `UserData` path with the `UserData` blocker and
//!    `ProductSubfolderOfVendor` about that path, without `GenericName`): shown, and by its category and
//!    blocker never Safe; otherwise **Weak**.
//! 5. **Caps.** A `Signature` candidate is at most Likely (no shipped-and-anchored knowledge rule exists in
//!    M1a). A `ProbeAgent` candidate needs engine Tier A for Safe like any other, and is never preselected.
//! 6. **Mode rules.** `external`: Safe only if the supporting Tier A evidence is `AdminOnly` and the score
//!    over admin-only evidence is still ≥ 8. `forced`, or verify-gone not passed
//!    (`VerifyGone::is_passed`): Safe is shown as Likely.
//! 7. **Ai.** Evidence of tier `Ai` counts for nothing above; one with a negative weight moves the item
//!    down one band (Safe → Likely → Weak), except that `ExactFullName` keeps an item at least Likely.
//! 8. `preselected` = band is Safe (and the origin is not an agent probe).

use purge_model::{
    Action, Band, Blocker, Candidate, Category, Decision, Evidence, EvidenceKind, Harm, Hive,
    Origin, Reversibility, ScanMode, Scope, SourceTrust, Target, Tier, VerifyGone,
};

use crate::explain::{self, Note};
use crate::harm::{effective_harm, is_declared_segment_edit};
use crate::score::{LIKELY_MIN, SAFE_MIN, effective_weight, score, score_where};

/// Version of the rule set in this crate. Bump it with every change that can alter a decision or an
/// explanation; the golden tests are keyed by it and it is part of the plan hash.
pub const POLICY_VERSION: &str = "m1a.6";

/// Whether a target is machine-wide or belongs to one user, for Rule T (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetScope {
    /// `HKLM`, Program Files, ProgramData outside the user's own vendor folder, services, tasks, firewall
    /// rules. Evidence from user-writable sources never attributes these at Tier A.
    Machine,
    /// A user's hive or a path inside a user's profile.
    PerUser,
}

impl TargetScope {
    /// The scope of a registry target in `hive`: per-user only for the hive of a user account. `HKLM` and
    /// the hives of the system accounts (`.DEFAULT`, `S-1-5-18`, …) are machine scope.
    #[must_use]
    pub fn of_hive(hive: &Hive) -> Self {
        match hive.sid() {
            Some(sid) if !hive.is_machine() && is_user_account_sid(sid) => TargetScope::PerUser,
            _ => TargetScope::Machine,
        }
    }

    /// `self`, or `Machine` when `target` is machine-wide by its own spelling whatever the caller said: a
    /// registry path that is not below `HKU\<SID of a user account>[_Classes]` (so `HKLM`, and also the
    /// hives of the system accounts such as `HKU\.DEFAULT` and `HKU\S-1-5-18`, which no ordinary user can
    /// write), a service, a task or a firewall rule. File paths and packages cannot be classified without
    /// system facts, so for those the caller's value stands.
    #[must_use]
    pub fn or_machine_for(self, target: &Target) -> Self {
        let forced_machine = match target {
            Target::RegKey { path }
            | Target::RegValue { path, .. }
            | Target::RegValueChanged { path, .. }
            | Target::RegMultiSzSegment { path, .. } => !is_user_hive_path(path),
            Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => true,
            Target::Path { .. } | Target::AppxPackage { .. } => false,
        };
        if forced_machine {
            TargetScope::Machine
        } else {
            self
        }
    }
}

/// Whether `sid` names an ordinary user account: a local or domain account (`S-1-5-21-…`) or an Entra ID
/// account (`S-1-12-1-…`), with or without the `_Classes` suffix of the classes hive. The system accounts
/// (`S-1-5-18`, `-19`, `-20`), `.DEFAULT` and anything unrecognised are not: their hives are not writable
/// by the users Rule T is about, so they are machine scope.
fn is_user_account_sid(sid: &str) -> bool {
    let has_prefix = |prefix: &str| {
        sid.len() > prefix.len()
            && sid
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    has_prefix("S-1-5-21-") || has_prefix("S-1-12-1-")
}

/// Whether the registry path `path` lies in a user account's hive: `HKU\<sid>` or `HKU\<sid>_Classes`,
/// optionally followed by a subkey, with `<sid>` passing [`is_user_account_sid`].
fn is_user_hive_path(path: &str) -> bool {
    let in_hku = path
        .get(..4)
        .is_some_and(|root| root.eq_ignore_ascii_case("HKU\\"));
    let hive = path
        .get(4..)
        .and_then(|rest| rest.split('\\').next())
        .unwrap_or("");
    in_hku && is_user_account_sid(hive)
}

/// What the policy needs to know besides the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyCtx {
    /// The situation the scan runs in (§5.1).
    pub mode: ScanMode,
    /// The verify-gone result of the run. Only [`VerifyGone::is_passed`] is consulted.
    pub verify_gone: VerifyGone,
    /// Whether the candidate's target is machine-wide or per-user, as classified by the caller from the
    /// canonical target (hive, or path class).
    pub target_scope: TargetScope,
}

/// Order of the bands from worst to best: Blocked < Weak < Likely < Safe. "Raising a band" means a higher
/// rank.
#[must_use]
pub fn rank(band: Band) -> u8 {
    match band {
        Band::Blocked => 0,
        Band::Weak => 1,
        Band::Likely => 2,
        Band::Safe => 3,
    }
}

/// The tier `evidence` counts as for a target of `target_scope` (rule 1 of the module docs).
#[must_use]
pub fn effective_tier(evidence: &Evidence, target_scope: TargetScope) -> Tier {
    let mut tier = evidence.tier.at_most(evidence.kind.default_tier());
    if !evidence.kind.scope().contains(evidence.scope) {
        tier = tier.at_most(Tier::B);
    }
    if target_scope == TargetScope::Machine && evidence.trust == SourceTrust::UserWritable {
        // Rule T.
        tier = tier.at_most(Tier::B);
    }
    tier
}

/// Whether `action` is one that can be carried out on `target`. `ReportOnly` fits nothing.
#[must_use]
pub fn action_fits(action: Action, target: &Target) -> bool {
    matches!(
        (action, target),
        (
            Action::Quarantine | Action::RemoveDirIfEmpty,
            Target::Path { .. }
        ) | (
            Action::DeleteKey | Action::RemoveDirIfEmpty,
            Target::RegKey { .. }
        ) | (Action::DeleteValue, Target::RegValue { .. })
            | (Action::EditSegment, Target::RegMultiSzSegment { .. })
            | (Action::RemovePackage, Target::AppxPackage { .. })
    )
}

/// The scope evidence must have to support `target`; `None` when nothing can (services, tasks, firewall
/// rules, and the truth-only `RegValueChanged`).
fn support_scope(target: &Target) -> Option<Scope> {
    match target {
        Target::RegValueChanged { .. } => None,
        // M1b: wired by M1B-POLICY (Object scope has no policy effect before then)
        Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => None,
        other => Scope::of(other),
    }
}

/// Decides one candidate: band, preselection, score and explanation (§5.8). Pure.
///
/// Any decision already stored in `candidate` is ignored.
#[must_use]
pub fn decide(candidate: &Candidate, ctx: &PolicyCtx) -> Decision {
    let c = candidate;
    let total = score(&c.evidence).total();
    if c.has_hard_blocker() {
        return Decision {
            band: Band::Blocked,
            preselected: false,
            score: total,
            explanation: explain::render_joined(c, Band::Blocked, &[]),
        };
    }

    let target_scope = ctx.target_scope.or_machine_for(&c.target);
    let needed = support_scope(&c.target);
    let tier_of = |e: &Evidence| effective_tier(e, target_scope);
    let supports = |e: &Evidence| {
        tier_of(e) == Tier::A
            && Some(e.scope) == needed
            && effective_weight(e) > 0
            && (e.kind != EvidenceKind::EmptyAfterPlan || c.action == Action::RemoveDirIfEmpty)
    };

    let any_tier_a = c.evidence.iter().any(|e| tier_of(e) == Tier::A);
    let supported = c.evidence.iter().any(supports);
    let rule_t_applied = c
        .evidence
        .iter()
        .any(|e| tier_of(e) != Tier::A && effective_tier(e, TargetScope::PerUser) == Tier::A);
    // A removal that cannot be undone is never ticked for the user (§5.6 SYS-APPX, §5.11), whether or not
    // the producer remembered to attach the `ReversibilityNone` blocker.
    let irreversible = c.reversibility == Reversibility::None || c.action == Action::RemovePackage;
    let irreversible_unstated = irreversible
        && !c
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::ReversibilityNone));
    let soft = c.has_soft_blocker() || irreversible;
    // Only evidence about the segment itself declares it: Value scope, or the segment taken as a path
    // (`InsideInstallRoot`). A manifest record about the key that holds the list says nothing about one
    // entry of it.
    let declared_segment = is_declared_segment_edit(
        c.action,
        &c.target,
        c.evidence
            .iter()
            .filter(|e| {
                tier_of(e) == Tier::A
                    && effective_weight(e) > 0
                    && (e.scope == Scope::Value || e.kind == EvidenceKind::InsideInstallRoot)
            })
            .map(|e| e.kind),
    );
    let harm = effective_harm(c.harm, declared_segment);
    let category_ok = !matches!(c.category, Category::UserData | Category::System);
    let actionable = action_fits(c.action, &c.target);
    let exact_full_name = c
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::ExactFullName && e.tier != Tier::Ai);

    // The app's own data folder, named after the product below its vendor's folder
    // (`%APPDATA%\<Vendor>\<Product>`): shown, never preselected (§1.4). It is user data with the
    // `UserData` blocker, so it can never be Safe; what the score would say about deleting it
    // unseen (programs inside, many files) is what "shown, not ticked" already says, and a
    // hidden profile is a leftover nobody gets to decide about. The evidence is about this
    // exact folder: the vendor's folder itself (`VendorContainer`) and a sibling product's
    // folder do not carry it. A folder with a generic name is not lifted.
    let product_data_folder = c.category == Category::UserData
        && matches!(c.target, Target::Path { .. })
        && c.blockers.iter().any(|b| matches!(b, Blocker::UserData))
        && c.evidence.iter().any(|e| {
            e.kind == EvidenceKind::ProductSubfolderOfVendor
                && e.tier != Tier::Ai
                && effective_weight(e) > 0
        })
        && !c
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::GenericName);

    let mut notes: Vec<Note> = Vec::new();
    let strong = supported && total >= SAFE_MIN && !soft;
    let safe = strong && harm <= Harm::Low && category_ok && actionable;
    let mut band = if safe {
        Band::Safe
    } else if (any_tier_a && (soft || c.harm >= Harm::Medium))
        || total >= LIKELY_MIN
        || exact_full_name
        || product_data_folder
    {
        Band::Likely
    } else {
        Band::Weak
    };

    // Why an item with Tier A evidence is not Safe, where no blocker line already says so.
    if !supported && rule_t_applied {
        notes.push(Note::UserWritableSource);
    } else if !supported && any_tier_a {
        notes.push(Note::ScopeMismatch);
    }
    if strong && !category_ok {
        notes.push(Note::CategoryNeverPreselected);
    } else if strong && harm > Harm::Low {
        notes.push(Note::HarmAboveLow);
    } else if strong && !actionable {
        notes.push(Note::NotActionable);
    }
    if irreversible_unstated {
        notes.push(Note::CannotBeUndone);
    }
    if declared_segment && c.harm == Harm::Medium {
        notes.push(Note::DeclaredSegment);
    }

    // Caps by origin.
    if band == Band::Safe && c.origin == Origin::Signature {
        band = Band::Likely;
        notes.push(Note::SignatureCap);
    }

    // Mode rules.
    if band == Band::Safe && ctx.mode == ScanMode::External {
        let admin = |e: &Evidence| e.trust == SourceTrust::AdminOnly;
        let admin_supported = c.evidence.iter().any(|e| admin(e) && supports(e));
        if !admin_supported || score_where(&c.evidence, admin).total() < SAFE_MIN {
            band = Band::Likely;
            notes.push(Note::ExternalNeedsAdminSource);
        }
    }
    if band == Band::Safe {
        if ctx.mode == ScanMode::Forced {
            band = Band::Likely;
            notes.push(Note::ForcedMode);
        } else if !ctx.verify_gone.is_passed() {
            band = Band::Likely;
            notes.push(Note::NotVerifiedGone);
        }
    }

    // A negative AI note moves the item down one band; it never moves anything up.
    let ai_negative = c
        .evidence
        .iter()
        .any(|e| e.tier == Tier::Ai && e.weight < 0);
    if ai_negative {
        let lowered = match band {
            Band::Safe => Band::Likely,
            Band::Likely if !exact_full_name => Band::Weak,
            other => other,
        };
        if lowered != band {
            band = lowered;
            notes.push(Note::AiLowered);
        }
    }

    let preselected = band == Band::Safe && c.origin != Origin::ProbeAgent;
    if band == Band::Safe && !preselected {
        notes.push(Note::AgentProposed);
    }

    Decision {
        band,
        preselected,
        score: total,
        explanation: explain::render_joined(c, band, &notes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_ranks_are_ordered() {
        assert!(rank(Band::Blocked) < rank(Band::Weak));
        assert!(rank(Band::Weak) < rank(Band::Likely));
        assert!(rank(Band::Likely) < rank(Band::Safe));
    }

    #[test]
    fn target_scope_helpers() {
        assert_eq!(TargetScope::of_hive(&Hive::Hklm), TargetScope::Machine);
        assert_eq!(
            TargetScope::of_hive(&Hive::Hku("S-1-5-21-1".into())),
            TargetScope::PerUser
        );
        assert_eq!(
            TargetScope::of_hive(&Hive::HkuClasses("S-1-5-21-1".into())),
            TargetScope::PerUser
        );
        let key = |path: &str| Target::RegKey { path: path.into() };
        let user = TargetScope::PerUser;
        assert_eq!(
            user.or_machine_for(&key(r"HKLM\SOFTWARE\X")),
            TargetScope::Machine
        );
        assert_eq!(
            user.or_machine_for(&key(r"hklm\SOFTWARE\X")),
            TargetScope::Machine
        );
        assert_eq!(
            user.or_machine_for(&key(r"HKCU\Software\X")),
            TargetScope::Machine
        );
        assert_eq!(user.or_machine_for(&key("HK")), TargetScope::Machine);
        assert_eq!(
            user.or_machine_for(&key(r"HKU\S-1-5-21-1\Software\X")),
            user
        );
        assert_eq!(user.or_machine_for(&key(r"hku\S-1-5-21-1_Classes\x")), user);
        assert_eq!(
            user.or_machine_for(&Target::Service { name: "svc".into() }),
            TargetScope::Machine
        );
        assert_eq!(
            user.or_machine_for(&Target::Task {
                path: r"\V\T".into()
            }),
            TargetScope::Machine
        );
        assert_eq!(
            user.or_machine_for(&Target::Path {
                path: r"C:\Program Files\X".into()
            }),
            user
        );
        let machine = TargetScope::Machine;
        assert_eq!(
            machine.or_machine_for(&key(r"HKU\S-1-5-21-1\Software\X")),
            machine
        );
        // Hives of the system accounts, and anything that is not a user account's SID, are machine scope.
        for system in [
            r"HKU\.DEFAULT\Software\X",
            r"HKU\S-1-5-18\Software\X",
            r"HKU\S-1-5-19\Environment",
            r"HKU\S-1-5-20_Classes\x",
            r"HKU\S-1-5-21-\x",
            r"HKU\\Software\X",
            r"HKU\",
            r"HKU\Software",
            "HKU\\\u{e9}",
            "HK\u{e9}\\S-1-5-21-1",
        ] {
            assert_eq!(user.or_machine_for(&key(system)), machine, "{system}");
        }
        assert_eq!(
            user.or_machine_for(&key(r"HKU\S-1-12-1-1-2-3-4\Software\X")),
            user
        );
        assert_eq!(user.or_machine_for(&key(r"HKU\S-1-5-21-1")), user);
        for sid in [".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20", ""] {
            assert_eq!(TargetScope::of_hive(&Hive::Hku(sid.into())), machine);
            assert_eq!(TargetScope::of_hive(&Hive::HkuClasses(sid.into())), machine);
        }
    }

    #[test]
    fn effective_tier_rules() {
        let new = |kind, scope, trust| Evidence::new(kind, scope, trust, "s").unwrap();
        let admin = new(
            EvidenceKind::HarvestedToken,
            Scope::Key,
            SourceTrust::AdminOnly,
        );
        let user = new(
            EvidenceKind::HarvestedToken,
            Scope::Key,
            SourceTrust::UserWritable,
        );
        assert_eq!(effective_tier(&admin, TargetScope::Machine), Tier::A);
        assert_eq!(effective_tier(&user, TargetScope::Machine), Tier::B);
        assert_eq!(effective_tier(&user, TargetScope::PerUser), Tier::A);
        // A stored tier above the table is not believed.
        let mut inflated = new(
            EvidenceKind::NameTokenExact,
            Scope::Key,
            SourceTrust::AdminOnly,
        );
        inflated.tier = Tier::A;
        assert_eq!(effective_tier(&inflated, TargetScope::PerUser), Tier::C);
        // A scope the table does not allow for the kind is at most Tier B.
        let mut wrong = new(
            EvidenceKind::PointsIntoInstallRoot,
            Scope::Value,
            SourceTrust::AdminOnly,
        );
        wrong.scope = Scope::Key;
        assert_eq!(effective_tier(&wrong, TargetScope::PerUser), Tier::B);
        // Rule T never raises a weaker tier.
        let chained =
            Evidence::chained(Tier::C, Scope::Value, SourceTrust::UserWritable, "s").unwrap();
        assert_eq!(effective_tier(&chained, TargetScope::Machine), Tier::C);
        let mut ai = admin.clone();
        ai.tier = Tier::Ai;
        assert_eq!(effective_tier(&ai, TargetScope::Machine), Tier::Ai);
    }

    #[test]
    fn action_and_target_must_fit() {
        let path = Target::Path {
            path: r"C:\x".into(),
        };
        let key = Target::RegKey {
            path: r"HKLM\x".into(),
        };
        let value = Target::RegValue {
            path: r"HKLM\x".into(),
            name: "v".into(),
        };
        let package = Target::AppxPackage {
            full_name: "p".into(),
        };
        assert!(action_fits(Action::Quarantine, &path));
        assert!(action_fits(Action::RemoveDirIfEmpty, &path));
        assert!(action_fits(Action::RemoveDirIfEmpty, &key));
        assert!(action_fits(Action::DeleteKey, &key));
        assert!(action_fits(Action::DeleteValue, &value));
        assert!(action_fits(Action::RemovePackage, &package));
        assert!(!action_fits(Action::DeleteKey, &path));
        assert!(!action_fits(Action::Quarantine, &key));
        assert!(!action_fits(Action::DeleteKey, &value));
        assert!(!action_fits(Action::EditSegment, &value));
        for target in [&path, &key, &value, &package] {
            assert!(!action_fits(Action::ReportOnly, target));
        }
    }
}
