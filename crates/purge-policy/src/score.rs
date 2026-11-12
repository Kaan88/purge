//! The score S of a candidate (ENGINE_PLAN.md §5.8.1). Pure.
//!
//! `S = Σ over distinct non-Ai evidence kinds of max(weight)`, plus +1 per additional independent source of
//! the same kind (at most [`MAX_SOURCE_BONUS`] per kind), plus the negatives. Evidence of tier `Ai` is
//! excluded: it can only lower a band (see `band`).
//!
//! The score never trusts the numbers stored in an [`Evidence`] beyond the §5.3 table: a weight is clamped
//! to the table weight of its kind ([`effective_weight`]), so a candidate read back from a file cannot
//! score higher than a scanner could have made it.

use purge_model::{Evidence, EvidenceKind, SourceId, Tier};

/// The most the independent-source bonus adds for one evidence kind.
pub const MAX_SOURCE_BONUS: i32 = 2;

/// The score a candidate needs, among other things, for the Safe band (§5.8.2).
pub const SAFE_MIN: i32 = 8;

/// The score from which a candidate is Likely on its score alone (§5.8.2).
pub const LIKELY_MIN: i32 = 4;

/// The parts of a score, for explanations and debugging.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Score {
    /// Sum over distinct positive kinds of the highest weight.
    pub positives: i32,
    /// Sum of the independent-source bonuses.
    pub source_bonus: i32,
    /// Sum over distinct negative kinds of their weight (zero or below).
    pub negatives: i32,
}

impl Score {
    /// The score S.
    #[must_use]
    pub fn total(self) -> i32 {
        self.positives + self.source_bonus + self.negatives
    }
}

/// The weight of `evidence` as the score counts it: the stored weight, limited by the §5.3 table.
///
/// A positive kind weighs between 0 and its table weight (a mega-vendor `VendorContainer` stays 0); a
/// negative kind weighs at most its table weight, i.e. it cannot be made milder than the table.
#[must_use]
pub fn effective_weight(evidence: &Evidence) -> i32 {
    let table = i32::from(evidence.kind.default_weight());
    let stored = i32::from(evidence.weight);
    if evidence.kind.is_negative() {
        stored.min(table)
    } else {
        stored.clamp(0, table)
    }
}

/// Whether `evidence` takes part in the score at all: everything except tier `Ai`.
#[must_use]
pub fn counts(evidence: &Evidence) -> bool {
    evidence.tier != Tier::Ai
}

/// The score of `evidence`.
#[must_use]
pub fn score(evidence: &[Evidence]) -> Score {
    score_where(evidence, |_| true)
}

/// The score counting only the positive evidence that `keep` accepts. Negatives always count, so a filter
/// can lower a score but never raise it. Used for the external-mode rule (§5.8.3), where only evidence from
/// admin-only sources may carry a candidate into Safe.
#[must_use]
pub fn score_where(evidence: &[Evidence], keep: impl Fn(&Evidence) -> bool) -> Score {
    struct PerKind<'a> {
        kind: EvidenceKind,
        weight: i32,
        sources: Vec<&'a SourceId>,
    }
    // Evidence lists are short; a vector keeps the order of first appearance and needs no ordering on kinds.
    let mut kinds: Vec<PerKind<'_>> = Vec::new();
    for e in evidence {
        if !counts(e) || (!e.kind.is_negative() && !keep(e)) {
            continue;
        }
        let weight = effective_weight(e);
        match kinds.iter_mut().find(|k| k.kind == e.kind) {
            Some(k) => {
                k.weight = if e.kind.is_negative() {
                    k.weight.min(weight)
                } else {
                    k.weight.max(weight)
                };
                if !k.sources.contains(&&e.source) {
                    k.sources.push(&e.source);
                }
            }
            None => kinds.push(PerKind {
                kind: e.kind,
                weight,
                sources: vec![&e.source],
            }),
        }
    }
    let mut total = Score::default();
    for k in &kinds {
        if k.kind.is_negative() {
            total.negatives += k.weight;
        } else {
            total.positives += k.weight;
            // A kind that weighs nothing (mega-vendor container) earns no bonus either.
            if k.weight > 0 {
                let extra = i32::try_from(k.sources.len() - 1).unwrap_or(i32::MAX);
                total.source_bonus += extra.min(MAX_SOURCE_BONUS);
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::{Scope, SourceTrust};

    fn ev(kind: EvidenceKind, source: &str) -> Evidence {
        let scope = kind.scope().iter().next().unwrap();
        Evidence::new(kind, scope, SourceTrust::AdminOnly, source).unwrap()
    }

    #[test]
    fn distinct_kinds_add_up_and_duplicates_take_the_max() {
        let mut low = ev(EvidenceKind::HarvestedToken, "a");
        low.weight = 3;
        let list = [
            ev(EvidenceKind::HarvestedToken, "a"),
            low,
            ev(EvidenceKind::PointsIntoInstallRoot, "b"),
        ];
        let s = score(&list);
        assert_eq!((s.positives, s.source_bonus, s.negatives), (13, 0, 0));
        assert_eq!(s.total(), 13);
        assert_eq!(score(&[]).total(), 0);
    }

    #[test]
    fn independent_sources_add_one_each_up_to_two() {
        let k = EvidenceKind::InPreUninstallRefSnapshot;
        assert_eq!(score(&[ev(k, "a"), ev(k, "a")]).total(), 8);
        assert_eq!(score(&[ev(k, "a"), ev(k, "b")]).total(), 9);
        assert_eq!(score(&[ev(k, "a"), ev(k, "b"), ev(k, "c")]).total(), 10);
        let four = [ev(k, "a"), ev(k, "b"), ev(k, "c"), ev(k, "d")];
        assert_eq!(score(&four).total(), 10);
        // The cap is per kind.
        let d = EvidenceKind::DanglingRef;
        let two_kinds = [ev(k, "a"), ev(k, "b"), ev(d, "a"), ev(d, "b")];
        assert_eq!(score(&two_kinds).total(), 8 + 1 + 7 + 1);
    }

    #[test]
    fn negatives_count_once_per_kind_and_get_no_bonus() {
        let list = [
            ev(EvidenceKind::NameTokenExact, "name"),
            ev(EvidenceKind::ExecutablesPresent, "fs1"),
            ev(EvidenceKind::ExecutablesPresent, "fs2"),
            ev(EvidenceKind::ManyFiles, "fs1"),
        ];
        let s = score(&list);
        assert_eq!((s.positives, s.source_bonus, s.negatives), (3, 0, -6));
    }

    #[test]
    fn ai_tier_is_excluded() {
        let mut ai = ev(EvidenceKind::ChainedRef, "agent");
        ai.tier = Tier::Ai;
        assert_eq!(score(std::slice::from_ref(&ai)).total(), 0);
        ai.weight = -3;
        assert_eq!(score(&[ev(EvidenceKind::TimeWindow, "t"), ai]).total(), 1);
    }

    #[test]
    fn stored_weights_are_limited_by_the_table() {
        let mut inflated = ev(EvidenceKind::NameTokenExact, "n");
        inflated.weight = 100;
        assert_eq!(effective_weight(&inflated), 3);
        let mut mild = ev(EvidenceKind::ModifiedAfterUninstall, "fs");
        mild.weight = -1;
        assert_eq!(effective_weight(&mild), -4);
        mild.weight = 5;
        assert_eq!(effective_weight(&mild), -4);
        mild.weight = -9;
        assert_eq!(effective_weight(&mild), -9);
        let mut mega = ev(EvidenceKind::VendorContainer, "v");
        mega.weight = EvidenceKind::MEGA_VENDOR_WEIGHT;
        let again = Evidence {
            source: "w".into(),
            ..mega.clone()
        };
        assert_eq!(score(&[mega, again]).total(), 0);
        let mut negative_positive = ev(EvidenceKind::TimeWindow, "t");
        negative_positive.weight = -5;
        assert_eq!(effective_weight(&negative_positive), 0);
    }

    #[test]
    fn a_filter_drops_positives_but_keeps_negatives() {
        let mut user = ev(EvidenceKind::InsideInstallRoot, "arp");
        user.trust = SourceTrust::UserWritable;
        assert_eq!(user.scope, Scope::Path);
        let list = [
            user,
            ev(EvidenceKind::UninstallerArtifact, "arp"),
            ev(EvidenceKind::ManyFiles, "fs"),
        ];
        assert_eq!(score(&list).total(), 13);
        let admin = score_where(&list, |e| e.trust == SourceTrust::AdminOnly);
        assert_eq!(admin.total(), 4);
    }
}
