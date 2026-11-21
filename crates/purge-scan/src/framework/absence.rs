//! The capped path: the one place of this crate where a scanner learns that a key is **not** Windows'
//! own (BASELINE_LOCAL_DESIGN.md §4.3, §4.4; invariants L3 to L5).
//!
//! A scan asks its baseline view two kinds of question:
//!
//! - **P, presence**: "is this Windows' own?" Any scanner may ask the view directly
//!   ([`ScanCtx::in_baseline`], `ctx.baseline.has_*`). The answer is the union of every set the view
//!   holds, at every trust; it only ever blocks.
//! - **A, absence**: "is this key proven not Windows' own?" A scanner asks **only here**:
//!   [`ScanCtx::key_absence`] for one key, [`ScanCtx::has_exact_baseline`] and
//!   [`ScanCtx::has_matching_exact_baseline`] for "is there a baseline whose absence is proof".
//!   `cargo xtask baseline-sites` fails when `key_absent` is called anywhere else in this crate.
//!
//! # Presence-only below Exact
//!
//! The local baseline ships presence-only (DECISIONS.md, Post-M1b, 2026-11-21): below Exact no
//! absence is used to offer anything. [`ScanCtx::key_absence`] therefore answers
//! [`Absence::Inferred`] never: what the view infers is handed out as [`Absence::Unknown`], and the
//! two gates are true for an Exact view only. An A site below Exact so takes exactly the path it
//! took without a baseline (values-only work, X-SYSTIDY, Tier B, no token evidence on a key), and
//! with an Exact view it sees what it saw from the baseline itself (L3).
//!
//! # The carrier and the seal (defence in depth)
//!
//! The machinery of the trust cap is here all the same, so that a site wired to inferred absence
//! by mistake, or on purpose once the cap is lifted (§8.5), cannot reach Safe or preselection:
//!
//! - [`CandidateBuilder::absence`] is the carrier: for [`Absence::Inferred`] it adds the soft blocker
//!   `BaselineInferred` and the detail facts `baseline`, `baseline_trust`, `baseline_neighbours` and
//!   `windows_build` to the candidate's absence-dependent evidence.
//! - [`ScanCtx::run`] seals with [`ScanCtx::baseline_cap_missing`]: under a view of trust Merged or
//!   Local, a key candidate whose evidence claims baseline absence and that lacks the blocker is
//!   dropped and recorded as a scanner fault (and fails a debug build).
//!
//! No production path reaches either with an inferred answer today.

use purge_index::baseline_view::Absence;
use purge_model::{
    BaselineTrust, Blocker, Candidate, Evidence, EvidenceKind, ManifestKind, OsInfo, Scope, Target,
};

use super::{CandidateBuilder, ScanCtx};

/// Detail key of the baseline an absence was answered from; the value `none` says no absence was
/// answered at all (the no-baseline path of an A site).
pub const BASELINE_FACT: &str = "baseline";
/// Value of [`BASELINE_FACT`] on evidence made without any absence answer.
pub const BASELINE_FACT_NONE: &str = "none";
/// Detail key of the trust an inferred absence was answered with ([`BaselineTrust::as_fact`]).
pub const BASELINE_TRUST_FACT: &str = "baseline_trust";
/// Detail key of the shipped neighbours of the view, `, `-separated.
pub const BASELINE_NEIGHBOURS_FACT: &str = "baseline_neighbours";
/// Detail key of the Windows build the view was asked for, `<build>.<ubr>`.
pub const WINDOWS_BUILD_FACT: &str = "windows_build";

/// What a view's absence answer is worth to a scanner while the local baseline is presence-only:
/// inferred absence is no answer.
fn capped(answer: Absence) -> Absence {
    match answer {
        Absence::Inferred(_) => Absence::Unknown,
        Absence::Present | Absence::Proven | Absence::Unknown => answer,
    }
}

impl ScanCtx<'_> {
    /// The Windows the scan runs on: the machine as the source reports it now, else as the
    /// fingerprint recorded it.
    pub(crate) fn os_now(&self) -> OsInfo {
        self.sys.os_info().unwrap_or_else(|_| self.fp.os.clone())
    }

    /// **A.** What the scan may conclude about `key` not being Windows' own: `Present`, `Proven`
    /// (an Exact view, inside the capture scope, not in the baseline) or `Unknown`. Never
    /// `Inferred`: see the module documentation.
    pub fn key_absence(&self, key: &str) -> Absence {
        capped(self.baseline.key_absent(key))
    }

    /// **A.** Whether the scan holds a baseline whose absence is proof: an Exact view. Below Exact
    /// this is what "no baseline" was (values-only work, §5.7.1 step 3), whatever the view holds
    /// for presence.
    pub fn has_exact_baseline(&self) -> bool {
        self.baseline.trust() == BaselineTrust::Exact
    }

    /// **A.** [`ScanCtx::has_exact_baseline`], and the baseline is of exactly the Windows the scan
    /// runs on (the machine as the source reports it now, else as the fingerprint recorded it).
    pub fn has_matching_exact_baseline(&self) -> bool {
        self.matching_exact_baseline().is_some()
    }

    /// **A.** The name (`<edition>-<build>.<ubr>`) of the exact baseline of the Windows the scan runs
    /// on, when the view is that.
    pub(crate) fn matching_exact_baseline(&self) -> Option<String> {
        if !self.has_exact_baseline() {
            return None;
        }
        let os = self.os_now();
        self.baseline
            .is_exact_for(&os.edition, os.build, os.ubr)
            .then(|| os.baseline_name())
    }

    /// The trust of the absence answers this scan consumed: what the pipeline hands to the policy
    /// as the scan's side of `BaselineTrust::for_policy`. Presence-only: `Exact` for an Exact view,
    /// `None` below it.
    pub fn absence_trust(&self) -> BaselineTrust {
        self.baseline.trust().presence_only()
    }

    /// The seal of the trust cap (§4.4 layer 2): whether `candidate` must not leave a scan made with
    /// this view. True when the view's trust is Merged or Local, the target is a registry key, the
    /// candidate does not carry `BaselineInferred`, and one of its pieces of evidence **claims
    /// baseline absence** ([`claims_absence`]).
    pub fn baseline_cap_missing(&self, candidate: &Candidate) -> bool {
        self.baseline.trust().is_inferred()
            && !candidate.blockers.contains(&Blocker::BaselineInferred)
            && candidate
                .evidence
                .iter()
                .any(|e| claims_absence(e, &candidate.target))
    }
}

/// Whether `evidence` about `target` says "the baseline does not have this key", so that under a view
/// below Exact it needs the carrier. It is the absence-dependent evidence
/// ([`Evidence::is_absence_dependent`]: a registry key target only) that the no-baseline path of its
/// site cannot have made:
///
/// - any that carries the fact `baseline_trust` (the carrier wrote it);
/// - `ProvenOwnedSkeleton` and `HarvestedToken`: without proof of absence neither is made on a key;
/// - `ComKeyOwnership` and a key-scope `InstallerManifest(Inno)` record, unless they carry
///   `baseline=none`, which is how their sites mark the Tier B form made without an absence answer.
///
/// Key-scope `InstallerManifest(Msi | Burn)` and `ChainedRef` are not in the list: their sites never
/// ask the baseline, with or without one, so they claim nothing about it. (The policy backstop
/// P-BL-1 still caps them when it is handed an inferred trust.)
pub fn claims_absence(evidence: &Evidence, target: &Target) -> bool {
    if !evidence.is_absence_dependent(target) {
        return false;
    }
    if evidence.detail.get(BASELINE_TRUST_FACT).is_some() {
        return true;
    }
    let unanswered = evidence.detail.get(BASELINE_FACT) == Some(BASELINE_FACT_NONE);
    match evidence.kind {
        EvidenceKind::ProvenOwnedSkeleton | EvidenceKind::HarvestedToken => true,
        EvidenceKind::ComKeyOwnership => !unanswered,
        EvidenceKind::InstallerManifest(ManifestKind::Inno) => {
            evidence.scope == Scope::Key && !unanswered
        }
        _ => false,
    }
}

impl CandidateBuilder<'_> {
    /// The carrier of the trust cap (§4.4 layer 1). Hand it every absence answer the candidate's
    /// evidence rests on. For [`Absence::Inferred`] it adds the soft blocker `BaselineInferred` and,
    /// to every piece of absence-dependent evidence (now and again at [`CandidateBuilder::build`]),
    /// the facts `baseline` (the view's name), `baseline_trust`, `baseline_neighbours` and
    /// `windows_build`; the evidence keeps its tier. Any other answer changes nothing.
    pub fn absence(&mut self, answer: Absence) -> &mut Self {
        if let Absence::Inferred(trust) = answer {
            // The weakest trust handed in is the one the facts name.
            self.inferred = Some(self.inferred.map_or(trust, |t| t.min(trust)));
            self.blocker(Blocker::BaselineInferred);
            self.mark_inferred();
        }
        self
    }

    /// Writes the carrier's facts on the absence-dependent evidence, when an inferred answer was
    /// handed in.
    pub(super) fn mark_inferred(&mut self) {
        let Some(trust) = self.inferred else {
            return;
        };
        let view = self.ctx.baseline;
        let os = self.ctx.os_now();
        let neighbours = view.neighbour_names().join(", ");
        let target = self.candidate.target.clone();
        for e in &mut self.candidate.evidence {
            if !e.is_absence_dependent(&target) {
                continue;
            }
            let mut detail = std::mem::take(&mut e.detail)
                .with(BASELINE_FACT, view.name())
                .with(BASELINE_TRUST_FACT, trust.as_fact())
                .with(WINDOWS_BUILD_FACT, format!("{}.{}", os.build, os.ubr));
            if !neighbours.is_empty() {
                detail = detail.with(BASELINE_NEIGHBOURS_FACT, neighbours.clone());
            }
            e.detail = detail;
        }
    }
}
