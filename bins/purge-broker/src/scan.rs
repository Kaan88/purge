//! `leftovers.scan`, `scan.candidates` and `candidate.explain` (M3 design 3.6, 6.3; package
//! M3-BROKER-FLOW).
//!
//! # The mode
//!
//! A scan of an uninstall session is `post` when the broker's uninstaller ran **and** verify-gone
//! passed; otherwise it is `forced` ([`purge_model::ScanMode::Forced`]). The client may ask for
//! `forced` in any case; it can never raise the mode. A scan from a stored fingerprint is `external`:
//! verify-gone is checked afresh, and the policy applies the forced-mode rules when it fails, so a
//! program still installed is never Safe.
//!
//! # Candidate ids
//!
//! The scan document is the broker's own. Before a scan is added to the tables (and again before it is
//! served), every candidate id must have the wire form `c-<16 hex>` and name exactly one candidate
//! (review M3-R1 M2). A scan that fails is refused with `plan_refused`; it is never served.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use purge_engine::pipeline;
use purge_model::{
    Action, Band, BaselineTrust, Candidate, CandidateId, Fingerprint, ProgramId, ScanMode, Target,
};
use purge_policy::explain;
use purge_rpc::error::{ErrorData, ErrorObject, IdKind, Refusal};
use purge_rpc::methods::{
    BandCounts, CandidateRef, CandidateRow, CandidatesPage, CandidatesParams, ExplainParams,
    Explanation, ItemKind, LeftoversScanParams, ScanResult, UninstallSessionId, Warning,
};
use purge_rpc::timing::TimingName;
use serde_json::Value;

use crate::serve::Ctx;
use crate::session::{gone, unique_index};
use crate::uninstall::Flow;
use crate::uninstall::FlowHandler;

/// One scan in the broker's memory: the engine's scan document and what the UI and `plan.create` need.
pub struct Scan {
    /// The engine's `purge.scan/0` document. The broker's plan is built from exactly this.
    pub doc: purge_plan::emit::ScanDoc,
    /// The mode it ran in.
    pub mode: ScanMode,
    /// Candidates per band.
    pub counts: BandCounts,
    /// The scan's warnings, as sent to the client.
    pub warnings: Vec<Warning>,
    /// How far the baseline view's absence answers were trusted.
    pub baseline_trust: BaselineTrust,
    /// The uninstall session it came from; `None` for a stored fingerprint.
    pub session: Option<UninstallSessionId>,
    /// The program it scanned. A run of this program spends every scan of it, not only the plan's
    /// (review M3-R2 S2).
    pub program: ProgramId,
    /// The app's display name, as the broker's own fingerprint names it.
    pub app_name: String,
    /// The install roots of the fingerprint the scan ran with, for the plan's object binding.
    pub program_roots: Vec<String>,
    /// The checked account the scan ran for, for the plan's executor settings.
    pub user_sid: String,
    /// The fingerprint the scan ran with: the broker's own harvest of the session (or its stored copy).
    /// Every plan made from this scan carries it, and the executor checks the plan's system objects
    /// against it (purge_exec::plan_in::unbound_objects).
    pub fingerprint: Arc<Fingerprint>,
    /// The one live plan of this scan, as raw [`purge_rpc::methods::PlanId`] bits (`0`: none). A second
    /// `plan.create` of the same scan is refused until the plan is taken
    /// ([`crate::plan::Plan::release`]).
    live_plan: AtomicU64,
    /// A run of the same program started: this scan describes the machine before it and can no longer
    /// be planned (review M3-R2 S2).
    spent: std::sync::atomic::AtomicBool,
}

impl Scan {
    /// A scan over `doc` and `fingerprint` for a test that seeds the tables.
    #[cfg(test)]
    pub(crate) fn for_test(
        doc: purge_plan::emit::ScanDoc,
        fingerprint: Fingerprint,
        user_sid: &str,
    ) -> Scan {
        Scan {
            program_roots: fingerprint
                .roots
                .iter()
                .map(|root| root.path.clone())
                .collect(),
            app_name: fingerprint.app.display_name.clone(),
            doc,
            mode: ScanMode::Post,
            counts: BandCounts::default(),
            warnings: Vec::new(),
            baseline_trust: BaselineTrust::None,
            session: None,
            program: fingerprint.app.program_id.clone(),
            user_sid: user_sid.to_owned(),
            fingerprint: Arc::new(fingerprint),
            live_plan: AtomicU64::new(0),
            spent: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claims the scan for `plan`, unless another live plan holds it.
    pub fn claim(&self, plan: purge_rpc::methods::PlanId) -> bool {
        self.live_plan
            .compare_exchange(0, plan.bits(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Releases the scan when `plan` is the live plan (a taken plan releases it; an older id does not
    /// take a newer plan's place).
    pub fn release(&self, plan: purge_rpc::methods::PlanId) -> bool {
        self.live_plan
            .compare_exchange(plan.bits(), 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Whether a run of this scan's program has started: the scan describes the machine before it.
    pub fn spent(&self) -> bool {
        self.spent.load(Ordering::SeqCst)
    }

    /// Marks the scan spent (a run of its program started; no plan can be made from it again).
    pub fn spend(&self) {
        self.spent.store(true, Ordering::SeqCst);
    }
}

/// A progress sink for `scan.progress`.
struct ScanProgress<'a, H: FlowHandler> {
    ctx: &'a Ctx<'a, H>,
    done: u64,
    failed: bool,
}

impl<H: FlowHandler> ScanProgress<'_, H> {
    fn line(&mut self, line: &str) {
        if self.failed {
            return;
        }
        self.done += 1;
        let notification =
            purge_rpc::methods::ServerNotification::ScanProgress(purge_rpc::methods::Progress {
                request: self.ctx.request(),
                program_id: None,
                phase: line.to_owned(),
                done: self.done,
                total: None,
            });
        if self.ctx.notify(&notification).is_err() {
            self.failed = true;
        }
    }
}

/// `leftovers.scan`: from a session after an uninstall, or from a stored fingerprint.
pub(crate) fn handle<H: FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: LeftoversScanParams,
) -> Result<Value, ErrorObject> {
    ctx.mark(TimingName::ScanStart);
    let machine = flow.machine();
    let (fingerprint, mode, session) = match params {
        LeftoversScanParams::Session(params) => {
            let session = ctx.tables().sessions.get(params.session_id)?;
            let verify = session.verify_gone();
            let ran_ok = session.ran() && session.uninstaller_ok();
            let mode = if params.forced || !ran_ok || !verify.is_some_and(|v| v.is_passed()) {
                ScanMode::Forced
            } else {
                ScanMode::Post
            };
            (session.fingerprint(), mode, Some(params.session_id))
        }
        LeftoversScanParams::Stored(params) => {
            let fingerprint = machine
                .read_fingerprint(&params.program_id)?
                .ok_or_else(|| gone(IdKind::Program))?;
            (fingerprint, ScanMode::External, None)
        }
    };
    if ctx.cancelled() {
        return Err(ErrorObject::runtime("the request was cancelled"));
    }
    let program_roots: Vec<String> = fingerprint
        .roots
        .iter()
        .map(|root| root.path.clone())
        .collect();
    let scanned = {
        let mut progress = ScanProgress {
            ctx,
            done: 0,
            failed: false,
        };
        pipeline::scan(
            machine.sources(),
            &fingerprint,
            mode,
            None,
            ctx.settings(),
            &mut |line| progress.line(line),
        )
        .map_err(|e| ErrorObject::runtime(e.to_string()))?
    };
    if ctx.cancelled() {
        return Err(ErrorObject::runtime("the request was cancelled"));
    }
    check_unique(&scanned.built.scan)?;
    let counts = band_counts(&scanned.built.scan);
    let warnings: Vec<Warning> = scanned
        .warnings
        .iter()
        .map(|warning| Warning {
            code: warning.code().to_owned(),
            message: warning.message().to_owned(),
        })
        .collect();
    let baseline_trust = scanned.baseline_trust;
    let scan = Scan {
        doc: scanned.built.scan,
        mode,
        counts,
        warnings: warnings.clone(),
        baseline_trust,
        session,
        program: fingerprint.app.program_id.clone(),
        app_name: fingerprint.app.display_name.clone(),
        program_roots,
        user_sid: ctx.user_sid().to_owned(),
        fingerprint: Arc::new(fingerprint),
        live_plan: AtomicU64::new(0),
        spent: std::sync::atomic::AtomicBool::new(false),
    };
    let scan_id = ctx.add_scan(scan)?;
    ctx.mark(TimingName::ScanComplete);
    serde_json::to_value(ScanResult {
        scan_id,
        mode,
        counts,
        baseline_trust,
        warnings,
        timings: ctx.timings(),
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// Refuses a scan document that cannot be served: every id has the wire form, and no two candidates
/// share one (review M3-R1 M2; a selection by id must name exactly one target).
pub(crate) fn check_unique(doc: &purge_plan::emit::ScanDoc) -> Result<(), ErrorObject> {
    let all: Vec<&Candidate> = doc.items.iter().chain(&doc.absorbed).collect();
    for candidate in &all {
        if CandidateRef::try_from(&candidate.id).is_err() {
            return Err(ErrorData::PlanRefused {
                refusals: vec![Refusal {
                    candidate_id: None,
                    reason: format!(
                        "candidate id {:?} is not of the wire form c-<16 hex>; the scan is not served",
                        candidate.id.0
                    ),
                }],
            }
            .into());
        }
    }
    match unique_index(&all, |candidate| &candidate.id) {
        Ok(_) => Ok(()),
        Err(id) => Err(ErrorData::PlanRefused {
            refusals: vec![Refusal {
                candidate_id: CandidateRef::try_from(id).ok(),
                reason: "two candidates of this scan share this id; the scan is not served".into(),
            }],
        }
        .into()),
    }
}

/// Candidates per band, over the scan's top-level items.
fn band_counts(doc: &purge_plan::emit::ScanDoc) -> BandCounts {
    let mut counts = BandCounts::default();
    for candidate in &doc.items {
        let Some(decision) = &candidate.decision else {
            counts.blocked += 1;
            continue;
        };
        match decision.band {
            Band::Safe => counts.safe += 1,
            Band::Likely => counts.likely += 1,
            Band::Weak => counts.weak += 1,
            Band::Blocked => counts.blocked += 1,
        }
        if decision.preselected && decision.band == Band::Safe {
            counts.preselected += 1;
        }
    }
    counts
}

/// `scan.candidates`: one page of the scan's top-level items, in plan order.
pub(crate) fn candidates<H: FlowHandler>(
    ctx: &Ctx<'_, H>,
    params: &CandidatesParams,
) -> Result<Value, ErrorObject> {
    let slot = ctx.tables().scans.get(params.scan_id)?;
    check_unique(&slot.scan.doc)?;
    let total = slot.scan.doc.items.len();
    let start = usize::try_from(params.offset)
        .unwrap_or(usize::MAX)
        .min(total);
    let limit = usize::from(params.limit.get());
    let end = start.saturating_add(limit).min(total);
    let items: Vec<CandidateRow> = slot.scan.doc.items[start..end].iter().map(row).collect();
    serde_json::to_value(CandidatesPage {
        total: u32::try_from(total).unwrap_or(u32::MAX),
        offset: u32::try_from(start).unwrap_or(u32::MAX),
        items,
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// `candidate.explain`: the evidence lines and blockers of one candidate of the scan.
pub(crate) fn explain<H: FlowHandler>(
    ctx: &Ctx<'_, H>,
    params: &ExplainParams,
) -> Result<Value, ErrorObject> {
    let slot = ctx.tables().scans.get(params.scan_id)?;
    check_unique(&slot.scan.doc)?;
    let wanted = CandidateId(params.candidate_id.to_string());
    let candidate = slot
        .scan
        .doc
        .items
        .iter()
        .chain(&slot.scan.doc.absorbed)
        .find(|candidate| candidate.id == wanted)
        .ok_or_else(|| gone(IdKind::Candidate))?;
    let owner = &candidate.owner.display_name;
    let mut evidence = Vec::new();
    for line in &candidate.evidence {
        evidence.extend(explain::evidence_lines(line, owner));
    }
    let blockers = candidate
        .blockers
        .iter()
        .map(explain::blocker_line)
        .collect();
    serde_json::to_value(Explanation {
        candidate_id: params.candidate_id,
        evidence,
        blockers,
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// One `scan.candidates` row.
pub(crate) fn row(candidate: &Candidate) -> CandidateRow {
    let decision = candidate.decision.as_ref();
    CandidateRow {
        candidate_id: CandidateRef::try_from(&candidate.id)
            .expect("check_unique admitted the scan"),
        band: decision.map_or(Band::Blocked, |decision| decision.band),
        kind: item_kind(candidate),
        category: candidate.category,
        display_name: display_name(candidate),
        owner_program: candidate.owner_program.clone(),
        size_bytes: candidate.size_bytes,
        warnings: candidate
            .blockers
            .iter()
            .map(|blocker| Warning {
                code: blocker.name().to_owned(),
                message: explain::blocker_line(blocker),
            })
            .collect(),
        preselected: decision
            .is_some_and(|decision| decision.preselected && decision.band == Band::Safe),
    }
}

/// What kind of item a candidate is, for display.
pub(crate) fn item_kind(candidate: &Candidate) -> ItemKind {
    match &candidate.target {
        Target::Path { .. } => {
            if candidate.child_count.is_some()
                || !candidate.children.is_empty()
                || candidate.action == Action::RemoveDirIfEmpty
            {
                ItemKind::Folder
            } else {
                ItemKind::File
            }
        }
        Target::RegKey { .. } => ItemKind::RegistryKey,
        Target::RegValue { .. } | Target::RegValueChanged { .. } => ItemKind::RegistryValue,
        Target::RegMultiSzSegment { .. } => ItemKind::RegistryData,
        Target::Service { .. } => ItemKind::Service,
        Target::Task { .. } => ItemKind::Task,
        Target::FirewallRule { .. } => ItemKind::FirewallRule,
        Target::AppxPackage { .. } => ItemKind::Package,
    }
}

/// The name a candidate is shown under: a path, `key\value`, or the object's readable name.
pub(crate) fn display_name(candidate: &Candidate) -> String {
    match &candidate.target {
        Target::Path { path } | Target::RegKey { path } | Target::Task { path } => path.clone(),
        Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
            value_name(path, name)
        }
        Target::RegValueChanged { path, name, .. } => value_name(path, name),
        Target::Service { name } => candidate
            .display_name
            .clone()
            .unwrap_or_else(|| name.clone()),
        Target::FirewallRule { id } => candidate.display_name.clone().unwrap_or_else(|| id.clone()),
        Target::AppxPackage { full_name } => full_name.clone(),
    }
}

fn value_name(path: &str, name: &str) -> String {
    if name.is_empty() {
        format!("{path}\\(Default)")
    } else {
        format!("{path}\\{name}")
    }
}
