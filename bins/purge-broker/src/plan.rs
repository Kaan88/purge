//! `plan.create` (M3 design 3.6, 6.3; package M3-BROKER-FLOW).
//!
//! The broker builds the plan from **its own** scan document and the candidate ids the client selected.
//! Nothing else crosses from the client: no path, no target, no document. An id that is not a
//! top-level item of that scan is refused with a reason ([`ErrorData::PlanRefused`]), and an item the
//! executor cannot act on is refused the same way, all in one list.
//!
//! The broker computes the confirmation itself ([`plan_in::confirm_hash`]) and calls
//! [`plan_in::bind`], which checks the plan hash, the structure, every selected item and the confirm.
//! The resulting [`BoundPlan`] is frozen behind an `Arc` in the plan table, together with the short
//! code the dialog shows. `plan.execute` draws the dialog from that object and runs that object; it
//! derives nothing again ("what consent shows is what runs").
//!
//! # One plan per scan
//!
//! A scan carries at most one live plan. A second `plan.create` of the same scan is refused until the
//! first plan is taken (`plan.execute` takes it, so a declined dialog can be followed by a new plan
//! from the same scan; see [`Plan::release`]). A plan id in the table is used once: `plan.execute`
//! takes it, and a used id is `gone`.

use std::sync::Arc;

use purge_exec::plan_in::{self, BoundPlan, ExecRequest, ExecSettings, PlanRefusal, Selection};
use purge_model::exec::op::Sha256Hex;
use purge_model::{Band, Candidate, CandidateId, Fingerprint, ProgramId};
use purge_rpc::error::{ErrorData, ErrorObject, Refusal};
use purge_rpc::methods::{
    AttentionItem, AttentionReason, CandidateRef, ConfirmCode, PlanCounts, PlanCreateParams,
    PlanCreated, PlanId, ScanId, UninstallSessionId, Warning,
};
use purge_rpc::timing::TimingName;
use serde_json::Value;

use crate::consent::view::{self, Facts, Reason};
use crate::scan::{Scan, check_unique, display_name, item_kind};
use crate::serve::Ctx;
use crate::session::Tables;
use crate::uninstall::{Flow, Session};

/// The tables of the broker's flow handler.
type FlowTables = Tables<Session, Scan, Plan>;

/// One plan in the broker's memory: the frozen bound plan and what the UI needs.
pub struct Plan {
    /// The scan it was created from (and whose claim it holds).
    pub scan_id: ScanId,
    /// The uninstall session the scan came from, when it came from one.
    pub session: Option<UninstallSessionId>,
    /// The program the plan acts on: a run spends every scan of it (review M3-R2 S2).
    pub program: ProgramId,
    /// The executor settings the broker decided when the plan was made (the account, the program roots).
    pub settings: ExecSettings,
    /// The program's name as the scan's fingerprint has it, for the dialog.
    pub app_name: String,
    /// The scan's fingerprint, frozen with the plan: the object binding of the run.
    pub fingerprint: Arc<Fingerprint>,
    /// The frozen plan: the same object the dialog is drawn from and the executor runs.
    pub bound: Arc<BoundPlan>,
    /// The short code of the confirm hash, `A1B2-C3D4`.
    pub code: ConfirmCode,
    /// Selected item counts.
    pub counts: PlanCounts,
    /// Bytes the plan moves to quarantine.
    pub bytes: u64,
    /// Items that need attention (never cut).
    pub attention: Vec<AttentionItem>,
    /// The scan's warnings.
    pub warnings: Vec<Warning>,
}

impl Plan {
    /// The bound plan.
    pub fn bound(&self) -> &BoundPlan {
        &self.bound
    }

    /// Gives the scan its next plan, once this plan has been taken for execution. `id` is the table key
    /// the plan was taken with; an older id does not release a newer plan.
    pub fn release(&self, tables: &FlowTables, id: PlanId) -> bool {
        tables
            .scans
            .get(self.scan_id)
            .is_ok_and(|slot| slot.scan.release(id))
    }
}

/// `plan.create`: one of the two forms of [`PlanCreateParams`].
pub(crate) fn create<H: crate::uninstall::FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: PlanCreateParams,
) -> Result<Value, ErrorObject> {
    let (scan_id, selection, allow_irreversible) = match params {
        PlanCreateParams::Selected(params) => (
            params.scan_id,
            Selection::Ids(
                params
                    .selected
                    .as_slice()
                    .iter()
                    .map(|id| CandidateId(id.to_string()))
                    .collect(),
            ),
            params.allow_irreversible,
        ),
        // The scan's preselection never holds a removal without an undo, so there is nothing to offer.
        PlanCreateParams::Preselected(params) => (params.scan_id, Selection::Preselected, false),
    };
    let slot = ctx.tables().scans.get(scan_id)?;
    let scan = &slot.scan;
    if scan.spent() {
        return Err(plan_refused(vec![Refusal {
            candidate_id: None,
            reason: "the program of this scan was already uninstalled; scan again".into(),
        }]));
    }
    if let Some(session) = scan.session
        && ctx.tables().sessions.get(session).is_err()
    {
        return Err(plan_refused(vec![Refusal {
            candidate_id: None,
            reason: "the uninstall session of this scan is gone; scan again".into(),
        }]));
    }
    check_unique(&scan.doc)?;

    // The ids this request names, in the selection's own order (the hash sorts them).
    let mut ids: Vec<CandidateId> = match &selection {
        Selection::Ids(ids) => ids.clone(),
        Selection::Preselected => scan
            .doc
            .items
            .iter()
            .filter(|candidate| is_preselected(candidate))
            .map(|candidate| candidate.id.clone())
            .collect(),
    };
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(plan_refused(vec![Refusal {
            candidate_id: None,
            reason: "nothing is selected: the scan preselects no item".into(),
        }]));
    }

    // Every id must be a top-level item of *this* scan. Absorbed candidates ride with their parent.
    let mut refusals = Vec::new();
    for id in &ids {
        if scan.doc.items.iter().any(|candidate| &candidate.id == id) {
            continue;
        }
        let absorbed = scan
            .doc
            .absorbed
            .iter()
            .any(|candidate| &candidate.id == id);
        refusals.push(Refusal {
            candidate_id: CandidateRef::try_from(id).ok(),
            reason: if absorbed {
                "it is an absorbed child; select its parent".into()
            } else {
                "it is not an item of this scan".into()
            },
        });
    }
    if !refusals.is_empty() {
        return Err(plan_refused(refusals));
    }

    let plan_hash: Sha256Hex = scan.doc.plan_hash.parse().map_err(|_| {
        plan_refused(vec![Refusal {
            candidate_id: None,
            reason: PlanRefusal::PlanHashForm(scan.doc.plan_hash.clone()).to_string(),
        }])
    })?;
    let settings = ExecSettings {
        user_sid: Some(scan.user_sid.clone()),
        program_roots: scan.program_roots.clone(),
        ..ExecSettings::default()
    };

    // Bind, and collect every item that cannot be acted on rather than only the first one. The
    // confirmation is computed over the ids as they stand: the broker never takes one from the client.
    let mut current = ids;
    let mut refused = Vec::new();
    let mut bound = None;
    let mut confirm = None;
    loop {
        let selection_hash = plan_in::selection_hash(current.iter());
        let request = ExecRequest {
            scan: scan.doc.clone(),
            confirm: plan_in::confirm_hash(plan_hash, selection_hash).to_string(),
            selection: Selection::Ids(current.clone()),
            allow_irreversible,
            settings: settings.clone(),
        };
        match plan_in::bind(&request) {
            Ok(bound_now) => {
                confirm = Some(plan_in::confirm_hash(plan_hash, selection_hash));
                bound = Some(bound_now);
                break;
            }
            Err(PlanRefusal::NotSelectable { id, why }) => {
                refused.push(refusal_of(PlanRefusal::NotSelectable {
                    id: id.clone(),
                    why: why.clone(),
                }));
                current.retain(|candidate| candidate != &id);
                if current.is_empty() {
                    break;
                }
            }
            Err(other) => return Err(plan_refused(vec![refusal_of(other)])),
        }
    }
    let (Some(bound), Some(confirm)) = (bound, confirm) else {
        return Err(plan_refused(refused));
    };
    if !refused.is_empty() {
        return Err(plan_refused(refused));
    }

    // The scan's own fingerprint must vouch for every system object the plan removes: the same check
    // execute_bound makes, so a plan the executor would refuse is never offered.
    let unbound = plan_in::unbound_objects(&bound, &scan.fingerprint);
    if !unbound.is_empty() {
        return Err(plan_refused(
            unbound
                .into_iter()
                .map(|id| Refusal {
                    candidate_id: CandidateRef::try_from(&CandidateId(id)).ok(),
                    reason: "the fingerprint of this scan does not record this system object as the program's, with the digest the scan saw"
                        .into(),
                })
                .collect(),
        ));
    }

    // Items the executor cannot quarantine, and a plan that would pass a volume's cap, are refused
    // here, before a plan id exists.
    let selected: Vec<&Candidate> = bound
        .items()
        .iter()
        .filter_map(|item| bound.candidate(item))
        .collect();
    let unstorable = flow.machine().unstorable(&selected)?;
    if !unstorable.is_empty() {
        return Err(plan_refused(unstorable));
    }

    // The review page and the dialog must list the same attention items: both come from the one view
    // model, over the same frozen plan.
    let consent = view::view(
        &bound,
        &Facts {
            app_name: scan.app_name.clone(),
            restorable_until: None,
            restore_point: false,
        },
    )
    .map_err(|error| {
        plan_refused(vec![Refusal {
            candidate_id: None,
            reason: error.to_string(),
        }])
    })?;
    if !consent.describes_plan(&bound) {
        return Err(ErrorObject::runtime(
            "the consent view does not describe this plan",
        ));
    }
    let counts = plan_counts(&bound);
    let bytes = consent.counts.bytes;
    let attention: Vec<AttentionItem> = consent
        .attention
        .iter()
        .filter_map(|entry| attention_item(&bound, entry))
        .collect();
    let code = ConfirmCode::of(&confirm);
    let plan_hash = bound.plan_hash();
    let plan = Plan {
        scan_id,
        session: scan.session,
        program: scan.program.clone(),
        settings,
        app_name: scan.app_name.clone(),
        fingerprint: scan.fingerprint.clone(),
        bound: Arc::new(bound),
        code,
        counts,
        bytes,
        attention: attention.clone(),
        warnings: scan.warnings.clone(),
    };
    let plan_id = ctx.tables().plans.insert(plan)?;
    if !scan.claim(plan_id) {
        ctx.tables().plans.remove(plan_id);
        return Err(plan_refused(vec![Refusal {
            candidate_id: None,
            reason: "a plan of this scan exists already; execute it or scan again".into(),
        }]));
    }
    ctx.mark(TimingName::PlanReady);
    serde_json::to_value(PlanCreated {
        plan_id,
        plan_hash,
        code,
        counts,
        bytes,
        attention,
        warnings: scan.warnings.clone(),
        timings: ctx.timings(),
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

fn is_preselected(candidate: &Candidate) -> bool {
    candidate
        .decision
        .as_ref()
        .is_some_and(|decision| decision.band == Band::Safe && decision.preselected)
}

fn plan_refused(refusals: Vec<Refusal>) -> ErrorObject {
    ErrorObject::server(ErrorData::PlanRefused { refusals })
}

fn refusal_of(refusal: PlanRefusal) -> Refusal {
    let id = match &refusal {
        PlanRefusal::DuplicateId(id)
        | PlanRefusal::UnknownId(id)
        | PlanRefusal::AbsorbedSelected(id) => Some(id),
        PlanRefusal::NotSelectable { id, .. } => Some(id),
        PlanRefusal::ChildMissing { parent, .. } | PlanRefusal::ChildOutside { parent, .. } => {
            Some(parent)
        }
        _ => None,
    };
    Refusal {
        candidate_id: id.and_then(|id| CandidateRef::try_from(id).ok()),
        reason: refusal.to_string(),
    }
}

fn plan_counts(bound: &BoundPlan) -> PlanCounts {
    let mut counts = PlanCounts {
        items: u32::try_from(bound.items().len()).unwrap_or(u32::MAX),
        preselected: 0,
        ticked: 0,
    };
    for item in bound.items() {
        if bound.candidate(item).is_some_and(is_preselected) {
            counts.preselected += 1;
        }
    }
    counts.ticked = counts.items.saturating_sub(counts.preselected);
    counts
}

/// One attention entry of the consent view, as the review page's row. The entry's id names a top-level
/// item or an absorbed one (an absorbed child is listed on its own and goes with its parent).
fn attention_item(bound: &BoundPlan, entry: &view::Entry) -> Option<AttentionItem> {
    let candidate = bound
        .scan()
        .items
        .iter()
        .chain(&bound.scan().absorbed)
        .find(|candidate| candidate.id.0 == entry.id)?;
    let reasons: Vec<AttentionReason> = entry
        .reasons
        .iter()
        .filter_map(|reason| match reason {
            Reason::UserData => Some(AttentionReason::UserData),
            Reason::NotChosen => Some(AttentionReason::NotPreselected),
            Reason::Large => Some(AttentionReason::Large),
            Reason::Irreversible => Some(AttentionReason::NoUndo),
            Reason::Inside => Some(AttentionReason::Inside),
            Reason::EscapedName | Reason::ShortenedName | Reason::LookAlikeName => {
                Some(AttentionReason::Name)
            }
            Reason::Conflict(_) => None,
        })
        .collect();
    Some(AttentionItem {
        candidate_id: CandidateRef::try_from(&candidate.id).ok()?,
        display_name: display_name(candidate),
        kind: item_kind(candidate),
        band: candidate
            .decision
            .as_ref()
            .map_or(Band::Blocked, |decision| decision.band),
        size_bytes: candidate.size_bytes,
        reasons,
    })
}
