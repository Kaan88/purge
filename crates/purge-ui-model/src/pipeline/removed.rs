//! "Check for leftovers" on the Programs page's "removed outside Purge" group (the port of
//! `ui/Purge.Client/Pipeline/RemovedLeftovers.cs`, M3 design 7a delta 5, section 10 S1).
//!
//! A program whose fingerprint Purge cannot have stored is [`RemovedCheckState::NoRecord`] from the start
//! (the probe of the fingerprint store by file name, no prompt); for the others the click starts the
//! elevated broker, asks `leftovers.stored`, and scans from the stored fingerprint
//! (`leftovers.scan {program_id}`). Such a scan is always mode `External`; the mode is passed on as it
//! came. The scan goes to the Leftovers page through [`RemovedRequest::Completed`], as after an
//! uninstall.

use std::collections::{HashMap, HashSet};

use purge_model::ProgramId;
use purge_rpc::methods::{ProgramRef, ScanResult};

use super::strings;
use super::{CallError, LaunchResult, LaunchState, NoticeKind};

/// Where a program of the "removed outside Purge" group stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemovedCheckState {
    /// Purge may have stored its fingerprint: "Check for leftovers" is offered.
    Record,
    /// Purge did not record what it installed: no button, no broker, no guess-based scan.
    NoRecord,
    /// The Windows prompt for the administrator part is up (or the part is starting).
    Starting,
    /// The broker is asked `leftovers.stored`.
    Checking,
    /// The broker scans from the stored fingerprint.
    Scanning,
}

/// The programs of the "removed outside Purge" group: what `inventory.changes` listed, less the ones
/// the user has dealt with in this session. A program leaves the group when its "Check for leftovers"
/// finished and reached the Leftovers page, when the user dismisses it, or when Purge itself uninstalled
/// it; the engine is then told (`inventory.forget`), so it does not come back in a later session. A
/// cancelled or failed check keeps it.
#[derive(Debug, Clone, Default)]
pub struct RemovedGroup {
    programs: Vec<ProgramRef>,
}

impl RemovedGroup {
    /// How many rows the group shows at most; the header counts them all.
    pub const MAX_SHOWN: usize = 5;

    /// The group of an `inventory.changes` answer's `disappeared` list (a repeated id is one row).
    pub fn new(disappeared: impl IntoIterator<Item = ProgramRef>) -> Self {
        let mut seen = HashSet::new();
        Self {
            programs: disappeared
                .into_iter()
                .filter(|p| seen.insert(p.program_id.clone()))
                .collect(),
        }
    }

    /// How many programs the group still has.
    pub fn count(&self) -> usize {
        self.programs.len()
    }

    /// True when nothing is left: the page hides the group.
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// The rows to show: the first [`Self::MAX_SHOWN`] still in the group.
    pub fn shown(&self) -> &[ProgramRef] {
        &self.programs[..self.programs.len().min(Self::MAX_SHOWN)]
    }

    /// Whether `program_id` is still in the group.
    pub fn contains(&self, program_id: &ProgramId) -> bool {
        self.programs.iter().any(|p| p.program_id == *program_id)
    }

    /// The group's header: the count, and how many are shown when not all are.
    pub fn header(&self, live: bool) -> String {
        strings::removed_header(self.programs.len(), Self::MAX_SHOWN, live)
    }

    /// Takes `program_id` out of the group; false when it is not in it. On true the caller sends
    /// `inventory.forget` for it (a failure of that is ignored: display-only state).
    pub fn acknowledge(&mut self, program_id: &ProgramId) -> bool {
        match self
            .programs
            .iter()
            .position(|p| p.program_id == *program_id)
        {
            Some(i) => {
                self.programs.remove(i);
                true
            }
            None => false,
        }
    }
}

/// A bar the Programs page shows for the last check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedNotice {
    /// Its severity.
    pub kind: NoticeKind,
    /// The title.
    pub title: String,
    /// The message.
    pub message: String,
}

impl RemovedNotice {
    fn new(kind: NoticeKind, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            message: message.into(),
        }
    }
}

/// A scan from a stored fingerprint, ready for the Leftovers page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredScanOutcome {
    /// The program.
    pub program_id: ProgramId,
    /// Its name as the group showed it.
    pub program_name: String,
    /// The scan.
    pub scan: ScanResult,
}

/// What [`RemovedLeftovers`] asks the UI to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovedRequest {
    /// Start the elevated broker (the first-elevation explanation and the Windows prompt happen there);
    /// answer with [`RemovedLeftovers::on_launch`].
    Launch,
    /// `leftovers.stored {program_ids}` over that broker; answer with [`RemovedLeftovers::on_stored`].
    Stored {
        /// The programs asked about.
        program_ids: Vec<ProgramId>,
    },
    /// `leftovers.scan {program_id}` (the stored fingerprint); feed `scan.progress` to
    /// [`RemovedLeftovers::on_scan_progress`] and answer with [`RemovedLeftovers::on_scan`].
    ScanStored {
        /// The program.
        program_id: ProgramId,
    },
    /// Stop the call in flight (the launch, or the broker's `$/cancel`); its answer comes back as
    /// [`CallError::Cancelled`].
    Cancel,
    /// End the broker: the check is over without a hand-off.
    CloseBroker,
    /// The user said No at the Windows prompt, or "Not now" at Purge's explanation (`declined`).
    AdminPromptCancelled {
        /// "Not now" at Purge's explanation: the Windows prompt was never shown.
        declined: bool,
    },
    /// The scan is in: the Leftovers page takes it with the broker's session (the link is handed over,
    /// not ended).
    Completed(StoredScanOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Launch,
    Stored,
    Scan,
}

/// The "Check for leftovers" controller of the group.
pub struct RemovedLeftovers {
    may_have_record: Box<dyn Fn(&ProgramId) -> bool>,
    states: HashMap<ProgramId, RemovedCheckState>,
    stage: Option<Stage>,
    cancel_asked: bool,
    active: Option<(ProgramId, String)>,
    progress_text: Option<String>,
    notice: Option<RemovedNotice>,
    notice_serial: u64,
}

impl std::fmt::Debug for RemovedLeftovers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemovedLeftovers")
            .field("states", &self.states)
            .field("stage", &self.stage)
            .field("active", &self.active)
            .field("notice", &self.notice)
            .finish_non_exhaustive()
    }
}

impl RemovedLeftovers {
    /// `may_have_record` is false when Purge surely stored no fingerprint for the id (a file-system
    /// lookup by name in `%ProgramData%\Purge\fp`, no prompt; `purge-client` has it).
    pub fn new(may_have_record: impl Fn(&ProgramId) -> bool + 'static) -> Self {
        Self {
            may_have_record: Box::new(may_have_record),
            states: HashMap::new(),
            stage: None,
            cancel_asked: false,
            active: None,
            progress_text: None,
            notice: None,
            notice_serial: 0,
        }
    }

    /// The program being checked, while a check runs.
    pub fn active_program(&self) -> Option<&ProgramId> {
        self.active.as_ref().map(|(id, _)| id)
    }

    /// The broker's last scan phase, while it scans.
    pub fn progress_text(&self) -> Option<&str> {
        self.progress_text.as_deref()
    }

    /// The bar for the last check that did not reach the Leftovers page; `None` when there is none.
    pub fn notice(&self) -> Option<&RemovedNotice> {
        self.notice.as_ref()
    }

    /// Counts the notices set so far, so a page shows each one once.
    pub fn notice_serial(&self) -> u64 {
        self.notice_serial
    }

    /// True while a check runs; the other rows' buttons wait.
    pub fn is_busy(&self) -> bool {
        self.stage.is_some()
    }

    /// Whether the user may dismiss `program_id`: not while its own check runs.
    pub fn can_dismiss(&self, program_id: &ProgramId) -> bool {
        !(self.is_busy() && self.active_program() == Some(program_id))
    }

    /// Probes each id once.
    pub fn classify<'a>(&mut self, program_ids: impl IntoIterator<Item = &'a ProgramId>) {
        for id in program_ids {
            if !self.states.contains_key(id) {
                let state = self.probe(id);
                self.states.insert(id.clone(), state);
            }
        }
    }

    /// The state of `program_id`; an id not classified yet is probed now.
    pub fn state_of(&mut self, program_id: &ProgramId) -> RemovedCheckState {
        self.classify([program_id]);
        self.states[program_id]
    }

    /// The state of `program_id` without probing (`Record` when it was never probed).
    pub fn known_state(&self, program_id: &ProgramId) -> Option<RemovedCheckState> {
        self.states.get(program_id).copied()
    }

    /// Stops the running check (the broker's `$/cancel`); the program keeps its button.
    pub fn cancel(&mut self) -> Vec<RemovedRequest> {
        if !self.is_busy() {
            return vec![];
        }
        self.cancel_asked = true;
        vec![RemovedRequest::Cancel]
    }

    /// The button: for a program with no record it does nothing (no prompt is ever shown for one);
    /// otherwise launch, `leftovers.stored`, then the scan. One check at a time.
    pub fn check(&mut self, program_id: &ProgramId, program_name: &str) -> Vec<RemovedRequest> {
        if self.is_busy() || self.state_of(program_id) == RemovedCheckState::NoRecord {
            return vec![];
        }
        self.stage = Some(Stage::Launch);
        self.cancel_asked = false;
        self.active = Some((program_id.clone(), program_name.to_owned()));
        self.progress_text = None;
        self.notice = None;
        self.set(program_id, RemovedCheckState::Starting);
        vec![RemovedRequest::Launch]
    }

    /// The broker's start. With [`LaunchState::Started`] the UI holds the link.
    pub fn on_launch(&mut self, launch: Result<LaunchResult, CallError>) -> Vec<RemovedRequest> {
        let Some((id, name)) = self.waiting(Stage::Launch) else {
            return vec![];
        };
        let launch = match launch {
            Ok(l) => l,
            Err(CallError::Cancelled) => {
                return self.end_with_error(&id, &name, CallError::Cancelled, false);
            }
            // The launcher's own failure is "could not start", as the WinUI launcher said.
            Err(e) => LaunchResult::of(LaunchState::CannotStart, e.message()),
        };
        if launch.state != LaunchState::Started {
            self.set(&id, RemovedCheckState::Record);
            let mut out = self.launch_failed(&launch);
            out.extend(self.finish(false));
            return out;
        }
        if self.cancel_asked {
            return self.end_with_error(&id, &name, CallError::Cancelled, true);
        }
        self.stage = Some(Stage::Stored);
        self.set(&id, RemovedCheckState::Checking);
        vec![RemovedRequest::Stored {
            program_ids: vec![id],
        }]
    }

    /// The answer of `leftovers.stored`: the asked programs that have a stored fingerprint.
    pub fn on_stored(&mut self, stored: Result<Vec<ProgramId>, CallError>) -> Vec<RemovedRequest> {
        let Some((id, name)) = self.waiting(Stage::Stored) else {
            return vec![];
        };
        match stored {
            Err(e) => self.end_with_error(&id, &name, e, true),
            Ok(stored) if !stored.contains(&id) => {
                self.set(&id, RemovedCheckState::NoRecord);
                self.set_notice(no_record_notice(&name));
                self.finish(true)
            }
            Ok(_) => {
                self.stage = Some(Stage::Scan);
                self.set(&id, RemovedCheckState::Scanning);
                self.progress_text = Some(strings::REMOVED_SCAN_STARTING.into());
                vec![RemovedRequest::ScanStored { program_id: id }]
            }
        }
    }

    /// A `scan.progress` of the stored scan: its phase.
    pub fn on_scan_progress(&mut self, phase: &str) {
        if self.stage == Some(Stage::Scan) {
            self.progress_text = Some(phase.to_owned());
        }
    }

    /// The answer of the stored scan.
    pub fn on_scan(&mut self, scan: Result<ScanResult, CallError>) -> Vec<RemovedRequest> {
        let Some((id, name)) = self.waiting(Stage::Scan) else {
            return vec![];
        };
        match scan {
            Err(e) => self.end_with_error(&id, &name, e, true),
            Ok(scan) => {
                self.set(&id, RemovedCheckState::Record);
                let mut out = vec![RemovedRequest::Completed(StoredScanOutcome {
                    program_id: id,
                    program_name: name,
                    scan,
                })];
                // The session went to the Leftovers page with the outcome: nothing to close.
                out.extend(self.finish(false));
                out
            }
        }
    }

    fn waiting(&self, stage: Stage) -> Option<(ProgramId, String)> {
        if self.stage == Some(stage) {
            self.active.clone()
        } else {
            None
        }
    }

    fn end_with_error(
        &mut self,
        id: &ProgramId,
        name: &str,
        error: CallError,
        close: bool,
    ) -> Vec<RemovedRequest> {
        match &error {
            CallError::Cancelled => {
                self.set(id, RemovedCheckState::Record);
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Info,
                    strings::REMOVED_STOPPED_TITLE,
                    strings::REMOVED_STOPPED_MESSAGE,
                ));
            }
            CallError::Rpc(_) if error.kind() == Some("gone") => {
                // The broker has no fingerprint for it (removed meanwhile, or another account's program).
                self.set(id, RemovedCheckState::NoRecord);
                self.set_notice(no_record_notice(name));
            }
            CallError::Rpc(e) => {
                self.set(id, RemovedCheckState::Record);
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Error,
                    strings::REFUSED_TITLE,
                    e.message.clone(),
                ));
            }
            CallError::Link(m) => {
                self.set(id, RemovedCheckState::Record);
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Error,
                    strings::BROKER_ENDED_TITLE,
                    format!("{m}{}", strings::REMOVED_LINK_TAIL),
                ));
            }
            CallError::Other(m) => {
                self.set(id, RemovedCheckState::Record);
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Error,
                    strings::WENT_WRONG_TITLE,
                    m.clone(),
                ));
            }
        }
        self.finish(close)
    }

    fn launch_failed(&mut self, launch: &LaunchResult) -> Vec<RemovedRequest> {
        match launch.state {
            LaunchState::Cancelled => {
                // The page's own bar says it; the program keeps its button for another try.
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Info,
                    strings::REMOVED_NOT_GIVEN_TITLE,
                    if launch.declined_explanation {
                        strings::REMOVED_NOT_NOW_MESSAGE
                    } else {
                        strings::REMOVED_PROMPT_CANCELLED_MESSAGE
                    },
                ));
                vec![RemovedRequest::AdminPromptCancelled {
                    declined: launch.declined_explanation,
                }]
            }
            LaunchState::NotAdministrator => {
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Error,
                    strings::NOT_ADMIN_TITLE,
                    launch.message.clone(),
                ));
                vec![]
            }
            _ => {
                let code = launch
                    .exit_code
                    .map(|c| format!(" (exit code {c})"))
                    .unwrap_or_default();
                self.set_notice(RemovedNotice::new(
                    NoticeKind::Error,
                    strings::CANNOT_START_TITLE,
                    format!("{}{code}", launch.message),
                ));
                vec![]
            }
        }
    }

    fn finish(&mut self, close: bool) -> Vec<RemovedRequest> {
        self.stage = None;
        self.cancel_asked = false;
        self.active = None;
        self.progress_text = None;
        if close {
            vec![RemovedRequest::CloseBroker]
        } else {
            vec![]
        }
    }

    fn set_notice(&mut self, notice: RemovedNotice) {
        self.notice = Some(notice);
        self.notice_serial += 1;
    }

    fn probe(&self, id: &ProgramId) -> RemovedCheckState {
        if (self.may_have_record)(id) {
            RemovedCheckState::Record
        } else {
            RemovedCheckState::NoRecord
        }
    }

    fn set(&mut self, id: &ProgramId, state: RemovedCheckState) {
        self.states.insert(id.clone(), state);
    }
}

/// The bar after an approved prompt that ended without a record (`leftovers.stored` did not list the
/// program, or `gone`): the user said yes to a prompt, so the page says why nothing followed.
fn no_record_notice(program_name: &str) -> RemovedNotice {
    RemovedNotice::new(
        NoticeKind::Info,
        strings::no_record_title(program_name),
        strings::NO_RECORD_MESSAGE,
    )
}

#[cfg(test)]
mod tests;
