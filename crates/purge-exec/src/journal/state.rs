//! The journal's rules as a state machine: what a session looks like after each record, and which record
//! may come next.

use std::collections::{BTreeMap, BTreeSet};

use purge_model::exec::journal::{
    Aborted, Commit, GateExemptions, Header, Intent, ItemFacts, MAX_GROUP_INTENTS, Reconcile,
    ReconcileResult, Record, RetryIntent, RunSettings, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ItemOutcome, OpId, OutcomeCounts, Sha256Hex};
use purge_model::exec::session::{JournalMark, RetentionClass, SessionId};
use purge_model::{CandidateId, Target};

/// A record that breaks the journal's rules. The reader refuses the journal; the writer refuses the record
/// and writes nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// The first record is not a `header`.
    #[error("the first record is not a header")]
    HeaderNotFirst,
    /// A second `header`.
    #[error("a second header")]
    DuplicateHeader,
    /// A record of the run (`validated`, `intent`, `done`, `group_end`, `commit`, `aborted`) after `commit`
    /// or `aborted`.
    #[error("a {0} record after the run ended")]
    AfterFinish(&'static str),
    /// A `validated` record after the first `intent` or `done`.
    #[error("op {0}: validated after the run started")]
    ValidatedAfterStart(OpId),
    /// An op id outside 1 to `header.items`.
    #[error("op {0} is outside the header's item count")]
    OpOutOfRange(OpId),
    /// A second `validated` record for an op.
    #[error("op {0} validated twice")]
    DuplicateValidated(OpId),
    /// The run started (or committed) before every item was validated.
    #[error("{validated} of {items} items validated when the run started or committed")]
    NotAllValidated {
        /// The header's item count.
        items: u32,
        /// How many were validated.
        validated: u32,
    },
    /// A record for an op that was never validated.
    #[error("op {0} was never validated")]
    UnknownOp(OpId),
    /// The record's candidate id differs from the op's `validated` record.
    #[error("op {0}: candidate id differs from its validated record")]
    ItemMismatch(OpId),
    /// The intent's op acts on another target than the op's `validated` record.
    #[error("op {0}: intent target differs from its validated record")]
    TargetMismatch(OpId),
    /// The intent's inverse does not fit its op, or a backup path leaves the session directory.
    #[error("op {0}: intent is not consistent")]
    InconsistentIntent(OpId),
    /// A second `intent` for an op.
    #[error("op {0}: second intent")]
    DuplicateIntent(OpId),
    /// An `intent` after the op's `done`.
    #[error("op {0}: intent after done")]
    IntentAfterDone(OpId),
    /// A second `done` for an op.
    #[error("op {0}: second done")]
    DuplicateDone(OpId),
    /// A `done` without an intent, with an outcome that needs one (`Done`, `HeldRetry`, `PendingReboot`).
    #[error("op {0}: done without intent, with an outcome that needs one")]
    DoneWithoutIntent(OpId),
    /// An `intent` while the open group already holds [`MAX_GROUP_INTENTS`] intents.
    #[error("op {0}: intent in a full group")]
    GroupFull(OpId),
    /// A `group_end` with no intent since the previous one.
    #[error("group_end with no intent in the group")]
    EmptyGroup,
    /// A `group_end` whose number or count does not match the journal.
    #[error(
        "group_end {group} with {ops} ops; expected group {expected_group} with {expected_ops}"
    )]
    GroupMismatch {
        /// The group number the journal is at.
        expected_group: u32,
        /// The intents since the previous `group_end`.
        expected_ops: u32,
        /// The record's group number.
        group: u32,
        /// The record's count.
        ops: u32,
    },
    /// `commit` while intents are not closed by a `group_end`.
    #[error("commit with an open group")]
    OpenGroup,
    /// `commit` while an op has no `done`.
    #[error("commit while op {0} has no done")]
    MissingDone(OpId),
    /// `commit` counts differ from the `done` records.
    #[error("commit counts differ from the done records")]
    CountsMismatch,
    /// An undo record for an op that has neither an intent nor a done, or an `undo_intent` for an op
    /// without an intent (nothing that could have changed the system).
    #[error("op {0}: nothing to undo")]
    UndoNotApplicable(OpId),
    /// An undo record for an op whose undo already settled (restored, already restored, nothing to undo).
    #[error("op {0}: undo already settled")]
    UndoSettled(OpId),
    /// An `undo_done` without an open `undo_intent`, with an outcome that needs one (`Restored`, `Failed`).
    #[error("op {0}: undo_done without undo_intent, with an outcome that needs one")]
    UndoDoneWithoutIntent(OpId),
    /// The writer was given an undo token for an op whose undo is not in progress.
    #[error("op {0}: no undo in progress")]
    UndoNotInProgress(OpId),
    /// The writer was asked to end an op without its token while its intent is open; use the token.
    #[error("op {0}: has an open intent, use its token")]
    TokenRequired(OpId),
    /// The writer was given a token another writer issued.
    #[error("op {0}: token from another journal writer")]
    ForeignToken(OpId),
    /// A `reconcile` for an op that is not pending.
    #[error("op {0}: reconcile for an op that is not pending")]
    NotPending(OpId),
    /// A `reconcile` result that does not fit the kind of pending op (`Retried` is for held items, the
    /// others for boot-time moves).
    #[error("op {0}: reconcile result does not fit the pending op")]
    ReconcileMismatch(OpId),
    /// An `expire` before `commit` or `aborted`.
    #[error("op {0}: expire before the run ended")]
    ExpireBeforeFinish(OpId),
    /// An `expire` for an op without an intent (it has no kept data).
    #[error("op {0}: expire for an op without intent")]
    ExpireWithoutIntent(OpId),
    /// A second `expire` of the same class for an op.
    #[error("op {0}: expired twice")]
    DuplicateExpire(OpId),
    /// A `settings` record anywhere but right after the header, or a second one.
    #[error("a settings record that does not follow the header directly")]
    SettingsMisplaced,
    /// A `retry_intent` for an op that is not held for a retry (its outcome, as changed by its
    /// reconcile records, is not `HeldRetry`), or before the run ended.
    #[error("op {0}: retry of an op that is not held")]
    RetryNotHeld(OpId),
    /// A `retry_intent`, undo or expire record while a retry of the op is in flight (a `retry_intent`
    /// with no `reconcile` after it): the retry may have moved the item.
    #[error("op {0}: a retry of the op is in flight")]
    RetryInFlight(OpId),
    /// The writer was given a retry token for an op whose retry is not in flight, or asked to write a
    /// `Retried` result without a retry token.
    #[error("op {0}: no retry in flight")]
    RetryNotInFlight(OpId),
    /// An `undo_intent` for an op whose kept data expiry deleted (an `expire` record of any class):
    /// the inverse has nothing to restore from. An `undo_conflict` may still record that.
    #[error("op {0}: undo after its data expired")]
    UndoAfterExpire(OpId),
    /// An `expire` while the op's undo is in progress: the inverse may still need the data.
    #[error("op {0}: expire while its undo is in progress")]
    ExpireDuringUndo(OpId),
}

/// Where a run stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// After the header: `validated` records are coming; no op started.
    Validating,
    /// At least one `intent` or `done` was written; no `commit` or `aborted` yet.
    Running,
    /// The run ended with `commit`.
    Committed,
    /// The run ended with `aborted`.
    Aborted,
}

/// Where the undo of one op stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoState {
    /// No undo record for the op.
    NotStarted,
    /// An `undo_intent` with no `undo_done` or `undo_conflict` after it: the inverse may have run in part.
    InProgress,
    /// The last undo attempt ended with this `undo_done`.
    Finished(UndoOutcome),
    /// The last undo attempt ended with this `undo_conflict`.
    Conflict(UndoConflict),
}

impl UndoState {
    /// Whether the undo has settled for good: restored, already restored, or nothing to undo. A failed or
    /// conflicting attempt may be tried again.
    pub fn is_settled(&self) -> bool {
        matches!(
            self,
            UndoState::Finished(
                UndoOutcome::Restored | UndoOutcome::AlreadyRestored | UndoOutcome::NothingToUndo
            )
        )
    }
}

/// What an op is waiting for after its run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pending {
    /// A boot-time move is registered (`PendingReboot`).
    Reboot,
    /// The item is held for the next Purge run (`HeldRetry`).
    Held,
}

/// The run status of one op, as the spec of recovery reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpStatus<'a> {
    /// Validated; neither intent nor done.
    Validated,
    /// An intent with no done: the action may have run, in full, in part or not at all. Recovery probes.
    IntentOnly,
    /// A done record, with or without an intent before it.
    Done(&'a ItemOutcome),
}

/// Everything the journal says about one op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpState {
    /// The op id.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// What the item acts on.
    pub target: Target,
    /// What the item looked like when validated.
    pub facts: ItemFacts,
    /// The exemptions the gate applied to the item when it was validated (the `validated` record's).
    /// Undo and recovery pass exactly these to the gate; see [`OpState::validated`].
    pub exemptions: GateExemptions,
    /// The intent, when one was written.
    pub intent: Option<Intent>,
    /// The outcome of the `done` record, when one was written; for an unconfirmed registry op that
    /// recovery's re-probe did not find done, the outcome of its `reconcile` `Retried` instead.
    pub outcome: Option<ItemOutcome>,
    /// The results of the `reconcile` records for the op, in order.
    pub reconciles: Vec<ReconcileResult>,
    /// Where its undo stands.
    pub undo: UndoState,
    /// How many `undo_intent` records the op has.
    pub undo_attempts: u32,
    /// The retention classes of its data that expiry deleted.
    pub expired: Vec<RetentionClass>,
    /// Whether a retry of the held item is in flight: a `retry_intent` with no `reconcile` after it.
    /// The retry may have moved the item; recovery probes it and ends it with the token of
    /// `JournalWriter::resume_retry`.
    pub retry_in_flight: bool,
}

impl OpState {
    /// The op's journal `validated` record, as written: what undo and recovery hand to
    /// `GateCtx::record` (and whose exemptions they pass to the undo gates) instead of reading the
    /// records again.
    pub fn validated(&self) -> Validated {
        Validated {
            op: self.op,
            item: self.item.clone(),
            target: self.target.clone(),
            facts: self.facts.clone(),
            exemptions: self.exemptions,
        }
    }

    /// The reconcile result that left the op needing the user's attention
    /// ([`ReconcileResult::needs_attention`]: an object kept in quarantine that is not the recorded
    /// one, or an item lost), when the last of its reconcile records is one.
    pub fn attention(&self) -> Option<&ReconcileResult> {
        self.reconciles
            .last()
            .filter(|result| result.needs_attention())
    }

    /// Validated, intent only, or done.
    pub fn status(&self) -> OpStatus<'_> {
        match (&self.intent, &self.outcome) {
            (_, Some(outcome)) => OpStatus::Done(outcome),
            (Some(_), None) => OpStatus::IntentOnly,
            (None, None) => OpStatus::Validated,
        }
    }

    /// What the op is still waiting for: its done outcome (`PendingReboot` or `HeldRetry`) as changed by
    /// its reconcile records, and nothing once its undo settled.
    pub fn pending(&self) -> Option<Pending> {
        if self.undo.is_settled() {
            return None;
        }
        let mut pending = pending_of(self.outcome.as_ref()?);
        for result in &self.reconciles {
            pending = match result {
                ReconcileResult::StillPending => pending,
                ReconcileResult::Completed
                | ReconcileResult::MismatchMovedBack
                | ReconcileResult::Cancelled
                | ReconcileResult::NotMoved { .. }
                | ReconcileResult::MismatchKept { .. }
                | ReconcileResult::Lost { .. } => None,
                ReconcileResult::Retried { outcome } => pending_of(outcome),
            };
        }
        pending
    }
}

/// Takes one `outcome` out of `counts` (the inverse of `OutcomeCounts::record`).
fn uncount(counts: &mut OutcomeCounts, outcome: &ItemOutcome) {
    let slot = match outcome {
        ItemOutcome::Done => &mut counts.done,
        ItemOutcome::Vanished => &mut counts.vanished,
        ItemOutcome::Skipped { .. } => &mut counts.skipped,
        ItemOutcome::HeldRetry => &mut counts.held_retry,
        ItemOutcome::PendingReboot { .. } => &mut counts.pending_reboot,
        // M1b: wired by M1B-X-INTEG (counted with the pending reboots, as `OutcomeCounts::record` does)
        ItemOutcome::PendingDelete => &mut counts.pending_reboot,
        ItemOutcome::Failed { .. } => &mut counts.failed,
    };
    *slot = slot.saturating_sub(1);
}

/// The pending kind an outcome stands for.
fn pending_of(outcome: &ItemOutcome) -> Option<Pending> {
    match outcome {
        ItemOutcome::PendingReboot { .. } => Some(Pending::Reboot),
        ItemOutcome::HeldRetry => Some(Pending::Held),
        _ => None,
    }
}

/// A session as its journal describes it so far.
///
/// Built from the header and fed every following record with [`JournalState::apply`], which refuses a
/// record that breaks the rules and then leaves the state unchanged. The rules of the run are listed in
/// the [module docs](crate::journal). The later records follow these:
///
/// - `undo_intent`: the op has an intent, its undo has not settled and none of its data expired
///   ([`Violation::UndoAfterExpire`]). A second `undo_intent` while one is open is allowed (an undo
///   restarted after a crash).
/// - `undo_done`: after an open `undo_intent`, any outcome; without one, only `NothingToUndo` or
///   `AlreadyRestored`, for an op with an intent or a done. Not after the undo settled.
/// - `undo_conflict`: ends the op's undo with or without an `undo_intent` before it, for an op with an
///   intent or a done; not after the undo settled. Failed and conflicting undos may be tried again.
/// - `reconcile`: the op is pending ([`OpState::pending`]); `Retried` only for a held item, the other
///   results only for a boot-time move. `NotMoved`, `MismatchKept` and `Lost` end the boot move's pending state like
///   `Completed` does; the last two leave the op needing attention ([`OpState::attention`]).
///   Recovery's re-probe also writes `Retried` for an unconfirmed op ([`JournalState::unconfirmed`])
///   while the run is open, with an outcome other than `Done`, `HeldRetry` and `PendingReboot`: that
///   outcome replaces the op's `Done` (in [`OpState::outcome`] and in the counts), and the op is no
///   longer unconfirmed.
/// - `retry_intent`: after `commit` or `aborted`, for a held op ([`Pending::Held`]) with no retry in
///   flight ([`Violation::RetryNotHeld`], [`Violation::RetryInFlight`]). The `reconcile` with
///   `Retried` that follows ends the retry; its outcome replaces `HeldRetry`. A `Retried` without a
///   `retry_intent` before it is still read (journals from before the record existed), but the
///   writer no longer writes one.
/// - While a retry is in flight, no undo record, no second `retry_intent` and no `expire` is accepted
///   for the op.
/// - `settings`: only right after the header, once ([`Violation::SettingsMisplaced`]).
/// - `undo_plan`: anywhere after the header; every op it names must be known. It replaces the plan
///   before it; the ops it names that get no undo record afterwards are
///   [`JournalState::undo_unfinished`]. Journals written before the record existed hold none, and
///   recovery then finishes only the undos in progress.
/// - `expire`: after `commit` or `aborted`, for an op with an intent, once per retention class, not
///   while the op's undo is in progress ([`Violation::ExpireDuringUndo`]).
///
/// Undo and reconcile records may also come before `commit` or `aborted` (a crash rollback ends with
/// `aborted` and reason `RolledBack`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalState {
    header: Header,
    settings: Option<RunSettings>,
    lines: u64,
    head: [u8; 32],
    phase: Phase,
    commit: Option<Commit>,
    aborted: Option<Aborted>,
    ops: BTreeMap<OpId, OpState>,
    groups_closed: u32,
    open_group_intents: u32,
    open_intents: u32,
    counts: OutcomeCounts,
    /// The free text of each op's last `undo_conflict`, while that conflict is where its undo stands.
    conflict_details: BTreeMap<OpId, String>,
    /// The ops of the last `undo_plan`, in order, and those of them an undo record was written for
    /// since.
    undo_plan: Option<(Vec<OpId>, BTreeSet<OpId>)>,
    /// Registry ops whose `done` (`Done`) came after the last `group_end` that vouches for the
    /// registry (`registry_flushed`), `commit` or `aborted`: see [`JournalState::unconfirmed`].
    unconfirmed: BTreeSet<OpId>,
}

impl JournalState {
    /// The state right after `header`.
    pub(super) fn new(header: Header) -> Self {
        JournalState {
            header,
            settings: None,
            lines: 0,
            head: [0; 32],
            phase: Phase::Validating,
            commit: None,
            aborted: None,
            ops: BTreeMap::new(),
            groups_closed: 0,
            open_group_intents: 0,
            open_intents: 0,
            counts: OutcomeCounts::default(),
            conflict_details: BTreeMap::new(),
            undo_plan: None,
            unconfirmed: BTreeSet::new(),
        }
    }

    /// The free text of the `undo_conflict` record that op `op`'s undo stands at
    /// ([`UndoState::Conflict`]); `None` when its undo is not in conflict. Empty when the record held
    /// none.
    pub fn undo_conflict_detail(&self, op: OpId) -> Option<&str> {
        match self.ops.get(&op).map(|s| &s.undo) {
            Some(UndoState::Conflict(_)) => {
                Some(self.conflict_details.get(&op).map_or("", String::as_str))
            }
            _ => None,
        }
    }

    /// The ops of the last `undo_plan` record, in undo order; `None` when the journal holds none
    /// (no undo ran, or every undo was written before the record existed).
    pub fn undo_plan(&self) -> Option<&[OpId]> {
        self.undo_plan.as_ref().map(|(ops, _)| ops.as_slice())
    }

    /// The ops of the last `undo_plan` that its undo run did not reach: no undo record was written
    /// for them after the plan, their undo has not settled, and they have an intent or a `done` (the
    /// undo driver acts on them). In plan order. An undo run that ended leaves none; one that was
    /// interrupted leaves the ops recovery still has to undo. Empty without a plan.
    pub fn undo_unfinished(&self) -> Vec<OpId> {
        let Some((ops, reached)) = &self.undo_plan else {
            return Vec::new();
        };
        ops.iter()
            .filter(|op| !reached.contains(op))
            .filter(|op| {
                self.ops.get(op).is_some_and(|s| {
                    !s.undo.is_settled() && !matches!(s.status(), OpStatus::Validated)
                })
            })
            .copied()
            .collect()
    }

    /// Notes that an undo record was written for `op` after the last plan.
    fn reach(&mut self, op: OpId) {
        if let Some((_, reached)) = &mut self.undo_plan {
            reached.insert(op);
        }
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The session id from the header.
    pub fn session(&self) -> &SessionId {
        &self.header.session
    }

    /// The run's settings from the `settings` record; `None` for a journal written before that record
    /// existed (or cut right after its header).
    pub fn settings(&self) -> Option<&RunSettings> {
        self.settings.as_ref()
    }

    /// How far the journal reaches: its complete lines (header included) and the chain value of the
    /// last one. The index entry records it (`SessionSummary::journal`, review M7).
    pub fn mark(&self) -> JournalMark {
        JournalMark {
            records: self.lines,
            head: Sha256Hex::from(self.head),
        }
    }

    /// Counts one more line, written or read, whose chain value is `head`.
    pub(super) fn advance(&mut self, head: [u8; 32]) {
        self.lines += 1;
        self.head = head;
    }

    /// Where the run stands.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether the run ended with `commit` or `aborted`.
    pub fn is_finished(&self) -> bool {
        matches!(self.phase, Phase::Committed | Phase::Aborted)
    }

    /// The `commit` record, when the run committed.
    pub fn commit(&self) -> Option<&Commit> {
        self.commit.as_ref()
    }

    /// The `aborted` record, when the run stopped early.
    pub fn aborted(&self) -> Option<&Aborted> {
        self.aborted.as_ref()
    }

    /// Every validated op, in op order.
    pub fn ops(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops.values()
    }

    /// One op.
    pub fn op(&self, op: OpId) -> Option<&OpState> {
        self.ops.get(&op)
    }

    /// How many ops were validated.
    pub fn validated_count(&self) -> u32 {
        u32::try_from(self.ops.len()).unwrap_or(u32::MAX)
    }

    /// The ops with an intent and no done, in op order: what recovery must probe.
    pub fn open_intents(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops
            .values()
            .filter(|s| matches!(s.status(), OpStatus::IntentOnly))
    }

    /// The ops with a registered boot-time move that is still pending, in op order.
    pub fn pending_reboot(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops
            .values()
            .filter(|s| s.pending() == Some(Pending::Reboot))
    }

    /// The ops held for a retry at the next run with no retry in flight, in op order.
    pub fn held_retry(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops
            .values()
            .filter(|s| s.pending() == Some(Pending::Held) && !s.retry_in_flight)
    }

    /// The ops whose retry is in flight (a `retry_intent` with no `reconcile` after it), in op order:
    /// what recovery must probe.
    pub fn retries_in_flight(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops.values().filter(|s| s.retry_in_flight)
    }

    /// The ops that need the user's attention after reconcile ([`OpState::attention`]), in op order.
    pub fn needs_attention(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops.values().filter(|s| s.attention().is_some())
    }

    /// The ops whose undo is in progress (an `undo_intent` with nothing after it), in op order: what
    /// recovery must finish.
    pub fn undo_in_progress(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.ops
            .values()
            .filter(|s| s.undo == UndoState::InProgress)
    }

    /// The registry ops whose `done` says `Done` and whose change the journal does not vouch for yet,
    /// in op order: their `done` came after the last `group_end` marked `registry_flushed` (none in a
    /// journal written before the mark existed) and the run has not ended. Windows writes registry
    /// changes lazily, so after an unclean stop such a change may be gone although its `done` is on
    /// disk; recovery probes these ops again ([`crate::durable`]). Empty once the run ended: the writer
    /// flushes the hives before `commit` and `aborted`.
    pub fn unconfirmed(&self) -> impl Iterator<Item = &OpState> + '_ {
        self.unconfirmed.iter().filter_map(|op| self.ops.get(op))
    }

    /// Whether op `op` is one of [`JournalState::unconfirmed`].
    pub fn is_unconfirmed(&self, op: OpId) -> bool {
        self.unconfirmed.contains(&op)
    }

    /// How many items ended in each outcome, from the `done` records.
    pub fn counts(&self) -> OutcomeCounts {
        self.counts
    }

    /// How many groups a `group_end` closed.
    pub fn groups_closed(&self) -> u32 {
        self.groups_closed
    }

    /// How many intents were written since the last `group_end`.
    pub fn open_group_intents(&self) -> u32 {
        self.open_group_intents
    }

    /// How many ops have an intent and no done.
    pub fn open_intent_count(&self) -> u32 {
        self.open_intents
    }

    /// Refuses a record of the run once the run ended.
    fn run_open(&self, record: &'static str) -> Result<(), Violation> {
        if self.is_finished() {
            Err(Violation::AfterFinish(record))
        } else {
            Ok(())
        }
    }

    /// Refuses to start (or commit) the run before every item was validated.
    fn all_validated(&self) -> Result<(), Violation> {
        if self.validated_count() == self.header.items {
            Ok(())
        } else {
            Err(Violation::NotAllValidated {
                items: self.header.items,
                validated: self.validated_count(),
            })
        }
    }

    fn known(&self, op: OpId) -> Result<&OpState, Violation> {
        self.ops.get(&op).ok_or(Violation::UnknownOp(op))
    }

    fn known_mut(&mut self, op: OpId) -> &mut OpState {
        // Only called after `known` succeeded for the same op.
        self.ops.get_mut(&op).expect("op checked before")
    }

    /// Applies `record` after the records so far, or refuses it and changes nothing.
    pub fn apply(&mut self, record: &Record) -> Result<(), Violation> {
        self.check(record)?;
        self.record(record);
        Ok(())
    }

    /// Whether `record` may follow the records so far ([`JournalState::apply`] would accept it).
    /// Changes nothing.
    pub fn check(&self, record: &Record) -> Result<(), Violation> {
        match record {
            Record::Header(_) => Err(Violation::DuplicateHeader),
            Record::Settings(_) => {
                self.run_open("settings")?;
                if self.phase != Phase::Validating
                    || !self.ops.is_empty()
                    || self.settings.is_some()
                    || self.lines != 1
                {
                    return Err(Violation::SettingsMisplaced);
                }
                Ok(())
            }
            Record::RetryIntent(r) => self.check_retry(r),
            Record::Validated(v) => {
                self.run_open("validated")?;
                if self.phase != Phase::Validating {
                    return Err(Violation::ValidatedAfterStart(v.op));
                }
                if v.op.0 == 0 || v.op.0 > self.header.items {
                    return Err(Violation::OpOutOfRange(v.op));
                }
                if self.ops.contains_key(&v.op) {
                    return Err(Violation::DuplicateValidated(v.op));
                }
                Ok(())
            }
            Record::Intent(i) => {
                self.run_open("intent")?;
                self.all_validated()?;
                let s = self.known(i.op)?;
                if s.intent.is_some() {
                    return Err(Violation::DuplicateIntent(i.op));
                }
                if s.outcome.is_some() {
                    return Err(Violation::IntentAfterDone(i.op));
                }
                if i.item != s.item {
                    return Err(Violation::ItemMismatch(i.op));
                }
                if i.exec_op.target() != s.target {
                    return Err(Violation::TargetMismatch(i.op));
                }
                if !i.is_consistent() {
                    return Err(Violation::InconsistentIntent(i.op));
                }
                if self.open_group_intents >= MAX_GROUP_INTENTS {
                    return Err(Violation::GroupFull(i.op));
                }
                Ok(())
            }
            Record::Done(d) => {
                self.run_open("done")?;
                self.all_validated()?;
                let s = self.known(d.op)?;
                if s.outcome.is_some() {
                    return Err(Violation::DuplicateDone(d.op));
                }
                if d.item != s.item {
                    return Err(Violation::ItemMismatch(d.op));
                }
                if s.intent.is_none() && !d.outcome.allowed_without_intent() {
                    return Err(Violation::DoneWithoutIntent(d.op));
                }
                Ok(())
            }
            Record::GroupEnd(g) => {
                self.run_open("group_end")?;
                if self.open_group_intents == 0 {
                    return Err(Violation::EmptyGroup);
                }
                let expected_group = self.groups_closed + 1;
                if g.group != expected_group || g.ops != self.open_group_intents {
                    return Err(Violation::GroupMismatch {
                        expected_group,
                        expected_ops: self.open_group_intents,
                        group: g.group,
                        ops: g.ops,
                    });
                }
                Ok(())
            }
            Record::Commit(c) => {
                self.run_open("commit")?;
                self.all_validated()?;
                if self.open_group_intents != 0 {
                    return Err(Violation::OpenGroup);
                }
                if let Some(s) = self.ops.values().find(|s| s.outcome.is_none()) {
                    return Err(Violation::MissingDone(s.op));
                }
                if c.counts != self.counts {
                    return Err(Violation::CountsMismatch);
                }
                Ok(())
            }
            Record::Aborted(_) => self.run_open("aborted"),
            Record::UndoIntent(u) => {
                let s = self.known(u.op)?;
                if s.retry_in_flight {
                    return Err(Violation::RetryInFlight(u.op));
                }
                if s.intent.is_none() {
                    return Err(Violation::UndoNotApplicable(u.op));
                }
                if s.undo.is_settled() {
                    return Err(Violation::UndoSettled(u.op));
                }
                // Expiry deleted (some of) what the inverse would restore from.
                if !s.expired.is_empty() {
                    return Err(Violation::UndoAfterExpire(u.op));
                }
                Ok(())
            }
            Record::UndoDone(u) => {
                let s = self.known(u.op)?;
                if s.retry_in_flight {
                    return Err(Violation::RetryInFlight(u.op));
                }
                if s.undo.is_settled() {
                    return Err(Violation::UndoSettled(u.op));
                }
                if s.undo != UndoState::InProgress {
                    if s.intent.is_none() && s.outcome.is_none() {
                        return Err(Violation::UndoNotApplicable(u.op));
                    }
                    if !matches!(
                        u.outcome,
                        UndoOutcome::NothingToUndo | UndoOutcome::AlreadyRestored
                    ) {
                        return Err(Violation::UndoDoneWithoutIntent(u.op));
                    }
                }
                Ok(())
            }
            Record::UndoConflict(c) => {
                let s = self.known(c.op)?;
                if s.retry_in_flight {
                    return Err(Violation::RetryInFlight(c.op));
                }
                if s.undo.is_settled() {
                    return Err(Violation::UndoSettled(c.op));
                }
                if s.intent.is_none() && s.outcome.is_none() {
                    return Err(Violation::UndoNotApplicable(c.op));
                }
                Ok(())
            }
            Record::Reconcile(r) => self.check_reconcile(r),
            Record::UndoPlan(plan) => {
                for op in &plan.ops {
                    self.known(*op)?;
                }
                Ok(())
            }
            Record::Expire(e) => {
                if !self.is_finished() {
                    return Err(Violation::ExpireBeforeFinish(e.op));
                }
                let s = self.known(e.op)?;
                if s.intent.is_none() {
                    return Err(Violation::ExpireWithoutIntent(e.op));
                }
                if s.retry_in_flight {
                    return Err(Violation::RetryInFlight(e.op));
                }
                if s.expired.contains(&e.class) {
                    return Err(Violation::DuplicateExpire(e.op));
                }
                // An undo in progress may still need the data.
                if s.undo == UndoState::InProgress {
                    return Err(Violation::ExpireDuringUndo(e.op));
                }
                Ok(())
            }
        }
    }

    /// Applies a record [`JournalState::check`] accepted (the writer checks, writes, and only then
    /// applies, so that its state never runs ahead of the file).
    pub(super) fn record(&mut self, record: &Record) {
        match record {
            Record::Header(_) => {}
            Record::Settings(settings) => self.settings = Some(settings.clone()),
            Record::RetryIntent(r) => self.known_mut(r.op).retry_in_flight = true,
            Record::Validated(v) => {
                self.ops.insert(
                    v.op,
                    OpState {
                        op: v.op,
                        item: v.item.clone(),
                        target: v.target.clone(),
                        facts: v.facts.clone(),
                        exemptions: v.exemptions,
                        intent: None,
                        outcome: None,
                        reconciles: Vec::new(),
                        undo: UndoState::NotStarted,
                        undo_attempts: 0,
                        expired: Vec::new(),
                        retry_in_flight: false,
                    },
                );
            }
            Record::Intent(i) => {
                self.known_mut(i.op).intent = Some(i.clone());
                self.phase = Phase::Running;
                self.open_group_intents += 1;
                self.open_intents += 1;
            }
            Record::Done(d) => {
                let s = self.known_mut(d.op);
                let had_intent = s.intent.is_some();
                let registry = s
                    .intent
                    .as_ref()
                    .is_some_and(|intent| intent.exec_op.is_registry());
                s.outcome = Some(d.outcome.clone());
                self.phase = Phase::Running;
                self.counts.record(&d.outcome);
                if had_intent {
                    self.open_intents -= 1;
                }
                if registry && d.outcome == ItemOutcome::Done {
                    self.unconfirmed.insert(d.op);
                }
            }
            Record::GroupEnd(g) => {
                self.groups_closed += 1;
                self.open_group_intents = 0;
                if g.registry_flushed {
                    self.unconfirmed.clear();
                }
            }
            Record::Commit(c) => {
                self.commit = Some(c.clone());
                self.phase = Phase::Committed;
                self.unconfirmed.clear();
            }
            Record::Aborted(a) => {
                self.aborted = Some(a.clone());
                self.phase = Phase::Aborted;
                self.unconfirmed.clear();
            }
            Record::UndoIntent(u) => {
                let s = self.known_mut(u.op);
                s.undo = UndoState::InProgress;
                s.undo_attempts = s.undo_attempts.saturating_add(1);
                self.conflict_details.remove(&u.op);
                self.reach(u.op);
            }
            Record::UndoDone(u) => {
                self.known_mut(u.op).undo = UndoState::Finished(u.outcome.clone());
                self.conflict_details.remove(&u.op);
                self.reach(u.op);
            }
            Record::UndoConflict(c) => {
                self.known_mut(c.op).undo = UndoState::Conflict(c.conflict.clone());
                self.conflict_details.insert(c.op, c.detail.clone());
                self.reach(c.op);
            }
            Record::UndoPlan(plan) => {
                self.undo_plan = Some((plan.ops.clone(), BTreeSet::new()));
            }
            Record::Reconcile(r) => {
                // A `Retried` for an unconfirmed op is recovery's verdict on a registry change it did
                // not find: its outcome replaces the `done`'s `Done` (and is counted instead).
                let corrected = match &r.result {
                    ReconcileResult::Retried { outcome } if self.unconfirmed.remove(&r.op) => {
                        Some(outcome.clone())
                    }
                    _ => None,
                };
                let s = self.known_mut(r.op);
                if matches!(r.result, ReconcileResult::Retried { .. }) {
                    s.retry_in_flight = false;
                }
                s.reconciles.push(r.result.clone());
                if let Some(outcome) = corrected {
                    if let Some(old) = s.outcome.replace(outcome.clone()) {
                        uncount(&mut self.counts, &old);
                    }
                    self.counts.record(&outcome);
                }
            }
            Record::Expire(e) => self.known_mut(e.op).expired.push(e.class),
        }
    }

    fn check_retry(&self, r: &RetryIntent) -> Result<(), Violation> {
        let s = self.known(r.op)?;
        if s.retry_in_flight {
            return Err(Violation::RetryInFlight(r.op));
        }
        if !self.is_finished() || s.pending() != Some(Pending::Held) {
            return Err(Violation::RetryNotHeld(r.op));
        }
        Ok(())
    }

    fn check_reconcile(&self, r: &Reconcile) -> Result<(), Violation> {
        if let ReconcileResult::Retried { outcome } = &r.result
            && self.unconfirmed.contains(&r.op)
        {
            // Recovery's verdict on an unconfirmed registry op whose change it did not find: only
            // while the run is open, and only an outcome that says the change is not (all) there.
            self.run_open("reconcile")?;
            let fits = !matches!(
                outcome,
                ItemOutcome::Done | ItemOutcome::HeldRetry | ItemOutcome::PendingReboot { .. }
            );
            return if fits {
                Ok(())
            } else {
                Err(Violation::ReconcileMismatch(r.op))
            };
        }
        let pending = self.known(r.op)?.pending();
        let fits = match (pending, &r.result) {
            (None, _) => return Err(Violation::NotPending(r.op)),
            (Some(Pending::Held), ReconcileResult::Retried { .. }) => true,
            (Some(Pending::Held), _) => false,
            (Some(Pending::Reboot), ReconcileResult::Retried { .. }) => false,
            (Some(Pending::Reboot), _) => true,
        };
        if !fits {
            return Err(Violation::ReconcileMismatch(r.op));
        }
        Ok(())
    }
}
