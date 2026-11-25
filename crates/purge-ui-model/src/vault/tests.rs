//! The port of `VaultPageTests`: the list, the use and the real cap per volume from
//! `history.index` (medium engine, no broker), "Put back…" as `undo.run`, "Review and delete…" as
//! `quarantine.expiring` then `quarantine.purge`, and "Delete now" (DECISIONS 2026-11-23 and
//! 2026-11-24). The real broker, its dialogs and UAC are VM tests.

use std::collections::VecDeque;

use purge_model::FileTime;
use purge_model::exec::session::{RetentionClass, SessionId, SessionState, SessionSummary};
use purge_rpc::error::{ErrorData, Outcome};
use purge_rpc::methods::{
    ExpiringItem, ExpiringList, ExpiringParams, ExpiryId, HistoryIndex, PurgeResult, UndoResult,
};

use super::*;
use crate::broker_link::{BrokerLaunch, CallError};
use crate::info_bar::Severity;

const GIT_SESSION: &str = "20251115T101502Z-9f3a6c1d2b7e4a50";
const OTHER_SESSION: &str = "20251116T080000Z-0000000000000001";

/// The fixture's session started 15 Nov 2025; this is a year and a bit later, past both
/// retention dates.
const NOW: FileTime = FileTime(134_076_753_020_000_000 + 400 * 864_000_000_000);

fn clock() -> Clock {
    Clock::utc(NOW)
}

fn days(n: f64) -> FileTime {
    Clock::add_days(NOW, n)
}

fn sid(text: &str) -> SessionId {
    text.parse().expect("a session id")
}

fn eid(n: u64) -> ExpiryId {
    ExpiryId::from_bits(n)
}

fn git_index() -> HistoryIndex {
    serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/stdio.history.index.result.json"
    ))
    .expect("the index fixture")
}

/// The Git session made fresh: two days old, files for 28 more days, backups for 178.
fn fresh(mut s: SessionSummary, purged: &[RetentionClass]) -> SessionSummary {
    s.started = days(-2.0);
    s.expires.quarantine = days(28.0);
    s.expires.backups = days(178.0);
    s.purged = purged.to_vec();
    s
}

fn fresh_index(purged: &[RetentionClass]) -> HistoryIndex {
    let mut index = git_index();
    index.sessions[0] = fresh(index.sessions[0].clone(), purged);
    index
}

fn purged(purged: u32, kept: u32, backups: u32, outcome: Outcome) -> PurgeResult {
    PurgeResult {
        outcome,
        purged,
        kept,
        purged_backups: backups,
    }
}

fn rpc(data: ErrorData, message: &str) -> CallError {
    CallError::rpc(data, message)
}

fn item(
    id: u64,
    session: &str,
    class: RetentionClass,
    due: bool,
    file: &str,
    until: FileTime,
    user_data: bool,
) -> ExpiringItem {
    ExpiringItem {
        expiry_id: eid(id),
        session: sid(session),
        app: "Git".into(),
        class,
        expired: until,
        due,
        files: vec![file.into()],
        bytes: 2048,
        user_data,
    }
}

/// What the broker lists with `include_not_due`: two quarantined items of the Git cleanup that are
/// not due (one of them user data), its registry backup (due), and an item of another cleanup.
fn held() -> ExpiringList {
    let until = days(20.0);
    ExpiringList {
        items: vec![
            item(
                3,
                GIT_SESSION,
                RetentionClass::Backup,
                true,
                r"reg\000003.regbackup.json",
                until,
                false,
            ),
            item(
                1,
                GIT_SESSION,
                RetentionClass::Quarantine,
                false,
                r"C:\Program Files\Git",
                until,
                false,
            ),
            item(
                2,
                GIT_SESSION,
                RetentionClass::Quarantine,
                false,
                r"C:\Users\u\Documents\Git",
                until,
                true,
            ),
            item(
                4,
                OTHER_SESSION,
                RetentionClass::Quarantine,
                false,
                r"C:\Program Files\Other",
                until,
                false,
            ),
        ],
    }
}

/// [`held`] plus a registry backup of the Git cleanup that is not due, and one of another cleanup.
fn held_with_backups() -> ExpiringList {
    let mut list = held();
    let until = days(170.0);
    for (id, session) in [(5, GIT_SESSION), (6, OTHER_SESSION)] {
        let mut backup = item(
            id,
            session,
            RetentionClass::Backup,
            false,
            r"reg\000005.regbackup.json",
            until,
            false,
        );
        backup.bytes = 512;
        list.items.push(backup);
    }
    list
}

type Answer<T> = Box<dyn FnMut() -> Result<T, CallError>>;

/// One broker played by the test (the C# `ScriptedVaultBroker`).
struct Broker {
    undo: Answer<UndoResult>,
    expiring: ExpiringList,
    expiring_error: Option<CallError>,
    purge: Answer<PurgeResult>,
    undo_calls: Vec<(SessionId, bool)>,
    purge_calls: Vec<Vec<ExpiryId>>,
    expiring_calls: usize,
    expiring_flags: Vec<bool>,
    backup_listings: usize,
    foreground: usize,
    disposed: bool,
}

impl Broker {
    fn new() -> Self {
        Self {
            undo: Box::new(|| {
                Ok(UndoResult {
                    outcome: Outcome::Complete,
                    conflicts: Vec::new(),
                    alerts: Vec::new(),
                })
            }),
            expiring: ExpiringList { items: Vec::new() },
            expiring_error: None,
            purge: Box::new(|| Ok(purged(0, 0, 0, Outcome::Complete))),
            undo_calls: Vec::new(),
            purge_calls: Vec::new(),
            expiring_calls: 0,
            expiring_flags: Vec::new(),
            backup_listings: 0,
            foreground: 0,
            disposed: false,
        }
    }

    fn listing(expiring: ExpiringList) -> Self {
        let mut broker = Self::new();
        broker.expiring = expiring;
        broker
    }

    fn purging(mut self, result: PurgeResult) -> Self {
        self.purge = Box::new(move || Ok(result));
        self
    }

    fn failing(mut self, error: CallError) -> Self {
        self.purge = Box::new(move || Err(error.clone()));
        self
    }

    /// As the broker: an item that is not due is listed only when asked for, and a backup that is
    /// not due only by the listing that asks for the backups too.
    fn expiring(&mut self, params: ExpiringParams) -> Result<ExpiringList, CallError> {
        self.expiring_calls += 1;
        if params.include_backups_not_due {
            self.backup_listings += 1;
        } else {
            self.expiring_flags.push(params.include_not_due);
        }
        if let Some(e) = &self.expiring_error {
            return Err(e.clone());
        }
        if params.include_backups_not_due {
            return Ok(self.expiring.clone());
        }
        Ok(ExpiringList {
            items: self
                .expiring
                .items
                .iter()
                .filter(|i| {
                    i.due || (params.include_not_due && i.class == RetentionClass::Quarantine)
                })
                .cloned()
                .collect(),
        })
    }
}

/// The engine and the brokers the page starts, in order.
struct Rig {
    index: Box<dyn FnMut() -> Result<HistoryIndex, CallError>>,
    reads: usize,
    brokers: Vec<Broker>,
    /// What launch `n` (0-based) answers; past the list: started.
    launch_answers: VecDeque<BrokerLaunch>,
    launches: usize,
    /// The broker serving now (an index into `brokers`).
    current: Option<usize>,
}

impl Rig {
    fn new(index: HistoryIndex, brokers: Vec<Broker>) -> Self {
        Self {
            index: Box::new(move || Ok(index.clone())),
            reads: 0,
            brokers,
            launch_answers: VecDeque::new(),
            launches: 0,
            current: None,
        }
    }

    fn git(broker: Broker) -> Self {
        Self::new(git_index(), vec![broker])
    }

    fn broker(&mut self) -> &mut Broker {
        let at = self.current.expect("a broker was started");
        &mut self.brokers[at]
    }

    fn run(&mut self, model: &mut VaultModel, calls: Vec<VaultCall>) {
        let mut queue: VecDeque<VaultCall> = calls.into();
        while let Some(call) = queue.pop_front() {
            let next = match call {
                VaultCall::ReadIndex => {
                    self.reads += 1;
                    let answer = (self.index)();
                    model.on_index(answer, &clock());
                    Vec::new()
                }
                VaultCall::Launch => {
                    let launch = self
                        .launch_answers
                        .pop_front()
                        .unwrap_or_else(BrokerLaunch::started);
                    if launch.started {
                        self.current = Some(self.launches);
                        self.launches += 1;
                    }
                    model.on_launch(launch)
                }
                VaultCall::DropBroker => {
                    self.broker().disposed = true;
                    Vec::new()
                }
                VaultCall::AllowForeground => {
                    self.broker().foreground += 1;
                    Vec::new()
                }
                VaultCall::Undo(p) => {
                    let broker = self.broker();
                    broker.undo_calls.push((p.session, p.item_ids.is_none()));
                    let answer = (broker.undo)();
                    model.on_undone(answer)
                }
                VaultCall::Expiring(p) => {
                    let answer = self.broker().expiring(p);
                    if matches!(answer, Err(CallError::Link { .. })) {
                        model.on_broker_ended();
                    }
                    model.on_expiring(answer, &clock())
                }
                VaultCall::Purge(p) => {
                    let broker = self.broker();
                    broker.purge_calls.push(p.expiry_ids.into_vec());
                    let answer = (broker.purge)();
                    model.on_purged(answer)
                }
            };
            queue.extend(next);
        }
    }

    fn loaded(&mut self) -> VaultModel {
        let mut model = VaultModel::new();
        let calls = model.load();
        self.run(&mut model, calls);
        model
    }

    fn act(&mut self, model: &mut VaultModel, act: impl FnOnce(&mut VaultModel) -> Vec<VaultCall>) {
        let calls = act(model);
        self.run(model, calls);
    }
}

#[test]
fn lists_what_the_index_holds_with_the_real_cap_without_starting_the_broker() {
    let mut index = git_index();
    let mut restored = index.sessions[0].clone();
    restored.id = sid(OTHER_SESSION);
    restored.state = SessionState::Undone;
    index.sessions.push(restored);
    let mut rig = Rig::new(index, Vec::new());

    let model = rig.loaded();

    assert_eq!(model.phase(), VaultPhase::Ready);
    assert_eq!(rig.launches, 0);
    assert_eq!(model.batches().len(), 1);
    let git = &model.batches()[0];
    assert_eq!(git.id, sid(GIT_SESSION));
    assert_eq!(git.name, "HKLM|64|Git_is1");
    assert_eq!(git.volume, r"C:\");
    assert_eq!(git.items, 21);
    assert_eq!(git.bytes, 1_234_567);
    // The fixture's session is a year old: past both retention dates.
    assert!(git.expired);
    assert_eq!(git.state, "Expired");
    assert_eq!(model.expired_batches().count(), 1);
    assert_eq!(model.volumes().len(), 1);
    let volume = &model.volumes()[0];
    assert_eq!(volume.root, r"C:\");
    assert_eq!(volume.cap, 10_737_418_240);
    assert_eq!(volume.used, 1_234_567);
    assert!(volume.note.starts_with("Expired or expiring soon: "));
    assert_eq!(model.interrupted(), 0);
}

#[test]
fn a_fresh_session_is_restorable_with_its_days_left() {
    let mut rig = Rig::new(fresh_index(&[]), Vec::new());
    let model = rig.loaded();

    let git = &model.batches()[0];
    assert!(!git.expired);
    assert!(!git.expiring);
    assert_eq!(git.state, "Restorable");
    assert_eq!(git.file_days, 28);
    assert_eq!(git.backup_days, 178);
    assert_eq!(
        git.detail,
        "Files restorable for 28 more days · registry backups 178 days"
    );
    assert_eq!(model.expired_batches().count(), 0);
    assert_eq!(model.volumes()[0].note, "Nothing expiring this week");
}

#[test]
fn once_the_files_are_deleted_the_row_says_only_the_registry_changes_can_be_undone() {
    let mut rig = Rig::new(fresh_index(&[RetentionClass::Quarantine]), Vec::new());
    let model = rig.loaded();

    let git = &model.batches()[0];
    assert!(git.registry_only);
    assert_eq!(git.state, "Registry undo only");
    assert_eq!(
        git.detail,
        "Files deleted · its registry changes can be undone for 178 more days"
    );
    assert!(!git.detail.to_lowercase().contains("restorable"));
    assert_eq!(
        model.batch_row(0).expect("a row").restore_text,
        "Undo registry changes…"
    );
}

#[test]
fn nothing_held_is_the_empty_state_and_an_interrupted_session_is_counted() {
    let mut index = git_index();
    index.sessions[0].state = SessionState::Open;
    let mut rig = Rig::new(index, Vec::new());
    let model = rig.loaded();

    assert_eq!(model.phase(), VaultPhase::Empty);
    assert!(model.batches().is_empty());
    assert_eq!(model.interrupted(), 1);
    assert!(model.shows_empty_card());
    assert_eq!(model.bars()[0].action, Some(VaultBarAction::OpenHistory));
}

#[test]
fn an_index_that_cannot_be_read_shows_the_error() {
    let mut rig = Rig::new(git_index(), Vec::new());
    rig.index = Box::new(|| Err(CallError::Other("index.json is busy".into())));
    let model = rig.loaded();

    assert_eq!(model.phase(), VaultPhase::Error);
    assert_eq!(model.error(), Some("index.json is busy"));
    assert_eq!(model.bars()[0].title, "Couldn't read the quarantine.");
}

#[test]
fn put_back_runs_undo_for_the_whole_session_and_reads_the_list_again() {
    let mut rig = Rig::git(Broker::new());
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.restore(&sid(GIT_SESSION)));

    assert_eq!(rig.brokers[0].undo_calls, [(sid(GIT_SESSION), true)]);
    assert_eq!(rig.brokers[0].foreground, 1);
    assert_eq!(model.result_title(), Some("HKLM|64|Git_is1 is back"));
    assert!(model.action_error().is_none());
    assert_eq!(rig.reads, 2);
    assert!(!model.busy());
}

#[test]
fn a_declined_prompt_puts_nothing_back_and_another_writer_is_busy() {
    let mut broker = Broker::new();
    let mut answers = VecDeque::from([
        rpc(ErrorData::ConsentDeclined, "declined"),
        rpc(ErrorData::Busy, "a mutating request is running"),
    ]);
    broker.undo = Box::new(move || Err(answers.pop_front().unwrap_or(CallError::Cancelled)));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.restore(&sid(GIT_SESSION)));
    assert_eq!(
        model.action_info(),
        Some("Nothing was put back: the prompt was cancelled.")
    );
    assert!(model.result_title().is_none());
    assert_eq!(rig.reads, 1);

    rig.act(&mut model, |m| m.restore(&sid(GIT_SESSION)));
    assert_eq!(
        model.action_error(),
        Some(
            "Another Purge window is changing the quarantine. Wait for it to finish, then try again."
        )
    );
}

#[test]
fn review_and_delete_asks_the_broker_what_expired_and_purges_it_through_its_dialog() {
    let broker = Broker::listing(
        serde_json::from_str(include_str!(
            "../../../purge-rpc/fixtures/pipe.quarantine.expiring.result.json"
        ))
        .expect("the fixture"),
    )
    .purging(
        serde_json::from_str(include_str!(
            "../../../purge-rpc/fixtures/pipe.quarantine.purge.result.json"
        ))
        .expect("the fixture"),
    );
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();
    assert!(model.review_button().enabled);

    rig.act(&mut model, VaultModel::review_expired);

    assert_eq!(rig.launches, 1);
    let broker = &rig.brokers[0];
    assert_eq!(broker.expiring_calls, 1);
    assert_eq!(
        broker.purge_calls,
        [vec![
            "e-0e0e000000000007".parse::<ExpiryId>().expect("an id")
        ]]
    );
    assert_eq!(broker.foreground, 1);
    assert_eq!(model.result_title(), Some("41 items deleted for good"));
    assert!(model.action_info().is_none());
}

#[test]
fn another_writer_says_nothing_was_deleted() {
    let broker = Broker::listing(held_expired())
        .failing(rpc(ErrorData::Busy, "another writer holds the store"));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, VaultModel::review_expired);

    assert_eq!(
        model.action_error(),
        Some(
            "Another Purge window is changing the quarantine; nothing was deleted. Try again when it has finished."
        )
    );
    assert!(model.result_title().is_none());
    assert!(!model.busy());
}

/// The expiring fixture: one due item.
fn held_expired() -> ExpiringList {
    serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/pipe.quarantine.expiring.result.json"
    ))
    .expect("the fixture")
}

#[test]
fn nothing_past_retention_is_a_note_not_a_dialog() {
    let mut rig = Rig::git(Broker::new());
    let mut model = rig.loaded();

    rig.act(&mut model, VaultModel::review_expired);

    assert_eq!(rig.brokers[0].expiring_calls, 1);
    assert!(rig.brokers[0].purge_calls.is_empty());
    assert_eq!(
        model.action_info(),
        Some("Nothing has passed its retention yet; nothing was deleted.")
    );
}

#[test]
fn a_cancelled_admin_prompt_starts_nothing() {
    let mut rig = Rig::git(Broker::new());
    rig.launch_answers.push_back(BrokerLaunch::cancelled(""));
    let mut model = rig.loaded();

    rig.act(&mut model, VaultModel::review_expired);

    assert!(model.prompt_cancelled());
    assert!(!model.prompt_declined());
    assert!(model.action_error().is_none());
    assert_eq!(model.action_info(), Some(text::NOT_STARTED));
    assert!(!model.busy());
}

#[test]
fn not_now_at_the_explanation_is_a_declined_prompt() {
    let mut rig = Rig::git(Broker::new());
    rig.launch_answers.push_back(BrokerLaunch::declined());
    let mut model = rig.loaded();

    rig.act(&mut model, VaultModel::review_expired);

    assert!(model.prompt_cancelled());
    assert!(model.prompt_declined());
    assert!(model.action_error().is_none());
}

#[test]
fn a_broker_that_dies_is_started_again_on_the_next_click() {
    let mut first = Broker::new();
    first.expiring_error = Some(CallError::link("pipe closed", false));
    let mut rig = Rig::new(git_index(), vec![first, Broker::new()]);
    let mut model = rig.loaded();

    rig.act(&mut model, VaultModel::review_expired);
    assert!(model.action_error().is_some());
    assert!(rig.brokers[0].disposed);

    rig.act(&mut model, VaultModel::review_expired);
    assert!(model.action_error().is_none());
    assert_eq!(rig.brokers[1].expiring_calls, 1);
}

// ---- "Delete now" (DECISIONS 2026-11-23) -------------------------------------------------------

#[test]
fn delete_now_sends_the_brokers_ids_of_that_cleanups_quarantined_items_and_nothing_else() {
    let broker = Broker::listing(held()).purging(purged(2, 0, 0, Outcome::Complete));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), false));

    // The listing asked for the items that are not due; the delete names ids, not paths: never
    // the backup, never another cleanup's item.
    let broker = &rig.brokers[0];
    assert_eq!(broker.expiring_flags, [true]);
    assert_eq!(broker.purge_calls, [vec![eid(1), eid(2)]]);
    assert_eq!(broker.foreground, 1);
    assert_eq!(
        model.result_title(),
        Some("2 items of HKLM|64|Git_is1 deleted for good")
    );
    assert!(model.action_info().is_none());
    assert!(model.action_error().is_none());
    assert_eq!(rig.reads, 2);
    assert!(!model.busy());
    // A completed delete ends the broker; the page drops its end.
    assert!(broker.disposed);
}

#[test]
fn without_the_tick_delete_now_never_asks_for_or_names_a_backup_that_is_not_due() {
    let broker = Broker::listing(held_with_backups()).purging(purged(2, 0, 0, Outcome::Complete));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), false));

    let broker = &rig.brokers[0];
    assert_eq!(broker.backup_listings, 0);
    assert_eq!(broker.purge_calls, [vec![eid(1), eid(2)]]);
    assert_eq!(
        model.result_title(),
        Some("2 items of HKLM|64|Git_is1 deleted for good")
    );
    assert!(model.action_info().is_none());
}

#[test]
fn with_the_tick_delete_now_also_sends_the_brokers_ids_of_that_cleanups_backups() {
    let broker = Broker::listing(held_with_backups()).purging(purged(4, 0, 2, Outcome::Complete));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), true));

    // One listing, the one that asks for the backups too; ids only, the files first, and nothing
    // of the other cleanup.
    let broker = &rig.brokers[0];
    assert_eq!(broker.backup_listings, 1);
    assert_eq!(broker.expiring_calls, 1);
    assert_eq!(broker.purge_calls, [vec![eid(1), eid(2), eid(3), eid(5)]]);
    assert_eq!(broker.foreground, 1);
    // The result does not count a backup as "an item", and says what was given up.
    assert_eq!(
        model.result_title(),
        Some("2 items of HKLM|64|Git_is1 deleted for good, and its registry backups")
    );
    assert_eq!(
        model.action_info(),
        Some("Its registry changes can no longer be undone.")
    );
    assert!(model.action_error().is_none());
    assert!(broker.disposed);
    // A note with the title: a warning bar, not a success.
    let bar = model
        .bars()
        .into_iter()
        .find(|b| b.title.starts_with("2 items"))
        .expect("the result bar");
    assert_eq!(bar.severity, Severity::Warning);
}

#[test]
fn the_backups_the_brokers_prompt_kept_are_not_said_to_be_deleted() {
    // The files were approved, the backups' own prompt was cancelled: two entries kept.
    let broker = Broker::listing(held_with_backups()).purging(purged(2, 2, 0, Outcome::Partial));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), true));

    assert_eq!(
        model.result_title(),
        Some("2 items of HKLM|64|Git_is1 deleted for good")
    );
    assert_eq!(
        model.action_info(),
        Some("2 kept: you declined them, or they could not be deleted.")
    );
}

#[test]
fn a_cleanup_with_only_registry_backups_left_deletes_them_only_with_the_tick() {
    let mut only = held_with_backups();
    only.items
        .retain(|i| !(i.session == sid(GIT_SESSION) && i.class == RetentionClass::Quarantine));
    let second = Broker::listing(only.clone());
    let broker = Broker::listing(only).purging(purged(2, 0, 2, Outcome::Complete));
    let mut rig = Rig::new(git_index(), vec![second, broker]);
    let mut model = rig.loaded();

    // Without the tick: a note, no prompt, nothing sent.
    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), false));
    assert!(rig.brokers[0].purge_calls.is_empty());
    assert!(
        model
            .action_info()
            .expect("a note")
            .starts_with("This cleanup has no quarantined files to delete now.")
    );
    rig.act(&mut model, VaultModel::close);

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), true));
    assert_eq!(rig.brokers[1].purge_calls, [vec![eid(3), eid(5)]]);
    assert_eq!(
        model.result_title(),
        Some("The registry backups of HKLM|64|Git_is1 were deleted for good")
    );
    assert_eq!(
        model.action_info(),
        Some("Its registry changes can no longer be undone.")
    );
}

#[test]
fn with_the_tick_a_cleanup_with_nothing_left_is_a_note_and_a_declined_prompt_deletes_nothing() {
    let mut nothing = held_with_backups();
    nothing.items.retain(|i| i.session != sid(GIT_SESSION));
    let empty = Broker::listing(nothing);
    let declined =
        Broker::listing(held_with_backups()).failing(rpc(ErrorData::ConsentDeclined, "declined"));
    let mut rig = Rig::new(git_index(), vec![empty, declined]);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), true));
    assert!(rig.brokers[0].purge_calls.is_empty());
    assert_eq!(rig.brokers[0].foreground, 0);
    assert!(
        model
            .action_info()
            .expect("a note")
            .starts_with("This cleanup has nothing to delete now")
    );
    rig.act(&mut model, VaultModel::close);

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), true));
    assert_eq!(
        model.action_info(),
        Some("Nothing was deleted: the prompt was cancelled.")
    );
    assert!(model.result_title().is_none());
    assert!(!model.busy());
}

#[test]
fn a_single_items_delete_now_never_takes_a_backup_with_it() {
    let broker = Broker::listing(held_with_backups()).purging(purged(1, 0, 0, Outcome::Complete));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();
    rig.act(&mut model, |m| m.show_items(&sid(GIT_SESSION)));

    // The list holds quarantined files only, and an id of a backup is not one of the list.
    let ids: Vec<ExpiryId> = model.items().iter().map(|i| i.expiry_id).collect();
    assert_eq!(ids, [eid(1), eid(2)]);
    assert!(model.delete_item_now(eid(5)).is_empty());

    rig.act(&mut model, |m| m.delete_item_now(eid(1)));
    assert_eq!(rig.brokers[0].purge_calls, [vec![eid(1)]]);
    assert_eq!(rig.brokers[0].backup_listings, 0);
}

#[test]
fn the_delete_now_choice_offers_the_backups_only_while_there_are_some_and_is_off_by_itself() {
    let clock = clock();
    let base = git_index().sessions[0].clone();
    let batch = |purged: &[RetentionClass]| VaultBatch::new(&fresh(base.clone(), purged), &clock);
    assert_eq!(
        text::ALSO_BACKUPS_TEXT,
        "Also delete its registry backups (its registry changes can then no longer be undone)"
    );

    // Files and backups held: the files alone are enough; the backups are an option.
    let full = batch(&[]);
    assert!(full.can_delete_now(false));
    assert!(full.can_delete_backups());
    assert!(
        full.delete_now_intro()
            .contains("nothing is deleted without it")
    );

    // Only registry backups left ("Registry undo only"): nothing to delete without the tick.
    let registry_only = batch(&[RetentionClass::Quarantine]);
    assert_eq!(registry_only.state, "Registry undo only");
    assert!(!registry_only.can_delete_now(false));
    assert!(registry_only.can_delete_now(true));
    assert!(registry_only.delete_now_intro().contains("already deleted"));

    // The backups went early and the files are kept: no backup option.
    let files_only = batch(&[RetentionClass::Backup]);
    assert!(!files_only.can_delete_backups());
    assert!(files_only.can_delete_now(true));
    assert_eq!(files_only.state, "Restorable");
    assert!(files_only.detail.contains("registry backups deleted"));

    // Everything deleted: the vault holds nothing of the cleanup and promises nothing.
    let gone = fresh(
        base.clone(),
        &[RetentionClass::Quarantine, RetentionClass::Backup],
    );
    assert!(!VaultBatch::holds(&gone));
    assert!(!VaultBatch::new(&gone, &clock).can_delete_now(true));

    // The page's flyout reads the same rules.
    let mut rig = Rig::new(fresh_index(&[RetentionClass::Quarantine]), Vec::new());
    let model = rig.loaded();
    let choice = model
        .delete_now_choice(&sid(GIT_SESSION))
        .expect("a choice");
    assert!(choice.offers_backups);
    assert!(!choice.can_continue_unticked);
    assert!(choice.can_continue_ticked);
}

#[test]
fn a_declined_delete_now_prompt_deletes_nothing_and_keeps_the_list() {
    let broker = Broker::listing(held()).failing(rpc(ErrorData::ConsentDeclined, "declined"));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), false));

    assert_eq!(
        model.action_info(),
        Some("Nothing was deleted: the prompt was cancelled.")
    );
    assert!(model.result_title().is_none());
    assert!(model.action_error().is_none());
    assert_eq!(rig.reads, 1);
    assert!(!rig.brokers[0].disposed);
    assert!(!model.busy());
}

#[test]
fn a_cleanup_with_nothing_in_quarantine_is_a_note_not_a_prompt() {
    let mut only = held();
    only.items
        .retain(|i| !(i.session == sid(GIT_SESSION) && i.class == RetentionClass::Quarantine));
    let mut rig = Rig::git(Broker::listing(only));
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.delete_now(&sid(GIT_SESSION), false));

    assert!(rig.brokers[0].purge_calls.is_empty());
    assert_eq!(rig.brokers[0].foreground, 0);
    assert!(
        model
            .action_info()
            .expect("a note")
            .starts_with("This cleanup has no quarantined files to delete now.")
    );
    assert!(model.result_title().is_none());
}

#[test]
fn choose_items_lists_the_cleanups_items_and_deletes_one_by_its_id() {
    let broker = Broker::listing(held()).purging(purged(1, 0, 0, Outcome::Complete));
    let second = Broker::listing(held()).purging(purged(0, 1, 0, Outcome::Partial));
    let mut rig = Rig::new(git_index(), vec![broker, second]);
    let mut model = rig.loaded();

    // An id the page was not given by the broker starts nothing.
    assert!(model.delete_item_now(eid(1)).is_empty());

    rig.act(&mut model, |m| m.show_items(&sid(GIT_SESSION)));

    assert_eq!(model.items_for(), Some(&sid(GIT_SESSION)));
    assert_eq!(model.items_name(), "HKLM|64|Git_is1");
    assert_eq!(
        model.items_title().as_deref(),
        Some("In quarantine from HKLM|64|Git_is1")
    );
    let ids: Vec<ExpiryId> = model.items().iter().map(|i| i.expiry_id).collect();
    assert_eq!(ids, [eid(1), eid(2)]);
    assert_eq!(model.items()[0].path, r"C:\Program Files\Git");
    let size = format_size(2048);
    assert_eq!(
        model.items()[0].detail,
        format!("{size} · can be put back for 20 more days")
    );
    assert_eq!(
        model.items()[1].detail,
        format!("{size} · user data · can be put back for 20 more days")
    );
    assert_eq!(
        model.items()[0].delete_label(),
        r"Delete C:\Program Files\Git now"
    );
    assert!(!model.items()[0].due);
    assert!(rig.brokers[0].purge_calls.is_empty());
    assert_eq!(rig.brokers[0].foreground, 0);

    // Not an id of this list: nothing is sent.
    assert!(model.delete_item_now(eid(4)).is_empty());

    rig.act(&mut model, |m| m.delete_item_now(eid(1)));

    assert_eq!(rig.brokers[0].purge_calls, [vec![eid(1)]]);
    assert_eq!(rig.brokers[0].foreground, 1);
    assert_eq!(
        model.result_title(),
        Some("1 item of HKLM|64|Git_is1 deleted for good")
    );
    // The deleted item leaves the list; the other stays, with its own "Delete now".
    let ids: Vec<ExpiryId> = model.items().iter().map(|i| i.expiry_id).collect();
    assert_eq!(ids, [eid(2)]);
    assert!(rig.brokers[0].disposed);

    // The next delete starts a new broker; an item the prompt declined stays listed.
    rig.act(&mut model, |m| m.delete_item_now(eid(2)));
    assert_eq!(rig.brokers[1].purge_calls, [vec![eid(2)]]);
    assert_eq!(model.result_title(), Some("Nothing was deleted"));
    assert_eq!(
        model.action_info(),
        Some("1 kept: you declined them, or they could not be deleted.")
    );
    let ids: Vec<ExpiryId> = model.items().iter().map(|i| i.expiry_id).collect();
    assert_eq!(ids, [eid(2)]);

    model.close_items();
    assert!(model.items_for().is_none());
    assert!(model.items().is_empty());
}

#[test]
fn an_item_that_is_no_longer_listed_by_the_broker_closes_the_list_and_deletes_nothing() {
    let broker = Broker::listing(held()).failing(rpc(
        ErrorData::Gone {
            id: purge_rpc::error::IdKind::Expiry,
        },
        "gone",
    ));
    let mut rig = Rig::git(broker);
    let mut model = rig.loaded();
    rig.act(&mut model, |m| m.show_items(&sid(GIT_SESSION)));

    rig.act(&mut model, |m| m.delete_item_now(eid(1)));

    assert!(model.items_for().is_none());
    assert_eq!(
        model.action_info(),
        Some(
            "That is no longer in quarantine as listed; nothing was deleted. The list is read again."
        )
    );
    assert!(model.result_title().is_none());
    assert_eq!(rig.reads, 2);
}

#[test]
fn no_second_action_starts_while_one_runs() {
    let mut rig = Rig::git(Broker::new());
    let mut model = rig.loaded();
    let git = sid(GIT_SESSION);

    let first = model.delete_now(&git, false);
    assert_eq!(first, [VaultCall::Launch]);
    assert!(model.busy());
    // Every other action is refused while the broker (or its prompt) is busy.
    assert!(model.delete_now(&git, false).is_empty());
    assert!(model.show_items(&git).is_empty());
    assert!(model.restore(&git).is_empty());
    assert!(model.review_expired().is_empty());
    assert!(!model.batch_row(0).expect("a row").can_act);
    assert_eq!(model.review_button().tooltip, Some(text::REVIEW_WAIT));

    assert!(model.on_launch(BrokerLaunch::cancelled("")).is_empty());
    assert!(!model.busy());
    assert!(model.prompt_cancelled());
}

#[test]
fn the_rows_and_bars_say_what_the_vault_holds() {
    let mut rig = Rig::git(Broker::new());
    let model = rig.loaded();

    let row = model.batch_row(0).expect("a row");
    assert_eq!(row.initial, "H");
    assert_eq!(row.when, "15 Nov 10:15");
    assert_eq!(row.summary, r"21 items · 1.2 MB on C:\");
    assert_eq!(row.chip, VaultChip::Expired);
    assert_eq!(row.days_text, "0");
    assert_eq!(row.days_caption, "days");
    assert_eq!(
        row.accessible_name,
        "HKLM|64|Git_is1, 15 Nov 10:15, Expired"
    );
    assert!(row.delete_visible);
    assert!(row.choose_visible);
    assert_eq!(
        model.totals(),
        "1 cleanup holds 1.2 MB · files 30 days, registry backups 180 days"
    );
    assert_eq!(model.volumes()[0].used_text, "1.2 MB of 10.0 GB limit");
    assert_eq!(model.volumes()[0].tip(), r"C:\ 0 % of its quarantine limit");

    let bars = model.bars();
    assert_eq!(bars.len(), 1);
    assert_eq!(bars[0].title, "One cleanup is past its retention.");
    assert_eq!(bars[0].action, Some(VaultBarAction::Review));
    assert_eq!(VaultBarAction::Review.text(), "Review and delete…");

    // A fresh session made today reads "Today".
    let mut index = fresh_index(&[]);
    index.sessions[0].started = days(-0.01);
    let mut rig = Rig::new(index, Vec::new());
    let model = rig.loaded();
    assert!(
        model
            .batch_row(0)
            .expect("a row")
            .when
            .starts_with("Today ")
    );
    assert_eq!(model.review_button().tooltip, Some(text::REVIEW_NOTHING));
}
