//! Tests of the purge handler: the wire mapping, the dialogs and every refusal the M3-R2 review
//! attacks. The broker runs over the testkit in-memory transport with the scripted consent; the store
//! is scripted, so a due item, a purge and a user-data flag can be set without an elevated store.
//!
//! What is **not** scripted here: the executor's own expiry walk, its store checks and its consent
//! refusal. Those are `purge_exec::expiry` and are tested there on real objects (including the M2
//! expiry traps); the broker passes its [`PurgeConsent`] unchanged to that same `expiry::purge`, and
//! [`StorageExpiry`] is the only thing between them. Running that adapter on a real store is a VM item
//! (it needs an elevated store).

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use purge_engine::pipeline::Settings;
use purge_exec::expiry::{
    ExpiringBackup, ExpiringItem, ExpiryId as ExecExpiryId, IndexUpdate, PurgeConsent, PurgeError,
    PurgeOutcome, PurgeReport, PurgeResult as ExecPurgeResult,
};
use purge_exec::storage::StorageError;
use purge_model::exec::op::OpId;
use purge_model::exec::session::{RetentionClass, SessionId};
use purge_model::{CandidateId, FileTime};
use purge_rpc::methods::{ExpiringList, ExpiryId, PurgeResult};
use purge_win::taskdialog::{Outcome, Page};
use serde_json::{Value, json};

use crate::lifetime::{Exit, ExitReason};
use crate::serve::{Ctx, Handler, Wiring, run};
use crate::testkit::{
    Client, FakeClock, FakeHost, FakeParent, Gate, HELLO, MemNet, SECS, ScriptedConsent, expected,
    kind, request, test_limits,
};

use super::{ExpirySource, Listing, Purger, wire_id};

// ---------------------------------------------------------------------------------------------------
// The scripted store.
// ---------------------------------------------------------------------------------------------------

const START: i64 = 1_794_700_800;

fn at(days: i64) -> FileTime {
    FileTime::from_unix_secs(START + days * 86_400)
}

fn session() -> SessionId {
    SessionId::new(at(0), 0x9f3a_6c1d_2b7e_4a50)
}

fn expiry(n: u32) -> ExecExpiryId {
    ExecExpiryId {
        session: session(),
        op: OpId(n),
    }
}

fn item(n: u32, user_data: bool) -> ExpiringItem {
    let session = session();
    ExpiringItem {
        id: expiry(n),
        item: CandidateId(format!("c-{n:03}")),
        original_path: format!(r"C:\Vendor\app-{n}"),
        quarantine_path: format!(
            r"C:\ProgramData\Purge\Quarantine\{}\{n}\app-{n}",
            session.as_str()
        ),
        expires: at(-1),
        bytes: 4096 + u64::from(n),
        is_dir: false,
        user_data,
        unfinished: false,
    }
}

fn backup(n: u32, user_data: bool) -> ExpiringBackup {
    ExpiringBackup {
        id: expiry(n),
        item: CandidateId(format!("c-{n:03}")),
        files: vec![
            format!(r"reg\0000{n:02}.regbackup.json"),
            format!(r"def\0000{n:02}.json"),
        ],
        expires: at(-2),
        bytes: 6,
        user_data,
        unfinished: false,
    }
}

/// One purge as the handler called it, with the consent it built.
#[derive(Debug, Default, Clone)]
struct Call {
    ids: Vec<ExecExpiryId>,
    /// For every unit the store held when the call arrived: was it named?
    named: BTreeMap<ExecExpiryId, bool>,
    /// For every unit: was it confirmed as user data?
    confirmed: BTreeMap<ExecExpiryId, bool>,
    /// For every backup file of every unit: was it named?
    files: BTreeMap<ExecExpiryId, Vec<(String, bool)>>,
    /// For every unit: was it allowed before its retention ends?
    early: BTreeMap<ExecExpiryId, bool>,
}

#[derive(Default)]
struct Scripted {
    items: Mutex<Vec<ExpiringItem>>,
    backups: Mutex<Vec<ExpiringBackup>>,
    /// Quarantined items whose retention has not ended.
    not_due: Mutex<Vec<ExpiringItem>>,
    apps: BTreeMap<SessionId, String>,
    calls: Mutex<Vec<Call>>,
    fail: Mutex<Option<StorageError>>,
    /// What `purge` refuses with, after recording the call.
    refuse: Mutex<Option<PurgeError>>,
    /// What `writer_busy` answers.
    writer_busy: Mutex<bool>,
    gate: Mutex<Option<Arc<Gate>>>,
    purge_started: Gate,
}

impl Scripted {
    fn new() -> Scripted {
        Scripted::default()
    }
}

impl Scripted {
    fn add_item(&self, item: ExpiringItem) {
        self.items.lock().unwrap().push(item);
    }

    fn add_backup(&self, backup: ExpiringBackup) {
        self.backups.lock().unwrap().push(backup);
    }

    /// A quarantined item whose retention ends in 20 days.
    fn add_not_due(&self, item: ExpiringItem) {
        self.not_due.lock().unwrap().push(ExpiringItem {
            expires: at(420),
            ..item
        });
    }

    fn fail_listing(&self, error: StorageError) {
        *self.fail.lock().unwrap() = Some(error);
    }

    /// Makes `purge` wait until the returned gate opens, after announcing that it started.
    fn hold_purge(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        *self.gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn held_ids(&self) -> Vec<ExecExpiryId> {
        let mut ids: Vec<ExecExpiryId> = self
            .items
            .lock()
            .unwrap()
            .iter()
            .map(|i| i.id.clone())
            .collect();
        ids.extend(self.backups.lock().unwrap().iter().map(|b| b.id.clone()));
        ids.extend(self.not_due.lock().unwrap().iter().map(|i| i.id.clone()));
        ids
    }
}

impl ExpirySource for Scripted {
    fn now(&self) -> FileTime {
        at(400)
    }

    fn writer_busy(&self) -> bool {
        *self.writer_busy.lock().unwrap()
    }

    fn listing(&self, _now: FileTime) -> Result<Listing, StorageError> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(Listing {
            items: self.items.lock().unwrap().clone(),
            backups: self.backups.lock().unwrap().clone(),
            not_due: self.not_due.lock().unwrap().clone(),
            apps: self.apps.clone(),
        })
    }

    fn purge(
        &self,
        ids: &[ExecExpiryId],
        consent: &PurgeConsent,
        _now: FileTime,
    ) -> Result<PurgeReport, PurgeError> {
        let held = self.held_ids();
        let mut call = Call {
            ids: ids.to_vec(),
            ..Call::default()
        };
        for id in &held {
            call.named.insert(id.clone(), consent.names(id));
            call.confirmed
                .insert(id.clone(), consent.confirms_user_data(id));
            call.early.insert(id.clone(), consent.allows_early(id));
        }
        for unit in self.backups.lock().unwrap().iter() {
            call.files.insert(
                unit.id.clone(),
                unit.files
                    .iter()
                    .map(|file| (file.clone(), consent.names_file(&unit.id, file)))
                    .collect(),
            );
        }
        self.calls.lock().unwrap().push(call);
        if let Some(refusal) = self.refuse.lock().unwrap().clone() {
            return Err(refusal);
        }

        if let Some(gate) = self.gate.lock().unwrap().clone() {
            self.purge_started.open();
            gate.wait(SECS);
        }

        // The store after the walk: the purged units are gone (so the next listing does not offer
        // them and a replay is `gone`), the others stay.
        self.items
            .lock()
            .unwrap()
            .retain(|unit| !ids.contains(&unit.id));
        self.backups
            .lock()
            .unwrap()
            .retain(|unit| !ids.contains(&unit.id));
        // As the executor: an item that is not due goes only when the consent allows it early.
        let kept_not_due: Vec<ExecExpiryId> = ids
            .iter()
            .filter(|id| {
                self.not_due.lock().unwrap().iter().any(|i| &i.id == *id)
                    && !consent.allows_early(id)
            })
            .cloned()
            .collect();
        self.not_due
            .lock()
            .unwrap()
            .retain(|unit| !ids.contains(&unit.id) || kept_not_due.contains(&unit.id));
        let ids: Vec<ExecExpiryId> = ids
            .iter()
            .filter(|id| !kept_not_due.contains(id))
            .cloned()
            .collect();
        Ok(PurgeReport {
            items: ids
                .iter()
                .map(|id| ExecPurgeResult {
                    id: id.clone(),
                    outcome: PurgeOutcome::Purged,
                    expire_recorded: true,
                    entries_deleted: 1,
                    bytes_deleted: 1,
                    op_dir_removed: false,
                })
                .collect(),
            alerts: Vec::new(),
            index: IndexUpdate::NotNeeded,
        })
    }
}

// ---------------------------------------------------------------------------------------------------
// The broker over the scripted store.
// ---------------------------------------------------------------------------------------------------

/// The purge handler as the dispatcher will call it, plus an `uninstall.prepare` that leaves one
/// session open (so a completed purge does not end the broker and a second request can be made).
struct PurgeOnly {
    purge: Purger,
}

impl Handler for PurgeOnly {
    type Session = ();
    type Scan = ();
    type Plan = ();

    fn call(
        &self,
        ctx: &Ctx<'_, Self>,
        call: purge_rpc::methods::PipeCall,
    ) -> Result<Value, purge_rpc::error::ErrorObject> {
        if matches!(call, purge_rpc::methods::PipeCall::UninstallPrepare(_)) {
            let id = ctx.tables().sessions.insert(())?;
            return Ok(json!({ "session_id": id.to_string() }));
        }
        match self.purge.handle(ctx, &call) {
            Some(result) => result,
            None => Err(purge_rpc::error::ErrorObject::runtime(format!(
                "{} is not scripted for this test",
                purge_rpc::table::CallSet::method(&call).name()
            ))),
        }
    }
}

struct Live {
    consent: Arc<ScriptedConsent>,
    client: Client,
    join: Option<JoinHandle<Exit>>,
}

impl Live {
    fn start(source: Arc<Scripted>) -> Live {
        let net = MemNet::default();
        let clock = Arc::new(FakeClock::default());
        let parent = Arc::new(FakeParent::default());
        let consent = Arc::new(ScriptedConsent::default());
        let handler = PurgeOnly {
            purge: Purger::new(source as Arc<dyn ExpirySource>),
        };
        let wiring = Wiring {
            link: net.link(),
            handler,
            expected: expected(),
            parent,
            consent: Arc::new(consent.clone()),
            host: Arc::new(FakeHost),
            clock,
            build: None,
            settings: Settings::default(),
            limits: test_limits(),
        };
        let join = thread::spawn(move || run(wiring));
        let client = net.connect(Ok(()));
        client.send_line(HELLO);
        let hello = client.reply();
        assert_eq!(hello["id"], 1, "{hello}");
        Live {
            consent,
            client,
            join: Some(join),
        }
    }

    fn send(&self, id: u64, method: &str, params: &Value) {
        self.client.send_line(&request(id, method, params));
    }

    fn send_purge(&self, id: u64, ids: &[ExpiryId]) {
        let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
        self.send(id, "quarantine.purge", &json!({ "expiry_ids": ids }));
    }

    fn purge(&self, id: u64, ids: &[ExpiryId]) -> Value {
        self.send_purge(id, ids);
        self.client.reply()
    }

    fn wire(&self, exec: &ExecExpiryId) -> ExpiryId {
        wire_id(exec)
    }

    fn open_session(&self) {
        self.send(
            90,
            "uninstall.prepare",
            &json!({ "program_ids": ["HKLM|64|Vendor_is1"] }),
        );
        let reply = self.client.reply();
        assert!(reply["result"]["session_id"].is_string(), "{reply}");
    }

    fn finish(mut self) -> Exit {
        self.client.close();
        self.join.take().unwrap().join().unwrap()
    }
}

fn result_of(reply: &Value) -> PurgeResult {
    serde_json::from_value(reply["result"].clone()).unwrap_or_else(|e| panic!("{e}: {reply}"))
}

fn pages_text(pages: &[Page]) -> String {
    let mut out = String::new();
    for page in pages {
        out.push_str(&page.title);
        out.push('\n');
        out.push_str(&page.instruction);
        out.push('\n');
        out.push_str(&page.content);
        out.push('\n');
        if let Some(footer) = &page.footer {
            out.push_str(footer);
            out.push('\n');
        }
        if let Some(expanded) = &page.expanded {
            out.push_str(expanded);
            out.push('\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------
// Listing.
// ---------------------------------------------------------------------------------------------------

#[test]
fn expiring_maps_items_and_backups_with_app_class_files_and_the_user_data_flag() {
    let mut source = Scripted::new();
    source.add_item(item(1, false));
    source.add_item(item(2, true));
    source.add_backup(backup(3, false));
    source.apps.insert(session(), "Vendor App".to_owned());
    let source = Arc::new(source);

    let purger = Purger::new(source.clone());
    let list: ExpiringList = purger.expiring(false).unwrap();
    assert_eq!(list.items.len(), 3);

    let first = &list.items[0];
    assert!(first.expiry_id.to_string().starts_with("e-"));
    assert_eq!(first.session, session());
    assert_eq!(first.app, "Vendor App");
    assert_eq!(first.class, RetentionClass::Quarantine);
    assert_eq!(first.expired, at(-1));
    assert_eq!(first.files, vec![r"C:\Vendor\app-1"]);
    assert_eq!(first.bytes, 4096 + 1);
    assert!(!first.user_data);

    assert!(list.items[1].user_data);

    let third = &list.items[2];
    assert_eq!(third.class, RetentionClass::Backup);
    assert_eq!(third.files, backup(3, false).files);
    assert_eq!(third.bytes, 6);

    // The ids are stable across listings and distinct.
    let again: ExpiringList = purger.expiring(false).unwrap();
    let ids = |l: &ExpiringList| -> Vec<String> {
        l.items.iter().map(|i| i.expiry_id.to_string()).collect()
    };
    assert_eq!(ids(&list), ids(&again));
    assert_eq!(ids(&list).into_iter().collect::<HashSet<_>>().len(), 3);
}

#[test]
fn the_bulk_view_refuses_a_user_data_unit() {
    // Defence in depth: even if the split missed one, the bulk dialog will not render it.
    let personal = item(1, true);
    let error = super::view::view_purge(&[super::PurgeUnit::Item(&personal)]);
    assert!(error.is_err(), "a user-data unit has no bulk dialog");
}

#[test]
fn expiring_still_lists_a_session_the_index_cannot_name() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let list = Purger::new(source).expiring(false).unwrap();
    assert_eq!(list.items[0].app, "");
}

// ---------------------------------------------------------------------------------------------------
// Ids the client cannot forge.
// ---------------------------------------------------------------------------------------------------

#[test]
fn the_id_of_the_listing_purges_that_unit_and_no_other() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_item(item(2, false));
    let live = Live::start(source.clone());

    live.send(2, "quarantine.expiring", &json!({}));
    let reply = live.client.reply();
    let listing: ExpiringList = serde_json::from_value(reply["result"].clone()).unwrap();
    assert_eq!(listing.items.len(), 2);
    let first = listing.items[0].expiry_id;

    live.send_purge(3, &[first]);
    let (_, pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the bulk dialog opened");
    let text = pages_text(&pages);
    assert!(text.contains(r"C:\Vendor\app-1"), "{text}");
    live.consent.answer(Outcome::Approved);

    let reply = live.client.reply();
    assert_eq!(result_of(&reply).purged, 1);
    assert_eq!(source.calls()[0].ids, vec![expiry(1)]);
    live.finish();
}

#[test]
fn an_id_that_is_not_due_is_gone_before_a_dialog_opens() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());

    let unknown = ExpiryId::from_bits(0x1234_5678);
    let reply = live.purge(2, &[unknown]);
    assert_eq!(kind(&reply), "gone", "{reply}");
    assert_eq!(reply["error"]["data"]["id"], "expiry", "{reply}");
    assert!(!live.consent.wait_open(Duration::from_millis(150)));
    assert_eq!(source.call_count(), 0);
    live.finish();
}

#[test]
fn a_path_is_not_an_expiry_id() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());

    live.send(
        2,
        "quarantine.purge",
        &json!({ "expiry_ids": [r"C:\Windows\System32"] }),
    );
    let reply = live.client.reply();
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    assert!(!live.consent.wait_open(Duration::from_millis(150)));
    assert_eq!(source.call_count(), 0);
    live.finish();
}

#[test]
fn a_purge_that_is_void_of_ids_is_refused_by_the_wire_type() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());
    live.send(2, "quarantine.purge", &json!({ "expiry_ids": [] }));
    let reply = live.client.reply();
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    assert_eq!(source.call_count(), 0);
    live.finish();
}

// ---------------------------------------------------------------------------------------------------
// Only what was requested and approved.
// ---------------------------------------------------------------------------------------------------

#[test]
fn only_the_requested_units_are_named_and_purged() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_item(item(2, false));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    assert!(live.consent.wait_open(SECS), "the bulk dialog opened");
    let text = pages_text(&live.consent.pages());
    assert!(text.contains(r"C:\Vendor\app-1"), "{text}");
    assert!(!text.contains(r"C:\Vendor\app-2"), "{text}");
    live.consent.answer(Outcome::Approved);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!(result.purged, 1);
    assert_eq!(result.kept, 0);
    assert_eq!(result.outcome, purge_rpc::error::Outcome::Complete);

    let calls = source.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ids, vec![expiry(1)]);
    assert_eq!(calls[0].named.get(&expiry(1)), Some(&true));
    assert_eq!(
        calls[0].named.get(&expiry(2)),
        Some(&false),
        "an item the request did not name is not in the consent"
    );
    assert_eq!(source.held_ids(), vec![expiry(2)]);
    live.finish();
}

#[test]
fn the_same_id_twice_names_one_unit() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one, one]);
    assert!(live.consent.wait_open(SECS));
    // One unit, one entry: a duplicated unit would make `view_purge` refuse the whole dialog.
    assert!(pages_text(&live.consent.pages()).contains("(1)"));
    live.consent.answer(Outcome::Approved);

    let reply = live.client.reply();
    assert_eq!(result_of(&reply).purged, 1);
    assert_eq!(source.calls()[0].ids, vec![expiry(1)]);
    live.finish();
}

#[test]
fn a_backup_unit_names_every_one_of_its_files_in_the_consent() {
    let source = Arc::new(Scripted::new());
    source.add_backup(backup(3, false));
    let live = Live::start(source.clone());
    let id = live.wire(&expiry(3));

    live.send_purge(2, &[id]);
    assert!(live.consent.wait_open(SECS));
    let text = pages_text(&live.consent.pages());
    for file in backup(3, false).files {
        assert!(text.contains(&file), "{text}");
    }
    live.consent.answer(Outcome::Approved);
    let reply = live.client.reply();
    assert_eq!(result_of(&reply).purged, 1);

    let calls = source.calls();
    let files = calls[0].files.get(&expiry(3)).unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|(_, named)| *named), "{files:?}");
    live.finish();
}

// ---------------------------------------------------------------------------------------------------
// User data: one dialog each, never in the bulk dialog.
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_user_data_item_gets_its_own_dialog_and_a_decline_keeps_it() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_item(item(2, true));
    let live = Live::start(source.clone());
    let plain = live.wire(&expiry(1));
    let personal = live.wire(&expiry(2));

    live.send_purge(2, &[plain, personal]);
    let (seen, bulk_pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the bulk dialog opened");
    let bulk = pages_text(&bulk_pages);
    assert!(bulk.contains(r"C:\Vendor\app-1"), "{bulk}");
    assert!(
        !bulk.contains(r"C:\Vendor\app-2"),
        "the user-data item is not in the bulk dialog: {bulk}"
    );
    live.consent.answer(Outcome::Approved);

    let (_, personal_pages) = live
        .consent
        .next_dialog(seen, SECS)
        .expect("the user-data dialog opened");
    let personal_text = pages_text(&personal_pages);
    assert!(
        personal_text.contains("Delete this user data for good?"),
        "{personal_text}"
    );
    assert!(
        personal_text.contains(r"C:\Vendor\app-2"),
        "{personal_text}"
    );
    assert!(
        !personal_text.contains(r"C:\Vendor\app-1"),
        "{personal_text}"
    );
    live.consent.answer(Outcome::Declined);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!(result.purged, 1);
    assert_eq!(result.kept, 1);
    assert_eq!(result.outcome, purge_rpc::error::Outcome::Partial);

    let calls = source.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ids, vec![expiry(1)]);
    assert_eq!(
        calls[0].named.get(&expiry(2)),
        Some(&false),
        "a declined user-data item is not named"
    );
    assert_eq!(
        calls[0].confirmed.get(&expiry(1)),
        Some(&false),
        "a plain item is never confirmed as user data"
    );
    assert_eq!(source.held_ids(), vec![expiry(2)]);
    live.finish();
}

#[test]
fn every_user_data_item_gets_a_dialog_of_its_own() {
    // The executor marks every unit as user data when a session has no scan copy (its own test
    // `without_a_scan_copy_every_item_counts_as_user_data`); the broker then asks one dialog per
    // unit, backup units included.
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, true));
    source.add_item(item(2, true));
    source.add_backup(backup(3, true));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));
    let two = live.wire(&expiry(2));
    let three = live.wire(&expiry(3));

    live.send_purge(2, &[one, two, three]);
    let mut seen = 0;
    let mut seen_text = Vec::new();
    for _ in 0..3 {
        let (number, pages) = live
            .consent
            .next_dialog(seen, SECS)
            .expect("each user-data item has a dialog");
        seen = number;
        seen_text.push(pages_text(&pages));
        live.consent.answer(Outcome::Approved);
    }
    assert!(
        live.consent
            .next_dialog(seen, Duration::from_millis(150))
            .is_none(),
        "exactly one dialog per user-data item"
    );

    let seen = seen_text;
    assert!(seen[0].contains(r"C:\Vendor\app-1"), "{}", seen[0]);
    assert!(!seen[0].contains(r"C:\Vendor\app-2"), "{}", seen[0]);
    assert!(seen[1].contains(r"C:\Vendor\app-2"), "{}", seen[1]);
    assert!(!seen[1].contains(r"C:\Vendor\app-1"), "{}", seen[1]);
    assert!(
        seen[2].contains(r"reg\000003.regbackup.json"),
        "{}",
        seen[2]
    );
    assert!(!seen[2].contains(r"C:\Vendor\app-1"), "{}", seen[2]);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!(result.purged, 3);
    assert_eq!(result.kept, 0);
    let calls = source.calls();
    assert_eq!(calls[0].ids.len(), 3);
    assert_eq!(calls[0].confirmed.get(&expiry(1)), Some(&true));
    assert_eq!(calls[0].confirmed.get(&expiry(2)), Some(&true));
    assert_eq!(calls[0].confirmed.get(&expiry(3)), Some(&true));
    live.finish();
}

#[test]
fn a_declined_bulk_dialog_changes_nothing_and_asks_no_user_data_dialog() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_item(item(2, true));
    let live = Live::start(source.clone());
    let plain = live.wire(&expiry(1));
    let personal = live.wire(&expiry(2));

    live.send_purge(2, &[plain, personal]);
    let (seen, _) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the bulk dialog opened");
    live.consent.answer(Outcome::Declined);
    assert!(
        live.consent
            .next_dialog(seen, Duration::from_millis(150))
            .is_none(),
        "a Cancel of the bulk dialog stops the request"
    );

    let reply = live.client.reply();
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert_eq!(source.call_count(), 0);
    assert_eq!(source.held_ids().len(), 2);
    live.finish();
}

// ---------------------------------------------------------------------------------------------------
// Purge once, and only once.
// ---------------------------------------------------------------------------------------------------

#[test]
fn declining_every_dialog_is_consent_declined_and_does_not_end_the_broker() {
    // Review S3 / flagged point 3: with no dialog approved the answer is `consent_declined`, and an
    // `Err` is not a completed change, so the broker keeps serving.
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, true));
    source.add_item(item(2, true));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));
    let two = live.wire(&expiry(2));

    live.send_purge(2, &[one, two]);
    let mut seen = 0;
    for _ in 0..2 {
        let (number, _) = live
            .consent
            .next_dialog(seen, SECS)
            .expect("each user-data item has a dialog");
        seen = number;
        live.consent.answer(Outcome::Declined);
    }
    assert!(
        live.consent
            .next_dialog(seen, Duration::from_millis(150))
            .is_none(),
        "exactly one dialog per user-data item"
    );

    let reply = live.client.reply();
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert_eq!(source.call_count(), 0, "nothing was purged");
    assert_eq!(source.held_ids().len(), 2);

    // Still serving: the declined request did not start the drain.
    live.send(3, "quarantine.expiring", &json!({}));
    let reply = live.client.reply();
    assert_eq!(reply["id"], 3, "{reply}");
    assert!(reply["result"]["items"].is_array(), "{reply}");

    let exit = live.finish();
    assert_eq!(
        exit.reason,
        ExitReason::PipeLost,
        "the broker ends because the client closed, not as a completed change"
    );
}

#[test]
fn a_second_purge_of_the_same_items_is_gone() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());
    live.open_session();
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    assert!(live.consent.wait_open(SECS));
    live.consent.answer(Outcome::Approved);
    let first = live.client.reply();
    assert_eq!(result_of(&first).purged, 1);

    let second = live.purge(3, &[one]);
    assert_eq!(kind(&second), "gone", "{second}");
    assert_eq!(second["error"]["data"]["id"], "expiry", "{second}");
    assert_eq!(source.call_count(), 1);
    live.finish();
}

#[test]
fn a_second_purge_while_the_dialog_is_open_is_busy() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());
    live.open_session();
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    assert!(live.consent.wait_open(SECS));
    live.send_purge(3, &[one]);
    let busy = live.client.reply();
    assert_eq!(kind(&busy), "busy", "{busy}");

    live.consent.answer(Outcome::Approved);
    let done = live.client.reply();
    assert_eq!(result_of(&done).purged, 1);
    assert_eq!(source.call_count(), 1);
    live.finish();
}

// ---------------------------------------------------------------------------------------------------
// The UI dies midway.
// ---------------------------------------------------------------------------------------------------

#[test]
fn the_ui_lost_with_the_dialog_open_purges_nothing() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let mut live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    assert!(live.consent.wait_open(SECS));
    live.client.close();

    let deadline = std::time::Instant::now() + SECS;
    while !live.consent.closed_by_broker() {
        assert!(
            std::time::Instant::now() < deadline,
            "the closer closes the dialog"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // The handler was answered Decline by the closing dialog; nothing was named or purged.
    assert_eq!(source.call_count(), 0);
    assert_eq!(source.held_ids(), vec![expiry(1)]);
    live.join.take().unwrap().join().unwrap();
}

#[test]
fn the_ui_lost_after_approval_finishes_the_purge() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let gate = source.hold_purge();
    let mut live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    assert!(live.consent.wait_open(SECS));
    live.consent.answer(Outcome::Approved);
    assert!(source.purge_started.wait(SECS), "the purge started");
    live.client.close();
    gate.open();

    // The answer cannot be sent, but the mutating request runs to its end.
    let deadline = std::time::Instant::now() + SECS;
    while !source.held_ids().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the purge finished after the client was lost"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(source.calls()[0].ids, vec![expiry(1)]);
    live.join.take().unwrap().join().unwrap();
}

// ---------------------------------------------------------------------------------------------------
// A store that cannot be read.
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_store_that_cannot_be_listed_purges_nothing() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));
    source.fail_listing(StorageError::VolumeMismatch {
        path: PathBuf::from(r"C:\ProgramData\Purge\sessions"),
        expected: 1,
        actual: 2,
    });

    let reply = live.purge(2, &[one]);
    assert_eq!(kind(&reply), "store_integrity", "{reply}");
    assert_eq!(source.call_count(), 0);
    assert!(!live.consent.wait_open(Duration::from_millis(150)));
    live.finish();
}

/// A purge while another broker writes the store (single writer, review R3) is `busy` before any dialog:
/// the user is not asked to delete what would be refused, and nothing was deleted.
#[test]
fn a_purge_refused_by_another_writer_of_the_store_is_busy() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    *source.writer_busy.lock().unwrap() = true;
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    let reply = live.purge(2, &[one]);
    assert_eq!(kind(&reply), "busy", "{reply}");
    assert!(
        !live.consent.wait_open(Duration::from_millis(150)),
        "no dialog opens"
    );
    assert_eq!(source.call_count(), 0);
    assert_eq!(source.held_ids(), vec![expiry(1)], "nothing was deleted");
    live.finish();
}

/// Another writer that took the store between the dialog and the purge: the purge's own lock refuses it,
/// `busy`, and nothing was deleted.
#[test]
fn a_purge_whose_lock_is_taken_after_the_dialog_is_busy_and_deletes_nothing() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    *source.refuse.lock().unwrap() = Some(PurgeError::Store(StorageError::WriterBusy {
        path: PathBuf::from(r"C:\ProgramData\Purge\sessions\writer.lock"),
    }));
    let live = Live::start(source.clone());
    let one = live.wire(&expiry(1));

    live.send_purge(2, &[one]);
    live.consent
        .next_dialog(0, SECS)
        .expect("the bulk dialog opened");
    live.consent.answer(Outcome::Approved);
    let reply = live.client.reply();
    assert_eq!(kind(&reply), "busy", "{reply}");
    assert_eq!(source.held_ids(), vec![expiry(1)], "nothing was deleted");
    live.finish();
}

// ---------------------------------------------------------------------------------------------------
// Delete now: a quarantined item before its retention ends.
// ---------------------------------------------------------------------------------------------------

/// The words every "Delete now" dialog must carry.
fn assert_says_delete_now(text: &str) {
    assert!(text.contains("before"), "{text}");
    assert!(text.contains("retention"), "{text}");
    assert!(text.contains("This cannot be undone."), "{text}");
    assert!(
        text.contains("Undo and History can no longer restore them")
            || text.contains("Undo and History can no longer restore it"),
        "{text}"
    );
}

#[test]
fn items_that_are_not_due_are_listed_only_when_asked_for_and_marked() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_backup(backup(2, false));
    source.add_not_due(item(3, false));
    source.add_not_due(item(4, true));
    let live = Live::start(source.clone());

    // Without the flag (absent params, `{}`, an explicit false): what is past retention, as before.
    for (id, params) in [
        (2, json!({})),
        (3, json!({ "include_not_due": false })),
        (4, Value::Null),
    ] {
        live.send(id, "quarantine.expiring", &params);
        let reply = live.client.reply();
        let list: ExpiringList = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(list.items.len(), 2, "{reply}");
        assert!(list.items.iter().all(|i| i.due), "{reply}");
    }

    live.send(
        5,
        "quarantine.expiring",
        &json!({ "include_not_due": true }),
    );
    let reply = live.client.reply();
    let list: ExpiringList = serde_json::from_value(reply["result"].clone()).unwrap();
    let rows: Vec<(ExpiryId, bool, RetentionClass, bool)> = list
        .items
        .iter()
        .map(|i| (i.expiry_id, i.due, i.class, i.user_data))
        .collect();
    assert_eq!(
        rows,
        [
            (
                live.wire(&expiry(1)),
                true,
                RetentionClass::Quarantine,
                false
            ),
            (live.wire(&expiry(2)), true, RetentionClass::Backup, false),
            (
                live.wire(&expiry(3)),
                false,
                RetentionClass::Quarantine,
                false
            ),
            (
                live.wire(&expiry(4)),
                false,
                RetentionClass::Quarantine,
                true
            ),
        ]
    );
    // The retention end of an item that is not due is in the future, and it names no path but the
    // original one, for display.
    assert_eq!(list.items[2].expired, at(420));
    assert_eq!(list.items[2].files, vec![r"C:\Vendor\app-3"]);

    // An unknown member is refused by the wire type, as for every params object.
    live.send(6, "quarantine.expiring", &json!({ "path": r"C:\Windows" }));
    assert_eq!(live.client.reply()["error"]["code"], -32602);
    live.finish();
}

#[test]
fn an_item_that_is_not_due_is_deleted_only_through_the_delete_now_dialog() {
    let source = Arc::new(Scripted::new());
    source.add_not_due(item(1, false));
    source.add_not_due(item(2, false));
    let live = Live::start(source.clone());
    // A session stays open, so the completed delete does not end the broker before the replay below.
    live.open_session();

    // The id comes from the broker's own listing.
    live.send(
        2,
        "quarantine.expiring",
        &json!({ "include_not_due": true }),
    );
    let reply = live.client.reply();
    let listing: ExpiringList = serde_json::from_value(reply["result"].clone()).unwrap();
    let first = listing.items[0].expiry_id;
    assert!(!listing.items[0].due);

    live.send_purge(3, &[first]);
    let (_, pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the Delete now dialog opened");
    let text = pages_text(&pages);
    assert!(
        text.contains("Delete 1 quarantined item now, before its retention ends?"),
        "{text}"
    );
    assert_says_delete_now(&text);
    assert!(text.contains(r"C:\Vendor\app-1"), "{text}");
    assert!(!text.contains(r"C:\Vendor\app-2"), "{text}");
    assert!(!text.contains("expired"), "not called expired: {text}");
    live.consent.answer(Outcome::Approved);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!((result.purged, result.kept), (1, 0), "{reply}");
    let calls = source.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ids, vec![expiry(1)]);
    assert_eq!(calls[0].named.get(&expiry(1)), Some(&true));
    assert_eq!(
        calls[0].early.get(&expiry(1)),
        Some(&true),
        "approved in the Delete now dialog: allowed early"
    );
    assert_eq!(calls[0].named.get(&expiry(2)), Some(&false));
    assert_eq!(
        calls[0].early.get(&expiry(2)),
        Some(&false),
        "an item the request did not name is not allowed early"
    );
    assert_eq!(source.held_ids(), vec![expiry(2)]);

    // Deleted is gone: the same id names nothing in the next listing.
    let again = live.purge(4, &[first]);
    assert_eq!(kind(&again), "gone", "{again}");
    assert_eq!(source.call_count(), 1);
    live.finish();
}

#[test]
fn a_declined_delete_now_dialog_deletes_nothing() {
    let source = Arc::new(Scripted::new());
    source.add_not_due(item(1, false));
    source.add_not_due(item(2, true));
    let live = Live::start(source.clone());
    live.open_session();
    let plain = live.wire(&expiry(1));
    let personal = live.wire(&expiry(2));

    live.send_purge(2, &[plain, personal]);
    let (seen, pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the Delete now dialog opened");
    assert_says_delete_now(&pages_text(&pages));
    live.consent.answer(Outcome::Declined);
    assert!(
        live.consent
            .next_dialog(seen, Duration::from_millis(150))
            .is_none(),
        "a Cancel of the Delete now dialog asks for no user data either"
    );
    let reply = live.client.reply();
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert_eq!(source.call_count(), 0);
    assert_eq!(source.held_ids().len(), 2, "nothing was deleted");

    // Not a completed change: the broker still serves, and the items are still listed.
    live.send(
        3,
        "quarantine.expiring",
        &json!({ "include_not_due": true }),
    );
    let reply = live.client.reply();
    assert_eq!(reply["result"]["items"].as_array().unwrap().len(), 2);
    live.finish();
}

#[test]
fn user_data_that_is_not_due_gets_a_delete_now_dialog_of_its_own() {
    let source = Arc::new(Scripted::new());
    source.add_not_due(item(1, false));
    source.add_not_due(item(2, true));
    source.add_not_due(item(3, true));
    let live = Live::start(source.clone());
    let ids = [1, 2, 3].map(|n| live.wire(&expiry(n)));

    live.send_purge(2, &ids);
    let (seen, bulk_pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the Delete now bulk dialog opened");
    let bulk = pages_text(&bulk_pages);
    assert!(bulk.contains(r"C:\Vendor\app-1"), "{bulk}");
    assert!(
        !bulk.contains(r"C:\Vendor\app-2") && !bulk.contains(r"C:\Vendor\app-3"),
        "user data is not in the bulk dialog: {bulk}"
    );
    live.consent.answer(Outcome::Approved);

    let (seen, second) = live
        .consent
        .next_dialog(seen, SECS)
        .expect("the first user-data dialog opened");
    let text = pages_text(&second);
    assert!(
        text.contains("Delete this user data now, before its retention ends?"),
        "{text}"
    );
    assert_says_delete_now(&text);
    assert!(text.contains(r"C:\Vendor\app-2"), "{text}");
    assert!(!text.contains(r"C:\Vendor\app-3"), "{text}");
    live.consent.answer(Outcome::Declined);

    let (_, third) = live
        .consent
        .next_dialog(seen, SECS)
        .expect("the second user-data dialog opened");
    let text = pages_text(&third);
    assert!(text.contains(r"C:\Vendor\app-3"), "{text}");
    live.consent.answer(Outcome::Approved);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!((result.purged, result.kept), (2, 1), "{reply}");
    assert_eq!(result.outcome, purge_rpc::error::Outcome::Partial);
    let calls = source.calls();
    assert_eq!(calls[0].ids, vec![expiry(1), expiry(3)]);
    assert_eq!(calls[0].confirmed.get(&expiry(1)), Some(&false));
    assert_eq!(calls[0].confirmed.get(&expiry(3)), Some(&true));
    assert_eq!(calls[0].early.get(&expiry(3)), Some(&true));
    assert_eq!(
        calls[0].named.get(&expiry(2)),
        Some(&false),
        "the declined user data is not named"
    );
    assert_eq!(calls[0].early.get(&expiry(2)), Some(&false));
    assert_eq!(source.held_ids(), vec![expiry(2)]);
    live.finish();
}

#[test]
fn expired_units_and_items_that_are_not_due_are_asked_apart_and_only_the_latter_are_early() {
    let source = Arc::new(Scripted::new());
    source.add_item(item(1, false));
    source.add_backup(backup(2, false));
    source.add_not_due(item(3, false));
    let live = Live::start(source.clone());
    let ids = [1, 2, 3].map(|n| live.wire(&expiry(n)));

    live.send_purge(2, &ids);
    let (seen, expired_pages) = live
        .consent
        .next_dialog(0, SECS)
        .expect("the purge dialog opened");
    let expired = pages_text(&expired_pages);
    assert!(expired.contains("expired"), "{expired}");
    assert!(expired.contains(r"C:\Vendor\app-1"), "{expired}");
    assert!(
        !expired.contains(r"C:\Vendor\app-3"),
        "the item that is not due is not called expired: {expired}"
    );
    live.consent.answer(Outcome::Approved);

    let (_, now_pages) = live
        .consent
        .next_dialog(seen, SECS)
        .expect("the Delete now dialog opened");
    let now = pages_text(&now_pages);
    assert_says_delete_now(&now);
    assert!(now.contains(r"C:\Vendor\app-3"), "{now}");
    assert!(
        !now.contains(r"C:\Vendor\app-1") && !now.contains("regbackup"),
        "no expired unit and no backup in the Delete now dialog: {now}"
    );
    // Declined: the expired units' approval stands, the item that is not due stays.
    live.consent.answer(Outcome::Declined);

    let reply = live.client.reply();
    let result = result_of(&reply);
    assert_eq!((result.purged, result.kept), (2, 1), "{reply}");
    let calls = source.calls();
    assert_eq!(calls[0].ids, vec![expiry(1), expiry(2)]);
    for n in [1, 2, 3] {
        assert_eq!(
            calls[0].early.get(&expiry(n)),
            Some(&false),
            "nothing is allowed early: unit {n}"
        );
    }
    assert_eq!(source.held_ids(), vec![expiry(3)]);
    live.finish();
}

#[test]
fn a_backup_has_no_delete_now_dialog() {
    // The executor lists no backup as not due. If one arrived there all the same, the view refuses
    // it and nothing is asked or deleted.
    let unit = backup(1, false);
    assert!(super::view::view_delete_now(&[super::PurgeUnit::Backup(&unit)]).is_err());
    let personal = backup(2, true);
    assert!(super::view::view_delete_now_user_data(super::PurgeUnit::Backup(&personal)).is_err());
}
