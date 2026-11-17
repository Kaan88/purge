//! Executor action: delete and recreate a Windows service (M1b).
//!
//! Every test runs over the in-memory backend `act_service::fake::FakeServices` and a relaxed store with
//! a real journal: nothing here creates, changes or deletes a service on this machine. The only live
//! test reads a built-in service and is read-only; the live create/delete round trip is VM-rig only
//! (ignored).

#![cfg(feature = "test-support")]

mod common;

use std::path::Path;

use common::{Scratch, safe};
use purge_exec::act_service::fake::{FakeService, FakeServices, dword, sz};
use purge_exec::act_service::{
    LiveServices, ObjErr, ObjErrKind, ServiceBackend, SvcPrepareArgs, SvcPrepared, SvcRemoval,
    SvcUndoArgs, SvcUndoPrepared, SvcUndoResult, SvcValidated, act, complete, prepare,
    prepare_undo, probe, run_undo, take_fault_trace, tree_difference, validate,
};
use purge_exec::fault;
use purge_exec::gate::Stamp;
use purge_exec::journal::{JournalWriter, sha256_bytes};
use purge_exec::objdef::{SvcDef, read_def};
use purge_exec::recover::Probe;
use purge_exec::storage::{BackupKind, SessionDir, StorageRoots, backup_rel};
use purge_guard::canon::GuardEnv;
use purge_guard::deny::{DenyList, ids};
use purge_model::exec::journal::{
    GateExemptions, Header, Intent, ItemFacts, JournalSchema, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, ItemOutcome, OpId, SkipReason};
use purge_model::exec::regbackup::RegTree;
use purge_model::{Action, Blocker, Candidate, ObjectKind, Reversibility, ScanMode, Target};
use purge_win::reg::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

const NAME: &str = "VendorUpdate";
const IMAGE: &str = r#""%ProgramFiles%\Vendor\update.exe" -service"#;
const ROOT: &str = r"C:\Program Files\Vendor";
const OP: OpId = OpId(1);

/// A plain own-process service with a description, a `Parameters` subtree, a value the SCM never
/// writes, and a `Security` subkey (so the DACL is applied on undo).
fn vendor_service() -> FakeService {
    let mut s = FakeService::new(NAME, IMAGE, None);
    s.set_value("Description", REG_SZ, sz("Keeps Vendor up to date"));
    s.set_value("VendorTag", REG_SZ, sz("stable"));
    s.scm.config2.description = Some("Keeps Vendor up to date".into());
    let params = s.add_key(0, "Parameters", vec![("Channel", REG_SZ, sz("beta"))]);
    s.add_key(params, "Sub", vec![("Depth", REG_DWORD, dword(2))]);
    s.add_key(
        0,
        "Security",
        vec![("Security", 3, vec![1, 0, 20, 0x80, 9, 9])],
    );
    s
}

fn deny() -> DenyList {
    DenyList::compile(&GuardEnv::sample())
}

fn candidate(service: &FakeService) -> Candidate {
    let mut cand = safe(
        "c-svc",
        Target::Service { name: NAME.into() },
        Action::DeleteKey,
    );
    cand.object_fp = Some(service.identity().fp());
    cand
}

fn exec_op() -> ExecOp {
    ExecOp::DeleteService { name: NAME.into() }
}

struct World {
    _s: Scratch,
    roots: StorageRoots,
    session: SessionDir,
    journal: JournalWriter,
    fake: FakeServices,
    deny: DenyList,
    /// The journal header's program roots, as the caller passes them to prepare and the act.
    program_roots: Vec<String>,
}

fn world(tag: &str, service: FakeService) -> World {
    let s = Scratch::new(tag);
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
    let session = roots.create_session().unwrap();
    let journal = JournalWriter::create(&session, header(&session)).unwrap();
    World {
        _s: s,
        roots,
        session,
        journal,
        fake: FakeServices::with([service]),
        deny: deny(),
        program_roots: vec![ROOT.to_owned()],
    }
}

fn header(session: &SessionDir) -> Header {
    Header {
        schema: JournalSchema,
        session: session.id().clone(),
        created: purge_model::FileTime(134_078_121_020_000_000),
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "m1b.1".into(),
        mode: ScanMode::Post,
        items: 1,
        allow_irreversible: false,
        volumes: Vec::new(),
        program_roots: Vec::new(),
    }
}

fn stamp_of(v: &SvcValidated) -> (Stamp, ItemFacts) {
    match v {
        SvcValidated::Validated { stamp, facts } => (stamp.clone(), facts.clone()),
        SvcValidated::Decided(r) => panic!("not validated: {r:?}"),
    }
}

impl World {
    fn validate(&self, cand: &Candidate) -> SvcValidated {
        validate(&self.fake, &self.deny, &exec_op(), cand)
    }

    fn prepare(&self, stamp: &Stamp, planned: Reversibility) -> SvcPrepared {
        let item = purge_model::CandidateId("c-svc".into());
        let op = exec_op();
        prepare(
            &self.fake,
            &self.session,
            &SvcPrepareArgs {
                op: OP,
                item: &item,
                exec_op: &op,
                validated: stamp,
                planned,
                key_limit: 50,
                program_roots: &self.program_roots,
                env: self.deny.env(),
            },
        )
        .unwrap()
    }

    /// Validate, prepare (planned `planned`) and journal the intent; the removal and its intent.
    fn ready(&mut self, planned: Reversibility) -> (Box<SvcRemoval>, Intent) {
        let service = self.fake.service(NAME).unwrap();
        let cand = candidate(&service);
        let (stamp, facts) = stamp_of(&self.validate(&cand));
        self.journal
            .validated(Validated {
                op: OP,
                item: cand.id.clone(),
                target: cand.target.clone(),
                facts,
                exemptions: GateExemptions::default(),
            })
            .unwrap();
        match self.prepare(&stamp, planned) {
            SvcPrepared::Ready(removal) => {
                let intent = removal.intent().clone();
                (removal, intent)
            }
            SvcPrepared::Decided(r) => panic!("not ready: {r:?}"),
        }
    }

    /// The whole run of the item: validate, prepare, intent, `act.before`, act, done.
    fn run(&mut self) -> (ItemOutcome, Intent) {
        let (removal, intent) = self.ready(Reversibility::Full);
        let token = self.journal.intent(intent.clone()).unwrap();
        fault::point(fault::ACT_BEFORE);
        let r = act(
            &self.fake,
            &self.deny,
            &self.session,
            removal,
            &token,
            &self.program_roots,
        );
        self.journal.done(token, r.outcome.clone()).unwrap();
        (r.outcome, intent)
    }

    fn undo_args<'a>(
        &self,
        intent: &'a Intent,
        done: Option<&'a ItemOutcome>,
        own_attempt: bool,
        roots: &'a [String],
    ) -> SvcUndoArgs<'a> {
        SvcUndoArgs {
            intent,
            done,
            own_attempt,
            program_roots: roots,
        }
    }

    /// Closes the journal (as a crash would) and opens it again for appending.
    fn reopen_journal(&mut self) {
        let other = self.roots.create_session().unwrap();
        let placeholder = JournalWriter::create(&other, header(&other)).unwrap();
        drop(std::mem::replace(&mut self.journal, placeholder));
        self.journal = JournalWriter::open_append(&self.session).unwrap();
    }

    /// The whole undo of the op, journalled.
    fn undo(&mut self, intent: &Intent, done: &ItemOutcome) -> SvcUndoResult {
        let roots = vec![ROOT.to_owned()];
        let args = self.undo_args(intent, Some(done), false, &roots);
        match prepare_undo(&self.fake, &self.session, &GuardEnv::sample(), &args) {
            SvcUndoPrepared::Decided(r) => r,
            SvcUndoPrepared::Ready(job) => {
                let token = self.journal.undo_intent(OP).unwrap();
                let r = run_undo(&self.fake, job, &token);
                match &r {
                    SvcUndoResult::Done { outcome, detail } => self
                        .journal
                        .undo_done_noted(token, outcome.clone(), detail)
                        .unwrap(),
                    SvcUndoResult::Conflict { conflict, detail } => self
                        .journal
                        .undo_conflict(token, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                r
            }
        }
    }
}

fn skip_reason(outcome: &ItemOutcome) -> &SkipReason {
    match outcome {
        ItemOutcome::Skipped { reason } => reason,
        other => panic!("not skipped: {other:?}"),
    }
}

fn decided(v: SvcValidated) -> ItemOutcome {
    match v {
        SvcValidated::Decided(r) => r.outcome,
        SvcValidated::Validated { .. } => panic!("validated"),
    }
}

fn conflict(r: &SvcUndoResult) -> &UndoConflict {
    match r {
        SvcUndoResult::Conflict { conflict, .. } => conflict,
        other => panic!("no conflict: {other:?}"),
    }
}

fn done_outcome(r: &SvcUndoResult) -> &UndoOutcome {
    match r {
        SvcUndoResult::Done { outcome, .. } => outcome,
        other => panic!("not done: {other:?}"),
    }
}

/// The two trees hold the same keys and values (order aside).
fn assert_same_tree(live: &RegTree, want: &RegTree) {
    assert_eq!(tree_difference(want, live), None);
    assert_eq!(live.keys.len(), want.keys.len());
}

fn creates(log: &[String]) -> usize {
    log.iter().filter(|l| l.starts_with("create ")).count()
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

#[test]
fn validate_absent_is_vanished() {
    let w = world("svc-v-absent", vendor_service());
    let cand = candidate(&vendor_service());
    w.fake.world().services.clear();
    assert_eq!(decided(w.validate(&cand)), ItemOutcome::Vanished);
}

#[test]
fn validate_passes_a_stopped_vendor_service() {
    let w = world("svc-v-pass", vendor_service());
    let cand = candidate(&vendor_service());
    let (stamp, facts) = stamp_of(&w.validate(&cand));
    let sha = vendor_service().identity().fp().sha256;
    assert_eq!(
        stamp,
        Stamp::Object {
            kind: ObjectKind::Service,
            sha256: sha.clone()
        }
    );
    assert_eq!(
        facts,
        ItemFacts::Object {
            kind: ObjectKind::Service,
            sha256: sha,
            running: false
        }
    );
    // Read-only.
    assert!(w.fake.log().iter().all(|l| l.starts_with("read ")));
}

#[test]
fn validate_digest_mismatch_changed_since_scan() {
    let w = world("svc-v-digest", vendor_service());
    let cand = candidate(&vendor_service());
    w.fake.world().services.values_mut().for_each(|s| {
        s.set_value("Start", REG_DWORD, dword(2));
    });
    assert_eq!(
        skip_reason(&decided(w.validate(&cand))),
        &SkipReason::ChangedSinceScan
    );
    // No plan fingerprint at all: the same.
    let mut bare = cand.clone();
    bare.object_fp = None;
    assert_eq!(
        skip_reason(&decided(w.validate(&bare))),
        &SkipReason::ChangedSinceScan
    );
}

#[test]
fn validate_driver_blocked() {
    let mut driver = vendor_service();
    driver.set_value("Type", REG_DWORD, dword(1));
    let w = world("svc-v-driver", driver.clone());
    let reason = decided(w.validate(&candidate(&driver)));
    assert_eq!(
        skip_reason(&reason),
        &SkipReason::GateBlocked {
            blocker: Blocker::DenyListed {
                rule: ids::SYS_DRIVER.into()
            }
        }
    );
}

#[test]
fn validate_running_is_in_use() {
    let mut running = vendor_service();
    running.state = 4;
    let w = world("svc-v-running", running.clone());
    assert_eq!(
        skip_reason(&decided(w.validate(&candidate(&running)))),
        &SkipReason::GateBlocked {
            blocker: Blocker::InUse
        }
    );
}

#[test]
fn validate_dependents_blocked() {
    let mut s = vendor_service();
    s.dependents = vec!["VendorHelper".into()];
    let w = world("svc-v-deps", s.clone());
    assert_eq!(
        skip_reason(&decided(w.validate(&candidate(&s)))),
        &SkipReason::GateBlocked {
            blocker: Blocker::HasDependents {
                names: vec!["VendorHelper".into()]
            }
        }
    );
}

#[test]
fn validate_delete_flag_blocked() {
    let mut s = vendor_service();
    s.set_value("DeleteFlag", REG_DWORD, dword(1));
    let w = world("svc-v-flag", s.clone());
    assert_eq!(
        skip_reason(&decided(w.validate(&candidate(&s)))),
        &SkipReason::GateBlocked {
            blocker: Blocker::DenyListed {
                rule: ids::SYS_SERVICE_MARKED.into()
            }
        }
    );
}

#[test]
fn validate_per_user_instance_blocked() {
    let mut s = vendor_service();
    s.per_user_instance = true;
    let w = world("svc-v-peruser", s.clone());
    assert_eq!(
        skip_reason(&decided(w.validate(&candidate(&s)))),
        &SkipReason::GateBlocked {
            blocker: Blocker::DenyListed {
                rule: ids::SYS_SERVICE_PERUSER.into()
            }
        }
    );
}

/// Hostile: the scan's fingerprint matches, but the service runs a program under `%SystemRoot%` (a
/// service moved there, or a plan forged with the matching digest): the guard refuses it on facts
/// read now.
#[test]
fn validate_program_moved_under_systemroot_blocked() {
    for image in [
        r"%SystemRoot%\System32\vendorsvc.exe",
        r"\SystemRoot\System32\vendorsvc.exe",
        r"System32\vendorsvc.exe",
        r#""C:\Windows\System32\vendorsvc.exe" -k"#,
    ] {
        let mut s = vendor_service();
        s.set_value("ImagePath", REG_EXPAND_SZ, sz(image));
        let w = world("svc-v-sysroot", s.clone());
        assert_eq!(
            skip_reason(&decided(w.validate(&candidate(&s)))),
            &SkipReason::GateBlocked {
                blocker: Blocker::DenyListed {
                    rule: ids::SYS_SERVICE_WINDOWS.into()
                }
            },
            "{image}"
        );
    }
}

#[test]
fn validate_unusable_names_refused_before_any_read() {
    let w = world("svc-v-name", vendor_service());
    for name in [r"..\Tcpip", "", "a/b"] {
        let op = ExecOp::DeleteService { name: name.into() };
        let cand = safe(
            "c-x",
            Target::Service { name: name.into() },
            Action::DeleteKey,
        );
        let outcome = decided(validate(&w.fake, &w.deny, &op, &cand));
        assert!(
            matches!(
                outcome,
                ItemOutcome::Failed {
                    code: FailCode::Internal,
                    ..
                }
            ),
            "{name}: {outcome:?}"
        );
    }
    assert!(w.fake.log().is_empty());
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

#[test]
fn prepare_writes_verified_def_with_key_backup() {
    let mut w = world("svc-p-def", vendor_service());
    let (_, intent) = w.ready(Reversibility::Full);
    assert!(intent.is_consistent(), "{intent:?}");
    let purge_model::exec::op::Inverse::RecreateService { definition } = &intent.inverse else {
        panic!("{:?}", intent.inverse);
    };
    let def: SvcDef = read_def(&w.session, definition).unwrap();
    assert_eq!(def.name, NAME);
    assert_eq!(def.identity_sha256, vendor_service().identity().fp().sha256);
    assert!(def.account_builtin);
    assert_eq!(def.key_backup.path, backup_rel(BackupKind::Registry, OP));
    assert_eq!(def.key_backup_for(OP), Some(&def.key_backup));
    let backup = purge_exec::regbackup::read_verified(&w.session, &def.key_backup).unwrap();
    assert_eq!(backup.tree().unwrap(), &vendor_service().tree);
    assert_eq!(
        backup.doc().key,
        format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{NAME}")
    );
    assert_eq!(
        def.config2.description.as_deref(),
        Some("Keeps Vendor up to date")
    );
    // Nothing was deleted.
    assert!(w.fake.service(NAME).is_some());
    assert!(!w.fake.log().iter().any(|l| l.starts_with("delete")));
}

/// A crash between the key backup and the intent leaves the backup file: the next prepare adopts it.
#[test]
fn prepare_adopts_its_own_leftover_key_backup() {
    let w = world("svc-p-adopt", vendor_service());
    let (stamp, _) = stamp_of(&w.validate(&candidate(&vendor_service())));
    assert!(matches!(
        w.prepare(&stamp, Reversibility::Full),
        SvcPrepared::Ready(_)
    ));
    // The definition file exists too now; write_def refuses an existing file, so drop it first as
    // the store would leave only the key backup after a crash before write_def.
    let def_rel = backup_rel(BackupKind::Definition, OP);
    w.session.delete_backup_file(&def_rel).unwrap();
    assert!(matches!(
        w.prepare(&stamp, Reversibility::Full),
        SvcPrepared::Ready(_)
    ));
}

/// Hostile: the service is replaced between the key capture and the SCM read.
#[test]
fn prepare_identity_changed_between_backup_and_definition_skips() {
    let w = world("svc-p-race", vendor_service());
    let (stamp, _) = stamp_of(&w.validate(&candidate(&vendor_service())));
    w.fake.after("definition", |world| {
        for s in world.services.values_mut() {
            s.set_value("ImagePath", REG_EXPAND_SZ, sz(r"C:\Users\Public\evil.exe"));
        }
    });
    let SvcPrepared::Decided(r) = w.prepare(&stamp, Reversibility::Full) else {
        panic!("ready");
    };
    assert_eq!(skip_reason(&r.outcome), &SkipReason::ChangedSinceScan);
    // Decided before any backup (the key backup is written only once every check passed, review R2b
    // B1); no definition either.
    let rel = backup_rel(BackupKind::Registry, OP);
    assert!(!w.session.path().join(&rel).exists());
    let def_rel = backup_rel(BackupKind::Definition, OP);
    assert!(!w.session.path().join(&def_rel).exists());
    assert!(!w.fake.log().iter().any(|l| l.starts_with("delete")));
}

#[test]
fn prepare_password_account_planned_full_is_blocked() {
    let mut s = vendor_service();
    s.set_value("ObjectName", REG_SZ, sz(r".\vendorsvc"));
    s.scm.config.service_start_name = Some(r".\vendorsvc".into());
    let w = world("svc-p-pass", s.clone());
    let (stamp, _) = stamp_of(&w.validate(&candidate(&s)));
    let SvcPrepared::Decided(r) = w.prepare(&stamp, Reversibility::Full) else {
        panic!("ready");
    };
    assert_eq!(
        skip_reason(&r.outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::ReversibilityPartial
        }
    );
    // Planned partial: prepared, and the definition says so.
    let SvcPrepared::Ready(removal) = w.prepare(&stamp, Reversibility::Partial) else {
        panic!("decided");
    };
    let purge_model::exec::op::Inverse::RecreateService { definition } = &removal.intent().inverse
    else {
        panic!();
    };
    let def: SvcDef = read_def(&w.session, definition).unwrap();
    assert!(!def.account_builtin);
}

#[test]
fn prepare_stamp_of_another_kind_is_internal() {
    let w = world("svc-p-stamp", vendor_service());
    let stamp = Stamp::Object {
        kind: ObjectKind::Task,
        sha256: vendor_service().identity().fp().sha256,
    };
    let SvcPrepared::Decided(r) = w.prepare(&stamp, Reversibility::Full) else {
        panic!("ready");
    };
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert!(w.fake.log().is_empty());
}

// ---------------------------------------------------------------------------------------------------
// Act
// ---------------------------------------------------------------------------------------------------

/// Hostile: between the intent and the act the service is started, then changed: each time the act
/// gate refuses and nothing is deleted.
#[test]
fn act_gate_rechecks_state_and_digest() {
    type Change = fn(&mut FakeService);
    let changes: [(Change, SkipReason); 3] = [
        (
            |s| s.state = 4,
            SkipReason::GateBlocked {
                blocker: Blocker::InUse,
            },
        ),
        (
            |s| s.set_value("ImagePath", REG_EXPAND_SZ, sz(r"C:\Users\Public\evil.exe")),
            SkipReason::ChangedSinceScan,
        ),
        (
            |s| s.dependents = vec!["Other".into()],
            SkipReason::GateBlocked {
                blocker: Blocker::HasDependents {
                    names: vec!["Other".into()],
                },
            },
        ),
    ];
    for (change, want) in changes {
        let mut w = world("svc-a-gate", vendor_service());
        let (removal, intent) = w.ready(Reversibility::Full);
        let token = w.journal.intent(intent).unwrap();
        w.fake.world().services.values_mut().for_each(change);
        let r = act(
            &w.fake,
            &w.deny,
            &w.session,
            removal,
            &token,
            &w.program_roots,
        );
        assert_eq!(skip_reason(&r.outcome), &want);
        assert!(!w.fake.log().iter().any(|l| l.starts_with("delete")));
        assert!(w.fake.service(NAME).is_some());
        w.journal.done(token, r.outcome).unwrap();
    }
}

#[test]
fn act_deleted_done() {
    let mut w = world("svc-a-done", vendor_service());
    let (outcome, _) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    assert!(w.fake.service(NAME).is_none());
}

/// Another handle keeps the service: it is only marked for delete (spike: `PendingDelete`).
#[test]
fn act_marked_pending_reboot() {
    let mut w = world("svc-a-marked", vendor_service());
    w.fake.world().mark_on_delete = true;
    let (outcome, _) = w.run();
    assert_eq!(outcome, ItemOutcome::PendingDelete);
    assert!(w.fake.service(NAME).is_some());
}

#[test]
fn act_flushes_system_before_done() {
    let mut w = world("svc-a-flush", vendor_service());
    let (removal, intent) = w.ready(Reversibility::Full);
    let token = w.journal.intent(intent).unwrap();
    let before = w.fake.log().len();
    take_fault_trace();
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert_eq!(r.outcome, ItemOutcome::Done);
    let log = w.fake.log()[before..].to_vec();
    let at = |line: &str| log.iter().position(|l| l == line).unwrap();
    assert!(at(&format!("delete {NAME}")) < at("flush"), "{log:?}");
    // The verdict read comes after the flush.
    assert_eq!(log.last().unwrap(), &format!("read {NAME}"));
    assert_eq!(
        take_fault_trace(),
        vec![fault::OBJDELETE_AFTER, fault::ACT_AFTER]
    );
    w.journal.done(token, r.outcome).unwrap();
}

#[test]
fn act_flush_failure_is_verify_failed() {
    let mut w = world("svc-a-flushfail", vendor_service());
    let (removal, intent) = w.ready(Reversibility::Full);
    let token = w.journal.intent(intent).unwrap();
    w.fake.world().fail_next.insert(
        "flush",
        ObjErr::new(ObjErrKind::Other, Some(1021), "flush failed"),
    );
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        }
    ));
}

#[test]
fn act_with_token_of_another_op_does_nothing() {
    let mut w = world("svc-a-token", vendor_service());
    let (removal, intent) = w.ready(Reversibility::Full);
    let _token = w.journal.intent(intent.clone()).unwrap();
    // A token of another item, from another run's journal.
    let other = Intent {
        item: purge_model::CandidateId("c-other".into()),
        ..intent
    };
    let other_session = w.roots.create_session().unwrap();
    let mut other_journal = JournalWriter::create(&other_session, header(&other_session)).unwrap();
    other_journal
        .validated(Validated {
            op: OP,
            item: other.item.clone(),
            target: Target::Service { name: NAME.into() },
            facts: other.pre.clone(),
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    let token2 = other_journal.intent(other).unwrap();
    let before = w.fake.log().len();
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token2,
        &w.program_roots,
    );
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(w.fake.log().len(), before);
}

#[test]
fn complete_present_without_flag_is_failed() {
    // After a delete call that reported success: not "nothing changed" (review R3b M4).
    let w = world("svc-a-complete", vendor_service());
    assert!(matches!(
        complete(&w.fake, NAME).outcome,
        ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------------------------------

fn prepared_intent(w: &mut World) -> Intent {
    let (_, intent) = w.ready(Reversibility::Full);
    intent
}

#[test]
fn probe_absent_done() {
    let mut w = world("svc-pr-absent", vendor_service());
    let intent = prepared_intent(&mut w);
    w.fake.world().services.clear();
    assert_eq!(probe(&w.fake, &intent), Probe::Done(ItemOutcome::Done));
}

#[test]
fn probe_marked_pending_reboot() {
    let mut w = world("svc-pr-marked", vendor_service());
    let intent = prepared_intent(&mut w);
    w.fake
        .world()
        .services
        .values_mut()
        .for_each(|s| s.set_value("DeleteFlag", REG_DWORD, dword(1)));
    assert_eq!(
        probe(&w.fake, &intent),
        Probe::Done(ItemOutcome::PendingDelete)
    );
}

#[test]
fn probe_present_same_digest_not_done() {
    let mut w = world("svc-pr-same", vendor_service());
    let intent = prepared_intent(&mut w);
    assert_eq!(probe(&w.fake, &intent), Probe::NotDone);
    // A resumed run rebuilds the removal from the intent and completes it.
    let removal = SvcRemoval::from_intent(&intent).unwrap();
    let token = w.journal.intent(intent).unwrap();
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        Box::new(removal),
        &token,
        &w.program_roots,
    );
    assert_eq!(r.outcome, ItemOutcome::Done);
}

#[test]
fn probe_present_other_digest_attention() {
    let mut w = world("svc-pr-other", vendor_service());
    let intent = prepared_intent(&mut w);
    w.fake
        .world()
        .services
        .values_mut()
        .for_each(|s| s.set_value("Start", REG_DWORD, dword(2)));
    assert!(matches!(probe(&w.fake, &intent), Probe::Attention { .. }));
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

#[test]
fn undo_restores_and_checks_exact() {
    let mut w = world("svc-u-exact", vendor_service());
    let (outcome, intent) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    let before = w.fake.log().len();
    take_fault_trace();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    let restored = w.fake.service(NAME).unwrap();
    assert_same_tree(&restored.tree, &vendor_service().tree);
    assert_eq!(restored.state, purge_exec::act_service::SERVICE_STOPPED);
    // Order: create, config2 (only Description: the backup holds no other item), DACL, write-back,
    // flush; the last capture is the exact check.
    let log: Vec<String> = w.fake.log()[before..]
        .iter()
        .filter(|l| !l.starts_with("read") && !l.starts_with("capture"))
        .cloned()
        .collect();
    assert_eq!(
        log,
        vec![
            format!("create {NAME}"),
            format!("config2 {NAME} description"),
            format!("security {NAME}"),
            format!("write_back {NAME} 6"),
            "flush".to_owned(),
        ]
    );
    assert_eq!(
        take_fault_trace(),
        vec![fault::SVCRESTORE_MID, fault::UNDO_ACT_AFTER]
    );
}

/// Without a `Security` subkey in the backup the DACL is not touched; config2 items the backup does not
/// hold are not applied (the spike's naive restore left extra values).
#[test]
fn undo_applies_only_what_the_backup_holds() {
    let mut s = FakeService::new(NAME, IMAGE, None);
    s.scm.config2.delayed_auto_start = Some(false);
    s.scm.config2.preshutdown_timeout_ms = Some(180_000);
    s.scm.config2.service_sid_type = Some(0);
    s.scm.config2.failure_actions_flag = Some(false);
    let mut w = world("svc-u-only", s.clone());
    let (outcome, intent) = w.run();
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    let log = w.fake.log()[before..].to_vec();
    assert!(!log.iter().any(|l| l.starts_with("config2")), "{log:?}");
    assert!(!log.iter().any(|l| l.starts_with("security")), "{log:?}");
    assert_same_tree(&w.fake.service(NAME).unwrap().tree, &s.tree);
}

#[test]
fn undo_existing_equal_is_already_restored() {
    let mut w = world("svc-u-equal", vendor_service());
    let (outcome, intent) = w.run();
    w.fake.insert(vendor_service());
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::AlreadyRestored);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
}

/// Hostile: a service of the same name was planted after the delete.
#[test]
fn undo_existing_different_is_object_exists() {
    let mut w = world("svc-u-exists", vendor_service());
    let (outcome, intent) = w.run();
    let mut squatter = FakeService::new(NAME, r"C:\Users\Public\evil.exe", None);
    squatter.set_value("Description", REG_SZ, sz("Keeps Vendor up to date"));
    w.fake.insert(squatter.clone());
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
    assert_eq!(w.fake.service(NAME).unwrap(), squatter);
    // Even with an undo attempt on record, a service that is not this restore's is not adopted.
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&intent, Some(&outcome), true, &roots);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
}

#[test]
fn undo_marked_for_delete_is_pending_delete() {
    let mut w = world("svc-u-marked", vendor_service());
    w.fake.world().mark_on_delete = true;
    let (outcome, intent) = w.run();
    assert_eq!(outcome, ItemOutcome::PendingDelete);
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::PendingDelete);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
}

/// Hostile: a definition and key backup (consistent, hash-checked) naming `cmd.exe`: the second lock
/// refuses to create a service for a program outside the run's roots.
#[test]
fn undo_binary_outside_recorded_root_refused() {
    let forged = FakeService::new(NAME, r"C:\Windows\System32\cmd.exe /c whoami", None);
    let mut w = world("svc-u-root", forged.clone());
    // Validate would have refused the program, and prepare and the act refuse it outside the roots
    // they are given: the forged state is what a store rewritten with matching hashes would hold, so
    // it is made here with a root that holds cmd.exe, and undone with the run's real one.
    w.program_roots = vec![r"C:\Windows\System32".to_owned()];
    let (stamp, facts) = (
        Stamp::Object {
            kind: ObjectKind::Service,
            sha256: forged.identity().fp().sha256,
        },
        ItemFacts::Object {
            kind: ObjectKind::Service,
            sha256: forged.identity().fp().sha256,
            running: false,
        },
    );
    w.journal
        .validated(Validated {
            op: OP,
            item: purge_model::CandidateId("c-svc".into()),
            target: Target::Service { name: NAME.into() },
            facts,
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    let SvcPrepared::Ready(removal) = w.prepare(&stamp, Reversibility::Full) else {
        panic!("decided");
    };
    let intent = removal.intent().clone();
    let token = w.journal.intent(intent.clone()).unwrap();
    w.fake.world().services.clear();
    w.journal.done(token, ItemOutcome::Done).unwrap();
    let r = w.undo(&intent, &ItemOutcome::Done);
    assert_eq!(conflict(&r), &UndoConflict::ProgramOutsideRoot, "{r:?}");
    assert!(w.fake.service(NAME).is_none());
    // No roots at all: refused too.
    let args = w.undo_args(&intent, Some(&ItemOutcome::Done), false, &[]);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::ProgramOutsideRoot);
}

#[test]
fn undo_tampered_def_refused() {
    let mut w = world("svc-u-tamper", vendor_service());
    let (outcome, intent) = w.run();
    let purge_model::exec::op::Inverse::RecreateService { definition } = &intent.inverse else {
        panic!();
    };
    let path = w.session.path().join(&definition.path);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.windows(6).position(|b| b == b"Vendor").unwrap();
    bytes[at] = b'X';
    std::fs::write(&path, &bytes).unwrap();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered);
    assert!(w.fake.service(NAME).is_none());
}

#[test]
fn undo_tampered_key_backup_refused() {
    let mut w = world("svc-u-tamperkey", vendor_service());
    let (outcome, intent) = w.run();
    let rel = backup_rel(BackupKind::Registry, OP);
    let path = w.session.path().join(&rel);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered, "{r:?}");
    assert!(w.fake.service(NAME).is_none());
}

/// DECISIONS.md M1b: `PasswordNeeded` is for tasks. A service under an account with a password is
/// re-created under that account without one, and the outcome says the password must be set again.
#[test]
fn undo_password_account_restores_without_password() {
    let mut s = vendor_service();
    s.set_value("ObjectName", REG_SZ, sz(r".\vendorsvc"));
    s.scm.config.service_start_name = Some(r".\vendorsvc".into());
    let mut w = world("svc-u-pass", s.clone());
    let (removal, intent) = w.ready(Reversibility::Partial);
    let token = w.journal.intent(intent.clone()).unwrap();
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    w.journal.done(token, r.outcome.clone()).unwrap();
    let u = w.undo(&intent, &r.outcome);
    let SvcUndoResult::Done { outcome, detail } = &u else {
        panic!("{u:?}");
    };
    assert_eq!(outcome, &UndoOutcome::Restored);
    assert!(detail.contains("password"), "{detail}");
    assert_same_tree(&w.fake.service(NAME).unwrap().tree, &s.tree);
    // The note is in the journal (review R2b S6), also after it is read back from disk.
    let noted = w.journal.state().undo_done_detail(OP).unwrap().to_owned();
    assert!(noted.contains("password"), "{noted}");
    w.reopen_journal();
    assert_eq!(w.journal.state().undo_done_detail(OP), Some(noted.as_str()));
}

/// Review R2b S5: the journal names the key backup itself (with its hash), so expiry, the byte count
/// and the report see it; an intent whose `definition` is another file is refused at undo.
#[test]
fn intent_names_the_key_backup_and_undo_requires_it() {
    let mut w = world("svc-u-keyref", vendor_service());
    let (outcome, intent) = w.run();
    let purge_model::exec::op::Inverse::RecreateService { definition } = &intent.inverse else {
        panic!();
    };
    let def: SvcDef = read_def(&w.session, definition).unwrap();
    assert_eq!(intent.definition.as_ref(), Some(&def.key_backup));
    let backups: Vec<_> = intent.backups().collect();
    assert!(backups.contains(&&def.key_backup), "{backups:?}");
    let mut other = intent.clone();
    other.definition = None;
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&other, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered);
    assert!(w.fake.service(NAME).is_none());
}

/// Review R2b B1: a service whose program is outside the run's roots is not deleted (undo would refuse
/// to create it), and no backup is written for it; with no roots at all, nothing is deleted.
#[test]
fn prepare_refuses_a_program_outside_the_roots() {
    for roots in [vec![r"C:\Program Files\Other".to_owned()], Vec::new()] {
        let mut w = world("svc-p-roots", vendor_service());
        w.program_roots = roots;
        let (stamp, _) = stamp_of(&w.validate(&candidate(&vendor_service())));
        let SvcPrepared::Decided(r) = w.prepare(&stamp, Reversibility::Full) else {
            panic!("ready");
        };
        assert_eq!(
            skip_reason(&r.outcome),
            &SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            },
            "{}",
            r.detail
        );
        assert!(
            !w.session
                .path()
                .join(backup_rel(BackupKind::Registry, OP))
                .exists()
        );
        assert!(
            !w.session
                .path()
                .join(backup_rel(BackupKind::Definition, OP))
                .exists()
        );
        assert!(!w.fake.log().iter().any(|l| l.starts_with("delete")));
    }
}

/// Review R2b B1: arguments the SCM wrapper would refuse at undo (an error control above 3) refuse the
/// delete.
#[test]
fn prepare_refuses_what_undo_could_not_create() {
    let mut s = vendor_service();
    s.set_value("ErrorControl", REG_DWORD, dword(7));
    let w = world("svc-p-create", s.clone());
    let (stamp, _) = stamp_of(&w.validate(&candidate(&s)));
    let SvcPrepared::Decided(r) = w.prepare(&stamp, Reversibility::Full) else {
        panic!("ready");
    };
    assert_eq!(
        skip_reason(&r.outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        },
        "{}",
        r.detail
    );
    assert!(
        !w.session
            .path()
            .join(backup_rel(BackupKind::Definition, OP))
            .exists()
    );
}

/// Review R2b S4: the act is bound to the backup, not only to the identity digest. A value added to
/// the key, an SCM setting changed, or a definition gone after prepare: nothing is deleted.
#[test]
fn act_binds_to_the_backup() {
    type Change = fn(&mut World);
    let changes: [(Change, SkipReason); 4] = [
        (
            |w| {
                w.fake.world().services.values_mut().for_each(|s| {
                    s.set_value("Injected", REG_SZ, sz("later"));
                })
            },
            SkipReason::ChangedSinceScan,
        ),
        (
            |w| {
                w.fake.world().services.values_mut().for_each(|s| {
                    s.scm.config2.description = Some("Something else".into());
                })
            },
            SkipReason::ChangedSinceScan,
        ),
        (
            |w| {
                w.session
                    .delete_backup_file(&backup_rel(BackupKind::Definition, OP))
                    .unwrap();
            },
            SkipReason::NoVerifiedBackup,
        ),
        (
            |w| {
                w.session
                    .delete_backup_file(&backup_rel(BackupKind::Registry, OP))
                    .unwrap();
            },
            SkipReason::NoVerifiedBackup,
        ),
    ];
    for (change, want) in changes {
        let mut w = world("svc-a-bind", vendor_service());
        let (removal, intent) = w.ready(Reversibility::Full);
        let token = w.journal.intent(intent).unwrap();
        change(&mut w);
        let r = act(
            &w.fake,
            &w.deny,
            &w.session,
            removal,
            &token,
            &w.program_roots,
        );
        assert_eq!(skip_reason(&r.outcome), &want, "{}", r.detail);
        assert!(!w.fake.log().iter().any(|l| l.starts_with("delete")));
        assert!(w.fake.service(NAME).is_some());
    }
    // The act made with roots that no longer hold the program (a resumed run's header): refused.
    let mut w = world("svc-a-roots", vendor_service());
    let (removal, intent) = w.ready(Reversibility::Full);
    let token = w.journal.intent(intent).unwrap();
    let r = act(&w.fake, &w.deny, &w.session, removal, &token, &[]);
    assert_eq!(
        skip_reason(&r.outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        }
    );
    assert!(w.fake.service(NAME).is_some());
}

/// Review R2b S3: a failed create is `ObjectApi` (nothing of this attempt exists, so the caller passes
/// `own_attempt: false`); a service another install then creates with the same identity but other
/// contents is `ObjectExists` and is not touched. A failure after the create is `VerifyFailed`.
#[test]
fn undo_failed_create_never_adopts_a_later_service() {
    let mut w = world("svc-u-own", vendor_service());
    let (outcome, intent) = w.run();
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    w.fake.world().fail_next.insert(
        "create",
        ObjErr::new(ObjErrKind::Other, Some(5), "access denied"),
    );
    let r = run_undo(&w.fake, job, &token);
    let SvcUndoResult::Done {
        outcome: UndoOutcome::Failed { code, .. },
        ..
    } = &r
    else {
        panic!("{r:?}");
    };
    assert_eq!(code, &FailCode::ObjectApi);
    assert!(w.fake.service(NAME).is_none());
    w.journal
        .undo_done(token, done_outcome(&r).clone())
        .unwrap();

    // Another install creates the service: same name and identity, another description and a value.
    let mut other = vendor_service();
    other.set_value("Description", REG_SZ, sz("Another product"));
    w.fake.insert(other.clone());
    let before = w.fake.log().len();
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
    assert_eq!(w.fake.service(NAME).unwrap(), other);

    // After a successful create, a failure is VerifyFailed (the next attempt may continue).
    w.fake.world().services.clear();
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    w.fake
        .world()
        .fail_next
        .insert("config2", ObjErr::new(ObjErrKind::Other, Some(1117), "io"));
    let r = run_undo(&w.fake, job, &token);
    let SvcUndoResult::Done {
        outcome: UndoOutcome::Failed { code, .. },
        ..
    } = &r
    else {
        panic!("{r:?}");
    };
    assert_eq!(code, &FailCode::VerifyFailed);
}

/// A crash after the create (`svcrestore.mid`): the service exists half configured. Run again with the
/// undo intent on record, the undo recognises its own partial restore and finishes; without that
/// record it is `ObjectExists`.
#[test]
fn undo_crash_at_svcrestore_mid_then_resume() {
    let mut w = world("svc-u-crash", vendor_service());
    let (outcome, intent) = w.run();
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    assert!(job.creates());
    let token = w.journal.undo_intent(OP).unwrap();
    // The "crash": the run stops right after the create (config2 fails), the token is lost.
    w.fake.world().fail_next.insert(
        "config2",
        ObjErr::new(ObjErrKind::Other, Some(1117), "power lost"),
    );
    let _ = run_undo(&w.fake, job, &token);
    drop(token);
    w.reopen_journal();
    let half = w.fake.service(NAME).unwrap();
    assert!(tree_difference(&vendor_service().tree, &half.tree).is_some());

    // Without the undo intent on record: someone else's service.
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);

    // With it: continue from config2, no second create.
    let token = w.journal.resume_undo(OP).expect("an open undo intent");
    let args = w.undo_args(&intent, Some(&outcome), true, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    assert!(!job.creates());
    let before = w.fake.log().len();
    let r = run_undo(&w.fake, job, &token);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    assert_eq!(creates(&w.fake.log()[before..]), 0);
    assert_same_tree(&w.fake.service(NAME).unwrap().tree, &vendor_service().tree);
    w.journal.undo_done(token, UndoOutcome::Restored).unwrap();
}

/// The backend has no start entry, and the module's source names no API that starts or controls a
/// service.
#[test]
fn undo_never_starts_service() {
    let mut w = world("svc-u-nostart", vendor_service());
    let (outcome, intent) = w.run();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored);
    assert_eq!(
        w.fake.service(NAME).unwrap().state,
        purge_exec::act_service::SERVICE_STOPPED
    );
    assert!(
        w.fake
            .log()
            .iter()
            .all(|l| !l.contains("start") && !l.contains("control"))
    );
    let source = include_str!("../src/act_service.rs");
    for forbidden in [
        concat!("Start", "Service"),
        concat!("Control", "Service"),
        concat!("StartServiceCtrl", "Dispatcher"),
        concat!("scm::", "start"),
        concat!("scm::", "control"),
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn undo_exact_check_detects_changed_value_type() {
    let mut w = world("svc-u-type", vendor_service());
    let (outcome, intent) = w.run();
    {
        let mut world = w.fake.world();
        // The SCM writes VendorTag as a DWORD on create, and the registry does not take the write-back.
        world
            .create_extra
            .push(("VendorTag".into(), REG_DWORD, dword(7)));
        world.skip_writes.push("VendorTag".into());
    }
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ValueDiffers, "{r:?}");
    let SvcUndoResult::Conflict { detail, .. } = &r else {
        unreachable!()
    };
    assert!(
        detail.contains("VendorTag") && detail.contains("type"),
        "{detail}"
    );
    // The service exists, stopped.
    assert_eq!(
        w.fake.service(NAME).unwrap().state,
        purge_exec::act_service::SERVICE_STOPPED
    );
}

#[test]
fn undo_exact_check_detects_extra_value() {
    let mut w = world("svc-u-extra", vendor_service());
    let (outcome, intent) = w.run();
    w.fake
        .world()
        .create_extra
        .push(("FailureActions".into(), 3, vec![0; 20]));
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ValueDiffers, "{r:?}");
}

#[test]
fn undo_of_an_op_that_changed_nothing() {
    let mut w = world("svc-u-nothing", vendor_service());
    let (removal, intent) = w.ready(Reversibility::Full);
    let token = w.journal.intent(intent.clone()).unwrap();
    w.fake
        .world()
        .services
        .values_mut()
        .for_each(|s| s.state = 4);
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    w.journal.done(token, r.outcome.clone()).unwrap();
    let u = w.undo(&intent, &r.outcome);
    assert_eq!(done_outcome(&u), &UndoOutcome::NothingToUndo);
}

/// Every fault point of the item and of its undo, in order (the executor's `act.before` and the
/// journal's `done.before` and `undo.intent` around them). With `fault-inject` the points really abort:
/// see `fault_points_abort`.
#[test]
fn fault_points_reached() {
    let mut w = world("svc-fault", vendor_service());
    take_fault_trace();
    let (outcome, intent) = w.run();
    assert_eq!(
        take_fault_trace(),
        vec![fault::OBJDELETE_AFTER, fault::ACT_AFTER]
    );
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored);
    assert_eq!(
        take_fault_trace(),
        vec![fault::SVCRESTORE_MID, fault::UNDO_ACT_AFTER]
    );
    for point in [
        fault::ACT_BEFORE,
        fault::OBJDELETE_AFTER,
        fault::ACT_AFTER,
        fault::DONE_BEFORE,
        fault::UNDO_INTENT,
        fault::SVCRESTORE_MID,
        fault::UNDO_ACT_AFTER,
    ] {
        assert!(fault::FAULT_POINTS.contains(&point), "{point}");
    }
}

// ---------------------------------------------------------------------------------------------------
// fault-inject: each point aborts the process
// ---------------------------------------------------------------------------------------------------

#[cfg(feature = "fault-inject")]
mod inject {
    use std::process::{Command, Stdio};

    use super::*;

    const CHILD: &str = "PURGE_TEST_SVC_CHILD";
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    /// The child: the whole item and its undo; it dies at the fault point the parent named.
    #[test]
    fn svc_child_scenario() {
        let Some(root) = std::env::var_os(CHILD) else {
            return;
        };
        let s = Scratch::at(Path::new(&root));
        let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
        let session = roots.create_session().unwrap();
        let journal = JournalWriter::create(&session, header(&session)).unwrap();
        let mut w = std::mem::ManuallyDrop::new(World {
            _s: s,
            roots,
            session,
            journal,
            fake: FakeServices::with([vendor_service()]),
            deny: deny(),
            program_roots: vec![ROOT.to_owned()],
        });
        let (outcome, intent) = w.run();
        let _ = w.undo(&intent, &outcome);
        // Not reached when the point fires.
        std::process::exit(7);
    }

    #[test]
    fn fault_points_abort() {
        for point in [
            fault::ACT_BEFORE,
            fault::OBJDELETE_AFTER,
            fault::ACT_AFTER,
            fault::DONE_BEFORE,
            fault::UNDO_INTENT,
            fault::SVCRESTORE_MID,
            fault::UNDO_ACT_AFTER,
        ] {
            let s = Scratch::new("svc-inject");
            let temp = s.dir("child-temp");
            let code = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "inject::svc_child_scenario", "--test-threads=1"])
                .env(CHILD, &s.root)
                .env(fault::ENV_AT, point)
                .env_remove(fault::ENV_PAUSE)
                .env("TEMP", &temp)
                .env("TMP", &temp)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .code();
            assert_eq!(code, Some(ABORT_CODE), "{point}");
        }
        // A point the scenario never reaches: it runs to its end.
        let s = Scratch::new("svc-inject");
        let code = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "inject::svc_child_scenario", "--test-threads=1"])
            .env(CHILD, &s.root)
            .env(fault::ENV_AT, fault::REGDELETE_MID)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code();
        assert_eq!(code, Some(7));
    }
}

// ---------------------------------------------------------------------------------------------------
// Live (read-only here; changes only on the VM rig)
// ---------------------------------------------------------------------------------------------------

/// Reads a built-in service through the live backend: identity as the scanner builds it, its tree, its
/// definition. Changes nothing. Needs elevation (`EventLog\Security` is not readable at Medium
/// integrity; only the elevated executor calls `capture_key`): skipped otherwise, as
/// purge-win/tests/scm.rs does, so `cargo xtask ci` passes unelevated (review R3b S1).
#[test]
fn live_read_of_a_builtin_service_is_consistent() {
    match purge_win::sid::is_elevated() {
        Ok(true) => {}
        other => {
            println!(
                "SKIPPED live_read_of_a_builtin_service_is_consistent: needs an elevated \
                 administrator; elevation check: {other:?}"
            );
            return;
        }
    }
    let live = LiveServices;
    let Some(svc) = live.read("EventLog").unwrap() else {
        panic!("EventLog is not installed");
    };
    let doc = live.capture_key("EventLog", 100_000).unwrap().unwrap();
    let tree_identity =
        purge_exec::act_service::identity_from_tree("EventLog", doc.tree().unwrap()).unwrap();
    assert_eq!(tree_identity, svc.identity);
    let def = live.definition("EventLog").unwrap();
    assert_eq!(
        def.config.service_type & 0x30,
        svc.identity.service_type & 0x30
    );
    // The guard refuses it (svchost under %SystemRoot%).
    let env = common::live_env(r"C:\ProgramData\PurgeTest");
    let deny = DenyList::compile(&env);
    assert!(purge_exec::act_service::gate_blocker(&deny, &svc).is_some());
    assert_eq!(live.read("PurgeNoSuchService_7f3a").unwrap(), None);
    assert!(
        live.capture_key("PurgeNoSuchService_7f3a", 10)
            .unwrap()
            .is_none()
    );
    let _ = &deny;
}

/// The real delete and re-create of a throwaway service. Elevated, changes the SCM: VM rig only.
#[test]
#[ignore = "creates and deletes a real service; elevated, VM rig only"]
fn rig_live_delete_and_recreate_round_trip() {
    use purge_win::scm::{self, ScmCreate};
    let name = "PurgeRigSvcRoundTrip";
    let s = Scratch::new("svc-rig");
    let program = s.file(r"bin\rigsvc.exe", b"MZ");
    scm::create(&ScmCreate {
        name: name.into(),
        display_name: Some("Purge rig service".into()),
        service_type: 0x10,
        start_type: 3,
        error_control: 1,
        binary_path: format!("\"{program}\" -rig"),
        load_order_group: None,
        dependencies: Vec::new(),
        service_start_name: None,
    })
    .unwrap();
    let live = LiveServices;
    let service = live.read(name).unwrap().unwrap();
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
    let session = roots.create_session().unwrap();
    let mut journal = JournalWriter::create(&session, header(&session)).unwrap();
    let env = common::live_env(&s.path("data"));
    let deny = DenyList::compile(&env);
    let program_roots = vec![
        std::path::Path::new(&program)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    ];
    let op = ExecOp::DeleteService { name: name.into() };
    let mut cand = safe(
        "c-rig",
        Target::Service { name: name.into() },
        Action::DeleteKey,
    );
    cand.object_fp = Some(service.identity.fp());
    let (stamp, facts) = stamp_of(&validate(&live, &deny, &op, &cand));
    journal
        .validated(Validated {
            op: OP,
            item: cand.id.clone(),
            target: cand.target.clone(),
            facts,
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    let SvcPrepared::Ready(removal) = prepare(
        &live,
        &session,
        &SvcPrepareArgs {
            op: OP,
            item: &cand.id,
            exec_op: &op,
            validated: &stamp,
            planned: Reversibility::Full,
            key_limit: 50,
            program_roots: &program_roots,
            env: &env,
        },
    )
    .unwrap() else {
        panic!("decided");
    };
    let intent = removal.intent().clone();
    let token = journal.intent(intent.clone()).unwrap();
    let r = act(&live, &deny, &session, removal, &token, &program_roots);
    assert_eq!(r.outcome, ItemOutcome::Done, "{}", r.detail);
    journal.done(token, r.outcome.clone()).unwrap();
    let args = SvcUndoArgs {
        intent: &intent,
        done: Some(&r.outcome),
        own_attempt: false,
        program_roots: &program_roots,
    };
    let SvcUndoPrepared::Ready(job) = prepare_undo(&live, &session, &env, &args) else {
        panic!("decided");
    };
    let token = journal.undo_intent(OP).unwrap();
    let u = run_undo(&live, job, &token);
    let _ = scm::delete(name);
    assert_eq!(done_outcome(&u), &UndoOutcome::Restored, "{u:?}");
}
