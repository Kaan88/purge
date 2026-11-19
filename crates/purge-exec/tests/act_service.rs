//! Executor action: delete and recreate a Windows service (M1b).
//!
//! Every test runs over the in-memory backend `act_service::fake::FakeServices` and a relaxed store with
//! a real journal: nothing here creates, changes or deletes a service on this machine. The only live
//! test reads a built-in service and is read-only; the live create/delete round trip is VM-rig only
//! (ignored). The registry write-back of the live backend is run on a scratch key below the current
//! user's `Software` (`write_back_*`; the `elevated_write_back_*` ones need an elevated administrator
//! and are part of the gate's elevated set E1).

#![cfg(feature = "test-support")]

mod common;

use std::path::Path;

use common::{Scratch, TestKey, safe};
use purge_exec::act_service::fake::{FakeService, FakeServices, KEY_SDDL, dword, sz};
use purge_exec::act_service::{
    LiveServices, ObjErr, ObjErrKind, ServiceBackend, SvcPrepareArgs, SvcPrepared, SvcRemoval,
    SvcUndoArgs, SvcUndoPrepared, SvcUndoResult, SvcValidated, WriteBack, act, complete, prepare,
    prepare_undo, probe, run_undo, take_fault_trace, tree_difference, validate,
    write_back_below_key, write_back_ops,
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
use purge_win::reg_write::{KeyAccess, WKey};

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

/// Hostile (smoke trap svc-svchost): a service hosted by svchost whose `ServiceDll` lies in the app's
/// folder is judged by its host, `svchost.exe` under `%SystemRoot%`, not by the DLL: never deleted.
#[test]
fn validate_svchost_service_with_dll_in_app_folder_blocked() {
    for image in [
        r"%SystemRoot%\System32\svchost.exe -k VendorGroup",
        r"C:\Windows\system32\svchost.exe -k VendorGroup -p",
    ] {
        let mut s = FakeService::new(NAME, image, None);
        s.set_value("Type", REG_DWORD, dword(0x20));
        s.scm.config.service_type = 0x20;
        s.add_key(
            0,
            "Parameters",
            vec![(
                "ServiceDll",
                REG_EXPAND_SZ,
                sz(&format!(r"{ROOT}\vendorsvc.dll")),
            )],
        );
        let w = world("svc-v-svchost", s.clone());
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

/// Review R8 S5: the process ends inside the write-back, after `Parameters` was created and before its
/// recorded descriptor was set. The next attempt (the undo intent is on record) finds the key, puts the
/// recorded descriptor on it and ends `Restored`; before, no write touched an existing key's descriptor
/// and every further attempt ended `ValueDiffers`, then `ObjectExists`.
#[test]
fn undo_crash_between_key_create_and_security_then_resume() {
    let mut w = world("svc-u-wbcrash", vendor_service());
    let (outcome, intent) = w.run();
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    // The "crash": the write-back stops, and what it had done by then is one key, created with the
    // descriptor creation gives it. The token is lost.
    w.fake.world().fail_next.insert(
        "write_back",
        ObjErr::new(ObjErrKind::Other, Some(1117), "power lost"),
    );
    let _ = run_undo(&w.fake, job, &token);
    drop(token);
    let created = "O:BAG:SYD:(A;CI;KA;;;BA)";
    assert_ne!(created, KEY_SDDL);
    {
        let mut world = w.fake.world();
        let service = world.services.values_mut().next().unwrap();
        let params = service.add_key(0, "Parameters", Vec::new());
        service.tree.keys[params].sddl = created.to_owned();
    }
    w.reopen_journal();
    let half = w.fake.service(NAME).unwrap();
    assert!(tree_difference(&vendor_service().tree, &half.tree).is_some());

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
    let live = w.fake.service(NAME).unwrap().tree;
    assert_same_tree(&live, &vendor_service().tree);
    assert!(live.keys.iter().all(|k| k.sddl == KEY_SDDL), "{live:#?}");
    w.journal.undo_done(token, UndoOutcome::Restored).unwrap();

    // Once more: nothing is left to do.
    let args = w.undo_args(&intent, Some(&outcome), false, &roots);
    let SvcUndoPrepared::Decided(r) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("ready");
    };
    assert_eq!(done_outcome(&r), &UndoOutcome::AlreadyRestored);
}

/// The same after an attempt that ended with an error instead of a crash: `Failed{VerifyFailed}` is on
/// record, the whole undo runs again and converges.
#[test]
fn undo_failed_in_the_write_back_then_again_restores_the_descriptor() {
    let mut w = world("svc-u-wbfail", vendor_service());
    let (outcome, intent) = w.run();
    w.fake.world().fail_next.insert(
        "write_back",
        ObjErr::new(
            ObjErrKind::AccessDenied,
            Some(5),
            "set the security descriptor of Parameters: access denied",
        ),
    );
    let r = w.undo(&intent, &outcome);
    let UndoOutcome::Failed { code, os_error, .. } = done_outcome(&r) else {
        panic!("{r:?}");
    };
    assert_eq!((code, os_error), (&FailCode::VerifyFailed, &Some(5)));
    {
        let mut world = w.fake.world();
        let service = world.services.values_mut().next().unwrap();
        let params = service.add_key(0, "Parameters", Vec::new());
        service.tree.keys[params].sddl = "O:BAG:SYD:(A;CI;KA;;;BA)".to_owned();
    }
    let roots = vec![ROOT.to_owned()];
    let args = w.undo_args(&intent, Some(&outcome), true, &roots);
    let SvcUndoPrepared::Ready(job) = prepare_undo(&w.fake, &w.session, &GuardEnv::sample(), &args)
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    let r = run_undo(&w.fake, job, &token);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    assert_same_tree(&w.fake.service(NAME).unwrap().tree, &vendor_service().tree);
}

/// Review R8 M2: an owner the write-back could not assign does not fail the undo (the exact check sets
/// the owner aside), and the `Restored` outcome says so in its detail.
#[test]
fn undo_names_an_owner_that_could_not_be_assigned() {
    let mut w = world("svc-u-owner", vendor_service());
    let (outcome, intent) = w.run();
    let note = "key Parameters keeps the owner BA: the recorded owner SY could not be assigned";
    w.fake.world().write_notes = vec![note.to_owned()];
    let r = w.undo(&intent, &outcome);
    let SvcUndoResult::Done { outcome, detail } = &r else {
        panic!("{r:?}");
    };
    assert_eq!(outcome, &UndoOutcome::Restored);
    assert_eq!(detail, note);
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

// ---------------------------------------------------------------------------------------------------
// The registry write-back of the live backend, on a scratch key standing in for `Services\<name>`
// ---------------------------------------------------------------------------------------------------

/// The scratch key opened as [`LiveServices`] opens a service's key for the write-back.
fn wb_root(t: &TestKey) -> WKey {
    t.open("", KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY)
}

fn wb_apply(t: &TestKey, writes: &[WriteBack]) -> Result<Vec<String>, ObjErr> {
    write_back_below_key(&wb_root(t), writes)
}

fn wb_tree(t: &TestKey) -> RegTree {
    purge_exec::regbackup::capture_tree(
        &t.open("", KeyAccess::READ),
        r"HKU\scratch",
        purge_exec::regbackup::DEFAULT_KEY_LIMIT,
    )
    .unwrap()
    .tree()
    .unwrap()
    .clone()
}

fn wb_sddl(t: &TestKey, sub: &str) -> String {
    t.open(sub, KeyAccess::READ).security_sddl().unwrap()
}

fn wb_remove(parent: &WKey, name: &str) {
    let key = parent.open_subkey(name, KeyAccess::READ).unwrap();
    for sub in key.subkey_names().unwrap() {
        wb_remove(&key, &sub);
    }
    drop(key);
    parent.delete_subkey(name).unwrap();
}

/// Whether the test process may assign SYSTEM as an owner (`SeRestorePrivilege`, which an elevated
/// administrator's token holds): tried on a probe key, removed again.
fn may_assign_system_owner(t: &TestKey) -> bool {
    let root = wb_root(t);
    let probe = root
        .create_subkey("privilege-probe", "", None, false)
        .unwrap();
    let held = probe.set_security("O:SY").is_ok();
    drop(probe);
    wb_remove(&root, "privilege-probe");
    held
}

/// Group and DACL of an SDDL string with an owner part.
fn owner_aside(sddl: &str) -> &str {
    &sddl[sddl.find("G:").unwrap()..]
}

fn create_key(path: &[&str], sddl: &str) -> WriteBack {
    WriteBack::CreateKey {
        path: path.iter().map(|p| (*p).to_owned()).collect(),
        class: String::new(),
        sddl: sddl.to_owned(),
        volatile: false,
    }
}

fn set_security(path: &[&str], sddl: &str) -> WriteBack {
    WriteBack::SetSecurity {
        path: path.iter().map(|p| (*p).to_owned()).collect(),
        sddl: sddl.to_owned(),
    }
}

fn set_value(path: &[&str], name: &str) -> WriteBack {
    WriteBack::SetValue {
        path: path.iter().map(|p| (*p).to_owned()).collect(),
        name: name.to_owned(),
        value_type: REG_SZ,
        data: sz("x"),
    }
}

/// A protected, auto-inherited DACL as a key stores it, with access mask `mask` for the current user
/// and for administrators and full control for SYSTEM: set on a model key, read back, removed.
fn stored_dacl(t: &TestKey, mask: &str) -> String {
    let root = wb_root(t);
    let sid = &t.sid;
    let model = root.create_subkey("dacl-model", "", None, false).unwrap();
    model
        .set_security(&format!(
            "D:PAI(A;CI;{mask};;;BA)(A;CI;{mask};;;{sid})(A;CI;KA;;;SY)"
        ))
        .unwrap();
    let stored = model.security_sddl().unwrap();
    drop(model);
    wb_remove(&root, "dacl-model");
    let dacl = stored[stored.find("D:").unwrap()..].to_owned();
    assert!(dacl.starts_with("D:PAI("), "{dacl}");
    dacl
}

/// Read, `DELETE` and `WRITE_DAC` (so the test can remove the key again), no `WRITE_OWNER`.
const NO_WRITE_OWNER: &str = "0x70019";
/// Everything a key has but `WRITE_OWNER`.
const ALL_BUT_WRITE_OWNER: &str = "0x7003f";

/// A `Parameters` key (class, value, auto-inherited DACL) with a `Deep` key below it (protected DACL),
/// backed up and removed again: the backup, and the two recorded descriptors.
fn parameters_backup(t: &TestKey) -> (RegTree, String, String) {
    let sid = &t.sid;
    let recorded = format!(
        "O:{sid}G:{sid}D:AI(A;CIID;KA;;;{sid})(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;BU)"
    );
    let deep = format!("O:{sid}G:{sid}D:PAI(A;CI;KA;;;{sid})(A;CI;KR;;;BU)");
    let root = wb_root(t);
    {
        let params = root
            .create_subkey("Parameters", "Cls", None, false)
            .unwrap();
        params.set_security(&recorded).unwrap();
        params
            .set_value_raw("ServiceDll", REG_SZ, &sz("x"))
            .unwrap();
        let inner = params.create_subkey("Deep", "", None, false).unwrap();
        inner.set_security(&deep).unwrap();
    }
    let backup = wb_tree(t);
    assert!(
        backup.keys.iter().any(|k| k.sddl == recorded),
        "{backup:#?}"
    );
    assert!(backup.keys.iter().any(|k| k.sddl == deep), "{backup:#?}");
    wb_remove(&root, "Parameters");
    assert_eq!(wb_tree(t).keys.len(), 1);
    (backup, recorded, deep)
}

/// M1b executor gate (K11 svc-full, K13): the write-back re-created `Parameters` from a descriptor
/// with an auto-inherited DACL (`D:AI(...)`), creation stored it as `D:(...)`, and undo's own exact
/// check then refused the tree it had just written. Backed up, deleted and written back, a subkey
/// (and a key below it) holds the recorded descriptor exactly, `AI` included.
#[test]
fn write_back_restores_an_auto_inherited_dacl_exactly() {
    let t = TestKey::new();
    let (backup, recorded, deep) = parameters_backup(&t);
    let writes = write_back_ops(&backup, &wb_tree(&t));
    assert_eq!(
        writes
            .iter()
            .filter(|w| matches!(w, WriteBack::CreateKey { .. }))
            .count(),
        2
    );
    assert_eq!(wb_apply(&t, &writes).unwrap(), Vec::<String>::new());

    assert_eq!(wb_sddl(&t, "Parameters"), recorded);
    assert_eq!(wb_sddl(&t, r"Parameters\Deep"), deep);
    assert_eq!(tree_difference(&backup, &wb_tree(&t)), None);
    assert_eq!(write_back_ops(&backup, &wb_tree(&t)), Vec::new());
}

/// The other arm: a recorded SYSTEM owner is refused at creation (1307), the key is created without
/// the owner part, and the recorded descriptor is still put on it. Elevated (`SeRestorePrivilege`) the
/// whole descriptor is the recorded one and nothing is noted. Unelevated the owner stays the creator's
/// (the exact check sets the owner aside) while group and DACL, `AI` included, are the recorded ones,
/// and the owner left is named in a note (review R8 M2).
#[test]
fn write_back_restores_the_dacl_of_a_key_whose_owner_cannot_be_assigned_at_creation() {
    let t = TestKey::new();
    let sid = &t.sid;
    let recorded =
        format!("O:SYG:SYD:AI(A;CIID;KA;;;{sid})(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;BU)");
    let notes = wb_apply(&t, &[create_key(&["Parameters"], &recorded)]).unwrap();
    let live = wb_sddl(&t, "Parameters");
    assert_eq!(owner_aside(&live), owner_aside(&recorded));
    if may_assign_system_owner(&t) {
        assert_eq!(live, recorded);
        assert_eq!(notes, Vec::<String>::new());
    } else {
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with("key Parameters keeps the owner ")
                && notes[0].contains("the recorded owner SY could not be assigned"),
            "{notes:?}"
        );
    }
}

/// Review R8 S6: the recorded DACL gives the token no `WRITE_OWNER` (and it is on the key from its
/// creation), and the recorded descriptor is still set whole afterwards, because the security write is
/// checked against the creating handle's rights. Both creation arms: an owner the token may assign
/// (created with the whole descriptor, then set for the flags creation dropped), and SYSTEM (created
/// without the owner; set whole when elevated, group and DACL with a note when not).
#[test]
fn write_back_restores_a_descriptor_whose_dacl_grants_no_write_owner() {
    let t = TestKey::new();
    let sid = &t.sid;
    let dacl = stored_dacl(&t, NO_WRITE_OWNER);

    let own = format!("O:{sid}G:{sid}{dacl}");
    assert_eq!(
        wb_apply(&t, &[create_key(&["Own"], &own)]).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(wb_sddl(&t, "Own"), own);

    let system = format!("O:SYG:SY{dacl}");
    let notes = wb_apply(&t, &[create_key(&["System"], &system)]).unwrap();
    let live = wb_sddl(&t, "System");
    assert_eq!(owner_aside(&live), owner_aside(&system));
    if may_assign_system_owner(&t) {
        assert_eq!(live, system);
        assert_eq!(notes, Vec::<String>::new());
    } else {
        assert_eq!(notes.len(), 1, "{notes:?}");
    }
}

/// Review R8 S5 on a real key: an attempt created `Parameters` as recorded and ended before the
/// security write (creation drops the auto-inherited flag). The next attempt names the key with a
/// `SetSecurity`, puts the recorded descriptor on it, creates what is still missing, and the tree is
/// the backup; a third attempt has nothing to write.
#[test]
fn write_back_converges_after_an_attempt_that_ended_between_create_and_set() {
    let t = TestKey::new();
    let (backup, recorded, deep) = parameters_backup(&t);
    drop(
        wb_root(&t)
            .create_subkey("Parameters", "Cls", Some(&recorded), false)
            .unwrap(),
    );
    let half = wb_tree(&t);
    assert_ne!(wb_sddl(&t, "Parameters"), recorded);
    assert_eq!(
        tree_difference(&backup, &half).as_deref(),
        Some(r"key Parameters\ has another security descriptor")
    );
    let writes = write_back_ops(&backup, &half);
    assert_eq!(writes[0], set_security(&["Parameters"], &recorded));
    assert_eq!(writes.len(), 3, "{writes:?}");
    assert_eq!(wb_apply(&t, &writes).unwrap(), Vec::<String>::new());
    assert_eq!(wb_sddl(&t, "Parameters"), recorded);
    assert_eq!(wb_sddl(&t, r"Parameters\Deep"), deep);
    assert_eq!(tree_difference(&backup, &wb_tree(&t)), None);
    assert_eq!(write_back_ops(&backup, &wb_tree(&t)), Vec::new());
}

/// The same for the hardest leftover: the recorded owner is SYSTEM, the key was created without it,
/// and its DACL (in force since creation) grants no `WRITE_OWNER`, so the key can be opened again for
/// `WRITE_DAC` only. The DACL is set alone, group and DACL are then the recorded ones (what the exact
/// check compares), and the owner left is named in a note; nothing fails.
#[test]
fn write_back_converges_on_a_leftover_key_it_cannot_open_for_write_owner() {
    let t = TestKey::new();
    let dacl = stored_dacl(&t, NO_WRITE_OWNER);
    let recorded = format!("O:SYG:SY{dacl}");
    drop(
        wb_root(&t)
            .create_subkey("System", "", Some(owner_aside(&recorded)), false)
            .unwrap(),
    );
    let created = wb_sddl(&t, "System");
    assert_ne!(owner_aside(&created), owner_aside(&recorded));

    let notes = wb_apply(&t, &[set_security(&["System"], &recorded)]).unwrap();
    let live = wb_sddl(&t, "System");
    assert_eq!(owner_aside(&live), owner_aside(&recorded));
    assert_ne!(live, recorded);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("the recorded owner SY could not be assigned"),
        "{notes:?}"
    );
    // Every further attempt says the same and changes nothing.
    assert_eq!(
        wb_apply(&t, &[set_security(&["System"], &recorded)]).unwrap(),
        notes
    );
    assert_eq!(wb_sddl(&t, "System"), live);
}

/// Review R8 M1: a descriptor that cannot be set and a key that cannot be created do not end the
/// write-back. The values of the first key and everything after both are still written, the writes at
/// and below the key that was not created are left out, and the error names all of it.
#[test]
fn write_back_writes_everything_it_can_and_reports_every_failure() {
    let t = TestKey::new();
    let sid = &t.sid;
    let dacl = stored_dacl(&t, ALL_BUT_WRITE_OWNER);
    // `Locked` exists with another group than recorded, and no handle to it gets `WRITE_OWNER`.
    {
        let locked = wb_root(&t)
            .create_subkey("Locked", "", None, false)
            .unwrap();
        locked
            .set_security(&format!("O:{sid}G:{sid}{dacl}"))
            .unwrap();
    }
    let recorded = format!("O:{sid}G:SY{dacl}");
    let plain = format!("O:{sid}G:{sid}D:P(A;CI;KA;;;{sid})(A;CI;KA;;;BA)");
    let writes = [
        set_security(&["Locked"], &recorded),
        set_value(&["Locked"], "v"),
        create_key(&["Bad"], "not a descriptor"),
        set_value(&["Bad"], "x"),
        create_key(&["Bad", "Sub"], &plain),
        create_key(&["After"], &plain),
        set_value(&["After"], "y"),
    ];
    let e = wb_apply(&t, &writes).unwrap_err();
    assert_eq!((e.kind, e.os_error), (ObjErrKind::AccessDenied, Some(5)));
    assert!(
        e.detail
            .starts_with("2 writes failed: set the security descriptor of Locked (it is ")
            && e.detail.contains("; create Bad: ")
            && e.detail
                .ends_with("; 2 writes at or below a key that was not created were left out"),
        "{}",
        e.detail
    );
    assert_eq!(wb_sddl(&t, "Locked"), format!("O:{sid}G:{sid}{dacl}"));
    assert_eq!(t.get("Locked", "v"), Some((REG_SZ, sz("x"))));
    assert!(!t.exists("Bad"));
    assert_eq!(wb_sddl(&t, "After"), plain);
    assert_eq!(t.get("After", "y"), Some((REG_SZ, sz("x"))));
}

/// The real thing, for the gate's elevated set (E1): a key owned by SYSTEM is backed up, deleted and
/// written back with owner, group and auto-inherited DACL exactly as recorded, and nothing is noted.
/// Needs an elevated administrator (`SeRestorePrivilege`): `cargo test -p purge-exec --features
/// test-support --test act_service -- --include-ignored elevated_write_back`.
#[test]
#[ignore = "needs an elevated administrator (SeRestorePrivilege)"]
fn elevated_write_back_restores_a_system_owned_auto_inherited_key() {
    let t = TestKey::new();
    assert!(may_assign_system_owner(&t), "run elevated");
    let recorded = "O:SYG:SYD:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;BU)";
    let root = wb_root(&t);
    root.create_subkey("Parameters", "", None, false)
        .unwrap()
        .set_security(recorded)
        .unwrap();
    let backup = wb_tree(&t);
    assert!(
        backup.keys.iter().any(|k| k.sddl == recorded),
        "{backup:#?}"
    );
    wb_remove(&root, "Parameters");
    let writes = write_back_ops(&backup, &wb_tree(&t));
    assert_eq!(wb_apply(&t, &writes).unwrap(), Vec::<String>::new());
    assert_eq!(wb_sddl(&t, "Parameters"), recorded);
    assert_eq!(tree_difference(&backup, &wb_tree(&t)), None);
}

/// Review R8 S5 and S6 with a SYSTEM owner, elevated: the leftover of an attempt that ended between
/// the creation (without the owner, which creation refuses) and the security write is opened again and
/// gets the whole recorded descriptor, owner included; and a SYSTEM-owned key whose recorded DACL gives
/// administrators no `WRITE_OWNER` is created and set exactly.
#[test]
#[ignore = "needs an elevated administrator (SeRestorePrivilege)"]
fn elevated_write_back_converges_on_a_system_owned_key_after_an_interrupted_attempt() {
    let t = TestKey::new();
    assert!(may_assign_system_owner(&t), "run elevated");
    let recorded = "O:SYG:SYD:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;BU)";
    let root = wb_root(&t);
    root.create_subkey("Parameters", "", None, false)
        .unwrap()
        .set_security(recorded)
        .unwrap();
    let backup = wb_tree(&t);
    wb_remove(&root, "Parameters");
    drop(
        root.create_subkey("Parameters", "", Some(owner_aside(recorded)), false)
            .unwrap(),
    );
    let half = wb_tree(&t);
    assert!(tree_difference(&backup, &half).is_some());
    let writes = write_back_ops(&backup, &half);
    assert_eq!(writes, vec![set_security(&["Parameters"], recorded)]);
    assert_eq!(wb_apply(&t, &writes).unwrap(), Vec::<String>::new());
    assert_eq!(wb_sddl(&t, "Parameters"), recorded);
    assert_eq!(tree_difference(&backup, &wb_tree(&t)), None);

    let system = format!("O:SYG:SY{}", stored_dacl(&t, NO_WRITE_OWNER));
    assert_eq!(
        wb_apply(&t, &[create_key(&["System"], &system)]).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(wb_sddl(&t, "System"), system);
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
