//! Executor action: delete and recreate a firewall rule (M1b).
//!
//! Every test runs over the in-memory backend `act_firewall::fake::FakeFirewall` and a relaxed store
//! with a real journal: nothing here creates, changes or deletes a firewall rule on this machine. The
//! live tests only read the registry; the live delete and re-create round trip is VM-rig only
//! (ignored, elevated).

#![cfg(feature = "test-support")]

mod common;

use std::path::Path;

use common::{Scratch, safe};
use purge_exec::act_firewall::fake::FakeFirewall;
use purge_exec::act_firewall::{
    FIREWALL_RULES_KEY, FirewallBackend, FwPrepareArgs, FwPrepared, FwRemoval, FwUndoArgs,
    FwUndoPrepared, FwUndoResult, FwValidated, LiveFirewall, act, complete, prepare, prepare_undo,
    probe, run_undo, take_fault_trace, validate,
};
use purge_exec::act_service::{ObjErr, ObjErrKind};
use purge_exec::fault;
use purge_exec::gate::Stamp;
use purge_exec::journal::{JournalWriter, sha256_bytes};
use purge_exec::objdef::{FWDEF_SCHEMA, FwDef, read_def, write_def};
use purge_exec::recover::Probe;
use purge_exec::storage::{BackupKind, SessionDir, StorageRoots, backup_rel};
use purge_guard::canon::GuardEnv;
use purge_guard::deny::{DenyList, ids};
use purge_model::exec::journal::{
    GateExemptions, Header, Intent, ItemFacts, JournalSchema, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::{
    Action, Blocker, Candidate, CandidateId, FIREWALL_RESTORE_EXACT, FirewallIdentity, ObjectKind,
    ScanMode, Target, parse_firewall_rule,
};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

const ID: &str = "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}";
/// Another rule with the same display name.
const TWIN: &str = "{7D1F0C55-2B44-4E0A-8C2E-5A9F3E61B0C2}";
const RULE: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|Defer=User|";
const TWIN_RULE: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\Vendor\helper.exe|Name=Vendor App|";
const ROOT: &str = r"C:\Program Files\Vendor";
const OP: OpId = OpId(1);

fn deny() -> DenyList {
    DenyList::compile(&GuardEnv::sample())
}

fn identity(id: &str, rule: &str) -> FirewallIdentity {
    FirewallIdentity {
        id: id.into(),
        rule: rule.into(),
    }
}

fn candidate_for(id: &str, rule: &str) -> Candidate {
    let mut cand = safe(
        "c-fw",
        Target::FirewallRule { id: id.into() },
        Action::DeleteKey,
    );
    cand.object_fp = Some(identity(id, rule).fp());
    cand
}

fn exec_op() -> ExecOp {
    ExecOp::DeleteFirewallRule { id: ID.into() }
}

struct World {
    _s: Scratch,
    roots: StorageRoots,
    session: SessionDir,
    journal: JournalWriter,
    fake: FakeFirewall,
    deny: DenyList,
    rule: String,
    /// The journal header's program roots, as the caller passes them to prepare and the act.
    program_roots: Vec<String>,
}

/// A store, a journal and a fake holding `rule` under [`ID`] and [`TWIN_RULE`] under [`TWIN`].
fn world(tag: &str, rule: &str) -> World {
    let s = Scratch::new(tag);
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
    let session = roots.create_session().unwrap();
    let journal = JournalWriter::create(&session, header(&session)).unwrap();
    World {
        _s: s,
        roots,
        session,
        journal,
        fake: FakeFirewall::with([(ID, rule), (TWIN, TWIN_RULE)]),
        deny: deny(),
        rule: rule.to_owned(),
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

fn stamp_of(v: &FwValidated) -> (Stamp, ItemFacts) {
    match v {
        FwValidated::Validated { stamp, facts } => (stamp.clone(), facts.clone()),
        FwValidated::Decided(r) => panic!("not validated: {r:?}"),
    }
}

impl World {
    fn candidate(&self) -> Candidate {
        candidate_for(ID, &self.rule)
    }

    fn validate(&self, cand: &Candidate) -> FwValidated {
        validate(&self.fake, &self.deny, &exec_op(), cand)
    }

    fn prepare(&self, stamp: &Stamp) -> FwPrepared {
        let item = CandidateId("c-fw".into());
        let op = exec_op();
        prepare(
            &self.fake,
            &self.deny,
            &self.session,
            &FwPrepareArgs {
                op: OP,
                item: &item,
                exec_op: &op,
                validated: stamp,
                program_roots: &self.program_roots,
            },
        )
        .unwrap()
    }

    /// Validate, journal `validated`, prepare, for a rule prepare decides: the outcome it decided.
    fn run_decided(&mut self) -> (ItemOutcome, String) {
        let cand = self.candidate();
        let (stamp, _) = stamp_of(&self.validate(&cand));
        match self.prepare(&stamp) {
            FwPrepared::Decided(r) => (r.outcome, r.detail),
            FwPrepared::Ready(_) => panic!("ready"),
        }
    }

    /// Validate, journal `validated`, prepare; the removal and its intent.
    fn ready(&mut self) -> (Box<FwRemoval>, Intent) {
        let cand = self.candidate();
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
        match self.prepare(&stamp) {
            FwPrepared::Ready(removal) => {
                let intent = removal.intent().clone();
                (removal, intent)
            }
            FwPrepared::Decided(r) => panic!("not ready: {r:?}"),
        }
    }

    /// The whole run of the item: validate, prepare, intent, `act.before`, act, done.
    fn run(&mut self) -> (ItemOutcome, Intent) {
        let (removal, intent) = self.ready();
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

    fn prepare_undo(
        &self,
        intent: &Intent,
        done: Option<&ItemOutcome>,
        own_attempt: bool,
        roots: &[String],
    ) -> FwUndoPrepared {
        prepare_undo(
            &self.fake,
            &self.session,
            &GuardEnv::sample(),
            &FwUndoArgs {
                intent,
                done,
                own_attempt,
                program_roots: roots,
            },
        )
    }

    /// Closes the journal (as a crash would) and opens it again for appending.
    fn reopen_journal(&mut self) {
        let other = self.roots.create_session().unwrap();
        let placeholder = JournalWriter::create(&other, header(&other)).unwrap();
        drop(std::mem::replace(&mut self.journal, placeholder));
        self.journal = JournalWriter::open_append(&self.session).unwrap();
    }

    /// The whole undo of the op with `roots`, journalled.
    fn undo_with(&mut self, intent: &Intent, done: &ItemOutcome, roots: &[String]) -> FwUndoResult {
        match self.prepare_undo(intent, Some(done), false, roots) {
            FwUndoPrepared::Decided(r) => r,
            FwUndoPrepared::Ready(job) => {
                let token = self.journal.undo_intent(OP).unwrap();
                let r = run_undo(&self.fake, job, &token);
                match &r {
                    FwUndoResult::Done { outcome, .. } => {
                        self.journal.undo_done(token, outcome.clone()).unwrap()
                    }
                    FwUndoResult::Conflict { conflict, detail } => self
                        .journal
                        .undo_conflict(token, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                r
            }
        }
    }

    fn undo(&mut self, intent: &Intent, done: &ItemOutcome) -> FwUndoResult {
        self.undo_with(intent, done, &[ROOT.to_owned()])
    }
}

fn skip_reason(outcome: &ItemOutcome) -> &SkipReason {
    match outcome {
        ItemOutcome::Skipped { reason } => reason,
        other => panic!("not skipped: {other:?}"),
    }
}

fn fail_code(outcome: &ItemOutcome) -> FailCode {
    match outcome {
        ItemOutcome::Failed { code, .. } => *code,
        other => panic!("not failed: {other:?}"),
    }
}

fn decided(v: FwValidated) -> ItemOutcome {
    match v {
        FwValidated::Decided(r) => r.outcome,
        FwValidated::Validated { .. } => panic!("validated"),
    }
}

fn conflict(r: &FwUndoResult) -> &UndoConflict {
    match r {
        FwUndoResult::Conflict { conflict, .. } => conflict,
        other => panic!("no conflict: {other:?}"),
    }
}

fn done_outcome(r: &FwUndoResult) -> &UndoOutcome {
    match r {
        FwUndoResult::Done { outcome, .. } => outcome,
        other => panic!("not done: {other:?}"),
    }
}

fn creates(log: &[String]) -> usize {
    log.iter().filter(|l| l.starts_with("create ")).count()
}

fn deletes(log: &[String]) -> Vec<String> {
    log.iter()
        .filter(|l| l.starts_with("delete "))
        .cloned()
        .collect()
}

fn definition_of(intent: &Intent) -> &purge_model::exec::op::BackupRef {
    match &intent.inverse {
        Inverse::RecreateFirewallRule { definition } => definition,
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

#[test]
fn validate_absent_vanished() {
    let w = world("fw-v-absent", RULE);
    w.fake.remove_rule(ID);
    assert_eq!(decided(w.validate(&w.candidate())), ItemOutcome::Vanished);
}

#[test]
fn validate_passes_a_vendor_rule_read_only() {
    let w = world("fw-v-pass", RULE);
    let (stamp, facts) = stamp_of(&w.validate(&w.candidate()));
    let sha = identity(ID, RULE).fp().sha256;
    assert_eq!(
        stamp,
        Stamp::Object {
            kind: ObjectKind::FirewallRule,
            sha256: sha.clone()
        }
    );
    assert_eq!(
        facts,
        ItemFacts::Object {
            kind: ObjectKind::FirewallRule,
            sha256: sha,
            running: false
        }
    );
    assert_eq!(w.fake.log(), vec![format!("read {ID}")]);
}

/// Hostile: after the scan the rule was edited to allow another program. Same id, same display name,
/// another digest.
#[test]
fn validate_digest_mismatch() {
    let w = world("fw-v-digest", RULE);
    let cand = w.candidate();
    w.fake.set_rule(
        ID,
        &RULE.replace(r"Vendor\app.exe", r"Vendor\..\..\Users\Public\evil.exe"),
    );
    assert_eq!(
        skip_reason(&decided(w.validate(&cand))),
        &SkipReason::ChangedSinceScan
    );
    // A candidate without a fingerprint, or with another kind's: the same.
    let mut bare = cand.clone();
    bare.object_fp = None;
    assert_eq!(
        skip_reason(&decided(w.validate(&bare))),
        &SkipReason::ChangedSinceScan
    );
    let mut other = w.candidate();
    other.object_fp = Some(purge_model::ObjectFp {
        kind: ObjectKind::Service,
        sha256: identity(ID, RULE).fp().sha256,
    });
    w.fake.set_rule(ID, RULE);
    assert_eq!(
        skip_reason(&decided(w.validate(&other))),
        &SkipReason::ChangedSinceScan
    );
    // A case variant of the id, stored by the registry as such, is another rule's identity.
    w.fake.remove_rule(ID);
    w.fake.set_rule(&ID.to_lowercase(), RULE);
    assert_eq!(
        skip_reason(&decided(w.validate(&cand))),
        &SkipReason::ChangedSinceScan
    );
}

/// An op that names the rule in another spelling of its id (the fingerprint still over the stored id):
/// not the rule the op names, refused before any delete.
#[test]
fn validate_other_spelling_of_the_id_refused() {
    let w = world("fw-v-spelling", RULE);
    let lower = ID.to_lowercase();
    let op = ExecOp::DeleteFirewallRule { id: lower.clone() };
    let mut cand = candidate_for(&lower, RULE);
    cand.object_fp = Some(identity(ID, RULE).fp());
    assert_eq!(
        skip_reason(&decided(validate(&w.fake, &w.deny, &op, &cand))),
        &SkipReason::ChangedSinceScan
    );
    assert!(deletes(&w.fake.log()).is_empty());
}

#[test]
fn validate_package_bound_blocked() {
    let rules = [
        (
            r"v2.33|Action=Allow|Dir=In|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|PFN=Vendor.App_8wekyb3d8bbwe|",
            ids::FW_PACKAGE_BOUND,
        ),
        (
            r"v2.33|Action=Allow|Dir=In|LUOwn=S-1-15-2-1-2-3|Name=Vendor App|",
            ids::FW_PACKAGE_BOUND,
        ),
        (
            r"v2.33|Action=Allow|Dir=In|App=C:\Program Files\Vendor\app.exe|Name=@{Vendor.App?ms-resource://x}|",
            ids::FW_RESOURCE_NAME,
        ),
        (
            r"v2.33|Action=Allow|Dir=In|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|EmbedCtxt=@FirewallAPI.dll,-28502|",
            ids::FW_RESOURCE_NAME,
        ),
    ];
    for (rule, id) in rules {
        let w = world("fw-v-pkg", rule);
        let outcome = decided(w.validate(&w.candidate()));
        assert_eq!(
            skip_reason(&outcome),
            &SkipReason::GateBlocked {
                blocker: Blocker::DenyListed { rule: id.into() }
            },
            "{rule}"
        );
    }
}

#[test]
fn validate_unparseable_blocked() {
    for rule in [
        "garbage",
        "v2.33|Action=Allow|NoEquals|Name=X|",
        // Parses, but a field has no exact re-create mapping: never deleted.
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Future=1|Name=Vendor App|",
        // Review R1 S3: Action, Active and Dir are required.
        r"v2.33|Action=Allow|Dir=In|Name=Vendor App|",
        r"v2.33|Active=TRUE|Dir=In|Name=Vendor App|",
        r"v2.33|Action=Allow|Active=TRUE|Name=Vendor App|",
    ] {
        let w = world("fw-v-parse", rule);
        assert_eq!(
            skip_reason(&decided(w.validate(&w.candidate()))),
            &SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            },
            "{rule}"
        );
    }
    // A value the backend cannot read as one exact string.
    let w = world("fw-v-raw", RULE);
    w.fake.world().fail_next.insert(
        "read",
        ObjErr::new(ObjErrKind::Refused, None, "text after the terminating NUL"),
    );
    assert_eq!(
        skip_reason(&decided(w.validate(&w.candidate()))),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        }
    );
    // Any other read failure.
    w.fake.world().fail_next.insert(
        "read",
        ObjErr::new(ObjErrKind::AccessDenied, Some(5), "denied"),
    );
    assert_eq!(
        fail_code(&decided(w.validate(&w.candidate()))),
        FailCode::ObjectApi
    );
}

/// Review R2b S2, B1: a rule of a form whose re-creation no VM round trip has proven yet, and a
/// service's rule (svchost), are never deleted: validate and prepare both refuse them.
#[test]
fn unproven_forms_and_service_rules_are_refused() {
    let base = r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|";
    // Still unproven after the VM run of 2026-11-17 (review R3b S4): LSM, ICMP, protocols other than
    // 6, 17 and 47.
    let mut rules: Vec<String> = [
        "LSM=TRUE|",
        "Protocol=1|ICMP4=8:*|",
        "Protocol=58|ICMP6=128:*|",
        "Protocol=1|",
        "Protocol=2|",
    ]
    .iter()
    .map(|extra| format!("{base}{extra}"))
    .collect();
    rules.push(
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\system32\svchost.exe|Svc=RpcSs|Name=Vendor App|"
            .to_owned(),
    );
    for rule in &rules {
        let w = world("fw-v-unproven", rule);
        assert_eq!(
            skip_reason(&decided(w.validate(&w.candidate()))),
            &SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            },
            "{rule}"
        );
        // Prepare judges the rule again from its own read (a stamp from before the change).
        let stamp = Stamp::Object {
            kind: ObjectKind::FirewallRule,
            sha256: identity(ID, rule).fp().sha256,
        };
        let FwPrepared::Decided(r) = w.prepare(&stamp) else {
            panic!("ready: {rule}");
        };
        assert_eq!(
            skip_reason(&r.outcome),
            &SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            },
            "{rule}: {}",
            r.detail
        );
        assert!(deletes(&w.fake.log()).is_empty());
    }
}

/// Review R3b S4: the seven shapes and protocol 47 the VM proved (own and native rules re-created
/// byte-equal) are deleted and created again like every other rule.
#[test]
fn shapes_the_vm_proved_are_deleted_and_restored() {
    let base = r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|";
    for extra in [
        "Protocol=17|Edge=TRUE|",
        "Protocol=17|Edge=TRUE|Defer=App|",
        "Protocol=17|LOM=TRUE|",
        "Protocol=6|LPort=7000|LA4=10.0.0.5|LA6=fe80::/64|",
        "Profile=Domain|",
        "Protocol=6|RPort2_10=8554-8558|",
        "IFType=Lan|",
        "Protocol=47|",
    ] {
        let rule = format!("{base}{extra}");
        let mut w = world("fw-proven", &rule);
        let (outcome, intent) = w.run();
        assert_eq!(outcome, ItemOutcome::Done, "{rule}");
        assert_eq!(w.fake.rule(ID), None, "{rule}");
        let r = w.undo(&intent, &outcome);
        assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{rule}");
        assert_eq!(w.fake.rule(ID).as_deref(), Some(rule.as_str()), "{rule}");
    }
}

/// Review R3b S2: with no program roots every rule is refused at prepare and at the act, a port rule
/// without `App` too (it passes the per-program check vacuously).
#[test]
fn no_roots_refuses_rules_without_a_program() {
    let port_rule = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9000|Name=Vendor App|";
    for rule in [port_rule, RULE] {
        let mut w = world("fw-noroots", rule);
        w.program_roots = Vec::new();
        let (outcome, detail) = w.run_decided();
        assert_eq!(
            skip_reason(&outcome),
            &SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            },
            "{rule}: {detail}"
        );
        assert!(detail.contains("gate.no-program-roots"), "{detail}");
        assert!(deletes(&w.fake.log()).is_empty());
    }
    // Prepared with roots (a port rule passes them), acted with none: refused at the act.
    let mut w = world("fw-noroots-act", port_rule);
    let (removal, intent) = w.ready();
    let token = w.journal.intent(intent).unwrap();
    let r = act(&w.fake, &w.deny, &w.session, removal, &token, &[]);
    assert_eq!(
        skip_reason(&r.outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        },
        "{}",
        r.detail
    );
    assert!(r.detail.contains("gate.no-program-roots"), "{}", r.detail);
    assert_eq!(w.fake.rule(ID).as_deref(), Some(port_rule));
}

/// Review R2b B1: an `App` outside the roots is refused at prepare and, with the roots of a resumed
/// run, at the act; S4: a definition gone before the act refuses it.
#[test]
fn prepare_and_act_refuse_what_undo_would_refuse() {
    let mut w = world("fw-p-roots", RULE);
    w.program_roots = vec![r"C:\Program Files\Other".to_owned()];
    let (outcome, detail) = w.run_decided();
    assert_eq!(
        skip_reason(&outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        },
        "{detail}"
    );
    let mut w = world("fw-a-roots", RULE);
    let (removal, intent) = w.ready();
    let token = w.journal.intent(intent).unwrap();
    let r = act(&w.fake, &w.deny, &w.session, removal, &token, &[]);
    assert_eq!(
        skip_reason(&r.outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        }
    );
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
    let mut w = world("fw-a-nodef", RULE);
    let (removal, intent) = w.ready();
    w.session
        .delete_backup_file(&definition_of(&intent).path)
        .unwrap();
    let token = w.journal.intent(intent).unwrap();
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert_eq!(skip_reason(&r.outcome), &SkipReason::NoVerifiedBackup);
    assert!(deletes(&w.fake.log()).is_empty());
}

#[test]
fn validate_unusable_ids_refused_before_any_read() {
    let w = world("fw-v-id", RULE);
    for id in ["", "{a}\u{1}", &"x".repeat(261)] {
        let op = ExecOp::DeleteFirewallRule { id: id.to_owned() };
        let cand = candidate_for(id, RULE);
        let v = validate(&w.fake, &w.deny, &op, &cand);
        assert_eq!(fail_code(&decided(v)), FailCode::Internal, "{id:?}");
    }
    // An op that does not act on the item's target.
    let cand = candidate_for(TWIN, TWIN_RULE);
    assert_eq!(
        fail_code(&decided(validate(&w.fake, &w.deny, &exec_op(), &cand))),
        FailCode::Internal
    );
    assert!(w.fake.log().is_empty(), "{:?}", w.fake.log());
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

#[test]
fn prepare_writes_the_definition_from_one_read() {
    let mut w = world("fw-p-def", RULE);
    let before = {
        let cand = w.candidate();
        let _ = w.validate(&cand);
        w.fake.log().len()
    };
    let (_, intent) = w.ready();
    assert!(intent.is_consistent(), "{intent:?}");
    // validate (again, inside ready) and prepare: one read each.
    assert_eq!(
        w.fake.log()[before..],
        [format!("read {ID}"), format!("read {ID}")]
    );
    let def: FwDef = read_def(&w.session, definition_of(&intent)).unwrap();
    assert_eq!(def.schema, FWDEF_SCHEMA);
    assert_eq!(def.id, ID);
    assert_eq!(def.rule, RULE);
    assert_eq!(def.identity_sha256, identity(ID, RULE).fp().sha256);
    assert_eq!(def.fields, parse_firewall_rule(RULE).unwrap().fields);
    assert_eq!(
        definition_of(&intent).path,
        backup_rel(BackupKind::Definition, OP)
    );
    // Nothing was deleted.
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
    assert!(deletes(&w.fake.log()).is_empty());
}

#[test]
fn prepare_rule_changed_since_validate_skips_without_a_definition() {
    let w = world("fw-p-changed", RULE);
    let (stamp, _) = stamp_of(&w.validate(&w.candidate()));
    w.fake.set_rule(ID, &RULE.replace("Dir=In", "Dir=Out"));
    let FwPrepared::Decided(r) = w.prepare(&stamp) else {
        panic!("ready");
    };
    assert_eq!(skip_reason(&r.outcome), &SkipReason::ChangedSinceScan);
    assert!(
        !w.session
            .path()
            .join(backup_rel(BackupKind::Definition, OP))
            .exists()
    );
    // Gone meanwhile: vanished. A stamp of another kind: internal.
    w.fake.remove_rule(ID);
    let FwPrepared::Decided(r) = w.prepare(&stamp) else {
        panic!("ready");
    };
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    let FwPrepared::Decided(r) = w.prepare(&Stamp::Package) else {
        panic!("ready");
    };
    assert_eq!(fail_code(&r.outcome), FailCode::Internal);
}

// ---------------------------------------------------------------------------------------------------
// Act
// ---------------------------------------------------------------------------------------------------

#[test]
fn act_deletes_only_by_id() {
    let mut w = world("fw-a-byid", RULE);
    let before = w.fake.rules();
    let (outcome, _) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    assert_eq!(w.fake.rule(ID), None);
    // The other rule of the same display name is untouched, byte for byte.
    assert_eq!(
        w.fake.rules(),
        before
            .into_iter()
            .filter(|(id, _)| id != ID)
            .collect::<Vec<_>>()
    );
    assert_eq!(w.fake.rule(TWIN).as_deref(), Some(TWIN_RULE));
    assert_eq!(deletes(&w.fake.log()), vec![format!("delete {ID}")]);
}

#[test]
fn act_gate_rechecks_the_digest() {
    let mut w = world("fw-a-gate", RULE);
    let (removal, intent) = w.ready();
    let token = w.journal.intent(intent).unwrap();
    w.fake
        .set_rule(ID, &RULE.replace("Action=Allow", "Action=Block"));
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert_eq!(skip_reason(&r.outcome), &SkipReason::ChangedSinceScan);
    assert!(deletes(&w.fake.log()).is_empty());
    w.journal.done(token, r.outcome).unwrap();
}

#[test]
fn act_gone_before_the_act_is_vanished() {
    let mut w = world("fw-a-gone", RULE);
    let (removal, intent) = w.ready();
    let token = w.journal.intent(intent).unwrap();
    w.fake.remove_rule(ID);
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    assert!(deletes(&w.fake.log()).is_empty());
    w.journal.done(token, r.outcome).unwrap();
}

#[test]
fn act_zero_deleted_still_present_fails() {
    let mut w = world("fw-a-zero", RULE);
    w.fake.world().delete_reports = Some(0);
    let (outcome, intent) = w.run();
    assert_eq!(fail_code(&outcome), FailCode::ObjectApi);
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
    // Nothing changed: undo has nothing to do.
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::NothingToUndo);
}

#[test]
fn act_zero_deleted_absent_vanished() {
    let mut w = world("fw-a-zero-gone", RULE);
    w.fake.world().delete_reports = Some(0);
    w.fake.after("delete", |world| {
        world.rules.retain(|(id, _)| id != ID);
    });
    let (outcome, _) = w.run();
    assert_eq!(outcome, ItemOutcome::Vanished);
    // No flush and no fault point: Purge deleted nothing.
    assert!(!w.fake.log().iter().any(|l| l == "flush"));
}

#[test]
fn act_flush_before_done() {
    let mut w = world("fw-a-flush", RULE);
    let (removal, intent) = w.ready();
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
    assert_eq!(
        log,
        vec![
            format!("read {ID}"),
            format!("delete {ID}"),
            "flush".to_owned(),
            format!("read {ID}"),
        ]
    );
    assert_eq!(
        take_fault_trace(),
        vec![fault::OBJDELETE_AFTER, fault::ACT_AFTER]
    );
    w.journal.done(token, r.outcome).unwrap();
}

#[test]
fn act_flush_failure_is_verify_failed() {
    let mut w = world("fw-a-flushfail", RULE);
    w.fake
        .world()
        .fail_next
        .insert("flush", ObjErr::new(ObjErrKind::Other, Some(1117), "io"));
    let (outcome, intent) = w.run();
    assert_eq!(fail_code(&outcome), FailCode::VerifyFailed);
    // A VerifyFailed delete is undone: the rule is gone.
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
}

/// A delete call that reports a failure but removed the rule anyway is a done delete (else undo would
/// call it "nothing changed" and never bring the rule back).
#[test]
fn act_failed_call_that_deleted_anyway_is_done() {
    let mut w = world("fw-a-failgone", RULE);
    {
        let mut world = w.fake.world();
        world.fail_after_act = true;
        world.fail_next.insert(
            "delete",
            ObjErr::new(ObjErrKind::Other, Some(0x8004_1001), "WBEM_E_FAILED"),
        );
    }
    let (outcome, intent) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    assert!(w.fake.log().iter().any(|l| l == "flush"));
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
}

#[test]
fn act_failed_call_rule_still_there_fails() {
    for (kind, code) in [
        (ObjErrKind::Other, FailCode::ObjectApi),
        (ObjErrKind::Refused, FailCode::ObjectApi),
        (ObjErrKind::AccessDenied, FailCode::AccessDenied),
    ] {
        let mut w = world("fw-a-fail", RULE);
        w.fake
            .world()
            .fail_next
            .insert("delete", ObjErr::new(kind, Some(5), "refused"));
        let (outcome, _) = w.run();
        assert_eq!(fail_code(&outcome), code, "{kind:?}");
        assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
    }
}

/// More than one deleted cannot happen (the wrapper deletes only on exactly one match). Reported
/// anyway with the rule gone, it stays undoable.
#[test]
fn act_more_than_one_reported() {
    let mut w = world("fw-a-two", RULE);
    w.fake.world().delete_reports = Some(2);
    let (outcome, _) = w.run();
    assert_eq!(fail_code(&outcome), FailCode::Internal);
    let mut w = world("fw-a-two-gone", RULE);
    w.fake.world().delete_reports = Some(2);
    w.fake.after("delete", |world| {
        world.rules.retain(|(id, _)| id != ID);
    });
    let (outcome, intent) = w.run();
    assert_eq!(fail_code(&outcome), FailCode::VerifyFailed);
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
}

#[test]
fn act_with_token_of_another_op_does_nothing() {
    let mut w = world("fw-a-token", RULE);
    let (removal, intent) = w.ready();
    let _token = w.journal.intent(intent.clone()).unwrap();
    // A token of another item, from another run's journal.
    let other = Intent {
        item: CandidateId("c-other".into()),
        ..intent
    };
    let other_session = w.roots.create_session().unwrap();
    let mut other_journal = JournalWriter::create(&other_session, header(&other_session)).unwrap();
    other_journal
        .validated(Validated {
            op: OP,
            item: other.item.clone(),
            target: Target::FirewallRule { id: ID.into() },
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
    assert_eq!(fail_code(&r.outcome), FailCode::Internal);
    assert_eq!(w.fake.log().len(), before);
}

#[test]
fn complete_present_is_verify_failed() {
    let w = world("fw-c", RULE);
    assert_eq!(
        fail_code(&complete(&w.fake, ID).outcome),
        FailCode::VerifyFailed
    );
    w.fake.remove_rule(ID);
    assert_eq!(complete(&w.fake, ID).outcome, ItemOutcome::Done);
}

/// A value that lags behind the delete is read again until it is gone.
#[test]
fn complete_waits_for_a_lagging_value() {
    let w = world("fw-c-lag", RULE);
    // The value is still there at the first read and gone at the second.
    w.fake
        .after("read", |world| world.rules.retain(|(id, _)| id != ID));
    assert_eq!(complete(&w.fake, ID).outcome, ItemOutcome::Done);
    assert_eq!(
        w.fake.log(),
        vec![format!("read {ID}"), format!("read {ID}")]
    );
}

// ---------------------------------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------------------------------

#[test]
fn probe_three_states() {
    let mut w = world("fw-probe", RULE);
    let (_, intent) = w.ready();
    assert_eq!(probe(&w.fake, &intent), Probe::NotDone);
    w.fake
        .set_rule(ID, &RULE.replace("Active=TRUE", "Active=FALSE"));
    assert!(matches!(probe(&w.fake, &intent), Probe::Attention { .. }));
    w.fake.remove_rule(ID);
    assert_eq!(probe(&w.fake, &intent), Probe::Done(ItemOutcome::Done));
    w.fake
        .world()
        .fail_next
        .insert("read", ObjErr::new(ObjErrKind::Other, Some(5), "denied"));
    assert!(matches!(probe(&w.fake, &intent), Probe::Attention { .. }));
    // A resumed run rebuilds the removal from the intent.
    let removal = FwRemoval::from_intent(&intent).expect("a firewall removal");
    assert_eq!(removal.intent(), &intent);
    let mut not_fw = intent.clone();
    not_fw.exec_op = ExecOp::DeleteService { name: "X".into() };
    assert!(FwRemoval::from_intent(&not_fw).is_none());
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

#[test]
fn undo_restores_same_id_and_same_rule() {
    let mut w = world("fw-u-restore", RULE);
    let (outcome, intent) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(
        r,
        FwUndoResult::Done {
            outcome: UndoOutcome::Restored,
            detail: String::new()
        }
    );
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));
    let log = w.fake.log()[before..].to_vec();
    assert_eq!(
        log,
        vec![
            format!("read {ID}"),
            format!("create {ID}"),
            "flush".to_owned(),
            format!("read {ID}"),
        ]
    );
    // The stored id is exactly the one deleted.
    assert!(w.fake.rules().iter().any(|(id, _)| id == ID));
}

/// The create may store another version prefix or field order; the fields decide (`same_rule`).
#[test]
fn undo_restored_with_another_version_says_so() {
    let mut w = world("fw-u-version", RULE);
    let (outcome, intent) = w.run();
    w.fake.world().create_version = "v2.34".into();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored);
    let FwUndoResult::Done { detail, .. } = &r else {
        unreachable!()
    };
    assert!(detail.contains("version"), "{detail}");
}

#[test]
fn undo_existing_same_already_restored() {
    let mut w = world("fw-u-same", RULE);
    let (outcome, intent) = w.run();
    // Re-created meanwhile (by the app's repair, say) with the same fields in another order.
    let reordered = r"v2.31|Name=Vendor App|Defer=User|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\Vendor\app.exe|";
    w.fake.set_rule(ID, reordered);
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(done_outcome(&r), &UndoOutcome::AlreadyRestored);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
    assert_eq!(w.fake.rule(ID).as_deref(), Some(reordered));
}

#[test]
fn undo_existing_different_object_exists() {
    let mut w = world("fw-u-differs", RULE);
    let (outcome, intent) = w.run();
    let other = RULE.replace(r"Vendor\app.exe", r"Other\app.exe");
    w.fake.set_rule(ID, &other);
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
    assert_eq!(creates(&w.fake.log()[before..]), 0);
    assert!(deletes(&w.fake.log()[before..]).is_empty());
    assert_eq!(w.fake.rule(ID), Some(other));
    // A case variant of the id with the same fields is not this rule either.
    w.fake.remove_rule(ID);
    w.fake.set_rule(&ID.to_lowercase(), RULE);
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
}

#[test]
fn undo_create_meeting_a_new_rule_is_object_exists() {
    let mut w = world("fw-u-race", RULE);
    let (outcome, intent) = w.run();
    let FwUndoPrepared::Ready(job) =
        w.prepare_undo(&intent, Some(&outcome), false, &[ROOT.to_owned()])
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    let other = RULE.replace("Dir=In", "Dir=Out");
    w.fake.set_rule(ID, &other);
    let r = run_undo(&w.fake, job, &token);
    assert_eq!(conflict(&r), &UndoConflict::ObjectExists);
    assert_eq!(w.fake.rule(ID), Some(other));
}

/// Hostile: a definition whose program lies outside every root recorded for the run. Validate does not
/// judge a rule's program (the scan did); undo must not open the firewall for it.
#[test]
fn undo_app_outside_root_refused() {
    let forged =
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=%SystemRoot%\System32\cmd.exe|Name=Vendor App|";
    let mut w = world("fw-u-root", forged);
    // Prepare and the act refuse it outside the roots they are given: made here with a root that
    // holds cmd.exe (as a store rewritten with matching hashes would), undone with the run's real one.
    w.program_roots = vec![r"C:\Windows\System32".to_owned()];
    let (outcome, intent) = w.run();
    assert_eq!(outcome, ItemOutcome::Done);
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ProgramOutsideRoot, "{r:?}");
    assert_eq!(creates(&w.fake.log()), 0);
    assert_eq!(w.fake.rule(ID), None);
    // No roots at all: refused too. And the vendor rule itself without its root.
    let mut w = world("fw-u-noroot", RULE);
    let (outcome, intent) = w.run();
    let r = w.undo_with(&intent, &outcome, &[]);
    assert_eq!(conflict(&r), &UndoConflict::ProgramOutsideRoot);
    let r = w.undo_with(&intent, &outcome, &[r"C:\Program Files\Vend".to_owned()]);
    assert_eq!(conflict(&r), &UndoConflict::ProgramOutsideRoot);
    assert_eq!(creates(&w.fake.log()), 0);
    // An unresolvable program is never deleted (undo would refuse it; review R2b B1); a rule without
    // a program needs no root.
    let mut w = world(
        "fw-u-unres",
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=%APPDATA%\x.exe|Name=Vendor App|",
    );
    let (outcome, _) = w.run_decided();
    assert_eq!(
        skip_reason(&outcome),
        &SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp
        }
    );
    assert!(deletes(&w.fake.log()).is_empty());
    let port_rule = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort2_10=8090-8095|Name=Vendor App|";
    let mut w = world("fw-u-port", port_rule);
    let (outcome, intent) = w.run();
    let r = w.undo_with(&intent, &outcome, &[]);
    assert_eq!(done_outcome(&r), &UndoOutcome::Restored, "{r:?}");
    assert_eq!(w.fake.rule(ID).as_deref(), Some(port_rule));
}

/// The re-created rule is not the backup: it is deleted again by its id, and the undo is a conflict.
#[test]
fn undo_half_made_rule_removed_when_check_fails() {
    let mut w = world("fw-u-half", RULE);
    let (outcome, intent) = w.run();
    w.fake
        .world()
        .create_extra
        .push(("RA4".into(), "LocalSubnet".into()));
    let before = w.fake.log().len();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ValueDiffers, "{r:?}");
    // The detail names the file that keeps the rule string (review R2b S2).
    let FwUndoResult::Conflict { detail, .. } = &r else {
        panic!();
    };
    let file = w.session.path().join(&definition_of(&intent).path);
    assert!(detail.contains(&file.display().to_string()), "{detail}");
    assert_eq!(w.fake.rule(ID), None);
    let log = w.fake.log()[before..].to_vec();
    assert_eq!(deletes(&log), vec![format!("delete {ID}")]);
    let created = log.iter().position(|l| l.starts_with("create ")).unwrap();
    let deleted = log.iter().position(|l| l.starts_with("delete ")).unwrap();
    assert!(created < deleted);
    assert_eq!(log.last().map(String::as_str), Some("flush"));
    // The twin of the same display name was never touched.
    assert_eq!(w.fake.rule(TWIN).as_deref(), Some(TWIN_RULE));
    // Stored under another spelling of the id: not exactly the id, so not restored either (and the
    // delete by the exact id refuses the case variant).
    let mut w = world("fw-u-case", RULE);
    let (outcome, intent) = w.run();
    w.fake.world().create_id_as = Some(ID.to_lowercase());
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::ValueDiffers, "{r:?}");
}

/// A crash at `fwrestore.mid` (here: the run stops at its flush right after the create, the token is
/// lost). The undo run again finds the re-created rule, flushes and calls it restored.
#[test]
fn undo_crash_at_fwrestore_mid_then_resume() {
    let mut w = world("fw-u-crash", RULE);
    let (outcome, intent) = w.run();
    let FwUndoPrepared::Ready(job) =
        w.prepare_undo(&intent, Some(&outcome), false, &[ROOT.to_owned()])
    else {
        panic!("decided");
    };
    let token = w.journal.undo_intent(OP).unwrap();
    w.fake.world().fail_next.insert(
        "flush",
        ObjErr::new(ObjErrKind::Other, Some(1117), "power lost"),
    );
    take_fault_trace();
    let _ = run_undo(&w.fake, job, &token);
    assert_eq!(take_fault_trace(), vec![fault::FWRESTORE_MID]);
    drop(token);
    w.reopen_journal();
    assert_eq!(w.fake.rule(ID).as_deref(), Some(RULE));

    let token = w.journal.resume_undo(OP).expect("an open undo intent");
    let before = w.fake.log().len();
    let FwUndoPrepared::Decided(r) =
        w.prepare_undo(&intent, Some(&outcome), true, &[ROOT.to_owned()])
    else {
        panic!("ready");
    };
    assert_eq!(done_outcome(&r), &UndoOutcome::AlreadyRestored, "{r:?}");
    let log = w.fake.log()[before..].to_vec();
    assert_eq!(creates(&log), 0);
    assert!(log.iter().any(|l| l == "flush"), "{log:?}");
    w.journal
        .undo_done(token, UndoOutcome::AlreadyRestored)
        .unwrap();
}

/// `FIREWALL_RESTORE_EXACT` is true (spike), so the fallback of the design (a new id and
/// `Reversibility::Partial`) does not exist: the module does not compile without the constant, and
/// every undo re-creates under the deleted rule's own id.
#[test]
fn undo_fallback_not_needed_restore_is_exact() {
    const { assert!(FIREWALL_RESTORE_EXACT) };
    let mut w = world("fw-u-exact", RULE);
    let (outcome, intent) = w.run();
    let FwUndoPrepared::Ready(job) =
        w.prepare_undo(&intent, Some(&outcome), false, &[ROOT.to_owned()])
    else {
        panic!("decided");
    };
    assert_eq!(job.id(), ID);
    let src = include_str!("../src/act_firewall.rs");
    assert!(src.contains("const _: () = assert!("));
    assert!(src.contains("FIREWALL_RESTORE_EXACT is false: act_firewall has no new-id fallback"));
}

#[test]
fn undo_tampered_def_refused() {
    let mut w = world("fw-u-tamper", RULE);
    let (outcome, intent) = w.run();
    let path = w.session.path().join(&definition_of(&intent).path);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.windows(6).position(|b| b == b"Vendor").unwrap();
    bytes[at] = b'X';
    std::fs::write(&path, &bytes).unwrap();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered);
    assert_eq!(creates(&w.fake.log()), 0);
    // Missing.
    std::fs::remove_file(&path).unwrap();
    let r = w.undo(&intent, &outcome);
    assert_eq!(conflict(&r), &UndoConflict::BackupMissing);
}

/// Hostile: a definition whose hashes all match, but whose `fields` (what the create is fed from) are
/// not its raw string's (what the digest covers). Refused before anything is read or created.
#[test]
fn undo_forged_fields_refused() {
    let w = world("fw-u-forged", RULE);
    let mut fields = parse_firewall_rule(RULE).unwrap().fields;
    for (k, v) in &mut fields {
        if k == "App" {
            *v = r"C:\Program Files\Vendor\..\..\Users\Public\evil.exe".into();
        }
    }
    let forged = FwDef {
        schema: FWDEF_SCHEMA.into(),
        id: ID.into(),
        identity_sha256: identity(ID, RULE).fp().sha256,
        rule: RULE.into(),
        fields,
    };
    let definition = write_def(&w.session, OP, &forged).unwrap();
    let intent = Intent {
        op: OP,
        item: CandidateId("c-fw".into()),
        exec_op: exec_op(),
        inverse: Inverse::RecreateFirewallRule { definition },
        definition: None,
        pre: ItemFacts::Object {
            kind: ObjectKind::FirewallRule,
            sha256: identity(ID, RULE).fp().sha256,
            running: false,
        },
    };
    w.fake.remove_rule(ID);
    let FwUndoPrepared::Decided(r) =
        w.prepare_undo(&intent, Some(&ItemOutcome::Done), false, &[ROOT.to_owned()])
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered, "{r:?}");
    // The definition of another op's rule (id or digest): refused as well.
    let mut other = intent.clone();
    other.exec_op = ExecOp::DeleteFirewallRule { id: TWIN.into() };
    let FwUndoPrepared::Decided(r) =
        w.prepare_undo(&other, Some(&ItemOutcome::Done), false, &[ROOT.to_owned()])
    else {
        panic!("ready");
    };
    assert_eq!(conflict(&r), &UndoConflict::BackupTampered);
    assert!(w.fake.log().is_empty(), "{:?}", w.fake.log());
}

#[test]
fn undo_of_an_op_that_changed_nothing() {
    let mut w = world("fw-u-nothing", RULE);
    let (removal, intent) = w.ready();
    let token = w.journal.intent(intent.clone()).unwrap();
    w.fake.remove_rule(ID);
    let r = act(
        &w.fake,
        &w.deny,
        &w.session,
        removal,
        &token,
        &w.program_roots,
    );
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    w.journal.done(token, r.outcome.clone()).unwrap();
    let u = w.undo(&intent, &r.outcome);
    assert_eq!(done_outcome(&u), &UndoOutcome::NothingToUndo);
    assert_eq!(creates(&w.fake.log()), 0);
}

/// The module's live code never writes the registry (the rules key or any other), never spawns a
/// tool, never uses the `INetFw*` objects, and never selects a rule by anything but its id.
#[test]
fn never_writes_firewall_registry() {
    let src = include_str!("../src/act_firewall.rs");
    let live = src.split("pub mod fake").next().expect("the module source");
    let code: String = live
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for word in [
        "set_value",
        "delete_value",
        "create_subkey",
        "delete_subkey",
        "set_security",
        "keyaccess::set_value",
        "keyaccess::create_sub_key",
        "keyaccess::write",
        "keyaccess::all",
        ".delete()",
        "delete_if_empty",
        "regsetvalue",
        "regdelete",
        "netsh",
        "powershell",
        "std::process",
        "command::new",
        "inetfw",
        "displayname",
        "elementname",
    ] {
        assert!(!code.contains(word), "act_firewall.rs uses {word:?}");
    }
    // Every registry open is read-only.
    for (n, line) in code.lines().enumerate() {
        if line.contains("keyaccess::") {
            assert!(line.contains("keyaccess::read"), "line {n}: {line}");
        }
    }
    // The firewall calls are exactly the two by-id ones.
    for call in code.match_indices("fw::").map(|(i, _)| &code[i..]) {
        let name: String = call[4..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        assert!(
            [
                "",
                "check_instance_id",
                "map_rule",
                "delete_by_instance_id",
                "create_with_instance_id"
            ]
            .contains(&name.as_str()),
            "fw::{name}"
        );
    }
}

/// Every fault point of the item and of its undo, in order (the executor's `act.before` and the
/// journal's `done.before` and `undo.intent` around them). With `fault-inject` the points really abort:
/// see `fault_points_abort`.
#[test]
fn fault_points_reached() {
    let mut w = world("fw-fault", RULE);
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
        vec![fault::FWRESTORE_MID, fault::UNDO_ACT_AFTER]
    );
    for point in [
        fault::BACKUP_WRITTEN,
        fault::BACKUP_VERIFIED,
        fault::ACT_BEFORE,
        fault::OBJDELETE_AFTER,
        fault::ACT_AFTER,
        fault::DONE_BEFORE,
        fault::UNDO_INTENT,
        fault::FWRESTORE_MID,
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

    const CHILD: &str = "PURGE_TEST_FW_CHILD";
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    /// The child: the whole item and its undo; it dies at the fault point the parent named.
    #[test]
    fn fw_child_scenario() {
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
            fake: FakeFirewall::with([(ID, RULE), (TWIN, TWIN_RULE)]),
            deny: deny(),
            rule: RULE.to_owned(),
            program_roots: vec![ROOT.to_owned()],
        });
        let (outcome, intent) = w.run();
        let _ = w.undo(&intent, &outcome);
        // Not reached when the point fires.
        std::process::exit(7);
    }

    fn child(point: &str) -> Option<i32> {
        let s = Scratch::new("fw-inject");
        let temp = s.dir("child-temp");
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "inject::fw_child_scenario", "--test-threads=1"])
            .env(CHILD, &s.root)
            .env(fault::ENV_AT, point)
            .env_remove(fault::ENV_PAUSE)
            .env("TEMP", &temp)
            .env("TMP", &temp)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code()
    }

    #[test]
    fn fault_points_abort() {
        for point in [
            fault::BACKUP_WRITTEN,
            fault::BACKUP_VERIFIED,
            fault::ACT_BEFORE,
            fault::OBJDELETE_AFTER,
            fault::ACT_AFTER,
            fault::DONE_BEFORE,
            fault::UNDO_INTENT,
            fault::FWRESTORE_MID,
            fault::UNDO_ACT_AFTER,
        ] {
            assert_eq!(child(point), Some(ABORT_CODE), "{point}");
        }
        // A point the scenario never reaches: it runs to its end.
        assert_eq!(child(fault::SVCRESTORE_MID), Some(7));
    }
}

// ---------------------------------------------------------------------------------------------------
// Live (read-only here; changes only on the VM rig)
// ---------------------------------------------------------------------------------------------------

/// Reads stored rules through the live backend: the identity is the value's stored name and exact
/// string. Changes nothing.
#[test]
fn live_read_is_the_registry_value() {
    use purge_win::reg::{Key, RegRoot, RegView, current_control_set};
    let live = LiveFirewall;
    assert_eq!(
        live.read("{00000000-0000-0000-0000-00000000F1A5}").unwrap(),
        None
    );
    assert_eq!(live.read("{a}\u{7}").unwrap_err().kind, ObjErrKind::Refused);
    assert!(FIREWALL_RULES_KEY.ends_with(r"FirewallPolicy\FirewallRules"));
    let cs = current_control_set().unwrap();
    let key = Key::open(
        RegRoot::Hklm,
        &format!(r"SYSTEM\{cs}\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"),
        RegView::K64,
    )
    .unwrap();
    let mut checked = 0;
    for value in key.values().unwrap().into_iter().take(20) {
        let Some(rule) = value.as_string() else {
            continue;
        };
        let read = live.read(&value.name).unwrap().expect("the rule is there");
        assert_eq!(read.id, value.name);
        assert_eq!(read.rule, rule);
        // Any spelling of the id reads the same value, under its stored name.
        let upper = live
            .read(&value.name.to_ascii_uppercase())
            .unwrap()
            .unwrap();
        assert_eq!(upper.id, value.name);
        checked += 1;
    }
    assert!(checked > 0, "no firewall rules on this machine");
}

/// The real delete and re-create of a throwaway rule through every entry point. Elevated, changes the
/// firewall: VM rig only.
#[test]
#[ignore = "creates and deletes a real firewall rule; elevated, VM rig only"]
fn rig_live_delete_and_recreate_round_trip() {
    use purge_win::firewall::{create_with_instance_id, delete_by_instance_id};
    let id = format!(
        "PurgeTest-fw-xfw-{}-{}",
        std::process::id(),
        common::unique("r")
    );
    let raw = r"v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=48123|App=C:\Program Files\PurgeTest\xfw.exe|Name=PurgeTest xfw|";
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = delete_by_instance_id(&self.0);
        }
    }
    let _cleanup = Cleanup(id.clone());
    create_with_instance_id(&id, &parse_firewall_rule(raw).unwrap().fields).unwrap();
    let live = LiveFirewall;
    let mut found = None;
    for _ in 0..50 {
        found = live.read(&id).unwrap();
        if found.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let found = found.expect("the created rule is stored");
    let s = Scratch::new("fw-rig");
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
    let session = roots.create_session().unwrap();
    let mut journal = JournalWriter::create(&session, header(&session)).unwrap();
    let env = common::live_env(&s.path("data"));
    let deny = DenyList::compile(&env);
    let program_roots = vec![r"C:\Program Files\PurgeTest".to_owned()];
    let op = ExecOp::DeleteFirewallRule { id: id.clone() };
    let mut cand = safe(
        "c-rig",
        Target::FirewallRule { id: id.clone() },
        Action::DeleteKey,
    );
    cand.object_fp = Some(found.fp());
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
    let FwPrepared::Ready(removal) = prepare(
        &live,
        &deny,
        &session,
        &FwPrepareArgs {
            op: OP,
            item: &cand.id,
            exec_op: &op,
            validated: &stamp,
            program_roots: &program_roots,
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
    assert_eq!(live.read(&id).unwrap(), None);
    let args = FwUndoArgs {
        intent: &intent,
        done: Some(&r.outcome),
        own_attempt: false,
        program_roots: &program_roots,
    };
    let FwUndoPrepared::Ready(job) = prepare_undo(&live, &session, &env, &args) else {
        panic!("decided");
    };
    let token = journal.undo_intent(OP).unwrap();
    let u = run_undo(&live, job, &token);
    assert_eq!(done_outcome(&u), &UndoOutcome::Restored, "{u:?}");
    let back = live.read(&id).unwrap().unwrap();
    assert_eq!(back, found);
}
