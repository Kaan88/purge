//! Tests of the typed actions with a fake package backend, a relaxed store in a temp directory and a real
//! journal. The few tests that call the real backend only enumerate, except the `#[ignore]`d one, which
//! removes a disposable package in the VM gate.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use purge_model::exec::journal::{
    GateExemptions, Header, ItemFacts, JournalSchema, Record, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::{Blocker, CandidateId, FileTime, ScanMode, Target};
use purge_win::appx::{AppxPackage, SignatureKind};
use purge_win::appx_write::{DeploymentError, RemovalScope, RemoveOutcome};

use super::*;
use crate::journal::{JournalWriter, read, sha256_reader};
use crate::storage::{SessionDir, StorageRoots};

/// The planned package.
const NAME: &str = "Vendor.App_1.0.0.0_x64__abcdefghjkmnp";
/// Same name, other publisher.
const OTHER_PUBLISHER: &str = "Vendor.App_1.0.0.0_x64__zyxwvtsrqpnmk";
/// Similar name, same publisher.
const SIMILAR: &str = "Vendor.App2_1.0.0.0_x64__abcdefghjkmnp";
/// Another version of the same package.
const OTHER_VERSION: &str = "Vendor.App_1.0.0.1_x64__abcdefghjkmnp";

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

/// A scratch directory under the temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "purge-typed-{tag}-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(purge_win::secure::extended_path(&self.0).unwrap());
    }
}

/// A session in a fresh relaxed store, with a journal of `ops` package ops (op n removes `name(n)`),
/// all validated.
struct Session {
    session: SessionDir,
    journal: JournalWriter,
    /// Last: removed after the journal and the session's handles are closed.
    _scratch: Scratch,
}

fn item(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

fn remove_op(name: &str) -> ExecOp {
    ExecOp::RemovePackage {
        full_name: name.to_owned(),
    }
}

impl Session {
    fn new(tag: &str, names: &[&str]) -> Session {
        let scratch = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(&scratch.0.join("data")).unwrap();
        let session = roots.create_session().unwrap();
        let header = Header {
            schema: JournalSchema,
            session: session.id().clone(),
            created: FileTime(134_078_121_020_000_000),
            engine_version: "0.1.0".into(),
            app: "vendor-app".into(),
            plan_hash: sha256_bytes(b"plan"),
            selection_hash: sha256_bytes(b"selection"),
            policy_version: "m1a.6".into(),
            mode: ScanMode::Post,
            items: names.len() as u32,
            allow_irreversible: true,
            volumes: Vec::new(),
        };
        let mut journal = JournalWriter::create(&session, header).unwrap();
        for (i, name) in names.iter().enumerate() {
            let n = i as u32 + 1;
            journal
                .validated(Validated {
                    op: OpId(n),
                    item: item(n),
                    target: Target::AppxPackage {
                        full_name: (*name).to_owned(),
                    },
                    facts: ItemFacts::Package,
                    exemptions: GateExemptions::default(),
                })
                .unwrap();
        }
        Session {
            session,
            journal,
            _scratch: scratch,
        }
    }

    fn prepare(
        &self,
        fake: &dyn PackageBackend,
        n: u32,
        name: &str,
        ack: IrreversibleAck,
    ) -> Prepared {
        prepare_remove_package(
            fake,
            &self.session,
            OpId(n),
            &item(n),
            &remove_op(name),
            ack,
        )
        .unwrap()
    }

    /// Runs the whole sequence for op `n` as the executor does and journals the result.
    fn run(&mut self, fake: &Fake, n: u32, name: &str) -> TypedResult {
        match self.prepare(fake, n, name, IrreversibleAck::Acknowledged) {
            Prepared::Decided(result) => {
                self.journal
                    .done_without_intent(OpId(n), result.outcome.clone())
                    .unwrap();
                result
            }
            Prepared::Ready(removal) => {
                let token = self.journal.intent(removal.intent().clone()).unwrap();
                let result = remove_package(fake, removal, &token);
                self.journal.done(token, result.outcome.clone()).unwrap();
                result
            }
        }
    }

    fn def_path(&self, n: u32) -> PathBuf {
        self.session
            .path()
            .join(backup_rel(BackupKind::Definition, OpId(n)))
    }

    fn records(&self) -> Vec<Record> {
        read(&self.session).unwrap().records
    }
}

fn info(full_name: &str) -> PackageInfo {
    PackageInfo {
        package: AppxPackage {
            full_name: full_name.to_owned(),
            family_name: family_of(full_name).unwrap(),
            installed_location: Some(r"C:\Program Files\Vendor\App".to_owned()),
            effective_external_path: Some(r"C:\Program Files\Vendor\App".to_owned()),
            signature_kind: Some(SignatureKind::Developer),
            is_framework: false,
            is_resource_package: false,
            users: Vec::new(),
            dependencies: None,
        },
        dependencies: Some(Vec::new()),
    }
}

/// What the fake does on `remove`.
#[derive(Clone)]
enum OnRemove {
    /// Unregisters the package and returns the outcome.
    Unregister(RemoveOutcome),
    /// Leaves the package registered and returns the outcome.
    Keep(RemoveOutcome),
}

/// A scripted package backend.
struct Fake {
    packages: RefCell<Vec<PackageInfo>>,
    on_remove: OnRemove,
    /// List calls from this number on (counted from 1) fail.
    fail_list_from: Cell<Option<u32>>,
    lists: Cell<u32>,
    removed: RefCell<Vec<(String, RemovalScope)>>,
    scopes: RefCell<Vec<RemovalScope>>,
}

impl Fake {
    fn new(packages: Vec<PackageInfo>) -> Fake {
        Fake {
            packages: RefCell::new(packages),
            on_remove: OnRemove::Unregister(RemoveOutcome::Removed),
            fail_list_from: Cell::new(None),
            lists: Cell::new(0),
            removed: RefCell::new(Vec::new()),
            scopes: RefCell::new(Vec::new()),
        }
    }

    fn with(mut self, on_remove: OnRemove) -> Fake {
        self.on_remove = on_remove;
        self
    }

    fn removes(&self) -> usize {
        self.removed.borrow().len()
    }
}

impl PackageBackend for Fake {
    fn list(&self, scope: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
        let n = self.lists.get() + 1;
        self.lists.set(n);
        self.scopes.borrow_mut().push(scope);
        if self.fail_list_from.get().is_some_and(|from| n >= from) {
            return Err(ListError {
                code: Some(0x8007_0005_u32 as i32),
                detail: "access denied".into(),
            });
        }
        Ok(self.packages.borrow().clone())
    }

    fn remove(&self, full_name: &str, scope: RemovalScope) -> RemoveOutcome {
        self.removed
            .borrow_mut()
            .push((full_name.to_owned(), scope));
        match &self.on_remove {
            OnRemove::Unregister(outcome) => {
                self.packages
                    .borrow_mut()
                    .retain(|p| !p.package.full_name.eq_ignore_ascii_case(full_name));
                outcome.clone()
            }
            OnRemove::Keep(outcome) => outcome.clone(),
        }
    }
}

fn deployment(hresult: u32) -> DeploymentError {
    DeploymentError {
        hresult: hresult as i32,
        extended_hresult: None,
        error_text: Some("deployment said no".into()),
        activity_id: None,
    }
}

fn denied(rule: &str) -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: SkipReason::GateBlocked {
            blocker: Blocker::DenyListed {
                rule: rule.to_owned(),
            },
        },
    }
}

fn decided(p: Prepared) -> TypedResult {
    match p {
        Prepared::Decided(r) => r,
        Prepared::Ready(r) => panic!("expected a decision, got a removal for {:?}", r.intent()),
    }
}

fn ready(p: Prepared) -> Box<PackageRemoval> {
    match p {
        Prepared::Ready(r) => r,
        Prepared::Decided(r) => panic!("expected a removal, got {r:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare: decisions before anything is written
// ---------------------------------------------------------------------------------------------------

#[test]
fn without_acknowledgement_it_is_skipped_and_nothing_is_looked_at() {
    let s = Session::new("noack", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    let r = decided(s.prepare(&fake, 1, NAME, IrreversibleAck::Missing));
    assert_eq!(
        r.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked {
                blocker: Blocker::ReversibilityNone
            }
        }
    );
    assert!(r.outcome.allowed_without_intent());
    assert_eq!(fake.lists.get(), 0);
    assert_eq!(fake.removes(), 0);
    assert!(!s.def_path(1).exists());
}

#[test]
fn an_absent_package_is_vanished() {
    let mut s = Session::new("absent", &[NAME]);
    let fake = Fake::new(vec![info(OTHER_VERSION)]);
    let r = s.run(&fake, 1, NAME);
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    assert_eq!(fake.removes(), 0);
    assert!(!s.def_path(1).exists());
    assert!(
        !s.records()
            .iter()
            .any(|rec| matches!(rec, Record::Intent(_)))
    );
}

#[test]
fn similar_names_are_never_matched() {
    let mut s = Session::new("similar", &[NAME]);
    let fake = Fake::new(vec![
        info(SIMILAR),
        info(OTHER_PUBLISHER),
        info(OTHER_VERSION),
        info("Vendor.Ap_1.0.0.0_x64__abcdefghjkmnp"),
    ]);
    let r = s.run(&fake, 1, NAME);
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    assert_eq!(fake.removes(), 0);
}

#[test]
fn the_full_name_matches_without_regard_to_ascii_case() {
    let mut s = Session::new("case", &[NAME]);
    let fake = Fake::new(vec![info(&NAME.to_ascii_lowercase())]);
    let r = s.run(&fake, 1, NAME);
    assert_eq!(r.outcome, ItemOutcome::Done);
    assert_eq!(
        *fake.removed.borrow(),
        [(NAME.to_owned(), RemovalScope::CurrentUser)]
    );
}

#[test]
fn a_family_that_does_not_fit_the_full_name_is_changed_since_scan() {
    let s = Session::new("family", &[NAME]);
    let mut p = info(NAME);
    p.package.family_name = "Vendor.App_zyxwvtsrqpnmk".into();
    let fake = Fake::new(vec![p]);
    let r = decided(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    assert_eq!(
        r.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }
    );
    assert!(!s.def_path(1).exists());
}

#[test]
fn two_packages_under_one_full_name_are_changed_since_scan() {
    let s = Session::new("twice", &[NAME]);
    let fake = Fake::new(vec![info(NAME), info(&NAME.to_ascii_uppercase())]);
    let r = decided(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    assert_eq!(
        r.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }
    );
}

#[test]
fn an_invalid_full_name_fails_before_any_call() {
    let s = Session::new("badname", &[]);
    let fake = Fake::new(vec![info(NAME)]);
    for bad in [
        "*",
        "Vendor.App_abcdefghjkmnp",
        r"C:\x_1.0.0.0_x64__abcdefghjkmnp",
        "",
    ] {
        let r = decided(s.prepare(&fake, 1, bad, IrreversibleAck::Acknowledged));
        assert!(
            matches!(
                r.outcome,
                ItemOutcome::Failed {
                    code: FailCode::Internal,
                    ..
                }
            ),
            "{bad:?}: {r:?}"
        );
    }
    assert_eq!(fake.lists.get(), 0);
    assert_eq!(fake.removes(), 0);
}

#[test]
fn an_op_that_is_not_typed_is_refused() {
    let s = Session::new("nottyped", &[]);
    let fake = Fake::new(vec![]);
    let op = ExecOp::QuarantineMove {
        path: r"C:\x".into(),
    };
    let r = decided(
        prepare_remove_package(
            &fake,
            &s.session,
            OpId(1),
            &item(1),
            &op,
            IrreversibleAck::Acknowledged,
        )
        .unwrap(),
    );
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(fake.lists.get(), 0);
}

/// A gate context of `s`'s session holding `records` as `GateCtx::record` accepts them.
fn gate_ctx(s: &Session, records: &[(ExecOp, Validated)]) -> GateCtx {
    let scope = s
        .session
        .roots()
        .store_scope::<&std::path::Path>(s.session.id(), &[])
        .unwrap();
    let ops: Vec<ExecOp> = records.iter().map(|(op, _)| op.clone()).collect();
    let deny = purge_guard::deny::DenyList::compile(&purge_guard::canon::GuardEnv::default());
    let mut ctx = GateCtx::new(deny, &ops, scope).unwrap();
    for (op, record) in records {
        ctx.record(op, record, 5_000).unwrap();
    }
    ctx
}

fn package_record(n: u32, name: &str, facts: ItemFacts) -> (ExecOp, Validated) {
    let op = remove_op(name);
    let record = Validated {
        op: OpId(n),
        item: item(n),
        target: op.target(),
        facts,
        exemptions: GateExemptions::default(),
    };
    (op, record)
}

#[test]
fn the_recorded_form_takes_item_and_op_from_the_journalled_record() {
    let mut s = Session::new("recorded", &[NAME, OTHER_VERSION]);
    let file_op = ExecOp::QuarantineMove {
        path: r"C:\Vendor\App\x.dll".into(),
    };
    let file_record = Validated {
        op: OpId(3),
        item: item(3),
        target: file_op.target(),
        facts: ItemFacts::File(purge_model::exec::journal::FileFacts {
            final_path: r"C:\Vendor\App\x.dll".into(),
            file_id: purge_model::exec::op::FileIdHex([7; 16]),
            volume_serial: 0x1234,
            reparse_tag: 0,
            attributes: 0x20,
            n_links: 1,
            is_dir: false,
            size: 1,
            tree_entries: None,
            tree_bytes: None,
        }),
        exemptions: GateExemptions::default(),
    };
    let ctx = gate_ctx(
        &s,
        &[
            package_record(1, NAME, ItemFacts::Package),
            // A package that was absent at validation: `GateCtx::record` keeps nothing for it.
            package_record(2, OTHER_VERSION, ItemFacts::Absent),
            (file_op, file_record),
        ],
    );
    let fake = Fake::new(vec![info(NAME), info(OTHER_VERSION)]);
    let failed_internal = |p: Prepared| {
        let r = decided(p);
        assert!(
            matches!(
                r.outcome,
                ItemOutcome::Failed {
                    code: FailCode::Internal,
                    ..
                }
            ),
            "{r:?}"
        );
    };

    // Op 2 has no record in the context, op 3 one of another kind, op 9 none at all: nothing is
    // looked at.
    for n in [2, 3, 9] {
        failed_internal(
            prepare_remove_package_recorded(
                &fake,
                &ctx,
                &s.session,
                OpId(n),
                IrreversibleAck::Acknowledged,
            )
            .unwrap(),
        );
    }
    assert_eq!(fake.lists.get(), 0);

    // Op 1: the plan item and the op of the record.
    let removal = ready(
        prepare_remove_package_recorded(
            &fake,
            &ctx,
            &s.session,
            OpId(1),
            IrreversibleAck::Acknowledged,
        )
        .unwrap(),
    );
    let intent = removal.intent().clone();
    assert_eq!(
        (intent.op, &intent.item, &intent.exec_op),
        (OpId(1), &item(1), &remove_op(NAME))
    );
    let token = s.journal.intent(intent).unwrap();
    let result = remove_package(&fake, removal, &token);
    s.journal.done(token, result.outcome.clone()).unwrap();
    assert_eq!(result.outcome, ItemOutcome::Done);
    assert_eq!(
        *fake.removed.borrow(),
        [(NAME.to_owned(), RemovalScope::CurrentUser)]
    );
}

#[test]
fn a_failed_listing_fails_the_item_untouched() {
    let mut s = Session::new("listfail", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    fake.fail_list_from.set(Some(1));
    let r = s.run(&fake, 1, NAME);
    assert_eq!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::PackageApi,
            os_error: Some(5),
            detail: r.detail.clone()
        }
    );
    assert_eq!(fake.removes(), 0);
    assert!(!s.def_path(1).exists());
}

#[test]
fn refusals() {
    let s = Session::new("refusals", &[NAME]);
    let mut framework = info(NAME);
    framework.package.is_framework = true;
    let mut resource = info(NAME);
    resource.package.is_resource_package = true;
    let signed = |kind: Option<SignatureKind>| {
        let mut p = info(NAME);
        p.package.signature_kind = kind;
        p
    };
    let cases: Vec<(Vec<PackageInfo>, ItemOutcome)> = vec![
        (vec![framework], denied(RULE_FRAMEWORK)),
        (vec![resource], denied(RULE_RESOURCE)),
        (
            vec![signed(Some(SignatureKind::Store))],
            denied(RULE_STORE_SIGNED),
        ),
        (
            vec![signed(Some(SignatureKind::System))],
            denied(RULE_SYSTEM_SIGNED),
        ),
        (vec![signed(None)], denied(RULE_SIGNATURE_UNKNOWN)),
        (
            vec![signed(Some(SignatureKind::Other(9)))],
            denied(RULE_SIGNATURE_UNKNOWN),
        ),
        (
            vec![info(NAME), {
                let mut p = info(SIMILAR);
                p.dependencies = None;
                p
            }],
            denied(RULE_DEPENDENTS_UNKNOWN),
        ),
        (
            vec![info(NAME), {
                let mut p = info(SIMILAR);
                p.dependencies = Some(vec![NAME.to_ascii_uppercase()]);
                p
            }],
            ItemOutcome::Skipped {
                reason: SkipReason::GateBlocked {
                    blocker: Blocker::ReferencedByOtherApp {
                        app: SIMILAR.to_owned(),
                    },
                },
            },
        ),
    ];
    for (listing, want) in cases {
        let fake = Fake::new(listing.clone());
        let r = decided(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
        assert_eq!(r.outcome, want, "{listing:?}");
        assert!(r.outcome.allowed_without_intent());
        assert!(!r.detail.is_empty());
        assert_eq!(fake.removes(), 0);
        assert!(!s.def_path(1).exists());
    }
}

#[test]
fn unsigned_developer_and_enterprise_packages_pass() {
    for kind in [
        SignatureKind::None,
        SignatureKind::Developer,
        SignatureKind::Enterprise,
    ] {
        let mut p = info(NAME);
        p.package.signature_kind = Some(kind);
        // The package's own dependencies do not matter, only those of the others.
        p.dependencies = None;
        let mut other = info(SIMILAR);
        other.dependencies = Some(vec![OTHER_VERSION.to_owned()]);
        assert_eq!(refusal(&p, &[p.clone(), other]), None, "{kind:?}");
    }
}

// ---------------------------------------------------------------------------------------------------
// Definition, intent, removal, verification
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_removal_writes_a_verified_definition_journals_the_intent_and_ends_done() {
    let mut s = Session::new("done", &[NAME]);
    let mut p = info(NAME);
    p.package.users = vec![purge_win::appx::AppxUser {
        sid: "S-1-5-21-1-2-3-1001".into(),
        install_state: purge_win::appx::AppxInstallState::Installed,
    }];
    let fake = Fake::new(vec![info(SIMILAR), p]);

    let removal = ready(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    assert_eq!(fake.removes(), 0, "prepare never removes");
    assert_eq!(removal.scope(), RemovalScope::CurrentUser);
    let intent = removal.intent().clone();
    assert!(intent.is_consistent());
    assert_eq!(intent.inverse, Inverse::None);
    assert_eq!(intent.pre, ItemFacts::Package);
    assert_eq!(intent.exec_op, remove_op(NAME));

    let def_ref = intent.definition.clone().unwrap();
    assert_eq!(def_ref.path, r"def\000001.json");
    let (sha, bytes) = sha256_reader(&mut s.session.open_file(&def_ref.path).unwrap()).unwrap();
    assert_eq!((sha, bytes), (def_ref.sha256, def_ref.bytes));
    crate::journal::verify_backup(&s.session, &def_ref).unwrap();
    let def: PackageDefinition =
        serde_json::from_slice(&std::fs::read(s.def_path(1)).unwrap()).unwrap();
    assert_eq!(&def, removal.definition());
    assert_eq!(def.schema, DEFINITION_SCHEMA);
    assert_eq!(def.op, OpId(1));
    assert_eq!(def.scope, "CurrentUser");
    assert_eq!(def.full_name, NAME);
    assert_eq!(def.family_name, "Vendor.App_abcdefghjkmnp");
    assert_eq!(
        (
            def.name.as_str(),
            def.version.as_str(),
            def.architecture.as_str(),
            def.resource_id.as_str(),
            def.publisher_id.as_str()
        ),
        ("Vendor.App", "1.0.0.0", "x64", "", "abcdefghjkmnp")
    );
    assert_eq!(def.signature_kind.as_deref(), Some("Developer"));
    assert_eq!(def.users[0].install_state, "Installed");
    assert_eq!(def.dependencies, Some(vec![]));

    let token = s.journal.intent(intent).unwrap();
    let r = remove_package(&fake, removal, &token);
    assert_eq!(r.outcome, ItemOutcome::Done);
    s.journal.done(token, r.outcome).unwrap();
    assert_eq!(
        *fake.removed.borrow(),
        [(NAME.to_owned(), RemovalScope::CurrentUser)]
    );
    assert!(
        fake.scopes
            .borrow()
            .iter()
            .all(|s| *s == RemovalScope::CurrentUser),
        "the scope is never widened"
    );
    // Prepare, re-check before the removal, verify after it.
    assert_eq!(fake.lists.get(), 3);
    assert_eq!(fake.packages.borrow().len(), 1, "the similar package stays");

    let records = s.records();
    assert!(matches!(records.last(), Some(Record::Done(d)) if d.outcome == ItemOutcome::Done));
    assert!(matches!(&records[records.len() - 2], Record::Intent(i) if i.definition.is_some()));
}

#[test]
fn reported_removed_but_still_listed_is_verify_failed() {
    // The all-users trap: the deployment service reports success for a package it did not remove.
    let mut s = Session::new("stillthere", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]).with(OnRemove::Keep(RemoveOutcome::Removed));
    let r = s.run(&fake, 1, NAME);
    assert!(
        matches!(
            r.outcome,
            ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            }
        ),
        "{r:?}"
    );
    assert_eq!(fake.removes(), 1);
}

#[test]
fn deployment_results_against_the_listing_after_the_removal() {
    let in_use = RemoveOutcome::InUse(deployment(0x8007_3D02));
    let access = RemoveOutcome::Failed(deployment(0x8007_0005));
    let other = RemoveOutcome::Failed(deployment(0x8007_3CFA));
    let failed = |code: FailCode, os_error: Option<u32>| (code, os_error);
    let still_listed = [
        (RemoveOutcome::NotFound, failed(FailCode::PackageApi, None)),
        (in_use.clone(), failed(FailCode::InUse, Some(0x3D02))),
        (access.clone(), failed(FailCode::AccessDenied, Some(5))),
        (other.clone(), failed(FailCode::PackageApi, Some(0x3CFA))),
        (RemoveOutcome::TimedOut, failed(FailCode::PackageApi, None)),
    ];
    for (outcome, (code, os_error)) in still_listed {
        let mut s = Session::new("kept", &[NAME]);
        let fake = Fake::new(vec![info(NAME)]).with(OnRemove::Keep(outcome.clone()));
        let r = s.run(&fake, 1, NAME);
        match &r.outcome {
            ItemOutcome::Failed {
                code: c,
                os_error: e,
                detail,
            } => {
                assert_eq!((*c, *e), (code, os_error), "{outcome:?}");
                assert!(detail.contains(NAME), "{detail}");
            }
            o => panic!("{outcome:?}: {o:?}"),
        }
    }
    let gone = [
        (RemoveOutcome::NotFound, ItemOutcome::Vanished),
        (in_use, ItemOutcome::Done),
        (access, ItemOutcome::Done),
        (other, ItemOutcome::Done),
        (RemoveOutcome::TimedOut, ItemOutcome::Done),
    ];
    for (outcome, want) in gone {
        let mut s = Session::new("gone", &[NAME]);
        let fake = Fake::new(vec![info(NAME)]).with(OnRemove::Unregister(outcome.clone()));
        let r = s.run(&fake, 1, NAME);
        assert_eq!(r.outcome, want, "{outcome:?}");
        assert!(!r.detail.is_empty(), "{outcome:?}");
    }
}

#[test]
fn a_failed_listing_after_the_removal_is_verify_failed() {
    let mut s = Session::new("verifyfail", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    fake.fail_list_from.set(Some(3));
    let r = s.run(&fake, 1, NAME);
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        }
    ));
    assert_eq!(fake.removes(), 1);
}

#[test]
fn a_failed_listing_before_the_removal_leaves_the_package() {
    let mut s = Session::new("recheckfail", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    fake.fail_list_from.set(Some(2));
    let r = s.run(&fake, 1, NAME);
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::PackageApi,
            ..
        }
    ));
    assert_eq!(fake.removes(), 0);
}

#[test]
fn a_package_that_changed_after_the_definition_is_not_removed() {
    type Change = fn(&mut PackageInfo);
    let changes: [(&str, Change); 4] = [
        ("location", |p| {
            p.package.installed_location = Some(r"C:\Elsewhere".into())
        }),
        ("signature", |p| {
            p.package.signature_kind = Some(SignatureKind::Enterprise)
        }),
        ("dependencies", |p| {
            p.dependencies = Some(vec![OTHER_VERSION.into()])
        }),
        ("framework", |p| p.package.is_framework = true),
    ];
    for (what, change) in changes {
        let mut s = Session::new("changed", &[NAME]);
        let fake = Fake::new(vec![info(NAME)]);
        let removal = ready(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
        change(&mut fake.packages.borrow_mut()[0]);
        let token = s.journal.intent(removal.intent().clone()).unwrap();
        let r = remove_package(&fake, removal, &token);
        assert_eq!(
            r.outcome,
            ItemOutcome::Skipped {
                reason: SkipReason::ChangedSinceScan
            },
            "{what}"
        );
        s.journal.done(token, r.outcome).unwrap();
        assert_eq!(fake.removes(), 0, "{what}");
    }
}

#[test]
fn a_new_dependent_after_the_definition_blocks_the_removal() {
    let mut s = Session::new("newdep", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    let removal = ready(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    let mut dependent = info(SIMILAR);
    dependent.dependencies = Some(vec![NAME.into()]);
    fake.packages.borrow_mut().push(dependent);
    let token = s.journal.intent(removal.intent().clone()).unwrap();
    let r = remove_package(&fake, removal, &token);
    assert_eq!(
        r.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked {
                blocker: Blocker::ReferencedByOtherApp {
                    app: SIMILAR.into()
                }
            }
        }
    );
    s.journal.done(token, r.outcome).unwrap();
    assert_eq!(fake.removes(), 0);
}

#[test]
fn a_package_unregistered_after_the_definition_is_vanished() {
    let mut s = Session::new("lateabsent", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    let removal = ready(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    fake.packages.borrow_mut().clear();
    let token = s.journal.intent(removal.intent().clone()).unwrap();
    let r = remove_package(&fake, removal, &token);
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    s.journal.done(token, r.outcome).unwrap();
    assert_eq!(fake.removes(), 0);
}

#[test]
fn the_token_of_another_op_removes_nothing() {
    let mut s = Session::new("token", &[NAME, SIMILAR]);
    let fake = Fake::new(vec![info(NAME), info(SIMILAR)]);
    let first = ready(s.prepare(&fake, 1, NAME, IrreversibleAck::Acknowledged));
    let second = ready(s.prepare(&fake, 2, SIMILAR, IrreversibleAck::Acknowledged));
    let token2 = s.journal.intent(second.intent().clone()).unwrap();
    let lists = fake.lists.get();
    let r = remove_package(&fake, first, &token2);
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(fake.lists.get(), lists);
    assert_eq!(fake.removes(), 0);
    let r = remove_package(&fake, second, &token2);
    assert_eq!(r.outcome, ItemOutcome::Done);
    assert_eq!(
        *fake.removed.borrow(),
        [(SIMILAR.to_owned(), RemovalScope::CurrentUser)]
    );
    s.journal.done(token2, r.outcome).unwrap();
}

#[test]
fn an_existing_definition_file_is_never_replaced() {
    let s = Session::new("defexists", &[NAME]);
    let fake = Fake::new(vec![info(NAME)]);
    let mut file = s.session.create_file(r"def\000001.json").unwrap();
    let path = file.report_path();
    file.write_all(b"not ours").unwrap();
    drop(file);
    let err = prepare_remove_package(
        &fake,
        &s.session,
        OpId(1),
        &item(1),
        &remove_op(NAME),
        IrreversibleAck::Acknowledged,
    )
    .unwrap_err();
    assert!(matches!(err, DefinitionError::Storage(_)), "{err}");
    assert!(!err.is_storage_integrity());
    assert_eq!(
        err.outcome(),
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup
        }
    );
    assert_eq!(std::fs::read(path).unwrap(), b"not ours");
    assert_eq!(fake.removes(), 0);
}

// ---------------------------------------------------------------------------------------------------
// Unsupported targets and undo
// ---------------------------------------------------------------------------------------------------

#[test]
fn services_tasks_and_firewall_rules_are_not_supported() {
    for target in [
        Target::Service {
            name: "VendorSvc".into(),
        },
        Target::Task {
            path: r"\Vendor\Updater".into(),
        },
        Target::FirewallRule {
            id: "{0F1E2D3C-0000-0000-0000-000000000000}".into(),
        },
    ] {
        let r = unsupported_target(&target).unwrap();
        assert_eq!(
            r.outcome,
            ItemOutcome::Skipped {
                reason: SkipReason::GateBlocked {
                    blocker: Blocker::CannotBackUp
                }
            }
        );
        assert!(
            r.detail.contains("not supported in this version"),
            "{}",
            r.detail
        );
        assert!(r.outcome.allowed_without_intent());
    }
    assert_eq!(
        unsupported_target(&Target::AppxPackage {
            full_name: NAME.into()
        }),
        None
    );
    assert_eq!(
        unsupported_target(&Target::Path {
            path: r"C:\x".into()
        }),
        None
    );
}

#[test]
fn undo_of_a_removed_package_is_an_irreversible_record() {
    let mut s = Session::new("undo", &[NAME, SIMILAR]);
    let fake = Fake::new(vec![info(NAME)]);
    assert_eq!(s.run(&fake, 1, NAME).outcome, ItemOutcome::Done);
    assert_eq!(s.run(&fake, 2, SIMILAR).outcome, ItemOutcome::Vanished);

    let op = remove_op(NAME);
    let undo = undo_typed(&op, &Inverse::None, Some(&ItemOutcome::Done)).unwrap();
    let TypedUndo::Conflict { conflict, detail } = undo.clone() else {
        panic!("{undo:?}");
    };
    assert_eq!(conflict, UndoConflict::Irreversible);
    assert!(detail.contains("cannot be"), "{detail}");
    s.journal
        .undo_conflict_without_intent(OpId(1), conflict, detail)
        .unwrap();

    let undo = undo_typed(
        &remove_op(SIMILAR),
        &Inverse::None,
        Some(&ItemOutcome::Vanished),
    );
    assert_eq!(undo, Some(TypedUndo::Done(UndoOutcome::NothingToUndo)));
    s.journal
        .undo_done_without_intent(OpId(2), UndoOutcome::NothingToUndo)
        .unwrap();
    read(&s.session).unwrap();

    // Intent only (the run stopped during the removal) and a removal that could not be verified are
    // treated as removed.
    for done in [
        None,
        Some(ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            os_error: None,
            detail: String::new(),
        }),
    ] {
        assert!(matches!(
            undo_typed(&op, &Inverse::None, done.as_ref()),
            Some(TypedUndo::Conflict {
                conflict: UndoConflict::Irreversible,
                ..
            })
        ));
    }
    for done in [
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan,
        },
        ItemOutcome::Failed {
            code: FailCode::InUse,
            os_error: Some(0x3D02),
            detail: String::new(),
        },
    ] {
        assert_eq!(
            undo_typed(&op, &Inverse::None, Some(&done)),
            Some(TypedUndo::Done(UndoOutcome::NothingToUndo))
        );
    }
    assert_eq!(
        undo_typed(
            &ExecOp::QuarantineMove {
                path: r"C:\x".into()
            },
            &Inverse::None,
            Some(&ItemOutcome::Done)
        ),
        None
    );
}

// ---------------------------------------------------------------------------------------------------
// Real backend
// ---------------------------------------------------------------------------------------------------

/// Enumeration only: the real listing carries dependencies; a framework package of this machine that
/// another package depends on is refused before anything is written (as a framework, and as referenced
/// when the framework rule is set aside), and a package that does not exist is vanished.
/// `prepare_remove_package` never calls `remove`.
#[test]
fn real_backend_refuses_a_framework_and_finds_nothing_for_a_missing_name() {
    let s = Session::new("real", &[]);
    let backend = WinPackages::new();
    let listing = backend.list(RemovalScope::CurrentUser).unwrap();
    assert!(
        listing.iter().all(|p| p.package.dependencies.is_none()),
        "the dependencies live in PackageInfo only"
    );
    assert!(
        listing
            .iter()
            .any(|p| p.dependencies.as_ref().is_some_and(|d| !d.is_empty())),
        "a desktop has packages that depend on a framework"
    );
    let depended_on = |p: &&PackageInfo| {
        listing.iter().any(|o| {
            o.dependencies
                .iter()
                .flatten()
                .any(|d| d.eq_ignore_ascii_case(&p.package.full_name))
        })
    };
    let framework = listing
        .iter()
        .filter(|p| p.package.is_framework)
        .find(depended_on)
        .expect("a desktop has framework packages that other packages depend on");

    // Set the framework rule aside: what depends on the package refuses it.
    let mut not_framework = framework.clone();
    not_framework.package.is_framework = false;
    not_framework.package.signature_kind = Some(SignatureKind::Developer);
    match refusal(&not_framework, &listing) {
        Some((Blocker::ReferencedByOtherApp { app }, why)) => {
            let dependent = listing
                .iter()
                .find(|o| o.package.full_name == app)
                .expect("the dependent is listed");
            assert!(
                dependent
                    .dependencies
                    .iter()
                    .flatten()
                    .any(|d| d.eq_ignore_ascii_case(&framework.package.full_name)),
                "{why}"
            );
        }
        other => panic!(
            "{} has dependents but is not refused as referenced: {other:?}",
            framework.package.full_name
        ),
    }

    let r = decided(s.prepare(
        &backend,
        1,
        &framework.package.full_name,
        IrreversibleAck::Acknowledged,
    ));
    assert_eq!(r.outcome, denied(RULE_FRAMEWORK));
    let r = decided(s.prepare(
        &backend,
        1,
        "Purge.Test.NoSuchPackage_1.0.0.0_x64__0000000000000",
        IrreversibleAck::Acknowledged,
    ));
    assert_eq!(r.outcome, ItemOutcome::Vanished);
    assert!(!s.def_path(1).exists());
}

/// Removes a disposable package installed by the VM rig and named in `PURGE_TEST_APPX_FULL_NAME`, through
/// the whole sequence. The package must be unsigned, developer- or enterprise-signed, not a framework or
/// resource package, nothing may depend on it, and every package's dependencies must be readable.
#[test]
#[ignore = "removes a real package irreversibly; runs only in the VM gate with PURGE_TEST_APPX_FULL_NAME set"]
fn real_backend_removes_a_disposable_package() {
    let full_name = std::env::var("PURGE_TEST_APPX_FULL_NAME")
        .expect("PURGE_TEST_APPX_FULL_NAME names the disposable test package");
    let backend = WinPackages::new();
    let mut s = Session::new("realremove", &[&full_name]);
    let removal = ready(s.prepare(&backend, 1, &full_name, IrreversibleAck::Acknowledged));
    let token = s.journal.intent(removal.intent().clone()).unwrap();
    let r = remove_package(&backend, removal, &token);
    assert_eq!(r.outcome, ItemOutcome::Done, "{}", r.detail);
    s.journal.done(token, r.outcome).unwrap();
    let listing = backend.list(RemovalScope::CurrentUser).unwrap();
    assert!(
        !listing
            .iter()
            .any(|p| p.package.full_name.eq_ignore_ascii_case(&full_name))
    );
}
