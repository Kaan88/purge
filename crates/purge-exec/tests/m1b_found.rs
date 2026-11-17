//! M1b executor foundation tests (M1B-X-FOUND): definition files (C-DEF), the object stamp and its
//! checks (C-ACT), and the fault points of C-FAULT. Unelevated, on a relaxed store below the temp
//! directory; no service, task or firewall rule is touched. `hive_of_typed_ops` is a unit test in
//! `durable.rs`, where the hive type lives.

#![cfg(feature = "test-support")]

mod common;

use std::io::Write;
use std::path::Path;
use std::process::Command;

use common::{Scratch, ext, safe};
use purge_exec::fault;
use purge_exec::gate::{
    Stamp, check_object_stamp, check_object_stamp_detailed, check_plan_fp, check_plan_fp_detailed,
    reason,
};
use purge_exec::journal::sha256_bytes;
use purge_exec::objdef::{
    DefWriteError, FWDEF_SCHEMA, FwDef, MAX_DEF_BYTES, SVCDEF_SCHEMA, SvcConfig, SvcConfig2,
    SvcDef, SvcFailureAction, SvcFailureActions, SvcTrigger, SvcTriggerData, TASKDEF_SCHEMA,
    TaskDef, account_builtin, read_def, read_def_detailed, write_def,
};
use purge_exec::storage::{
    BackupKind, DEF_DIR, SessionDir, StorageError, StorageRoots, backup_rel,
};
use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{BackupRef, ItemOutcome, OpId, SkipReason};
use purge_model::{
    Action, FirewallIdentity, ObjectFp, ObjectKind, ServiceIdentity, Target, TaskAction,
    TaskIdentity,
};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

struct Store {
    s: Scratch,
    _roots: StorageRoots,
    session: SessionDir,
}

fn store(tag: &str) -> Store {
    let s = Scratch::new(tag);
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
    let session = roots.create_session().unwrap();
    Store {
        s,
        _roots: roots,
        session,
    }
}

fn service_identity() -> ServiceIdentity {
    ServiceIdentity {
        name: "VendorUpdate".into(),
        image_path: Some(r#""%ProgramFiles%\Vendor\update.exe" -service"#.into()),
        service_dll: None,
        service_type: 0x10,
        start: 2,
        object_name: Some("LocalSystem".into()),
    }
}

fn svcdef(op: OpId) -> SvcDef {
    SvcDef {
        schema: SVCDEF_SCHEMA.into(),
        name: "VendorUpdate".into(),
        identity_sha256: service_identity().fp().sha256,
        config: SvcConfig {
            service_type: 0x10,
            start_type: 2,
            error_control: 1,
            binary_path: r#""C:\Program Files\Vendor\update.exe" -service"#.into(),
            load_order_group: None,
            tag_id: 0,
            dependencies: vec!["RpcSs".into(), "+NetworkProvider".into()],
            service_start_name: Some("LocalSystem".into()),
            display_name: Some("Vendor Update Service".into()),
        },
        config2: SvcConfig2 {
            description: Some("Keeps Vendor up to date. \u{e9}\u{4e2d}".into()),
            delayed_auto_start: Some(true),
            failure_actions: Some(SvcFailureActions {
                reset_period: 86_400,
                reboot_msg: None,
                command: Some(String::new()),
                actions: vec![
                    SvcFailureAction {
                        action_type: 1,
                        delay_ms: 60_000,
                    },
                    SvcFailureAction {
                        action_type: 0,
                        delay_ms: 0,
                    },
                ],
            }),
            failure_actions_flag: None,
            service_sid_type: Some(1),
            required_privileges: Some(vec!["SeChangeNotifyPrivilege".into()]),
            preshutdown_timeout_ms: None,
            triggers: Some(vec![SvcTrigger {
                trigger_type: 3,
                action: 1,
                subtype: "{4D1E55B2-F16F-11CF-88CB-001111000030}".into(),
                data: vec![SvcTriggerData {
                    data_type: 2,
                    base64: "VQBTAEIAAAA=".into(),
                }],
            }]),
            launch_protected: None,
        },
        sddl: "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)".into(),
        key_backup: BackupRef {
            path: backup_rel(BackupKind::Registry, op),
            sha256: sha256_bytes(b"the key backup"),
            bytes: 14,
        },
        account_builtin: true,
    }
}

fn task_identity() -> TaskIdentity {
    TaskIdentity {
        path: r"\Vendor\Update Check".into(),
        actions: vec![
            TaskAction::Exec {
                path: r"C:\Program Files\Vendor\update.exe".into(),
                arguments: Some("/check".into()),
                working_dir: None,
            },
            TaskAction::ComHandler {
                clsid: "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}".into(),
                data: None,
            },
        ],
    }
}

fn taskdef() -> TaskDef {
    let identity = task_identity();
    TaskDef {
        schema: TASKDEF_SCHEMA.into(),
        path: identity.path.clone(),
        identity_sha256: identity.fp().sha256,
        actions: identity.actions,
        xml: "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" \
              xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <Actions \
              Context=\"Author\"/>\r\n</Task>"
            .into(),
        sddl: "D:(A;;FA;;;BA)(A;;FA;;;SY)".into(),
        enabled: true,
        logon_type: 5,
        stored_password: false,
    }
}

const RULE: &str = r"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort2_10=5000-5010|App=C:\Program Files\Vendor\server.exe|Name=Vendor Server|";

fn fw_identity() -> FirewallIdentity {
    FirewallIdentity {
        id: "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}".into(),
        rule: RULE.into(),
    }
}

fn fwdef() -> FwDef {
    let identity = fw_identity();
    FwDef {
        schema: FWDEF_SCHEMA.into(),
        id: identity.id.clone(),
        identity_sha256: identity.fp().sha256,
        rule: identity.rule,
        fields: purge_model::parse_firewall_rule(RULE).unwrap().fields,
    }
}

/// Creates the session file `rel` through the store with exactly `bytes`, and returns a reference that
/// matches it: a file the journal could have named.
fn plant(session: &SessionDir, rel: &str, bytes: &[u8]) -> BackupRef {
    let mut file = session.create_file(rel).unwrap();
    file.write_all(bytes).unwrap();
    file.sync().unwrap();
    drop(file);
    BackupRef {
        path: rel.to_owned(),
        sha256: sha256_bytes(bytes),
        bytes: bytes.len() as u64,
    }
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J {}", link.display());
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------------------
// C-DEF: round trips
// ---------------------------------------------------------------------------------------------------

/// The file is the op's `def\<op>.json`, its reference holds the size and SHA-256 of the bytes on disk,
/// and it reads back as the same document.
fn assert_round_trip<T>(st: &Store, op: OpId, def: &T)
where
    T: purge_exec::objdef::ObjectDef,
{
    let reference = write_def(&st.session, op, def).unwrap();
    assert_eq!(reference.path, backup_rel(BackupKind::Definition, op));
    assert!(reference.path.starts_with(&format!(r"{DEF_DIR}\")));
    let on_disk = std::fs::read(ext(&st
        .session
        .path()
        .join(&reference.path)
        .display()
        .to_string()))
    .unwrap();
    assert_eq!(reference.bytes, on_disk.len() as u64);
    assert_eq!(reference.sha256, sha256_bytes(&on_disk));
    let back: T = read_def(&st.session, &reference).unwrap();
    assert_eq!(&back, def);
    // A second write of the same definition (a resumed run before the intent) adopts the file.
    assert_eq!(write_def(&st.session, op, def).unwrap(), reference);
}

#[test]
fn svcdef_round_trip() {
    let st = store("svcdef");
    let def = svcdef(OpId(4));
    assert_round_trip(&st, OpId(4), &def);
    // The wire form is the one C-DEF spells.
    let reference = write_def(&st.session, OpId(4), &def).unwrap();
    let text = std::fs::read_to_string(st.session.path().join(&reference.path)).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["schema"], "purge.svcdef/1");
    assert_eq!(doc["config"]["start_type"], 2);
    assert_eq!(doc["config2"]["failure_actions"]["actions"][0]["type"], 1);
    assert_eq!(
        doc["config2"]["triggers"][0]["data"][0]["base64"],
        "VQBTAEIAAAA="
    );
    assert!(doc["config2"]["launch_protected"].is_null());
    assert_eq!(doc["key_backup"]["path"], r"reg\000004.regbackup.json");
    assert_eq!(doc["account_builtin"], true);
    // The key backup is taken only as the op's own registry backup.
    assert_eq!(def.key_backup_for(OpId(4)), Some(&def.key_backup));
    assert_eq!(def.key_backup_for(OpId(5)), None);
}

#[test]
fn taskdef_round_trip() {
    let st = store("taskdef");
    assert_round_trip(&st, OpId(1), &taskdef());
    let doc = serde_json::to_value(taskdef()).unwrap();
    assert_eq!(doc["actions"][0]["kind"], "exec");
    assert_eq!(doc["actions"][1]["kind"], "com_handler");
    assert_eq!(doc["stored_password"], false);
}

#[test]
fn fwdef_round_trip() {
    let st = store("fwdef");
    let def = fwdef();
    assert_round_trip(&st, OpId(12), &def);
    // Fields are pairs, in order.
    let doc = serde_json::to_value(&def).unwrap();
    assert_eq!(doc["fields"][0], serde_json::json!(["Action", "Allow"]));
    assert_eq!(doc["rule"], RULE);
}

#[test]
fn write_def_refuses_a_definition_that_fails_its_checks() {
    let st = store("defcheck");
    let mut def = taskdef();
    def.identity_sha256 = fw_identity().fp().sha256;
    let err = write_def(&st.session, OpId(1), &def).unwrap_err();
    assert!(matches!(err, DefWriteError::Invalid(_)), "{err}");
    assert_eq!(
        err.outcome(),
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup
        }
    );
    let mut def = svcdef(OpId(2));
    def.config.service_start_name = Some(r".\vendoruser".into());
    assert!(write_def(&st.session, OpId(2), &def).is_err());
    def.account_builtin = false;
    write_def(&st.session, OpId(2), &def).unwrap();
}

// ---------------------------------------------------------------------------------------------------
// C-DEF: hostile reads
// ---------------------------------------------------------------------------------------------------

#[test]
fn read_def_tampered_is_backup_tampered() {
    let st = store("deftamper");
    let reference = write_def(&st.session, OpId(3), &fwdef()).unwrap();
    let path = st.session.path().join(&reference.path);

    // One byte changed, same size: the SHA-256 differs.
    let original = std::fs::read(&path).unwrap();
    let mut bytes = original.clone();
    let at = bytes.iter().position(|&b| b == b'5').unwrap();
    bytes[at] = b'6';
    std::fs::write(&path, &bytes).unwrap();
    let err = read_def_detailed::<FwDef>(&st.session, &reference).unwrap_err();
    assert_eq!(err.conflict, UndoConflict::BackupTampered, "{}", err.detail);
    assert_eq!(
        read_def::<FwDef>(&st.session, &reference),
        Err(UndoConflict::BackupTampered)
    );

    // Grown by a byte.
    let mut longer = original.clone();
    longer.push(b' ');
    std::fs::write(&path, &longer).unwrap();
    assert_eq!(
        read_def::<FwDef>(&st.session, &reference),
        Err(UndoConflict::BackupTampered)
    );

    // Put back, it reads again; a reference with another hash does not.
    std::fs::write(&path, &original).unwrap();
    read_def::<FwDef>(&st.session, &reference).unwrap();
    let wrong = BackupRef {
        sha256: sha256_bytes(b"other"),
        ..reference.clone()
    };
    assert_eq!(
        read_def::<FwDef>(&st.session, &wrong),
        Err(UndoConflict::BackupTampered)
    );

    // A reference from anywhere but the session's def directory is refused before anything is
    // opened: the registry backup directory, a path out of the session, a stream.
    for path in [
        r"reg\000003.regbackup.json",
        r"..\index.json",
        r"def\..\journal.jsonl",
        r"def\000003.json:alt",
        "journal.jsonl",
        r"C:\Windows\win.ini",
    ] {
        let elsewhere = BackupRef {
            path: path.into(),
            ..reference.clone()
        };
        assert_eq!(
            read_def::<FwDef>(&st.session, &elsewhere),
            Err(UndoConflict::BackupTampered),
            "{path}"
        );
    }
}

#[test]
fn read_def_missing_is_backup_missing() {
    let st = store("defmissing");
    let reference = BackupRef {
        path: backup_rel(BackupKind::Definition, OpId(9)),
        sha256: sha256_bytes(b"{}"),
        bytes: 2,
    };
    // No def directory yet.
    assert_eq!(
        read_def::<SvcDef>(&st.session, &reference),
        Err(UndoConflict::BackupMissing)
    );
    // The directory exists, the file does not.
    write_def(&st.session, OpId(1), &taskdef()).unwrap();
    let err = read_def_detailed::<SvcDef>(&st.session, &reference).unwrap_err();
    assert_eq!(err.conflict, UndoConflict::BackupMissing, "{}", err.detail);
}

#[test]
fn read_def_wrong_schema_refused() {
    let st = store("defschema");
    // A verified task definition is not a service or rule definition.
    let task = write_def(&st.session, OpId(1), &taskdef()).unwrap();
    assert_eq!(
        read_def::<SvcDef>(&st.session, &task),
        Err(UndoConflict::BackupTampered)
    );
    assert_eq!(
        read_def::<FwDef>(&st.session, &task),
        Err(UndoConflict::BackupTampered)
    );

    // A file the journal names exactly (size and SHA-256 match) whose schema is another version, or
    // missing, or whose document has a member C-DEF does not list.
    let mut doc = serde_json::to_value(fwdef()).unwrap();
    doc["schema"] = "purge.fwdef/2".into();
    let v2 = plant(
        &st.session,
        &backup_rel(BackupKind::Definition, OpId(2)),
        &serde_json::to_vec(&doc).unwrap(),
    );
    let err = read_def_detailed::<FwDef>(&st.session, &v2).unwrap_err();
    assert_eq!(err.conflict, UndoConflict::BackupTampered);
    assert!(err.detail.contains("schema"), "{}", err.detail);

    let mut doc = serde_json::to_value(fwdef()).unwrap();
    doc.as_object_mut().unwrap().remove("schema");
    let none = plant(
        &st.session,
        &backup_rel(BackupKind::Definition, OpId(3)),
        &serde_json::to_vec(&doc).unwrap(),
    );
    assert_eq!(
        read_def::<FwDef>(&st.session, &none),
        Err(UndoConflict::BackupTampered)
    );

    let mut doc = serde_json::to_value(fwdef()).unwrap();
    doc["profile"] = "Any".into();
    let extra = plant(
        &st.session,
        &backup_rel(BackupKind::Definition, OpId(4)),
        &serde_json::to_vec(&doc).unwrap(),
    );
    assert_eq!(
        read_def::<FwDef>(&st.session, &extra),
        Err(UndoConflict::BackupTampered)
    );

    // The right schema, but a digest that is not the rule's: the definition describes another object.
    let mut doc = serde_json::to_value(fwdef()).unwrap();
    doc["rule"] = "v2.31|Action=Block|Dir=In|Name=Vendor Server|".into();
    let other = plant(
        &st.session,
        &backup_rel(BackupKind::Definition, OpId(5)),
        &serde_json::to_vec(&doc).unwrap(),
    );
    assert_eq!(
        read_def::<FwDef>(&st.session, &other),
        Err(UndoConflict::BackupTampered)
    );
}

/// Hostile: a 5 MiB definition file whose size and SHA-256 the journal names exactly is still refused,
/// without being parsed; so is a reference that names more than the limit.
#[test]
fn read_def_oversized_refused() {
    let st = store("defbig");
    let mut doc = serde_json::to_value(taskdef()).unwrap();
    doc["xml"] = "x".repeat(5 << 20).into();
    let bytes = serde_json::to_vec(&doc).unwrap();
    assert!(bytes.len() as u64 > MAX_DEF_BYTES);
    let reference = plant(
        &st.session,
        &backup_rel(BackupKind::Definition, OpId(1)),
        &bytes,
    );
    let err = read_def_detailed::<TaskDef>(&st.session, &reference).unwrap_err();
    assert_eq!(err.conflict, UndoConflict::BackupTampered, "{}", err.detail);

    // The journal names a small file, but the file on disk is the large one.
    let small = BackupRef {
        bytes: 100,
        ..reference.clone()
    };
    assert_eq!(
        read_def::<TaskDef>(&st.session, &small),
        Err(UndoConflict::BackupTampered)
    );

    // Writing one that large is refused before anything is created.
    let mut def = taskdef();
    def.xml = "x".repeat(5 << 20);
    let err = write_def(&st.session, OpId(2), &def).unwrap_err();
    assert!(matches!(err, DefWriteError::Invalid(_)), "{err}");
    assert!(
        !st.session
            .path()
            .join(backup_rel(BackupKind::Definition, OpId(2)))
            .exists()
    );
}

/// Hostile: the session's `def` directory is a junction to somewhere else, planted before the first
/// definition and again after one was written. The store refuses (an integrity failure, renamed aside
/// as for registry backups) and nothing is written through the junction.
#[test]
fn write_def_goes_through_store_checks() {
    let st = store("defjunction");
    let canary = st.s.dir("elsewhere");
    std::fs::write(ext(&format!(r"{canary}\canary.txt")), b"canary").unwrap();
    let canary = Path::new(&canary).to_path_buf();
    let def_dir = st.session.path().join(DEF_DIR);

    junction(&def_dir, &canary);
    let err = write_def(&st.session, OpId(1), &taskdef()).unwrap_err();
    assert!(err.is_storage_integrity(), "{err}");
    assert_eq!(
        err.outcome(),
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup
        }
    );
    assert_eq!(listing(&canary), ["canary.txt"]);
    assert!(!def_dir.exists(), "the junction was renamed aside");

    // Written once for real, then the directory is swapped for a junction.
    let reference = write_def(&st.session, OpId(1), &taskdef()).unwrap();
    std::fs::rename(&def_dir, st.session.path().join("def-moved")).unwrap();
    junction(&def_dir, &canary);
    let err = write_def(&st.session, OpId(2), &fwdef()).unwrap_err();
    assert!(
        matches!(err, DefWriteError::Storage(StorageError::Integrity { .. })),
        "{err}"
    );
    assert_eq!(listing(&canary), ["canary.txt"]);

    // Reading through a planted junction is refused too: the file behind it is never parsed.
    std::fs::copy(
        st.session.path().join("def-moved").join("000001.json"),
        canary.join("000001.json"),
    )
    .unwrap();
    junction(&def_dir, &canary);
    assert_eq!(
        read_def::<TaskDef>(&st.session, &reference),
        Err(UndoConflict::BackupTampered)
    );
}

// ---------------------------------------------------------------------------------------------------
// C-ACT: the object stamp and the plan fingerprint
// ---------------------------------------------------------------------------------------------------

fn object_stamp(fp: &ObjectFp) -> Stamp {
    Stamp::Object {
        kind: fp.kind,
        sha256: fp.sha256.clone(),
    }
}

#[test]
fn check_object_stamp_equal_ok() {
    for fp in [
        service_identity().fp(),
        task_identity().fp(),
        fw_identity().fp(),
    ] {
        assert_eq!(check_object_stamp(&object_stamp(&fp), Some(&fp)), Ok(()));
    }
}

#[test]
fn check_object_stamp_kind_mismatch_changed() {
    let fp = service_identity().fp();
    let other_kind = ObjectFp {
        kind: ObjectKind::Task,
        sha256: fp.sha256.clone(),
    };
    assert_eq!(
        check_object_stamp_detailed(&object_stamp(&fp), Some(&other_kind)),
        Err((SkipReason::ChangedSinceScan, reason::OBJECT_KIND))
    );
    // Not an object stamp at all, or the object is gone: refused as well (the caller's `Vanished`
    // comes before this check).
    assert_eq!(
        check_object_stamp(&Stamp::Package, Some(&fp)),
        Err(SkipReason::ChangedSinceScan)
    );
    assert_eq!(
        check_object_stamp(&object_stamp(&fp), None),
        Err(SkipReason::ChangedSinceScan)
    );
}

#[test]
fn check_object_stamp_digest_mismatch_changed() {
    let validated = service_identity().fp();
    let mut moved = service_identity();
    moved.image_path = Some(r#""%ProgramFiles%\Other\update.exe" -service"#.into());
    let live = moved.fp();
    assert_eq!(
        check_object_stamp_detailed(&object_stamp(&validated), Some(&live)),
        Err((SkipReason::ChangedSinceScan, reason::OBJECT_CHANGED))
    );
    // The same digest in upper case is not the digest; neither is an empty one on both sides.
    let upper = ObjectFp {
        kind: validated.kind,
        sha256: validated.sha256.to_uppercase(),
    };
    assert_eq!(
        check_object_stamp(&object_stamp(&upper), Some(&upper)),
        Err(SkipReason::ChangedSinceScan)
    );
    let empty = ObjectFp {
        kind: validated.kind,
        sha256: String::new(),
    };
    assert_eq!(
        check_object_stamp(&object_stamp(&empty), Some(&empty)),
        Err(SkipReason::ChangedSinceScan)
    );
}

#[test]
fn check_plan_fp_missing_fp_refused() {
    let live = service_identity().fp();
    let mut cand = safe(
        "c-svc",
        Target::Service {
            name: "VendorUpdate".into(),
        },
        Action::DeleteKey,
    );
    assert_eq!(cand.object_fp, None);
    assert_eq!(
        check_plan_fp_detailed(&cand, &live),
        Err((SkipReason::ChangedSinceScan, reason::NO_OBJECT_FP))
    );
    assert_eq!(reason::NO_OBJECT_FP, "no object fingerprint");
    assert_eq!(
        check_plan_fp(&cand, &live),
        Err(SkipReason::ChangedSinceScan)
    );

    // With the scan's fingerprint it passes; another digest, another kind or a malformed one does not.
    cand.object_fp = Some(live.clone());
    assert_eq!(check_plan_fp(&cand, &live), Ok(()));
    let mut changed = service_identity();
    changed.start = 3;
    assert_eq!(
        check_plan_fp_detailed(&cand, &changed.fp()),
        Err((SkipReason::ChangedSinceScan, reason::OBJECT_CHANGED))
    );
    cand.object_fp = Some(ObjectFp {
        kind: ObjectKind::Task,
        sha256: live.sha256.clone(),
    });
    assert_eq!(
        check_plan_fp(&cand, &live),
        Err(SkipReason::ChangedSinceScan)
    );
    cand.object_fp = Some(ObjectFp {
        kind: ObjectKind::Service,
        sha256: live.sha256.to_uppercase(),
    });
    assert_eq!(
        check_plan_fp_detailed(&cand, &live),
        Err((SkipReason::ChangedSinceScan, reason::NO_OBJECT_FP))
    );
    // A fingerprint of the right kind on a target of another kind.
    let mut task = safe(
        "c-task",
        Target::Task {
            path: r"\Vendor\Update Check".into(),
        },
        Action::DeleteKey,
    );
    task.object_fp = Some(live.clone());
    assert_eq!(
        check_plan_fp(&task, &live),
        Err(SkipReason::ChangedSinceScan)
    );
}

// ---------------------------------------------------------------------------------------------------
// C-FAULT, C-DEF account rule
// ---------------------------------------------------------------------------------------------------

#[test]
fn fault_points_declared_and_unique() {
    for name in ["svcrestore.mid", "fwrestore.mid", "objdelete.after"] {
        assert!(fault::is_point(name), "{name}");
        assert!(fault::describe(name).is_some(), "{name}");
    }
    assert_eq!(fault::SVCRESTORE_MID, "svcrestore.mid");
    assert_eq!(fault::FWRESTORE_MID, "fwrestore.mid");
    assert_eq!(fault::OBJDELETE_AFTER, "objdelete.after");
    // The M2 points apply to typed items unchanged and are all still there.
    for name in [
        "journal.header",
        "backup.written",
        "backup.verified",
        "intent.flushed",
        "act.before",
        "act.after",
        "done.before",
        "group.end",
        "commit.before",
        "undo.intent",
        "undo.act.after",
    ] {
        assert!(fault::is_point(name), "{name}");
    }
    for (i, name) in fault::FAULT_POINTS.iter().enumerate() {
        assert!(!fault::FAULT_POINTS[..i].contains(name), "duplicate {name}");
    }
    assert_eq!(fault::FAULT_POINTS.len(), 19);
}

#[test]
fn account_builtin_table() {
    let table: &[(Option<&str>, bool)] = &[
        (None, true),
        (Some("LocalSystem"), true),
        (Some("localsystem"), true),
        (Some(r"NT AUTHORITY\LocalService"), true),
        (Some(r"nt authority\localservice"), true),
        (Some(r"NT AUTHORITY\NetworkService"), true),
        (Some(r"NT AUTHORITY\NETWORKSERVICE"), true),
        (Some(r"NT SERVICE\VendorUpdate"), true),
        (Some(r"nt service\TrustedInstaller"), true),
        (Some(r".\vendoruser"), false),
        (Some(r"CORP\svc-vendor"), false),
        (Some("vendor@corp.example"), false),
        (Some("LocalSystem2"), false),
        (Some(r"NT SERVICE"), false),
    ];
    for (account, builtin) in table {
        assert_eq!(account_builtin(*account), *builtin, "{account:?}");
        // The definition carries the same answer, and a definition that says otherwise is refused.
        let mut def = svcdef(OpId(1));
        def.config.service_start_name = account.map(str::to_owned);
        def.account_builtin = *builtin;
        assert_eq!(
            purge_exec::objdef::ObjectDef::check(&def),
            Ok(()),
            "{account:?}"
        );
        def.account_builtin = !*builtin;
        assert!(
            purge_exec::objdef::ObjectDef::check(&def).is_err(),
            "{account:?}"
        );
    }
}
