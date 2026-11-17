//! M1b executor tests of the engine CLI (M1B-X-INTEG, `rig-exec` builds only).
//!
//! `plan from-targets` -> `exec --fp` -> `undo` with a service, a scheduled task and a firewall rule,
//! through [`run_with_exec`] over the `nsis` fixture machine, a relaxed store below the target's temp
//! directory and in-memory object backends (`act_service::fake::FakeServices`,
//! `act_firewall::fake::FakeFirewall` and the task fake below). No service, task or firewall rule of
//! this machine is read, created, changed or deleted.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use purge_engine::cli::exec::{ExecHost, RIG_OWNER};
use purge_engine::cli::{Env, Exit, run_with_exec};
use purge_engine::pipeline::Settings;
use purge_exec::act_firewall::fake::FakeFirewall;
use purge_exec::act_service::fake::{FakeService, FakeServices, sz};
use purge_exec::act_task::{ObjErr, Register, TaskBackend, TaskLive, TaskXml};
use purge_exec::act_typed::{ListError, PackageBackend, PackageInfo};
use purge_exec::execute::ObjectBackends;
use purge_exec::locked::MemoryPendingRenames;
use purge_exec::objdef::TaskDef;
use purge_exec::plan_in::{confirm_hash, selection_hash};
use purge_exec::prepare::{LockerQuery, RestorePointBackend};
use purge_exec::storage::StorageRoots;
use purge_inventory::runner::RunOptions;
use purge_model::exec::op::ItemOutcome;
use purge_model::exec::session::{ExecReport, SessionState, UndoReport};
use purge_model::object::fold;
use purge_model::{CandidateId, FirewallIdentity, TaskAction, TaskIdentity};
use purge_plan::emit::ScanDoc;
use purge_win::appx_write::{RemovalScope, RemoveOutcome};
use purge_win::os::Win32Error;
use purge_win::reg::REG_SZ;
use purge_win::rm::{LockerList, RebootReasons};
use purge_win::sr::SrOutcome;
use serde_json::{Value, json};

use crate::common::{FakeHost, Switch, arg, machine, scratch};

const ROOT: &str = r"C:\Program Files\Vendor";
const SVC: &str = "VendorUpdate";
const IMAGE: &str = r#""C:\Program Files\Vendor\update.exe" -service"#;
const TASK: &str = r"\Vendor\Update Check";
const EXE: &str = r"C:\Program Files\Vendor\update.exe";
const FW: &str = "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}";
const RULE: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|";

// ---------------------------------------------------------------------------------------------------
// Stand-ins
// ---------------------------------------------------------------------------------------------------

struct NoPackages;

impl PackageBackend for NoPackages {
    fn list(&self, _: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
        Ok(Vec::new())
    }
    fn remove(&self, _: &str, _: RemovalScope) -> RemoveOutcome {
        RemoveOutcome::NotFound
    }
}

struct NoLockers;

impl LockerQuery for NoLockers {
    fn query(&self, _: &[PathBuf]) -> Result<LockerList, Win32Error> {
        Ok(LockerList {
            lockers: Vec::new(),
            reboot_reasons: RebootReasons(0),
        })
    }
}

#[derive(Clone)]
struct FakeRestore;

impl RestorePointBackend for FakeRestore {
    fn create(&self, _: &str) -> SrOutcome {
        SrOutcome::Created { seq: 7 }
    }
}

fn vendor_service() -> FakeService {
    let mut s = FakeService::new(SVC, IMAGE, None);
    s.set_value("Description", REG_SZ, sz("Keeps Vendor up to date"));
    s.scm.config2.description = Some("Keeps Vendor up to date".into());
    s
}

fn vendor_task() -> (TaskLive, TaskXml) {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <Principals>\
         <Principal id=\"Author\"><LogonType>InteractiveToken</LogonType></Principal></Principals>\
         \r\n  <Settings><Enabled>true</Enabled></Settings>\r\n  <Actions Context=\"Author\"><Exec>\
         <Command>{EXE}</Command></Exec></Actions>\r\n</Task>"
    );
    (
        TaskLive {
            identity: TaskIdentity {
                path: TASK.into(),
                actions: vec![TaskAction::Exec {
                    path: EXE.into(),
                    arguments: None,
                    working_dir: None,
                }],
            },
            running: false,
            stored_password: false,
            enabled: true,
            logon_type: 3,
        },
        TaskXml {
            xml,
            sddl: "O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;SY)".into(),
        },
    )
}

/// A Task Scheduler in memory.
#[derive(Default)]
struct FakeTasks {
    tasks: RefCell<BTreeMap<String, (TaskLive, TaskXml)>>,
}

impl FakeTasks {
    fn with_vendor() -> FakeTasks {
        let fake = FakeTasks::default();
        fake.tasks.borrow_mut().insert(fold(TASK), vendor_task());
        fake
    }

    fn get(&self, path: &str) -> Option<(TaskLive, TaskXml)> {
        self.tasks.borrow().get(&fold(path)).cloned()
    }
}

impl TaskBackend for FakeTasks {
    fn read(&self, path: &str) -> Result<Option<TaskLive>, ObjErr> {
        Ok(self.get(path).map(|t| t.0))
    }
    fn definition(&self, path: &str) -> Result<Option<TaskXml>, ObjErr> {
        Ok(self.get(path).map(|t| t.1))
    }
    fn delete(&self, path: &str) -> Result<(), ObjErr> {
        self.tasks.borrow_mut().remove(&fold(path));
        Ok(())
    }
    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), ObjErr> {
        assert_eq!(mode, Register::CreateOnly);
        if self.get(&def.path).is_some() {
            return Err(ObjErr::AlreadyExists);
        }
        let live = TaskLive {
            identity: TaskIdentity {
                path: def.path.clone(),
                actions: def.actions.clone(),
            },
            running: false,
            stored_password: def.stored_password,
            enabled: def.enabled,
            logon_type: def.logon_type,
        };
        let xml = TaskXml {
            xml: def.xml.clone(),
            sddl: def.sddl.clone(),
        };
        self.tasks.borrow_mut().insert(fold(&def.path), (live, xml));
        Ok(())
    }
    fn flush(&self, _: &str) -> Result<(), ObjErr> {
        Ok(())
    }
}

/// The objects of the machine.
struct Objects {
    services: FakeServices,
    tasks: FakeTasks,
    firewall: FakeFirewall,
}

impl Objects {
    fn new() -> Objects {
        Objects {
            services: FakeServices::with([vendor_service()]),
            tasks: FakeTasks::with_vendor(),
            firewall: FakeFirewall::with([(FW, RULE)]),
        }
    }

    fn present(&self) -> [bool; 3] {
        [
            self.services.service(SVC).is_some(),
            self.tasks.get(TASK).is_some(),
            self.firewall.rule(FW).is_some(),
        ]
    }

    fn backends(&self) -> ObjectBackends<'_> {
        ObjectBackends {
            services: &self.services,
            tasks: &self.tasks,
            firewall: &self.firewall,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Driving the CLI
// ---------------------------------------------------------------------------------------------------

struct Ran {
    exit: Exit,
    out: String,
    err: String,
}

struct Rig {
    dir: PathBuf,
    roots: StorageRoots,
    machine: Switch,
}

impl Rig {
    fn new(name: &str) -> Rig {
        let dir = scratch(&format!("m1b-exec-{name}"));
        let roots = StorageRoots::install_relaxed(&dir.join("data")).unwrap();
        Rig {
            dir,
            roots,
            machine: Switch::new(machine("nsis", |_| {})),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn cli(&self, args: &[&str], objects: Option<ObjectBackends<'_>>, elevated: bool) -> Ran {
        let packages = NoPackages;
        let lockers = NoLockers;
        let mut pending = MemoryPendingRenames::with_pairs(&[]);
        let mut host = ExecHost {
            roots: Ok(self.roots.clone()),
            elevated,
            packages: &packages,
            objects,
            lockers: &lockers,
            pending_renames: &mut pending,
            restore_points: FakeRestore,
            now_offset_days: Ok(0),
        };
        let mut process_host = FakeHost::new(&self.machine, Some(0), false);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let exit = run_with_exec(
            &args,
            &mut Env {
                sources: self.machine.sources(),
                host: &mut process_host,
                settings: Settings::default(),
                run_options: RunOptions::default(),
                stdout: &mut out,
                stderr: &mut err,
            },
            &mut host,
        );
        Ran {
            exit,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    /// Plans the three objects with `plan from-targets` and gives each its scan-time digest in the
    /// sidecar (the plan the user sees does not carry it). Returns the plan path and the confirm hash.
    fn plan(&self) -> (PathBuf, String) {
        let targets = json!({
            "schema": "purge.rig.targets/0", "source": "m1b_exec.rs", "origin": "ManualUser",
            "targets": [
                { "id": "svc", "target": { "type": "Service", "name": SVC }, "action": "DeleteKey" },
                { "id": "task", "target": { "type": "Task", "path": TASK }, "action": "DeleteKey" },
                { "id": "fw", "target": { "type": "FirewallRule", "id": FW }, "action": "DeleteKey" },
            ],
        });
        let targets_path = self.path("targets.json");
        std::fs::write(&targets_path, targets.to_string()).unwrap();
        let plan = self.path("plan.json");
        let ran = self.cli(
            &["plan", "from-targets", arg(&targets_path), "-o", arg(&plan)],
            None,
            true,
        );
        assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
        let sidecar = self.path("plan.scan.json");
        let mut scan: ScanDoc = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        for c in &mut scan.items {
            c.object_fp = Some(match c.id.0.as_str() {
                "svc" => vendor_service().identity().fp(),
                "task" => vendor_task().0.identity.fp(),
                _ => FirewallIdentity {
                    id: FW.into(),
                    rule: RULE.into(),
                }
                .fp(),
            });
        }
        std::fs::write(&sidecar, serde_json::to_string_pretty(&scan).unwrap()).unwrap();
        let ids: Vec<CandidateId> = scan.items.iter().map(|c| c.id.clone()).collect();
        let confirm = confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(&ids));
        (plan, confirm.to_string())
    }

    /// The fingerprint of the rig's owner with the vendor's install root and the three objects as the
    /// harvest records them (`sys`), for `exec --fp`.
    fn fingerprint(&self, owner: &str) -> PathBuf {
        self.fingerprint_with(owner, &[ROOT], true)
    }

    /// [`Rig::fingerprint`] with `roots` as its install roots; `sys` false leaves the objects out.
    fn fingerprint_with(&self, owner: &str, roots: &[&str], sys: bool) -> PathBuf {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/purge-model/testdata/m1a-7zip.fp.json");
        let mut fp: Value = serde_json::from_slice(&std::fs::read(base).unwrap()).unwrap();
        fp["app"]["program_id"] = json!(owner);
        fp["roots"] = roots
            .iter()
            .map(|root| {
                json!({
                    "path": root, "kind": "InstallRoot", "source": "ArpInstallLocation",
                    "trust": "AdminOnly", "volume_serial": null, "parent_existed": true
                })
            })
            .collect();
        if sys {
            fp["sys"] = json!({
                "services": [{
                    "identity": vendor_service().identity(),
                    "program": EXE, "why": "program_in_root"
                }],
                "tasks": [{
                    "identity": vendor_task().0.identity,
                    "program": EXE, "why": "program_in_root"
                }],
                "firewall_rules": [{
                    "identity": FirewallIdentity { id: FW.into(), rule: RULE.into() },
                    "program": null, "why": "program_in_root"
                }],
            });
        }
        let path = self.path(&format!(
            "fp-{}.json",
            self.roots.list_sessions().unwrap().sessions.len()
        ));
        std::fs::write(&path, fp.to_string()).unwrap();
        path
    }

    fn exec(&self, objects: &Objects, fp: Option<&Path>, elevated: bool) -> Ran {
        let (plan, confirm) = self.plan();
        let mut args = vec![
            "exec",
            "--plan",
            arg(&plan),
            "--confirm",
            &confirm,
            "--restore-point",
            "off",
        ];
        if let Some(fp) = fp {
            args.extend(["--fp", arg(fp)]);
        }
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.cli(&args, Some(objects.backends()), elevated)
    }
}

// ---------------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------------

#[test]
fn engine_cli_executes_and_undoes_fixture_plan_with_three_typed_items() {
    let rig = Rig::new("round");
    let objects = Objects::new();
    let fp = rig.fingerprint(RIG_OWNER);
    let ran = rig.exec(&objects, Some(&fp), true);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let report: ExecReport = serde_json::from_str(&ran.out).unwrap();
    assert_eq!(report.state, SessionState::Committed);
    assert_eq!(report.items.len(), 3);
    assert!(
        report.items.iter().all(|i| i.outcome == ItemOutcome::Done),
        "{report:?}"
    );
    assert!(
        report.items.iter().all(|i| i.exec_op.is_some()),
        "{report:?}"
    );
    assert_eq!(objects.present(), [false; 3]);
    assert!(ran.err.contains("1 install root(s)"), "{}", ran.err);

    let session = report.session.to_string();
    let ran = rig.cli(
        &["undo", "--session", &session],
        Some(objects.backends()),
        true,
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let undone: UndoReport = serde_json::from_str(&ran.out).unwrap();
    assert_eq!(undone.counts.restored, 3, "{undone:?}");
    assert_eq!(undone.state, SessionState::Undone);
    assert_eq!(objects.present(), [true; 3]);
    assert_eq!(
        objects.services.service(SVC).unwrap().identity().fp(),
        vendor_service().identity().fp()
    );
    assert_eq!(objects.tasks.get(TASK), Some(vendor_task()));
    assert_eq!(objects.firewall.rule(FW).as_deref(), Some(RULE));

    // `journal show` lists each op with the note of the undo that restored it (none here).
    let ran = rig.cli(&["journal", "show", "--session", &session], None, true);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let shown: Value = serde_json::from_str(&ran.out).unwrap();
    for op in shown["ops"].as_array().unwrap() {
        assert_eq!(op.get("undo_note"), Some(&Value::Null), "{op}");
    }
}

/// Review R3b S3: the fingerprint is bound to the selected objects (owner, and each object recorded
/// in `sys` with the plan's digest), and its roots pass the guard's root rule before they are
/// journalled.
#[test]
fn fingerprint_is_bound_to_the_objects_and_its_roots_are_checked() {
    let rig = Rig::new("fpbind");
    let objects = Objects::new();
    let sessions = rig.roots.list_sessions().unwrap().sessions.len();
    // No `sys` records: not the fingerprint the objects were scanned from. Refused before any session.
    let bare = rig.fingerprint_with(RIG_OWNER, &[ROOT], false);
    let ran = rig.exec(&objects, Some(&bare), true);
    assert_eq!(ran.exit, Exit::PlanRefused, "{}", ran.err);
    assert!(ran.err.contains("svc"), "{}", ran.err);
    assert_eq!(rig.roots.list_sessions().unwrap().sessions.len(), sessions);
    assert_eq!(objects.present(), [true; 3]);

    // `C:\Program Files` itself as the root: dropped with a warning; with no root left every object
    // is refused (review R3b S2), nothing is deleted.
    let wide = rig.fingerprint_with(RIG_OWNER, &[r"C:\Program Files"], true);
    let ran = rig.exec(&objects, Some(&wide), true);
    assert_eq!(ran.exit, Exit::Partial, "{}", ran.err);
    let report: ExecReport = serde_json::from_str(&ran.out).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("was not recorded for the run")),
        "{report:?}"
    );
    assert!(
        report.items.iter().all(|i| !i.outcome.is_success()),
        "{report:?}"
    );
    assert_eq!(objects.present(), [true; 3]);
    let session = report.session.to_string();
    let ran = rig.cli(&["journal", "show", "--session", &session], None, true);
    let shown: Value = serde_json::from_str(&ran.out).unwrap();
    // No root recorded: the field is left out, as for a run without object ops.
    assert_eq!(shown["header"].get("program_roots"), None, "{shown}");
}

/// Typed items count in the exit code as every other item: one not carried out is `Partial` (10); an
/// unelevated run, or one without object backends, is `NeedsElevation` (7) before any session; a
/// fingerprint of an app that owns nothing in the plan is `PlanRefused` (6).
#[test]
fn exit_code_precedence_unchanged_with_typed_failures() {
    let rig = Rig::new("exit");
    // Without --fp: no program roots, so every object delete is refused; the run commits.
    let objects = Objects::new();
    let ran = rig.exec(&objects, None, true);
    assert_eq!(ran.exit, Exit::Partial, "{}", ran.err);
    let report: ExecReport = serde_json::from_str(&ran.out).unwrap();
    assert_eq!(report.state, SessionState::Committed);
    assert!(
        report.items.iter().all(|i| !i.outcome.is_success()),
        "{report:?}"
    );
    assert_eq!(objects.present(), [true; 3]);

    // One object changed since the scan: that item is skipped, the others are done.
    let fp = rig.fingerprint(RIG_OWNER);
    objects
        .firewall
        .set_rule(FW, &RULE.replace("Dir=In", "Dir=Out"));
    let ran = rig.exec(&objects, Some(&fp), true);
    assert_eq!(ran.exit, Exit::Partial, "{}", ran.err);
    assert_eq!(objects.present(), [false, false, true]);

    // Refusals before any session.
    let sessions = rig.roots.list_sessions().unwrap().sessions.len();
    let other = rig.fingerprint("HKLM|64|SomeoneElse");
    let ran = rig.exec(&objects, Some(&other), true);
    assert_eq!(ran.exit, Exit::PlanRefused, "{}", ran.err);
    let ran = rig.exec(&objects, Some(&fp), false);
    assert_eq!(ran.exit, Exit::NeedsElevation, "{}", ran.err);
    let (plan, confirm) = rig.plan();
    let ran = rig.cli(
        &[
            "exec",
            "--plan",
            arg(&plan),
            "--confirm",
            &confirm,
            "--restore-point",
            "off",
            "--fp",
            arg(&fp),
        ],
        None,
        true,
    );
    assert_eq!(ran.exit, Exit::NeedsElevation, "{}", ran.err);
    assert_eq!(rig.roots.list_sessions().unwrap().sessions.len(), sessions);
}
