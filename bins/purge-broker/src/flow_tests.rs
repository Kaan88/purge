//! Library tests of the request flow (`uninstall.*`, `leftovers.*`, `plan.create`) over the in-memory
//! transport and a fixture machine (package M3-BROKER-FLOW).
//!
//! The fixture is a small machine with one broker-route app (under `Program Files`), one medium-route
//! app (under the user's `AppData`) and leftover data. The scripted uninstaller never starts a process:
//! everything that needs an elevated broker or a VM is listed in the package notes, not faked here.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use purge_engine::pipeline::{self, Settings};
use purge_inventory::runner::{RanAs, Routing, RunReport, WaitEnd};
use purge_inventory::verify_gone::{MsiCheck, VerifyGoneCheck};
use purge_model::exec::op::resolve;
use purge_model::{
    Action, Band, Candidate, CandidateId, FileTime, Fingerprint, ProgramId, RunDoc, RunOutcome,
    RunSchema, ScanMode, VerifyGone, View,
};
use purge_rpc::BaselineBuild;
use purge_rpc::error::{ErrorData, ErrorObject, Refusal};
use purge_rpc::methods::{CandidateRef, PipeCall, PlanId, UninstallSessionId};
use purge_source::fixture::Fixture;
use purge_source::types::{ExistsState, RegData};
use serde_json::{Value, json};

use crate::baseline::BuildHandle;
use crate::lifetime::Exit;
use crate::serve::{Ctx, Handler, Wiring};
use crate::testkit::{
    FakeBuild, FakeClock, FakeHost, FakeParent, HELLO, ME, SECS, ScriptedConsent, expected, kind,
    request, test_limits,
};
use crate::uninstall::{Flow, Machine, RunRequest};

// ---------------------------------------------------------------------------------------------------
// The fixture machine
// ---------------------------------------------------------------------------------------------------

const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const BROKER_KEY: &str = "Purge Test App_is1";
const BROKER_NAME: &str = "Purge Test App";
const BROKER_DIR: &str = r"C:\Program Files\Purge Test App";
const MEDIUM_KEY: &str = "Purge Medium App_is1";
const MEDIUM_NAME: &str = "Purge Medium App";
const MEDIUM_DIR: &str = r"C:\Users\tester\AppData\Local\Purge Medium App";
const DATA_DIR: &str = r"C:\Users\tester\AppData\Local\Purge Test App";

/// A machine with the two apps and the broker app's leftover data.
fn app_fixture() -> Fixture {
    let mut fx = Fixture::builder()
        .os("Professional", 26340, 9882)
        .user_sid(ME)
        .elevated(true)
        .admin_only_roots(&[
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\Windows",
        ])
        .build();
    {
        let facts = fx.system_mut();
        for (name, value) in [
            ("USERNAME", "tester"),
            ("SYSTEMDRIVE", "C:"),
            ("WINDIR", r"C:\Windows"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("PROGRAMFILES", r"C:\Program Files"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("PUBLIC", r"C:\Users\Public"),
            ("APPDATA", r"C:\Users\tester\AppData\Roaming"),
            ("LOCALAPPDATA", r"C:\Users\tester\AppData\Local"),
        ] {
            facts.env.entry(name.to_owned()).or_insert(value.to_owned());
        }
        if facts.profiles.as_ref().is_none_or(Vec::is_empty) {
            facts.profiles = Some(vec![purge_source::types::ProfileInfo {
                sid: ME.to_owned(),
                path: r"C:\Users\tester".to_owned(),
            }]);
        }
    }

    let broker = format!(r"{UNINSTALL}\{BROKER_KEY}");
    fx.set_value(&broker, "DisplayName", RegData::from_sz(BROKER_NAME));
    fx.set_value(&broker, "Publisher", RegData::from_sz("Purge Tests"));
    fx.set_value(&broker, "InstallLocation", RegData::from_sz(BROKER_DIR));
    fx.set_value(
        &broker,
        "DisplayIcon",
        RegData::from_sz(&format!(r"{BROKER_DIR}\app.exe")),
    );
    fx.set_value(
        &broker,
        "UninstallString",
        RegData::from_sz(&format!(r#""{BROKER_DIR}\unins000.exe""#)),
    );
    fx.set_value(
        &broker,
        "QuietUninstallString",
        RegData::from_sz(&format!(r#""{BROKER_DIR}\unins000.exe" /S"#)),
    );
    for (name, size) in [
        ("unins000.exe", 4096u64),
        ("app.exe", 8192),
        ("data.bin", 1024),
    ] {
        fx.add_file(&format!(r"{BROKER_DIR}\{name}"), size);
    }
    fx.add_file(&format!(r"{DATA_DIR}\cache.dat"), 2048);
    fx.set_value(
        &format!(r"HKU\{ME}\Software\PurgeTest"),
        "Cache",
        RegData::from_sz(DATA_DIR),
    );

    let medium = format!(r"{UNINSTALL}\{MEDIUM_KEY}");
    fx.set_value(&medium, "DisplayName", RegData::from_sz(MEDIUM_NAME));
    fx.set_value(&medium, "InstallLocation", RegData::from_sz(MEDIUM_DIR));
    fx.set_value(
        &medium,
        "UninstallString",
        RegData::from_sz(&format!(r#""{MEDIUM_DIR}\unins000.exe""#)),
    );
    fx.add_file(&format!(r"{MEDIUM_DIR}\unins000.exe"), 4096);
    fx.add_file(&format!(r"{MEDIUM_DIR}\app.exe"), 8192);
    fx
}

fn broker_id() -> ProgramId {
    ProgramId::machine(View::K64, BROKER_KEY).expect("program id")
}

fn medium_id() -> ProgramId {
    ProgramId::machine(View::K64, MEDIUM_KEY).expect("program id")
}

/// What the scripted uninstaller reports.
#[derive(Clone, Copy)]
struct ScriptedRun {
    outcome: RunOutcome,
    exit_code: Option<u32>,
    verify: VerifyGone,
}

impl Default for ScriptedRun {
    fn default() -> Self {
        ScriptedRun {
            outcome: RunOutcome::Success,
            exit_code: Some(0),
            verify: VerifyGone::new(true, true, true),
        }
    }
}

/// The fixture machine: the engine's sources, a scripted uninstaller and an in-memory fingerprint store.
struct FixtureMachine {
    fixture: Fixture,
    runs: Mutex<Vec<String>>,
    scripted: Mutex<ScriptedRun>,
    verify: Mutex<Option<VerifyGone>>,
    stored: Mutex<BTreeMap<String, Fingerprint>>,
    unstorable: Mutex<Vec<Refusal>>,
    cap: Mutex<Option<ErrorObject>>,
}

impl FixtureMachine {
    fn new(fixture: Fixture) -> Self {
        FixtureMachine {
            fixture,
            runs: Mutex::new(Vec::new()),
            scripted: Mutex::new(ScriptedRun::default()),
            verify: Mutex::new(None),
            stored: Mutex::new(BTreeMap::new()),
            unstorable: Mutex::new(Vec::new()),
            cap: Mutex::new(None),
        }
    }

    fn script(&self, script: ScriptedRun) {
        *self.scripted.lock().unwrap() = script;
    }

    fn scripted_verify(&self, verify: VerifyGone) {
        *self.verify.lock().unwrap() = Some(verify);
    }

    fn runs(&self) -> Vec<String> {
        self.runs.lock().unwrap().clone()
    }

    fn stored(&self, program: &ProgramId) -> Option<Fingerprint> {
        self.stored
            .lock()
            .unwrap()
            .get(&program.to_string())
            .cloned()
    }

    fn refuse_unstorable(&self, refusals: Vec<Refusal>) {
        *self.unstorable.lock().unwrap() = refusals;
    }

    fn cap(&self, error: ErrorObject) {
        *self.cap.lock().unwrap() = Some(error);
    }
}

impl Machine for FixtureMachine {
    fn sources(&self) -> pipeline::Sources<'_> {
        pipeline::Sources::of(&self.fixture)
    }

    fn run_uninstall(
        &self,
        request: RunRequest<'_>,
    ) -> Result<pipeline::Uninstalled, pipeline::PipelineError> {
        self.runs
            .lock()
            .unwrap()
            .push(request.command.to_command_line());
        (request.progress)("uninstall: scripted");
        let script = *self.scripted.lock().unwrap();
        let at = FileTime::from_unix_secs(1_800_000_000);
        request.fingerprint.window.t_start = Some(at);
        request.fingerprint.window.t_end = Some(at);
        request.fingerprint.verify_gone = Some(script.verify);
        let mut fingerprint = request.fingerprint.clone();
        fingerprint.co_removed.clear();
        let report = RunReport {
            doc: RunDoc {
                schema: RunSchema,
                program_id: request.program.clone(),
                cmd: request.command.to_command_line(),
                signer: None,
                t_start: at,
                t_end: at,
                exit_code: script.exit_code,
                outcome: script.outcome,
                verify_gone: script.verify,
                processes: Vec::new(),
                co_removed: Vec::new(),
            },
            command: request.command.clone(),
            routing: Routing {
                ran_as: RanAs::Elevated,
                should_run_medium: false,
            },
            wait_end: WaitEnd::Settled,
            verify: VerifyGoneCheck {
                arp: ExistsState::Absent,
                msi: MsiCheck::NoProductCode,
                exes: Vec::new(),
                result: script.verify,
            },
            warnings: Vec::new(),
        };
        Ok(pipeline::Uninstalled {
            report,
            warnings: Vec::new(),
        })
    }

    fn verify_gone(&self, program: &ProgramId, fingerprint: &Fingerprint) -> VerifyGone {
        if let Some(verify) = *self.verify.lock().unwrap() {
            return verify;
        }
        let main_exes: Vec<String> = fingerprint
            .main_exes()
            .map(|exe| exe.path.clone())
            .collect();
        let sources = self.sources();
        purge_inventory::verify_gone::verify_gone(
            sources.reg,
            sources.fs,
            sources.sys,
            &purge_inventory::verify_gone::VerifyTarget {
                arp_key: program.key_path(),
                product_code: None,
                main_exes,
            },
        )
    }

    fn read_fingerprint(&self, program: &ProgramId) -> Result<Option<Fingerprint>, ErrorObject> {
        Ok(self.stored(program))
    }

    fn write_fingerprint(
        &self,
        program: &ProgramId,
        fingerprint: &Fingerprint,
    ) -> Result<(), ErrorObject> {
        self.stored
            .lock()
            .unwrap()
            .insert(program.to_string(), fingerprint.clone());
        Ok(())
    }

    fn unstorable(&self, _: &[&Candidate]) -> Result<Vec<Refusal>, ErrorObject> {
        if let Some(error) = self.cap.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.unstorable.lock().unwrap().clone())
    }
}

// ---------------------------------------------------------------------------------------------------
// The handler and the harness
// ---------------------------------------------------------------------------------------------------

/// The flow, with the plans and scans it created kept for the test.
struct RecordingFlow {
    inner: Flow,
    plans: Arc<Mutex<Vec<Arc<crate::plan::Plan>>>>,
    scans: Arc<Mutex<Vec<Arc<crate::session::ScanSlot<crate::scan::Scan>>>>>,
}

impl Handler for RecordingFlow {
    type Session = crate::uninstall::Session;
    type Scan = crate::scan::Scan;
    type Plan = crate::plan::Plan;

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        match call {
            PipeCall::PlanExecute(params) => {
                // The stand-in for M3-EXEC: take the plan (a plan id works once) and give the scan its
                // next plan.
                if let Ok(plan) = ctx.tables().plans.take(params.plan_id) {
                    plan.release(ctx.tables(), params.plan_id);
                }
                Err(ErrorObject::runtime("plan.execute is M3-EXEC"))
            }
            PipeCall::PlanCreate(params) => {
                let out = self.inner.dispatch(ctx, PipeCall::PlanCreate(params))?;
                let id: PlanId = out["plan_id"].as_str().unwrap_or_default().parse().unwrap();
                if let Ok(plan) = ctx.tables().plans.get(id) {
                    self.plans.lock().unwrap().push(plan);
                }
                Ok(out)
            }
            PipeCall::LeftoversScan(params) => {
                let out = self.inner.dispatch(ctx, PipeCall::LeftoversScan(params))?;
                let id = out["scan_id"].as_str().unwrap_or_default().parse().unwrap();
                if let Ok(scan) = ctx.tables().scans.get(id) {
                    self.scans.lock().unwrap().push(scan);
                }
                Ok(out)
            }
            other => self.inner.dispatch(ctx, other),
        }
    }
}

/// The engine settings of the real broker: the shipped baselines, unread directory rules (a fixture
/// knows nothing of the volume the files are on).
fn shipped_settings() -> Settings {
    Settings {
        baseline_dir: Some(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../kb/baselines")
                .to_path_buf(),
        ),
        ..Settings::default()
    }
}

/// One broker in a thread over the in-memory transport.
struct Broker {
    net: crate::testkit::MemNet,
    build: Arc<FakeBuild>,
    machine: Arc<FixtureMachine>,
    plans: Arc<Mutex<Vec<Arc<crate::plan::Plan>>>>,
    scans: Arc<Mutex<Vec<Arc<crate::session::ScanSlot<crate::scan::Scan>>>>>,
    join: Option<JoinHandle<Exit>>,
}

impl Broker {
    fn start(machine: FixtureMachine) -> Broker {
        Broker::start_all(
            machine,
            BaselineBuild::None {
                reason: "test".into(),
            },
            Settings::default(),
        )
    }

    fn start_with(machine: FixtureMachine, build_state: BaselineBuild) -> Broker {
        Broker::start_all(machine, build_state, Settings::default())
    }

    fn start_with_settings(machine: FixtureMachine, settings: Settings) -> Broker {
        Broker::start_all(
            machine,
            BaselineBuild::None {
                reason: "test".into(),
            },
            settings,
        )
    }

    fn start_all(
        machine: FixtureMachine,
        build_state: BaselineBuild,
        settings: Settings,
    ) -> Broker {
        let net = crate::testkit::MemNet::default();
        let clock = Arc::new(FakeClock::default());
        let parent = Arc::new(FakeParent::default());
        let build = FakeBuild::new(build_state);
        let consent = Arc::new(ScriptedConsent::default());
        let machine = Arc::new(machine);
        let plans = Arc::new(Mutex::new(Vec::new()));
        let scans = Arc::new(Mutex::new(Vec::new()));
        let wiring = Wiring {
            link: net.link(),
            handler: RecordingFlow {
                inner: Flow::new(machine.clone()),
                plans: plans.clone(),
                scans: scans.clone(),
            },
            expected: expected(),
            parent: parent.clone(),
            consent: Arc::new(consent.clone()),
            host: Arc::new(FakeHost),
            clock: clock.clone(),
            build: Some(build.clone() as Arc<dyn BuildHandle>),
            settings,
            limits: test_limits(),
        };
        let join = std::thread::spawn(move || crate::serve::run(wiring));
        Broker {
            net,
            build,
            machine,
            plans,
            scans,
            join: Some(join),
        }
    }

    fn client(&self) -> crate::testkit::Client {
        let c = self.net.connect(Ok(()));
        c.send_line(HELLO);
        let hello = c.reply();
        assert_eq!(hello["id"], 1, "{hello}");
        c
    }

    fn exit(&mut self, timeout: Duration) -> Exit {
        let join = self.join.take().expect("the broker was running");
        let deadline = std::time::Instant::now() + timeout;
        while !join.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the broker did not end"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        join.join().unwrap()
    }

    fn plan(&self) -> Arc<crate::plan::Plan> {
        self.plans.lock().unwrap().last().cloned().expect("a plan")
    }

    fn scan(&self) -> Arc<crate::session::ScanSlot<crate::scan::Scan>> {
        self.scans.lock().unwrap().last().cloned().expect("a scan")
    }
}

/// How long a heavy request (a harvest or a scan over the shipped baseline) may take in a debug build.
const LONG: Duration = Duration::from_secs(300);

/// Sends one request and answers its response, skipping the progress notifications it sends.
fn ask(c: &crate::testkit::Client, id: u64, method: &str, params: Value) -> Value {
    c.send_line(&request(id, method, &params));
    loop {
        let line = c
            .recv(LONG)
            .unwrap_or_else(|| panic!("no answer to {method}"));
        if line.get("id").and_then(Value::as_u64) == Some(id) {
            return line;
        }
    }
}

fn prepared(c: &crate::testkit::Client, id: u64, programs: &[ProgramId]) -> Value {
    ask(
        c,
        id,
        "uninstall.prepare",
        json!({ "program_ids": programs }),
    )
}

fn scan_session(c: &crate::testkit::Client, id: u64, session: &str, forced: bool) -> Value {
    ask(
        c,
        id,
        "leftovers.scan",
        json!({ "session_id": session, "forced": forced }),
    )
}

fn create_selected(c: &crate::testkit::Client, id: u64, scan: &str, selected: &[&str]) -> Value {
    ask(
        c,
        id,
        "plan.create",
        json!({ "scan_id": scan, "selected": selected }),
    )
}

fn created_id(reply: &Value) -> String {
    reply["result"]["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no plan id in {reply}"))
        .to_owned()
}

fn candidate_id(reply: &Value, index: usize) -> String {
    reply["result"]["items"][index]["candidate_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no candidate at {index} in {reply}"))
        .to_owned()
}

fn refusal_ids(reply: &Value) -> Vec<String> {
    reply["error"]["data"]["refusals"]
        .as_array()
        .unwrap_or_else(|| panic!("no refusals in {reply}"))
        .iter()
        .filter_map(|r| r["candidate_id"].as_str().map(str::to_owned))
        .collect()
}

/// The first top-level item a plan can select.
fn first_selectable(scan: &crate::scan::Scan) -> &Candidate {
    scan.doc
        .items
        .iter()
        .find(|candidate| {
            let decided = candidate
                .decision
                .as_ref()
                .is_some_and(|decision| decision.band != Band::Blocked);
            decided
                && candidate.action != Action::ReportOnly
                && resolve(
                    &candidate.target,
                    candidate.action,
                    candidate.object_fp.as_ref(),
                )
                .is_ok()
        })
        .expect("the scan has a selectable item")
}

// ---------------------------------------------------------------------------------------------------
// uninstall.prepare
// ---------------------------------------------------------------------------------------------------

/// Preparing a program that is not in the broker's inventory is `gone`, and no session is opened.
#[test]
fn prepare_refuses_a_program_that_is_not_in_the_inventory() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let reply = prepared(
        &c,
        2,
        &[ProgramId::machine(View::K64, "No Such App").unwrap()],
    );
    assert_eq!(kind(&reply), "gone", "{reply}");
    assert_eq!(reply["error"]["data"]["id"], "program", "{reply}");
    c.close();
    b.exit(SECS);
}

/// `prepare` harvests both routes and stores a fingerprint under the program id.
#[test]
fn prepare_answers_both_routes_and_stores_the_fingerprint() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let reply = prepared(&c, 2, &[broker_id(), medium_id()]);
    let programs = reply["result"]["programs"].as_array().unwrap();
    assert_eq!(programs.len(), 2, "{reply}");
    assert_eq!(programs[0]["route"], "broker", "{reply}");
    assert_eq!(
        programs[0]["command"],
        r#""C:\Program Files\Purge Test App\unins000.exe""#
    );
    assert_eq!(
        programs[0]["quiet_command"],
        r#""C:\Program Files\Purge Test App\unins000.exe" /S"#
    );
    assert_eq!(programs[1]["route"], "medium", "{reply}");
    assert!(
        programs[0]["fingerprint_summary"]["roots"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(b.machine.stored(&broker_id()).is_some());
    assert!(b.machine.stored(&medium_id()).is_some());
    let first: UninstallSessionId = programs[0]["session_id"].as_str().unwrap().parse().unwrap();
    let second: UninstallSessionId = programs[1]["session_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(first, second);
    c.close();
    b.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// uninstall.run and uninstall.observed
// ---------------------------------------------------------------------------------------------------

/// A medium-route session is never run by the broker.
#[test]
fn run_refuses_a_medium_route_session() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[medium_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reply = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(kind(&reply), "wrong_route", "{reply}");
    assert_eq!(reply["error"]["data"]["route"], "medium", "{reply}");
    assert!(b.machine.runs().is_empty(), "nothing may run");
    c.close();
    b.exit(SECS);
}

/// The command `prepare` showed is the exact command the broker runs.
#[test]
fn run_runs_the_command_prepare_showed() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let program = &prepare["result"]["programs"][0];
    let session = program["session_id"].as_str().unwrap().to_owned();
    let shown = program["quiet_command"].as_str().unwrap().to_owned();
    let reply = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(reply["result"]["outcome"], "Success", "{reply}");
    assert_eq!(reply["result"]["verify_gone"]["passed"], true, "{reply}");
    assert_eq!(b.machine.runs(), vec![shown]);
    c.close();
    b.exit(SECS);
}

/// A failed uninstaller is `uninstall_failed`, and the next scan is forced with nothing preselected.
#[test]
fn a_failed_uninstaller_offers_a_forced_scan_with_nothing_preselected() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    b.machine.script(ScriptedRun {
        outcome: RunOutcome::Failed,
        exit_code: Some(1603),
        verify: VerifyGone::new(false, true, false),
    });
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reply = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(kind(&reply), "uninstall_failed", "{reply}");
    assert_eq!(reply["error"]["data"]["exit_code"], 1603, "{reply}");
    assert_eq!(reply["error"]["data"]["forced_offered"], true, "{reply}");

    let scan = scan_session(&c, 4, &session, false);
    assert_eq!(scan["result"]["mode"], "forced", "{scan}");
    assert_eq!(scan["result"]["counts"]["preselected"], 0, "{scan}");
    c.close();
    b.exit(SECS);
}

/// A failed uninstaller gives forced mode even when the program did vanish.
#[test]
fn a_failed_uninstaller_is_forced_even_when_the_program_is_gone() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    b.machine.script(ScriptedRun {
        outcome: RunOutcome::Failed,
        exit_code: Some(1),
        verify: VerifyGone::new(true, true, true),
    });
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let run = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(kind(&run), "uninstall_failed", "{run}");
    let scan = scan_session(&c, 4, &session, false);
    assert_eq!(scan["result"]["mode"], "forced", "{scan}");
    assert_eq!(scan["result"]["counts"]["preselected"], 0, "{scan}");
    c.close();
    b.exit(SECS);
}

/// A scan after a successful run is `post`; asking for forced lowers it.
#[test]
fn a_successful_run_scans_post_and_forced_lowers_it() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let run = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(run["result"]["outcome"], "Success", "{run}");

    let post = scan_session(&c, 4, &session, false);
    assert_eq!(post["result"]["mode"], "post", "{post}");
    let forced = scan_session(&c, 5, &session, true);
    assert_eq!(forced["result"]["mode"], "forced", "{forced}");
    assert_eq!(forced["result"]["counts"]["preselected"], 0, "{forced}");
    c.close();
    b.exit(SECS);
}

/// `uninstall.observed` runs the broker's own verify-gone for a medium-route session.
#[test]
fn observed_answers_the_brokers_own_verify_gone() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    b.machine
        .scripted_verify(VerifyGone::new(true, true, false));
    let c = b.client();
    let prepare = prepared(&c, 2, &[medium_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reply = ask(
        &c,
        3,
        "uninstall.observed",
        json!({ "session_id": session }),
    );
    assert_eq!(reply["result"]["verify_gone"]["arp_gone"], true, "{reply}");
    assert_eq!(reply["result"]["verify_gone"]["passed"], false, "{reply}");
    let scan = scan_session(&c, 4, &session, false);
    assert_eq!(scan["result"]["mode"], "forced", "{scan}");
    c.close();
    b.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// leftovers.stored and a scan from a stored fingerprint
// ---------------------------------------------------------------------------------------------------

#[test]
fn stored_lists_only_programs_with_a_fingerprint() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    assert_eq!(prepare["result"]["programs"].as_array().unwrap().len(), 1);
    let reply = ask(
        &c,
        3,
        "leftovers.stored",
        json!({ "program_ids": [broker_id(), medium_id()] }),
    );
    let stored = reply["result"]["stored"].as_array().unwrap();
    assert_eq!(stored.len(), 1, "{reply}");
    assert_eq!(stored[0], broker_id().to_string(), "{reply}");
    c.close();
    b.exit(SECS);
}

#[test]
fn a_stored_fingerprint_is_scanned_in_the_external_mode() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    prepared(&c, 2, &[broker_id()]);
    let reply = ask(
        &c,
        3,
        "leftovers.scan",
        json!({ "program_id": broker_id() }),
    );
    assert_eq!(reply["result"]["mode"], "external", "{reply}");
    assert!(reply["result"]["scan_id"].is_string(), "{reply}");

    // A program with no stored fingerprint is gone, not an empty scan.
    let gone = ask(
        &c,
        4,
        "leftovers.scan",
        json!({ "program_id": medium_id() }),
    );
    assert_eq!(kind(&gone), "gone", "{gone}");
    assert_eq!(gone["error"]["data"]["id"], "program", "{gone}");
    c.close();
    b.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// scan.candidates and candidate.explain
// ---------------------------------------------------------------------------------------------------

#[test]
fn candidates_come_in_pages_and_a_gone_scan_is_gone() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();

    let first = ask(
        &c,
        4,
        "scan.candidates",
        json!({ "scan_id": scan_id, "offset": 0, "limit": 1 }),
    );
    let total = first["result"]["total"].as_u64().unwrap();
    assert!(total >= 1, "{first}");
    assert_eq!(
        first["result"]["items"].as_array().unwrap().len(),
        1,
        "{first}"
    );
    if total >= 2 {
        let second = ask(
            &c,
            5,
            "scan.candidates",
            json!({ "scan_id": scan_id, "offset": 1, "limit": 1 }),
        );
        assert_eq!(second["result"]["offset"], 1, "{second}");
        assert_ne!(
            first["result"]["items"][0]["candidate_id"],
            second["result"]["items"][0]["candidate_id"]
        );
    }
    let past = ask(
        &c,
        6,
        "scan.candidates",
        json!({ "scan_id": scan_id, "offset": 100000, "limit": 500 }),
    );
    assert_eq!(
        past["result"]["items"].as_array().unwrap().len(),
        0,
        "{past}"
    );

    let gone = ask(
        &c,
        7,
        "scan.candidates",
        json!({
            "scan_id": purge_rpc::methods::ScanId::from_bits(1).to_string(),
            "offset": 0,
            "limit": 1
        }),
    );
    assert_eq!(kind(&gone), "gone", "{gone}");
    assert_eq!(gone["error"]["data"]["id"], "scan", "{gone}");
    c.close();
    b.exit(SECS);
}

#[test]
fn explain_refuses_a_candidate_of_another_scan() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let page = ask(
        &c,
        4,
        "scan.candidates",
        json!({ "scan_id": scan_id, "offset": 0, "limit": 1 }),
    );
    let id = candidate_id(&page, 0);
    let ok = ask(
        &c,
        5,
        "candidate.explain",
        json!({ "scan_id": scan_id, "candidate_id": id }),
    );
    assert!(ok["result"]["evidence"].is_array(), "{ok}");

    let other = ask(
        &c,
        6,
        "candidate.explain",
        json!({ "scan_id": scan_id, "candidate_id": CandidateRef::from_bits(0x1234).to_string() }),
    );
    assert_eq!(kind(&other), "gone", "{other}");
    assert_eq!(other["error"]["data"]["id"], "candidate", "{other}");
    c.close();
    b.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// plan.create
// ---------------------------------------------------------------------------------------------------

/// A plan is built from this scan's item and reports the scan's plan hash and the confirm code.
#[test]
fn plan_create_holds_the_frozen_plan_the_response_describes() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&b.scan().scan).id.0.clone();

    let reply = create_selected(&c, 4, &scan_id, &[&item]);
    assert_eq!(reply["result"]["counts"]["items"], 1, "{reply}");
    let plan = b.plan();
    assert_eq!(
        plan.bound().scan().plan_hash,
        reply["result"]["plan_hash"].as_str().unwrap()
    );
    assert_eq!(plan.bound().scan().plan_hash, b.scan().scan.doc.plan_hash);
    assert_eq!(plan.bound().items().len(), 1);
    assert_eq!(
        plan.bound().scan().items[plan.bound().items()[0].index]
            .id
            .0,
        item
    );
    assert_eq!(
        plan.code.to_string(),
        reply["result"]["code"].as_str().unwrap()
    );
    assert_eq!(
        plan.bound().selection_hash(),
        purge_exec::plan_in::selection_hash([&CandidateId(item.clone())])
    );
    // The review page's attention list is the dialog's, item for item.
    let consent = crate::consent::view::view(
        plan.bound(),
        &crate::consent::view::Facts {
            app_name: BROKER_NAME.into(),
            restorable_until: None,
            restore_point: false,
        },
    )
    .expect("the view");
    let attention = reply["result"]["attention"].as_array().unwrap();
    assert_eq!(attention.len(), consent.attention.len(), "{reply}");
    let ids: Vec<&str> = attention
        .iter()
        .map(|item| item["candidate_id"].as_str().unwrap())
        .collect();
    let expected: Vec<&str> = consent
        .attention
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    assert_eq!(ids, expected);
    c.close();
    b.exit(SECS);
}

/// The preselected form uses exactly the scan's Safe preselection; none means a refusal.
#[test]
fn plan_create_preselected_follows_the_scan() {
    let mut b = Broker::start_with_settings(FixtureMachine::new(app_fixture()), shipped_settings());
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let run = ask(
        &c,
        3,
        "uninstall.run",
        json!({ "session_id": session, "quiet": true }),
    );
    assert_eq!(run["result"]["outcome"], "Success", "{run}");
    let scan = scan_session(&c, 4, &session, false);
    assert_eq!(scan["result"]["mode"], "post", "{scan}");
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let preselected = scan["result"]["counts"]["preselected"].as_u64().unwrap();
    let reply = ask(
        &c,
        5,
        "plan.create",
        json!({ "scan_id": scan_id, "preselected": true }),
    );
    assert!(
        preselected > 0,
        "the post scan preselects some Safe items: {scan}"
    );
    assert_eq!(
        reply["result"]["counts"]["items"].as_u64().unwrap(),
        preselected,
        "{reply}"
    );
    assert_eq!(
        reply["result"]["counts"]["preselected"].as_u64().unwrap(),
        preselected
    );
    assert_eq!(reply["result"]["counts"]["ticked"], 0);
    c.close();
    b.exit(SECS);
}

/// A second plan of the same scan is refused until the first is taken; then a new one may be made.
#[test]
fn a_plan_cannot_be_created_twice_from_one_scan() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&b.scan().scan).id.0.clone();
    let first = create_selected(&c, 4, &scan_id, &[&item]);
    let plan_id = created_id(&first);
    let second = create_selected(&c, 5, &scan_id, &[&item]);
    assert_eq!(kind(&second), "plan_refused", "{second}");
    assert!(
        second["error"]["data"]["refusals"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("exists already")
    );

    // M3-EXEC takes the plan and releases the scan; retrying after a declined dialog works.
    let _taken = ask(
        &c,
        6,
        "plan.execute",
        json!({ "plan_id": plan_id, "restore_point": "off" }),
    );
    let third = create_selected(&c, 7, &scan_id, &[&item]);
    assert!(third["result"]["plan_id"].is_string(), "{third}");
    c.close();
    b.exit(SECS);
}

/// An id of another scan is refused with its reason, not silently dropped.
#[test]
fn plan_create_refuses_ids_that_are_not_of_this_scan() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let unknown = CandidateRef::from_bits(0xabcd).to_string();
    let absorbed = b.scan().scan.doc.absorbed.first().map(|c| c.id.0.clone());
    let mut selection = vec![unknown.as_str()];
    if let Some(id) = absorbed.as_deref() {
        selection.push(id);
    }
    let reply = create_selected(&c, 4, &scan_id, &selection);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    let refused = refusal_ids(&reply);
    assert!(refused.contains(&unknown), "{reply}");
    if let Some(id) = absorbed {
        assert!(refused.contains(&id), "{reply}");
    }
    assert!(b.plans.lock().unwrap().is_empty());
    c.close();
    b.exit(SECS);
}

/// A blocked item is refused with its reason.
#[test]
fn plan_create_refuses_a_blocked_item() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let blocked = b
        .scan()
        .scan
        .doc
        .items
        .iter()
        .find(|candidate| {
            candidate
                .decision
                .as_ref()
                .is_some_and(|decision| decision.band == Band::Blocked)
        })
        .map(|candidate| candidate.id.0.clone());
    let Some(blocked) = blocked else {
        c.close();
        b.exit(SECS);
        return;
    };
    let reply = create_selected(&c, 4, &scan_id, &[&blocked]);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    assert_eq!(refusal_ids(&reply), vec![blocked.clone()], "{reply}");
    c.close();
    b.exit(SECS);
}

/// A scan id of another broker is not this broker's: it is `gone`.
#[test]
fn ids_of_another_broker_are_gone() {
    let mut first = Broker::start(FixtureMachine::new(app_fixture()));
    let c1 = first.client();
    let prepare = prepared(&c1, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c1, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    c1.close();
    first.exit(SECS);

    let mut second = Broker::start(FixtureMachine::new(app_fixture()));
    let c2 = second.client();
    let reply = ask(&c2, 2, "leftovers.scan", json!({ "session_id": session }));
    assert_eq!(kind(&reply), "gone", "{reply}");
    assert_eq!(reply["error"]["data"]["id"], "uninstall_session", "{reply}");
    let plan = ask(
        &c2,
        3,
        "plan.create",
        json!({ "scan_id": scan_id, "preselected": true }),
    );
    assert_eq!(kind(&plan), "gone", "{plan}");
    assert_eq!(plan["error"]["data"]["id"], "scan", "{plan}");
    c2.close();
    second.exit(SECS);
}

/// An item the executor cannot quarantine is refused with its reason.
#[test]
fn plan_create_refuses_an_item_the_executor_cannot_quarantine() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&b.scan().scan).id.0.clone();
    b.machine.refuse_unstorable(vec![Refusal {
        candidate_id: item.parse().ok(),
        reason: "this volume cannot hold a quarantine".into(),
    }]);
    let reply = create_selected(&c, 4, &scan_id, &[&item]);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    assert_eq!(refusal_ids(&reply), vec![item.clone()], "{reply}");
    c.close();
    b.exit(SECS);
}

/// A plan that would pass the quarantine cap is refused with the cap's numbers.
#[test]
fn plan_create_refuses_a_plan_over_the_cap() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&b.scan().scan).id.0.clone();
    b.machine.cap(ErrorObject::server(ErrorData::CapExceeded {
        volume: r"C:\".into(),
        used: 9,
        needed: 10,
        cap: 12,
    }));
    let reply = create_selected(&c, 4, &scan_id, &[&item]);
    assert_eq!(kind(&reply), "cap_exceeded", "{reply}");
    assert_eq!(reply["error"]["data"]["cap"], 12, "{reply}");
    c.close();
    b.exit(SECS);
}

/// No client value can pose as a path or a document: the params refuse what they do not know.
#[test]
fn plan_create_takes_ids_only() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let reply = ask(
        &c,
        2,
        "plan.create",
        json!({
            "scan_id": "s-0000000000000001",
            "preselected": true,
            "scan": { "items": [] }
        }),
    );
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    c.close();
    b.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// The scan's own checks
// ---------------------------------------------------------------------------------------------------

/// The broker's scan of the fixture equals the CLI's scan of the same fixture.
#[test]
fn the_broker_scan_equals_the_cli_scan() {
    let mut b = Broker::start(FixtureMachine::new(app_fixture()));
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let _scan = scan_session(&c, 3, &session, true);
    let broker_scan = b.scan();
    let fingerprint = b.machine.stored(&broker_id()).expect("the fingerprint");
    let cli = pipeline::scan(
        b.machine.sources(),
        &fingerprint,
        ScanMode::Forced,
        None,
        &Settings::default(),
        &mut |_| {},
    )
    .expect("the CLI scan runs");
    assert_eq!(broker_scan.scan.doc, cli.built.scan);
    c.close();
    b.exit(SECS);
}

/// A scan with two candidates sharing an id, or one whose id is not the wire form, is not served.
#[test]
fn a_scan_with_a_shared_or_malformed_candidate_id_is_refused() {
    let fixture = app_fixture();
    let fingerprint = pipeline::harvest(
        pipeline::Sources::of(&fixture),
        &broker_id().to_string(),
        purge_identity::kbdata::Kb::shipped(),
        &Settings::default(),
        &mut |_| {},
    )
    .expect("the harvest")
    .report
    .fingerprint;
    let scanned = pipeline::scan(
        pipeline::Sources::of(&fixture),
        &fingerprint,
        ScanMode::Forced,
        None,
        &Settings::default(),
        &mut |_| {},
    )
    .expect("the scan");
    assert!(crate::scan::check_unique(&scanned.built.scan).is_ok());
    let mut doubled = scanned.built.scan.clone();
    let first = doubled.items[0].clone();
    doubled.absorbed.push(first);
    let error = crate::scan::check_unique(&doubled).expect_err("a shared id is refused");
    assert_eq!(error.data.map(|data| data.kind()), Some("plan_refused"));
    let mut malformed = scanned.built.scan.clone();
    malformed.items[0].id = CandidateId("not-an-id".into());
    assert!(crate::scan::check_unique(&malformed).is_err());
}

// ---------------------------------------------------------------------------------------------------
// The baseline build
// ---------------------------------------------------------------------------------------------------

/// A scan made while the local baseline is building is offered again when it completes.
#[test]
fn a_scan_made_during_the_build_is_offered_again() {
    let mut b = Broker::start_with(
        FixtureMachine::new(app_fixture()),
        BaselineBuild::Building {
            parts: vec!["S1".into()],
            scan_waiting: false,
        },
    );
    let c = b.client();
    let prepare = prepared(&c, 2, &[broker_id()]);
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scan = scan_session(&c, 3, &session, true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    b.build.set(BaselineBuild::Done { rescan: true });
    let changed = c.recv(SECS).expect("baseline.changed");
    assert_eq!(changed["method"], "baseline.changed", "{changed}");
    assert_eq!(
        changed["params"]["rescan_offered"],
        json!([scan_id]),
        "{changed}"
    );
    c.close();
    b.exit(SECS);
}
