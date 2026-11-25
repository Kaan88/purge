//! The sample broker (UI-FLOW): a made-up administrator part for `--sample`, so the uninstall flow
//! can be walked end to end with nothing elevated and nothing changed on the PC. It answers the
//! pipe calls the Uninstall and Leftovers pages send with the wire fixtures of `purge-rpc`
//! (`crates/purge-rpc/fixtures`), made to name the program being uninstalled, and it plays the
//! broker's security prompt as a `consent.shown` and a short wait.
//!
//! It is never used with the real engine: [`crate::link::BrokerHub`] makes one only for the
//! sample source, in place of the launch (so no Windows prompt either).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use purge_client::{Answer, Broker, CallId, ClientError, ClientEvent, Sink};
use purge_model::ProgramId;
use purge_rpc::EngineHello;
use purge_rpc::methods::{LeftoversScanParams, PipeCall, PlanCreateParams};
use purge_rpc::table::CallSet;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// A made-up candidate: band, kind, category, path, size and whether it starts ticked.
type Row<'a> = (&'a str, &'a str, &'a str, &'a str, Option<u64>, bool);

/// Whether a Firefox was said to be running already in this run.
static FIREFOX_SEEN: AtomicBool = AtomicBool::new(false);

/// The fixture of `stem`, as a JSON value (they are part of the build; a broken one is a test
/// failure, see the tests below).
fn fixture(stem: &str) -> Value {
    let text = match stem {
        "hello" => include_str!("../../../crates/purge-rpc/fixtures/pipe.engine.hello.result.json"),
        "prepare" => {
            include_str!("../../../crates/purge-rpc/fixtures/pipe.uninstall.prepare.result.json")
        }
        "run" => include_str!("../../../crates/purge-rpc/fixtures/pipe.uninstall.run.result.json"),
        "observed" => {
            include_str!("../../../crates/purge-rpc/fixtures/pipe.uninstall.observed.result.json")
        }
        "scan" => {
            include_str!("../../../crates/purge-rpc/fixtures/pipe.leftovers.scan.result.json")
        }
        "plan" => include_str!("../../../crates/purge-rpc/fixtures/pipe.plan.create.result.json"),
        "exec" => include_str!("../../../crates/purge-rpc/fixtures/pipe.plan.execute.result.json"),
        _ => "null",
    };
    serde_json::from_str(text).unwrap_or(Value::Null)
}

fn decode<T: DeserializeOwned>(v: Value) -> Result<T, ClientError> {
    serde_json::from_value(v).map_err(|e| ClientError::BadReply(format!("sample broker: {e}")))
}

/// What the sample knows of a program: its name and where it is installed.
#[derive(Debug, Clone, Default)]
pub struct SampleProgram {
    pub name: String,
    pub location: String,
    pub uninstall: String,
    pub quiet: bool,
}

/// How long each answer takes, so the steps can be seen (and the rig's waits find them).
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    /// A plain call.
    pub step: Duration,
    /// The security prompt that "shows" before a consent call runs.
    pub prompt: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Pace {
            step: Duration::from_millis(900),
            prompt: Duration::from_millis(2500),
        }
    }
}

struct State {
    live: bool,
    cancelled: HashSet<CallId>,
    /// The program of the last prepare: the scan's items are made from it.
    program: SampleProgram,
    /// The candidates the last scan made, by id.
    items: Vec<Value>,
    /// How many items the last plan holds.
    planned: usize,
}

/// The made-up broker session.
pub struct SampleBroker {
    sink: Sink,
    hello: EngineHello,
    programs: HashMap<ProgramId, SampleProgram>,
    pace: Pace,
    state: Arc<Mutex<State>>,
    session: u64,
}

impl fmt::Debug for SampleBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SampleBroker")
    }
}

impl SampleBroker {
    /// A session that answers through `sink`, knowing these programs.
    pub fn new(sink: Sink, programs: HashMap<ProgramId, SampleProgram>, pace: Pace) -> Self {
        // The fixture is part of the build and checked by a test below.
        let hello = serde_json::from_value(fixture("hello"))
            .unwrap_or_else(|e| panic!("the sample broker's hello fixture does not parse: {e}"));
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1 << 40);
        SampleBroker {
            sink,
            hello,
            programs,
            pace,
            state: Arc::new(Mutex::new(State {
                live: true,
                cancelled: HashSet::new(),
                program: SampleProgram::default(),
                items: Vec::new(),
                planned: 0,
            })),
            session: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The answer of `request`, and whether it waits for the security prompt first.
    fn answer(&self, request: &PipeCall) -> (bool, Vec<&'static str>, Result<Answer, ClientError>) {
        match request {
            PipeCall::EngineHello(_) => {
                (false, vec![], Ok(Answer::BrokerHello(self.hello.clone())))
            }
            PipeCall::UninstallPrepare(p) => {
                let id = p.program_ids.as_slice()[0].clone();
                let mut program = self.programs.get(&id).cloned().unwrap_or_default();
                if program.uninstall.is_empty() {
                    // The sample list names no command for some: one in the program's folder,
                    // with the quiet switch most uninstallers of that shape take.
                    let folder = if program.location.is_empty() {
                        format!(r"C:\Program Files\{}", program.name)
                    } else {
                        program.location.trim_end_matches('\\').to_owned()
                    };
                    program.uninstall = format!(r#""{folder}\uninstall\helper.exe""#);
                    program.quiet = true;
                }
                let mut v = fixture("prepare");
                let item = &mut v["programs"][0];
                item["program_id"] = json!(id);
                item["command"] = json!(program.uninstall);
                item["quiet_command"] = if program.quiet {
                    json!(format!("{} /S", program.uninstall))
                } else {
                    Value::Null
                };
                item["signer"] = json!(format!("{} (sample)", program.name));
                item["co_products"] = json!([]);
                item["warnings"] = json!([]);
                // The first Firefox of the run is still open, so the confirmation's "Check
                // again" can be seen; once checked again it is closed.
                if program.name.contains("Firefox") && !FIREFOX_SEEN.swap(true, Ordering::Relaxed) {
                    item["running"] = json!([{ "pid": 4242, "name": "firefox.exe" }]);
                }
                self.lock().program = program;
                (
                    false,
                    vec!["harvest", "fingerprint"],
                    decode(v).map(Answer::Prepare),
                )
            }
            PipeCall::UninstallRun(_) => (
                true,
                vec!["Running its uninstaller", "Checking that it is gone"],
                decode(fixture("run")).map(Answer::Run),
            ),
            PipeCall::UninstallObserved(_) => (
                false,
                vec![],
                decode(fixture("observed")).map(Answer::Observed),
            ),
            PipeCall::LeftoversScan(p) => {
                let forced = matches!(p, LeftoversScanParams::Session(s) if s.forced);
                let items = self.items();
                let count = |band: &str| items.iter().filter(|i| i["band"] == band).count();
                let mut v = fixture("scan");
                v["mode"] = json!(if forced { "forced" } else { "post" });
                v["counts"] = json!({
                    "safe": count("Safe"), "likely": count("Likely"), "weak": count("Weak"),
                    "blocked": count("Blocked"),
                    "preselected": items.iter().filter(|i| i["preselected"] == true).count(),
                });
                self.lock().items = items;
                (
                    false,
                    vec!["Comparing with the recording", "Checking the registry"],
                    decode(v).map(Answer::Scan),
                )
            }
            PipeCall::ScanCandidates(p) => {
                let items = self.lock().items.clone();
                let from = (p.offset as usize).min(items.len());
                let page: Vec<Value> = items[from..].to_vec();
                let v = json!({"total": items.len(), "offset": p.offset, "items": page});
                (false, vec![], decode(v).map(Answer::Candidates))
            }
            PipeCall::CandidateExplain(p) => {
                let name = self.lock().program.name.clone();
                let v = json!({
                    "candidate_id": p.candidate_id,
                    "evidence": [
                        format!("Recorded under {name}'s install folder before the uninstall."),
                        "Still there after its own uninstaller ran.",
                    ],
                    "blockers": [],
                });
                (false, vec![], decode(v).map(Answer::Explanation))
            }
            PipeCall::PlanCreate(p) => {
                let n = match p {
                    PlanCreateParams::Selected(s) => s.selected.as_slice().len(),
                    PlanCreateParams::Preselected(_) => 0,
                };
                self.lock().planned = n;
                let mut v = fixture("plan");
                v["attention"] = json!([]);
                v["counts"] = json!({"items": n, "preselected": n, "ticked": 0});
                (false, vec![], decode(v).map(Answer::Plan))
            }
            PipeCall::PlanExecute(p) => {
                let mut v = fixture("exec");
                let n = self.lock().planned.max(1);
                v["counts"] = json!({"done": n, "failed": 0, "held_retry": 0, "pending_reboot": 0,
                    "skipped": 0, "vanished": 0});
                v["held"] = json!([]);
                v["outcome"] = json!("complete");
                v["delete_after"] = if p.delete_after {
                    json!({"kept": 0, "outcome": "complete", "purged": n})
                } else {
                    Value::Null
                };
                (
                    true,
                    vec!["Moving to quarantine"],
                    decode(v).map(Answer::Exec),
                )
            }
            PipeCall::UndoRun(_) => {
                let v = json!({"outcome": "complete", "conflicts": [], "alerts": []});
                (true, vec!["Putting back"], decode(v).map(Answer::Undo))
            }
            other => (
                false,
                vec![],
                Err(ClientError::NotAvailable(format!(
                    "The sample has no answer for {}.",
                    other.method().name()
                ))),
            ),
        }
    }

    /// The made-up leftovers of the last prepared program.
    fn items(&self) -> Vec<Value> {
        let program = self.lock().program.clone();
        let name = if program.name.is_empty() {
            "Sample".to_owned()
        } else {
            program.name.clone()
        };
        let short: String = name
            .split_whitespace()
            .next()
            .unwrap_or("Sample")
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect();
        let folder = if program.location.is_empty() {
            format!(r"C:\Program Files\{short}")
        } else {
            program.location.clone()
        };
        // Band, kind, category, path (empty: made from the name), size, preselected.
        let rows: [Row<'_>; 9] = [
            (
                "Safe",
                "folder",
                "AppFiles",
                &folder,
                Some(18_400_000),
                true,
            ),
            ("Safe", "folder", "AppData", "", Some(2_300_000), true),
            ("Safe", "registry_key", "Registration", "", None, true),
            ("Safe", "task", "Startup", "", None, true),
            ("Likely", "folder", "Cache", "", Some(540_000), false),
            ("Likely", "file", "UserData", "", Some(812), false),
            ("Weak", "registry_key", "Registration", "", None, false),
            (
                "Blocked",
                "folder",
                "System",
                r"C:\Windows\System32\drivers",
                None,
                false,
            ),
            ("Safe", "file", "Startup", "", Some(2_100), true),
        ];
        let made = [
            String::new(),
            format!(r"C:\Users\Sample\AppData\Roaming\{short}"),
            format!(r"HKCU\Software\{short}"),
            format!(r"\{short} Update Task"),
            format!(r"C:\Users\Sample\AppData\Local\{short}\Cache"),
            format!(r"C:\Users\Sample\Documents\{short}\settings.json"),
            format!(r"HKLM\SOFTWARE\Classes\{short}.Document"),
            String::new(),
            format!(r"C:\Users\Sample\Desktop\{name}.lnk"),
        ];
        rows.iter()
            .zip(made)
            .enumerate()
            .map(|(i, ((band, kind, category, fixed, size, pre), made))| {
                let display = if fixed.is_empty() {
                    made
                } else {
                    fixed.to_string()
                };
                json!({
                    "candidate_id": format!("c-5a5a{:012x}", i + 1),
                    "band": band,
                    "kind": kind,
                    "category": category,
                    "display_name": display,
                    "owner_program": name,
                    "size_bytes": size,
                    "warnings": [],
                    "preselected": pre,
                })
            })
            .collect()
    }
}

impl Broker for SampleBroker {
    fn hello(&self) -> &EngineHello {
        &self.hello
    }

    fn is_live(&self) -> bool {
        self.lock().live
    }

    fn closed_reason(&self) -> Option<String> {
        (!self.is_live()).then(|| "The sample administrator part was closed.".to_owned())
    }

    fn allow_foreground(&self) {}

    fn request(&self, request: PipeCall) -> CallId {
        let call = CallId::next();
        let (consent, phases, answer) = self.answer(&request);
        // A completed plan.execute ends the real broker (it exits after the move); so does this.
        let ends = matches!(request, PipeCall::PlanExecute(_));
        let session = self.session;
        let sink = self.sink.clone();
        let state = self.state.clone();
        let pace = self.pace;
        let gone = move |state: &Arc<Mutex<State>>| {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            !s.live || s.cancelled.contains(&call)
        };
        std::thread::spawn(move || {
            if consent {
                if let Ok(shown) =
                    serde_json::from_value(json!({"request": 1, "code": "A1B2-C3D4"}))
                {
                    sink.send(ClientEvent::ConsentShown {
                        call: Some(call),
                        shown,
                    });
                }
                std::thread::sleep(pace.prompt);
            }
            for (k, phase) in phases.iter().enumerate() {
                if gone(&state) {
                    return;
                }
                if let Ok(progress) = serde_json::from_value(json!({
                    "request": 1, "phase": phase, "done": k, "total": phases.len()
                })) {
                    sink.send(ClientEvent::Progress { call, progress });
                }
                std::thread::sleep(pace.step / phases.len().max(1) as u32);
            }
            if phases.is_empty() {
                std::thread::sleep(pace.step / 4);
            }
            if gone(&state) {
                return;
            }
            let ok = answer.is_ok();
            sink.send(ClientEvent::Reply {
                call,
                result: answer,
            });
            if ends && ok {
                state.lock().unwrap_or_else(|e| e.into_inner()).live = false;
                sink.send(ClientEvent::BrokerClosed {
                    session,
                    reason: "The administrator part exited after the move.".into(),
                });
            }
        });
        call
    }

    fn cancel(&self, call: CallId) {
        self.lock().cancelled.insert(call);
        self.sink.send(ClientEvent::Reply {
            call,
            result: Err(ClientError::Cancelled),
        });
    }

    fn close(&self) {
        let was = std::mem::replace(&mut self.lock().live, false);
        if was {
            self.sink.send(ClientEvent::BrokerClosed {
                session: self.session,
                reason: "The sample administrator part was closed.".into(),
            });
        }
    }

    fn session(&self) -> u64 {
        self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_rpc::methods::{NonEmpty, ProgramsParams, ScanSessionParams};
    use std::sync::mpsc::channel;

    fn pid() -> ProgramId {
        "HKLM|64|7-Zip".parse().expect("a program id")
    }

    fn broker() -> (SampleBroker, std::sync::mpsc::Receiver<ClientEvent>) {
        let (tx, rx) = channel();
        let sink = Sink::new(tx, Arc::new(|| {}));
        let mut programs = HashMap::new();
        programs.insert(
            pid(),
            SampleProgram {
                name: "7-Zip 24.08 (x64)".into(),
                location: r"C:\Program Files\7-Zip".into(),
                uninstall: r#""C:\Program Files\7-Zip\Uninstall.exe""#.into(),
                quiet: true,
            },
        );
        let pace = Pace {
            step: Duration::from_millis(4),
            prompt: Duration::from_millis(4),
        };
        (SampleBroker::new(sink, programs, pace), rx)
    }

    fn reply(rx: &std::sync::mpsc::Receiver<ClientEvent>, call: CallId) -> Answer {
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).expect("an event") {
                ClientEvent::Reply { call: c, result } if c == call => {
                    return result.expect("an answer");
                }
                _ => {}
            }
        }
    }

    #[test]
    fn every_fixture_the_sample_answers_with_parses() {
        let (b, rx) = broker();
        let id = pid();
        let call = b.request(PipeCall::UninstallPrepare(ProgramsParams {
            program_ids: NonEmpty::new(vec![id.clone()]).expect("one"),
        }));
        let Answer::Prepare(p) = reply(&rx, call) else {
            panic!("a prepare")
        };
        assert_eq!(p.programs[0].program_id, id);
        assert!(p.programs[0].quiet_command.is_some());
        let Answer::Scan(scan) = reply(
            &rx,
            b.request(PipeCall::LeftoversScan(LeftoversScanParams::Session(
                ScanSessionParams {
                    session_id: p.programs[0].session_id,
                    forced: false,
                },
            ))),
        ) else {
            panic!("a scan")
        };
        let call = b.request(PipeCall::ScanCandidates(
            purge_rpc::methods::CandidatesParams {
                scan_id: scan.scan_id,
                offset: 0,
                limit: serde_json::from_value(json!(500)).expect("a limit"),
            },
        ));
        let Answer::Candidates(page) = reply(&rx, call) else {
            panic!("candidates")
        };
        assert_eq!(page.items.len(), 9);
        assert!(page.items[0].display_name.contains("7-Zip"));
        for stem in ["run", "observed", "plan", "exec"] {
            assert!(!fixture(stem).is_null(), "{stem}");
        }
        let _: purge_rpc::methods::RunResult = decode(fixture("run")).expect("run");
        let _: purge_rpc::methods::PlanCreated = decode(fixture("plan")).expect("plan");
        let _: purge_rpc::methods::ExecResult = decode(fixture("exec")).expect("exec");
    }

    #[test]
    fn a_consent_call_shows_the_prompt_first_and_a_cancel_answers_once() {
        let (b, rx) = broker();
        let call = b.request(PipeCall::UndoRun(
            serde_json::from_value(json!({"session": "20251115T101502Z-9f3a6c1d2b7e4a50"}))
                .expect("undo params"),
        ));
        match rx.recv_timeout(Duration::from_secs(5)).expect("an event") {
            ClientEvent::ConsentShown { call: c, .. } => assert_eq!(c, Some(call)),
            other => panic!("the prompt first: {other:?}"),
        }
        assert!(matches!(reply(&rx, call), Answer::Undo(_)));
        let call = b.request(PipeCall::UndoRun(
            serde_json::from_value(json!({"session": "20251115T101502Z-9f3a6c1d2b7e4a50"}))
                .expect("undo params"),
        ));
        b.cancel(call);
        std::thread::sleep(Duration::from_millis(60));
        let replies = rx
            .try_iter()
            .filter(|e| matches!(e, ClientEvent::Reply { call: c, .. } if *c == call))
            .count();
        assert_eq!(replies, 1, "a cancelled call is answered once");
        b.close();
        assert!(!b.is_live());
    }
}
