//! The engine API: newline-delimited JSON-RPC 2.0.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §3.3; M3_DESIGN.md §6): request, response and notification
//! framing, the method table, the capability sets `Read`, `UserRun`, `Propose` and `Execute` and the
//! transports that may use them, outcomes and error kinds, and the request, result and notification
//! types. Holds no executor code, no `purge-win`, no handle and no thread, so `purge-mcp` can depend on
//! it.
//!
//! | Module | What |
//! |---|---|
//! | [`frame`] | line reader and writer with limits, envelope checks, [`frame::RequestId`] |
//! | [`table`] | [`table::METHODS`] (one set per method), [`table::lookup`], [`table::route`], [`table::Dispatcher`], [`table::serve`] |
//! | [`sets`] | [`sets::CapSet`], [`sets::Transport`] and its fixed [`sets::SetMask`], the line limits |
//! | [`error`] | [`error::Outcome`], [`error::ErrorData`] (`error.data.kind`), [`error::ErrorObject`] |
//! | [`methods`] | broker ids, params, results, notifications, [`methods::StdioCall`], [`methods::PipeCall`], [`methods::dtos`] |
//! | [`timing`] | the broker's timing marks: the optional `timings` member of four results, and its event-log line (gate G12) |
//!
//! Present before M3: the result of `engine.hello` ([`EngineHello`]), because the baseline view reports
//! through it (BASELINE_LOCAL_DESIGN.md, package BL-CACHE). Agent `Propose` methods come in M6.

pub mod error;
pub mod frame;
pub mod methods;
pub mod sets;
pub mod table;
pub mod timing;

use purge_model::{BaselineTrust, BaselineViewRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The method that reports what the engine is and what it can prove (ENGINE_PLAN.md §3.3).
pub const ENGINE_HELLO: &str = "engine.hello";

/// The result of [`ENGINE_HELLO`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineHello {
    /// The engine's version.
    pub version: String,
    /// Whether the engine process is elevated.
    pub elevated: bool,
    /// The SID of the account the engine runs as.
    pub user_sid: String,
    /// The SID of the interactive shell's account, when it is another one.
    #[serde(default)]
    pub shell_sid: Option<String>,
    /// Windows `EditionID`.
    pub edition: String,
    /// Windows build number.
    pub build: u32,
    /// Windows update build revision.
    pub ubr: u32,
    /// The policy rule set (`purge_policy::POLICY_VERSION`).
    pub policy_version: String,
    /// What the engine knows about "Windows' own" on this machine.
    #[serde(flatten)]
    pub baseline: BaselineStatus,
}

/// The baseline fields of [`EngineHello`] (BASELINE_LOCAL_DESIGN.md §4.1, §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BaselineStatus {
    /// A shipped baseline of exactly this Windows is in use: `baseline_trust` is `Exact`.
    pub baseline_available: bool,
    /// How far an absence answer of the view is trusted. Below `Exact` nothing is ever offered on
    /// absence; the view only blocks what Windows owns.
    pub baseline_trust: BaselineTrust,
    /// The view in use: its name, trust and the id of the local baseline it holds. `None` when no
    /// baseline directory is configured.
    #[serde(default)]
    pub baseline_view: Option<BaselineViewRef>,
    /// The local baseline's background build in this engine process.
    pub baseline_build: BaselineBuild,
}

/// The state of the local baseline's background build (BASELINE_LOCAL_DESIGN.md §5, W4): it starts
/// with the engine, never blocks a scan, and a scan made before it ended can be made again after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BaselineBuild {
    /// No build runs in this process: an exact shipped baseline, a complete cache, an engine that is
    /// not elevated, or no cache directory. `reason` says which.
    None {
        /// Why nothing is built.
        reason: String,
    },
    /// Deciding whether a build is needed.
    Checking,
    /// Building. A scan made now does not use what is still being built.
    Building {
        /// The sources being built (`S1`, `S2`, `S4`).
        parts: Vec<String>,
        /// A scan has asked for the view since the build started, so the build runs at normal
        /// priority and that scan is worth making again when the build is done.
        scan_waiting: bool,
    },
    /// Built in this process.
    Done {
        /// A scan ran before the build ended: making it again uses the new local baseline.
        rescan: bool,
    },
    /// The build did not produce a usable cache.
    Failed {
        /// Why.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_carries_the_baseline_trust_and_view() {
        let hello = EngineHello {
            version: "0.1.0".into(),
            elevated: true,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            shell_sid: None,
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
            policy_version: "bl.1".into(),
            baseline: BaselineStatus {
                baseline_available: false,
                baseline_trust: BaselineTrust::Merged,
                baseline_view: Some(BaselineViewRef {
                    name: "local-Professional-26100.9711+2".into(),
                    trust: BaselineTrust::Merged,
                    local_id: Some("0123456789abcdef".into()),
                }),
                baseline_build: BaselineBuild::Building {
                    parts: vec!["S1".into()],
                    scan_waiting: true,
                },
            },
        };
        let json = serde_json::to_value(&hello).unwrap();
        assert_eq!(json["baseline_available"], false);
        assert_eq!(json["baseline_trust"], "Merged");
        assert_eq!(
            json["baseline_view"]["name"],
            "local-Professional-26100.9711+2"
        );
        assert_eq!(json["baseline_view"]["local_id"], "0123456789abcdef");
        assert_eq!(json["baseline_build"]["state"], "building");
        assert_eq!(json["baseline_build"]["scan_waiting"], true);
        let back: EngineHello = serde_json::from_value(json).unwrap();
        assert_eq!(back, hello);
    }
}

/// Tests across the modules: the table walk per transport, the request-shape walk (threat T3), the
/// extra-member and path fuzz, the fixture round trip and the serve loop.
#[cfg(test)]
mod api_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use purge_model::exec::journal::UndoConflict;
    use purge_model::exec::op::{ItemOutcome, OpId, OutcomeCounts, Sha256Hex};
    use purge_model::exec::session::{
        Expiry, Locker, RestorePointOutcome, RetentionClass, SessionId, SessionState,
        SessionSummary, VolumeUsage,
    };
    use purge_model::{
        Band, Category, FileTime, InstallScope, InstallerKind, ProgramId, RunOutcome, ScanMode,
        VerifyGone, View, WritableBy,
    };
    use serde::Serialize;
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::error::{
        ErrorData, ErrorObject, INVALID_PARAMS, INVALID_REQUEST, IdKind, METHOD_NOT_FOUND, Outcome,
        Refusal,
    };
    use crate::frame::{
        FrameError, FrameWriter, RequestId, RequestLine, Response, ServerMessage, parse_server_line,
    };
    use crate::methods::*;
    use crate::sets::{CapSet, STDIO_IN_LIMIT, Transport};
    use crate::table::{
        CallSet, Dispatcher, METHODS, Method, Notify, Routed, route, serve, write_response,
    };
    use crate::timing::{TIMING_LINE_KIND, TimingLine, TimingMark, TimingName, Timings};

    fn v<T: Serialize>(value: T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    /// A `timings` member: the process was created at a fixed wall time, each mark `ms` after it.
    fn timings(marks: &[(TimingName, u64)]) -> Timings {
        const CREATED: u64 = 1_795_000_000_000;
        Timings {
            process_created_unix_ms: Some(CREATED),
            marks: marks
                .iter()
                .map(|&(mark, ms)| TimingMark {
                    mark,
                    ms,
                    wall_unix_ms: CREATED + ms,
                })
                .collect(),
        }
    }

    fn ne<T>(items: Vec<T>) -> NonEmpty<T> {
        NonEmpty::new(items).unwrap()
    }

    fn git() -> ProgramId {
        "HKLM|64|Git_is1".parse().unwrap()
    }

    fn code_user() -> ProgramId {
        ProgramId::user(
            "S-1-5-21-1-2-3-1001",
            View::K64,
            "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1",
        )
        .unwrap()
    }

    fn started() -> FileTime {
        FileTime::from_unix_secs(1_763_201_702)
    }

    fn session() -> SessionId {
        SessionId::new(started(), 0x9f3a_6c1d_2b7e_4a50)
    }

    fn hash() -> Sha256Hex {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]);
        bytes[31] = 0x01;
        Sha256Hex(bytes)
    }

    fn uid() -> UninstallSessionId {
        UninstallSessionId::from_bits(0x1122_3344_5566_7788)
    }

    fn scan() -> ScanId {
        ScanId::from_bits(0x0123_4567_89ab_cdef)
    }

    fn plan() -> PlanId {
        PlanId::from_bits(0xfeed_0000_0000_0001)
    }

    fn cand(n: u64) -> CandidateRef {
        CandidateRef::from_bits(0x5a5a_0000_0000_0000 | n)
    }

    fn expiry() -> ExpiryId {
        ExpiryId::from_bits(0x0e0e_0000_0000_0007)
    }

    fn warning() -> Warning {
        Warning {
            code: "baseline_inferred".into(),
            message: "Windows' own items are inferred from a local baseline.".into(),
        }
    }

    fn hello() -> EngineHello {
        EngineHello {
            version: "0.1.0".into(),
            elevated: true,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            shell_sid: None,
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
            policy_version: "bl.1".into(),
            baseline: BaselineStatus {
                baseline_available: true,
                baseline_trust: BaselineTrust::Exact,
                baseline_view: Some(BaselineViewRef {
                    name: "Professional-26100.9711".into(),
                    trust: BaselineTrust::Exact,
                    local_id: None,
                }),
                baseline_build: BaselineBuild::None {
                    reason: "exact shipped baseline".into(),
                },
            },
        }
    }

    fn summary() -> SessionSummary {
        SessionSummary {
            id: session(),
            app: "HKLM|64|Git_is1".into(),
            owner: None,
            plan_hash: hash(),
            state: SessionState::Committed,
            started: started(),
            finished: Some(FileTime(started().0 + 600_000_000)),
            counts: OutcomeCounts {
                done: 21,
                held_retry: 1,
                ..OutcomeCounts::default()
            },
            undone: 0,
            backup_bytes: 1_234_567,
            usage: vec![VolumeUsage {
                serial: 0x1234_abcd,
                root: "C:\\".into(),
                bytes: 1_234_567,
            }],
            expires: Expiry::from_start(started()),
            purged: vec![],
            pending_reboot: false,
            journal: None,
        }
    }

    fn row(program_id: ProgramId, name: &str) -> ProgramRow {
        ProgramRow {
            program_id,
            name: name.into(),
            publisher: Some("The Git Development Community".into()),
            version: Some("2.47.0".into()),
            scope: InstallScope::Machine,
            size_bytes: Some(345_000_000),
            install_time: Some(started()),
        }
    }

    fn progress(request: u64, phase: &str, program_id: Option<ProgramId>) -> Progress {
        Progress {
            request: RequestId(request),
            program_id,
            phase: phase.into(),
            done: 3,
            total: Some(9),
        }
    }

    fn all_error_data() -> Vec<ErrorData> {
        vec![
            ErrorData::ConsentDeclined,
            ErrorData::PlanRefused {
                refusals: vec![
                    Refusal {
                        candidate_id: Some(cand(2)),
                        reason: "The quarantine cannot hold this item.".into(),
                    },
                    Refusal {
                        candidate_id: None,
                        reason: "Nothing is selected.".into(),
                    },
                ],
            },
            ErrorData::NeedsRecovery {
                sessions: vec![session()],
            },
            ErrorData::StoreIntegrity {
                message: "journal chain broken at line 12".into(),
            },
            ErrorData::UninstallFailed {
                exit_code: Some(1603),
                forced_offered: true,
            },
            ErrorData::OtherAccount,
            ErrorData::NotElevated,
            ErrorData::InstallUntrusted,
            ErrorData::WrongRoute {
                route: Route::Medium,
            },
            ErrorData::Busy,
            ErrorData::Gone { id: IdKind::Scan },
            ErrorData::CapExceeded {
                volume: "C:\\".into(),
                used: 9_000_000_000,
                needed: 2_000_000_000,
                cap: 10_000_000_000,
            },
            ErrorData::Runtime {
                message: "the harvest store could not be opened".into(),
            },
        ]
    }

    /// One sample value per fixture stem. The fixtures are these values, pretty-printed; run the tests
    /// with `PURGE_RPC_BLESS=1` to write them again after a type changed.
    fn samples() -> BTreeMap<String, Value> {
        let mut samples = BTreeMap::new();
        {
            let mut put = |stem: &str, value: Value| {
                assert!(
                    samples.insert(stem.to_owned(), value).is_none(),
                    "sample {stem} twice"
                );
            };
            let none = json!({});

            put("stdio.engine.hello.params", none.clone());
            put("stdio.programs.list.params", none.clone());
            put(
                "stdio.programs.get.params",
                v(ProgramParams { program_id: git() }),
            );
            put(
                "stdio.programs.icons.params",
                v(IconsParams {
                    program_ids: ne(vec![git(), code_user()]),
                    px: 24,
                }),
            );
            put(
                "stdio.programs.sizes.params",
                v(ProgramsParams {
                    program_ids: ne(vec![git()]),
                }),
            );
            put("stdio.inventory.changes.params", none.clone());
            put(
                "stdio.inventory.forget.params",
                v(ProgramsParams {
                    program_ids: ne(vec![git()]),
                }),
            );
            put("stdio.history.index.params", none.clone());
            put(
                "stdio.uninstall.route.params",
                v(ProgramParams {
                    program_id: code_user(),
                }),
            );
            put(
                "stdio.uninstall.run_user.params",
                v(RunUserParams {
                    program_id: code_user(),
                    quiet: false,
                }),
            );
            put(
                "stdio.cancel.params",
                v(CancelParams {
                    request: RequestId(7),
                }),
            );

            put(
                "stdio.engine.hello.result",
                v(MediumHello {
                    hello: EngineHello {
                        elevated: false,
                        ..hello()
                    },
                    elevation_type: ElevationType::Limited,
                    shell_matches: true,
                }),
            );
            put("stdio.programs.list.result", v(Started { count: 212 }));
            put(
                "stdio.programs.get.result",
                v(ProgramDetails {
                    row: row(git(), "Git"),
                    installer: InstallerKind::Inno,
                    writable_by: WritableBy::Admin,
                    install_location: Some("C:\\Program Files\\Git\\".into()),
                    uninstall_command: Some("\"C:\\Program Files\\Git\\unins000.exe\"".into()),
                    quiet_uninstall_command: Some(
                        "\"C:\\Program Files\\Git\\unins000.exe\" /SILENT".into(),
                    ),
                    product_code: None,
                }),
            );
            put("stdio.programs.icons.result", v(Started { count: 2 }));
            put("stdio.programs.sizes.result", v(Started { count: 1 }));
            put(
                "stdio.inventory.changes.result",
                v(InventoryChanges {
                    disappeared: vec![ProgramRef {
                        program_id: git(),
                        name: "Git".into(),
                    }],
                    appeared: vec![],
                }),
            );
            put("stdio.inventory.forget.result", v(Started { count: 1 }));
            put(
                "stdio.history.index.result",
                v(HistoryIndex {
                    sessions: vec![summary()],
                    volumes: vec![VolumeCap {
                        serial: 0x1234_abcd,
                        root: "C:\\".into(),
                        used: 1_234_567,
                        cap: 10_737_418_240,
                    }],
                }),
            );
            put(
                "stdio.uninstall.route.result",
                v(RouteInfo {
                    route: Route::Medium,
                    command: "\"C:\\Users\\u\\AppData\\Local\\Programs\\Microsoft VS Code\\unins000.exe\""
                        .into(),
                    quiet_command: Some(
                        "\"C:\\Users\\u\\AppData\\Local\\Programs\\Microsoft VS Code\\unins000.exe\" /VERYSILENT"
                            .into(),
                    ),
                    signer: Some("Microsoft Corporation".into()),
                    running: vec![RunningProcess {
                        pid: 4242,
                        name: "Code.exe".into(),
                    }],
                }),
            );
            put(
                "stdio.uninstall.run_user.result",
                v(RunUserResult {
                    exit_code: Some(0),
                    outcome: RunOutcome::Success,
                }),
            );

            put("pipe.engine.hello.params", none.clone());
            put(
                "pipe.uninstall.prepare.params",
                v(ProgramsParams {
                    program_ids: ne(vec![git()]),
                }),
            );
            put(
                "pipe.uninstall.run.params",
                v(RunParams {
                    session_id: uid(),
                    quiet: true,
                    restore_point: Some(RestorePoint::HighRisk),
                }),
            );
            put(
                "pipe.uninstall.observed.params",
                v(ObservedParams {
                    session_id: uid(),
                    outcome: Some(purge_model::RunOutcome::Failed),
                }),
            );
            put(
                "pipe.leftovers.stored.params",
                v(ProgramsParams {
                    program_ids: ne(vec![git(), code_user()]),
                }),
            );
            put(
                "pipe.leftovers.scan.params",
                v(LeftoversScanParams::Session(ScanSessionParams {
                    session_id: uid(),
                    forced: false,
                })),
            );
            put(
                "pipe.leftovers.scan.params.stored",
                v(LeftoversScanParams::Stored(ScanStoredParams {
                    program_id: git(),
                })),
            );
            put(
                "pipe.scan.candidates.params",
                v(CandidatesParams {
                    scan_id: scan(),
                    offset: 0,
                    limit: PageLimit::new(500).unwrap(),
                }),
            );
            put(
                "pipe.candidate.explain.params",
                v(ExplainParams {
                    scan_id: scan(),
                    candidate_id: cand(1),
                }),
            );
            put(
                "pipe.plan.create.params",
                v(PlanCreateParams::Selected(PlanSelectedParams {
                    scan_id: scan(),
                    selected: ne(vec![cand(1), cand(2)]),
                    allow_irreversible: true,
                })),
            );
            put(
                "pipe.plan.create.params.preselected",
                v(PlanCreateParams::Preselected(PlanPreselectedParams {
                    scan_id: scan(),
                    preselected: True,
                })),
            );
            put(
                "pipe.plan.execute.params",
                v(PlanExecuteParams {
                    plan_id: plan(),
                    restore_point: RestorePoint::HighRisk,
                }),
            );
            put(
                "pipe.history.get.params",
                v(SessionParams { session: session() }),
            );
            put(
                "pipe.undo.run.params",
                v(UndoParams {
                    session: session(),
                    item_ids: Some(ne(vec![OpId(1), OpId(3)])),
                }),
            );
            put("pipe.journal.pending.params", none.clone());
            for method in ["journal.resume", "journal.rollback", "journal.retry_held"] {
                put(
                    &format!("pipe.{method}.params"),
                    v(SessionParams { session: session() }),
                );
            }
            put(
                "pipe.quarantine.expiring.params",
                v(ExpiringParams {
                    include_not_due: true,
                }),
            );
            put(
                "pipe.quarantine.purge.params",
                v(PurgeParams {
                    expiry_ids: ne(vec![expiry()]),
                }),
            );
            put("pipe.broker.shutdown.params", none);
            put(
                "pipe.cancel.params",
                v(CancelParams {
                    request: RequestId(12),
                }),
            );

            put("pipe.engine.hello.result", v(hello()));
            put(
                "pipe.uninstall.prepare.result",
                v(PrepareResult {
                    programs: vec![Prepared {
                        program_id: git(),
                        session_id: uid(),
                        route: Route::Broker,
                        command: "\"C:\\Program Files\\Git\\unins000.exe\"".into(),
                        quiet_command: Some(
                            "\"C:\\Program Files\\Git\\unins000.exe\" /SILENT".into(),
                        ),
                        signer: Some("Johannes Schindelin".into()),
                        co_products: vec![CoProduct {
                            name: "Git Credential Manager".into(),
                            program_id: None,
                        }],
                        running: vec![],
                        fingerprint_summary: FingerprintSummary {
                            roots: 1,
                            files: 1_830,
                            registry: 42,
                            objects: 0,
                        },
                        warnings: vec![warning()],
                    }],
                    timings: None,
                }),
            );
            put(
                "pipe.uninstall.run.result",
                v(RunResult {
                    exit_code: Some(0),
                    outcome: RunOutcome::Success,
                    verify_gone: VerifyGone::new(true, true, true),
                }),
            );
            put(
                "pipe.uninstall.observed.result",
                v(ObservedResult {
                    verify_gone: VerifyGone::new(true, true, false),
                }),
            );
            put(
                "pipe.leftovers.stored.result",
                v(StoredResult {
                    stored: vec![git()],
                }),
            );
            put(
                "pipe.leftovers.scan.result",
                v(ScanResult {
                    scan_id: scan(),
                    mode: ScanMode::Post,
                    counts: BandCounts {
                        safe: 20,
                        likely: 4,
                        weak: 2,
                        blocked: 3,
                        preselected: 20,
                    },
                    baseline_trust: BaselineTrust::Exact,
                    warnings: vec![],
                    timings: Some(timings(&[
                        (TimingName::BrokerStart, 41),
                        (TimingName::PipeConnected, 180),
                        (TimingName::ScanStart, 9_020),
                        (TimingName::FirstProgress, 9_034),
                        (TimingName::ScanComplete, 12_310),
                    ])),
                }),
            );
            put(
                "pipe.scan.candidates.result",
                v(CandidatesPage {
                    total: 29,
                    offset: 0,
                    items: vec![CandidateRow {
                        candidate_id: cand(1),
                        band: Band::Safe,
                        kind: ItemKind::Folder,
                        category: Category::AppFiles,
                        display_name: "C:\\Program Files\\Git".into(),
                        owner_program: Some("Git".into()),
                        size_bytes: Some(12_345),
                        warnings: vec![],
                        preselected: true,
                    }],
                }),
            );
            put(
                "pipe.candidate.explain.result",
                v(Explanation {
                    candidate_id: cand(1),
                    evidence: vec!["Listed in the Inno Setup uninstall log unins000.dat.".into()],
                    blockers: vec![],
                }),
            );
            put(
                "pipe.plan.create.result",
                v(PlanCreated {
                    plan_id: plan(),
                    plan_hash: hash(),
                    code: ConfirmCode::of(&hash()),
                    counts: PlanCounts {
                        items: 22,
                        preselected: 20,
                        ticked: 2,
                    },
                    bytes: 1_234_567,
                    attention: vec![AttentionItem {
                        candidate_id: cand(2),
                        display_name: "C:\\Users\\u\\.gitconfig".into(),
                        kind: ItemKind::File,
                        band: Band::Likely,
                        size_bytes: Some(812),
                        reasons: vec![AttentionReason::UserData, AttentionReason::NotPreselected],
                    }],
                    warnings: vec![],
                    timings: None,
                }),
            );
            put(
                "pipe.plan.execute.result",
                v(ExecResult {
                    outcome: Outcome::Partial,
                    session: session(),
                    counts: OutcomeCounts {
                        done: 21,
                        held_retry: 1,
                        ..OutcomeCounts::default()
                    },
                    held: vec![HeldItem {
                        op: OpId(4),
                        display_name: "C:\\Program Files\\Git\\git-bash.exe".into(),
                        lockers: vec![Locker {
                            pid: 77,
                            name: "git-bash.exe".into(),
                            service: None,
                        }],
                    }],
                    restore_point: RestorePointOutcome::Created { sequence: 42 },
                    timings: Some(timings(&[
                        (TimingName::BrokerStart, 41),
                        (TimingName::PipeConnected, 180),
                        (TimingName::ConsentShown, 14_002),
                        (TimingName::ConsentAnswered, 16_480),
                        (TimingName::ExecuteStart, 16_481),
                        (TimingName::ExecuteComplete, 19_900),
                    ])),
                }),
            );
            put(
                "pipe.history.get.result",
                v(HistoryDetail {
                    session: session(),
                    state: SessionState::Committed,
                    items: vec![HistoryItem {
                        op: OpId(1),
                        display_name: "C:\\Program Files\\Git".into(),
                        kind: ItemKind::Folder,
                        outcome: ItemOutcome::Done,
                        undone: false,
                        alert: Some(Alert {
                            op: OpId(1),
                            original_path: "C:\\Program Files\\Git".into(),
                            moved_back: true,
                        }),
                        deleted: None,
                    }],
                }),
            );
            // The second form of a history item: its kept data was deleted, here before the retention
            // ended ("Delete now"), and after it.
            put(
                "pipe.history.get.result.deleted",
                v(HistoryDetail {
                    session: session(),
                    state: SessionState::Committed,
                    items: [Deleted::Early, Deleted::Expired]
                        .into_iter()
                        .zip(1..)
                        .map(|(deleted, op)| HistoryItem {
                            op: OpId(op),
                            display_name: format!("C:\\ProgramData\\Git\\cache{op}"),
                            kind: ItemKind::Folder,
                            outcome: ItemOutcome::Done,
                            undone: false,
                            alert: None,
                            deleted: Some(deleted),
                        })
                        .collect(),
                }),
            );
            put(
                "pipe.undo.run.result",
                v(UndoResult {
                    outcome: Outcome::UndoConflicts,
                    conflicts: vec![ConflictRow {
                        op: OpId(3),
                        display_name: "C:\\Program Files\\Git\\etc".into(),
                        conflict: UndoConflict::DestinationExists,
                    }],
                    alerts: vec![Alert {
                        op: OpId(2),
                        original_path: "C:\\Program Files\\Git\\cmd".into(),
                        moved_back: true,
                    }],
                }),
            );
            put(
                "pipe.journal.pending.result",
                v(PendingList {
                    sessions: vec![PendingSession {
                        session: session(),
                        app: "Mozilla Firefox".into(),
                        started: started(),
                        done: 37,
                        total: 52,
                    }],
                }),
            );
            put(
                "pipe.journal.resume.result",
                v(OutcomeResult {
                    outcome: Outcome::Complete,
                    alerts: Vec::new(),
                }),
            );
            put(
                "pipe.journal.rollback.result",
                v(OutcomeResult {
                    outcome: Outcome::NotClosed,
                    alerts: Vec::new(),
                }),
            );
            put(
                "pipe.journal.retry_held.result",
                v(OutcomeResult {
                    outcome: Outcome::Partial,
                    alerts: Vec::new(),
                }),
            );
            put(
                "pipe.quarantine.expiring.result",
                v(ExpiringList {
                    items: vec![ExpiringItem {
                        expiry_id: expiry(),
                        session: session(),
                        app: "Git".into(),
                        class: RetentionClass::Quarantine,
                        expired: FileTime(started().0 + 25_920_000_000_000),
                        due: true,
                        files: vec!["C:\\Program Files\\Git".into()],
                        bytes: 345_000_000,
                        user_data: false,
                    }],
                }),
            );
            put(
                "pipe.quarantine.purge.result",
                v(PurgeResult {
                    outcome: Outcome::Complete,
                    purged: 41,
                    kept: 0,
                }),
            );
            put(
                "pipe.broker.shutdown.result",
                v(ShutdownResult { exiting: true }),
            );

            put(
                "notification.programs.batch",
                v(ProgramsBatch {
                    request: RequestId(2),
                    rows: vec![row(git(), "Git")],
                }),
            );
            put(
                "notification.programs.patch",
                v(ProgramsPatch {
                    request: RequestId(2),
                    patches: vec![ProgramPatch {
                        program_id: git(),
                        installer: Some(InstallerKind::Inno),
                        product_code: None,
                        bundle: None,
                        appx: Some(false),
                        system_component: Some(false),
                        unnamed: None,
                        parent_key: None,
                    }],
                }),
            );
            put(
                "notification.icon.batch",
                v(IconBatch {
                    request: RequestId(3),
                    icons: vec![
                        Icon {
                            program_id: git(),
                            px: 1,
                            bgra: Some("AAAA/w==".into()),
                        },
                        Icon {
                            program_id: code_user(),
                            px: 24,
                            bgra: None,
                        },
                    ],
                }),
            );
            put(
                "notification.size.ready",
                v(SizeReady {
                    request: RequestId(4),
                    sizes: vec![
                        ProgramSize {
                            program_id: git(),
                            bytes: Some(345_000_000),
                        },
                        ProgramSize {
                            program_id: code_user(),
                            bytes: None,
                        },
                    ],
                }),
            );
            put(
                "notification.uninstall.progress",
                v(progress(5, "wait", None)),
            );
            put(
                "notification.baseline.changed",
                v(BaselineChanged {
                    build: BaselineBuild::Done { rescan: true },
                    rescan_offered: vec![scan()],
                }),
            );
            put(
                "notification.prepare.progress",
                v(progress(6, "harvest", Some(git()))),
            );
            put("notification.scan.progress", v(progress(9, "scan", None)));
            put(
                "notification.consent.shown",
                v(ConsentShown {
                    request: RequestId(10),
                    code: ConfirmCode::of(&hash()),
                }),
            );
            put("notification.exec.progress", v(progress(10, "move", None)));
            put(
                "notification.undo.progress",
                v(progress(11, "restore", None)),
            );

            for data in all_error_data() {
                put(
                    &format!("error.{}", data.kind()),
                    v(ErrorObject::server(data)),
                );
            }
        }
        samples
    }

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    #[test]
    fn fixture_round_trip_for_every_type() {
        let samples = samples();
        let dtos = dtos();
        let stems: BTreeSet<String> = dtos.iter().map(|d| d.stem.clone()).collect();
        assert_eq!(stems.len(), dtos.len(), "a fixture stem is used twice");
        assert_eq!(
            samples.keys().cloned().collect::<BTreeSet<_>>(),
            stems,
            "every DTO has exactly one sample"
        );
        let dir = fixtures_dir();
        if std::env::var_os("PURGE_RPC_BLESS").is_some() {
            std::fs::create_dir_all(&dir).unwrap();
            for (stem, value) in &samples {
                let text = serde_json::to_string_pretty(value).unwrap() + "\n";
                std::fs::write(dir.join(format!("{stem}.json")), text).unwrap();
            }
        }
        for dto in &dtos {
            let path = dir.join(format!("{}.json", dto.stem));
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}; run with PURGE_RPC_BLESS=1", path.display()));
            let file: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                file, samples[&dto.stem],
                "{} differs from its sample; run with PURGE_RPC_BLESS=1",
                dto.stem
            );
            let back = (dto.round_trip)(&text).unwrap_or_else(|e| panic!("{}: {e}", dto.stem));
            assert_eq!(back, file, "{} does not round trip", dto.stem);
            let schema = serde_json::to_value((dto.schema)()).unwrap();
            assert!(schema.is_object(), "{} has no schema", dto.stem);
        }
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let stem = name.strip_suffix(".json").unwrap_or(&name);
            assert!(stems.contains(stem), "fixture {name} has no type");
        }
    }

    #[test]
    fn every_error_kind_has_a_fixture() {
        let kinds: Vec<&str> = all_error_data().iter().map(ErrorData::kind).collect();
        assert_eq!(kinds, ERROR_KINDS);
    }

    fn request_line(id: u64, method: &str, params: &Value) -> Vec<u8> {
        serde_json::to_vec(&RequestLine {
            id: RequestId(id),
            method,
            params: Some(params),
        })
        .unwrap()
    }

    /// The method a line was routed to, or the error code it was answered with.
    fn routed<C: CallSet + std::fmt::Debug>(line: &[u8]) -> Result<Method, i32> {
        match route::<C>(line) {
            Routed::Call { call, .. } => Ok(call.method()),
            Routed::Reply(Response { body: Err(e), .. }) => Err(e.code),
            other => panic!("not a request: {other:?}"),
        }
    }

    fn routed_on(transport: Transport, line: &[u8]) -> Result<Method, i32> {
        match transport {
            Transport::Stdio => routed::<StdioCall>(line),
            Transport::Pipe => routed::<PipeCall>(line),
        }
    }

    /// Params that decode for the method, from the transport that serves it, so that a refusal on the
    /// other transport can only come from the table and its mask.
    fn params_for(samples: &BTreeMap<String, Value>, name: &str) -> Value {
        samples
            .get(&format!("pipe.{name}.params"))
            .or_else(|| samples.get(&format!("stdio.{name}.params")))
            .unwrap_or_else(|| panic!("no params sample for {name}"))
            .clone()
    }

    #[test]
    fn table_walk_per_transport() {
        let samples = samples();
        for spec in METHODS {
            let line = request_line(1, spec.name, &params_for(&samples, spec.name));
            for transport in Transport::ALL {
                let got = routed_on(transport, &line);
                let reachable = spec.served.on(transport) && transport.mask().contains(spec.set);
                if reachable {
                    assert_eq!(got, Ok(spec.method), "{} on {transport:?}", spec.name);
                } else {
                    assert_eq!(got, Err(METHOD_NOT_FOUND), "{} on {transport:?}", spec.name);
                }
            }
            if matches!(spec.set, CapSet::Execute | CapSet::Propose) {
                assert_eq!(
                    routed_on(Transport::Stdio, &line),
                    Err(METHOD_NOT_FOUND),
                    "{} reached over stdio",
                    spec.name
                );
            }
            if spec.set == CapSet::UserRun {
                assert_eq!(
                    routed_on(Transport::Pipe, &line),
                    Err(METHOD_NOT_FOUND),
                    "{} reached over the pipe",
                    spec.name
                );
            }
        }
        for name in [
            "",
            "plan.Execute",
            "PLAN.EXECUTE",
            "plan.execute ",
            "rpc.discover",
            "$/cancel",
            "consent.shown",
            "programs.batch",
            "engine.hello\u{0}",
        ] {
            for transport in Transport::ALL {
                let line = request_line(1, name, &json!({}));
                assert_eq!(
                    routed_on(transport, &line),
                    Err(METHOD_NOT_FOUND),
                    "{name:?}"
                );
            }
        }
    }

    #[test]
    fn call_sets_have_variants_only_for_their_transport() {
        for (transport, methods) in [
            (Transport::Stdio, StdioCall::METHODS),
            (Transport::Pipe, PipeCall::METHODS),
        ] {
            let expected: Vec<Method> = METHODS
                .iter()
                .filter(|s| s.served.on(transport) && transport.mask().contains(s.set))
                .map(|s| s.method)
                .collect();
            assert_eq!(methods, expected.as_slice(), "{transport:?}");
        }
        for spec in METHODS {
            if StdioCall::METHODS.contains(&spec.method) {
                assert!(
                    matches!(spec.set, CapSet::Read | CapSet::UserRun),
                    "{}",
                    spec.name
                );
            }
            if PipeCall::METHODS.contains(&spec.method) {
                assert_ne!(spec.set, CapSet::UserRun, "{}", spec.name);
            }
        }
        // Past the table, too: a call set cannot decode another transport's method even with valid
        // params.
        let samples = samples();
        for spec in METHODS {
            let params = serde_json::to_string(&params_for(&samples, spec.name)).unwrap();
            let raw = serde_json::value::RawValue::from_string(params).unwrap();
            if !StdioCall::METHODS.contains(&spec.method) {
                assert_eq!(
                    StdioCall::decode(spec.method, Some(&raw)).unwrap_err().code,
                    METHOD_NOT_FOUND,
                    "{}",
                    spec.name
                );
            }
            if !PipeCall::METHODS.contains(&spec.method) {
                assert_eq!(
                    PipeCall::decode(spec.method, Some(&raw)).unwrap_err().code,
                    METHOD_NOT_FOUND,
                    "{}",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn a_request_sent_as_a_notification_runs_nothing() {
        let samples = samples();
        for spec in METHODS {
            let line = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": spec.name,
                "params": params_for(&samples, spec.name),
            }))
            .unwrap();
            assert_eq!(route::<PipeCall>(&line), Routed::Ignored, "{}", spec.name);
            assert_eq!(route::<StdioCall>(&line), Routed::Ignored, "{}", spec.name);
        }
        let cancel = br#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":4}}"#;
        assert_eq!(
            route::<PipeCall>(cancel),
            Routed::Cancel {
                request: RequestId(4)
            }
        );
        for bad in [
            &br#"{"jsonrpc":"2.0","method":"$/cancel"}"#[..],
            br#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":"4"}}"#,
            br#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":4,"path":"C:\\"}}"#,
        ] {
            assert_eq!(route::<StdioCall>(bad), Routed::Ignored);
        }
    }

    #[test]
    fn params_of_the_wrong_form_are_invalid_params() {
        let line = |params: &str| {
            format!(r#"{{"jsonrpc":"2.0","id":5,"method":"plan.execute","params":{params}}}"#)
        };
        for params in [
            "[]",
            r#"["p-feed000000000001","off"]"#,
            "5",
            r#""x""#,
            "{}",
            r#"{"plan_id":"p-feed000000000001"}"#,
            r#"{"plan_id":"p-feed000000000001","restore_point":"sometimes"}"#,
            r#"{"plan_id":"s-feed000000000001","restore_point":"off"}"#,
            r#"{"plan_id":"p-FEED000000000001","restore_point":"off"}"#,
            r#"{"plan_id":"p-feed000000000001","restore_point":"off","plan_id":"p-feed000000000002"}"#,
            r#"{"plan_id":"p-feed000000000001","restore_point":"off","confirm":"a1b2"}"#,
        ] {
            assert_eq!(
                routed::<PipeCall>(line(params).as_bytes()),
                Err(INVALID_PARAMS),
                "{params}"
            );
        }
        // Absent and null params read as {} for a method without params.
        for line in [
            &br#"{"jsonrpc":"2.0","id":1,"method":"engine.hello"}"#[..],
            br#"{"jsonrpc":"2.0","id":1,"method":"engine.hello","params":null}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"engine.hello","params":{}}"#,
        ] {
            assert_eq!(routed::<PipeCall>(line), Ok(Method::EngineHello));
        }
        assert_eq!(
            routed::<PipeCall>(
                br#"{"jsonrpc":"2.0","id":1,"method":"engine.hello","params":{"x":1}}"#
            ),
            Err(INVALID_PARAMS)
        );
        // An envelope error answers -32600 before the table is looked at.
        assert_eq!(
            routed::<PipeCall>(br#"[{"jsonrpc":"2.0","id":1,"method":"plan.execute"}]"#),
            Err(INVALID_REQUEST)
        );
    }

    #[test]
    fn plan_create_and_leftovers_scan_take_exactly_one_form() {
        let scan = r#""s-0123456789abcdef""#;
        let refused = [
            format!(r#"{{"scan_id":{scan}}}"#),
            format!(r#"{{"scan_id":{scan},"selected":[]}}"#),
            format!(r#"{{"scan_id":{scan},"preselected":false}}"#),
            format!(r#"{{"scan_id":{scan},"selected":["c-5a5a000000000001"],"preselected":true}}"#),
        ];
        for params in &refused {
            assert!(
                serde_json::from_str::<PlanCreateParams>(params).is_err(),
                "{params}"
            );
        }
        let session_id = r#""u-1122334455667788""#;
        for params in [
            format!(r#"{{"session_id":{session_id},"program_id":"HKLM|64|Git_is1"}}"#),
            r#"{"program_id":"HKLM|64|Git_is1","forced":true}"#.to_owned(),
            "{}".to_owned(),
        ] {
            assert!(
                serde_json::from_str::<LeftoversScanParams>(&params).is_err(),
                "{params}"
            );
        }
        let forced: LeftoversScanParams =
            serde_json::from_str(&format!(r#"{{"session_id":{session_id},"forced":true}}"#))
                .unwrap();
        assert_eq!(
            forced,
            LeftoversScanParams::Session(ScanSessionParams {
                session_id: uid(),
                forced: true
            })
        );
        for limit in ["0", "501", "-1", "1.5"] {
            let params = format!(r#"{{"scan_id":{scan},"offset":0,"limit":{limit}}}"#);
            assert!(
                serde_json::from_str::<CandidatesParams>(&params).is_err(),
                "{limit}"
            );
        }
        let undo_all: UndoParams =
            serde_json::from_str(&format!(r#"{{"session":"{}"}}"#, session())).unwrap();
        assert_eq!(undo_all.item_ids, None);
        for items in ["[]", "[0]", "[-1]"] {
            let params = format!(r#"{{"session":"{}","item_ids":{items}}}"#, session());
            assert!(
                serde_json::from_str::<UndoParams>(&params).is_err(),
                "{items}"
            );
        }
    }

    /// The names of the types a broker request may hold besides integers, booleans and enums. Each is a
    /// string of one fixed form, checked when read.
    const ID_TYPES: [&str; 7] = [
        "ProgramId",
        "SessionId",
        "UninstallSessionId",
        "ScanId",
        "PlanId",
        "ExpiryId",
        "CandidateRef",
    ];

    fn walk(
        node: &Value,
        defs: &Map<String, Value>,
        at: &str,
        out: &mut Vec<String>,
        stack: &mut Vec<String>,
    ) {
        let Some(map) = node.as_object() else {
            out.push(format!("{at}: the schema {node} takes any value"));
            return;
        };
        if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
            let name = reference.strip_prefix("#/$defs/").unwrap_or(reference);
            let Some(def) = defs.get(name) else {
                out.push(format!("{at}: unresolved {reference}"));
                return;
            };
            if ID_TYPES.contains(&name) {
                if def.get("type") != Some(&json!("string")) || def.get("pattern").is_none() {
                    out.push(format!(
                        "{at}: id type {name} is not a string of a fixed form"
                    ));
                }
                return;
            }
            if !stack.iter().any(|seen| seen == name) {
                stack.push(name.to_owned());
                walk(def, defs, &format!("{at}->{name}"), out, stack);
                stack.pop();
            }
            return;
        }
        let mut combined = false;
        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(list) = map.get(key) {
                combined = true;
                for (i, sub) in list.as_array().into_iter().flatten().enumerate() {
                    walk(sub, defs, &format!("{at}.{key}[{i}]"), out, stack);
                }
            }
        }
        let types: Vec<&str> = match map.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if types.is_empty() {
            if !combined && !map.contains_key("const") && !map.contains_key("enum") {
                out.push(format!("{at}: an untyped schema takes any value"));
            }
            return;
        }
        for t in types {
            match t {
                "null" | "boolean" | "integer" => {}
                "string" => {
                    if !map.contains_key("const") && !map.contains_key("enum") {
                        out.push(format!("{at}: a free string"));
                    }
                }
                "object" => {
                    if map.get("additionalProperties") != Some(&Value::Bool(false)) {
                        out.push(format!("{at}: an object that takes unknown members"));
                    }
                    if map.contains_key("patternProperties") {
                        out.push(format!("{at}: an object with free member names"));
                    }
                    for (name, sub) in map
                        .get("properties")
                        .and_then(Value::as_object)
                        .into_iter()
                        .flatten()
                    {
                        walk(sub, defs, &format!("{at}.{name}"), out, stack);
                    }
                }
                "array" => match map.get("items") {
                    Some(items) => walk(items, defs, &format!("{at}[]"), out, stack),
                    None => out.push(format!("{at}: an array of anything")),
                },
                other => out.push(format!("{at}: type {other} is not taken")),
            }
        }
    }

    fn shape_violations(schema: &Value) -> Vec<String> {
        let defs = schema
            .get("$defs")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        walk(schema, &defs, "$", &mut out, &mut Vec::new());
        out
    }

    #[test]
    fn broker_requests_hold_only_ids_enums_booleans_and_integers() {
        let mut walked = BTreeSet::new();
        for dto in dtos() {
            if let Direction::Request(transport) = dto.direction {
                let schema = serde_json::to_value((dto.schema)()).unwrap();
                let violations = shape_violations(&schema);
                assert!(
                    violations.is_empty(),
                    "{} ({}): {violations:#?}",
                    dto.stem,
                    dto.type_name
                );
                if transport == Transport::Pipe {
                    walked.insert(dto.type_name.to_string());
                }
            }
        }
        for name in [
            "NoParams",
            "ProgramsParams",
            "RunParams",
            "ObservedParams",
            "LeftoversScanParams",
            "CandidatesParams",
            "ExplainParams",
            "PlanCreateParams",
            "PlanExecuteParams",
            "SessionParams",
            "UndoParams",
            "ExpiringParams",
            "PurgeParams",
            "CancelParams",
        ] {
            assert!(walked.contains(name), "{name} was not walked");
        }
    }

    #[test]
    fn the_shape_walk_catches_what_it_must() {
        #![allow(dead_code)]
        use schemars::JsonSchema;

        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithPath {
            scan_id: ScanId,
            path: String,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithDocument {
            doc: Value,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithMap {
            m: BTreeMap<String, u32>,
        }
        #[derive(JsonSchema)]
        struct Open {
            n: u32,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithFloat {
            x: f64,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithModelCandidateId {
            id: purge_model::CandidateId,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithTarget {
            target: purge_model::Target,
        }
        #[derive(JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct WithNames {
            ids: Vec<ScanId>,
            names: Option<Vec<String>>,
        }
        let schemas = [
            schemars::schema_for!(WithPath),
            schemars::schema_for!(WithDocument),
            schemars::schema_for!(WithMap),
            schemars::schema_for!(Open),
            schemars::schema_for!(WithFloat),
            schemars::schema_for!(WithModelCandidateId),
            schemars::schema_for!(WithTarget),
            schemars::schema_for!(WithNames),
        ];
        for schema in schemas {
            let schema = serde_json::to_value(schema).unwrap();
            assert!(
                !shape_violations(&schema).is_empty(),
                "not caught: {schema:#}"
            );
        }
    }

    /// Paths and documents in every spelling a client might try.
    const PATHS: [&str; 7] = [
        "C:\\Windows\\System32",
        "C:/Windows/System32",
        "\\\\?\\C:\\Windows",
        "..\\..\\Windows",
        "HKLM\\SOFTWARE\\Microsoft",
        "%SystemRoot%",
        "{\"schema\":\"purge.scan/1\"}",
    ];

    /// Every object and every string position of a JSON value, as paths of keys and indexes.
    fn positions(
        value: &Value,
        at: &mut Vec<Value>,
        objects: &mut Vec<Vec<Value>>,
        strings: &mut Vec<Vec<Value>>,
    ) {
        match value {
            Value::Object(map) => {
                objects.push(at.clone());
                for (key, sub) in map {
                    at.push(json!(key));
                    positions(sub, at, objects, strings);
                    at.pop();
                }
            }
            Value::Array(list) => {
                for (i, sub) in list.iter().enumerate() {
                    at.push(json!(i));
                    positions(sub, at, objects, strings);
                    at.pop();
                }
            }
            Value::String(_) => strings.push(at.clone()),
            _ => {}
        }
    }

    fn at_mut<'a>(value: &'a mut Value, path: &[Value]) -> &'a mut Value {
        path.iter().fold(value, |node, step| match step {
            Value::String(key) => &mut node[key.as_str()],
            Value::Number(i) => &mut node[usize::try_from(i.as_u64().unwrap()).unwrap()],
            _ => unreachable!(),
        })
    }

    #[test]
    fn no_request_takes_an_extra_member_and_no_broker_request_takes_a_path() {
        let samples = samples();
        let mut strings_tried = 0;
        for dto in dtos() {
            let Direction::Request(transport) = dto.direction else {
                continue;
            };
            let fixture = &samples[&dto.stem];
            assert!(
                (dto.round_trip)(&fixture.to_string()).is_ok(),
                "{} sample",
                dto.stem
            );
            let (mut objects, mut strings) = (Vec::new(), Vec::new());
            positions(fixture, &mut Vec::new(), &mut objects, &mut strings);
            for object in &objects {
                for member in ["path", "target", "fingerprint", "scan", "plan", "document"] {
                    for extra in [json!(PATHS[0]), json!({"items": []}), Value::Null, json!(1)] {
                        let mut mutated = fixture.clone();
                        at_mut(&mut mutated, object)[member] = extra;
                        assert!(
                            (dto.round_trip)(&mutated.to_string()).is_err(),
                            "{} took {mutated}",
                            dto.stem
                        );
                    }
                }
            }
            if transport == Transport::Pipe {
                for string in &strings {
                    for path in PATHS {
                        let mut mutated = fixture.clone();
                        *at_mut(&mut mutated, string) = json!(path);
                        assert!(
                            (dto.round_trip)(&mutated.to_string()).is_err(),
                            "{} took {mutated}",
                            dto.stem
                        );
                        strings_tried += 1;
                    }
                }
            }
        }
        assert!(strings_tried > 100, "only {strings_tried} positions tried");
        // The same through the whole route: a path in a plan id is -32602, never a call.
        let line = br#"{"jsonrpc":"2.0","id":2,"method":"plan.execute","params":{"plan_id":"C:\\Windows","restore_point":"off"}}"#;
        assert_eq!(routed::<PipeCall>(line), Err(INVALID_PARAMS));
    }

    #[test]
    fn ids_have_one_form() {
        assert_eq!(scan().to_string(), "s-0123456789abcdef");
        assert_eq!("s-0123456789abcdef".parse::<ScanId>().unwrap(), scan());
        for bad in [
            "s-0123456789abcde",
            "s-0123456789abcdef0",
            "s-0123456789ABCDEF",
            "p-0123456789abcdef",
            "s_0123456789abcdef",
            " s-0123456789abcdef",
            "s-+123456789abcdef",
            "",
        ] {
            assert!(bad.parse::<ScanId>().is_err(), "{bad:?}");
        }
        let model = purge_model::CandidateId("c-5a5a000000000001".into());
        let wire = CandidateRef::try_from(&model).unwrap();
        assert_eq!(wire, cand(1));
        assert_eq!(purge_model::CandidateId::from(wire), model);
        assert!(CandidateRef::try_from(&purge_model::CandidateId("c-01".into())).is_err());

        let code = ConfirmCode::of(&hash());
        assert_eq!(code.to_string(), "A1B2-C3D4");
        assert_eq!("A1B2-C3D4".parse::<ConfirmCode>().unwrap(), code);
        for bad in [
            "a1b2-c3d4",
            "A1B2C3D4",
            "A1B2-C3D",
            "A1B2-C3D4 ",
            "+1B2-C3D4",
        ] {
            assert!(bad.parse::<ConfirmCode>().is_err(), "{bad:?}");
        }
        for bad in ["C:\\Windows", "HKLM|64|Git\\x", "HKLM|64|"] {
            assert!(bad.parse::<ProgramId>().is_err(), "{bad:?}");
        }
    }

    #[derive(Default)]
    struct Scripted {
        cancels: Vec<RequestId>,
    }

    impl Dispatcher for Scripted {
        type Call = StdioCall;

        fn call(
            &mut self,
            id: RequestId,
            call: StdioCall,
            notify: &mut dyn Notify,
        ) -> Result<Value, ErrorObject> {
            match call {
                StdioCall::EngineHello(_) => Ok(json!({"hello": true})),
                StdioCall::ProgramsList(_) => {
                    notify
                        .notify(&ServerNotification::ProgramsBatch(ProgramsBatch {
                            request: id,
                            rows: vec![],
                        }))
                        .unwrap();
                    let refused = notify.notify(&ServerNotification::ConsentShown(ConsentShown {
                        request: id,
                        code: ConfirmCode::of(&hash()),
                    }));
                    assert!(matches!(
                        refused,
                        Err(FrameError::NotOnTransport("consent.shown"))
                    ));
                    Ok(v(Started { count: 0 }))
                }
                other => Err(ErrorObject::runtime(other.method().name())),
            }
        }

        fn cancel(&mut self, request: RequestId) {
            self.cancels.push(request);
        }
    }

    #[test]
    fn serve_answers_each_request_once_and_closes_on_an_oversize_line() {
        let samples = samples();
        let mut input = Vec::new();
        let mut push = |line: &[u8]| {
            input.extend_from_slice(line);
            input.push(b'\n');
        };
        push(&request_line(1, "engine.hello", &json!({})));
        push(&request_line(
            2,
            "plan.execute",
            &samples["pipe.plan.execute.params"],
        ));
        push(br#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":2}}"#);
        push(br#"{"jsonrpc":"2.0","method":"programs.list"}"#);
        push(&request_line(3, "programs.list", &json!({})));
        push(b"[]");
        push(&vec![b' '; STDIO_IN_LIMIT + 1]);
        push(&request_line(4, "engine.hello", &json!({})));

        let mut out = Vec::new();
        let mut dispatcher = Scripted::default();
        let error = serve(&input[..], &mut out, &mut dispatcher).unwrap_err();
        assert!(matches!(
            error,
            FrameError::Oversize {
                limit: STDIO_IN_LIMIT
            }
        ));
        assert_eq!(dispatcher.cancels, vec![RequestId(2)]);

        let got: Vec<String> = out
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| match parse_server_line(line).unwrap() {
                ServerMessage::Response(Response { id, body: Ok(r) }) => format!("{id:?} ok {r}"),
                ServerMessage::Response(Response { id, body: Err(e) }) => {
                    format!("{id:?} error {}", e.code)
                }
                ServerMessage::Notification { method, .. } => format!("note {method}"),
            })
            .collect();
        assert_eq!(
            got,
            vec![
                r#"Some(RequestId(1)) ok {"hello":true}"#.to_owned(),
                format!("Some(RequestId(2)) error {METHOD_NOT_FOUND}"),
                "note programs.batch".to_owned(),
                r#"Some(RequestId(3)) ok {"count":0}"#.to_owned(),
                format!("None error {INVALID_REQUEST}"),
            ]
        );
    }

    #[test]
    fn an_answer_over_the_output_limit_becomes_a_runtime_error() {
        let mut writer = FrameWriter::new(Vec::new(), 200);
        write_response(
            &mut writer,
            &Response {
                id: Some(RequestId(5)),
                body: Ok(json!({ "x": "y".repeat(500) })),
            },
        )
        .unwrap();
        let line = writer.get_mut().strip_suffix(b"\n").unwrap().to_vec();
        let ServerMessage::Response(response) = parse_server_line(&line).unwrap() else {
            panic!("a response")
        };
        assert_eq!(response.id, Some(RequestId(5)));
        assert_eq!(response.body.unwrap_err().data.unwrap().kind(), "runtime");
    }

    #[test]
    fn notifications_read_back() {
        let note = ServerNotification::ScanProgress(progress(9, "scan", None));
        let line = serde_json::to_vec(&note).unwrap();
        let ServerMessage::Notification { method, params } = parse_server_line(&line).unwrap()
        else {
            panic!("a notification")
        };
        assert_eq!(method, "scan.progress");
        assert_eq!(ServerNotification::decode(&method, params).unwrap(), note);
        assert!(ServerNotification::decode("plan.execute", json!({})).is_err());
    }

    #[test]
    fn timings_are_optional_both_ways_and_a_line_is_flat() {
        // A result without the member reads as `None` and is written without it.
        let mut scan = samples()["pipe.leftovers.scan.result"].clone();
        scan.as_object_mut().unwrap().remove("timings");
        let read: ScanResult = serde_json::from_value(scan.clone()).unwrap();
        assert_eq!(read.timings, None);
        assert_eq!(v(&read), scan);
        // A newer member inside `timings` is ignored like any unknown result member.
        let mut with = samples()["pipe.leftovers.scan.result"].clone();
        with["timings"]["later"] = json!(1);
        let read: ScanResult = serde_json::from_value(with).unwrap();
        assert_eq!(read.timings.unwrap().marks.len(), 5);

        let line = TimingLine {
            kind: TIMING_LINE_KIND.into(),
            pid: 4242,
            process_created_unix_ms: Some(1_000),
            request: Some(RequestId(3)),
            method: Some("leftovers.scan".into()),
            mark: TimingMark {
                mark: TimingName::FirstProgress,
                ms: 12,
                wall_unix_ms: 1_012,
            },
        };
        let text = serde_json::to_value(&line).unwrap();
        assert_eq!(
            text,
            json!({
                "kind": "purge.broker.timing/1", "pid": 4242, "process_created_unix_ms": 1_000,
                "request": 3, "method": "leftovers.scan", "mark": "first_progress", "ms": 12,
                "wall_unix_ms": 1_012
            })
        );
        assert_eq!(serde_json::from_value::<TimingLine>(text).unwrap(), line);
        assert!(TimingName::PipeConnected.is_process_mark());
        assert!(!TimingName::ScanStart.is_process_mark());
    }
}
