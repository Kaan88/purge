//! The executor verbs of the CLI (M2-CLI; vm/RIG.md §11.4, §11.7).
//!
//! In every build: the exit-code table (the code, `--help` and RIG.md agree) and usage errors through
//! the real binary. Without `rig-exec`: every executor verb of the real binary answers exit code 5 and
//! creates nothing. With `rig-exec`, through [`cli::run_with_exec`] with a relaxed store in a fresh
//! temp directory (the binary itself always uses the installed store with its strict policy, and these
//! tests run unelevated) and stand-in package, locker and restore-point backends:
//!
//! - `plan from-targets` -> `exec` -> `journal show` -> `undo`, with every document parsed back;
//! - a wrong confirm, a tampered sidecar, an altered selection and a reordered plan are refused with
//!   exit code 6 and leave no session; an unelevated `exec` is refused with 7;
//! - `journal fault-points` in the rig's format;
//! - a crash injected with `PURGE_FAULT_AT` in a child process exits 0xC0000409; `journal recover`
//!   lists the session, a new `exec` is refused with 8, and `journal resume` and `journal rollback`
//!   each finish it (two separate stores);
//! - `quarantine expiring` / `purge` with the clock offset, user-data confirmation included.
//!
//! The registry is touched only below a fresh `HKU\<SID>\Software\PurgeTest-<unique>` key, removed on
//! drop; every file lives in a scratch directory below the temp directory, removed on drop.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use purge_engine::cli::Exit;
use purge_engine::cli::args::USAGE;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A name no other test or process uses.
fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{tag}-{:x}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A fresh directory below the temp directory (its final, long-form path), removed on drop.
struct Scratch {
    root: PathBuf,
    owned: bool,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(unique(&format!("purge-cli-{tag}")));
        std::fs::create_dir(&dir).unwrap();
        let mut s = Scratch::at(&dir);
        s.owned = true;
        s
    }

    /// The scratch directory `dir` of another process, which this one must not remove.
    fn at(dir: &Path) -> Scratch {
        let final_path = purge_win::fs::FileHandle::open(dir)
            .unwrap()
            .final_path()
            .unwrap();
        let root = final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&final_path)
            .to_owned();
        Scratch {
            root: PathBuf::from(root),
            owned: false,
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn file(&self, rel: &str, data: &str) -> PathBuf {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        p
    }

    /// The names directly below the root, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

/// Clears the read-only attribute of everything below `dir`, so that it can be removed.
fn make_writable(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            let mut permissions = meta.permissions();
            if permissions.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(&path, permissions);
            }
            if meta.is_dir() {
                make_writable(&path);
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.owned {
            make_writable(&self.root);
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// Runs the real binary with `args` in `cwd`, with its temp directory inside `cwd`; returns the exit
/// code, stdout and stderr.
fn binary(cwd: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let temp = cwd.join("bin-temp");
    std::fs::create_dir_all(&temp).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_purge-engine"))
        .args(args)
        .current_dir(cwd)
        .env("TEMP", &temp)
        .env("TMP", &temp)
        .env_remove("PURGE_FAULT_AT")
        .env_remove("PURGE_FAULT_PAUSE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    std::fs::remove_dir_all(&temp).unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------------------------------
// Every build
// ---------------------------------------------------------------------------------------------------

/// The exit-code table: distinct numbers 0..=12, one line each in `--help` and one row each in
/// vm/RIG.md §11.7, all with the same wording.
#[test]
fn exit_code_table() {
    let codes: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(codes, (0..=12).collect::<Vec<u8>>());
    let rig_md =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vm/RIG.md"))
            .unwrap()
            .replace("\r\n", "\n");
    let section = rig_md.split_once("### 11.7").expect("RIG.md has §11.7").1;
    for exit in Exit::ALL {
        let help_line = format!("{:>4}  {}\n", exit.code(), exit.meaning());
        assert!(USAGE.contains(&help_line), "--help lacks {help_line:?}");
        let row = format!("| {} | {} |", exit.code(), exit.meaning());
        assert!(section.contains(&row), "RIG.md §11.7 lacks {row:?}");
    }
    assert_eq!(Exit::NeedsConsent.code(), 5);
    assert_eq!(Exit::PlanRefused.code(), 6);
    assert_eq!(Exit::NeedsElevation.code(), 7);
    assert_eq!(Exit::NeedsRecovery.code(), 8);
    assert_eq!(Exit::StoreIntegrity.code(), 9);
    assert_eq!(Exit::Partial.code(), 10);
    assert_eq!(Exit::UndoConflicts.code(), 11);
    assert_eq!(Exit::Unrecorded.code(), 12);
}

/// Usage errors of every executor verb come back from the binary as exit code 2, with the usage text,
/// in every build.
#[test]
fn executor_usage_errors_through_the_binary() {
    let s = Scratch::new("usage");
    for line in [
        "exec --plan p.json",
        "exec --plan p.json --confirm c --restore-point never",
        "exec --plan p.json --confirm c --data-root d",
        "undo",
        "journal show",
        "journal recover extra",
        "journal frobnicate",
        "quarantine purge --ids s/1",
        "quarantine purge --ids s/1 --yes-irreversible --confirm-user-data s/2",
        "plan from-targets t.json",
    ] {
        let args: Vec<&str> = line.split_whitespace().collect();
        let (code, out, err) = binary(&s.root, &args);
        assert_eq!(code, Some(2), "{line}: {err}");
        assert!(out.is_empty(), "{line}");
        assert!(err.contains("usage:"), "{line}: {err}");
    }
    let (code, out, _) = binary(&s.root, &["--help"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("journal fault-points") && out.contains("exit codes:"));
    assert!(s.names().is_empty(), "{:?}", s.names());
}

// ---------------------------------------------------------------------------------------------------
// Without rig-exec
// ---------------------------------------------------------------------------------------------------

/// A normal build refuses every executor verb with exit code 5 and creates nothing: no output file, no
/// sidecar, nothing in its working or temp directory.
#[cfg(not(feature = "rig-exec"))]
#[test]
fn default_build_refuses_every_executor_verb_and_creates_nothing() {
    let s = Scratch::new("consent");
    s.file("targets.json", "{}");
    s.file("plan.json", "{}");
    s.file("plan.scan.json", "{}");
    s.file("ids.json", "[]");
    let before = s.names();
    for (line, why) in [
        (
            "exec --plan plan.json --confirm 00 --select ids.json -o report.json",
            "needs the consent dialog",
        ),
        (
            "undo --session s1 --items ids.json -o undo.json",
            "needs the consent dialog",
        ),
        ("journal recover", "needs the consent dialog"),
        ("journal resume", "needs the consent dialog"),
        ("journal resume --session s1", "needs the consent dialog"),
        ("journal rollback --session s1", "needs the consent dialog"),
        ("journal show --session s1", "needs the consent dialog"),
        (
            "journal retry-held --session s1",
            "needs the consent dialog",
        ),
        ("quarantine expiring", "needs the consent dialog"),
        (
            "quarantine purge --ids s/1 s/2 --yes-irreversible",
            "needs the consent dialog",
        ),
        ("journal fault-points", "test tool of the VM rig"),
        (
            "plan from-targets targets.json -o out-plan.json",
            "test tool of the VM rig",
        ),
    ] {
        let args: Vec<&str> = line.split_whitespace().collect();
        let (code, out, err) = binary(&s.root, &args);
        assert_eq!(code, Some(5), "{line}: {err}");
        assert!(out.is_empty(), "{line}: {out}");
        assert!(err.contains(why), "{line}: {err}");
        assert_eq!(s.names(), before, "{line} created something");
    }
    // The version names no rig-exec build.
    let (code, out, _) = binary(&s.root, &["--version"]);
    assert_eq!(code, Some(0));
    assert!(!out.contains("rig-exec"), "{out}");
}

/// Review M2 M23: the binary of a normal build holds none of the executor's strings: not the rig-exec
/// build marker, not the fault-injection variable, not the executor's journal schema. The same check in
/// a rig-exec build finds them, so the strings are a valid witness.
#[test]
fn the_binary_holds_the_executor_strings_only_in_a_rig_exec_build() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_purge-engine")).unwrap();
    let holds = |text: &str| exe.windows(text.len()).any(|w| w == text.as_bytes());
    for marker in [
        "rig-exec build: executor verbs run headless",
        "PURGE_FAULT_AT",
        "purge.cli.recovered/1",
    ] {
        assert_eq!(holds(marker), cfg!(feature = "rig-exec"), "{marker}");
    }
}

// ---------------------------------------------------------------------------------------------------
// With rig-exec
// ---------------------------------------------------------------------------------------------------

#[cfg(feature = "rig-exec")]
mod rig {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use purge_engine::cli::exec::{BUILD_MARKER, ExecHost};
    use purge_engine::cli::{Env, Exit, run_with_exec};
    use purge_engine::pipeline::{Settings, Sources};
    use purge_exec::act_typed::{ListError, PackageBackend, PackageInfo};
    use purge_exec::fault;
    use purge_exec::locked::MemoryPendingRenames;
    use purge_exec::plan_in::{confirm_hash, selection_hash};
    use purge_exec::prepare::{LockerQuery, RestorePointBackend};
    use purge_exec::storage::StorageRoots;
    use purge_inventory::runner::{LiveHost, RunOptions};
    use purge_model::exec::session::{ExecReport, SessionId, SessionState, UndoReport};
    use purge_model::{CandidateId, Plan};
    use purge_plan::emit::ScanDoc;
    use purge_source::live::Live;
    use purge_win::appx_write::{RemovalScope, RemoveOutcome};
    use purge_win::os::Win32Error;
    use purge_win::reg::{REG_SZ, RegRoot, RegView};
    use purge_win::reg_write::{KeyAccess, WKey};
    use purge_win::rm::{LockerList, RebootReasons};
    use purge_win::sid::current_user_sid;
    use purge_win::sr::SrOutcome;
    use serde_json::{Value, json};

    use super::{Scratch, binary, unique};

    /// The child test's variables: its data root and its command line (a JSON array).
    const CHILD_DATA: &str = "PURGE_CLI_TEST_CHILD_DATA";
    const CHILD_ARGS: &str = "PURGE_CLI_TEST_CHILD_ARGS";
    /// `std::process::abort` of an injected fault: STATUS_STACK_BUFFER_OVERRUN.
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    // -----------------------------------------------------------------------------------------------
    // Stand-ins
    // -----------------------------------------------------------------------------------------------

    /// No package is installed; nothing is removed.
    struct NoPackages;

    impl PackageBackend for NoPackages {
        fn list(&self, _: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
            Ok(Vec::new())
        }
        fn remove(&self, _: &str, _: RemovalScope) -> RemoveOutcome {
            RemoveOutcome::NotFound
        }
    }

    /// Nothing holds any file.
    struct NoLockers;

    impl LockerQuery for NoLockers {
        fn query(&self, _: &[PathBuf]) -> Result<LockerList, Win32Error> {
            Ok(LockerList {
                lockers: Vec::new(),
                reboot_reasons: RebootReasons(0),
            })
        }
    }

    /// A restore point is "created" without asking Windows.
    #[derive(Clone)]
    struct FakeRestore;

    impl RestorePointBackend for FakeRestore {
        fn create(&self, _: &str) -> SrOutcome {
            SrOutcome::Created { seq: 7 }
        }
    }

    // -----------------------------------------------------------------------------------------------
    // The registry
    // -----------------------------------------------------------------------------------------------

    /// A fresh `HKU\<SID>\Software\PurgeTest-<unique>` key, removed with everything below it on drop.
    struct TestKey {
        rel: String,
    }

    impl TestKey {
        fn new() -> TestKey {
            let sid = current_user_sid().unwrap();
            let name = unique("PurgeTest");
            WKey::open(
                RegRoot::Hku,
                &format!(r"{sid}\Software"),
                RegView::K64,
                KeyAccess::CREATE_SUB_KEY,
            )
            .unwrap()
            .create_subkey(&name, "", None, false)
            .unwrap();
            TestKey {
                rel: format!(r"{sid}\Software\{name}"),
            }
        }

        fn wire(&self, sub: &str) -> String {
            format!(r"HKU\{}\{sub}", self.rel)
        }

        fn open(&self, sub: &str, access: KeyAccess) -> Option<WKey> {
            WKey::open(
                RegRoot::Hku,
                &format!(r"{}\{sub}", self.rel),
                RegView::K64,
                access,
            )
            .ok()
        }

        /// Creates `sub` with one string value `v`.
        fn create(&self, sub: &str, value: &str) {
            WKey::open(
                RegRoot::Hku,
                &self.rel,
                RegView::K64,
                KeyAccess::CREATE_SUB_KEY,
            )
            .unwrap()
            .create_subkey(sub, "", None, false)
            .unwrap();
            let data: Vec<u8> = value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            self.open(sub, KeyAccess::SET_VALUE)
                .unwrap()
                .set_value_raw("v", REG_SZ, &data)
                .unwrap();
        }

        /// The raw data of value `v` of `sub`, `None` when the key is absent.
        fn value(&self, sub: &str) -> Option<Vec<u8>> {
            let key = self.open(sub, KeyAccess::READ)?;
            key.value("v").unwrap().map(|v| v.data)
        }

        fn nuke(key: &WKey) {
            for sub in key.subkey_names().unwrap_or_default() {
                if let Ok(child) = key.open_subkey(&sub, KeyAccess::DELETE) {
                    Self::nuke(&child);
                }
            }
            let _ = key.delete();
        }
    }

    impl Drop for TestKey {
        fn drop(&mut self) {
            if let Ok(root) = WKey::open(RegRoot::Hku, &self.rel, RegView::K64, KeyAccess::DELETE) {
                Self::nuke(&root);
            }
        }
    }

    // -----------------------------------------------------------------------------------------------
    // Driving the CLI
    // -----------------------------------------------------------------------------------------------

    /// One CLI run through `run_with_exec` on the relaxed store `roots`.
    struct Run {
        exit: Exit,
        out: String,
        err: String,
    }

    impl Run {
        fn json(&self) -> Value {
            serde_json::from_str(&self.out).unwrap_or_else(|e| panic!("{e}: {}", self.out))
        }
    }

    fn cli_with(
        roots: &StorageRoots,
        args: &[String],
        elevated: bool,
        offset: Result<i64, String>,
    ) -> Run {
        let live = Live::new();
        let mut process_host = LiveHost::new();
        let packages = NoPackages;
        let lockers = NoLockers;
        let mut pending = MemoryPendingRenames::with_pairs(&[]);
        let mut host = ExecHost {
            roots: Ok(roots.clone()),
            elevated,
            packages: &packages,
            objects: None,
            lockers: &lockers,
            pending_renames: &mut pending,
            restore_points: FakeRestore,
            now_offset_days: offset,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = run_with_exec(
            args,
            &mut Env {
                sources: Sources {
                    reg: &live.registry,
                    fs: &live.fs,
                    sys: &live.system,
                },
                host: &mut process_host,
                settings: Settings::default(),
                run_options: RunOptions::default(),
                stdout: &mut out,
                stderr: &mut err,
            },
            &mut host,
        );
        Run {
            exit,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn cli(roots: &StorageRoots, args: &[String]) -> Run {
        cli_with(roots, args, true, Ok(0))
    }

    fn args(parts: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<String> {
        parts
            .iter()
            .map(|p| p.as_ref().to_string_lossy().into_owned())
            .collect()
    }

    /// A scratch directory with a fresh relaxed store in `data`.
    struct Fixture {
        s: Scratch,
        roots: StorageRoots,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let s = Scratch::new(tag);
            let roots = StorageRoots::install_relaxed(&s.path("data")).unwrap();
            Fixture { s, roots }
        }

        fn sessions(&self) -> Vec<SessionId> {
            self.roots.list_sessions().unwrap().sessions
        }

        /// Writes a `purge.rig.targets/0` document and plans it; returns the plan path and the plan
        /// hash.
        fn plan(&self, name: &str, targets: Value) -> (PathBuf, String) {
            let doc = json!({
                "schema": "purge.rig.targets/0", "source": "exec_cli.rs", "origin": "ManualUser",
                "targets": targets,
            });
            let t = self
                .s
                .file(&format!("{name}-targets.json"), &doc.to_string());
            let plan = self.s.path(&format!("{name}.json"));
            let run = cli(
                &self.roots,
                &args(&[&"plan", &"from-targets", &t, &"-o", &plan]),
            );
            assert_eq!(run.exit, Exit::Ok, "{}", run.err);
            let scan: ScanDoc = read(&self.s.path(&format!("{name}.scan.json")));
            (plan, scan.plan_hash)
        }

        /// Writes an id list.
        fn ids(&self, name: &str, ids: &[&str]) -> PathBuf {
            self.s.file(name, &json!(ids).to_string())
        }
    }

    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn confirm(plan_hash: &str, ids: &[&str]) -> String {
        let ids: Vec<CandidateId> = ids.iter().map(|i| CandidateId((*i).to_owned())).collect();
        confirm_hash(plan_hash.parse().unwrap(), selection_hash(&ids)).to_string()
    }

    fn quarantine(id: &str, path: &Path) -> Value {
        json!({ "id": id, "trap": "t", "group": "main",
                "target": { "type": "Path", "path": path }, "action": "Quarantine" })
    }

    // -----------------------------------------------------------------------------------------------
    // The tests
    // -----------------------------------------------------------------------------------------------

    /// `plan from-targets` -> `exec` -> `journal show` -> `undo` -> `journal recover`, every document
    /// parsed back.
    #[test]
    fn plan_exec_show_undo_round_trip() {
        let f = Fixture::new("round");
        let key = TestKey::new();
        key.create("App", "hello");
        let dir = f.s.file(r"work\app\a.txt", "alpha");
        let dir = dir.parent().unwrap().to_path_buf();
        f.s.file(r"work\app\sub\b.txt", "beta");
        let single = f.s.file(r"work\single.txt", "single");
        let ids = ["files.dir", "single", "reg.key"];
        let (plan_path, hash) = f.plan(
            "plan",
            json!([
                quarantine("files.dir", &dir),
                quarantine("single", &single),
                { "id": "reg.key", "target": { "type": "RegKey", "path": key.wire("App") },
                  "action": "DeleteKey" },
            ]),
        );
        // The plan and its sidecar: the rig's ids, in order, ManualUser, Safe and preselected.
        let plan: Plan = read(&plan_path);
        let scan: ScanDoc = read(&f.s.path("plan.scan.json"));
        assert_eq!(plan.items.len(), 3);
        assert!(plan.items.iter().all(|i| i.preselected));
        let scan_ids: Vec<&str> = scan.items.iter().map(|c| c.id.0.as_str()).collect();
        assert_eq!(scan_ids, ids);
        assert!(
            scan.items
                .iter()
                .all(|c| c.origin == purge_model::Origin::ManualUser)
        );
        assert_eq!(
            scan.plan_hash,
            purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode)
        );

        let select = f.ids("select.json", &ids);
        let report_path = f.s.path("report.json");
        let run = cli(
            &f.roots,
            &args(&[
                &"exec",
                &"--plan",
                &plan_path,
                &"--confirm",
                &confirm(&hash, &ids),
                &"--select",
                &select,
                &"--restore-point",
                &"off",
                &"-o",
                &report_path,
            ]),
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let report: ExecReport = serde_json::from_str(&run.out).unwrap();
        assert_eq!(report, read::<ExecReport>(&report_path));
        assert_eq!(report.state, SessionState::Committed);
        assert_eq!(report.items.len(), 3);
        assert!(
            report.items.iter().all(|i| i.outcome.is_success()),
            "{report:?}"
        );
        assert_eq!(f.sessions(), std::slice::from_ref(&report.session));
        assert!(
            run.err.contains(&format!("session {}", report.session)),
            "{}",
            run.err
        );
        assert!(!dir.exists() && !single.exists());
        assert_eq!(key.value("App"), None);
        // The report is pure JSON: one document on stdout.
        let doc = run.json();
        assert_eq!(doc["schema"], "purge.exec/1");

        let session = report.session.to_string();
        let run = cli(
            &f.roots,
            &args(&[&"journal", &"show", &"--session", &session]),
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let shown = run.json();
        assert_eq!(shown["schema"], "purge.cli.journal/1");
        assert_eq!(shown["session"], session.as_str());
        assert_eq!(shown["finished"], true);
        assert_eq!(shown["index_mark"], "matches");
        assert_eq!(shown["ops"].as_array().unwrap().len(), 3);
        assert_eq!(shown["header"]["plan_hash"], hash.as_str());
        assert!(!shown["journal"].as_array().unwrap().is_empty());

        let undo_path = f.s.path("undo.json");
        let run = cli(
            &f.roots,
            &args(&[
                &"undo",
                &"--session",
                &session,
                &"--confirm",
                &hash,
                &"-o",
                &undo_path,
            ]),
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let undone: UndoReport = serde_json::from_str(&run.out).unwrap();
        assert_eq!(undone, read::<UndoReport>(&undo_path));
        assert_eq!(undone.counts.restored, 3, "{undone:?}");
        assert_eq!(undone.state, SessionState::Undone);
        assert_eq!(std::fs::read_to_string(dir.join("a.txt")).unwrap(), "alpha");
        assert_eq!(
            std::fs::read_to_string(dir.join(r"sub\b.txt")).unwrap(),
            "beta"
        );
        assert_eq!(std::fs::read_to_string(&single).unwrap(), "single");
        assert!(key.value("App").is_some());

        let run = cli(&f.roots, &args(&[&"journal", &"recover"]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["sessions"], json!([]));

        // An undo under another plan hash or of an unknown item is refused.
        let other = "0".repeat(64);
        let run = cli(
            &f.roots,
            &args(&[&"undo", &"--session", &session, &"--confirm", &other]),
        );
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        let unknown = f.ids("unknown.json", &["nope"]);
        let run = cli(
            &f.roots,
            &args(&[&"undo", &"--session", &session, &"--items", &unknown]),
        );
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        // An unknown session is a usage error.
        let run = cli(
            &f.roots,
            &args(&[&"undo", &"--session", &"20261115T101502Z-9f3a6c1d2b7e4a50"]),
        );
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);
        let run = cli(
            &f.roots,
            &args(&[&"journal", &"show", &"--session", &"../x"]),
        );
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);
    }

    /// A wrong confirm, a tampered sidecar, an altered selection and a reordered plan are refused with
    /// exit code 6 before a session exists; an unelevated exec is refused with 7.
    #[test]
    fn refusals_leave_no_session_and_no_report() {
        let f = Fixture::new("refuse");
        let one = f.s.file(r"work\one.txt", "one");
        let two = f.s.file(r"work\two.txt", "two");
        let targets = json!([quarantine("one", &one), quarantine("two", &two)]);
        let (plan, hash) = f.plan("plan", targets.clone());
        let ids = ["one", "two"];
        let select = f.ids("select.json", &ids);
        let good = confirm(&hash, &ids);
        let report = f.s.path("report.json");
        let exec = |plan: &Path, confirm: &str, select: &Path, elevated: bool| {
            cli_with(
                &f.roots,
                &args(&[
                    &"exec",
                    &"--plan",
                    &plan,
                    &"--confirm",
                    &confirm,
                    &"--select",
                    &select,
                    &"--restore-point",
                    &"off",
                    &"-o",
                    &report,
                ]),
                elevated,
                Ok(0),
            )
        };
        let unchanged = || {
            assert!(f.sessions().is_empty());
            assert!(!report.exists());
            assert!(one.exists() && two.exists());
        };

        // Wrong confirm.
        let run = exec(&plan, &"0".repeat(64), &select, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        assert!(run.out.is_empty());
        unchanged();
        // A malformed confirm.
        let run = exec(&plan, "abc", &select, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        unchanged();

        // A sidecar with a path changed: it no longer matches the plan.
        let tampered = f.s.path("plan-t.json");
        std::fs::copy(&plan, &tampered).unwrap();
        let sidecar = std::fs::read_to_string(f.s.path("plan.scan.json")).unwrap();
        assert!(sidecar.contains("two.txt"));
        f.s.file(
            "plan-t.scan.json",
            &sidecar.replacen("two.txt", "twp.txt", 1),
        );
        let run = exec(&tampered, &good, &select, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        assert!(
            run.err.contains("does not match its sidecar"),
            "{}",
            run.err
        );
        unchanged();
        // A sidecar with an id changed: the plan matches, the plan hash does not.
        let mut scan: Value = serde_json::from_str(&sidecar).unwrap();
        scan["items"][1]["id"] = json!("tw0");
        f.s.file("plan-t.scan.json", &scan.to_string());
        let run = exec(&tampered, &good, &select, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        assert!(
            run.err.contains("changed after it was hashed"),
            "{}",
            run.err
        );
        unchanged();
        // No sidecar at all.
        std::fs::remove_file(f.s.path("plan-t.scan.json")).unwrap();
        let run = exec(&tampered, &good, &select, true);
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);
        unchanged();

        // An altered selection: one id dropped, or one the plan does not hold.
        let fewer = f.ids("fewer.json", &["one"]);
        let run = exec(&plan, &good, &fewer, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        unchanged();
        let more = f.ids("more.json", &["one", "two", "three"]);
        let run = exec(&plan, &good, &more, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        unchanged();

        // The same targets planned in reverse order, with the confirm of the first plan.
        let mut reversed = targets.as_array().unwrap().clone();
        reversed.reverse();
        let (plan_r, hash_r) = f.plan("plan-r", Value::Array(reversed));
        assert_ne!(hash_r, hash);
        let run = exec(&plan_r, &good, &select, true);
        assert_eq!(run.exit, Exit::PlanRefused, "{}", run.err);
        unchanged();

        // Unelevated.
        let run = exec(&plan, &good, &select, false);
        assert_eq!(run.exit, Exit::NeedsElevation, "{}", run.err);
        unchanged();
        for line in [
            vec!["undo", "--session", "20261115T101502Z-9f3a6c1d2b7e4a50"],
            vec!["journal", "resume"],
            vec!["journal", "rollback"],
            vec![
                "quarantine",
                "purge",
                "--ids",
                "20261115T101502Z-9f3a6c1d2b7e4a50/1",
                "--yes-irreversible",
            ],
        ] {
            let line: Vec<String> = line.into_iter().map(String::from).collect();
            let run = cli_with(&f.roots, &line, false, Ok(0));
            assert_eq!(run.exit, Exit::NeedsElevation, "{line:?}: {}", run.err);
        }

        // With the right confirm the same plan runs.
        let run = exec(&plan, &good, &select, true);
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(f.sessions().len(), 1);
        assert!(!one.exists() && !two.exists());
    }

    /// `journal fault-points` prints every declared point, one per line, in the format the rig parses
    /// (`ConvertFrom-M2FaultPoints`: a dotted lower-case name at the start of the line).
    #[test]
    fn fault_points_in_the_rig_format() {
        let f = Fixture::new("faultpoints");
        let run = cli(&f.roots, &args(&[&"journal", &"fault-points"]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let mut names = Vec::new();
        for line in run.out.lines() {
            let (name, description) = line.split_once('\t').expect("name TAB description");
            assert!(!description.is_empty(), "{line}");
            let mut parts = name.split('.');
            let first = parts.next().unwrap();
            assert!(
                first.starts_with(|c: char| c.is_ascii_lowercase()),
                "{name}"
            );
            let rest: Vec<&str> = parts.collect();
            assert!(!rest.is_empty(), "{name} has no dot");
            for part in std::iter::once(first).chain(rest) {
                assert!(
                    !part.is_empty()
                        && part
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "{name}"
                );
            }
            names.push(name.to_owned());
        }
        assert_eq!(names, fault::FAULT_POINTS);
        assert_eq!(names.len(), 19);
    }

    /// The child half of the crash test: runs the command line of [`CHILD_ARGS`] on the store at
    /// [`CHILD_DATA`] and exits with the CLI's exit code, unless the fault point the parent set kills it
    /// first. Does nothing when run as an ordinary test.
    #[test]
    fn child_cli() {
        let (Some(data), Ok(line)) = (std::env::var_os(CHILD_DATA), std::env::var(CHILD_ARGS))
        else {
            return;
        };
        let roots = StorageRoots::relaxed(Path::new(&data)).unwrap();
        let line: Vec<String> = serde_json::from_str(&line).unwrap();
        let run = cli(&roots, &line);
        std::process::exit(i32::from(run.exit.code()));
    }

    /// Runs [`child_cli`] with `line` and the fault variable `at`; returns the exit code.
    fn spawn(f: &Fixture, line: &[String], at: &str) -> Option<i32> {
        let temp = f.s.path("child-temp");
        std::fs::create_dir_all(&temp).unwrap();
        let code = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rig::child_cli", "--test-threads=1"])
            .env(CHILD_DATA, f.roots.data_root())
            .env(CHILD_ARGS, serde_json::to_string(line).unwrap())
            .env(fault::ENV_AT, at)
            .env_remove(fault::ENV_PAUSE)
            .env("TEMP", &temp)
            .env("TMP", &temp)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code();
        let _ = std::fs::remove_dir_all(&temp);
        code
    }

    /// Plans two files and kills `exec` after the first one moved; `journal recover` lists the session
    /// (and changes nothing), a new `exec` is refused with 8, then `journal <after>` finishes it.
    fn crash_and(after: &str) {
        let f = Fixture::new(&format!("crash-{after}"));
        let one = f.s.file(r"work\one.txt", "one");
        let two = f.s.file(r"work\two.txt", "two");
        let (plan, hash) = f.plan(
            "plan",
            json!([quarantine("one", &one), quarantine("two", &two)]),
        );
        let ids = ["one", "two"];
        let select = f.ids("select.json", &ids);
        let report = f.s.path("report.json");
        let line = args(&[
            &"exec",
            &"--plan",
            &plan,
            &"--confirm",
            &confirm(&hash, &ids),
            &"--select",
            &select,
            &"--restore-point",
            &"off",
            &"-o",
            &report,
        ]);
        assert_eq!(spawn(&f, &line, "act.after"), Some(ABORT_CODE));
        assert!(!report.exists());
        assert!(!one.exists() && two.exists());
        let [session]: [SessionId; 1] = f.sessions().try_into().unwrap();

        for _ in 0..2 {
            let run = cli(&f.roots, &args(&[&"journal", &"recover"]));
            assert_eq!(run.exit, Exit::Ok, "{}", run.err);
            let doc = run.json();
            assert_eq!(doc["schema"], "purge.cli.recover/1");
            let listed = doc["sessions"].as_array().unwrap();
            assert_eq!(listed.len(), 1, "{doc}");
            assert_eq!(listed[0]["session"], session.to_string().as_str());
            assert_eq!(listed[0]["kind"], "Run");
            assert_eq!(listed[0]["open_intents"], json!([1]));
            assert_eq!(listed[0]["probes"][0]["result"]["probe"], "Done", "{doc}");
            assert!(!one.exists() && two.exists());
        }

        // No new run while this one waits for recovery.
        let three = f.s.file(r"work\three.txt", "three");
        let (plan3, hash3) = f.plan("plan3", json!([quarantine("three", &three)]));
        let run = cli(
            &f.roots,
            &args(&[
                &"exec",
                &"--plan",
                &plan3,
                &"--confirm",
                &confirm(&hash3, &["three"]),
            ]),
        );
        assert_eq!(run.exit, Exit::NeedsRecovery, "{}", run.err);
        assert!(three.exists());
        assert_eq!(f.sessions().len(), 1);

        let id = session.to_string();
        let run = cli(&f.roots, &args(&[&"journal", &after, &"--session", &id]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let doc = run.json();
        assert_eq!(doc["schema"], "purge.cli.recovered/1");
        assert_eq!(doc["mode"], after);
        assert_eq!(doc["sessions"][0]["session"], id.as_str());
        match after {
            "resume" => {
                assert_eq!(doc["sessions"][0]["state"], "Committed", "{doc}");
                assert!(!one.exists() && !two.exists());
            }
            _ => {
                assert_eq!(doc["sessions"][0]["state"], "Undone", "{doc}");
                assert_eq!(std::fs::read_to_string(&one).unwrap(), "one");
                assert_eq!(std::fs::read_to_string(&two).unwrap(), "two");
            }
        }
        let run = cli(&f.roots, &args(&[&"journal", &"recover"]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["sessions"], json!([]));
        // A second recovery finds nothing to do.
        let run = cli(&f.roots, &args(&[&"journal", &after]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["sessions"], json!([]));
        let run = cli(&f.roots, &args(&[&"journal", &"show", &"--session", &id]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["finished"], true);
    }

    #[test]
    fn crash_then_journal_resume_finishes_the_run() {
        crash_and("resume");
    }

    #[test]
    fn crash_then_journal_rollback_restores_the_run() {
        crash_and("rollback");
    }

    /// A malformed fault variable is a usage error before anything runs.
    #[test]
    fn a_malformed_fault_variable_is_refused() {
        let f = Fixture::new("badfault");
        let line = args(&[&"journal", &"recover"]);
        assert_eq!(spawn(&f, &line, "no.such.point"), Some(2));
        assert_eq!(spawn(&f, &line, ""), Some(0));
    }

    /// `quarantine expiring` lists nothing today and both items 400 days on; `purge` needs
    /// `--yes-irreversible`, elevation and, for a user-data item, `--confirm-user-data`.
    #[test]
    fn quarantine_expiring_and_purge_with_the_clock_offset() {
        let f = Fixture::new("expiry");
        let app = f.s.file(r"work\app.txt", "app");
        let user = f.s.file(r"work\user.txt", "user");
        let mut user_target = quarantine("user", &user);
        user_target["category"] = json!("UserData");
        let (plan, hash) = f.plan("plan", json!([quarantine("app", &app), user_target]));
        let run = cli(
            &f.roots,
            &args(&[
                &"exec",
                &"--plan",
                &plan,
                &"--confirm",
                &confirm(&hash, &["app", "user"]),
            ]),
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let report: ExecReport = serde_json::from_str(&run.out).unwrap();
        let session = report.session.to_string();
        let (id_app, id_user) = (format!("{session}/1"), format!("{session}/2"));

        let expiring = |offset: Result<i64, String>| {
            cli_with(
                &f.roots,
                &args(&[&"quarantine", &"expiring"]),
                false,
                offset,
            )
        };
        let run = expiring(Ok(0));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["items"], json!([]));
        let run = expiring(Err("bad offset".into()));
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);

        let run = expiring(Ok(400));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let doc = run.json();
        assert_eq!(doc["schema"], "purge.cli.expiring/1");
        assert_eq!(doc["offset_days"], 400);
        let items = doc["items"].as_array().unwrap();
        assert_eq!(items.len(), 2, "{doc}");
        assert_eq!(items[0]["id"], id_app.as_str());
        assert_eq!(items[0]["original_path"], app.to_str().unwrap());
        assert_eq!(items[0]["user_data"], false);
        assert_eq!(items[1]["id"], id_user.as_str());
        assert_eq!(items[1]["user_data"], true);

        let purge = |ids: &[&str], extra: &[&str], elevated: bool| {
            let mut line = vec!["quarantine", "purge", "--ids"];
            line.extend_from_slice(ids);
            line.extend_from_slice(extra);
            let line: Vec<String> = line.into_iter().map(String::from).collect();
            cli_with(&f.roots, &line, elevated, Ok(400))
        };
        let both = [id_app.as_str(), id_user.as_str()];
        let run = purge(&both, &[], true);
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);
        let run = purge(&both, &["--yes-irreversible"], false);
        assert_eq!(run.exit, Exit::NeedsElevation, "{}", run.err);
        let run = purge(&["nope"], &["--yes-irreversible"], true);
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);

        // Without the user-data confirmation the user-data item stays.
        let run = purge(&both, &["--yes-irreversible"], true);
        assert_eq!(run.exit, Exit::Partial, "{}", run.err);
        let doc = run.json();
        assert_eq!(doc["schema"], "purge.cli.purge/1");
        assert_eq!(doc["items"][0]["outcome"], "Purged", "{doc}");
        assert_eq!(doc["items"][1]["outcome"], "Excluded", "{doc}");
        assert!(run.err.contains(app.to_str().unwrap()), "{}", run.err);

        let run = purge(
            &[id_user.as_str()],
            &[
                "--yes-irreversible",
                "--confirm-user-data",
                id_user.as_str(),
            ],
            true,
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["items"][0]["outcome"], "Purged");
        let run = expiring(Ok(400));
        assert_eq!(run.json()["items"], json!([]), "{}", run.out);
        assert!(!app.exists() && !user.exists());
    }

    /// The real binary of a rig-exec build: it names itself, lists the fault points, and refuses
    /// `exec` unelevated with 7 before reading anything.
    #[test]
    fn the_rig_exec_binary() {
        let s = Scratch::new("binary");
        let (code, out, _) = binary(&s.root, &["--version"]);
        assert_eq!(code, Some(0));
        assert!(out.contains(BUILD_MARKER), "{out}");
        let (code, out, _) = binary(&s.root, &["journal", "fault-points"]);
        assert_eq!(code, Some(0));
        assert_eq!(out.lines().count(), fault::FAULT_POINTS.len());
        let elevated = {
            use purge_source::system::SystemSource;
            Live::new().system.elevated()
        };
        if !elevated {
            let (code, _, err) = binary(
                &s.root,
                &[
                    "exec",
                    "--plan",
                    "missing.json",
                    "--confirm",
                    "x",
                    "-o",
                    "r.json",
                ],
            );
            assert_eq!(code, Some(7), "{err}");
            assert!(err.contains("elevated"), "{err}");
        }
        assert!(s.names().is_empty(), "{:?}", s.names());
    }

    /// Runs `exec` of the selected `ids` of `plan` without a restore point.
    fn exec(f: &Fixture, plan: &Path, hash: &str, ids: &[&str]) -> Run {
        let select = f.ids(&format!("select-{}.json", unique("sel")), ids);
        cli(
            &f.roots,
            &args(&[
                &"exec",
                &"--plan",
                &plan,
                &"--confirm",
                &confirm(hash, ids),
                &"--select",
                &select,
                &"--restore-point",
                &"off",
            ]),
        )
    }

    /// `journal retry-held --session`: an item in use during `exec` is held (exit 10); a retry while it
    /// is still in use keeps it held (10); once released, the retry moves it (0) and a second retry has
    /// nothing to do (0). Unelevated it is refused with 7, an unknown session with 2.
    #[test]
    fn journal_retry_held_moves_a_released_item() {
        use std::os::windows::fs::OpenOptionsExt;

        let f = Fixture::new("retryheld");
        let busy = f.s.file(r"work\busy.txt", "busy");
        let (plan, hash) = f.plan("plan", json!([quarantine("busy", &busy)]));
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&busy)
            .unwrap();
        let run = exec(&f, &plan, &hash, &["busy"]);
        assert_eq!(run.exit, Exit::Partial, "{}", run.err);
        let report: ExecReport = serde_json::from_str(&run.out).unwrap();
        assert_eq!(
            report.items[0].outcome,
            purge_model::exec::op::ItemOutcome::HeldRetry,
            "{report:?}"
        );
        let session = report.session.to_string();
        let retry = |elevated: bool| {
            cli_with(
                &f.roots,
                &args(&[&"journal", &"retry-held", &"--session", &session]),
                elevated,
                Ok(0),
            )
        };
        let run = retry(false);
        assert_eq!(run.exit, Exit::NeedsElevation, "{}", run.err);
        let run = retry(true);
        assert_eq!(run.exit, Exit::Partial, "{}", run.err);
        assert_eq!(
            run.json()["retried"][0]["outcome"]["kind"],
            "HeldRetry",
            "{}",
            run.out
        );
        assert!(busy.exists());

        drop(lock);
        let run = retry(true);
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        let doc = run.json();
        assert_eq!(doc["schema"], "purge.cli.retried/1");
        assert_eq!(doc["session"], session.as_str());
        assert_eq!(
            doc["retried"],
            json!([{ "op": 1, "outcome": { "kind": "Done" } }]),
            "{doc}"
        );
        assert_eq!(doc["index_updated"], true);
        assert!(!busy.exists());
        let run = retry(true);
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["retried"], json!([]));
        let run = cli(
            &f.roots,
            &args(&[
                &"journal",
                &"retry-held",
                &"--session",
                &"20261115T101502Z-9f3a6c1d2b7e4a50",
            ]),
        );
        assert_eq!(run.exit, Exit::Usage, "{}", run.err);
    }

    /// Review M2 M21: a run or an undo whose index entry cannot be written ends with 12, the document
    /// still written; `journal resume` then brings the entry up to date and ends with 0.
    #[test]
    fn an_unwritten_index_entry_is_not_exit_zero() {
        use std::os::windows::fs::OpenOptionsExt;

        let f = Fixture::new("unrecorded");
        let a = f.s.file(r"work\a.txt", "a");
        let b = f.s.file(r"work\b.txt", "b");
        let (plan, hash) = f.plan("plan", json!([quarantine("a", &a), quarantine("b", &b)]));
        let run = exec(&f, &plan, &hash, &["a"]);
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);

        // The index is held without delete sharing: it cannot be replaced.
        let index = f.roots.index_path();
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&index)
            .unwrap();
        let run = exec(&f, &plan, &hash, &["b"]);
        assert_eq!(run.exit, Exit::Unrecorded, "{}", run.err);
        assert!(run.err.contains("index was not updated"), "{}", run.err);
        let report: ExecReport = serde_json::from_str(&run.out).unwrap();
        assert_eq!(report.state, SessionState::Committed);
        assert!(!b.exists());
        let session = report.session.to_string();
        let run = cli(&f.roots, &args(&[&"undo", &"--session", &session]));
        assert_eq!(run.exit, Exit::Unrecorded, "{}", run.err);
        let undone: UndoReport = serde_json::from_str(&run.out).unwrap();
        assert_eq!(undone.state, SessionState::Undone);
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "b");
        let run = cli(
            &f.roots,
            &args(&[&"journal", &"resume", &"--session", &session]),
        );
        assert_eq!(run.exit, Exit::Unrecorded, "{}", run.err);

        drop(hold);
        let run = cli(
            &f.roots,
            &args(&[&"journal", &"resume", &"--session", &session]),
        );
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(
            run.json()["sessions"][0]["index_updated"],
            true,
            "{}",
            run.out
        );
        let run = cli(&f.roots, &args(&[&"journal", &"recover"]));
        assert_eq!(run.exit, Exit::Ok, "{}", run.err);
        assert_eq!(run.json()["sessions"], json!([]));
    }
}
