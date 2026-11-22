//! Test support: before/after machines from the committed fixtures, a source that switches from
//! "before" to "after" when the fake uninstaller starts, the fake process host, an Inno Setup log writer,
//! golden files and a copy of the rig's plan reader.
//!
//! Golden files live in `tests/golden/`. Run the tests with `PURGE_BLESS=1` to rewrite them after an
//! intended change, then review the diff.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use purge_engine::cli::{self, Env, Exit};
use purge_engine::pipeline::{Settings, Sources};
use purge_inventory::runner::{JobId, ProcessHost, RunOptions};
use purge_model::{FileTime, ProcessSeen};
use purge_source::filesystem::FileSystemSource;
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::sysobj::{MsiTables, TaskInfo};
use purge_source::system::SystemSource;
use purge_source::types::{
    DirEntry, ExistsState, FileMeta, KeyInfo, KnownFolder, MsiContextState, MsiProduct, OsInfo,
    PackageInfo, ProcessInfo, ProfileInfo, RegData, RegValue, ShortcutInfo, SourceResult,
    VersionInfo, VolumeInfo,
};
use serde::Deserialize;

/// FileTime of the fake host's clock at zero (2026-11-08).
pub const BASE: u64 = 134_410_000_000_000_000;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// What an uninstaller removes: `<name>.uninstall.json`.
#[derive(Debug, Deserialize)]
struct Delta {
    remove_keys: Vec<String>,
    #[serde(default)]
    remove_values: Vec<(String, String)>,
    remove_paths: Vec<String>,
}

/// The machine before and after the uninstall: `<name>.before.json` (plus `extra`, applied to both), and
/// the same with `<name>.uninstall.json` removed.
pub fn machine(name: &str, extra: impl FnOnce(&mut Fixture)) -> (Fixture, Fixture) {
    let dir = fixtures();
    let mut before = Fixture::from_json_file(&dir.join(format!("{name}.before.json")))
        .unwrap_or_else(|e| panic!("{name}.before.json: {e}"));
    extra(&mut before);
    let text = std::fs::read_to_string(dir.join(format!("{name}.uninstall.json"))).unwrap();
    let delta: Delta = serde_json::from_str(&text).unwrap();
    let mut after = before.clone();
    for key in &delta.remove_keys {
        assert!(after.remove_key(key), "{name}: no key {key}");
    }
    for (key, value) in &delta.remove_values {
        assert!(
            after.remove_value(key, value),
            "{name}: no value {key} : {value}"
        );
    }
    for path in &delta.remove_paths {
        assert!(after.remove_path(path), "{name}: no path {path}");
    }
    (before, after)
}

// ---------------------------------------------------------------------------------------------------------
// The switching machine
// ---------------------------------------------------------------------------------------------------------

/// A machine that reads as `before` until the flag is set (by [`FakeHost`] when it "starts" the
/// uninstaller), and as `after` from then on.
pub struct Switch {
    before: Fixture,
    after: Fixture,
    flag: Arc<AtomicBool>,
}

impl Switch {
    /// A machine in its "before" state.
    pub fn new((before, after): (Fixture, Fixture)) -> Self {
        Self {
            before,
            after,
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag that switches to "after".
    pub fn flag(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }

    /// The sources over this machine.
    pub fn sources(&self) -> Sources<'_> {
        Sources::of(self)
    }

    fn now(&self) -> &Fixture {
        if self.flag.load(Ordering::SeqCst) {
            &self.after
        } else {
            &self.before
        }
    }
}

impl RegistrySource for Switch {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        self.now().key_info(key)
    }
    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.now().subkeys(key)
    }
    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        self.now().values(key)
    }
    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.now().value(key, name)
    }
    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.now().loaded_user_sids()
    }
    fn current_control_set(&self) -> SourceResult<u32> {
        self.now().current_control_set()
    }
}

impl FileSystemSource for Switch {
    fn metadata(&self, path: &str) -> SourceResult<FileMeta> {
        self.now().metadata(path)
    }
    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>> {
        self.now().list_dir(path)
    }
    fn exists(&self, path: &str) -> ExistsState {
        self.now().exists(path)
    }
    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>> {
        self.now().read_bytes(path, max)
    }
    fn long_path(&self, path: &str) -> SourceResult<String> {
        self.now().long_path(path)
    }
    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo> {
        self.now().volume_info(path)
    }
    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>> {
        self.now().version_info(path)
    }
    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>> {
        self.now().signer_cn(path)
    }
    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo> {
        self.now().read_shortcut(path)
    }
    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool> {
        self.now().is_admin_only_writable(path)
    }
    fn is_admin_only_executable(&self, path: &str) -> SourceResult<bool> {
        self.now().is_admin_only_executable(path)
    }
}

impl SystemSource for Switch {
    fn os_info(&self) -> SourceResult<OsInfo> {
        self.now().os_info()
    }
    fn user_sid(&self) -> SourceResult<String> {
        self.now().user_sid()
    }
    fn elevated(&self) -> bool {
        self.now().elevated()
    }
    fn profiles(&self) -> SourceResult<Vec<ProfileInfo>> {
        self.now().profiles()
    }
    fn known_folders(&self) -> SourceResult<BTreeMap<KnownFolder, String>> {
        self.now().known_folders()
    }
    fn env(&self) -> SourceResult<BTreeMap<String, String>> {
        self.now().env()
    }
    fn machine_env(&self) -> SourceResult<BTreeMap<String, String>> {
        self.now().machine_env()
    }
    fn processes(&self) -> SourceResult<Vec<ProcessInfo>> {
        self.now().processes()
    }
    fn msi_products(&self) -> SourceResult<Vec<MsiProduct>> {
        self.now().msi_products()
    }
    fn msi_product_state_all(&self, code: &str) -> SourceResult<Vec<MsiContextState>> {
        self.now().msi_product_state_all(code)
    }
    fn packages(&self) -> SourceResult<Vec<PackageInfo>> {
        self.now().packages()
    }
    fn msi_tables(&self, local_package: &str) -> SourceResult<MsiTables> {
        self.now().msi_tables(local_package)
    }
    fn tasks(&self) -> SourceResult<Vec<TaskInfo>> {
        self.now().tasks()
    }
    fn now(&self) -> FileTime {
        SystemSource::now(Switch::now(self))
    }
}

#[test]
fn switch_forwards_msi_tables_and_tasks_to_the_active_side() {
    use purge_source::types::SourceError;
    let pkg = r"C:\Windows\Installer\1a2b3c.msi";
    let mut before = Fixture::new();
    before.set_msi_tables(
        pkg,
        MsiTables {
            progids: vec!["App.Doc".into()],
            ..MsiTables::default()
        },
    );
    before.add_task(TaskInfo::default());
    let switch = Switch::new((before.clone(), Fixture::new()));
    assert_eq!(switch.msi_tables(pkg), before.msi_tables(pkg));
    assert_eq!(switch.tasks(), Ok(vec![TaskInfo::default()]));
    switch.flag().store(true, Ordering::SeqCst);
    assert_eq!(switch.msi_tables(pkg), Err(SourceError::NotCaptured));
    assert_eq!(switch.tasks(), Err(SourceError::NotCaptured));
}

// ---------------------------------------------------------------------------------------------------------
// The fake process host
// ---------------------------------------------------------------------------------------------------------

/// The environment and working directory of one start.
pub type SpawnRecord = (
    Option<std::collections::BTreeMap<String, String>>,
    Option<std::path::PathBuf>,
);

/// A scripted uninstaller: it "runs" for `run_ms` of fake time, then exits with `exit` (`None`: never).
/// Starting it switches the machine to "after" when `removes` is set. Nothing real is ever started.
pub struct FakeHost {
    flag: Arc<AtomicBool>,
    removes: bool,
    exit: Option<u32>,
    run_ms: u64,
    clock_ms: u64,
    started_at: Option<u64>,
    /// The command lines it was asked to start.
    pub spawned: Vec<String>,
    /// The environment and working directory of each start.
    pub spawned_with: Vec<SpawnRecord>,
}

impl FakeHost {
    /// An uninstaller that runs for two seconds, exits with `exit` and, when `removes`, removes the app.
    pub fn new(switch: &Switch, exit: Option<u32>, removes: bool) -> Self {
        Self {
            flag: switch.flag(),
            removes,
            exit,
            run_ms: 2_000,
            clock_ms: 0,
            started_at: None,
            spawned: Vec::new(),
            spawned_with: Vec::new(),
        }
    }

    fn alive(&self) -> bool {
        match (self.started_at, self.exit) {
            (Some(start), Some(_)) => self.clock_ms < start + self.run_ms,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

impl ProcessHost for FakeHost {
    fn spawn_in_job(
        &mut self,
        command_line: &str,
        context: purge_inventory::runner::SpawnContext<'_>,
    ) -> io::Result<JobId> {
        self.spawned.push(command_line.to_owned());
        self.spawned_with.push((
            context.environment.cloned(),
            context.current_dir.map(|d| d.to_path_buf()),
        ));
        self.started_at = Some(self.clock_ms);
        if self.removes {
            self.flag.store(true, Ordering::SeqCst);
        }
        Ok(JobId(1))
    }

    fn job_active_pids(&mut self, _: JobId) -> io::Result<Vec<u32>> {
        Ok(if self.alive() { vec![4242] } else { Vec::new() })
    }

    fn job_exit_code(&mut self, _: JobId) -> io::Result<Option<u32>> {
        Ok(if self.alive() { None } else { self.exit })
    }

    fn process_info(&mut self, pid: u32) -> Option<ProcessSeen> {
        Some(ProcessSeen {
            pid,
            name: "uninstaller.exe".into(),
            path: None,
            start: None,
        })
    }

    fn running_processes(&mut self) -> io::Result<Vec<ProcessSeen>> {
        Ok(Vec::new())
    }

    fn mutex_exists(&mut self, _: &str) -> io::Result<bool> {
        Ok(false)
    }

    fn now(&self) -> FileTime {
        FileTime(BASE + self.clock_ms * 10_000)
    }

    fn sleep(&mut self, d: Duration) {
        self.clock_ms += u64::try_from(d.as_millis()).unwrap();
    }
}

// ---------------------------------------------------------------------------------------------------------
// The CLI
// ---------------------------------------------------------------------------------------------------------

/// The output of one CLI run.
pub struct Ran {
    /// The exit code.
    pub exit: Exit,
    /// What went to stdout.
    pub out: String,
    /// What went to stderr.
    pub err: String,
}

/// Runs the CLI over `switch` with `host`, no baseline directory and short waits.
pub fn cli(switch: &Switch, host: &mut FakeHost, args: &[&str]) -> Ran {
    cli_with(switch, host, args, RunOptions::default())
}

/// [`cli`] with the runner's options.
pub fn cli_with(switch: &Switch, host: &mut FakeHost, args: &[&str], run: RunOptions) -> Ran {
    cli_in(switch, host, args, run, Settings::default())
}

/// The shipped baselines (`kb/baselines`): the fixtures' Windows is one of them.
pub fn shipped_baselines() -> Settings {
    Settings {
        baseline_dir: Some(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../kb/baselines")
                .to_path_buf(),
        ),
        ..Settings::default()
    }
}

/// [`cli_with`] with the engine's settings (a baseline directory).
pub fn cli_in(
    switch: &Switch,
    host: &mut FakeHost,
    args: &[&str],
    run: RunOptions,
    settings: Settings,
) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let exit = cli::run(
        &args,
        &mut Env {
            sources: switch.sources(),
            host,
            settings,
            run_options: run,
            stdout: &mut out,
            stderr: &mut err,
        },
    );
    Ran {
        exit,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// A fresh, empty scratch directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("engine-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A path as a command-line argument.
pub fn arg(p: &Path) -> &str {
    p.to_str().unwrap()
}

// ---------------------------------------------------------------------------------------------------------
// Golden files
// ---------------------------------------------------------------------------------------------------------

/// Compares `text` with `tests/golden/<name>` (line endings normalised); rewrites the file when
/// `PURGE_BLESS=1`.
pub fn golden(name: &str, text: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name);
    let text = text.replace("\r\n", "\n");
    if std::env::var_os("PURGE_BLESS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with PURGE_BLESS=1)", path.display()))
        .replace("\r\n", "\n");
    if want != text {
        let first = want
            .lines()
            .zip(text.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| want.lines().count().min(text.lines().count()));
        panic!(
            "{name} differs from the golden file at line {}:\n  want: {:?}\n  got:  {:?}\n(run with \
             PURGE_BLESS=1 to accept)\n--- got ---\n{text}",
            first + 1,
            want.lines().nth(first),
            text.lines().nth(first)
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// An Inno Setup uninstall log writer
// ---------------------------------------------------------------------------------------------------------

/// Inno Setup log constants, from the published format (`Setup.UninstallLog.pas`).
pub mod inno {
    /// `StartInstall`.
    pub const START: u16 = 0x10;
    /// `EndInstall`.
    pub const END: u16 = 0x11;
    /// `DeleteDirOrFiles`.
    pub const DIR: u16 = 0x81;
    /// `DeleteFile`.
    pub const FILE: u16 = 0x82;
    /// `RegDeleteEntireKey`.
    pub const KEY: u16 = 0x86;
    /// `RegDeleteKeyIfEmpty`.
    pub const KEY_IF_EMPTY: u16 = 0x88;
    /// `RegDeleteValue`.
    pub const VALUE: u16 = 0x89;
    /// `HKEY_CURRENT_USER`, 64-bit view.
    pub const HKCU: u32 = 0x8100_0001;
    /// `HKEY_LOCAL_MACHINE`, 64-bit view.
    pub const HKLM: u32 = 0x8100_0002;
    /// `DeleteDirOrFiles` of a whole tree: is-dir, delete files, delete subdirectories.
    pub const DIR_TREE: u32 = 2 | 4 | 8;
    /// Header flags of a 64-bit administrative install.
    pub const ADMIN_64: u32 = 1 | (1 << 5) | (1 << 7);
}

/// CRC-32 (IEEE, reflected), as the log format uses it.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One log record: type, `ExtraData`, strings.
pub type Rec<'a> = (u16, u32, &'a [&'a str]);

/// The bytes of a 64-bit uninstall log with the given header facts and records.
pub fn inno_log(app_id: &str, app_name: &str, flags: u32, recs: &[Rec<'_>]) -> Vec<u8> {
    let mut stream = Vec::new();
    for (typ, extra, strings) in recs {
        let mut data = Vec::new();
        for s in *strings {
            let utf16: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            data.push(0xFE);
            data.extend_from_slice(&(-i32::try_from(utf16.len()).unwrap()).to_le_bytes());
            data.extend_from_slice(&utf16);
        }
        data.push(0xFF);
        stream.extend_from_slice(&typ.to_le_bytes());
        stream.extend_from_slice(&extra.to_le_bytes());
        stream.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&data);
    }
    let mut out = vec![0u8; 448];
    let id = b"Inno Setup Uninstall Log (b) 64-bit";
    out[..id.len()].copy_from_slice(id);
    out[64..64 + app_id.len()].copy_from_slice(app_id.as_bytes());
    out[192..192 + app_name.len()].copy_from_slice(app_name.as_bytes());
    for chunk in stream.chunks(4096) {
        let size = u32::try_from(chunk.len()).unwrap();
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(!size).to_le_bytes());
        out.extend_from_slice(&crc32(chunk).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    let end = u32::try_from(out.len()).unwrap();
    out[320..324].copy_from_slice(&1048i32.to_le_bytes());
    out[324..328].copy_from_slice(&i32::try_from(recs.len()).unwrap().to_le_bytes());
    out[328..332].copy_from_slice(&end.to_le_bytes());
    out[332..336].copy_from_slice(&flags.to_le_bytes());
    let crc = crc32(&out[..444]);
    out[444..448].copy_from_slice(&crc.to_le_bytes());
    out
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

// ---------------------------------------------------------------------------------------------------------
// The rig's plan reader
// ---------------------------------------------------------------------------------------------------------

/// A copy of what `vm/rigtool` reads from a plan (`score.rs`, `target.rs`): a plan that deserialises here
/// is accepted by `rigtool score --plan`.
pub mod rig {
    use serde::{Deserialize, Deserializer};

    fn null_str<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
    }

    /// A target.
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[allow(dead_code)]
    pub enum Target {
        /// A file or directory.
        Path {
            /// Its path.
            path: String,
        },
        /// A key.
        RegKey {
            /// Its path.
            path: String,
        },
        /// A value.
        RegValue {
            /// The key.
            path: String,
            /// The value name.
            #[serde(default, deserialize_with = "null_str")]
            name: String,
        },
        /// A changed value.
        RegValueChanged {
            /// The key.
            path: String,
            /// The value name.
            #[serde(default, deserialize_with = "null_str")]
            name: String,
            /// Before.
            #[serde(default)]
            before: String,
            /// After.
            #[serde(default)]
            after: String,
        },
        /// A segment of a list value.
        RegMultiSzSegment {
            /// The key.
            path: String,
            /// The value name.
            #[serde(default, deserialize_with = "null_str")]
            name: String,
            /// The segment.
            segment: String,
        },
        /// A service.
        Service {
            /// Its name.
            name: String,
        },
        /// A scheduled task.
        Task {
            /// Its path.
            path: String,
        },
        /// A firewall rule.
        FirewallRule {
            /// Its id.
            #[serde(alias = "rule_id")]
            id: String,
        },
        /// A package.
        AppxPackage {
            /// Its full name.
            full_name: String,
        },
    }

    /// An item.
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    pub struct PlanItem {
        /// The target.
        pub target: Target,
        /// The band.
        #[serde(default)]
        pub band: String,
        /// Ticked.
        #[serde(default)]
        pub preselected: bool,
        /// The scanner.
        #[serde(default)]
        pub scanner: Option<String>,
        /// The category.
        #[serde(default)]
        pub category: Option<String>,
    }

    /// A plan.
    #[derive(Deserialize, Debug, Default)]
    #[allow(dead_code)]
    pub struct Plan {
        /// The schema id.
        #[serde(default)]
        pub schema: String,
        /// The app id.
        #[serde(default)]
        pub app: String,
        /// The tool.
        #[serde(default)]
        pub tool: String,
        /// The mode.
        #[serde(default)]
        pub mode: String,
        /// The items.
        #[serde(default)]
        pub items: Vec<PlanItem>,
    }
}
