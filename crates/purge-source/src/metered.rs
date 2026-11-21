//! Call counters for the three sources: where a run spends its reads (diagnostics only).
//!
//! [`MeteredRegistry`], [`MeteredFileSystem`] and [`MeteredSystem`] wrap any source and pass every call
//! through unchanged, counting for each kind of call ([`Op`]) how often it was made, how many items it
//! returned (subkey names, values, directory entries) and how long it took. Nothing is cached and no
//! result is changed, so a metered run reads exactly what an unmetered one reads.
//!
//! The engine meters only when the `PURGE_TIMING` variable is set: it then wraps its live sources,
//! [`install`]s the [`Meter`] and writes the counters of each step to stderr. Without the variable no
//! wrapper exists and the cost is nil.
//!
//! The times are the sum over all calls, so with several threads reading at once they add up to more
//! than the wall time.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::filesystem::FileSystemSource;
use crate::registry::{KeyWalker, RegistrySource};
use crate::sysobj::{MsiTables, TaskInfo};
use crate::system::SystemSource;
use crate::types::{
    DirEntry, ExistsState, FileMeta, FileTime, KeyInfo, KnownFolder, MsiContextState, MsiProduct,
    OsInfo, PackageInfo, ProcessInfo, ProfileInfo, RegData, RegValue, ShortcutInfo, SourceResult,
    VersionInfo, VolumeInfo,
};

/// One kind of source call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// [`RegistrySource::key_info`].
    RegKeyInfo,
    /// [`RegistrySource::subkeys`]; items are subkey names.
    RegSubkeys,
    /// [`RegistrySource::values`]; items are values.
    RegValues,
    /// [`RegistrySource::value`].
    RegValue,
    /// [`RegistrySource::loaded_user_sids`] and [`RegistrySource::current_control_set`].
    RegOther,
    /// [`FileSystemSource::metadata`].
    FsMetadata,
    /// [`FileSystemSource::list_dir`]; items are directory entries.
    FsListDir,
    /// [`FileSystemSource::exists`].
    FsExists,
    /// [`FileSystemSource::read_bytes`]; items are bytes.
    FsReadBytes,
    /// [`FileSystemSource::long_path`].
    FsLongPath,
    /// [`FileSystemSource::volume_info`].
    FsVolumeInfo,
    /// [`FileSystemSource::version_info`].
    FsVersionInfo,
    /// [`FileSystemSource::signer_cn`] (Authenticode).
    FsSignerCn,
    /// [`FileSystemSource::read_shortcut`].
    FsReadShortcut,
    /// [`FileSystemSource::is_admin_only_writable`].
    FsAdminOnly,
    /// Every [`SystemSource`] call not counted under a kind of its own.
    System,
    /// [`SystemSource::msi_tables`]; items are rows over all tables.
    SysMsiTables,
    /// [`SystemSource::tasks`]; items are tasks.
    SysTasks,
}

impl Op {
    /// Every kind, in report order.
    pub const ALL: [Op; 18] = [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
        Op::FsMetadata,
        Op::FsListDir,
        Op::FsExists,
        Op::FsReadBytes,
        Op::FsLongPath,
        Op::FsVolumeInfo,
        Op::FsVersionInfo,
        Op::FsSignerCn,
        Op::FsReadShortcut,
        Op::FsAdminOnly,
        Op::System,
        Op::SysMsiTables,
        Op::SysTasks,
    ];

    /// The short name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            Op::RegKeyInfo => "reg.key_info",
            Op::RegSubkeys => "reg.subkeys",
            Op::RegValues => "reg.values",
            Op::RegValue => "reg.value",
            Op::RegOther => "reg.other",
            Op::FsMetadata => "fs.metadata",
            Op::FsListDir => "fs.list_dir",
            Op::FsExists => "fs.exists",
            Op::FsReadBytes => "fs.read_bytes",
            Op::FsLongPath => "fs.long_path",
            Op::FsVolumeInfo => "fs.volume_info",
            Op::FsVersionInfo => "fs.version_info",
            Op::FsSignerCn => "fs.signer_cn",
            Op::FsReadShortcut => "fs.read_shortcut",
            Op::FsAdminOnly => "fs.admin_only",
            Op::System => "sys",
            Op::SysMsiTables => "sys.msi_tables",
            Op::SysTasks => "sys.tasks",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Default)]
struct Counter {
    calls: AtomicU64,
    items: AtomicU64,
    nanos: AtomicU64,
}

/// The counters of every [`Op`]. Shared by the wrappers of one run; safe to update from many threads.
#[derive(Debug, Default)]
pub struct Meter {
    counters: [Counter; Op::ALL.len()],
}

/// The counters of one [`Op`] at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpCount {
    /// Calls made.
    pub calls: u64,
    /// Items the calls returned (see [`Op`]).
    pub items: u64,
    /// Time spent in the calls, summed over threads.
    pub busy: Duration,
}

/// A copy of a [`Meter`]'s counters, for reports and differences.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeterSnapshot {
    counts: BTreeMap<Op, OpCount>,
}

impl Meter {
    /// A meter with every counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts one call of `op` that returned `items` items and took `elapsed`.
    pub fn record(&self, op: Op, items: u64, elapsed: Duration) {
        let c = &self.counters[op.index()];
        c.calls.fetch_add(1, Ordering::Relaxed);
        c.items.fetch_add(items, Ordering::Relaxed);
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        c.nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// Runs `f` and counts it as one call of `op`, with the items `count` finds in its result.
    fn time<T>(&self, op: Op, count: impl FnOnce(&T) -> u64, f: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let out = f();
        self.record(op, count(&out), started.elapsed());
        out
    }

    /// The counters now.
    pub fn snapshot(&self) -> MeterSnapshot {
        let counts = Op::ALL
            .iter()
            .map(|&op| {
                let c = &self.counters[op.index()];
                let count = OpCount {
                    calls: c.calls.load(Ordering::Relaxed),
                    items: c.items.load(Ordering::Relaxed),
                    busy: Duration::from_nanos(c.nanos.load(Ordering::Relaxed)),
                };
                (op, count)
            })
            .collect();
        MeterSnapshot { counts }
    }
}

impl MeterSnapshot {
    /// The counters of one kind of call.
    pub fn get(&self, op: Op) -> OpCount {
        self.counts.get(&op).copied().unwrap_or_default()
    }

    /// What happened between `earlier` and this snapshot.
    pub fn since(&self, earlier: &MeterSnapshot) -> MeterSnapshot {
        let counts = Op::ALL
            .iter()
            .map(|&op| {
                let (now, then) = (self.get(op), earlier.get(op));
                let count = OpCount {
                    calls: now.calls.saturating_sub(then.calls),
                    items: now.items.saturating_sub(then.items),
                    busy: now.busy.saturating_sub(then.busy),
                };
                (op, count)
            })
            .collect();
        MeterSnapshot { counts }
    }

    /// The kinds that were called, as `name calls[/items] busy` parts separated by `; `; empty when
    /// nothing was called.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for op in Op::ALL {
            let c = self.get(op);
            if c.calls == 0 {
                continue;
            }
            if !out.is_empty() {
                out.push_str("; ");
            }
            let _ = write!(out, "{} {}", op.name(), c.calls);
            if c.items > 0 {
                let _ = write!(out, "/{}", c.items);
            }
            let _ = write!(out, " {:.3}s", c.busy.as_secs_f64());
        }
        out
    }
}

static INSTALLED: OnceLock<&'static Meter> = OnceLock::new();

/// Makes `meter` the one [`installed`] returns, for reports far from where the sources are made.
/// `false` when another meter was installed first (it stays).
pub fn install(meter: &'static Meter) -> bool {
    INSTALLED.set(meter).is_ok()
}

/// The meter of this process, when one was [`install`]ed.
pub fn installed() -> Option<&'static Meter> {
    INSTALLED.get().copied()
}

fn len<T, E>(r: &Result<Vec<T>, E>) -> u64 {
    r.as_ref().map_or(0, |v| v.len() as u64)
}

fn none<T>(_: &T) -> u64 {
    0
}

fn rows<E>(r: &Result<MsiTables, E>) -> u64 {
    r.as_ref().map_or(0, |t| t.row_count() as u64)
}

/// A [`RegistrySource`] that counts the calls it passes on.
pub struct MeteredRegistry<'a> {
    inner: &'a dyn RegistrySource,
    meter: &'a Meter,
}

impl<'a> MeteredRegistry<'a> {
    /// Counts the calls to `inner` in `meter`.
    pub fn new(inner: &'a dyn RegistrySource, meter: &'a Meter) -> Self {
        Self { inner, meter }
    }
}

impl RegistrySource for MeteredRegistry<'_> {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        self.meter
            .time(Op::RegKeyInfo, none, || self.inner.key_info(key))
    }

    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.meter
            .time(Op::RegSubkeys, len, || self.inner.subkeys(key))
    }

    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        self.meter
            .time(Op::RegValues, len, || self.inner.values(key))
    }

    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.meter
            .time(Op::RegValue, none, || self.inner.value(key, name))
    }

    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.meter
            .time(Op::RegOther, none, || self.inner.loaded_user_sids())
    }

    fn current_control_set(&self) -> SourceResult<u32> {
        self.meter
            .time(Op::RegOther, none, || self.inner.current_control_set())
    }

    fn key_exists(&self, key: &str) -> ExistsState {
        // Counted as the `key_info` it is made of.
        self.meter
            .time(Op::RegKeyInfo, none, || self.inner.key_exists(key))
    }

    fn walker(&self) -> Box<dyn KeyWalker + '_> {
        // The inner source's own walker, so that a metered walk reads as an unmetered one.
        Box::new(MeteredWalker {
            inner: self.inner.walker(),
            meter: self.meter,
        })
    }
}

/// A [`KeyWalker`] that counts its calls like the [`RegistrySource`] calls they stand for.
struct MeteredWalker<'a> {
    inner: Box<dyn KeyWalker + 'a>,
    meter: &'a Meter,
}

impl KeyWalker for MeteredWalker<'_> {
    fn enter(&mut self, key: &str) -> SourceResult<KeyInfo> {
        let inner = &mut self.inner;
        self.meter.time(Op::RegKeyInfo, none, || inner.enter(key))
    }

    fn values(&mut self) -> SourceResult<Vec<RegValue>> {
        let inner = &mut self.inner;
        self.meter.time(Op::RegValues, len, || inner.values())
    }

    fn subkeys(&mut self) -> SourceResult<Vec<String>> {
        let inner = &mut self.inner;
        self.meter.time(Op::RegSubkeys, len, || inner.subkeys())
    }
}

/// A [`FileSystemSource`] that counts the calls it passes on.
pub struct MeteredFileSystem<'a> {
    inner: &'a dyn FileSystemSource,
    meter: &'a Meter,
}

impl<'a> MeteredFileSystem<'a> {
    /// Counts the calls to `inner` in `meter`.
    pub fn new(inner: &'a dyn FileSystemSource, meter: &'a Meter) -> Self {
        Self { inner, meter }
    }
}

impl FileSystemSource for MeteredFileSystem<'_> {
    fn metadata(&self, path: &str) -> SourceResult<FileMeta> {
        self.meter
            .time(Op::FsMetadata, none, || self.inner.metadata(path))
    }

    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>> {
        self.meter
            .time(Op::FsListDir, len, || self.inner.list_dir(path))
    }

    fn exists(&self, path: &str) -> ExistsState {
        self.meter
            .time(Op::FsExists, none, || self.inner.exists(path))
    }

    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>> {
        self.meter
            .time(Op::FsReadBytes, len, || self.inner.read_bytes(path, max))
    }

    fn long_path(&self, path: &str) -> SourceResult<String> {
        self.meter
            .time(Op::FsLongPath, none, || self.inner.long_path(path))
    }

    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo> {
        self.meter
            .time(Op::FsVolumeInfo, none, || self.inner.volume_info(path))
    }

    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>> {
        self.meter
            .time(Op::FsVersionInfo, none, || self.inner.version_info(path))
    }

    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>> {
        self.meter
            .time(Op::FsSignerCn, none, || self.inner.signer_cn(path))
    }

    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo> {
        self.meter
            .time(Op::FsReadShortcut, none, || self.inner.read_shortcut(path))
    }

    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool> {
        self.meter.time(Op::FsAdminOnly, none, || {
            self.inner.is_admin_only_writable(path)
        })
    }
}

/// A [`SystemSource`] that counts the calls it passes on.
pub struct MeteredSystem<'a> {
    inner: &'a dyn SystemSource,
    meter: &'a Meter,
}

impl<'a> MeteredSystem<'a> {
    /// Counts the calls to `inner` in `meter`.
    pub fn new(inner: &'a dyn SystemSource, meter: &'a Meter) -> Self {
        Self { inner, meter }
    }
}

impl SystemSource for MeteredSystem<'_> {
    fn os_info(&self) -> SourceResult<OsInfo> {
        self.meter.time(Op::System, none, || self.inner.os_info())
    }

    fn user_sid(&self) -> SourceResult<String> {
        self.meter.time(Op::System, none, || self.inner.user_sid())
    }

    fn elevated(&self) -> bool {
        self.meter.time(Op::System, none, || self.inner.elevated())
    }

    fn profiles(&self) -> SourceResult<Vec<ProfileInfo>> {
        self.meter.time(Op::System, none, || self.inner.profiles())
    }

    fn known_folders(&self) -> SourceResult<BTreeMap<KnownFolder, String>> {
        self.meter
            .time(Op::System, none, || self.inner.known_folders())
    }

    fn env(&self) -> SourceResult<BTreeMap<String, String>> {
        self.meter.time(Op::System, none, || self.inner.env())
    }

    fn machine_env(&self) -> SourceResult<BTreeMap<String, String>> {
        self.meter
            .time(Op::System, none, || self.inner.machine_env())
    }

    fn processes(&self) -> SourceResult<Vec<ProcessInfo>> {
        self.meter.time(Op::System, none, || self.inner.processes())
    }

    fn msi_products(&self) -> SourceResult<Vec<MsiProduct>> {
        self.meter
            .time(Op::System, none, || self.inner.msi_products())
    }

    fn msi_product_state_all(&self, code: &str) -> SourceResult<Vec<MsiContextState>> {
        self.meter
            .time(Op::System, none, || self.inner.msi_product_state_all(code))
    }

    fn packages(&self) -> SourceResult<Vec<PackageInfo>> {
        self.meter.time(Op::System, none, || self.inner.packages())
    }

    fn msi_tables(&self, local_package: &str) -> SourceResult<MsiTables> {
        self.meter.time(Op::SysMsiTables, rows, || {
            self.inner.msi_tables(local_package)
        })
    }

    fn tasks(&self) -> SourceResult<Vec<TaskInfo>> {
        self.meter.time(Op::SysTasks, len, || self.inner.tasks())
    }

    fn now(&self) -> FileTime {
        self.meter.time(Op::System, none, || self.inner.now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Fixture;

    #[test]
    fn calls_pass_through_unchanged_and_are_counted() {
        let mut f = Fixture::new();
        f.set_value(r"HKLM\SOFTWARE\A", "x", RegData::from_dword(1));
        f.set_value(r"HKLM\SOFTWARE\A\B", "y", RegData::from_dword(2));
        let meter = Meter::new();
        let reg = MeteredRegistry::new(&f, &meter);
        assert_eq!(
            reg.subkeys(r"HKLM\SOFTWARE\A"),
            f.subkeys(r"HKLM\SOFTWARE\A")
        );
        assert_eq!(reg.values(r"HKLM\SOFTWARE\A"), f.values(r"HKLM\SOFTWARE\A"));
        assert_eq!(
            reg.value(r"HKLM\SOFTWARE\A", "x"),
            f.value(r"HKLM\SOFTWARE\A", "x")
        );
        assert!(reg.key_exists(r"HKLM\SOFTWARE\Nothing").is_absent());
        let first = meter.snapshot();
        assert_eq!(first.get(Op::RegSubkeys).calls, 1);
        assert_eq!(first.get(Op::RegSubkeys).items, 1);
        assert_eq!(first.get(Op::RegValues).items, 1);
        assert_eq!(first.get(Op::RegValue).calls, 1);
        assert_eq!(first.get(Op::RegKeyInfo).calls, 1);
        let _ = reg.values(r"HKLM\SOFTWARE\A\B");
        let delta = meter.snapshot().since(&first);
        assert_eq!(delta.get(Op::RegValues).calls, 1);
        assert_eq!(delta.get(Op::RegSubkeys).calls, 0);
        let summary = delta.summary();
        assert!(summary.starts_with("reg.values 1/1 "), "{summary}");
        assert!(!summary.contains("reg.subkeys"), "{summary}");
        assert_eq!(MeterSnapshot::default().summary(), "");
    }

    #[test]
    fn metered_forwards_and_counts_msi_tables_and_tasks() {
        use crate::sysobj::MsiComponentRow;
        use crate::types::SourceError;
        use purge_model::object::{TaskAction, TaskIdentity};

        let pkg = r"C:\Windows\Installer\1a2b3c.msi";
        let tables = MsiTables {
            properties: vec![("ProductName".into(), "App".into())],
            components: vec![MsiComponentRow {
                component: "Main".into(),
                component_id: None,
                attributes: 0,
                key_path: None,
            }],
            progids: vec!["App.Doc".into()],
            ..MsiTables::default()
        };
        let task = TaskInfo {
            identity: TaskIdentity {
                path: r"\Vendor\Update".into(),
                actions: vec![TaskAction::Exec {
                    path: r"C:\Program Files\App\update.exe".into(),
                    arguments: None,
                    working_dir: None,
                }],
            },
            enabled: true,
            ..TaskInfo::default()
        };
        let mut f = Fixture::new();
        f.set_msi_tables(pkg, tables.clone());
        f.add_task(task.clone());
        f.add_task(TaskInfo::default());

        let meter = Meter::new();
        let sys = MeteredSystem::new(&f, &meter);
        assert_eq!(sys.msi_tables(pkg), Ok(tables));
        assert_eq!(
            sys.msi_tables(r"C:\Windows\Installer\other.msi"),
            Err(SourceError::NotFound)
        );
        assert_eq!(sys.tasks(), Ok(vec![task, TaskInfo::default()]));
        let snap = meter.snapshot();
        assert_eq!(snap.get(Op::SysMsiTables).calls, 2);
        assert_eq!(snap.get(Op::SysMsiTables).items, 3);
        assert_eq!(snap.get(Op::SysTasks).calls, 1);
        assert_eq!(snap.get(Op::SysTasks).items, 2);
        assert_eq!(snap.get(Op::System).calls, 0);
        let summary = snap.summary();
        assert!(summary.starts_with("sys.msi_tables 2/3 "), "{summary}");
        assert!(summary.contains("; sys.tasks 1/2 "), "{summary}");

        // Errors pass through unchanged and still count as calls.
        let empty = Fixture::new();
        let meter = Meter::new();
        let sys = MeteredSystem::new(&empty, &meter);
        assert_eq!(sys.msi_tables(pkg), Err(SourceError::NotCaptured));
        assert_eq!(sys.tasks(), Err(SourceError::NotCaptured));
        let snap = meter.snapshot();
        assert_eq!(snap.get(Op::SysMsiTables).calls, 1);
        assert_eq!(snap.get(Op::SysTasks).calls, 1);
        assert_eq!(snap.get(Op::SysTasks).items, 0);
    }
}
