//! The local baseline build: every source read in parallel, records merged, the completeness seal,
//! the file encoded (BASELINE_LOCAL_DESIGN.md §3.4, §3.5, §5 "Budget"; package BL-BUILD).
//!
//! [`build`] reads S1 (component manifests) on a pool of scoped worker threads, each taking the next
//! manifest from the shared lazy listing, expanding it with `purge_win::sxs` and parsing it into its
//! own [`Records`]; meanwhile one more thread reads S2, S3 and S4. Every thread runs in background mode
//! (`purge_win::process::set_thread_background`: lower CPU, I/O and memory priority) when
//! [`BuildOptions::background`] is set; the caller's own thread is never switched. The parts are merged
//! (a union, L1), sealed ([`SealFloors`], design §3.4) and encoded ([`super::file::encode`]): sorted,
//! no time in the body, so the same inputs give the same bytes.
//!
//! The build never fails because a source failed: a source that cannot be read is a `failed` `#src`
//! line and the file is incomplete (L2). [`build`] itself fails only when encoding fails.
//!
//! # Source id
//!
//! [`SourceStamp::id`] is the first 16 hex digits of the SHA-256 over the count, total size and newest
//! write time of the `*.manifest` files of `WinSxS\Manifests`, the size and write time of the default
//! profile's hive, and the sorted full names of the S4 packages (design §5 "Key and invalidation").
//! The caller reads the file stamps ([`file_stamps`]) **before** the build, so a servicing change
//! during the build gives a stale id, which a later check sees as a miss.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use purge_model::OsInfo;
use purge_source::filesystem::FileSystemSource;
use purge_source::local_baseline::{
    InboxPackages, LocalSources, ManifestIter, default_hive_path, system_root,
};
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::SourceResult;
use purge_win::sxs::{self, ExpandCounts, ManifestFormat, SxsBase};
use sha2::{Digest, Sha256};

use super::Records;
use super::appx::{self, InboxStats};
use super::file::{
    LocalHeader, LocalSource, SourceLine, SourceStatus, encode, fact_value, seal_reasons,
};
use super::hive::{self, HiveStats};
use super::manifest::{self, ManifestStats, Skipped};
use crate::baseline::RecordCounts;

/// The builder's version, written into the header. A file of another builder version is a miss
/// (`LocalBaseline::from_bytes`). Raise it whenever the records a host gives change: the mapping, the
/// macro table, the sources or the seal.
pub const BUILDER_VERSION: &str = "bl.2";

/// Failures named in a `#src` line (the first ones by name); the count is always complete.
const LISTED_FAILURES: usize = 5;
/// Unknown macro names listed in the S1 line (the most frequent first).
const LISTED_MACROS: usize = 10;

/// The floors of the completeness seal (design §3.4). [`Default`] gives the design's numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealFloors {
    /// S1: manifests expanded and parsed, per mille of those listed (999 = 99.9%).
    pub s1_parsed_per_mille: u64,
    /// S1: manifests listed.
    pub s1_manifests: u64,
    /// S1: distinct keys.
    pub s1_keys: u64,
    /// S1: at most this many key names skipped for an unknown macro.
    pub s1_max_key_unknown_macro: u64,
    /// S2: keys.
    pub s2_keys: u64,
    /// S4: manifests parsed.
    pub s4_manifests: u64,
}

impl Default for SealFloors {
    fn default() -> Self {
        SealFloors {
            s1_parsed_per_mille: 999,
            s1_manifests: 15_000,
            s1_keys: 150_000,
            s1_max_key_unknown_macro: 50,
            s2_keys: 500,
            s4_manifests: 20,
        }
    }
}

/// Sizes and write times of the files the source id covers, read before the build ([`file_stamps`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileStamps {
    /// `*.manifest` files in `WinSxS\Manifests`.
    pub manifests: u64,
    /// Their total size in bytes (as stored).
    pub manifest_bytes: u64,
    /// The newest write time among them (FILETIME ticks).
    pub manifest_newest_write: u64,
    /// The default profile's hive size in bytes.
    pub hive_bytes: u64,
    /// Its write time (FILETIME ticks).
    pub hive_write: u64,
    /// What could not be read (each part left at zero); for warnings, not part of the id.
    pub problems: Vec<String>,
}

/// Reads the [`FileStamps`] through the sources: one listing of `%SystemRoot%\WinSxS\Manifests` (the
/// filter of `list_manifests`) and the metadata of the hive `ProfileList` names.
pub fn file_stamps(
    fs: &dyn FileSystemSource,
    reg: &dyn RegistrySource,
    sys: &dyn SystemSource,
) -> FileStamps {
    let mut out = FileStamps::default();
    let listing =
        system_root(sys).and_then(|root| fs.list_dir(&format!(r"{root}\WinSxS\Manifests")));
    match listing {
        Ok(entries) => {
            for e in entries.iter().filter(|e| {
                !e.meta.is_dir()
                    && !e.meta.is_reparse_point()
                    && e.name.to_ascii_lowercase().ends_with(".manifest")
            }) {
                out.manifests += 1;
                out.manifest_bytes += e.meta.size;
                let written = e.meta.times.modified.map_or(0, |t| t.0);
                out.manifest_newest_write = out.manifest_newest_write.max(written);
            }
        }
        Err(e) => out.problems.push(format!("cannot list the manifests: {e}")),
    }
    match default_hive_path(reg, sys).and_then(|p| fs.metadata(&p)) {
        Ok(meta) => {
            out.hive_bytes = meta.size;
            out.hive_write = meta.times.modified.map_or(0, |t| t.0);
        }
        Err(e) => out
            .problems
            .push(format!("cannot stat the default hive: {e}")),
    }
    out
}

/// Everything the source id is computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceStamp {
    /// The file stamps.
    pub files: FileStamps,
    /// The full names of the S4 packages (any order; sorted for the id).
    pub packages: Vec<String>,
}

impl SourceStamp {
    /// The source id: 16 lower-case hex digits (see the module documentation).
    pub fn id(&self) -> String {
        let f = &self.files;
        let mut sha = Sha256::new();
        sha.update(b"purge-local-source/1\n");
        sha.update(
            format!(
                "manifests\t{}\t{}\t{}\nhive\t{}\t{}\n",
                f.manifests, f.manifest_bytes, f.manifest_newest_write, f.hive_bytes, f.hive_write
            )
            .as_bytes(),
        );
        let mut names: Vec<&str> = self.packages.iter().map(String::as_str).collect();
        names.sort_unstable();
        names.dedup();
        for n in names {
            sha.update(b"package\t");
            sha.update(n.as_bytes());
            sha.update(b"\n");
        }
        sha.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// How to build.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// The header's time (ISO-8601 UTC, [`iso_utc`]).
    pub built_at: String,
    /// The header's computer name.
    pub computer: String,
    /// The delta base for `DCM` manifests (`purge_win::sxs::find_base`), or why there is none.
    pub base: Result<SxsBase, String>,
    /// The file stamps of the source id, read before the build.
    pub stamps: FileStamps,
    /// S1 worker threads; 0 = the machine's available parallelism.
    pub threads: usize,
    /// Run every build thread in background mode.
    pub background: bool,
    /// The seal's floors.
    pub floors: SealFloors,
}

/// Time spent per phase (`baseline.local.*`, design §5 "Budget").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildTimings {
    /// S1 listing (`LocalSources::manifests`).
    pub list: Duration,
    /// Taking the next manifest from the listing, its file read included, summed over the worker
    /// threads (waiting for another worker's read counts too).
    pub read: Duration,
    /// Expanding manifests, summed over the worker threads.
    pub expand: Duration,
    /// Parsing manifests, summed over the worker threads.
    pub parse: Duration,
    /// S1 from the listing to the last worker's end (wall clock).
    pub s1: Duration,
    /// S2 and S3.
    pub hive: Duration,
    /// S4.
    pub appx: Duration,
    /// Merging the workers' records into one set (thread time) and the sources' sets, and sealing.
    pub merge: Duration,
    /// Encoding (sort order, escape, hash, gzip) in memory.
    pub write: Duration,
    /// The whole build (wall clock).
    pub total: Duration,
}

impl BuildTimings {
    /// One `timing:` line per phase.
    pub fn lines(&self, threads: usize) -> Vec<String> {
        let s = |d: Duration| format!("{:.3} s", d.as_secs_f64());
        vec![
            format!("timing: baseline.local.list {}", s(self.list)),
            format!(
                "timing: baseline.local.read {} (thread time, {threads} threads)",
                s(self.read)
            ),
            format!(
                "timing: baseline.local.expand {} (thread time, {threads} threads)",
                s(self.expand)
            ),
            format!(
                "timing: baseline.local.parse {} (thread time, {threads} threads)",
                s(self.parse)
            ),
            format!("timing: baseline.local.s1 {} (wall)", s(self.s1)),
            format!("timing: baseline.local.hive {}", s(self.hive)),
            format!("timing: baseline.local.appx {}", s(self.appx)),
            format!("timing: baseline.local.merge {}", s(self.merge)),
            format!("timing: baseline.local.write {} (encode)", s(self.write)),
            format!("timing: baseline.local.total {} (wall)", s(self.total)),
        ]
    }
}

/// A built local baseline: the encoded file and what went into it.
#[derive(Debug, Clone)]
pub struct LocalBaselineFile {
    /// The header written.
    pub header: LocalHeader,
    /// The `#src` lines written, S1 to S4.
    pub sources: Vec<SourceLine>,
    /// Records of each type.
    pub counts: RecordCounts,
    /// Record lines (`K`+`V`+`D`+`F`), as `#end` says.
    pub record_count: u64,
    /// The `#end` hash.
    pub sha256: String,
    /// Bytes of text before `#end` (uncompressed).
    pub text_bytes: u64,
    /// The file (gzip).
    pub bytes: Vec<u8>,
    /// Everything the source id was computed from.
    pub stamp: SourceStamp,
    /// Time per phase.
    pub timings: BuildTimings,
    /// S1 worker threads used.
    pub threads: usize,
}

impl LocalBaselineFile {
    /// The completeness seal of what was written (the same rule `LocalBaseline::complete` applies).
    pub fn complete(&self) -> bool {
        seal_reasons(&self.sources).is_empty()
    }

    /// Why it is not complete, one line per source.
    pub fn incomplete_reasons(&self) -> Vec<String> {
        seal_reasons(&self.sources)
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the Unix epoch (UTC).
pub fn iso_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    // Civil from days (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Builds the local baseline of the Windows `src` describes. See the module documentation.
pub fn build(
    src: &dyn LocalSources,
    os: &OsInfo,
    opts: &BuildOptions,
) -> io::Result<LocalBaselineFile> {
    let started = Instant::now();
    let threads = match opts.threads {
        0 => std::thread::available_parallelism().map_or(2, |n| n.get()),
        n => n,
    }
    .clamp(1, 64);
    let floors = &opts.floors;

    // Everything runs on scoped threads, so the caller's thread mode is never changed.
    let (s1, others) = std::thread::scope(|scope| {
        let others = scope.spawn(|| {
            enter_background(opts.background);
            read_others(src)
        });
        let s1 = read_s1(src, opts.base.as_ref().ok(), threads, opts.background);
        let others = others.join().unwrap_or_else(|_| Others::panicked());
        (s1, others)
    });

    let merge_started = Instant::now();
    let stamp = SourceStamp {
        files: opts.stamps.clone(),
        packages: others.package_names.clone(),
    };
    let mut sources = vec![s1_line(&s1, &opts.base, floors)];
    sources.push(hive_line(LocalSource::S2, &others.s2, floors));
    sources.push(hive_line(LocalSource::S3, &others.s3, floors));
    sources.push(s4_line(&others.s4, floors));
    let mut records = s1.records;
    for part in [others.s2_records, others.s3_records, others.s4_records] {
        records.merge(part);
    }
    let merge = merge_started.elapsed();

    let header = LocalHeader {
        built_at: opts.built_at.clone(),
        computer: opts.computer.clone(),
        edition: os.edition.clone(),
        build: os.build,
        ubr: os.ubr,
        builder_version: BUILDER_VERSION.to_owned(),
        source_id: stamp.id(),
    };
    let write_started = Instant::now();
    let counts = records.counts();
    let encoded = encode(&header, &sources, &records)?;
    drop(records);
    let write = write_started.elapsed();

    Ok(LocalBaselineFile {
        header,
        sources,
        counts,
        record_count: encoded.record_count,
        sha256: encoded.sha256,
        text_bytes: encoded.text_bytes,
        bytes: encoded.bytes,
        stamp,
        timings: BuildTimings {
            list: s1.list_time,
            read: s1.read_time,
            expand: s1.expand_time,
            parse: s1.parse_time,
            s1: s1.wall,
            hive: others.hive_time,
            appx: others.appx_time,
            merge: merge + s1.merge_time,
            write,
            total: started.elapsed(),
        },
        threads,
    })
}

fn enter_background(on: bool) {
    if on {
        // Background mode only lowers priority; failing to enter it changes nothing else.
        let _ = purge_win::process::set_thread_background(true);
    }
}

// ---------------------------------------------------------------------------------------------------
// S1

/// What S1 gave, merged over the worker threads.
#[derive(Debug, Default)]
struct S1 {
    /// Why S1 failed as a whole: the listing failed or a worker panicked.
    failed: Option<String>,
    records: Records,
    listed: u64,
    read_failed: u64,
    expand: ExpandCounts,
    no_base: u64,
    parse_failed: u64,
    parsed: u64,
    failures: Vec<(String, String)>,
    stats: StatsSum,
    list_time: Duration,
    read_time: Duration,
    expand_time: Duration,
    parse_time: Duration,
    merge_time: Duration,
    wall: Duration,
}

/// Element counts summed over the parsed manifests.
#[derive(Debug, Default)]
struct StatsSum {
    registry_keys: u64,
    registry_values: u64,
    files: u64,
    directories: u64,
    files_without_destination: u64,
    unknown_value_types: u64,
    skipped: Skipped,
    unknown_macros: BTreeMap<String, u64>,
    unknown_macros_unlisted: u64,
    wow64: u64,
    tokens: BTreeMap<String, u64>,
}

impl StatsSum {
    fn add(&mut self, s: ManifestStats) {
        self.registry_keys += s.registry_keys;
        self.registry_values += s.registry_values;
        self.files += s.files;
        self.directories += s.directories;
        self.files_without_destination += s.files_without_destination;
        self.unknown_value_types += s.unknown_value_types;
        add_skipped(&mut self.skipped, &s.skipped);
        for (name, n) in s.unknown_macros {
            *self.unknown_macros.entry(name).or_default() += n;
        }
        self.unknown_macros_unlisted += s.unknown_macros_unlisted;
        if s.view == super::macros::View::Wow64 {
            self.wow64 += 1;
        }
        let token = s.public_key_token.unwrap_or_else(|| "none".into());
        *self.tokens.entry(token.to_ascii_lowercase()).or_default() += 1;
    }

    fn merge(&mut self, o: StatsSum) {
        self.registry_keys += o.registry_keys;
        self.registry_values += o.registry_values;
        self.files += o.files;
        self.directories += o.directories;
        self.files_without_destination += o.files_without_destination;
        self.unknown_value_types += o.unknown_value_types;
        add_skipped(&mut self.skipped, &o.skipped);
        for (name, n) in o.unknown_macros {
            *self.unknown_macros.entry(name).or_default() += n;
        }
        self.unknown_macros_unlisted += o.unknown_macros_unlisted;
        self.wow64 += o.wow64;
        for (t, n) in o.tokens {
            *self.tokens.entry(t).or_default() += n;
        }
    }
}

fn add_skipped(to: &mut Skipped, s: &Skipped) {
    to.key_unknown_macro += s.key_unknown_macro;
    to.value_unknown_macro += s.value_unknown_macro;
    to.path_unknown_macro += s.path_unknown_macro;
    to.unknown_root += s.unknown_root;
    to.too_long += s.too_long;
    to.not_absolute += s.not_absolute;
    to.incomplete += s.incomplete;
    to.orphan_values += s.orphan_values;
    to.values_of_skipped_keys += s.values_of_skipped_keys;
}

fn read_s1(src: &dyn LocalSources, base: Option<&SxsBase>, threads: usize, background: bool) -> S1 {
    let started = Instant::now();
    let listing = std::thread::scope(|scope| {
        // The listing runs on a background thread as well.
        scope
            .spawn(|| {
                enter_background(background);
                src.manifests()
            })
            .join()
    });
    let list_time = started.elapsed();
    let items: ManifestIter<'_> = match listing {
        Ok(Ok(items)) => items,
        Ok(Err(e)) => {
            return S1 {
                failed: Some(format!("cannot list the manifests: {e}")),
                list_time,
                wall: started.elapsed(),
                ..S1::default()
            };
        }
        Err(_) => {
            return S1 {
                failed: Some("the listing thread panicked".into()),
                list_time,
                wall: started.elapsed(),
                ..S1::default()
            };
        }
    };
    let queue = Mutex::new(items);
    let shared = Mutex::new(Records::new());
    let parts: Vec<Option<S1>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    enter_background(background);
                    s1_worker(&queue, &shared, base)
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().ok()).collect()
    });
    let mut out = S1 {
        list_time,
        records: shared.into_inner().unwrap_or_else(PoisonError::into_inner),
        ..S1::default()
    };
    for part in parts {
        let Some(p) = part else {
            out.failed = Some("a manifest worker thread panicked".into());
            continue;
        };
        out.records.merge(p.records);
        out.listed += p.listed;
        out.read_failed += p.read_failed;
        out.expand.expanded += p.expand.expanded;
        out.expand.plain += p.expand.plain;
        out.expand.unsupported += p.expand.unsupported;
        out.expand.failed += p.expand.failed;
        out.no_base += p.no_base;
        out.parse_failed += p.parse_failed;
        out.parsed += p.parsed;
        out.failures.extend(p.failures);
        out.stats.merge(p.stats);
        out.read_time += p.read_time;
        out.expand_time += p.expand_time;
        out.parse_time += p.parse_time;
        out.merge_time += p.merge_time;
    }
    out.failures.sort();
    out.wall = started.elapsed();
    out
}

/// Records a worker collects before it merges them into the shared set (when the set is free).
const FLUSH_RECORDS: u64 = 32 * 1024;

/// Merges `part.records` into `shared`: always when `force`, else only past [`FLUSH_RECORDS`] and when
/// no other worker holds the set (past four times as many it waits). Keeps the threads' copies of the
/// same keys short-lived, which bounds the build's peak memory.
fn flush(part: &mut S1, shared: &Mutex<Records>, force: bool) {
    let c = part.records.counts();
    let n = c.keys + c.values + c.dirs + c.files;
    if n == 0 || (!force && n < FLUSH_RECORDS) {
        return;
    }
    let t = Instant::now();
    let mut guard = if force || n >= 4 * FLUSH_RECORDS {
        shared.lock().unwrap_or_else(PoisonError::into_inner)
    } else {
        match shared.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        }
    };
    guard.merge(std::mem::take(&mut part.records));
    drop(guard);
    part.merge_time += t.elapsed();
}

fn s1_worker(
    queue: &Mutex<ManifestIter<'_>>,
    shared: &Mutex<Records>,
    base: Option<&SxsBase>,
) -> S1 {
    let mut part = S1::default();
    // `expand` reads the base only for a `DCM` file, which never reaches it without one.
    let no_base = SxsBase::from_bytes(Vec::new(), PathBuf::new());
    loop {
        let t = Instant::now();
        let next = queue.lock().unwrap_or_else(PoisonError::into_inner).next();
        part.read_time += t.elapsed();
        let Some((name, bytes)) = next else { break };
        part.listed += 1;
        let bytes: SourceResult<Vec<u8>> = bytes;
        let bytes = match bytes {
            Ok(b) => b,
            Err(e) => {
                part.read_failed += 1;
                part.failures.push((name, format!("read: {e}")));
                continue;
            }
        };
        let format = ManifestFormat::detect(&bytes);
        let t = Instant::now();
        let xml = if format == ManifestFormat::Dcm && base.is_none() {
            part.no_base += 1;
            part.expand.failed += 1;
            part.failures.push((name, "expand: no delta base".into()));
            part.expand_time += t.elapsed();
            continue;
        } else {
            sxs::expand(&bytes, base.unwrap_or(&no_base))
        };
        part.expand.add(format, &xml);
        part.expand_time += t.elapsed();
        drop(bytes);
        let xml = match xml {
            Ok(x) => x,
            Err(e) => {
                part.failures.push((name, format!("expand: {e}")));
                continue;
            }
        };
        let t = Instant::now();
        match manifest::parse(&xml, &mut part.records) {
            Ok(stats) => {
                part.parsed += 1;
                part.stats.add(stats);
            }
            Err(e) => {
                part.parse_failed += 1;
                part.failures.push((name, format!("parse: {e}")));
            }
        }
        part.parse_time += t.elapsed();
        flush(&mut part, shared, false);
    }
    flush(&mut part, shared, true);
    part
}

fn s1_line(s1: &S1, base: &Result<SxsBase, String>, floors: &SealFloors) -> SourceLine {
    let c = s1.records.counts();
    let mut reasons = Vec::new();
    let mut facts: Vec<(String, String)> = Vec::new();
    let mut fact = |name: &str, value: String| facts.push((name.to_owned(), fact_value(&value)));
    match base {
        Ok(b) => fact(
            "base",
            format!("{} ({} bytes)", b.wcp_path().display(), b.bytes().len()),
        ),
        Err(e) => {
            fact("base", "none".into());
            reasons.push(fact_value(&format!("no delta base: {e}")));
        }
    }
    fact("manifests", s1.listed.to_string());
    fact("parsed", s1.parsed.to_string());
    fact("dcm-expanded", s1.expand.expanded.to_string());
    fact("plain", s1.expand.plain.to_string());
    fact("unsupported", s1.expand.unsupported.to_string());
    fact("expand-failed", s1.expand.failed.to_string());
    fact("no-base", s1.no_base.to_string());
    fact("read-failed", s1.read_failed.to_string());
    fact("parse-failed", s1.parse_failed.to_string());
    fact("keys", c.keys.to_string());
    fact("values", c.values.to_string());
    fact("dirs", c.dirs.to_string());
    fact("files", c.files.to_string());
    let st = &s1.stats;
    fact("registry-key-elements", st.registry_keys.to_string());
    fact("registry-value-elements", st.registry_values.to_string());
    fact("file-elements", st.files.to_string());
    fact("directory-elements", st.directories.to_string());
    fact(
        "files-without-destination",
        st.files_without_destination.to_string(),
    );
    fact("unknown-value-types", st.unknown_value_types.to_string());
    fact("wow64-manifests", st.wow64.to_string());
    let sk = &st.skipped;
    fact("key-unknown-macro", sk.key_unknown_macro.to_string());
    fact("value-unknown-macro", sk.value_unknown_macro.to_string());
    fact("path-unknown-macro", sk.path_unknown_macro.to_string());
    fact("unknown-root", sk.unknown_root.to_string());
    fact("too-long", sk.too_long.to_string());
    fact("not-absolute", sk.not_absolute.to_string());
    fact("incomplete-elements", sk.incomplete.to_string());
    fact("orphan-values", sk.orphan_values.to_string());
    fact(
        "values-of-skipped-keys",
        sk.values_of_skipped_keys.to_string(),
    );
    let mut macros: Vec<(&String, &u64)> = st.unknown_macros.iter().collect();
    macros.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    fact(
        "unknown-macros",
        macros
            .iter()
            .take(LISTED_MACROS)
            .map(|(n, c)| format!("{n}:{c}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    fact(
        "unknown-macros-unlisted",
        st.unknown_macros_unlisted.to_string(),
    );
    fact(
        "tokens",
        st.tokens
            .iter()
            .map(|(t, n)| format!("{t}:{n}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    fact("first-failures", failures(&s1.failures));

    let status = match &s1.failed {
        Some(e) => {
            reasons.push(fact_value(e));
            SourceStatus::Failed
        }
        None => {
            if s1.parsed.saturating_mul(1000) < s1.listed.saturating_mul(floors.s1_parsed_per_mille)
            {
                reasons.push(format!(
                    "{} of {} manifests expanded and parsed, below {}.{}%",
                    s1.parsed,
                    s1.listed,
                    floors.s1_parsed_per_mille / 10,
                    floors.s1_parsed_per_mille % 10
                ));
            }
            if s1.listed < floors.s1_manifests {
                reasons.push(format!(
                    "{} manifests listed, below {}",
                    s1.listed, floors.s1_manifests
                ));
            }
            if c.keys < floors.s1_keys {
                reasons.push(format!(
                    "{} distinct keys, below {}",
                    c.keys, floors.s1_keys
                ));
            }
            if sk.key_unknown_macro > floors.s1_max_key_unknown_macro {
                reasons.push(format!(
                    "{} key names skipped for an unknown macro, above {}",
                    sk.key_unknown_macro, floors.s1_max_key_unknown_macro
                ));
            }
            if reasons.is_empty() {
                SourceStatus::Ok
            } else {
                SourceStatus::Incomplete
            }
        }
    };
    SourceLine {
        source: LocalSource::S1,
        status,
        items: s1.listed,
        records: c.keys + c.values + c.dirs + c.files,
        skipped: s1.listed - s1.parsed.min(s1.listed),
        reasons,
        facts,
    }
}

fn failures(list: &[(String, String)]) -> String {
    list.iter()
        .take(LISTED_FAILURES)
        .map(|(name, why)| format!("{name} ({why})"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------------------------------
// S2, S3, S4

struct Others {
    s2: Result<HiveStats, String>,
    s2_records: Records,
    s3: Result<HiveStats, String>,
    s3_records: Records,
    s4: Result<InboxStats, String>,
    s4_records: Records,
    package_names: Vec<String>,
    hive_time: Duration,
    appx_time: Duration,
}

impl Others {
    fn panicked() -> Others {
        let e = "the reading thread panicked";
        Others {
            s2: Err(e.to_owned()),
            s2_records: Records::new(),
            s3: Err(e.to_owned()),
            s3_records: Records::new(),
            s4: Err(e.to_owned()),
            s4_records: Records::new(),
            package_names: Vec::new(),
            hive_time: Duration::ZERO,
            appx_time: Duration::ZERO,
        }
    }
}

fn read_others(src: &dyn LocalSources) -> Others {
    let t = Instant::now();
    let mut s2_records = Records::new();
    let s2 = hive::default_hive_records(src, &mut s2_records).map_err(|e| e.to_string());
    let mut s3_records = Records::new();
    let s3 = hive::system_default_records(src, &mut s3_records).map_err(|e| e.to_string());
    let hive_time = t.elapsed();
    let t = Instant::now();
    let mut s4_records = Records::new();
    let (s4, package_names) = match src.inbox_packages() {
        Ok(inbox) => {
            let names = names_of(&inbox);
            (Ok(appx::packages_records(&inbox, &mut s4_records)), names)
        }
        Err(e) => (Err(e.to_string()), Vec::new()),
    };
    Others {
        s2,
        s2_records,
        s3,
        s3_records,
        s4,
        s4_records,
        package_names,
        hive_time,
        appx_time: t.elapsed(),
    }
}

fn names_of(inbox: &InboxPackages) -> Vec<String> {
    let mut names: Vec<String> = inbox.packages.iter().map(|p| p.full_name.clone()).collect();
    names.sort();
    names
}

/// Keys of `HKU\.DEFAULT` whose DACL Windows sets so that an elevated Administrator cannot read them
/// (design §3.4). An S3 walk that cannot read one of these, and nothing else, is still complete:
/// what the elevated builder cannot read, the elevated scanner cannot read either, so no candidate
/// can be judged against what the baseline misses there. Exact paths, compared folded.
///
/// - `…\SystemCertificates\Root\ProtectedRoots`: the protected root list of the account's certificate
///   store. Its DACL is protected (not inherited) and grants only the account itself (here SYSTEM),
///   `NT SERVICE\CryptSvc` and one capability SID; Administrators get nothing (checked on the host's
///   own `HKCU` copy, 2026-11-21). Taken to be the one `unreadable=1` key of S3 on both rig VMs in
///   gate M round 1; the `unreadable-keys` detail of the next run confirms it.
pub const S3_DENIED_BY_DESIGN: &[&str] =
    &[r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root\ProtectedRoots"];

/// `key` (a full path as the walk spells it) is on [`S3_DENIED_BY_DESIGN`].
fn denied_by_design(key: &str) -> bool {
    let key = crate::baseline::normalised_key(key);
    S3_DENIED_BY_DESIGN
        .iter()
        .any(|k| crate::baseline::normalised_key(k) == key)
}

/// A walk's named keys as one detail value (`, `-separated, each as the format can carry it).
fn key_list(keys: &[String]) -> String {
    keys.iter()
        .map(|k| fact_value(k))
        .collect::<Vec<_>>()
        .join(", ")
}

fn hive_line(
    source: LocalSource,
    s: &Result<HiveStats, String>,
    floors: &SealFloors,
) -> SourceLine {
    let stats = match s {
        Ok(stats) => stats,
        Err(e) => {
            return SourceLine {
                source,
                status: SourceStatus::Failed,
                items: 0,
                records: 0,
                skipped: 0,
                reasons: vec![fact_value(&format!("cannot read: {e}"))],
                facts: Vec::new(),
            };
        }
    };
    let w = &stats.walk;
    let mut reasons = Vec::new();
    // S3 only: the named unreadable keys Windows denies to Administrators by design do not make the
    // walk incomplete. A key beyond the named ones is never on the list, so it always counts.
    let by_design = if source == LocalSource::S3 {
        w.unreadable_keys
            .iter()
            .filter(|k| denied_by_design(k))
            .count() as u64
    } else {
        0
    };
    let unreadable = w.unreadable.saturating_sub(by_design);
    if unreadable > 0 {
        reasons.push(format!("{unreadable} keys not read whole (unreadable)"));
    }
    if w.vanished > 0 {
        reasons.push(format!(
            "{} listed keys could not be opened (vanished)",
            w.vanished
        ));
    }
    if w.capped {
        reasons.push("the walk reached its depth or key cap".into());
    }
    if source == LocalSource::S2 && w.keys < floors.s2_keys {
        reasons.push(format!("{} keys, below {}", w.keys, floors.s2_keys));
    }
    let mut facts = vec![
        ("origin".to_owned(), fact_value(&w.origin)),
        ("keys".to_owned(), w.keys.to_string()),
        ("values".to_owned(), w.values.to_string()),
        ("unreadable".to_owned(), w.unreadable.to_string()),
        ("vanished".to_owned(), w.vanished.to_string()),
        ("links".to_owned(), w.links.to_string()),
        ("capped".to_owned(), w.capped.to_string()),
    ];
    if source == LocalSource::S3 {
        facts.push(("unreadable-by-design".to_owned(), by_design.to_string()));
    }
    facts.push(("unreadable-keys".to_owned(), key_list(&w.unreadable_keys)));
    facts.push(("vanished-keys".to_owned(), key_list(&w.vanished_keys)));
    SourceLine {
        source,
        status: if reasons.is_empty() {
            SourceStatus::Ok
        } else {
            SourceStatus::Incomplete
        },
        items: w.keys + w.values,
        records: stats.records,
        skipped: w.unreadable + w.vanished,
        reasons,
        facts,
    }
}

fn s4_line(s: &Result<InboxStats, String>, floors: &SealFloors) -> SourceLine {
    let stats = match s {
        Ok(stats) => stats,
        Err(e) => {
            return SourceLine {
                source: LocalSource::S4,
                status: SourceStatus::Failed,
                items: 0,
                records: 0,
                skipped: 0,
                reasons: vec![fact_value(&format!("cannot read the package list: {e}"))],
                facts: Vec::new(),
            };
        }
    };
    let mut reasons = Vec::new();
    if !stats.machine_wide {
        reasons.push(
            "the package list is the engine account's own, not every user's (not elevated)".into(),
        );
    }
    if !stats.provisioned_read {
        reasons.push("the provisioned package list could not be read".into());
    }
    if !stats.repository_read {
        reasons.push("the package repository index could not be read".into());
    }
    if stats.parsed < floors.s4_manifests {
        reasons.push(format!(
            "{} package manifests parsed, below {}",
            stats.parsed, floors.s4_manifests
        ));
    }
    let d = &stats.declarations;
    let facts = vec![
        ("packages".to_owned(), stats.packages.to_string()),
        ("system".to_owned(), stats.system.to_string()),
        ("parsed".to_owned(), stats.parsed.to_string()),
        ("failed".to_owned(), stats.failed.len().to_string()),
        ("not-inbox".to_owned(), stats.not_inbox.to_string()),
        ("machine-wide".to_owned(), stats.machine_wide.to_string()),
        ("provisioned".to_owned(), stats.provisioned_read.to_string()),
        ("repository".to_owned(), stats.repository_read.to_string()),
        ("file-types".to_owned(), d.file_types.to_string()),
        ("protocols".to_owned(), d.protocols.to_string()),
        ("classes".to_owned(), d.classes.to_string()),
        ("interfaces".to_owned(), d.interfaces.to_string()),
        ("type-libs".to_owned(), d.type_libs.to_string()),
        ("prog-ids".to_owned(), d.prog_ids.to_string()),
        (
            "generated-prog-ids".to_owned(),
            d.generated_prog_ids.to_string(),
        ),
        ("declarations-skipped".to_owned(), d.skipped.to_string()),
        (
            "first-failures".to_owned(),
            fact_value(&failures(&sorted(&stats.failed))),
        ),
    ];
    SourceLine {
        source: LocalSource::S4,
        status: if reasons.is_empty() {
            SourceStatus::Ok
        } else {
            SourceStatus::Incomplete
        },
        items: stats.packages,
        records: stats.records,
        skipped: stats.failed.len() as u64,
        reasons,
        facts,
    }
}

fn sorted(list: &[(String, String)]) -> Vec<(String, String)> {
    let mut v = list.to_vec();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use purge_model::FileTime;
    use purge_source::fixture::{Fixture, FixtureBuilder, HiveFixture};
    use purge_source::local_baseline::{PROFILE_LIST, PROVISIONED_KEY, REPOSITORY_EXTENSIONS_KEY};
    use purge_source::types::{FileTimes, PackageInfo, PackageSignatureKind, RegData};

    use super::*;
    use crate::local_baseline::file::LocalBaseline;

    const MANIFESTS: &str = r"C:\Windows\WinSxS\Manifests";
    const HIVE: &str = r"C:\Users\Default\NTUSER.DAT";
    const SHELL: &str =
        "Microsoft.Windows.ShellExperienceHost_10.0.1.0_neutral_neutral_cw5n1h2txyewy";

    fn fixture_manifest(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/manifests/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).unwrap()
    }

    /// Hand-written in the shape of an inbox package manifest.
    const APPX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Applications>
    <Application Id="App">
      <Extensions>
        <uap:Extension Category="windows.fileTypeAssociation">
          <uap:FileTypeAssociation Name="t">
            <uap:SupportedFileTypes><uap:FileType>.purgeappx</uap:FileType></uap:SupportedFileTypes>
          </uap:FileTypeAssociation>
        </uap:Extension>
        <uap:Extension Category="windows.protocol">
          <uap:Protocol Name="ms-purgetest"/>
        </uap:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"#;

    /// A machine whose four sources all pass [`floors`] once [`with_hive`] adds the default hive.
    fn machine() -> FixtureBuilder {
        let write = FileTimes {
            modified: Some(FileTime(133_000_000_000_000_000)),
            ..FileTimes::default()
        };
        let mut b = Fixture::builder()
            .elevated(true)
            .env("SystemRoot", r"C:\Windows")
            .env("SystemDrive", "C:")
            .expand_sz(PROFILE_LIST, "Default", r"%SystemDrive%\Users\Default")
            .file(HIVE, 262_144)
            .times(HIVE, write)
            .sz(
                r"HKU\.DEFAULT\Control Panel\Colors",
                "Window",
                "255 255 255",
            )
            .dword(r"HKU\.DEFAULT\Software\Microsoft\PurgeTest", "Flag", 1)
            .key(&format!(
                r"{PROVISIONED_KEY}\Some.Package_1.0.0.0_neutral_~_8wekyb3d8bbwe"
            ))
            .value(
                &format!(r"{REPOSITORY_EXTENSIONS_KEY}\ProgIDs\AppXpurgetest"),
                SHELL,
                RegData::new(0, Vec::new()),
            )
            .package(PackageInfo {
                full_name: SHELL.into(),
                family: "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy".into(),
                install_location: Some(r"C:\Windows\SystemApps\Shell".into()),
                external_location: None,
                sparse: false,
                users: Vec::new(),
                is_framework: false,
                is_resource: false,
                signature_kind: PackageSignatureKind::System,
            })
            .file_content(
                r"C:\Windows\SystemApps\Shell\AppxManifest.xml",
                APPX.as_bytes().to_vec(),
            );
        for name in [
            "clsid.manifest",
            "hkcu.manifest",
            "wow64.manifest",
            "paths.manifest",
        ] {
            b = b
                .file_content(&format!(r"{MANIFESTS}\{name}"), fixture_manifest(name))
                .times(&format!(r"{MANIFESTS}\{name}"), write);
        }
        b
    }

    fn with_hive(mut f: Fixture) -> Fixture {
        f.set_offline_hive(
            HIVE,
            HiveFixture::new()
                .value(
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    "OneDriveSetup",
                    1,
                )
                .value(r"Control Panel\Desktop", "Wallpaper", 1)
                .key(r"AppEvents\Schemes"),
        );
        f
    }

    fn floors() -> SealFloors {
        SealFloors {
            s1_parsed_per_mille: 999,
            s1_manifests: 4,
            s1_keys: 20,
            s1_max_key_unknown_macro: 0,
            s2_keys: 5,
            s4_manifests: 1,
        }
    }

    fn os() -> OsInfo {
        OsInfo {
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
        }
    }

    fn options(f: &Fixture) -> BuildOptions {
        BuildOptions {
            built_at: iso_utc(1_763_683_200),
            computer: "TEST-PC".into(),
            base: Ok(SxsBase::from_bytes(
                vec![0; 16],
                PathBuf::from(r"C:\fake\wcp.dll"),
            )),
            stamps: file_stamps(f, f, f),
            threads: 2,
            background: false,
            floors: floors(),
        }
    }

    fn text(file: &LocalBaselineFile) -> String {
        let mut s = String::new();
        flate2::read::GzDecoder::new(&file.bytes[..])
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    fn line(file: &LocalBaselineFile, source: LocalSource) -> &SourceLine {
        file.sources.iter().find(|s| s.source == source).unwrap()
    }

    #[test]
    fn fixture_build_records_counts_and_bytes() {
        let f = with_hive(machine().build());
        let opts = options(&f);
        assert!(
            opts.stamps.problems.is_empty(),
            "{:?}",
            opts.stamps.problems
        );
        assert_eq!(opts.stamps.manifests, 4);
        assert_eq!(opts.stamps.hive_bytes, 262_144);
        let built = build(&f, &os(), &opts).unwrap();
        assert!(built.complete(), "{:?}", built.incomplete_reasons());

        let s1 = line(&built, LocalSource::S1);
        assert_eq!((s1.status, s1.items, s1.skipped), (SourceStatus::Ok, 4, 0));
        assert_eq!(s1.fact("plain"), Some("4"));
        assert_eq!(s1.fact("key-unknown-macro"), Some("0"));
        assert_eq!(s1.fact("base"), Some(r"C:\fake\wcp.dll (16 bytes)"));
        assert_eq!(s1.fact("tokens"), Some("31bf3856ad364e35:4"));
        let s2 = line(&built, LocalSource::S2);
        // The root, Software … Run (5), Control Panel, Desktop, AppEvents, Schemes: 10 keys, 2 values.
        assert_eq!((s2.status, s2.skipped), (SourceStatus::Ok, 0));
        assert_eq!(
            (s2.fact("keys"), s2.fact("values")),
            (Some("10"), Some("2"))
        );
        assert_eq!(s2.items, 12);
        assert_eq!(s2.fact("origin"), Some(HIVE));
        let s3 = line(&built, LocalSource::S3);
        assert_eq!(s3.status, SourceStatus::Ok);
        // The root, Control Panel, Colors, Software, Microsoft, PurgeTest.
        assert_eq!(s3.fact("keys"), Some("6"));
        let s4 = line(&built, LocalSource::S4);
        assert_eq!((s4.status, s4.items, s4.skipped), (SourceStatus::Ok, 1, 0));
        assert_eq!(s4.fact("file-types"), Some("1"));
        assert_eq!(built.stamp.packages, [SHELL]);
        assert_eq!(built.header.source_id, built.stamp.id());
        assert_eq!(built.header.builder_version, BUILDER_VERSION);

        let t = text(&built);
        assert!(t.starts_with(&format!(
            "#purge-baseline-local 1\t2025-11-21T00:00:00Z\tTEST-PC\tProfessional\t26100.9711\tbl.2\t{}\n#src\tS1\tok\t4\t",
            built.stamp.id()
        )));
        assert_eq!(t.matches("\n#src\t").count(), 4);
        for want in [
            "K\thklm\\\\software\\\\classes\\\\clsid\\\\{0d7a1f64-3c2b-4e5a-9f10-0000000000a1}\\\\inprocserver32\n",
            "K\thklm\\\\software\\\\classes\\\\wow6432node\\\\clsid\\\\{0d7a1f64-3c2b-4e5a-9f10-0000000000b2}\n",
            "K\thku\\\\s-1-5-21-0-0-0-1000\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\n",
            "K\thku\\\\.default\\\\control panel\\\\colors\n",
            "K\thklm\\\\software\\\\classes\\\\.purgeappx\n",
            "V\thku\\\\.default\\\\software\\\\microsoft\\\\purgetest\tflag\t4\t0000000000000000\n",
            "F\tc:\\\\windows\\\\system32\\\\purgetest.dll\n",
        ] {
            assert!(t.contains(want), "missing {want:?}");
        }
        let records = t
            .lines()
            .filter(|l| matches!(l.as_bytes().first(), Some(b'K' | b'V' | b'D' | b'F')))
            .count() as u64;
        assert_eq!(records, built.record_count);
        let c = built.counts;
        assert_eq!(c.keys + c.values + c.dirs + c.files, built.record_count);
        assert!(t.ends_with(&format!("#end\t{}\t{}\n", built.record_count, built.sha256)));

        // The reader gives the same seal and answers from every source.
        let lb = LocalBaseline::from_bytes(&built.bytes).unwrap();
        assert!(lb.complete());
        assert_eq!(lb.sources(), built.sources.as_slice());
        assert_eq!(lb.id(), built.stamp.id());
        assert!(lb.has_key(r"HKCR\CLSID\{0D7A1F64-3C2B-4E5A-9F10-0000000000A1}\InProcServer32"));
        assert!(
            lb.has_key(r"HKU\S-1-5-21-5-6-7-1001\Software\Microsoft\Windows\CurrentVersion\Run")
        );
        assert!(lb.has_value(r"HKU\S-1-5-18\Software\Microsoft\PurgeTest", "Flag"));
        assert!(lb.has_key(r"HKU\S-1-5-21-5-6-7-1001_Classes\.purgeappx"));
        assert!(!lb.has_key(r"HKLM\SOFTWARE\Classes\.notthere"));

        // Deterministic: another thread count, background mode, a second run give the same bytes.
        for (threads, background) in [(1, false), (3, true), (2, false)] {
            let again = build(
                &f,
                &os(),
                &BuildOptions {
                    threads,
                    background,
                    ..options(&f)
                },
            )
            .unwrap();
            assert_eq!(again.bytes, built.bytes, "{threads} threads");
        }
        let timing = built.timings.lines(built.threads);
        assert_eq!(timing.len(), 10);
        assert!(
            timing
                .iter()
                .all(|l| l.starts_with("timing: baseline.local."))
        );
    }

    /// Builds `f` with the options changed by `tweak`; it must be incomplete, in memory and in the file.
    fn incomplete(
        f: &Fixture,
        tweak: impl FnOnce(&mut BuildOptions),
    ) -> (LocalBaselineFile, Vec<String>) {
        let mut opts = options(f);
        tweak(&mut opts);
        let built = build(f, &os(), &opts).unwrap();
        assert!(!built.complete());
        let lb = LocalBaseline::from_bytes(&built.bytes).unwrap();
        assert!(!lb.complete());
        assert_eq!(lb.incomplete_reasons(), built.incomplete_reasons());
        let reasons = built.incomplete_reasons();
        (built, reasons)
    }

    fn one_reason(reasons: &[String], prefix: &str, part: &str) {
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(
            reasons[0].starts_with(prefix) && reasons[0].contains(part),
            "{reasons:?}"
        );
    }

    #[test]
    fn each_floor_violated_in_turn() {
        let f = with_hive(machine().build());
        let (_, r) = incomplete(&f, |o| o.floors.s1_manifests = 5);
        one_reason(&r, "S1 incomplete", "4 manifests listed, below 5");
        let (_, r) = incomplete(&f, |o| o.floors.s1_keys = 10_000);
        one_reason(&r, "S1 incomplete", "distinct keys, below 10000");
        let (_, r) = incomplete(&f, |o| o.base = Err("no servicing stack".into()));
        one_reason(&r, "S1 incomplete", "no delta base: no servicing stack");
        let (_, r) = incomplete(&f, |o| o.floors.s2_keys = 100);
        one_reason(&r, "S2 incomplete", "10 keys, below 100");
        let (_, r) = incomplete(&f, |o| o.floors.s4_manifests = 2);
        one_reason(&r, "S4 incomplete", "1 package manifests parsed, below 2");

        // One manifest of five that does not parse: 80% < 99.9%.
        let f = with_hive(
            machine()
                .file_content(
                    &format!(r"{MANIFESTS}\bad.manifest"),
                    fixture_manifest("malformed.manifest"),
                )
                .build(),
        );
        let (built, r) = incomplete(&f, |_| {});
        one_reason(
            &r,
            "S1 incomplete",
            "4 of 5 manifests expanded and parsed, below 99.9%",
        );
        let s1 = line(&built, LocalSource::S1);
        assert_eq!((s1.skipped, s1.fact("parse-failed")), (1, Some("1")));
        assert!(
            s1.fact("first-failures")
                .unwrap()
                .starts_with("bad.manifest (parse: ")
        );

        // A delta without a base is counted, not expanded.
        let f = with_hive(
            machine()
                .file_content(
                    &format!(r"{MANIFESTS}\delta.manifest"),
                    b"DCM\x01PA30xxxx".to_vec(),
                )
                .build(),
        );
        let (built, r) = incomplete(&f, |o| o.base = Err("none".into()));
        assert!(
            r[0].contains("no delta base") && r[0].contains("4 of 5"),
            "{r:?}"
        );
        assert_eq!(line(&built, LocalSource::S1).fact("no-base"), Some("1"));

        // Key names with an unknown macro above the floor.
        let f = with_hive(
            machine()
                .file_content(
                    &format!(r"{MANIFESTS}\macros.manifest"),
                    fixture_manifest("key-macros.manifest"),
                )
                .build(),
        );
        let (built, r) = incomplete(&f, |o| o.floors.s1_manifests = 5);
        one_reason(
            &r,
            "S1 incomplete",
            "key names skipped for an unknown macro, above 0",
        );
        assert!(
            line(&built, LocalSource::S1)
                .fact("unknown-macros")
                .unwrap()
                .contains("build.arch")
        );

        // Unelevated: the package list is not every user's.
        let f = with_hive(machine().elevated(false).build());
        let (_, r) = incomplete(&f, |_| {});
        one_reason(&r, "S4 incomplete", "not elevated");

        // A key of HKU\.DEFAULT that cannot be read whole.
        let f = with_hive(
            machine()
                .key(r"HKU\.DEFAULT\Software\Secret\Deeper")
                .denied(r"HKU\.DEFAULT\Software\Secret")
                .build(),
        );
        let (built, r) = incomplete(&f, |_| {});
        one_reason(&r, "S3 incomplete", "1 keys not read whole");
        // The key is named in the detail, as the file carries it.
        let s3 = line(&built, LocalSource::S3);
        assert_eq!(
            s3.fact("unreadable-keys"),
            Some(r"HKU\.DEFAULT\Software\Secret")
        );
        assert_eq!(
            (s3.fact("unreadable-by-design"), s3.fact("vanished-keys")),
            (Some("0"), Some(""))
        );
        let lb = LocalBaseline::from_bytes(&built.bytes).unwrap();
        assert_eq!(
            lb.sources()[2].fact("unreadable-keys"),
            s3.fact("unreadable-keys")
        );
        assert!(
            s3.line()
                .contains(r"unreadable-keys=HKU\\.DEFAULT\\Software\\Secret; ")
        );
    }

    #[test]
    fn s3_keys_denied_by_design() {
        const PROTECTED: &str =
            r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root\ProtectedRoots";
        // ProtectedRoots alone (spelled in another case): complete, and still named.
        let f = with_hive(
            machine()
                .key(&format!(r"{PROTECTED}\Inner"))
                .denied(&PROTECTED.to_ascii_lowercase())
                .build(),
        );
        let built = build(&f, &os(), &options(&f)).unwrap();
        assert!(built.complete(), "{:?}", built.incomplete_reasons());
        let s3 = line(&built, LocalSource::S3);
        assert_eq!(s3.status, SourceStatus::Ok);
        assert_eq!(
            (s3.fact("unreadable"), s3.fact("unreadable-by-design")),
            (Some("1"), Some("1"))
        );
        assert!(
            s3.fact("unreadable-keys")
                .unwrap()
                .eq_ignore_ascii_case(PROTECTED)
        );
        assert!(LocalBaseline::from_bytes(&built.bytes).unwrap().complete());

        // ProtectedRoots and one other key: incomplete, counting only the other one.
        let f = with_hive(
            machine()
                .key(&format!(r"{PROTECTED}\Inner"))
                .denied(PROTECTED)
                .key(r"HKU\.DEFAULT\Software\Secret\Deeper")
                .denied(r"HKU\.DEFAULT\Software\Secret")
                .build(),
        );
        let (built, r) = incomplete(&f, |_| {});
        one_reason(&r, "S3 incomplete", "1 keys not read whole (unreadable)");
        let s3 = line(&built, LocalSource::S3);
        assert_eq!(
            (s3.fact("unreadable"), s3.fact("unreadable-by-design")),
            (Some("2"), Some("1"))
        );

        // A key below ProtectedRoots or beside it is not on the list (exact paths only).
        for other in [
            format!(r"{PROTECTED}\Inner"),
            r"HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root".to_owned(),
        ] {
            let f = with_hive(
                machine()
                    .key(&format!(r"{other}\Deeper"))
                    .denied(&other)
                    .build(),
            );
            let (_, r) = incomplete(&f, |_| {});
            one_reason(&r, "S3 incomplete", "1 keys not read whole");
        }

        // More unreadable keys than the line names: those beyond the list always count.
        let mut b = machine()
            .key(&format!(r"{PROTECTED}\Inner"))
            .denied(PROTECTED);
        for i in 0..20 {
            b = b
                .key(&format!(r"HKU\.DEFAULT\Software\Z{i:02}\Deeper"))
                .denied(&format!(r"HKU\.DEFAULT\Software\Z{i:02}"));
        }
        let (built, r) = incomplete(&with_hive(b.build()), |_| {});
        one_reason(&r, "S3 incomplete", "20 keys not read whole");
        let s3 = line(&built, LocalSource::S3);
        assert_eq!(
            s3.fact("unreadable-keys").unwrap().split(", ").count(),
            purge_source::local_baseline::LISTED_WALK_KEYS
        );

        // Folded, exact.
        assert!(denied_by_design(PROTECTED));
        assert!(denied_by_design(&PROTECTED.to_ascii_uppercase()));
        assert!(!denied_by_design(&format!(r"{PROTECTED}\x")));
    }

    #[test]
    fn an_unreadable_source_fails_its_line() {
        // S2: no hive at the path ProfileList names.
        let (built, r) = incomplete(&machine().build(), |_| {});
        one_reason(&r, "S2 failed", "cannot read");
        assert_eq!(line(&built, LocalSource::S2).records, 0);
        // S4: the package list cannot be read.
        let mut f = with_hive(machine().build());
        f.set_packages(None);
        let (_, r) = incomplete(&f, |_| {});
        one_reason(&r, "S4 failed", "cannot read the package list");
        // S1: no %SystemRoot%, so no manifest directory; S3: no HKU\.DEFAULT.
        let f = with_hive(
            Fixture::builder()
                .expand_sz(PROFILE_LIST, "Default", r"C:\Users\Default")
                .build(),
        );
        let (built, r) = incomplete(&f, |o| o.floors = SealFloors::default());
        assert!(
            r.iter()
                .any(|r| r.starts_with("S1 failed: cannot list the manifests")),
            "{r:?}"
        );
        assert!(
            r.iter().any(|r| r.starts_with("S3 failed: cannot read")),
            "{r:?}"
        );
        assert_eq!(line(&built, LocalSource::S1).status, SourceStatus::Failed);
    }

    #[test]
    fn source_id_follows_every_input() {
        let f = with_hive(machine().build());
        let base = SourceStamp {
            files: file_stamps(&f, &f, &f),
            packages: vec!["B".into(), "A".into()],
        };
        let id = base.id();
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        let same = SourceStamp {
            packages: vec!["A".into(), "B".into()],
            ..base.clone()
        };
        assert_eq!(same.id(), id, "package order does not matter");
        let changes: [fn(&mut SourceStamp); 7] = [
            |s| s.files.manifests += 1,
            |s| s.files.manifest_bytes += 1,
            |s| s.files.manifest_newest_write += 1,
            |s| s.files.hive_bytes += 1,
            |s| s.files.hive_write += 1,
            |s| s.packages.push("C".into()),
            |s| s.packages[0] = "A2".into(),
        ];
        for change in changes {
            let mut s = base.clone();
            change(&mut s);
            assert_ne!(s.id(), id, "{s:?}");
        }
        // Missing inputs are reported, not guessed.
        let empty = Fixture::new();
        let stamps = file_stamps(&empty, &empty, &empty);
        assert_eq!(stamps.problems.len(), 2, "{:?}", stamps.problems);
        assert_eq!((stamps.manifests, stamps.hive_bytes), (0, 0));
    }

    #[test]
    fn iso_times() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_763_683_200), "2025-11-21T00:00:00Z");
    }

    /// Budget run on the real machine (the rig and the host; not in CI): builds from the live
    /// sources and prints the `#src` and timing lines.
    /// `cargo test -p purge-index --release --lib -- --ignored live_build_budget --nocapture`.
    /// For the W4 investigation only (test knobs, never read by the engine): `PURGE_TEST_BL_FOREGROUND=1`
    /// builds at normal priority, `PURGE_TEST_BL_THREADS=<n>` sets the S1 worker count.
    #[test]
    #[ignore = "reads the whole live machine; run on the rig"]
    fn live_build_budget() {
        use purge_source::live::{Live, LiveLocal};
        let live = Live::new();
        let local = LiveLocal::new();
        let os = purge_source::system::SystemSource::os_info(&live.system).unwrap();
        let foreground = std::env::var("PURGE_TEST_BL_FOREGROUND").is_ok_and(|v| v == "1");
        let threads = std::env::var("PURGE_TEST_BL_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0usize);
        eprintln!("background {}, threads {threads} (0 = all)", !foreground);
        let opts = BuildOptions {
            built_at: iso_utc(0),
            computer: "budget".into(),
            base: sxs::find_base().map_err(|e| e.to_string()),
            stamps: file_stamps(&live.fs, &live.registry, &live.system),
            threads,
            background: !foreground,
            floors: SealFloors::default(),
        };
        let built = build(&local, &os, &opts).unwrap();
        for s in &built.sources {
            eprintln!("{}", s.line());
        }
        let lines = built.timings.lines(built.threads);
        for l in &lines {
            eprintln!("{l}");
        }
        eprintln!(
            "records {} ({:?}), text {} bytes, file {} bytes, complete {}: {:?}",
            built.record_count,
            built.counts,
            built.text_bytes,
            built.bytes.len(),
            built.complete(),
            built.incomplete_reasons()
        );
        assert_eq!(lines.len(), 10);
        assert!(
            lines
                .iter()
                .all(|l| l.starts_with("timing: baseline.local."))
        );
        let lb = LocalBaseline::from_bytes(&built.bytes).unwrap();
        assert_eq!(lb.record_count(), built.record_count);
    }
}
