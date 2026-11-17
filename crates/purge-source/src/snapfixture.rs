//! Building a [`Fixture`] from a rig snapshot (`snap-<run>-<phase>.tsv.gz`, vm/RIG.md §2), its structured
//! lists (`lists-<run>-<phase>.json`, RIG.md §3) and an optional overlay of file contents.
//!
//! What a snapshot gives and what it does not:
//! - `D`/`F` records become directories and files (attributes, size, write time, reparse tag). File
//!   contents, version info, signers and shortcut targets are not captured: the fixture is marked
//!   `unknown_file_facts`, and contents come only from the overlay directory
//!   (`<overlay>\C\Program Files\App\unins000.dat` supplies `C:\Program Files\App\unins000.dat`).
//! - `K` records become keys with their LastWriteTime and recorded value/subkey counts. Key names under
//!   `HKLM\SYSTEM\CurrentControlSet` are stored under `ControlSet001`.
//! - `V` records become values. `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`, `REG_MULTI_SZ`, `REG_DWORD` and
//!   `REG_QWORD` are rebuilt from the preview and the recorded length (terminators and trailing empty
//!   strings restored); a preview cut at 1024 characters gives [`RegData::truncated`]; every other type
//!   (binary, unknown) is [`RegData::data_unknown`] unless its length is 0. The recorded hash is kept in
//!   [`RegData::hash`].
//! - `#roots` / `#exclude` become the fixture's coverage, so a path outside the captured roots reads as
//!   not captured (never as absent). `#denied` and the paths of `#errors` become denied paths.
//! - The header gives the OS (`edition`, `build.ubr`), the computer name and "now". The lists give the
//!   interactive user's SID, MSI products, AppX packages and processes; without lists those are
//!   `NotCaptured`. Profiles, environment and known folders are derived from the captured registry
//!   ([`Fixture::derive_system_facts`]). The rig agent runs elevated, so the fixture is `elevated`.
//!
//! # M1b: scheduled tasks and MSI tables
//!
//! - **Tasks** come from the lists' `tasks` section when it has the M1b fields (RIG.md §3:
//!   `actions_detail`, `hidden`, `logon_type`, `has_stored_password`). [`SystemSource::tasks`] answers
//!   [`SourceError::NotCaptured`] (unknown, never "no tasks") for: lists without a `tasks` section, an
//!   M0/M1a/M2 list (no entry has `actions_detail`), an empty section (Windows always has tasks, and an
//!   empty section cannot tell an old list from a new one), and a list whose `errors` name the `tasks`
//!   section (the rig then writes an empty section). A section in which only some entries have
//!   `actions_detail`, or with an entry that does not have the documented shape, fails the load. The
//!   rig does not capture the author or the principal's user id (`None`); `stored_password` is set when
//!   `has_stored_password` is, and also when the logon type is missing or not one of the names known to
//!   hold no password (the cautious side, as the live source). Another action's kind is the CIM class
//!   name, with the two known ones written as the live source writes them (`send_email`,
//!   `show_message`).
//! - **MSI tables** come from an optional file beside the snapshot, `msi-tables-<run>-<phase>.json`
//!   (plain or gzip) for `snap-<run>-<phase>.tsv[.gz]` ([`msi_tables_file_for`]), written by the rig:
//!   `{"schema": "purge.rig.msi_tables/1", "packages": {"<LocalPackage>": <MsiTables>, ...}}`, where
//!   `<MsiTables>` has the fixture's `msi_tables` shape. Unknown fields are rejected at every depth; a
//!   package listed twice (in any case or slash form) fails the load. A package the rig could not read
//!   is written with `"truncated": true` (the caller treats it as unreadable); a package absent from a
//!   present file is `NotFound`. Without the file, [`SystemSource::msi_tables`] answers `NotCaptured`.
//!
//! An old snapshot (no M1b fields, no tables file) loads exactly as before.
//!
//! [`SystemSource::tasks`]: crate::system::SystemSource::tasks
//! [`SystemSource::msi_tables`]: crate::system::SystemSource::msi_tables
//! [`SourceError::NotCaptured`]: crate::types::SourceError::NotCaptured

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use purge_model::object::{TaskAction, TaskIdentity};
use serde::Deserialize;
use serde_json::Value;

use crate::fixture::{Coverage, CoverageRoot, Fixture, FixtureError};
use crate::registry::is_registry_path;
use crate::sysobj::{MsiTables, TaskInfo};
use crate::system::SystemSource;
use crate::types::{
    FILE_ATTRIBUTE_DIRECTORY, FileMeta, FileTime, FileTimes, MsiContext, MsiProduct, OsInfo,
    PackageInfo, ProcessInfo, REG_DWORD, REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ, REG_QWORD, REG_SZ,
    RegData,
};

/// Longest preview a snapshot writes, in characters (RIG.md §2).
pub const PREVIEW_MAX_CHARS: usize = 1024;

/// What a snapshot load read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapStats {
    /// `D` records.
    pub dirs: usize,
    /// `F` records.
    pub files: usize,
    /// `K` records.
    pub keys: usize,
    /// `V` records.
    pub values: usize,
    /// Values rebuilt from a preview cut at [`PREVIEW_MAX_CHARS`].
    pub truncated_values: usize,
    /// Values whose data is unknown (types without a preview).
    pub unknown_values: usize,
    /// `#denied` lines.
    pub denied: usize,
    /// The error count of the `#errors` line.
    pub errors: usize,
    /// Header time, as written.
    pub time: String,
    /// Header computer name.
    pub computer: String,
    /// Header edition.
    pub edition: String,
    /// Header `build.ubr`.
    pub build: String,
}

/// Reverses the snapshot field escaping: `\\` `\t` `\n` `\r` `\0`. Unknown escapes are kept literally.
pub fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => out.push('\\'),
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(x) => {
                out.push('\\');
                out.push(x);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Parses an ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SS[.fraction][Z|±HH:MM]`, no offset = UTC) into a
/// `FILETIME`.
pub fn parse_iso8601(s: &str) -> Option<FileTime> {
    let s = s.trim();
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse().ok() };
    if s.len() < 19
        || s.as_bytes()[4] != b'-'
        || s.as_bytes()[7] != b'-'
        || s.as_bytes()[13] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut ticks: u64 = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        rest = &frac[digits.len()..];
        let mut padded: String = digits.chars().take(7).collect();
        while padded.len() < 7 {
            padded.push('0');
        }
        ticks = padded.parse().ok()?;
    }
    let offset_secs: i64 = match rest {
        "" | "Z" | "z" => 0,
        o if (o.starts_with('+') || o.starts_with('-')) && o.len() == 6 && &o[3..4] == ":" => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let oh: i64 = o[1..3].parse().ok()?;
            let om: i64 = o[4..6].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    // Days from civil (proleptic Gregorian), H. Hinnant's algorithm.
    let y_adj = if mo <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    let base = FileTime::from_unix_secs(unix);
    Some(FileTime(base.0 + ticks))
}

fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Rebuilds a value's data from its snapshot record (RIG.md §2 preview rules).
pub fn data_from_preview(ty: u32, len: u32, hash: u64, preview: &str) -> RegData {
    let target = len as usize;
    let mut data = if target == 0 {
        RegData::new(ty, Vec::new())
    } else {
        match ty {
            REG_SZ | REG_EXPAND_SZ | REG_LINK | REG_MULTI_SZ => {
                let mut bytes = utf16_le(preview);
                let cut = preview.chars().count() >= PREVIEW_MAX_CHARS;
                // What may follow the preview without it being cut: the terminator(s).
                let slack = if ty == REG_MULTI_SZ { 4 } else { 2 };
                if bytes.len() >= target {
                    bytes.truncate(target);
                    RegData::new(ty, bytes)
                } else if cut && target - bytes.len() > slack {
                    let mut d = RegData::new(ty, bytes);
                    d.truncated = true;
                    d
                } else {
                    // Terminating NULs, padding NULs or trailing empty MULTI_SZ strings.
                    bytes.resize(target, 0);
                    RegData::new(ty, bytes)
                }
            }
            REG_DWORD if target == 4 => match preview.parse::<u32>() {
                Ok(v) => RegData::from_dword(v),
                Err(_) => RegData::unknown(ty, len),
            },
            REG_QWORD if target == 8 => match preview.parse::<u64>() {
                Ok(v) => RegData::from_qword(v),
                Err(_) => RegData::unknown(ty, len),
            },
            _ => RegData::unknown(ty, len),
        }
    };
    data.len = len;
    data.hash = Some(hash);
    data
}

fn parse_root_spec(spec: &str) -> CoverageRoot {
    if let Some((path, depth)) = spec.rsplit_once('@') {
        if let Ok(d) = depth.parse::<u32>() {
            return CoverageRoot {
                path: path.to_string(),
                depth: Some(d),
            };
        }
    }
    CoverageRoot {
        path: spec.to_string(),
        depth: None,
    }
}

fn opt_u32(s: &str) -> Result<Option<u32>, String> {
    if s.is_empty() {
        Ok(None)
    } else {
        s.parse().map(Some).map_err(|e| format!("{s:?}: {e}"))
    }
}

fn hex_u32(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 16).map_err(|e| format!("{s:?}: {e}"))
}

fn num<T: std::str::FromStr>(s: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    s.parse().map_err(|e| format!("{s:?}: {e}"))
}

/// Coverage collected from `#roots` / `#exclude`, split by registry and filesystem.
#[derive(Default)]
struct SnapCoverage {
    reg: Coverage,
    fs: Coverage,
}

impl Fixture {
    /// Loads a rig snapshot (`.tsv.gz` or plain `.tsv`), optionally with its `lists-*.json` and an overlay
    /// directory of file contents. See the module documentation for what is reconstructed.
    pub fn from_snap(
        snap: &Path,
        lists: Option<&Path>,
        overlay_dir: Option<&Path>,
    ) -> Result<Fixture, FixtureError> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| FixtureError::Io { path, source }
        };
        let mut file = std::fs::File::open(snap).map_err(io(snap))?;
        let mut magic = [0u8; 2];
        let n = file.read(&mut magic).map_err(io(snap))?;
        let file = std::fs::File::open(snap).map_err(io(snap))?;
        let reader: Box<dyn BufRead> = if n == 2 && magic == [0x1f, 0x8b] {
            Box::new(BufReader::with_capacity(1 << 20, MultiGzDecoder::new(file)))
        } else {
            Box::new(BufReader::with_capacity(1 << 20, file))
        };
        let lists_text = match lists {
            Some(p) => Some(std::fs::read_to_string(p).map_err(io(p))?),
            None => None,
        };
        let mut f = Self::from_snap_parts(reader, lists_text.as_deref(), overlay_dir)?;
        if let Some(tables) = msi_tables_file_for(snap).filter(|p| p.is_file()) {
            f.apply_msi_tables_json(&read_maybe_gz(&tables).map_err(io(&tables))?)?;
        }
        Ok(f)
    }

    /// [`Fixture::from_snap`] over already opened (decompressed) snapshot text and lists JSON text.
    pub fn from_snap_parts(
        snap: impl BufRead,
        lists_json: Option<&str>,
        overlay_dir: Option<&Path>,
    ) -> Result<Fixture, FixtureError> {
        let mut f = Fixture::new();
        f.set_unknown_file_facts(true);
        f.system_mut().elevated = true;
        // Only the lists capture these; without them they are unknown, not empty.
        f.set_msi_products(None);
        f.set_packages(None);
        f.system_mut().processes = None;
        let mut stats = SnapStats::default();
        let mut cov = SnapCoverage::default();
        let mut last_key: Option<(String, usize)> = None;

        for (i, line) in snap.lines().enumerate() {
            let lineno = i + 1;
            let line = line.map_err(|e| FixtureError::Snap {
                line: lineno,
                msg: e.to_string(),
            })?;
            f.snap_line(&line, &mut stats, &mut cov, &mut last_key)
                .map_err(|msg| FixtureError::Snap { line: lineno, msg })?;
        }

        f.set_registry_coverage(cov.reg);
        f.set_fs_coverage(cov.fs);
        if stats.keys > 0 && stats.values == 0 {
            f.set_values_captured(false);
        }
        if let Some(json) = lists_json {
            f.apply_lists_json(json)?;
        }
        f.set_overlay_dir(overlay_dir.map(Path::to_path_buf));
        f.derive_system_facts();
        f.snap_stats = Some(stats);
        Ok(f)
    }

    fn snap_line(
        &mut self,
        line: &str,
        stats: &mut SnapStats,
        cov: &mut SnapCoverage,
        last_key: &mut Option<(String, usize)>,
    ) -> Result<(), String> {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return Ok(());
        }
        let f: Vec<&str> = line.split('\t').collect();
        if line.starts_with('#') {
            let field = |i: usize| f.get(i).map(|s| unescape(s)).unwrap_or_default();
            match f[0] {
                "#purge-snap 1" | "#purge-baseline 1" => {
                    stats.time = field(1);
                    stats.computer = field(2);
                    stats.edition = field(3);
                    stats.build = field(4);
                    let (build, ubr) = stats.build.split_once('.').unwrap_or((&stats.build, "0"));
                    if let (Ok(build), Ok(ubr)) = (build.parse(), ubr.parse()) {
                        self.system_mut().os = Some(OsInfo {
                            edition: stats.edition.clone(),
                            build,
                            ubr,
                        });
                    }
                    if !stats.computer.is_empty() {
                        self.system_mut().computer = Some(stats.computer.clone());
                    }
                    self.system_mut().now = parse_iso8601(&stats.time);
                }
                "#roots" => {
                    for spec in f[1..].iter().map(|s| unescape(s)) {
                        let root = parse_root_spec(&spec);
                        if is_registry_path(&root.path) {
                            cov.reg.roots.push(root);
                        } else {
                            cov.fs.roots.push(root);
                        }
                    }
                }
                "#exclude" => {
                    for p in f[1..].iter().map(|s| unescape(s)) {
                        if is_registry_path(&p) {
                            cov.reg.exclude.push(p);
                        } else {
                            cov.fs.exclude.push(p);
                        }
                    }
                }
                "#denied" => {
                    for p in f[1..].iter().map(|s| unescape(s)) {
                        stats.denied += 1;
                        self.add_denied(&p);
                    }
                }
                "#errors" => {
                    stats.errors = f.get(1).and_then(|n| n.parse().ok()).unwrap_or(0);
                    for p in field(2).split('|').filter(|p| !p.is_empty()) {
                        self.add_denied(p);
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        let need = |n: usize| {
            if f.len() < n {
                Err(format!(
                    "short {} record ({} fields, want {n})",
                    f[0],
                    f.len()
                ))
            } else {
                Ok(())
            }
        };
        match f[0] {
            "D" => {
                need(5)?;
                let path = unescape(f[1]);
                let attrs = hex_u32(f[2])? | FILE_ATTRIBUTE_DIRECTORY;
                let mtime: u64 = num(f[3])?;
                let reparse = hex_u32(f[4])?;
                self.set_meta(&path, snap_meta(0, attrs, mtime, reparse));
                stats.dirs += 1;
            }
            "F" => {
                need(6)?;
                let path = unescape(f[1]);
                let size: u64 = num(f[2])?;
                let attrs = hex_u32(f[3])? & !FILE_ATTRIBUTE_DIRECTORY;
                let mtime: u64 = num(f[4])?;
                let reparse = hex_u32(f[5])?;
                self.set_meta(&path, snap_meta(size, attrs, mtime, reparse));
                stats.files += 1;
            }
            "K" => {
                need(5)?;
                let key = unescape(f[1]);
                let lwt: u64 = num(f[2])?;
                let nv = opt_u32(f[3])?;
                let ns = opt_u32(f[4])?;
                let idx = self.snap_key(&key, lwt, nv, ns);
                *last_key = Some((key, idx));
                stats.keys += 1;
            }
            "V" => {
                need(6)?;
                let key = unescape(f[1]);
                let name = unescape(f[2]);
                let ty: u32 = num(f[3])?;
                let len: u32 = num(f[4])?;
                let hash =
                    u64::from_str_radix(f[5], 16).map_err(|e| format!("hash {:?}: {e}", f[5]))?;
                let preview = f.get(6).map(|s| unescape(s)).unwrap_or_default();
                let data = data_from_preview(ty, len, hash, &preview);
                if data.truncated {
                    stats.truncated_values += 1;
                }
                if data.data_unknown {
                    stats.unknown_values += 1;
                }
                // Values follow their `K` record; reuse its node instead of walking the tree again.
                let idx = match last_key {
                    Some((k, idx)) if *k == key => Some(*idx),
                    _ => None,
                };
                let idx = self.snap_value(idx, &key, name, data);
                *last_key = Some((key, idx));
                stats.values += 1;
            }
            other => return Err(format!("unknown record type {other:?}")),
        }
        Ok(())
    }

    /// Applies a `lists-*.json` document (RIG.md §3): user SID, computer, MSI products, AppX packages and
    /// processes. Lists missing from the document stay as they were.
    pub fn apply_lists_json(&mut self, json: &str) -> Result<(), FixtureError> {
        let v: Value = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        if let Some(sid) = s(&v, "user_sid") {
            self.system_mut().user_sid = Some(sid);
        }
        if let Some(c) = s(&v, "computer") {
            self.system_mut().computer = Some(c);
        }
        if let Some(rows) = v.get("msi").and_then(Value::as_array) {
            let products = rows
                .iter()
                .filter_map(|r| {
                    let code = s(r, "code")?.to_ascii_uppercase();
                    let context = match s(r, "context").as_deref() {
                        Some("user_managed") => MsiContext::UserManaged,
                        Some("user_unmanaged") => MsiContext::UserUnmanaged,
                        _ => MsiContext::Machine,
                    };
                    Some(MsiProduct {
                        code,
                        context,
                        user_sid: s(r, "sid"),
                        name: s(r, "name"),
                        version: s(r, "version"),
                        publisher: s(r, "publisher"),
                        install_location: s(r, "install_location"),
                        local_package: s(r, "local_package"),
                        install_date: s(r, "install_date"),
                    })
                })
                .collect();
            self.set_msi_products(Some(products));
        }
        if let Some(rows) = v.get("appx").and_then(Value::as_array) {
            let packages = rows
                .iter()
                .filter_map(|r| {
                    let full_name = s(r, "full_name")?;
                    // Name_Version_Arch_ResourceId_PublisherId: resource packages carry `split.*`.
                    let is_resource = full_name
                        .split('_')
                        .nth(3)
                        .is_some_and(|rid| rid.starts_with("split."));
                    Some(PackageInfo {
                        family: s(r, "family").unwrap_or_default(),
                        install_location: s(r, "install_location"),
                        external_location: s(r, "external_location"),
                        sparse: r.get("sparse").and_then(Value::as_bool).unwrap_or(false),
                        users: r
                            .get("users")
                            .and_then(Value::as_array)
                            .map(|u| {
                                u.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        is_framework: r
                            .get("is_framework")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        is_resource,
                        signature_kind: Default::default(),
                        full_name,
                    })
                })
                .collect();
            self.set_packages(Some(packages));
        }
        if let Some(rows) = v.get("processes").and_then(Value::as_array) {
            let u32_of = |r: &Value, k: &str| {
                r.get(k)
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            };
            let processes = rows
                .iter()
                .filter_map(|r| {
                    Some(ProcessInfo {
                        pid: u32_of(r, "pid")?,
                        ppid: u32_of(r, "ppid"),
                        name: s(r, "name").unwrap_or_default(),
                        path: s(r, "path"),
                        start: s(r, "start").and_then(|t| parse_iso8601(&t)),
                        session: u32_of(r, "session"),
                        cmd: s(r, "cmd"),
                    })
                })
                .collect();
            self.system_mut().processes = Some(processes);
        }
        // M1b: tasks only from a list that carries the M1b fields (module docs); otherwise unchanged.
        if let Some(tasks) = tasks_from_lists(&v)? {
            self.set_tasks(Some(tasks));
        }
        Ok(())
    }

    /// Applies an MSI tables document (`purge.rig.msi_tables/1`, see the module documentation): the
    /// tables become captured, each listed package is set, and every other package is `NotFound`.
    /// Nothing is changed when the document is refused.
    pub fn apply_msi_tables_json(&mut self, json: &str) -> Result<(), FixtureError> {
        let doc: MsiTablesDoc = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
        if doc.schema != MSI_TABLES_SCHEMA {
            // Not `FixtureError::Schema`, whose message names the fixture schema.
            return Err(FixtureError::Invalid(format!(
                "msi tables: unsupported schema {:?} (want {MSI_TABLES_SCHEMA})",
                doc.schema
            )));
        }
        // Built aside first, so a refused document changes nothing.
        let mut staged = Fixture::new();
        staged.set_msi_tables_captured(true);
        for (path, tables) in &doc.packages.0 {
            if staged.msi_tables(path).is_ok() {
                return Err(FixtureError::Invalid(format!(
                    "msi tables: package {path:?} listed twice"
                )));
            }
            if !staged.set_msi_tables(path, tables.clone()) {
                return Err(FixtureError::Invalid(format!(
                    "msi tables: bad package path {path:?}"
                )));
            }
        }
        self.set_msi_tables_captured(true);
        for (path, tables) in doc.packages.0 {
            self.set_msi_tables(&path, tables);
        }
        Ok(())
    }
}

/// The schema id of the MSI tables file beside a snapshot.
pub const MSI_TABLES_SCHEMA: &str = "purge.rig.msi_tables/1";

/// The MSI tables file of a snapshot: `msi-tables-<run>-<phase>.json` in the snapshot's directory for
/// `snap-<run>-<phase>.tsv.gz` or `.tsv`; `None` for a snapshot not named that way.
pub fn msi_tables_file_for(snap: &Path) -> Option<PathBuf> {
    let name = snap.file_name()?.to_str()?;
    let stem = name.strip_prefix("snap-")?;
    let stem = stem
        .strip_suffix(".tsv.gz")
        .or_else(|| stem.strip_suffix(".tsv"))?;
    if stem.is_empty() {
        return None;
    }
    Some(snap.with_file_name(format!("msi-tables-{stem}.json")))
}

/// A file's text, decompressed when it starts with the gzip magic.
fn read_maybe_gz(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut text = String::new();
        MultiGzDecoder::new(bytes.as_slice()).read_to_string(&mut text)?;
        Ok(text)
    } else {
        String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// The MSI tables document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MsiTablesDoc {
    schema: String,
    packages: Packages,
}

/// `packages` in document order, with every key kept (a JSON map would keep only the last of two
/// equal keys, hiding the duplicate).
struct Packages(Vec<(String, MsiTables)>);

impl<'de> Deserialize<'de> for Packages {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Packages;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object mapping LocalPackage paths to MSI tables")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Packages, A::Error> {
                let mut out = Vec::new();
                while let Some(entry) = map.next_entry::<String, MsiTables>()? {
                    out.push(entry);
                }
                Ok(Packages(out))
            }
        }
        d.deserialize_map(Visit)
    }
}

/// Logon type names (the `ScheduledTasks` module's `LogonType`) that never hold a stored password.
const NO_PASSWORD_LOGON_TYPES: [&str; 5] =
    ["None", "S4U", "Interactive", "Group", "ServiceAccount"];

/// The tasks of a lists document, or `None` when the document does not capture them (module docs).
fn tasks_from_lists(v: &Value) -> Result<Option<Vec<TaskInfo>>, FixtureError> {
    let section_failed = v
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errs| {
            errs.iter()
                .filter_map(Value::as_str)
                .any(|e| e.trim_start().starts_with("tasks:"))
        });
    if section_failed {
        return Ok(None);
    }
    let Some(rows) = v.get("tasks").and_then(Value::as_array) else {
        return Ok(None);
    };
    let with_detail = rows
        .iter()
        .filter(|r| r.get("actions_detail").is_some())
        .count();
    if rows.is_empty() || with_detail == 0 {
        return Ok(None);
    }
    if with_detail != rows.len() {
        return Err(FixtureError::Invalid(format!(
            "lists: {} of {} tasks have no actions_detail",
            rows.len() - with_detail,
            rows.len()
        )));
    }
    rows.iter()
        .enumerate()
        .map(|(i, r)| {
            task_from_row(r).map_err(|e| FixtureError::Invalid(format!("lists: tasks[{i}]: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// One `tasks[]` entry of an M1b lists document.
fn task_from_row(r: &Value) -> Result<TaskInfo, String> {
    let path = r.get("path").and_then(Value::as_str).ok_or("no path")?;
    if !path.starts_with('\\') {
        return Err(format!("path {path:?} does not start with a backslash"));
    }
    let flag = |k: &str| -> Result<bool, String> {
        match r.get(k) {
            Some(Value::Bool(b)) => Ok(*b),
            Some(Value::Null) | None => Ok(false),
            Some(other) => Err(format!("{k} is not a boolean: {other}")),
        }
    };
    let logon_type = match r.get("logon_type") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Null) | None => None,
        Some(other) => return Err(format!("logon_type is not a string: {other}")),
    };
    let no_password = logon_type.is_some_and(|t| NO_PASSWORD_LOGON_TYPES.contains(&t));
    let actions = match r.get("actions_detail") {
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(j, a)| action_from_row(a).map_err(|e| format!("actions_detail[{j}]: {e}")))
            .collect::<Result<Vec<_>, _>>()?,
        // PowerShell writes a one-element array as the element itself in some versions.
        Some(one @ Value::Object(_)) => {
            vec![action_from_row(one).map_err(|e| format!("actions_detail: {e}"))?]
        }
        // No action list: kept as a task whose actions are unknown.
        Some(Value::Null) => Vec::new(),
        Some(other) => return Err(format!("actions_detail is not a list: {other}")),
        None => return Err("no actions_detail".into()),
    };
    Ok(TaskInfo {
        identity: TaskIdentity {
            path: path.to_string(),
            actions,
        },
        enabled: flag("enabled")?,
        hidden: flag("hidden")?,
        author: None,
        stored_password: flag("has_stored_password")? || !no_password,
        run_as: None,
    })
}

/// One `actions_detail[]` record.
fn action_from_row(a: &Value) -> Result<TaskAction, String> {
    let text = |k: &str| -> Result<Option<String>, String> {
        match a.get(k) {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(Value::Null) | None => Ok(None),
            Some(other) => Err(format!("{k} is not a string: {other}")),
        }
    };
    // Task Scheduler stores an empty optional field as nothing; the live source reads it as `None`.
    let optional = |k: &str| text(k).map(|s| s.filter(|s| !s.is_empty()));
    match a.get("kind").and_then(Value::as_str) {
        Some("exec") => Ok(TaskAction::Exec {
            path: text("path")?.unwrap_or_default(),
            arguments: optional("arguments")?,
            working_dir: optional("working_dir")?,
        }),
        Some("com_handler") => Ok(TaskAction::ComHandler {
            clsid: text("clsid")?.unwrap_or_default(),
            data: optional("data")?,
        }),
        Some("other") => {
            let class = text("data")?.unwrap_or_default();
            let kind = match class.as_str() {
                "MSFT_TaskSendEmailAction" => "send_email".to_string(),
                "MSFT_TaskShowMessageAction" => "show_message".to_string(),
                "" => "unknown".to_string(),
                _ => class,
            };
            Ok(TaskAction::Other { kind })
        }
        Some(other) => Err(format!("unknown action kind {other:?}")),
        None => Err("no action kind".into()),
    }
}

fn snap_meta(size: u64, attrs: u32, mtime: u64, reparse_tag: u32) -> FileMeta {
    FileMeta {
        size,
        attrs,
        times: FileTimes {
            created: None,
            modified: Some(FileTime(mtime)),
            accessed: None,
        },
        reparse_tag,
        file_id: None,
        volume_serial: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::FileSystemSource;
    use crate::registry::RegistrySource;
    use crate::system::SystemSource;
    use crate::types::{ExistsState, KnownFolder, MsiProductState, REG_BINARY, SourceError};
    use std::io::Write;

    fn fixtures_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn escape_decoding() {
        assert_eq!(unescape("C:\\\\Program Files\\\\x"), "C:\\Program Files\\x");
        assert_eq!(unescape("a\\tb\\nc\\rd\\0e"), "a\tb\nc\rd\0e");
        assert_eq!(unescape("\\\\0 literal"), "\\0 literal");
        assert_eq!(unescape("odd\\q"), "odd\\q");
        assert_eq!(unescape("trail\\"), "trail\\");
        assert_eq!(unescape("plain"), "plain");
    }

    #[test]
    fn iso_times() {
        // 1970-01-01T00:00:00Z is 116444736000000000 in FILETIME.
        assert_eq!(
            parse_iso8601("1970-01-01T00:00:00Z"),
            Some(FileTime(116_444_736_000_000_000))
        );
        let a = parse_iso8601("2026-11-11T19:02:40.9834290-08:00").unwrap();
        let b = parse_iso8601("2026-11-12T03:02:40.983429Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.0 % 10_000_000, 9_834_290);
        assert_eq!(
            parse_iso8601("2024-02-29T12:00:00").unwrap().to_unix_secs(),
            1_709_208_000
        );
        assert_eq!(parse_iso8601("not a time"), None);
        assert_eq!(parse_iso8601("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn preview_reconstruction() {
        // REG_SZ with terminator.
        let d = data_from_preview(REG_SZ, 6, 1, "ab");
        assert_eq!(d.bytes, vec![b'a', 0, b'b', 0, 0, 0]);
        assert!(d.is_complete());
        assert_eq!(d.hash, Some(1));
        // Without terminator, and padded with extra NULs.
        assert_eq!(data_from_preview(REG_SZ, 4, 1, "ab").bytes.len(), 4);
        let padded = data_from_preview(REG_SZ, 10, 1, "ab");
        assert_eq!(padded.bytes.len(), 10);
        assert_eq!(padded.sz().as_deref(), Some("ab"));
        // MULTI_SZ.
        let m = data_from_preview(REG_MULTI_SZ, 10, 1, "a\0b");
        assert_eq!(m.multi_sz().unwrap(), vec!["a", "b"]);
        assert_eq!(m.bytes.len(), 10);
        // REG_LINK without terminator.
        let l = data_from_preview(REG_LINK, 8, 1, "\\REG");
        assert_eq!(l.link_target().as_deref(), Some("\\REG"));
        // Numbers.
        assert_eq!(
            data_from_preview(REG_DWORD, 4, 1, "4294967295").dword(),
            Some(u32::MAX)
        );
        assert_eq!(
            data_from_preview(REG_QWORD, 8, 1, "1099511627776").qword(),
            Some(1 << 40)
        );
        assert!(data_from_preview(REG_DWORD, 3, 1, "").data_unknown);
        // Binary and custom types are unknown unless empty.
        let b = data_from_preview(REG_BINARY, 16, 7, "");
        assert!(b.data_unknown && b.len == 16 && b.hash == Some(7));
        assert_eq!(b.binary_utf16_strings(), None);
        assert!(!data_from_preview(REG_BINARY, 0, 7, "").data_unknown);
        assert!(data_from_preview(1_048_576, 4, 7, "").data_unknown);
    }

    #[test]
    fn truncated_preview_flag() {
        let long: String = "x".repeat(PREVIEW_MAX_CHARS);
        let d = data_from_preview(REG_SZ, 4000, 1, &long);
        assert!(d.truncated);
        assert_eq!(d.len, 4000);
        assert_eq!(d.sz().unwrap().len(), PREVIEW_MAX_CHARS);
        assert_eq!(d.dword(), None);
        // Exactly 1024 characters plus the terminator is complete, not truncated.
        let exact = data_from_preview(REG_SZ, (PREVIEW_MAX_CHARS as u32 + 1) * 2, 1, &long);
        assert!(!exact.truncated);
        // A short preview is never truncated.
        assert!(!data_from_preview(REG_SZ, 4000, 1, "short").truncated);
    }

    fn load_mini() -> Fixture {
        let dir = fixtures_dir();
        Fixture::from_snap(
            &dir.join("mini.snap.tsv"),
            Some(&dir.join("mini.lists.json")),
            Some(&dir.join("overlay")),
        )
        .unwrap()
    }

    #[test]
    fn mini_snap_tree() {
        let f = load_mini();
        let st = f.snap_stats().unwrap();
        assert_eq!((st.dirs, st.files, st.keys, st.values), (3, 4, 7, 9));
        assert_eq!(
            (st.truncated_values, st.unknown_values, st.denied, st.errors),
            (0, 1, 1, 2)
        );
        assert_eq!(f.dir_count(), 3);
        assert_eq!(f.file_count(), 4);
        assert_eq!(f.key_count(), 7);
        assert_eq!(f.value_count(), 9);

        // Header.
        let os = f.os_info().unwrap();
        assert_eq!(
            (os.edition.as_str(), os.build, os.ubr),
            ("EnterpriseSEval", 26100, 1742)
        );
        assert_eq!(f.now(), parse_iso8601("2026-11-11T16:05:36Z").unwrap());
        assert!(f.elevated());

        // Keys and values.
        let app = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Demo_is1";
        let info = f.key_info(app).unwrap();
        assert_eq!(info.lwt, FileTime(134_388_866_613_378_836));
        assert_eq!((info.n_values, info.n_subkeys), (4, 0));
        assert_eq!(
            f.value(app, "DisplayName").unwrap().sz().as_deref(),
            Some("Demo\tApp")
        );
        assert_eq!(
            f.value(app, "InstallLocation").unwrap().sz().as_deref(),
            Some("C:\\Program Files\\Demo\\")
        );
        assert_eq!(f.value(app, "EstimatedSize").unwrap().dword(), Some(1234));
        let blob = f.value(app, "Blob").unwrap();
        assert!(blob.data_unknown && blob.len == 3);
        assert_eq!(
            f.value("HKLM\\SOFTWARE\\Demo", "")
                .unwrap()
                .multi_sz()
                .unwrap(),
            vec!["one", "two"]
        );
        // CurrentControlSet in the snap is stored as ControlSet001.
        let svc = "HKLM\\SYSTEM\\ControlSet001\\Services\\DemoSvc";
        assert_eq!(f.value(svc, "Start").unwrap().dword(), Some(2));
        assert!(
            f.key_info("HKLM\\SYSTEM\\CurrentControlSet\\Services\\DemoSvc")
                .is_ok()
        );
        // Link key recorded, not followed.
        let classes = "HKU\\S-1-5-21-100-200-300-1001\\Software\\Classes";
        let link = f.key_info(classes).unwrap();
        assert!(link.is_link);
        assert_eq!(
            link.link_target.as_deref(),
            Some("\\REGISTRY\\USER\\S-1-5-21-100-200-300-1001_Classes")
        );
        assert_eq!(
            f.loaded_user_sids().unwrap(),
            vec!["S-1-5-21-100-200-300-1001"]
        );
        // Outside the captured roots: not captured; inside: not found.
        assert_eq!(
            f.key_info("HKLM\\HARDWARE\\X"),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(
            f.key_info("HKLM\\SOFTWARE\\Nope"),
            Err(SourceError::NotFound)
        );
        assert_eq!(
            f.key_info("HKLM\\SYSTEM\\ControlSet001\\Enum\\X"),
            Err(SourceError::NotCaptured)
        );

        // Files.
        assert_eq!(
            f.exists("C:\\Program Files\\Demo\\demo.exe"),
            ExistsState::Present
        );
        assert_eq!(
            f.exists("C:\\Program Files\\Demo\\gone.exe"),
            ExistsState::Absent
        );
        assert_eq!(
            f.exists("C:\\Windows\\System32\\notepad.exe"),
            ExistsState::Present
        );
        // System32 is a depth-1 root: deeper paths are unknown, not absent.
        assert_eq!(
            f.exists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            ExistsState::Unknown
        );
        assert_eq!(f.exists("C:\\Elsewhere\\x.exe"), ExistsState::Unknown);
        assert_eq!(f.exists("C:\\ProgramData\\Locked\\x"), ExistsState::Unknown);
        let exe = f.metadata("C:\\Program Files\\Demo\\demo.exe").unwrap();
        assert_eq!(exe.size, 4096);
        assert_eq!(exe.times.modified, Some(FileTime(134_388_866_613_378_836)));
        let junction = f.metadata("C:\\ProgramData\\Link").unwrap();
        assert!(junction.is_dir() && junction.reparse_tag == 0xA000_0003);
        assert_eq!(
            f.list_dir("C:\\ProgramData\\Link"),
            Err(SourceError::ReparsePoint)
        );
        assert_eq!(
            f.list_dir("C:\\ProgramData\\Locked"),
            Err(SourceError::AccessDenied)
        );
        let names: Vec<String> = f
            .list_dir("C:\\Program Files\\Demo")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["demo.exe", "unins000.dat"]);
        // File contents only from the overlay; file facts are not captured.
        assert!(
            f.read_bytes("C:\\Program Files\\Demo\\unins000.dat", 100)
                .unwrap()
                .starts_with(b"overlay content")
        );
        assert_eq!(
            f.read_bytes("C:\\Program Files\\Demo\\demo.exe", 100),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(
            f.version_info("C:\\Program Files\\Demo\\demo.exe"),
            Err(SourceError::NotCaptured)
        );
        assert!(
            f.is_admin_only_writable("C:\\Program Files\\Demo\\demo.exe")
                .unwrap()
        );
        assert!(!f.is_admin_only_writable("C:\\ProgramData\\Link").unwrap());

        // Lists and derived facts.
        assert_eq!(f.user_sid().unwrap(), "S-1-5-21-100-200-300-1001");
        let msi = f.msi_products().unwrap();
        assert_eq!(msi.len(), 1);
        assert_eq!(msi[0].context, MsiContext::Machine);
        let states = f
            .msi_product_state_all("{23170f69-40c1-2702-2408-000001000000}")
            .unwrap();
        assert_eq!(states[0].state, MsiProductState::Default);
        let pk = f.packages().unwrap();
        assert_eq!(pk.len(), 2);
        assert!(pk[0].is_sparse());
        assert!(pk[1].is_resource);
        let procs = f.processes().unwrap();
        assert_eq!(procs[0].name, "demo.exe");
        assert_eq!(
            procs[0].start,
            parse_iso8601("2026-11-11T19:02:40.9834290-08:00")
        );
        let profiles = f.profiles().unwrap();
        assert_eq!(profiles[0].path, "C:\\Users\\tester");
        let env = f.env().unwrap();
        assert_eq!(env["USERPROFILE"], "C:\\Users\\tester");
        assert_eq!(env["APPDATA"], "C:\\Users\\tester\\AppData\\Roaming");
        assert_eq!(env["DEMOVAR"], "C:\\Users\\tester\\demo");
        let kf = f.known_folders().unwrap();
        assert_eq!(kf[&KnownFolder::ProgramFiles], "C:\\Program Files");
        assert_eq!(
            kf[&KnownFolder::LocalAppData],
            "C:\\Users\\tester\\AppData\\Local"
        );
    }

    #[test]
    fn mini_snap_gzip_and_without_lists() {
        let text = std::fs::read(fixtures_dir().join("mini.snap.tsv")).unwrap();
        let dir = std::env::temp_dir().join(format!("purge-source-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gz = dir.join("snap-mini-1.tsv.gz");
        {
            let mut enc = flate2::write::GzEncoder::new(
                std::fs::File::create(&gz).unwrap(),
                flate2::Compression::default(),
            );
            enc.write_all(&text).unwrap();
            enc.finish().unwrap();
        }
        let f = Fixture::from_snap(&gz, None, None).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(f.snap_stats().unwrap().keys, 7);
        // Without lists: the user SID is derived from the hives, the lists are not captured.
        assert_eq!(f.user_sid().unwrap(), "S-1-5-21-100-200-300-1001");
        assert_eq!(f.msi_products(), Err(SourceError::NotCaptured));
        assert_eq!(f.packages(), Err(SourceError::NotCaptured));
        assert_eq!(f.processes(), Err(SourceError::NotCaptured));
        // Without overlay, contents are not captured.
        assert_eq!(
            f.read_bytes("C:\\Program Files\\Demo\\unins000.dat", 10),
            Err(SourceError::NotCaptured)
        );
    }

    #[test]
    fn snap_errors_report_line() {
        let bad = "#purge-snap 1\t2026-11-11T16:05:36Z\tPC\tPro\t26100.1\nK\tHKLM\\\\SOFTWARE\t1\n";
        match Fixture::from_snap_parts(bad.as_bytes(), None, None) {
            Err(FixtureError::Snap { line, .. }) => assert_eq!(line, 2),
            other => panic!("unexpected {other:?}"),
        }
        let bad = "X\tsomething\n";
        assert!(Fixture::from_snap_parts(bad.as_bytes(), None, None).is_err());
    }

    /// Counts the record lines of a snapshot independently of the loader.
    fn count_records(path: &Path) -> (usize, usize, usize, usize) {
        let reader = BufReader::new(MultiGzDecoder::new(std::fs::File::open(path).unwrap()));
        let mut c = (0, 0, 0, 0);
        for line in reader.lines() {
            let line = line.unwrap();
            match line.split('\t').next() {
                Some("D") => c.0 += 1,
                Some("F") => c.1 += 1,
                Some("K") => c.2 += 1,
                Some("V") => c.3 += 1,
                _ => {}
            }
        }
        c
    }

    /// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): loads `vscode/snap-vscode-1.tsv.gz` with its lists and
    /// checks the fixture's counts against the snapshot's own record counts.
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
    fn real_vscode_snap_counts() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let dir = Path::new(&runs).join("vscode");
        let snap = dir.join("snap-vscode-1.tsv.gz");
        let lists = dir.join("lists-vscode-1.json");
        let t = std::time::Instant::now();
        let f =
            Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), None).unwrap();
        let load = t.elapsed();
        let (d, fl, k, v) = count_records(&snap);
        let st = f.snap_stats().unwrap();
        eprintln!(
            "loaded in {load:?}: D {} F {} K {} V {} (truncated {}, unknown {}), denied {}, errors {}",
            st.dirs,
            st.files,
            st.keys,
            st.values,
            st.truncated_values,
            st.unknown_values,
            st.denied,
            st.errors
        );
        eprintln!(
            "fixture: dirs {} files {} keys {} values {}",
            f.dir_count(),
            f.file_count(),
            f.key_count(),
            f.value_count()
        );
        assert_eq!((st.dirs, st.files, st.keys, st.values), (d, fl, k, v));
        assert_eq!(f.dir_count(), d, "declared directories");
        assert_eq!(f.file_count(), fl, "declared files");
        assert_eq!(f.key_count(), k, "declared keys");
        assert_eq!(f.value_count(), v, "values");
        assert!(f.os_info().is_ok());
        assert!(f.user_sid().is_ok());
    }
}
