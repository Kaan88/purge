//! From an Inno Setup uninstall log on disk to the fingerprint's [`InnoRecord`]s (ENGINE_PLAN.md §5.3
//! `InstallerManifest{inno}`, §6.1).
//!
//! [`crate::inno`] parses bytes; this module does what needs the machine:
//!
//! - **Locating the log**: `unins000.dat` next to the `unins000.exe` the entry's `UninstallString` runs
//!   ([`locate`]).
//! - **Binding `HKCU`**: a record under `HKEY_CURRENT_USER` means the hive of the user who ran that
//!   install. For an entry in a user hive that is the hive's SID. For an `HKLM` entry it is the account
//!   named by the install run's `StartInstall` record, looked up among the known users
//!   ([`UserBinding::users`]); a record whose user cannot be resolved is dropped and counted, never
//!   guessed. Bound records are rewritten to `HKU\<sid>\…` (`HKU\<sid>_Classes\…` for the user's
//!   classes) and keep [`InnoRecord::user_hive`] set.
//! - **Canonical targets**: every registry key goes through the guard's canonicalisation (`SOFTWARE`
//!   spelling, `CurrentControlSet`, the WOW64 view); every file path too. A target that does not
//!   canonicalise (a UNC path, an unknown root) is dropped and counted: a record is Tier A evidence and
//!   must name exactly one location. For a user's classes the 32-bit view applies only to the keys
//!   Windows redirects (`CLSID`, `Interface`, …), as the parser already does for the machine's classes.
//! - **`System32` of a 32-bit install**: without the record's "redirection disabled" flag, a `System32`
//!   path written by an install that did not run in 64-bit mode means `SysWOW64`, and is rewritten.
//! - **Scope**: `key_create` is kept only on `RegDeleteEntireKey` / `RegDeleteKeyIfEmpty` records whose
//!   target is the key itself; every other record gives Value or Path scope.
//! - **Duplicates**: a log holds one record set per install or update run. Records with the same kind
//!   and target are folded into one, in the order of their first occurrence; `existed_before` and
//!   `shared` are kept when any run set them.
//!
//! A log that is missing, unreadable, of an unsupported version or inconsistent gives no records and a
//! warning for the fingerprint; the harvest then goes on without it (§11.2 "Inno format changes").

use std::collections::HashMap;

use purge_guard::canon::{GuardEnv, canon_key, canon_path};
use purge_guard::prefix;
use purge_inventory::arp::inno_log_path;
use purge_model::{
    AppFileOutsideRoot, InnoRecord, InnoRecordKind, InventoryEntry, Root, SourceId, Target, View,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::types::SourceError;
use purge_win::env::EnvMap;

use crate::inno::{self, InnoLogError, LogOp, LogRecord, RegRoot, UninstallLog};
use crate::roots::{command_exe, under_any};

/// Most bytes of a log that are read. Real logs are a few megabytes at most.
pub const LOG_READ_MAX: usize = 64 * 1024 * 1024;

/// Class keys that WOW64 redirects for 32-bit programs; every other class key is shared by both views.
const REDIRECTED_CLASS_KEYS: [&str; 5] = [
    "CLSID",
    "DirectShow",
    "Interface",
    "Media Type",
    "MediaFoundation",
];

/// File extensions of executable code, for [`outside_root_files`].
const CODE_EXTENSIONS: [&str; 9] = ["exe", "dll", "com", "ocx", "cpl", "scr", "sys", "ax", "drv"];

/// Who `HKCU` records belong to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserBinding {
    /// SID of the user hive the Uninstall key is in; `None` for an `HKLM` entry. When set, every `HKCU`
    /// record is bound to it.
    pub hive_sid: Option<String>,
    /// Known users as (account name, SID): the profile directory names and the interactive user. Used
    /// to resolve the account a `StartInstall` record names.
    pub users: Vec<(String, String)>,
}

impl UserBinding {
    /// The SID of the account `name`, when exactly one known user has that name.
    fn sid_of(&self, name: &str) -> Option<&str> {
        let mut sids = self
            .users
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name.trim()))
            .map(|(_, sid)| sid.as_str());
        let first = sids.next()?;
        sids.all(|s| s.eq_ignore_ascii_case(first)).then_some(first)
    }
}

/// What the uninstall log of one entry gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InnoHarvest {
    /// Canonical path of the log, when the entry has an Inno uninstaller.
    pub log_path: Option<String>,
    /// The log was read and parsed.
    pub parsed: bool,
    /// The header's `AppId`.
    pub app_id: Option<String>,
    /// The header's `AppName`.
    pub app_name: Option<String>,
    /// The app directories the install runs name, each once, in log order.
    pub app_dirs: Vec<String>,
    /// The directories an install run of the log created (canonical, each once): see
    /// [`LogRecord::created_dir`]. A directory that is not here existed before the first install the
    /// log records.
    pub created_dirs: Vec<String>,
    /// The mapped records: bound, canonical, without duplicates.
    pub records: Vec<InnoRecord>,
    /// Number of records in the log, of every type.
    pub raw_records: usize,
    /// What could not be done, for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// The canonical path of the uninstall log next to the entry's Inno uninstaller; `None` when the
/// `UninstallString` does not run an `unins###.exe`.
pub fn locate(entry: &InventoryEntry, env: &EnvMap, guard: &GuardEnv) -> Option<String> {
    let exe = command_exe(entry.uninstall_string.as_deref()?, env, guard)?;
    inno_log_path(&exe)
}

/// Reads, parses and maps the uninstall log of `entry`. Never fails: problems become
/// [`InnoHarvest::warnings`].
pub fn read(
    fs: &dyn FileSystemSource,
    entry: &InventoryEntry,
    binding: &UserBinding,
    env: &EnvMap,
    guard: &GuardEnv,
) -> InnoHarvest {
    let mut out = InnoHarvest::default();
    let Some(path) = locate(entry, env, guard) else {
        return out;
    };
    out.log_path = Some(path.clone());
    let bytes = match fs.read_bytes(&path, LOG_READ_MAX) {
        Ok(bytes) => bytes,
        Err(SourceError::NotFound) => {
            out.warnings
                .push(format!("inno: no uninstall log at {path}"));
            return out;
        }
        Err(e) => {
            out.warnings
                .push(format!("inno: cannot read the uninstall log {path}: {e}"));
            return out;
        }
    };
    match inno::parse(&bytes) {
        Ok(log) => map_into(&log, binding, guard, &mut out),
        Err(InnoLogError::Unsupported { version }) => out.warnings.push(format!(
            "inno: log version {version} is newer than supported ({}); the log is not used",
            inno::MAX_SUPPORTED_VERSION
        )),
        Err(e) => out
            .warnings
            .push(format!("inno: the uninstall log {path} is not usable: {e}")),
    }
    out
}

/// Maps a parsed log; see the module documentation for the rules.
pub fn map(log: &UninstallLog, binding: &UserBinding, guard: &GuardEnv) -> InnoHarvest {
    let mut out = InnoHarvest::default();
    map_into(log, binding, guard, &mut out);
    out
}

fn map_into(log: &UninstallLog, binding: &UserBinding, guard: &GuardEnv, out: &mut InnoHarvest) {
    out.parsed = true;
    out.raw_records = log.records.len();
    out.app_id = Some(log.header.app_id.clone()).filter(|s| !s.is_empty());
    out.app_name = Some(log.header.app_name.clone()).filter(|s| !s.is_empty());
    out.warnings
        .extend(log.warnings.iter().map(|w| format!("inno: {w}")));

    let admin = log.header.is_admin_install();
    let mut run_user: Option<String> = None;
    let mut unbound = 0usize;
    let mut unbound_users: Vec<String> = Vec::new();
    let mut not_canonical = 0usize;
    let mut index: HashMap<(InnoRecordKind, String), usize> = HashMap::new();

    for record in &log.records {
        if let LogOp::StartInstall {
            user_name, app_dir, ..
        } = &record.op
        {
            run_user = Some(user_name.clone());
            let dir = app_dir.trim().trim_end_matches('\\');
            if !dir.is_empty() && !out.app_dirs.iter().any(|d| d.eq_ignore_ascii_case(dir)) {
                out.app_dirs.push(dir.to_owned());
            }
            continue;
        }
        // An install without administrative rights cannot have written the machine's classes; see
        // `UninstallLog::model_records`.
        if !admin && reg_root(&record.op) == Some(RegRoot::ClassesRoot) {
            continue;
        }
        if let Some(dir) = record.created_dir() {
            if let Ok(canon) = canon_path(&dir, guard, None) {
                let redirected = !log.header.is_64bit && !record.fs_redirection_disabled();
                let dir = if redirected {
                    syswow64(&canon.path, guard)
                } else {
                    canon.path
                };
                if !out.created_dirs.iter().any(|d| prefix::is_same(d, &dir)) {
                    out.created_dirs.push(dir);
                }
            }
        }
        let Some(model) = record.to_model() else {
            continue;
        };
        let sid = match &binding.hive_sid {
            Some(sid) => Some(sid.as_str()),
            None => run_user.as_deref().and_then(|name| binding.sid_of(name)),
        };
        if model.user_hive && sid.is_none() {
            unbound += 1;
            let name = run_user.clone().unwrap_or_default();
            if !unbound_users.contains(&name) {
                unbound_users.push(name);
            }
            continue;
        }
        let Some(model) = canonical(model, record, log.header.is_64bit, sid, guard) else {
            not_canonical += 1;
            continue;
        };
        let key = (model.kind, target_key(&model.target));
        match index.get(&key) {
            Some(&at) => {
                out.records[at].existed_before |= model.existed_before;
                out.records[at].shared |= model.shared;
            }
            None => {
                index.insert(key, out.records.len());
                out.records.push(model);
            }
        }
    }
    if unbound > 0 {
        out.warnings.push(format!(
            "inno: {unbound} HKCU record(s) dropped: the installing user ({}) is not a known user",
            unbound_users.join(", ")
        ));
    }
    if not_canonical > 0 {
        out.warnings.push(format!(
            "inno: {not_canonical} record(s) dropped: the target is not a canonical local location"
        ));
    }
}

/// The registry root of a registry record.
fn reg_root(op: &LogOp) -> Option<RegRoot> {
    match op {
        LogOp::RegDeleteEntireKey { root, .. }
        | LogOp::RegDeleteKeyIfEmpty { root, .. }
        | LogOp::RegClearValue { root, .. }
        | LogOp::RegDeleteValue { root, .. } => Some(*root),
        _ => None,
    }
}

/// A case-folded identity of a target, for folding duplicates.
fn target_key(target: &Target) -> String {
    match target {
        Target::Path { path } => format!("p|{}", prefix::fold(path)),
        Target::RegKey { path } => format!("k|{}", prefix::fold(path)),
        Target::RegValue { path, name } => {
            format!("v|{}|{}", prefix::fold(path), prefix::fold(name))
        }
        other => format!("o|{other:?}"),
    }
}

/// The record with its target in canonical form and `HKCU` bound to `sid`; `None` when the target has
/// no canonical form.
fn canonical(
    mut model: InnoRecord,
    record: &LogRecord,
    is_64bit: bool,
    sid: Option<&str>,
    guard: &GuardEnv,
) -> Option<InnoRecord> {
    let key = |path: &str| -> Option<String> {
        let view = if model.user_hive {
            user_view(path, model.view)
        } else {
            None
        };
        let sid = if model.user_hive { sid } else { None };
        canon_key(path, view, guard, sid).ok().map(|k| k.key_path())
    };
    let target = match &model.target {
        Target::Path { path } => {
            let canon = canon_path(path, guard, None).ok()?;
            let redirected = !is_64bit
                && matches!(
                    record.op,
                    LogOp::DeleteFile { .. } | LogOp::DeleteDirOrFiles { .. }
                )
                && !record.fs_redirection_disabled();
            Target::Path {
                path: if redirected {
                    syswow64(&canon.path, guard)
                } else {
                    canon.path
                },
            }
        }
        Target::RegKey { path } => Target::RegKey { path: key(path)? },
        Target::RegValue { path, name } => Target::RegValue {
            path: key(path)?,
            name: name.clone(),
        },
        _ => return None,
    };
    model.key_create = model.key_create
        && matches!(
            model.kind,
            InnoRecordKind::RegDeleteEntireKey | InnoRecordKind::RegDeleteKeyIfEmpty
        )
        && matches!(target, Target::RegKey { .. });
    model.target = target;
    Some(model)
}

/// The view to bind an `HKCU\…` key path with: the logged 32-bit view only for a redirected class key.
fn user_view(path: &str, logged: Option<View>) -> Option<View> {
    let mut segs = path.split('\\').filter(|s| !s.is_empty()).skip(1);
    let in_classes = segs
        .next()
        .is_some_and(|s| s.eq_ignore_ascii_case("Software"))
        && segs
            .next()
            .is_some_and(|s| s.eq_ignore_ascii_case("Classes"));
    let redirected = in_classes
        && segs.next().is_some_and(|first| {
            REDIRECTED_CLASS_KEYS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(first))
        });
    (redirected && logged == Some(View::K32)).then_some(View::K32)
}

/// A path at or below `%WINDIR%\System32`, as a 32-bit program sees it: under `SysWOW64`.
fn syswow64(path: &str, guard: &GuardEnv) -> String {
    let system32 = format!("{}\\System32", guard.windir.trim_end_matches('\\'));
    match prefix::strip_prefix(path, &system32) {
        Some(rest) if !guard.windir.is_empty() => {
            let base = format!("{}\\SysWOW64", guard.windir.trim_end_matches('\\'));
            if rest.is_empty() {
                base
            } else {
                format!("{base}\\{rest}")
            }
        }
        _ => path.to_owned(),
    }
}

/// The executable files the log declares outside every root (`py.exe` in `C:\Windows`): `DeleteFile`
/// records with a code extension that are under none of `roots`. They only help to recognise dangling
/// references; they are never removal targets by themselves.
pub fn outside_root_files(
    records: &[InnoRecord],
    roots: &[Root],
    log_path: &str,
) -> Vec<AppFileOutsideRoot> {
    let name = prefix::leaf(log_path).unwrap_or("unins000.dat");
    let source = SourceId(format!("inno:{name}"));
    let mut out: Vec<AppFileOutsideRoot> = Vec::new();
    for record in records {
        let Target::Path { path } = &record.target else {
            continue;
        };
        let is_code = path
            .rsplit_once('.')
            .is_some_and(|(_, ext)| CODE_EXTENSIONS.iter().any(|c| c.eq_ignore_ascii_case(ext)));
        if record.kind != InnoRecordKind::DeleteFile || !is_code || under_any(path, roots) {
            continue;
        }
        if !out.iter().any(|f| prefix::is_same(&f.path, path)) {
            out.push(AppFileOutsideRoot {
                path: path.clone(),
                source: source.clone(),
            });
        }
    }
    out.sort_by_key(|f| prefix::fold(&f.path));
    out
}

/// A writer of small synthetic uninstall logs, for the tests of this crate.
#[cfg(test)]
pub(crate) mod testlog {
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

    /// `HKEY_CLASSES_ROOT`, 64-bit view.
    pub const HKCR: u32 = 0x8100_0000;
    /// `HKEY_CURRENT_USER`, 64-bit view.
    pub const HKCU: u32 = 0x8100_0001;
    /// `HKEY_CURRENT_USER`, 32-bit view.
    pub const HKCU32: u32 = 0x8000_0001;
    /// `HKEY_LOCAL_MACHINE`, 64-bit view.
    pub const HKLM: u32 = 0x8100_0002;

    /// Header flag: administrative install mode.
    pub const ADMIN: u32 = 1 << 7;

    /// One record: type, `ExtraData`, strings.
    pub type Rec<'a> = (u16, u32, &'a [&'a str]);

    /// The bytes of a log with the given header facts and records.
    pub fn build(
        app_id: &str,
        app_name: &str,
        version: i32,
        flags: u32,
        is_64bit: bool,
        recs: &[Rec<'_>],
    ) -> Vec<u8> {
        let mut stream = Vec::new();
        for (typ, extra, strings) in recs {
            let mut data = Vec::new();
            for s in *strings {
                let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
                data.push(0xFE);
                data.extend_from_slice(&(-(bytes.len() as i32)).to_le_bytes());
                data.extend_from_slice(&bytes);
            }
            data.push(0xFF);
            stream.extend_from_slice(&typ.to_le_bytes());
            stream.extend_from_slice(&extra.to_le_bytes());
            stream.extend_from_slice(&(data.len() as u32).to_le_bytes());
            stream.extend_from_slice(&data);
        }
        let mut out = vec![0u8; 448];
        let id: &[u8] = if is_64bit {
            b"Inno Setup Uninstall Log (b) 64-bit"
        } else {
            b"Inno Setup Uninstall Log (b)"
        };
        out[..id.len()].copy_from_slice(id);
        out[64..64 + app_id.len()].copy_from_slice(app_id.as_bytes());
        out[192..192 + app_name.len()].copy_from_slice(app_name.as_bytes());
        for chunk in stream.chunks(4096) {
            let size = chunk.len() as u32;
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(!size).to_le_bytes());
            out.extend_from_slice(&crc32fast::hash(chunk).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        let end = out.len() as u32;
        out[320..324].copy_from_slice(&version.to_le_bytes());
        out[324..328].copy_from_slice(&(recs.len() as i32).to_le_bytes());
        out[328..332].copy_from_slice(&end.to_le_bytes());
        out[332..336].copy_from_slice(&flags.to_le_bytes());
        let crc = crc32fast::hash(&out[..444]);
        out[444..448].copy_from_slice(&crc.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testlog::*;
    use super::*;
    use crate::roots::tests_support::entry;
    use purge_model::{RootKind, RootSource, SourceTrust};
    use purge_source::fixture::Fixture;

    const SID: &str = GuardEnv::SAMPLE_SID;
    const OTHER_SID: &str = "S-1-5-21-1-2-3-1002";

    fn guard() -> GuardEnv {
        let mut g = GuardEnv::sample();
        g.loaded_sids.push(OTHER_SID.into());
        g
    }

    fn binding() -> UserBinding {
        UserBinding {
            hive_sid: None,
            users: vec![
                ("tester".into(), SID.into()),
                ("admin".into(), OTHER_SID.into()),
            ],
        }
    }

    fn parse(bytes: &[u8]) -> UninstallLog {
        inno::parse(bytes).unwrap()
    }

    fn targets(h: &InnoHarvest) -> Vec<(InnoRecordKind, Target, bool)> {
        h.records
            .iter()
            .map(|r| (r.kind, r.target.clone(), r.key_create))
            .collect()
    }

    fn key(path: &str) -> Target {
        Target::RegKey { path: path.into() }
    }

    fn value(path: &str, name: &str) -> Target {
        Target::RegValue {
            path: path.into(),
            name: name.into(),
        }
    }

    fn file(path: &str) -> Target {
        Target::Path { path: path.into() }
    }

    #[test]
    fn admin_install_binds_hkcu_to_the_installing_user_and_canonicalises() {
        let log = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION,
            ADMIN,
            true,
            &[
                (START, 0, &["PC", "Tester", r"C:\Program Files\My App", ""]),
                (FILE, 0, &[r"C:\Program Files\My App\app.exe"]),
                (KEY, HKLM, &[r"Software\Classes\MyApp.doc"]),
                (KEY, HKCR, &["MyApp.txt"]),
                (KEY_IF_EMPTY, HKLM, &[r"Software\Vendor"]),
                (
                    VALUE,
                    HKLM,
                    &[
                        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                        "MYAPP",
                    ],
                ),
                (
                    VALUE,
                    HKCU,
                    &[r"Software\Classes\.txt\OpenWithProgids", "MyApp.txt"],
                ),
                (KEY, HKCU, &[r"Software\Vendor\My App"]),
                (
                    KEY,
                    HKCU32,
                    &[r"Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}"],
                ),
                (KEY, HKCU32, &[r"Software\Classes\MyApp.user"]),
                (END, 0, &[""]),
            ],
        );
        let h = map(&parse(&log), &binding(), &guard());
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);
        assert_eq!(h.app_id.as_deref(), Some("{APP}"));
        assert_eq!(h.app_name.as_deref(), Some("My App"));
        assert_eq!(h.app_dirs, [r"C:\Program Files\My App"]);
        assert_eq!(h.raw_records, 11);
        use InnoRecordKind::*;
        assert_eq!(
            targets(&h),
            [
                (DeleteFile, file(r"C:\Program Files\My App\app.exe"), false),
                (
                    RegDeleteEntireKey,
                    key(r"HKLM\SOFTWARE\Classes\MyApp.doc"),
                    true
                ),
                (
                    RegDeleteEntireKey,
                    key(r"HKLM\SOFTWARE\Classes\MyApp.txt"),
                    true
                ),
                (RegDeleteKeyIfEmpty, key(r"HKLM\SOFTWARE\Vendor"), true),
                (
                    RegDeleteValue,
                    value(
                        r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment",
                        "MYAPP"
                    ),
                    false
                ),
                (
                    RegDeleteValue,
                    value(
                        &format!(r"HKU\{SID}_Classes\.txt\OpenWithProgids"),
                        "MyApp.txt"
                    ),
                    false
                ),
                (
                    RegDeleteEntireKey,
                    key(&format!(r"HKU\{SID}\Software\Vendor\My App")),
                    true
                ),
                (
                    RegDeleteEntireKey,
                    key(&format!(
                        r"HKU\{SID}_Classes\WOW6432Node\CLSID\{{11111111-2222-3333-4444-555555555555}}"
                    )),
                    true
                ),
                // A class key that is not redirected has one location, whatever view was logged.
                (
                    RegDeleteEntireKey,
                    key(&format!(r"HKU\{SID}_Classes\MyApp.user")),
                    true
                ),
            ]
        );
        // Bound records stay marked, and every registry target has a typed form.
        for r in &h.records {
            assert_eq!(
                r.user_hive,
                matches!(&r.target, Target::RegKey { path } | Target::RegValue { path, .. } if path.starts_with("HKU"))
            );
            if r.target.is_registry() {
                purge_model::TypedTarget::try_from(&r.target).unwrap();
            }
        }
    }

    #[test]
    fn per_user_install_binds_to_the_hive_of_the_entry() {
        // No administrative rights: HKCR records are left out; HKCU goes to the entry's hive even when
        // the log names another account.
        let log = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION,
            0,
            true,
            &[
                (
                    START,
                    0,
                    &[
                        "PC",
                        "somebody",
                        r"C:\Users\tester\AppData\Local\Programs\My App",
                        "",
                    ],
                ),
                (KEY, HKCR, &["MyApp.txt"]),
                (KEY, HKCU, &[r"Software\Classes\MyApp.txt"]),
                (VALUE, HKCU, &[r"Environment", "Path"]),
            ],
        );
        let per_user = UserBinding {
            hive_sid: Some(OTHER_SID.into()),
            users: binding().users,
        };
        let h = map(&parse(&log), &per_user, &guard());
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);
        assert_eq!(
            targets(&h),
            [
                (
                    InnoRecordKind::RegDeleteEntireKey,
                    key(&format!(r"HKU\{OTHER_SID}_Classes\MyApp.txt")),
                    true
                ),
                (
                    InnoRecordKind::RegDeleteValue,
                    value(&format!(r"HKU\{OTHER_SID}\Environment"), "Path"),
                    false
                ),
            ]
        );
        assert!(h.records.iter().all(|r| r.user_hive));
    }

    #[test]
    fn unknown_installing_user_drops_hkcu_records_with_a_warning() {
        let log = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION,
            ADMIN,
            true,
            &[
                (START, 0, &["PC", "ghost", r"C:\Program Files\My App", ""]),
                (KEY, HKCU, &[r"Software\Vendor\My App"]),
                (KEY, HKLM, &[r"Software\Vendor\My App"]),
                (FILE, 0, &[r"\\server\share\x.dll"]),
            ],
        );
        let h = map(&parse(&log), &binding(), &guard());
        assert_eq!(
            targets(&h),
            [(
                InnoRecordKind::RegDeleteEntireKey,
                key(r"HKLM\SOFTWARE\Vendor\My App"),
                true
            )]
        );
        assert_eq!(h.warnings.len(), 2, "{:?}", h.warnings);
        assert!(h.warnings[0].contains("1 HKCU record(s)") && h.warnings[0].contains("ghost"));
        assert!(h.warnings[1].contains("not a canonical"));
        // Two users with one account name are ambiguous: not bound either.
        let twins = UserBinding {
            hive_sid: None,
            users: vec![
                ("ghost".into(), SID.into()),
                ("GHOST".into(), OTHER_SID.into()),
            ],
        };
        assert_eq!(map(&parse(&log), &twins, &guard()).records.len(), 1);
    }

    #[test]
    fn update_runs_are_folded_and_each_run_binds_its_own_user() {
        let run = |user: &'static str, existed: u32| -> Vec<Rec<'static>> {
            vec![
                (
                    START,
                    0,
                    match user {
                        "tester" => &["PC", "tester", r"C:\Program Files\My App", ""],
                        _ => &["PC", "admin", r"C:\Program Files\My App\", ""],
                    },
                ),
                (FILE, existed, &[r"C:\Program Files\My App\app.exe"]),
                (FILE, 8, &[r"c:\program files\my app\shared.dll"]),
                (KEY, HKCU, &[r"Software\Vendor\My App"]),
                (END, 0, &[""]),
            ]
        };
        let mut recs = run("tester", 0);
        recs.extend(run("admin", 1));
        recs.extend(run("tester", 0));
        let log = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION,
            ADMIN,
            true,
            &recs,
        );
        let h = map(&parse(&log), &binding(), &guard());
        assert_eq!(h.app_dirs, [r"C:\Program Files\My App"]);
        assert_eq!(h.raw_records, 15);
        assert_eq!(h.records.len(), 4, "{:?}", h.records);
        // The flag of any run is kept.
        assert!(h.records[0].existed_before && !h.records[0].shared);
        assert!(h.records[1].shared);
        assert_eq!(
            h.records[2].target,
            key(&format!(r"HKU\{SID}\Software\Vendor\My App"))
        );
        assert_eq!(
            h.records[3].target,
            key(&format!(r"HKU\{OTHER_SID}\Software\Vendor\My App"))
        );
        // Deterministic.
        assert_eq!(map(&parse(&log), &binding(), &guard()), h);
    }

    #[test]
    fn system32_of_a_32_bit_install_is_syswow64() {
        let recs: &[Rec<'_>] = &[
            (
                START,
                0,
                &["PC", "tester", r"C:\Program Files (x86)\My App", ""],
            ),
            (FILE, 0, &[r"C:\Windows\system32\legacy.dll"]),
            // FILE_DISABLE_FS_REDIR.
            (FILE, 2048, &[r"C:\Windows\System32\native.dll"]),
            (FILE, 0, &[r"C:\Windows\py.exe"]),
            (
                FILE,
                0,
                &[r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\My App.lnk"],
            ),
            // Whole tree: DIR_IS_DIR | DIR_DELETE_FILES | DIR_DELETE_SUBDIRS_ALSO.
            (DIR, 14, &[r"C:\Program Files (x86)\My App\cache"]),
            // Only when empty: not mapped.
            (DIR, 2, &[r"C:\Program Files (x86)\My App"]),
        ];
        let h32 = map(
            &parse(&build(
                "{APP}",
                "My App",
                inno::MAX_SUPPORTED_VERSION,
                ADMIN,
                false,
                recs,
            )),
            &binding(),
            &guard(),
        );
        let paths = |h: &InnoHarvest| -> Vec<String> {
            h.records
                .iter()
                .map(|r| match &r.target {
                    Target::Path { path } => path.clone(),
                    other => panic!("{other:?}"),
                })
                .collect()
        };
        assert_eq!(
            paths(&h32),
            [
                r"C:\Windows\SysWOW64\legacy.dll",
                r"C:\Windows\System32\native.dll",
                r"C:\Windows\py.exe",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\My App.lnk",
                r"C:\Program Files (x86)\My App\cache",
            ]
        );
        let h64 = map(
            &parse(&build(
                "{APP}",
                "My App",
                inno::MAX_SUPPORTED_VERSION,
                ADMIN,
                true,
                recs,
            )),
            &binding(),
            &guard(),
        );
        assert_eq!(paths(&h64)[0], r"C:\Windows\system32\legacy.dll");

        // Declared executables outside the roots.
        let roots = [Root {
            path: r"C:\Program Files (x86)\My App".into(),
            kind: RootKind::InstallRoot,
            source: RootSource::InnoApp,
            trust: SourceTrust::AdminOnly,
            volume_serial: None,
            parent_existed: true,
        }];
        let outside = outside_root_files(
            &h32.records,
            &roots,
            r"C:\Program Files (x86)\My App\unins000.dat",
        );
        assert_eq!(
            outside
                .iter()
                .map(|f| (f.path.as_str(), f.source.0.as_str()))
                .collect::<Vec<_>>(),
            [
                (r"C:\Windows\py.exe", "inno:unins000.dat"),
                (r"C:\Windows\System32\native.dll", "inno:unins000.dat"),
                (r"C:\Windows\SysWOW64\legacy.dll", "inno:unins000.dat"),
            ]
        );
    }

    #[test]
    fn read_locates_the_log_and_reports_problems_as_warnings() {
        let good = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION,
            ADMIN,
            true,
            &[
                (START, 0, &["PC", "tester", r"C:\Program Files\My App", ""]),
                (KEY, HKCU, &[r"Software\Vendor\My App"]),
            ],
        );
        let newer = build(
            "{APP}",
            "My App",
            inno::MAX_SUPPORTED_VERSION + 1,
            ADMIN,
            true,
            &[],
        );
        let f = Fixture::builder()
            .file_content(r"C:\Program Files\My App\unins000.dat", good)
            .file_content(r"C:\Program Files\Newer\unins001.dat", newer)
            .file_content(
                r"C:\Program Files\Broken\unins000.dat",
                b"not a log".to_vec(),
            )
            .file(r"C:\Program Files\NoContent\unins000.dat", 10)
            .dir(r"C:\Program Files\NoLog")
            .build();
        let env = EnvMap::new();
        let g = guard();
        let harvest = |uninstall: &str| {
            let mut e = entry("App_is1", "My App");
            e.uninstall_string = Some(uninstall.into());
            read(&f, &e, &binding(), &env, &g)
        };

        let h = harvest(r#""C:\Program Files\My App\unins000.exe" /SILENT"#);
        assert!(h.parsed && h.warnings.is_empty(), "{:?}", h.warnings);
        assert_eq!(
            h.log_path.as_deref(),
            Some(r"C:\Program Files\My App\unins000.dat")
        );
        assert_eq!(h.records.len(), 1);

        let h = harvest(r"C:\Program Files\Newer\unins001.exe");
        assert!(!h.parsed && h.records.is_empty());
        assert_eq!(
            h.log_path.as_deref(),
            Some(r"C:\Program Files\Newer\unins001.dat")
        );
        assert!(
            h.warnings[0].contains(&format!("version {}", inno::MAX_SUPPORTED_VERSION + 1)),
            "{:?}",
            h.warnings
        );

        for (uninstall, needle) in [
            (r"C:\Program Files\Broken\unins000.exe", "not usable"),
            (r"C:\Program Files\NoContent\unins000.exe", "cannot read"),
            (r"C:\Program Files\NoLog\unins000.exe", "no uninstall log"),
        ] {
            let h = harvest(uninstall);
            assert!(!h.parsed && h.records.is_empty(), "{uninstall}");
            assert_eq!(h.warnings.len(), 1);
            assert!(
                h.warnings[0].contains(needle),
                "{uninstall}: {:?}",
                h.warnings
            );
        }

        // Not an Inno uninstaller: nothing to read, nothing to warn about.
        let h = harvest(r#""C:\Program Files\My App\uninstall.exe""#);
        assert_eq!(h, InnoHarvest::default());
    }
}
