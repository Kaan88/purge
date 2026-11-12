// Copyright (c) 2017 Marcin Szeniak
// Modified by Purge
// Ported from BCU: source/UninstallTools/Factory/RegistryFactory.cs (Apache-2.0)
// Ported from BCU: source/UninstallTools/Factory/InfoAdders/InstallDateAdder.cs (Apache-2.0)

//! ARP enumeration: one [`InventoryEntry`] per Uninstall key (ENGINE_PLAN.md §4.1, §4.2).
//!
//! Written fresh from Microsoft's documented Uninstall-key semantics, with BCU's `RegistryFactory` as a
//! starting point for which values are read and how they are trimmed. Nothing comes from the clone's list
//! builder.
//!
//! What is enumerated, in this order:
//! 1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit view);
//! 2. `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit view);
//! 3. `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Uninstall` for every loaded user hive, the
//!    interactive user first. `HKCU\Software` is shared between the views, so user hives have no 32-bit
//!    twin.
//!
//! The rules:
//! - **Exactly one entry per key.** Nothing is deduplicated (the same key name in both views gives two
//!   entries) and nothing is dropped: a key without `DisplayName` is kept with `has_display_name = false`,
//!   and a key whose values cannot be read is kept with what is known plus a warning.
//! - Raw flags are reported as found; grouping into tabs is UI policy.
//! - `writable_by` is `admin` for `HKLM` and `user` for `HKU` entries; `scope` follows the hive.
//! - `install_time_evidence` keeps every hint as found: `InstallDate` (day precision, local midnight via
//!   [`ArpOptions::utc_offset_secs`]), the key's LastWriteTime, the creation time of the install directory
//!   and of the Inno uninstall log (`unins000.dat` next to `unins000.exe`), when the source knows them.
//! - Paths read from the key are expanded with the interactive user's environment
//!   ([`ArpOptions::env`]) only for `HKLM` entries and the interactive user's own entries; another user's
//!   `%LOCALAPPDATA%` is not the interactive user's.
//!
//! [`inventory`] runs the enumeration and the MSI merge ([`crate::msi_merge`]) over all three sources and
//! gives the `purge.inventory/0` document.

use std::collections::BTreeMap;
use std::fmt;

use purge_model::{
    FileTime, InstallScope, InstallTimeEvidence, InstallTimeSource, InventoryDoc, InventoryEntry,
    ProgramId, RawFlags, View, WritableBy,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{RegValue, SourceError};
use purge_win::env::{EnvMap, expand_with};

use crate::kind::{self, BUNDLE_VALUES, EXE_SCAN_BYTES, INNO_VALUE_PREFIX, KindFacts};

/// The Uninstall key below `SOFTWARE` (and below `SOFTWARE\WOW6432Node` for the 32-bit view).
pub const UNINSTALL_TAIL: &str = r"Microsoft\Windows\CurrentVersion\Uninstall";

/// How the enumeration reads paths and dates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArpOptions {
    /// The interactive user's SID: that hive is enumerated first among the user hives, and its entries'
    /// paths are expanded with [`env`](Self::env).
    pub interactive_sid: Option<String>,
    /// The interactive user's environment (names upper-cased, as `SystemSource::env` gives them).
    pub env: BTreeMap<String, String>,
    /// Local time minus UTC, in seconds, for day-precision dates (`InstallDate` is a local calendar day).
    /// 0 when unknown: the day then starts at UTC midnight.
    pub utc_offset_secs: i64,
}

/// Something the inventory could not read. The enumeration goes on; the entry set may be incomplete
/// where a warning names an Uninstall root, and an entry may lack facts where it names a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryWarning {
    /// The key (or the source call) the problem is about.
    pub location: String,
    /// What was being read.
    pub reading: &'static str,
    /// The source's answer.
    pub error: SourceError,
}

impl fmt::Display for InventoryWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: cannot read {}: {}",
            self.location, self.reading, self.error
        )
    }
}

/// The entries one enumeration found, before the MSI merge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArpScan {
    /// One entry per Uninstall key, in enumeration order.
    pub entries: Vec<InventoryEntry>,
    /// What could not be read.
    pub warnings: Vec<InventoryWarning>,
}

/// A complete inventory: the document plus what could not be read on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// The `purge.inventory/0` document.
    pub doc: InventoryDoc,
    /// What could not be read.
    pub warnings: Vec<InventoryWarning>,
}

/// One Uninstall root: the hive's SID (`None` for `HKLM`) and the view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UninstallRoot {
    sid: Option<String>,
    view: View,
}

impl UninstallRoot {
    fn path(&self) -> String {
        let wow = match self.view {
            View::K64 => "",
            View::K32 => "WOW6432Node\\",
        };
        match &self.sid {
            None => format!("HKLM\\SOFTWARE\\{wow}{UNINSTALL_TAIL}"),
            Some(sid) => format!("HKU\\{sid}\\Software\\{wow}{UNINSTALL_TAIL}"),
        }
    }

    fn program_id(&self, key_name: &str) -> Result<ProgramId, purge_model::ProgramIdError> {
        match &self.sid {
            None => ProgramId::machine(self.view, key_name),
            Some(sid) => ProgramId::user(sid.clone(), self.view, key_name),
        }
    }
}

/// The full inventory over the three sources: ARP enumeration ([`enumerate`]) with options taken from
/// `sys` (interactive SID, environment), then the MSI merge by ProductCode
/// ([`crate::msi_merge::merge`]). `utc_offset_secs` is as in [`ArpOptions`].
pub fn inventory(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
    utc_offset_secs: i64,
) -> Inventory {
    let mut warnings = Vec::new();
    let mut warn = |location: &str, reading, error| {
        warnings.push(InventoryWarning {
            location: location.to_owned(),
            reading,
            error,
        })
    };
    let interactive_sid = sys
        .user_sid()
        .map_err(|e| warn("system", "the interactive user's SID", e))
        .ok();
    let env = sys
        .env()
        .map_err(|e| warn("system", "the environment", e))
        .unwrap_or_default();
    let products = sys
        .msi_products()
        .map_err(|e| warn("msi", "the installed MSI products", e))
        .unwrap_or_default();
    let opts = ArpOptions {
        interactive_sid,
        env,
        utc_offset_secs,
    };
    let scan = enumerate(reg, fs, &opts);
    warnings.extend(scan.warnings);
    Inventory {
        doc: crate::msi_merge::merge(scan.entries, &products, utc_offset_secs),
        warnings,
    }
}

/// Enumerates every Uninstall key (see the module documentation for the order and the rules).
pub fn enumerate(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    opts: &ArpOptions,
) -> ArpScan {
    let mut scan = ArpScan::default();
    let mut roots = vec![
        UninstallRoot {
            sid: None,
            view: View::K64,
        },
        UninstallRoot {
            sid: None,
            view: View::K32,
        },
    ];
    let mut sids = match reg.loaded_user_sids() {
        Ok(sids) => sids,
        Err(error) => {
            scan.warnings.push(InventoryWarning {
                location: "HKU".into(),
                reading: "the loaded user hives",
                error,
            });
            Vec::new()
        }
    };
    // The interactive user first; the rest keep the source's order.
    if let Some(me) = &opts.interactive_sid
        && let Some(i) = sids.iter().position(|s| s.eq_ignore_ascii_case(me))
    {
        let mine = sids.remove(i);
        sids.insert(0, mine);
    }
    roots.extend(sids.into_iter().map(|sid| UninstallRoot {
        sid: Some(sid),
        view: View::K64,
    }));

    let env: EnvMap = opts
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for root in &roots {
        let root_path = root.path();
        let names = match reg.subkeys(&root_path) {
            Ok(names) => names,
            Err(SourceError::NotFound) => continue,
            Err(error) => {
                scan.warnings.push(InventoryWarning {
                    location: root_path,
                    reading: "the Uninstall key's subkeys",
                    error,
                });
                continue;
            }
        };
        let expand = match &root.sid {
            None => true,
            Some(sid) => opts
                .interactive_sid
                .as_deref()
                .is_some_and(|me| me.eq_ignore_ascii_case(sid)),
        };
        for name in names {
            let id = match root.program_id(&name) {
                Ok(id) => id,
                Err(e) => {
                    // A subkey name cannot be empty or hold `\`, and `loaded_user_sids` leaves out the
                    // `_Classes` hives, so this is a source defect; report it rather than invent an id.
                    scan.warnings.push(InventoryWarning {
                        location: format!("{root_path}\\{name}"),
                        reading: "a program id for the key",
                        error: SourceError::InvalidPath(e.to_string()),
                    });
                    continue;
                }
            };
            let (entry, warnings) = read_entry_with(reg, fs, id, expand.then_some(&env), opts);
            scan.entries.push(entry);
            scan.warnings.extend(warnings);
        }
    }
    scan
}

/// Reads one Uninstall key into an entry. `id` names the key; paths in it are expanded with the options'
/// environment when the key is `HKLM` or the interactive user's.
pub fn read_entry(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    id: ProgramId,
    opts: &ArpOptions,
) -> (InventoryEntry, Vec<InventoryWarning>) {
    let expand = match id.hive_sid() {
        None => true,
        Some(sid) => opts
            .interactive_sid
            .as_deref()
            .is_some_and(|me| me.eq_ignore_ascii_case(sid)),
    };
    let env: EnvMap = opts
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    read_entry_with(reg, fs, id, expand.then_some(&env), opts)
}

/// The values of one key, looked up by name case-insensitively.
struct KeyValues(Vec<RegValue>);

impl KeyValues {
    fn get(&self, name: &str) -> Option<&RegValue> {
        self.0.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    /// A `REG_SZ`/`REG_EXPAND_SZ` value as written, `None` when missing, of another type or blank.
    fn raw_string(&self, name: &str) -> Option<String> {
        self.get(name)
            .and_then(|v| v.data.string())
            .filter(|s| !s.trim().is_empty())
    }

    /// A string value trimmed of surrounding whitespace.
    fn trimmed(&self, name: &str) -> Option<String> {
        self.raw_string(name).map(|s| s.trim().to_owned())
    }

    /// A flag value: a non-zero DWORD, or the string `1`.
    fn flag(&self, name: &str) -> bool {
        self.get(name).is_some_and(|v| {
            v.data.dword().is_some_and(|d| d != 0)
                || v.data.string().is_some_and(|s| s.trim() == "1")
        })
    }

    fn has_prefix(&self, prefix: &str) -> bool {
        self.0.iter().any(|v| {
            v.name
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        })
    }

    /// The first non-empty string of a `REG_MULTI_SZ` or a plain string value.
    fn first_string(&self, name: &str) -> Option<String> {
        let v = self.get(name)?;
        v.data
            .multi_sz()
            .and_then(|segs| segs.into_iter().find(|s| !s.trim().is_empty()))
            .or_else(|| v.data.string())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }
}

fn read_entry_with(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    id: ProgramId,
    env: Option<&EnvMap>,
    opts: &ArpOptions,
) -> (InventoryEntry, Vec<InventoryWarning>) {
    let key_path = id.key_path();
    let mut warnings = Vec::new();
    let values = KeyValues(match reg.values(&key_path) {
        Ok(v) => v,
        Err(error) => {
            warnings.push(InventoryWarning {
                location: key_path.clone(),
                reading: "the key's values",
                error,
            });
            Vec::new()
        }
    });

    let display_name = values.trimmed("DisplayName");
    let uninstall_string = values.raw_string("UninstallString");
    let quiet_uninstall_string = values.raw_string("QuietUninstallString");
    let install_location = values.raw_string("InstallLocation");
    let flags = RawFlags {
        system_component: values.flag("SystemComponent"),
        has_display_name: display_name.is_some(),
        has_uninstall_string: uninstall_string.is_some(),
        parent_key: values.trimmed("ParentKeyName"),
        release_type: values.trimmed("ReleaseType"),
        windows_installer: values.flag("WindowsInstaller"),
    };

    let expand_path = |raw: &str| -> Option<String> {
        let s = raw.trim().trim_matches('"').trim();
        if s.is_empty() {
            return None;
        }
        match env {
            Some(env) => Some(expand_with(s, env)),
            None if s.contains('%') => None,
            None => Some(s.to_owned()),
        }
    };

    let facts = KindFacts {
        key_name: id.key_name(),
        windows_installer: flags.windows_installer,
        uninstall_string: uninstall_string.as_deref(),
        quiet_uninstall_string: quiet_uninstall_string.as_deref(),
        has_inno_values: values.has_prefix(INNO_VALUE_PREFIX),
        has_bundle_values: BUNDLE_VALUES.iter().any(|n| values.get(n).is_some()),
    };
    let detection = kind::detect(&facts, |exe| {
        let path = expand_path(exe)?;
        fs.read_bytes(&path, EXE_SCAN_BYTES).ok()
    });
    let upgrade_code = match detection.kind {
        purge_model::InstallerKind::Burn => values.first_string("BundleUpgradeCode"),
        _ => values.first_string("UpgradeCode"),
    };

    // Install-time hints, each as found.
    let mut install_time_evidence = Vec::new();
    let mut hint = |source, time: Option<FileTime>| {
        if let Some(time) = time.filter(|t| t.0 != 0) {
            install_time_evidence.push(InstallTimeEvidence { source, time });
        }
    };
    let install_date = values.get("InstallDate").and_then(|v| {
        v.data
            .string()
            .and_then(|s| parse_install_date(&s, opts.utc_offset_secs))
            .or_else(|| v.data.dword().and_then(dword_install_date))
    });
    hint(InstallTimeSource::ArpInstallDate, install_date);
    hint(
        InstallTimeSource::KeyLastWrite,
        reg.key_info(&key_path).ok().map(|i| i.lwt),
    );
    let created = |path: &str| fs.metadata(path).ok().and_then(|m| m.times.created);
    hint(
        InstallTimeSource::InstallDirCreation,
        install_location
            .as_deref()
            .and_then(expand_path)
            .and_then(|p| created(&p)),
    );
    hint(
        InstallTimeSource::UninstallLogCreation,
        uninstall_string
            .as_deref()
            .and_then(kind::uninstaller)
            .and_then(|cmd| inno_log_path(&cmd.exe))
            .and_then(|p| expand_path(&p))
            .and_then(|p| created(&p)),
    );

    let (scope, writable_by) = match id.hive_sid() {
        None => (InstallScope::Machine, WritableBy::Admin),
        Some(_) => (InstallScope::User, WritableBy::User),
    };
    let entry = InventoryEntry {
        key_path,
        hive_sid: id.hive_sid().map(String::from),
        view: id.view(),
        display_name: display_name.unwrap_or_else(|| id.key_name().to_owned()),
        version: values.trimmed("DisplayVersion"),
        publisher: values.trimmed("Publisher"),
        flags,
        installer_kind: detection.kind,
        scope,
        product_code: detection.product_code,
        upgrade_code,
        inno_app_id: detection.inno_app_id,
        writable_by,
        install_location,
        uninstall_string,
        quiet_uninstall_string,
        display_icon: values.raw_string("DisplayIcon"),
        install_time_evidence,
        msi: None,
        program_id: id,
    };
    (entry, warnings)
}

/// The Inno uninstall log next to an Inno uninstaller: `unins000.exe` -> `unins000.dat`. `None` for any
/// other file name.
pub fn inno_log_path(uninstaller_exe: &str) -> Option<String> {
    let name_start = uninstaller_exe.rfind(['\\', '/']).map_or(0, |i| i + 1);
    let name = &uninstaller_exe[name_start..];
    let b = name.as_bytes();
    let is_inno = b.len() == 12
        && b[..5].eq_ignore_ascii_case(b"unins")
        && b[5..8].iter().all(u8::is_ascii_digit)
        && b[8..].eq_ignore_ascii_case(b".exe");
    is_inno.then(|| format!("{}{}.dat", &uninstaller_exe[..name_start], &name[..8]))
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Local midnight of a calendar day as a [`FileTime`]; `None` for an impossible or implausible date
/// (years outside 1980..=2100).
pub fn local_midnight(year: i64, month: i64, day: i64, utc_offset_secs: i64) -> Option<FileTime> {
    let valid = (1980..=2100).contains(&year)
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day);
    valid.then(|| {
        FileTime::from_unix_secs(days_from_civil(year, month, day) * 86_400 - utc_offset_secs)
    })
}

/// Parses an install date written as `YYYYMMDD` (the documented form, also MSI's `InstallDate`),
/// `YYYY-MM-DD` or `YYYY/MM/DD` into local midnight of that day. Other forms give `None`: the raw value
/// stays in the key, and guessing a day/month order would invent evidence.
pub fn parse_install_date(s: &str, utc_offset_secs: i64) -> Option<FileTime> {
    let s = s.trim();
    if !s.is_ascii() {
        return None;
    }
    let digits: String = match s.len() {
        8 => s.to_owned(),
        10 if matches!(&s[4..5], "-" | "/") && s[4..5] == s[7..8] => {
            format!("{}{}{}", &s[..4], &s[5..7], &s[8..])
        }
        _ => return None,
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| digits[r].parse::<i64>().ok();
    local_midnight(n(0..4)?, n(4..6)?, n(6..8)?, utc_offset_secs)
}

/// A DWORD `InstallDate`: some installers write seconds since the Unix epoch. Accepted only in the
/// plausible range (from 1990); anything else is not a date.
fn dword_install_date(v: u32) -> Option<FileTime> {
    const FROM: u32 = 631_152_000; // 1990-01-01; a u32 ends in 2106.
    (v >= FROM).then(|| FileTime::from_unix_secs(i64::from(v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::InstallerKind;
    use purge_source::fixture::Fixture;
    use purge_source::types::{FileTimes, RegData};

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";
    const HKLM64: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const HKLM32: &str = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    fn hku(sid: &str) -> String {
        format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall")
    }

    fn opts() -> ArpOptions {
        ArpOptions {
            interactive_sid: Some(SID.into()),
            ..ArpOptions::default()
        }
    }

    fn by_id<'a>(scan: &'a ArpScan, id: &str) -> &'a InventoryEntry {
        let id: ProgramId = id.parse().unwrap();
        scan.entries
            .iter()
            .find(|e| e.program_id == id)
            .unwrap_or_else(|| panic!("no entry {id}"))
    }

    #[test]
    fn both_views_give_two_entries() {
        let mut f = Fixture::new();
        f.set_value(
            &format!(r"{HKLM64}\Notepad++"),
            "DisplayName",
            RegData::from_sz("Notepad++ (64-bit x64)"),
        );
        f.set_value(
            &format!(r"{HKLM32}\Notepad++"),
            "DisplayName",
            RegData::from_sz("Notepad++ (32-bit x86)"),
        );
        let scan = enumerate(&f, &f, &opts());
        assert_eq!(scan.entries.len(), 2);
        let a = by_id(&scan, "HKLM|64|Notepad++");
        let b = by_id(&scan, "HKLM|32|Notepad++");
        assert_eq!(a.view, View::K64);
        assert_eq!(b.view, View::K32);
        assert_eq!(b.key_path, format!(r"{HKLM32}\Notepad++"));
        assert_eq!(b.display_name, "Notepad++ (32-bit x86)");
        assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
    }

    #[test]
    fn user_entries_are_user_writable_and_interactive_first() {
        let mut f = Fixture::new();
        f.set_value(
            &format!(r"{}\B", hku(OTHER)),
            "DisplayName",
            RegData::from_sz("B"),
        );
        f.set_value(
            &format!(r"{}\A", hku(SID)),
            "DisplayName",
            RegData::from_sz("A"),
        );
        f.set_value(
            &format!(r"{HKLM64}\M"),
            "DisplayName",
            RegData::from_sz("M"),
        );
        // A classes hive next to the profile is never a source of entries.
        f.set_value(
            &format!(r"HKU\{SID}_Classes\Software\{UNINSTALL_TAIL}\C"),
            "DisplayName",
            RegData::from_sz("C"),
        );
        let scan = enumerate(&f, &f, &opts());
        let ids: Vec<String> = scan
            .entries
            .iter()
            .map(|e| e.program_id.to_string())
            .collect();
        assert_eq!(
            ids,
            vec![
                "HKLM|64|M".to_string(),
                format!("HKU:{SID}|64|A"),
                format!("HKU:{OTHER}|64|B")
            ]
        );
        let a = &scan.entries[1];
        assert_eq!(a.writable_by, WritableBy::User);
        assert_eq!(a.scope, InstallScope::User);
        assert_eq!(a.hive_sid.as_deref(), Some(SID));
        assert_eq!(a.key_path, format!(r"{}\A", hku(SID)));
        assert_eq!(scan.entries[0].writable_by, WritableBy::Admin);
        assert_eq!(scan.entries[0].scope, InstallScope::Machine);
        assert_eq!(scan.entries[0].hive_sid, None);
        // The model's consistency rule holds for every entry.
        for e in &scan.entries {
            assert_eq!(e.program_id.key_path(), e.key_path);
            assert_eq!(e.program_id.hive_sid(), e.hive_sid.as_deref());
            assert_eq!(e.program_id.view(), e.view);
        }
    }

    #[test]
    fn keys_without_display_name_are_kept() {
        let mut f = Fixture::new();
        f.add_key(&format!(r"{HKLM64}\AddressBook"));
        f.set_value(
            &format!(r"{HKLM64}\Connection Manager"),
            "SystemComponent",
            RegData::from_dword(1),
        );
        f.set_value(
            &format!(r"{HKLM64}\Blank"),
            "DisplayName",
            RegData::from_sz("   "),
        );
        let scan = enumerate(&f, &f, &opts());
        assert_eq!(scan.entries.len(), 3);
        for e in &scan.entries {
            assert!(!e.flags.has_display_name, "{}", e.program_id);
            assert_eq!(e.display_name, e.program_id.key_name());
            assert_eq!(e.installer_kind, InstallerKind::Unknown);
        }
        assert!(
            by_id(&scan, "HKLM|64|Connection Manager")
                .flags
                .system_component
        );
    }

    #[test]
    fn raw_flags_are_read() {
        let mut f = Fixture::new();
        let k = format!(r"{HKLM64}\KB123");
        f.set_value(
            &k,
            "DisplayName",
            RegData::from_sz("  Security Update for X  "),
        );
        f.set_value(&k, "SystemComponent", RegData::from_sz("1"));
        f.set_value(&k, "ParentKeyName", RegData::from_sz("Office16"));
        f.set_value(&k, "ReleaseType", RegData::from_sz("Security Update"));
        f.set_value(&k, "WindowsInstaller", RegData::from_dword(1));
        f.set_value(
            &k,
            "UninstallString",
            RegData::from_expand_sz("MsiExec.exe /X{90160000-008C-0000-1000-0000000FF1CE}"),
        );
        f.set_value(&k, "DisplayVersion", RegData::from_sz(" 1.0 "));
        f.set_value(&k, "Publisher", RegData::from_sz(""));
        let k0 = format!(r"{HKLM64}\Zero");
        f.set_value(&k0, "SystemComponent", RegData::from_dword(0));
        f.set_value(&k0, "WindowsInstaller", RegData::from_sz("0"));
        let scan = enumerate(&f, &f, &opts());
        let e = by_id(&scan, "HKLM|64|KB123");
        assert_eq!(
            e.flags,
            RawFlags {
                system_component: true,
                has_display_name: true,
                has_uninstall_string: true,
                parent_key: Some("Office16".into()),
                release_type: Some("Security Update".into()),
                windows_installer: true,
            }
        );
        assert_eq!(e.display_name, "Security Update for X");
        assert_eq!(e.version.as_deref(), Some("1.0"));
        assert_eq!(e.publisher, None);
        assert_eq!(e.installer_kind, InstallerKind::Msi);
        assert_eq!(
            e.product_code.as_deref(),
            Some("{90160000-008C-0000-1000-0000000FF1CE}")
        );
        let z = by_id(&scan, "HKLM|64|Zero");
        assert!(!z.flags.system_component && !z.flags.windows_installer);
    }

    #[test]
    fn kind_fields_and_burn_upgrade_code() {
        let mut f = Fixture::new();
        let git = format!(r"{HKLM64}\Git_is1");
        f.set_value(
            &git,
            "Inno Setup: App Path",
            RegData::from_sz(r"C:\Program Files\Git"),
        );
        f.set_value(
            &git,
            "UninstallString",
            RegData::from_sz(r#""C:\Program Files\Git\unins000.exe""#),
        );
        let py = format!(r"{}\{{e9b7c837-5066-4f10-851a-69179f987b18}}", hku(SID));
        f.set_value(&py, "BundleProviderKey", RegData::from_sz("CPython-3.12"));
        f.set_value(
            &py,
            "BundleUpgradeCode",
            RegData::from_multi_sz(&["", "{11111111-2222-3333-4444-555555555555}"]),
        );
        let scan = enumerate(&f, &f, &opts());
        let g = by_id(&scan, "HKLM|64|Git_is1");
        assert_eq!(
            (g.installer_kind, g.inno_app_id.as_deref()),
            (InstallerKind::Inno, Some("Git"))
        );
        let p = &scan.entries[1];
        assert_eq!(p.installer_kind, InstallerKind::Burn);
        assert_eq!(p.product_code, None);
        assert_eq!(
            p.upgrade_code.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
    }

    #[test]
    fn nsis_marker_is_read_through_the_filesystem_with_env_expansion() {
        let mut f = Fixture::new();
        let k = format!(r"{HKLM64}\App");
        f.set_value(
            &k,
            "UninstallString",
            RegData::from_expand_sz(r#""%ProgramFiles%\App\remove.exe""#),
        );
        let mut bytes = b"MZ....".to_vec();
        bytes.extend_from_slice(b"Nullsoft.NSIS.exehead");
        f.add_file_with_content(r"C:\Program Files\App\remove.exe", bytes);
        let mut o = opts();
        o.env
            .insert("PROGRAMFILES".into(), r"C:\Program Files".into());
        let scan = enumerate(&f, &f, &o);
        assert_eq!(scan.entries[0].installer_kind, InstallerKind::Nsis);
        // Without the environment the path cannot be read, and nothing else marks it.
        let scan = enumerate(&f, &f, &opts());
        assert_eq!(scan.entries[0].installer_kind, InstallerKind::Unknown);
    }

    #[test]
    fn install_time_evidence_is_collected() {
        let mut f = Fixture::new();
        let k = format!(r"{HKLM64}\Git_is1");
        f.set_value(&k, "InstallDate", RegData::from_sz("20261112"));
        f.set_value(
            &k,
            "InstallLocation",
            RegData::from_sz(r"C:\Program Files\Git\"),
        );
        f.set_value(
            &k,
            "UninstallString",
            RegData::from_sz(r#""C:\Program Files\Git\unins000.exe""#),
        );
        f.set_key_lwt(&k, FileTime(133_900_000_450_000_000));
        f.add_dir(r"C:\Program Files\Git");
        f.set_times(
            r"C:\Program Files\Git",
            FileTimes {
                created: Some(FileTime(133_900_000_400_000_000)),
                ..FileTimes::default()
            },
        );
        f.add_file(r"C:\Program Files\Git\unins000.dat", 10);
        f.set_times(
            r"C:\Program Files\Git\unins000.dat",
            FileTimes {
                created: Some(FileTime(133_900_000_440_000_000)),
                ..FileTimes::default()
            },
        );
        let mut o = opts();
        o.utc_offset_secs = 3 * 3600;
        let scan = enumerate(&f, &f, &o);
        let ev = &scan.entries[0].install_time_evidence;
        let day = FileTime::from_unix_secs(days_from_civil(2026, 11, 12) * 86_400 - 3 * 3600);
        assert_eq!(
            ev,
            &vec![
                InstallTimeEvidence {
                    source: InstallTimeSource::ArpInstallDate,
                    time: day
                },
                InstallTimeEvidence {
                    source: InstallTimeSource::KeyLastWrite,
                    time: FileTime(133_900_000_450_000_000)
                },
                InstallTimeEvidence {
                    source: InstallTimeSource::InstallDirCreation,
                    time: FileTime(133_900_000_400_000_000)
                },
                InstallTimeEvidence {
                    source: InstallTimeSource::UninstallLogCreation,
                    time: FileTime(133_900_000_440_000_000)
                },
            ]
        );
    }

    #[test]
    fn unreadable_roots_and_keys_warn_but_keep_entries() {
        let mut f = Fixture::new();
        f.set_value(
            &format!(r"{HKLM64}\Secret"),
            "DisplayName",
            RegData::from_sz("S"),
        );
        f.add_denied(&format!(r"{HKLM64}\Secret"));
        f.add_key(&format!(r"{HKLM32}\X"));
        f.add_denied(HKLM32);
        let scan = enumerate(&f, &f, &opts());
        let ids: Vec<String> = scan
            .entries
            .iter()
            .map(|e| e.program_id.to_string())
            .collect();
        assert_eq!(ids, vec!["HKLM|64|Secret"]);
        assert_eq!(scan.warnings.len(), 2, "{:?}", scan.warnings);
        assert!(
            scan.warnings
                .iter()
                .any(|w| w.location == HKLM32 && w.error == SourceError::AccessDenied)
        );
        assert!(scan.warnings[0].to_string().contains("cannot read"));
    }

    #[test]
    fn dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        let t = parse_install_date("20240229", 0).unwrap();
        assert_eq!(t.to_unix_secs(), 1_709_164_800);
        assert_eq!(parse_install_date("2024-02-29", 0), Some(t));
        assert_eq!(parse_install_date("2024/02/29", 0), Some(t));
        assert_eq!(parse_install_date("20230229", 0), None);
        assert_eq!(parse_install_date("2024-02/29", 0), None);
        assert_eq!(parse_install_date("11/12/2026", 0), None);
        assert_eq!(parse_install_date("19000101", 0), None);
        assert_eq!(parse_install_date("2024é229", 0), None);
        assert_eq!(parse_install_date("", 0), None);
        assert_eq!(
            parse_install_date("20240229", 3600).unwrap().to_unix_secs(),
            1_709_164_800 - 3600
        );
        assert_eq!(
            dword_install_date(1_709_164_800).unwrap().to_unix_secs(),
            1_709_164_800
        );
        assert_eq!(dword_install_date(20_240_229), None);
    }

    #[test]
    fn inno_log_paths() {
        assert_eq!(
            inno_log_path(r"C:\Git\unins000.exe").as_deref(),
            Some(r"C:\Git\unins000.dat")
        );
        assert_eq!(
            inno_log_path(r"C:\Git\UNINS001.EXE").as_deref(),
            Some(r"C:\Git\UNINS001.dat")
        );
        assert_eq!(
            inno_log_path("unins000.exe").as_deref(),
            Some("unins000.dat")
        );
        assert_eq!(inno_log_path(r"C:\Git\uninstall.exe"), None);
        assert_eq!(inno_log_path(r"C:\Git\unins00x.exe"), None);
        assert_eq!(inno_log_path(r"C:\Git\éé.exe"), None);
    }
}

/// The §11.1 inventory exit criterion on recorded rig data: the entry set equals the raw enumeration.
#[cfg(test)]
mod acceptance {
    use std::collections::BTreeSet;
    use std::path::Path;

    use serde_json::Value;

    use super::*;
    use crate::quiet::{QuietCommand, quiet_command};
    use purge_model::InstallerKind;
    use purge_source::fixture::Fixture;
    use purge_source::types::RegData;

    /// `lists-registry.json` from the VM rig: 78 HKLM rows (35 of them WOW6432Node) and 2 HKCU rows.
    const SAMPLE: &str = include_str!("../tests/fixtures/lists-registry-sample.json");
    const SID: &str = "S-1-5-21-3871234567-1234567890-987654321-1001";

    /// The rig's spelling of a key, as a canonical source path.
    fn canonical(key: &str) -> String {
        if let Some(rest) = key.strip_prefix("HKEY_LOCAL_MACHINE\\") {
            format!("HKLM\\{rest}")
        } else if let Some(rest) = key.strip_prefix("HKEY_CURRENT_USER\\") {
            format!("HKU\\{SID}\\{rest}")
        } else {
            key.to_owned()
        }
    }

    /// A fixture holding exactly the sample's Uninstall keys and their recorded values.
    fn sample_fixture() -> (Fixture, Vec<Value>) {
        let rows: Vec<Value> = serde_json::from_str(SAMPLE).unwrap();
        let mut f = Fixture::new();
        f.system_mut().user_sid = Some(SID.into());
        for r in &rows {
            let key = canonical(r["key"].as_str().unwrap());
            f.add_key(&key);
            let s = |n: &str| r[n].as_str().map(String::from);
            for (field, value) in [
                ("name", "DisplayName"),
                ("version", "DisplayVersion"),
                ("parent", "ParentKeyName"),
                ("uninstall", "UninstallString"),
                ("quiet", "QuietUninstallString"),
                ("loc", "InstallLocation"),
            ] {
                if let Some(text) = s(field) {
                    f.set_value(&key, value, RegData::from_sz(&text));
                }
            }
            for (field, value) in [("sys", "SystemComponent"), ("size", "EstimatedSize")] {
                if let Some(n) = r[field].as_u64() {
                    f.set_value(&key, value, RegData::from_dword(u32::try_from(n).unwrap()));
                }
            }
        }
        (f, rows)
    }

    fn folded(s: &str) -> String {
        s.to_lowercase()
    }

    /// `{U} <switches>` of `vm/guest/apps.ps1`, split the same way as the engine splits.
    fn template(uninstall: &str, switches: &str) -> (String, BTreeSet<String>) {
        let s = purge_win::cmdline::split(&format!("{uninstall} {switches}")).unwrap();
        (
            folded(&s.exe),
            s.args.split_whitespace().map(folded).collect(),
        )
    }

    fn shape(q: &QuietCommand) -> (String, BTreeSet<String>) {
        (
            folded(&q.exe),
            q.args.split_whitespace().map(folded).collect(),
        )
    }

    #[test]
    fn sample_gives_one_entry_per_key_and_the_rig_quiet_forms() {
        let (f, rows) = sample_fixture();
        let opts = ArpOptions {
            interactive_sid: Some(SID.into()),
            ..ArpOptions::default()
        };
        let scan = enumerate(&f, &f, &opts);
        assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);

        // Exactly one entry per source key.
        let want: BTreeSet<String> = rows
            .iter()
            .map(|r| folded(&canonical(r["key"].as_str().unwrap())))
            .collect();
        let got: Vec<String> = scan.entries.iter().map(|e| folded(&e.key_path)).collect();
        assert_eq!(rows.len(), 80);
        assert_eq!(got.len(), rows.len(), "one entry per key");
        assert_eq!(got.iter().cloned().collect::<BTreeSet<_>>(), want);
        let hklm = scan.entries.iter().filter(|e| e.hive_sid.is_none()).count();
        let wow = scan.entries.iter().filter(|e| e.view == View::K32).count();
        let user = scan
            .entries
            .iter()
            .filter(|e| e.writable_by == WritableBy::User)
            .count();
        assert_eq!((hklm, wow, user), (78, 35, 2));
        // Keys without DisplayName are kept.
        let nameless = rows.iter().filter(|r| r["name"].is_null()).count();
        assert_eq!(
            scan.entries
                .iter()
                .filter(|e| !e.flags.has_display_name)
                .count(),
            nameless
        );

        let entry = |name: &str| {
            scan.entries
                .iter()
                .find(|e| e.program_id.key_name().eq_ignore_ascii_case(name) && e.view == View::K64)
                .unwrap_or_else(|| panic!("{name}"))
        };
        let u = |e: &InventoryEntry| e.uninstall_string.clone().unwrap();
        let inno = "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES";

        let git = entry("Git_is1");
        assert_eq!(git.installer_kind, InstallerKind::Inno);
        assert_eq!(shape(&quiet_command(git).unwrap()), template(&u(git), inno));
        let code = entry("{EA457B21-F73E-494C-ACAB-524FDE069978}_is1");
        assert_eq!(
            shape(&quiet_command(code).unwrap()),
            template(&u(code), inno)
        );

        let firefox = entry("Mozilla Firefox");
        assert_eq!(firefox.installer_kind, InstallerKind::Nsis);
        let q = quiet_command(firefox).unwrap();
        assert!(q.generated);
        assert_eq!(shape(&q), template(&u(firefox), "/S"));

        let npp = entry("Notepad++");
        assert_eq!(npp.installer_kind, InstallerKind::Nsis);
        assert_eq!(shape(&quiet_command(npp).unwrap()), template(&u(npp), "/S"));

        // `msiexec /x {PC} /qn ...` (apps.ps1 adds /norestart; the engine adds REBOOT=ReallySuppress).
        let zip = entry("{23170F69-40C1-2702-2408-000001000000}");
        assert_eq!(zip.installer_kind, InstallerKind::Msi);
        let q = quiet_command(zip).unwrap();
        assert!(
            q.exe.to_ascii_lowercase().ends_with("\\msiexec.exe"),
            "{}",
            q.exe
        );
        let tokens: Vec<String> = q.args.split_whitespace().map(folded).collect();
        assert_eq!(
            tokens[..3],
            ["/x", "{23170f69-40c1-2702-2408-000001000000}", "/qn"]
        );
    }

    /// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): the inventory over the vscode snap-1 fixture equals the key
    /// set of `lists-vscode-1.json` `uninstall`; differences are listed.
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
    fn real_vscode_snap_entry_set() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let dir = Path::new(&runs).join("vscode");
        let lists = dir.join("lists-vscode-1.json");
        let f = Fixture::from_snap(&dir.join("snap-vscode-1.tsv.gz"), Some(&lists), None).unwrap();
        let inv = inventory(&f, &f, &f, 0);
        for w in &inv.warnings {
            eprintln!("warning: {w}");
        }
        let text = std::fs::read_to_string(&lists).unwrap();
        let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        let want: BTreeSet<String> = v["uninstall"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| folded(r["key"].as_str().unwrap()))
            .collect();
        let got: BTreeSet<String> = inv
            .doc
            .entries
            .iter()
            .map(|e| folded(&e.key_path))
            .collect();
        assert_eq!(got.len(), inv.doc.entries.len(), "duplicate entries");
        let missing: Vec<_> = want.difference(&got).collect();
        let extra: Vec<_> = got.difference(&want).collect();
        eprintln!(
            "entries {} (rig {}), msi_only {}; missing {missing:?}; extra {extra:?}",
            got.len(),
            want.len(),
            inv.doc.msi_only.len()
        );
        for e in &inv.doc.entries {
            eprintln!(
                "  {:<70} {:?} msi={} quiet={:?}",
                e.program_id.to_string(),
                e.installer_kind,
                e.msi.is_some(),
                quiet_command(e).map(|q| q.to_command_line())
            );
        }
        for row in &inv.doc.msi_only {
            eprintln!("  msi_only {} {:?}", row.product_code, row.product_name);
        }
        assert!(missing.is_empty() && extra.is_empty());
        assert_eq!(want.len(), 35);
    }
}
