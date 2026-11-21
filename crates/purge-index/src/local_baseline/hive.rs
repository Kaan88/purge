//! Sources S2 (the default profile's hive) and S3 (`HKU\.DEFAULT`) to baseline records
//! (BASELINE_LOCAL_DESIGN.md §3.1, §3.2 "S2").
//!
//! - S2: every key of the hive as `HKU\S-1-5-21-0-0-0-1000\<path>` ([`DEFAULT_HIVE_ROOT`]), every value as
//!   a `V` record under it. The placeholder SID is a user SID to the baseline normaliser, which turns it
//!   into `<sid>` and folds `Software\Classes` onto `<sid>_Classes`, so the template stands for every
//!   user.
//! - S3: every key and value of `HKU\.DEFAULT` as written (`HKU\S-1-5-18` is folded onto it by the
//!   normaliser).
//!
//! Records are text, one per line in the `kb/baselines/README.md` format; value records carry the hash
//! `0000000000000000` because no value data is read (§3.3: only the name is ever used). Hashing happens
//! only in the loader.
//!
//! This module also holds [`Records`], the record set the local sources write into (see the note on the
//! type).

use std::collections::BTreeSet;

use purge_source::local_baseline::{HiveEntry, HiveWalk, LocalSources};
use purge_source::types::SourceResult;

/// The SID the default profile's hive is recorded under (any user SID works; the normaliser replaces it).
pub const DEFAULT_PROFILE_SID: &str = "S-1-5-21-0-0-0-1000";
/// Where S2 keys are recorded.
pub const DEFAULT_HIVE_ROOT: &str = r"HKU\S-1-5-21-0-0-0-1000";
/// Where S3 keys are recorded.
pub const SYSTEM_DEFAULT_ROOT: &str = r"HKU\.DEFAULT";
/// The hash field of a value record whose data was not read.
pub const NO_HASH: &str = "0000000000000000";

/// One baseline record (`K` or `V`; the local sources of this module write no `D`/`F`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Record {
    /// `K\t<key>`.
    Key(String),
    /// `V\t<key>\t<name>\t<type>\t0000000000000000`.
    Value {
        /// The key.
        key: String,
        /// The value name (`""` for the default value).
        name: String,
        /// The `REG_*` type.
        ty: u32,
    },
}

impl Record {
    /// The record as one line of the baseline format, without the line feed.
    pub fn to_line(&self) -> String {
        match self {
            Record::Key(k) => format!("K\t{}", escape(k)),
            Record::Value { key, name, ty } => {
                format!("V\t{}\t{}\t{ty}\t{NO_HASH}", escape(key), escape(name))
            }
        }
    }
}

/// Escapes a text field as `kb/baselines/README.md` says: `\`, TAB, LF, CR and NUL.
pub fn escape(field: &str) -> String {
    let mut out = String::with_capacity(field.len() + 8);
    for c in field.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\0' => out.push_str(r"\0"),
            c => out.push(c),
        }
    }
    out
}

/// A de-duplicated, sorted set of baseline records as text.
///
/// Defined here for BL-SOURCES; BL-MANIFEST writes component-manifest records into a set of the same
/// role, and the two are one type once both packages are merged. Adding a key adds every ancestor
/// below the root (`HKLM\SOFTWARE` for `HKLM\SOFTWARE\X`; a bare `HKLM` or `HKU` is not a record).
/// Nothing is ever removed (L1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    set: BTreeSet<Record>,
}

impl Records {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds key `key` and its ancestors. Empty segments (doubled or trailing `\`) are dropped.
    pub fn key(&mut self, key: &str) {
        let segs: Vec<&str> = key.split('\\').filter(|s| !s.is_empty()).collect();
        for n in (2..=segs.len()).rev() {
            if !self.set.insert(Record::Key(segs[..n].join("\\"))) {
                break; // its ancestors are there already
            }
        }
    }

    /// Adds value `name` of type `ty` of `key`, and the key with its ancestors.
    pub fn value(&mut self, key: &str, name: &str, ty: u32) {
        let key = key.split('\\').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\\");
        self.key(&key);
        self.set.insert(Record::Value {
            key,
            name: name.to_owned(),
            ty,
        });
    }

    /// Whether `key` is recorded, spelled exactly (case included).
    pub fn has_key(&self, key: &str) -> bool {
        self.set.contains(&Record::Key(key.to_owned()))
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// No records.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// The records in order.
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.set.iter()
    }

    /// Every record as a line with its line feed, in order.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for r in &self.set {
            out.push_str(&r.to_line());
            out.push('\n');
        }
        out
    }
}

/// What one hive source gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiveStats {
    /// The walk summary from the source.
    pub walk: HiveWalk,
    /// Records added to the set (new ones only).
    pub records: u64,
}

/// S2: the default profile's hive into `out` under [`DEFAULT_HIVE_ROOT`].
pub fn default_hive_records(src: &dyn LocalSources, out: &mut Records) -> SourceResult<HiveStats> {
    let before = out.len();
    let walk = src.default_hive(&mut |e| add(out, DEFAULT_HIVE_ROOT, e))?;
    Ok(HiveStats {
        walk,
        records: (out.len() - before) as u64,
    })
}

/// S3: `HKU\.DEFAULT` into `out` under [`SYSTEM_DEFAULT_ROOT`].
pub fn system_default_records(
    src: &dyn LocalSources,
    out: &mut Records,
) -> SourceResult<HiveStats> {
    let before = out.len();
    let walk = src.system_default(&mut |e| add(out, SYSTEM_DEFAULT_ROOT, e))?;
    Ok(HiveStats {
        walk,
        records: (out.len() - before) as u64,
    })
}

fn add(out: &mut Records, root: &str, e: HiveEntry<'_>) {
    let full = |rel: &str| {
        if rel.is_empty() {
            root.to_owned()
        } else {
            format!(r"{root}\{rel}")
        }
    };
    match e {
        HiveEntry::Key { path } => out.key(&full(path)),
        HiveEntry::Value { key, name, kind } => out.value(&full(key), name, kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{Baseline, normalised_key};
    use purge_source::fixture::{Fixture, HiveFixture};
    use purge_source::local_baseline::PROFILE_LIST;

    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

    fn fixture() -> Fixture {
        let mut f = Fixture::builder()
            .expand_sz(PROFILE_LIST, "Default", r"%SystemDrive%\Users\Default")
            .env("SYSTEMDRIVE", "C:")
            .sz(r"HKU\.DEFAULT\Control Panel\Colors", "Window", "255 255 255")
            .dword(r"HKU\.DEFAULT\Software\Microsoft\Tab\Key", "Flag", 1)
            .key(r"HKU\S-1-5-21-1-2-3-1001\Software\NotDefault")
            .build();
        f.set_offline_hive(
            r"C:\Users\Default\NTUSER.DAT",
            HiveFixture::new()
                .value(
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    "OneDriveSetup",
                    REG_SZ,
                )
                .value(r"Software\Classes\.tmpl", "", REG_SZ)
                .value(r"Control Panel\Desktop", "Tab\tName", REG_DWORD)
                .key(r"AppEvents\Schemes"),
        );
        f
    }

    /// Records as a baseline file, through the shipped loader (hashing and normalising there).
    fn load(records: &Records) -> Baseline {
        let text = format!("#purge-baseline 1\tT\tPC\tSynthetic\t1.2\n{}", records.to_text());
        Baseline::from_bytes(text.as_bytes()).expect("records parse")
    }

    #[test]
    fn default_hive_to_records() {
        let f = fixture();
        let mut out = Records::new();
        let s = default_hive_records(&f, &mut out).unwrap();
        assert!(s.walk.is_complete());
        assert_eq!(s.walk.origin, r"C:\Users\Default\NTUSER.DAT");
        assert_eq!(s.records as usize, out.len());
        let text = out.to_text();
        for line in [
            r"K	HKU\\S-1-5-21-0-0-0-1000",
            r"K	HKU\\S-1-5-21-0-0-0-1000\\AppEvents\\Schemes",
            r"K	HKU\\S-1-5-21-0-0-0-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"V	HKU\\S-1-5-21-0-0-0-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run	OneDriveSetup	1	0000000000000000",
            r"V	HKU\\S-1-5-21-0-0-0-1000\\Control Panel\\Desktop	Tab\tName	4	0000000000000000",
            r"V	HKU\\S-1-5-21-0-0-0-1000\\Software\\Classes\\.tmpl		1	0000000000000000",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} missing in\n{text}");
        }
        // 12 keys of the hive (root included) and 3 values.
        assert_eq!((s.walk.keys, s.walk.values), (12, 3));
        assert_eq!(out.len(), 12 + 3);
        assert!(!text.contains("NotDefault"));
    }

    #[test]
    fn sid_placeholder_through_the_normaliser() {
        let f = fixture();
        let mut out = Records::new();
        default_hive_records(&f, &mut out).unwrap();
        system_default_records(&f, &mut out).unwrap();

        assert_eq!(
            normalised_key(&format!(r"{DEFAULT_HIVE_ROOT}\Software\Microsoft")),
            r"hku\<sid>\software\microsoft"
        );
        assert_eq!(
            normalised_key(&format!(r"{DEFAULT_HIVE_ROOT}\Software\Classes\.tmpl")),
            r"hku\<sid>_classes\.tmpl"
        );

        let b = load(&out);
        // Any user's spelling finds the template's keys and values.
        for sid in ["S-1-5-21-111-222-333-1001", "S-1-12-1-1-2-3-4"] {
            assert!(b.has_key(&format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run")));
            assert!(b.has_value(
                &format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "onedrivesetup"
            ));
            assert!(b.has_key(&format!(r"HKU\{sid}_Classes\.tmpl")));
            assert!(b.has_key(&format!(r"HKU\{sid}\Software\Classes\.tmpl")));
            assert!(b.has_value(&format!(r"HKU\{sid}\Control Panel\Desktop"), "Tab\tName"));
        }
        assert!(b.has_key(r"HKCU\AppEvents\Schemes"));
        assert!(!b.has_key(r"HKU\S-1-5-21-111-222-333-1001\Software\Vendor"));
        // S3 as written, and through the S-1-5-18 alias.
        assert!(b.has_key(r"HKU\.DEFAULT\Control Panel\Colors"));
        assert!(b.has_key(r"HKU\S-1-5-18\Software\Microsoft\Tab\Key"));
        assert!(b.has_value(r"HKU\S-1-5-18\Software\Microsoft\Tab\Key", "Flag"));
        // S3 is not a user template.
        assert!(!b.has_key(r"HKU\S-1-5-21-111-222-333-1001\Control Panel\Colors"));
    }

    #[test]
    fn missing_sources_are_errors_not_records() {
        let f = Fixture::builder()
            .expand_sz(PROFILE_LIST, "Default", r"C:\Users\Default")
            .build();
        let mut out = Records::new();
        assert!(default_hive_records(&f, &mut out).is_err());
        assert!(system_default_records(&f, &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn records_keep_ancestors_and_escape() {
        let mut r = Records::new();
        r.key(r"HKLM\SOFTWARE\Classes\CLSID\{X}\\");
        r.value(r"HKLM\SOFTWARE\A", "n\\m", 0);
        assert!(r.has_key(r"HKLM\SOFTWARE"));
        assert!(r.has_key(r"HKLM\SOFTWARE\Classes\CLSID"));
        assert!(r.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{X}"));
        assert!(!r.has_key("HKLM"));
        assert_eq!(
            r.to_text(),
            "K\tHKLM\\\\SOFTWARE\nK\tHKLM\\\\SOFTWARE\\\\A\nK\tHKLM\\\\SOFTWARE\\\\Classes\nK\tHKLM\\\\SOFTWARE\\\\Classes\\\\CLSID\nK\tHKLM\\\\SOFTWARE\\\\Classes\\\\CLSID\\\\{X}\nV\tHKLM\\\\SOFTWARE\\\\A\tn\\\\m\t0\t0000000000000000\n"
        );
        assert_eq!(escape("a\0\r\n"), r"a\0\r\n");
    }
}
