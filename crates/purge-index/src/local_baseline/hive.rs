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
//! Records go into the shared [`Records`]; no value data is read (§3.3: only the name is ever used).

use purge_source::local_baseline::{HiveEntry, HiveWalk, LocalSources};
use purge_source::types::SourceResult;

use super::Records;

/// The SID the default profile's hive is recorded under (any user SID works; the normaliser replaces it).
pub const DEFAULT_PROFILE_SID: &str = "S-1-5-21-0-0-0-1000";
/// Where S2 keys are recorded.
pub const DEFAULT_HIVE_ROOT: &str = r"HKU\S-1-5-21-0-0-0-1000";
/// Where S3 keys are recorded.
pub const SYSTEM_DEFAULT_ROOT: &str = r"HKU\.DEFAULT";

/// Number of key and value records in `r`.
pub(crate) fn record_count(r: &Records) -> u64 {
    let c = r.counts();
    c.keys + c.values
}

/// What one hive source gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiveStats {
    /// The walk summary from the source.
    pub walk: HiveWalk,
    /// Key and value records added to the set (new ones only).
    pub records: u64,
}

/// S2: the default profile's hive into `out` under [`DEFAULT_HIVE_ROOT`].
pub fn default_hive_records(src: &dyn LocalSources, out: &mut Records) -> SourceResult<HiveStats> {
    let before = record_count(out);
    let walk = src.default_hive(&mut |e| add(out, DEFAULT_HIVE_ROOT, e))?;
    Ok(HiveStats {
        walk,
        records: record_count(out) - before,
    })
}

/// S3: `HKU\.DEFAULT` into `out` under [`SYSTEM_DEFAULT_ROOT`].
pub fn system_default_records(
    src: &dyn LocalSources,
    out: &mut Records,
) -> SourceResult<HiveStats> {
    let before = record_count(out);
    let walk = src.system_default(&mut |e| add(out, SYSTEM_DEFAULT_ROOT, e))?;
    Ok(HiveStats {
        walk,
        records: record_count(out) - before,
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
        HiveEntry::Key { path } => {
            out.add_key(&full(path));
        }
        HiveEntry::Value { key, name, kind } => {
            out.add_value(&full(key), name, kind);
        }
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
            .sz(
                r"HKU\.DEFAULT\Control Panel\Colors",
                "Window",
                "255 255 255",
            )
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

    fn text(records: &Records) -> String {
        let mut out = Vec::new();
        records.write_records(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Records as a baseline file, through the shipped loader (hashing and normalising there).
    fn load(records: &Records) -> Baseline {
        let text = format!(
            "#purge-baseline 1\tT\tPC\tSynthetic\t1.2\n{}",
            text(records)
        );
        Baseline::from_bytes(text.as_bytes()).expect("records parse")
    }

    #[test]
    fn default_hive_to_records() {
        let f = fixture();
        let mut out = Records::new();
        let s = default_hive_records(&f, &mut out).unwrap();
        assert!(s.walk.is_complete());
        assert_eq!(s.walk.origin, r"C:\Users\Default\NTUSER.DAT");
        assert_eq!(s.records, record_count(&out));
        let text = text(&out);
        for line in [
            r"K	hku\\s-1-5-21-0-0-0-1000",
            r"K	hku\\s-1-5-21-0-0-0-1000\\appevents\\schemes",
            r"K	hku\\s-1-5-21-0-0-0-1000\\software\\microsoft\\windows\\currentversion\\run",
            r"V	hku\\s-1-5-21-0-0-0-1000\\software\\microsoft\\windows\\currentversion\\run	onedrivesetup	1	0000000000000000",
            r"V	hku\\s-1-5-21-0-0-0-1000\\control panel\\desktop	tab\tname	4	0000000000000000",
            r"V	hku\\s-1-5-21-0-0-0-1000\\software\\classes\\.tmpl		1	0000000000000000",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} missing in\n{text}");
        }
        // 12 keys of the hive (root included) and 3 values.
        assert_eq!((s.walk.keys, s.walk.values), (12, 3));
        assert_eq!((out.counts().keys, out.counts().values), (12, 3));
        assert!(!text.contains("notdefault"));
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
            assert!(b.has_key(&format!(
                r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run"
            )));
            assert!(b.has_value(
                &format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "OneDriveSetup"
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

    /// win-unit, read only, unelevated: S2, S3 and S4 of this machine to records, with counts and times.
    #[test]
    fn live_sources_to_records() {
        use std::time::Instant;
        let live = purge_source::live::LiveLocal::new();
        let mut out = Records::new();
        let t = Instant::now();
        let s2 = default_hive_records(&live, &mut out).expect("S2");
        eprintln!(
            "S2: {} records, {:?} in {:?}",
            s2.records,
            s2.walk,
            t.elapsed()
        );
        let t = Instant::now();
        let s3 = system_default_records(&live, &mut out).expect("S3");
        eprintln!(
            "S3: {} records, {:?} in {:?}",
            s3.records,
            s3.walk,
            t.elapsed()
        );
        let t = Instant::now();
        let s4 = super::super::appx::inbox_records(&live, &mut out).expect("S4");
        eprintln!(
            "S4: {} records, {} packages ({} System), {} parsed, {} failed {:?}, {:?} in {:?}",
            s4.records,
            s4.packages,
            s4.system,
            s4.parsed,
            s4.failed.len(),
            s4.failed,
            s4.declarations,
            t.elapsed()
        );
        eprintln!("total {:?}", out.counts());
        assert!(s2.walk.is_complete() && s2.records > 500);
        assert!(s3.records > 100);
        assert!(s4.parsed >= 20 && s4.records > 0);
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
}
