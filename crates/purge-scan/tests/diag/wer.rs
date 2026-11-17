//! FS-WER: Windows Error Reporting reports of the app's programs.

use purge_model::{Action, Band, Category, EvidenceKind, Target, Tier};
use purge_scan::fs_wer::MAX_REPORT_BYTES;
use purge_source::fixture::Fixture;

use super::world::*;

/// `Report.wer` text naming `app_path`, as WER writes it (UTF-16 LE with its byte-order mark).
pub fn report_utf16(app_path: &str) -> Vec<u8> {
    let text = format!(
        "Version=1\r\nEventType=APPCRASH\r\nAppName={}\r\nAppPath={app_path}\r\n",
        app_path.rsplit('\\').next().unwrap_or(app_path)
    );
    let mut out = vec![0xFF, 0xFE];
    out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

/// A report directory `store\name` holding `Report.wer` (`report`, when given) and a minidump.
pub fn report(fx: &mut Fixture, store: &str, name: &str, report: Option<Vec<u8>>) -> String {
    let dir = format!(r"{store}\{name}");
    fx.add_dir(&dir);
    fx.add_file(&format!(r"{dir}\memory.hdmp"), 4096);
    if let Some(bytes) = report {
        fx.add_file_with_content(&format!(r"{dir}\Report.wer"), bytes);
    }
    dir
}

#[test]
fn wer_report_apppath_in_root_likely() {
    let mut fx = machine();
    let main = app_file(MAIN_EXE);
    let user = report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_5c1e2f3a4b_9d8e7f_cab_0a1b2c3d",
        Some(report_utf16(&main)),
    );
    // WER cuts long names short; UTF-8 text is read too.
    let queued = report(
        &mut fx,
        PD_QUEUE,
        "AppHang_AppMain.e_1a2b_3c4d",
        Some(format!("AppPath={main}\n").into_bytes()),
    );
    let world = World::new(fx).ready();
    let found = world.wer();
    assert_eq!(found.len(), 2, "{:#?}", spots(&found));
    for dir in [&user, &queued] {
        let c = get(&found, dir);
        assert_eq!(c.action, Action::Quarantine);
        assert_eq!(c.category, Category::Privacy);
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        assert!(
            has(c, EvidenceKind::PointsIntoInstallRoot, Tier::B),
            "{:#?}",
            c.evidence
        );
        assert!(!any_tier_a(c));
        assert_eq!(band(c), Band::Likely);
    }
    let c = get(&found, &user);
    assert_eq!(c.child_count, Some(2));
    assert_eq!(c.size_bytes, Some(4096 + report_utf16(&main).len() as u64));
}

#[test]
fn wer_report_same_exe_name_other_path_nothing() {
    // Hostile: another product's `AppMain.exe` crashed; its report carries the app's exe name.
    let mut fx = machine();
    report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_1_2",
        Some(report_utf16(&format!(r"{OTHER_ROOT}\{MAIN_EXE}"))),
    );
    // And a report whose program is a bare name, or a UNC path.
    report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_3_4",
        Some(report_utf16(MAIN_EXE)),
    );
    report(
        &mut fx,
        USER_QUEUE,
        "AppCrash_AppMain.exe_5_6",
        Some(report_utf16(r"\\server\share\App\AppMain.exe")),
    );
    // Two `AppPath=` lines that disagree.
    report(
        &mut fx,
        USER_QUEUE,
        "AppCrash_AppMain.exe_7_8",
        Some(
            format!(
                "AppPath={}\r\nAppPath={OTHER_ROOT}\\{MAIN_EXE}\r\n",
                app_file(MAIN_EXE)
            )
            .into_bytes(),
        ),
    );
    let world = World::new(fx).ready();
    let found = world.wer();
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

#[test]
fn wer_report_without_wer_file_nothing() {
    let mut fx = machine();
    report(&mut fx, USER_ARCHIVE, "AppCrash_AppMain.exe_1_2", None);
    // A report directory with a directory inside is not the shape WER writes.
    let odd = report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_3_4",
        Some(report_utf16(&app_file(MAIN_EXE))),
    );
    fx.add_dir(&format!(r"{odd}\sub"));
    // A report that decodes as nothing.
    report(
        &mut fx,
        USER_QUEUE,
        "AppCrash_AppMain.exe_5_6",
        Some(vec![0xFF, 0xFE, 0x41]),
    );
    let world = World::new(fx).ready();
    let found = world.wer();
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

#[test]
fn wer_oversized_report_file_nothing() {
    let mut fx = machine();
    // UTF-8, so that any first part of it would decode and name the app.
    let mut big = format!("AppPath={}\r\n", app_file(MAIN_EXE)).into_bytes();
    big.resize(MAX_REPORT_BYTES + 64, b' ');
    report(&mut fx, USER_ARCHIVE, "AppCrash_AppMain.exe_1_2", Some(big));
    // Exactly at the cap is read.
    let mut at_cap = report_utf16(&app_file(MAIN_EXE));
    at_cap.resize(MAX_REPORT_BYTES, 0);
    let ok = report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_3_4",
        Some(at_cap),
    );
    let world = World::new(fx).ready();
    let found = world.wer();
    assert_eq!(spots(&found), [ok]);
}

#[test]
fn wer_root_never() {
    let mut fx = machine();
    // Files named like reports directly in the stores, a report in WER's `Temp`, and a report that
    // names the app below a store: only report directories are ever offered.
    fx.add_file_with_content(
        &format!(r"{USER_ARCHIVE}\AppCrash_AppMain.exe_1_2"),
        report_utf16(&app_file(MAIN_EXE)),
    );
    report(
        &mut fx,
        PD_TEMP,
        "AppCrash_AppMain.exe_3_4",
        Some(report_utf16(&app_file(MAIN_EXE))),
    );
    let ok = report(
        &mut fx,
        PD_ARCHIVE,
        "NonCritical_AppMain.exe_5_6",
        Some(report_utf16(&app_file(MAIN_EXE))),
    );
    let world = World::new(fx).ready();
    let found = world.wer();
    assert_eq!(spots(&found), [ok]);
    for c in &found {
        let Target::Path { path } = &c.target else {
            panic!("{c:?}")
        };
        for root in [
            PD_ARCHIVE,
            PD_QUEUE,
            PD_TEMP,
            USER_ARCHIVE,
            USER_QUEUE,
            r"C:\ProgramData\Microsoft\Windows\WER",
            r"C:\Users\tester\AppData\Local\Microsoft\Windows\WER",
        ] {
            assert!(!path.eq_ignore_ascii_case(root), "{path}");
        }
    }
}

#[test]
fn wer_store_that_cannot_be_read_offers_nothing() {
    let mut fx = machine();
    report(
        &mut fx,
        USER_ARCHIVE,
        "AppCrash_AppMain.exe_1_2",
        Some(report_utf16(&app_file(MAIN_EXE))),
    );
    fx.add_denied(USER_ARCHIVE);
    let world = World::new(fx).ready();
    assert!(world.wer().is_empty());
}
