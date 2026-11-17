//! The read budget of REG-DIAG and FS-WER (M1B_DESIGN.json `budgets`): REG-DIAG at most one `subkeys()`
//! per event log plus 2 opens per source matched, one `subkeys()` of `Tracing` (one per registry view)
//! and, once a tracing key matched, one `subkeys()` of each `App Paths` key (R3a S5); FS-WER one `list_dir()` of each WER store (at most 6), names only, plus one `list_dir()` per
//! matched report.
//!
//! The common blockers of every scanner read the target key's facts once (`key_info()`); that read is
//! counted against the 2 opens of a source, and as the one open of a tracing key candidate.

use purge_scan::framework::{AppIdentityView, Scanner};
use purge_scan::fs_wer::FsWer;
use purge_scan::reg_diag::RegDiag;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, Op};
use purge_source::types::RegData;

use super::wer::{report, report_utf16};
use super::world::*;

/// The app's event sources, tracing keys and reports of the busy world.
const N: usize = 6;

/// A world with `N` sources of the app in one log, `N` tracing keys and `N` reports of the app, and
/// `others` sources, logs, tracing keys and reports that are not the app's.
fn busy_world(others: usize) -> World {
    let mut fx = machine();
    let mut exes = Vec::new();
    for i in 0..N {
        let exe = format!("Tool{i}.exe");
        fx.add_key(&format!(r"{TRACING}\Tool{i}_RASAPI32"));
        event_source(
            &mut fx,
            "Application",
            &format!("App Source {i}"),
            &app_file(&format!("msg{i}.dll")),
        );
        report(
            &mut fx,
            USER_ARCHIVE,
            &format!("AppCrash_{exe}_{i:08x}_cab"),
            Some(report_utf16(&app_file(&exe))),
        );
        exes.push(exe);
    }
    for i in 0..others {
        fx.add_key(&format!(r"{TRACING}\foreign{i}_RASAPI32"));
        fx.set_value(
            &format!(r"{EVENTLOG_SET}\Log{i}\Source{i}"),
            "EventMessageFile",
            RegData::from_expand_sz(&format!(r"{OTHER_ROOT}\msg{i}.dll")),
        );
        fx.set_value(
            &format!(r"{EVENTLOG_SET}\Application\Foreign {i}"),
            "EventMessageFile",
            RegData::from_expand_sz(r"%SystemRoot%\System32\wevtapi.dll"),
        );
        report(
            &mut fx,
            USER_QUEUE,
            &format!("AppCrash_foreign{i}.exe_{i:08x}_cab"),
            Some(report_utf16(&format!(r"{OTHER_ROOT}\foreign{i}.exe"))),
        );
    }
    let mut world = World::new(fx);
    world.fp.exes = exes
        .iter()
        .map(|e| purge_model::ExeFile {
            path: app_file(e),
            main: false,
        })
        .collect();
    world.ready()
}

/// The reads of one scan by `scanner`: (registry key opens, directory listings, file reads,
/// candidates).
fn reads(world: &World, scanner: &dyn Scanner) -> (u64, u64, u64, usize) {
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let fs = MeteredFileSystem::new(&world.fixture, &meter);
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = scanner.scan(&world.ctx_with(&reg, &fs), &app);
    let snap = meter.snapshot();
    let opens = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|&op| snap.get(op).calls)
        .sum();
    (
        opens,
        snap.get(Op::FsListDir).calls,
        snap.get(Op::FsReadBytes).calls,
        found.len(),
    )
}

#[test]
fn budget_key_opens_and_dir_lists() {
    let world = busy_world(40);

    // REG-DIAG: one listing of each Tracing view, one of each of the three `App Paths` keys once a
    // tracing key matched (R3a S5), one of the one log holding the app's sources, and per candidate its
    // values and the common blockers' key facts.
    let (opens, lists, files, found) = reads(&world, &RegDiag);
    assert_eq!(found, 2 * N, "candidates");
    assert_eq!((lists, files), (0, 0), "REG-DIAG reads no file");
    let budget = 2 + 3 + 1 + 2 * N as u64 + N as u64;
    assert!(
        opens <= budget,
        "REG-DIAG: {opens} key opens (budget {budget})"
    );
    // Another product's sources, logs and tracing keys are never opened one by one.
    let quiet = busy_world(0);
    assert_eq!(
        reads(&quiet, &RegDiag).0,
        opens,
        "foreign items changed the reads"
    );

    // FS-WER: the stores (two of the machine, two of the one profile), then one listing and one read per
    // report of the app.
    let (opens, lists, files, found) = reads(&world, &FsWer);
    assert_eq!(found, N, "reports");
    assert_eq!(opens, 0, "FS-WER reads no key");
    let stores = 4u64;
    assert!(stores <= 6);
    assert!(
        lists <= stores + N as u64,
        "FS-WER: {lists} listings (budget {})",
        stores + N as u64
    );
    assert!(files <= N as u64, "FS-WER: {files} reads");
    assert_eq!(
        reads(&quiet, &FsWer).1,
        lists,
        "foreign reports changed the listings"
    );
}
