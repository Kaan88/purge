//! M1B-S-DIAG: the REG-DIAG (Tracing, EventLog sources) and FS-WER scanners, called directly (they are
//! not in the catalog yet). Every source is a fixture; the shared reference walk runs over it as the
//! pipeline runs it.

mod budget;
mod eventlog;
#[path = "../shared/l5.rs"]
mod l5;
mod tracing;
mod wer;
mod world;

/// Invariant L5 over a world with one leftover of each kind (two tracing keys, an event source the
/// MSI package records, a WER report), with both scanners: a view below Exact that holds nothing
/// gives the no-baseline candidates exactly; one that says Windows has the keys and directories
/// preselects nothing new and unblocks nothing (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    use world::*;
    let source = source_key("Application", "App Service");
    let make = || {
        let mut fx = machine();
        fx.add_key(&format!(r"{TRACING}\{MAIN_STEM}_RASAPI32"));
        fx.add_key(&format!(r"{TRACING32}\appmain_RASAPI32"));
        event_source(&mut fx, "Application", "App Service", &app_file("msg.dll"));
        wer::report(
            &mut fx,
            USER_ARCHIVE,
            "AppCrash_AppMain.exe_5c1e2f3a4b_9d8e7f_cab_0a1b2c3d",
            Some(wer::report_utf16(&app_file(MAIN_EXE))),
        );
        let mut world = World::new(fx);
        world.fp.msi = vec![msi_with_whole_key(&source, "RegEventSource")];
        world
    };
    let none = l5::check("diag", &make().fp.os, &|view| {
        let mut world = make();
        world.baseline = view;
        let world = world.ready();
        let mut found = world.diag();
        found.extend(world.wer());
        found
    });
    assert_eq!(none.len(), 4, "{:#?}", spots(&none));
    none.must_offer("diag", &["REG-DIAG", "FS-WER"])
        .must_change("diag");
}
