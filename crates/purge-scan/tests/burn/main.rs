//! SYS-BURNDEPS and FS-PKGCACHE tests (M1B-S-BURN). Every source is a fixture:
//! `tests/data/burn/machine.json` holds the dependency records and Package Cache directories of a removed
//! Burn bundle "App Bundle" (`{B0B0...}`, provider key `AppBundle`) and its packages:
//!
//! | package | provider key | product | state |
//! |---|---|---|---|
//! | core | `AppBundle_Core` | `{C0C0...}` | gone |
//! | Python Launcher | `{73831AC2-...}` | the same | installed, kept by nobody else |
//! | VC++ runtime | `Microsoft.VS.VC_RuntimeMinimumVSU_amd64,v14` | `{D0D0...}` | installed (a shared component) |
//! | trap `burn-shared-package` | `PurgeTrapPkg` | `{E0E0...}` | gone; another bundle depends on it since the harvest |
//! | per-user part | `AppBundle_User` (in the user's Classes) | `{F0F0...}` | gone |
//!
//! Each test changes what it needs and records what the harvest would have recorded.
//!
//! `tests/data/burn/python.json` is the real shape of a removed CPython bundle (vm/runs/m1b-python): no
//! package provider record at all, the Python Launcher linked through the kb ([`world::World::python`]).

mod burndeps;
#[path = "../shared/l5.rs"]
mod l5;
mod launcher;
mod pkgcache;
mod world;

/// Invariant L5 over both bundle worlds, with both scanners: a view below Exact that holds nothing
/// gives the no-baseline candidates exactly; one that says Windows has the keys and directories
/// preselects nothing new and unblocks nothing (`tests/shared/l5.rs`). These scanners never ask the
/// baseline for absence.
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    use purge_index::baseline_view::BaselineView;
    use purge_scan::framework::Scanner;
    use world::World;
    type Make = fn() -> World;
    let worlds: [(&str, Make); 2] = [("bundle", World::new), ("python", World::python)];
    let scanners: [&dyn Scanner; 2] = [
        &purge_scan::sys_burndeps::SysBurnDeps,
        &purge_scan::fs_pkgcache::FsPkgCache,
    ];
    let mut tally = l5::Tally::default();
    for (name, make) in worlds {
        for scanner in scanners {
            let checked = l5::check(
                &format!("{name}/{}", scanner.id()),
                &make().fp.os,
                &|view| {
                    let mut world = make();
                    world.baseline = view.unwrap_or_else(|| BaselineView::empty().clone());
                    world.run(scanner)
                },
            );
            tally.add(scanner.id(), &checked);
        }
    }
    // Both scanners offer something, and presence changes it.
    tally.assert_not_vacuous(&[], &[]);
}
