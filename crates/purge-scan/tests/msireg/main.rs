//! Tests of the MSI registry scanners (M1B-S-MSIREG): REG-ARP-MSI, REG-INSTFOLDERS and REG-SHAREDDLLS.
//! Every source is a fixture built in `world.rs`; the scanners are called directly through the sealing
//! driver (they are not in the catalog yet).

mod arp_msi;
mod instfolders;
#[path = "../shared/l5.rs"]
mod l5;
mod shareddlls;
mod world;

/// Invariant L5 over the gone MSI product's registration (its keys, its `Folders` values, a SharedDLLs
/// counter), with each of the three scanners: a view below Exact that holds nothing gives the
/// no-baseline candidates exactly; one that says Windows has the keys preselects nothing new and
/// unblocks nothing (`tests/shared/l5.rs`). These scanners never ask the baseline for absence.
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    use purge_index::baseline_view::BaselineView;
    use purge_scan::framework::Scanner;
    use purge_source::types::RegData;
    use world::*;
    let make = || {
        let mut fx = machine();
        fx.set_value(FOLDERS, &format!(r"{ROOT}\"), RegData::from_sz(""));
        fx.set_value(SHARED, &file("lib.dll"), RegData::from_dword(1));
        let mut world = World::with(fx);
        world.remove_root();
        world
    };
    let scanners: [&dyn Scanner; 3] = [
        &purge_scan::reg_arp_msi::RegArpMsi,
        &purge_scan::reg_instfolders::RegInstFolders,
        &purge_scan::reg_shareddlls::RegSharedDlls,
    ];
    let mut tally = l5::Tally::default();
    for scanner in scanners {
        let checked = l5::check(scanner.id(), &make().fp.os, &|view| {
            let mut world = make();
            world.baseline = view.unwrap_or_else(|| BaselineView::empty().clone());
            world.run(scanner)
        });
        tally.add(scanner.id(), &checked);
    }
    // Each of the three offers something, and presence changes it.
    tally.assert_not_vacuous(&[], &[]);
}
