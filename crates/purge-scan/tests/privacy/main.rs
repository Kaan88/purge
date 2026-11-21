//! M1B-S-PRIVACY: the REG-PRIVACY scanner, called directly (it is not in the catalog yet). Every source
//! is a fixture; the shared data is read over it as the pipeline reads it, and the real policy bands
//! what the scanner returns.

mod budget;
mod hostile;
#[path = "../shared/l5.rs"]
mod l5;
mod stores;
mod ufh;
mod world;

/// Invariant L5 over a world with a MuiCache trace and a shortcut-usage slot of the app: a view below
/// Exact that holds nothing gives the no-baseline candidates exactly; one that says Windows has the
/// keys preselects nothing new and unblocks nothing (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    use purge_source::types::RegData;
    use world::*;
    let make = || {
        let mut fx = machine();
        sz(
            &mut fx,
            &muicache(SID),
            &format!("{}.FriendlyAppName", app_exe()),
            "App",
        );
        fx.set_value(
            &shc(SID),
            "0",
            RegData::from_multi_sz(&[app_exe().as_str()]),
        );
        fx
    };
    let none = l5::check("privacy", &fingerprint().os, &|view| {
        let mut world = World::new(make());
        world.baseline = view;
        world.privacy()
    });
    assert_eq!(none.len(), 2, "{none:#?}");
    none.must_offer("privacy", &["REG-PRIVACY"])
        .must_change("privacy");
}
