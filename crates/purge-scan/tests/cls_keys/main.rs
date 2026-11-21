//! Goldens for the Classes key scanners of M1a package P34: CLS-PROGID, CLS-VERBS, CLS-PROTOCOL,
//! CLS-AUMID and CLS-REGAPPS (ENGINE_PLAN.md §5.6 "Classes", §1.4 Git / Firefox / VS Code targets).
//!
//! Each test builds a registry fixture and a fingerprint, runs one or more scanners and compares the
//! candidates, rendered one per line by [`common::render`], with the expected list.

mod common;
#[path = "../shared/l5.rs"]
mod l5;

mod aumid;
mod firefox;
mod git;
mod hardening;
mod progid;
mod protocol;
mod regapps;
mod verbs;

/// Invariant L5 for one world of this crate, with each Classes key scanner (`tests/shared/l5.rs`).
/// `offers`: the scanners that offer something in this world without a baseline; each of them must,
/// and some presence view must change what it offers. Returns how many candidates the no-baseline
/// scans offer.
fn l5_check(name: &str, make: &dyn Fn() -> common::World, offers: &[&str]) -> usize {
    use purge_scan::framework::Scanner;
    let scanners: [&dyn Scanner; 5] = [
        &purge_scan::cls_progid::ClsProgId,
        &purge_scan::cls_verbs::ClsVerbs,
        &purge_scan::cls_protocol::ClsProtocol,
        &purge_scan::cls_aumid::ClsAumid,
        &purge_scan::cls_regapps::ClsRegApps,
    ];
    for id in offers {
        assert!(scanners.iter().any(|s| s.id() == *id), "{id} is no scanner");
    }
    let mut offered = 0;
    for scanner in scanners {
        let what = format!("{name}/{}", scanner.id());
        let checked = l5::check(&what, &make().fp.os, &|view| {
            let mut world = make();
            world.baseline = view;
            world.run(scanner)
        });
        if offers.contains(&scanner.id()) {
            checked
                .must_offer(&what, &[scanner.id()])
                .must_change(&what);
        } else {
            assert!(
                checked.none.is_empty(),
                "{what}: offers something and is not named: {:#?}",
                checked.none
            );
        }
        offered += checked.none.len();
    }
    offered
}
