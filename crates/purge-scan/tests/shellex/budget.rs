//! COM-SHELLEX: the key-open budget (M1B_DESIGN.json `budgets`): one `subkeys()` call on each of at
//! most 60 fixed places per registry view, plus at most 4 opens per shared-walk hit. The class keys the
//! handlers name are read once per class and view, charged at COM-CLASS's budget (40 per anchor).

use purge_scan::com_shellex::ComShellex;
use purge_scan::framework::{AppIdentityView, Scanner};
use purge_source::metered::{Meter, MeteredRegistry, Op};
use purge_source::types::RegData;

use super::world::*;

/// The app's classes of the budget world.
const N: usize = 8;

/// A world with `N` classes of the app, gone, each named by four registrations (a menu handler by its
/// default, one by its name, an approval, an overlay), and `others` handlers and approvals of another
/// product's class.
fn busy_world(others: usize) -> World {
    let mut fx = machine();
    let mut clsids = Vec::new();
    for i in 0..N {
        let clsid = format!("{{A0A0A0A0-0000-4000-8000-{i:012X}}}");
        class(
            &mut fx,
            HKLM_CLASSES,
            &clsid,
            "InprocServer32",
            &app_file(&format!("a{i}.dll")),
        );
        let menu = handler_key(HKLM_CLASSES, "*", "ContextMenuHandlers", &format!("App{i}"));
        sz(&mut fx, &menu, &clsid);
        fx.add_key(&handler_key(
            HKLM_CLASSES,
            "Directory",
            "ContextMenuHandlers",
            &clsid,
        ));
        fx.set_value(&approved(CV), &clsid, RegData::from_sz("App"));
        let overlay = format!(r"{CV}\Explorer\ShellIconOverlayIdentifiers\App{i}");
        sz(&mut fx, &overlay, &clsid);
        clsids.push(clsid);
    }
    for i in 0..others {
        let menu = handler_key(
            HKLM_CLASSES,
            "*",
            "ContextMenuHandlers",
            &format!("Other{i}"),
        );
        sz(&mut fx, &menu, FOREIGN);
        fx.set_value(
            &approved(CV),
            &format!("{{0F0F0F0F-0000-4000-8000-{i:012X}}}"),
            RegData::from_sz("Other"),
        );
    }
    let mut world = World::new(fx);
    world.fp.anchors.clsids = clsids;
    world.ready(&[])
}

/// The key-opening registry reads of one scan, and the candidates it returned.
fn reads(world: &World) -> (u64, usize) {
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = ComShellex.scan(&world.ctx_with(&reg), &app);
    let snap = meter.snapshot();
    let opens = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|&op| snap.get(op).calls)
        .sum();
    (opens, found.len())
}

#[test]
fn budget_key_opens() {
    let world = busy_world(200);
    let (opens, found) = reads(&world);
    assert_eq!(found, 4 * N, "candidates");
    // The views listed: the machine's Classes, the user's Classes, HKLM\SOFTWARE in both views and the
    // user's Software.
    let views = 5;
    let hits = world
        .ext
        .ref_hits_for(&world.fp.app.program_id)
        .map_or(0, |h| h.len() as u64);
    let budget = 60 * views + 4 * hits + 40 * N as u64;
    assert!(
        opens <= budget,
        "COM-SHELLEX: {opens} opens for {hits} hits and {N} classes (budget {budget})"
    );
    // Another product's handlers are listed by the one call on their list, never opened one by one.
    assert_eq!(
        opens,
        reads(&busy_world(0)).0,
        "foreign handlers changed the reads"
    );
}
