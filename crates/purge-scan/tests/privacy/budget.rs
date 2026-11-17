//! REG-PRIVACY: the key-open budget (M1B_DESIGN.json `budgets`: "REG-PRIVACY at most 12 keys per
//! loaded user"), plus one read of the machine's `AppCompatFlags\Layers`. The shared walk is not used.
//!
//! What is counted: every `values()`, `subkeys()` and `key_info()` call of one scan. Apart from them the
//! scan reads each offered value once more with `value()`: the framework's rule about what a value holds
//! (`CandidateBuilder::build`), at most one per candidate.

use purge_scan::framework::{AppIdentityView, Scanner};
use purge_scan::reg_privacy::{MAX_USER_KEY_READS, RegPrivacy};
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredRegistry, Op};
use purge_source::types::RegData;

use super::world::*;

/// The users of the budget world.
const USERS: [&str; 3] = [SID, SID2, "S-1-5-21-1-2-3-1003"];

/// A machine where every user has the app's traces in every store, `others` traces of other programs
/// next to each, and `guids` UserAssist GUIDs.
fn busy(others: usize, guids: usize) -> Fixture {
    let mut fx = machine();
    let exe = app_exe();
    for sid in USERS {
        fx.add_key(&format!(r"HKU\{sid}\Software"));
        fx.add_key(&format!(r"HKU\{sid}_Classes"));
        let mut keys = vec![
            layers(sid),
            pca_store(sid),
            pca_persisted(sid),
            feature_usage(sid, "AppBadgeUpdated"),
            feature_usage(sid, "AppLaunch"),
            feature_usage(sid, "AppSwitched"),
            feature_usage(sid, "ShowJumpView"),
        ];
        keys.push(muicache(sid));
        for key in &keys {
            let suffix = if *key == muicache(sid) {
                ".FriendlyAppName"
            } else {
                ""
            };
            fx.set_value(key, &format!("{exe}{suffix}"), RegData::from_dword(1));
            for i in 0..others {
                let other = other_file(&format!("p{i}.exe"));
                fx.set_value(key, &format!("{other}{suffix}"), RegData::from_dword(1));
            }
        }
        for g in 0..guids {
            let count = user_assist(sid, &format!("{{CEBFF5CD-ACE2-4F4F-9178-{g:012X}}}"));
            fx.set_value(&count, &rot13(&exe), ua_counters());
            for i in 0..others {
                fx.set_value(
                    &count,
                    &rot13(&other_file(&format!("p{i}.exe"))),
                    ua_counters(),
                );
            }
        }
        fx.set_value(
            &shc(sid),
            "0",
            RegData::from_multi_sz(&[app_exe().as_str()]),
        );
        for i in 0..others {
            fx.set_value(
                &shc(sid),
                &format!("{}", i + 1),
                RegData::from_multi_sz(&[other_file(&format!("p{i}.exe")).as_str()]),
            );
        }
    }
    sz(&mut fx, HKLM_LAYERS, &exe, "~ RUNASADMIN");
    for i in 0..others {
        sz(
            &mut fx,
            HKLM_LAYERS,
            &other_file(&format!("p{i}.exe")),
            "~ RUNASADMIN",
        );
    }
    fx
}

/// The key reads (`values`, `subkeys`, `key_info`), the value reads and the candidates of one scan.
fn reads(fx: Fixture) -> (u64, u64, usize) {
    let world = World::new(fx);
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = RegPrivacy.scan(&world.ctx_with(&reg), &app);
    let snap = meter.snapshot();
    let keys = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues]
        .iter()
        .map(|&op| snap.get(op).calls)
        .sum();
    (keys, snap.get(Op::RegValue).calls, found.len())
}

#[test]
fn budget_key_opens() {
    let users = USERS.len() as u64;
    let budget = MAX_USER_KEY_READS as u64 * users + 1;
    let (keys, values, found) = reads(busy(200, 2));
    // Per user: 8 path-store values (MuiCache, PCA x2, Layers, FeatureUsage x4), 2 UserAssist entries,
    // 1 UFH slot; once: the machine's Layers value.
    assert_eq!(found, 11 * USERS.len() + 1, "candidates");
    assert!(
        keys <= budget,
        "REG-PRIVACY: {keys} key reads for {users} users (budget {budget})"
    );
    assert!(
        values <= found as u64,
        "{values} value reads for {found} candidates"
    );
    // Other programs' traces are read with the one call on their store, never one by one.
    assert_eq!(
        keys,
        reads(busy(0, 2)).0,
        "foreign values changed the key reads"
    );
}

/// More UserAssist GUIDs than the budget leaves room for: the budget holds, and the `Count` keys within
/// it are still read.
#[test]
fn budget_holds_with_many_user_assist_guids() {
    let users = USERS.len() as u64;
    let budget = MAX_USER_KEY_READS as u64 * users + 1;
    let (keys, _, found) = reads(busy(3, 6));
    assert!(keys <= budget, "{keys} key reads (budget {budget})");
    // Within the budget: two `Count` keys per user.
    assert_eq!(found, 11 * USERS.len() + 1, "candidates");
}
