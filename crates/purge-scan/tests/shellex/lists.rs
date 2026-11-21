//! COM-SHELLEX: the shell's approval lists (`Shell Extensions\Approved`, `Cached`), the Explorer hook
//! lists, and the per-user and 32-bit places.

use purge_model::{Action, Band, EvidenceKind, Target, Tier};
use purge_source::types::RegData;

use super::world::*;

/// `<cv>\Shell Extensions\Cached`.
fn cached(cv: &str) -> String {
    format!(r"{cv}\Shell Extensions\Cached")
}

#[test]
fn approved_value_only_never_key() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let list = approved(CV);
    fx.set_value(&list, CLS_A, RegData::from_sz("App menu"));
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &value_spot(&list, CLS_A));
    assert_eq!(c.action, Action::DeleteValue);
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert!(has(c, EvidenceKind::ChainedRef, Tier::A), "{c:#?}");
    assert_eq!(band(c), Band::Safe);
    // The list holds nothing else of anybody's: still never the key.
    assert!(
        !found
            .iter()
            .any(|c| matches!(&c.target, Target::RegKey { .. }))
    );
}

/// Trap `shellex-approved`: approvals of classes that are not the app's stay, also when their class
/// is gone and the app's own entry is offered.
#[test]
fn approved_value_of_foreign_clsid_untouched() {
    let mut fx = machine();
    dangling_class(&mut fx);
    class(
        &mut fx,
        HKLM_CLASSES,
        FOREIGN,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    );
    let list = approved(CV);
    fx.set_value(&list, CLS_A, RegData::from_sz("App menu"));
    fx.set_value(&list, FOREIGN, RegData::from_sz("Other menu"));
    // An approval naming the app's class in its data only.
    fx.set_value(
        &list,
        "{0D0D0D0D-0000-4000-8000-00000000000D}",
        RegData::from_sz(CLS_A),
    );
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(find(&found, &value_spot(&list, CLS_A)).is_some());
}

/// Hostile: `Cached` names start with the class; only a name that is the class exactly, then nothing
/// or a blank, is the class's.
#[test]
fn cached_value_prefix_match_is_guid_exact() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let list = cached(&user_cv());
    let good = format!("{CLS_A} {{000214E6-0000-0000-C000-000000000046}} 0xFFFF");
    let glued = format!("{CLS_A}X {{000214E6-0000-0000-C000-000000000046}} 0xFFFF");
    let longer = format!("{}0}}", &CLS_A[..37]);
    for name in [&good, &glued, &longer] {
        fx.set_value(&list, name, RegData::from_binary(vec![1, 0, 0, 0]));
    }
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &value_spot(&list, &good));
    assert_eq!(c.action, Action::DeleteValue);
    assert_eq!(band(c), Band::Safe);
    // `Cached` is a per-user list: the machine's key of that name is not read.
    let mut fx = machine();
    dangling_class(&mut fx);
    fx.set_value(&cached(CV), &good, RegData::from_binary(vec![1, 0, 0, 0]));
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
}

#[test]
fn execute_hooks_and_task_scheduler_values() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let hooks = format!(r"{CV}\Explorer\ShellExecuteHooks");
    let tasks = format!(r"{CV}\Explorer\SharedTaskScheduler");
    fx.set_value(&hooks, CLS_A, RegData::from_sz(""));
    fx.set_value(&tasks, CLS_A, RegData::from_sz("App task"));
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 2, "{found:#?}");
    for list in [&hooks, &tasks] {
        let c = get(&found, &value_spot(list, CLS_A));
        assert_eq!(c.action, Action::DeleteValue);
        assert_eq!(band(c), Band::Safe, "{list}");
    }
}

/// A value naming a class that is gone in every view has no server left to prove dangling: Likely,
/// unless the harvest recorded the value.
#[test]
fn approved_value_of_a_gone_class_likely() {
    let mut fx = machine();
    fx.set_value(&approved(CV), CLS_A, RegData::from_sz("App menu"));
    let found = app_world(fx).ready(&[]).shellex();
    let c = get(&found, &value_spot(&approved(CV), CLS_A));
    assert_eq!(band(c), Band::Likely, "{c:#?}");
    // With the harvest's record of the value.
    let mut fx = machine();
    fx.set_value(&approved(CV), CLS_A, RegData::from_sz("App menu"));
    let mut world = app_world(fx);
    world.fp.ref_snapshot = vec![purge_model::RefSnapEntry {
        target: Target::RegValue {
            path: approved(CV),
            name: CLS_A.into(),
        },
        carrier: purge_model::RefCarrier::ValueName,
        anchor: purge_model::AnchorRef {
            kind: purge_model::AnchorKind::Clsid,
            text: CLS_A.into(),
        },
        parent_values: 1,
        parent_subkeys: 0,
        data_hash: None,
    }];
    let found = world.ready(&[]).shellex();
    let c = get(&found, &value_spot(&approved(CV), CLS_A));
    assert!(
        has_kind(c, EvidenceKind::InPreUninstallRefSnapshot),
        "{c:#?}"
    );
    assert_eq!(band(c), Band::Safe, "{c:#?}");
}

#[test]
fn per_user_and_wow64_places() {
    let mut fx = machine();
    // CLS_A: the user's own class (per-user registration), gone. CLS_B: only in the 32-bit view.
    class(
        &mut fx,
        &user_classes(),
        CLS_A,
        "InprocServer32",
        &app_file("a.dll"),
    );
    class(
        &mut fx,
        HKLM_CLASSES32,
        CLS_B,
        "InprocServer32",
        &app_file("b32.dll"),
    );
    let user_menu = handler_key(&user_classes(), "*", "ContextMenuHandlers", "App");
    let user_overlay = format!(
        r"{}\Explorer\ShellIconOverlayIdentifiers\AppOverlay",
        user_cv()
    );
    sz(&mut fx, &user_menu, CLS_A);
    sz(&mut fx, &user_overlay, CLS_A);
    fx.set_value(&approved(&user_cv()), CLS_A, RegData::from_sz("App"));
    // The 32-bit lists, and the 64-bit list for a class the 64-bit view does not have.
    fx.set_value(&approved(CV32), CLS_B, RegData::from_sz("App 32"));
    fx.set_value(&approved(CV), CLS_B, RegData::from_sz("App 32"));
    let overlay32 = format!(r"{CV32}\Explorer\ShellIconOverlayIdentifiers\App32");
    sz(&mut fx, &overlay32, CLS_B);
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 6, "{found:#?}");
    for at in [
        user_menu.clone(),
        user_overlay.clone(),
        value_spot(&approved(&user_cv()), CLS_A),
        value_spot(&approved(CV32), CLS_B),
        overlay32.clone(),
    ] {
        assert_eq!(band(get(&found, &at)), Band::Safe, "{at}");
    }
    // Explorer's 64-bit list names a class the 64-bit view does not have: listed, not Safe.
    assert_eq!(
        band(get(&found, &value_spot(&approved(CV), CLS_B))),
        Band::Likely
    );
    // Spelled through the physical keys.
    assert!(user_menu.starts_with(&format!(r"HKU\{SID}_Classes\")));
    assert!(overlay32.starts_with(r"HKLM\SOFTWARE\WOW6432Node\"));
}

/// Invariant L5 over the approval lists and an overlay handler of the app's gone class: a view below
/// Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let make = || {
        let mut fx = machine();
        dangling_class(&mut fx);
        fx.set_value(&approved(CV), CLS_A, RegData::from_sz("App menu"));
        fx.set_value(&approved(&user_cv()), CLS_A, RegData::from_sz("App"));
        sz(
            &mut fx,
            &format!(r"{CV}\Explorer\ShellIconOverlayIdentifiers\App"),
            CLS_A,
        );
        app_world(fx)
    };
    let none = crate::l5::check("approval lists", &make().fp.os, &|view| {
        let mut world = make();
        world.baseline = view;
        world.ready(&[]).shellex()
    });
    assert!(none.len() >= 2, "{none:#?}");
    none.must_offer("approval lists", &["COM-SHELLEX"])
        .must_change("approval lists");
}
