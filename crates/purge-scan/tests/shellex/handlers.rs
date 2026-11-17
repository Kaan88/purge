//! COM-SHELLEX: handler keys below `shellex`, the Explorer lists of handler keys, and the class they
//! stand for.

use purge_model::{Action, Band, Blocker, Category, EvidenceKind, Harm, Reversibility, Tier};
use purge_source::types::RegData;

use super::world::*;

/// `HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\App`, default `CLS_A`.
fn star_menu() -> String {
    handler_key(HKLM_CLASSES, "*", "ContextMenuHandlers", "App")
}

#[test]
fn context_menu_handler_named_key_with_default_clsid_safe() {
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &star_menu(), CLS_A);
    let world = app_world(fx).ready(&[]);
    let found = world.shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &star_menu());
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::ShellCom);
    assert_eq!(c.harm, Harm::Low);
    assert_eq!(c.reversibility, Reversibility::Full);
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::A), "{c:#?}");
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert!(has(c, EvidenceKind::ChainedRef, Tier::A), "{c:#?}");
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), Band::Safe);
}

/// A handler key whose name is the class: found by listing the handler list, with or without a
/// default value of its own.
#[test]
fn handler_key_named_by_clsid() {
    for default in [None, Some("App menu")] {
        let mut fx = machine();
        dangling_class(&mut fx);
        let key = handler_key(HKLM_CLASSES, "Directory", "ContextMenuHandlers", CLS_A);
        match default {
            Some(text) => sz(&mut fx, &key, text),
            None => fx.add_key(&key),
        }
        let world = app_world(fx).ready(&[]);
        let found = world.shellex();
        assert_eq!(found.len(), 1, "{default:?}: {found:#?}");
        let c = get(&found, &key);
        assert_eq!(c.action, Action::DeleteKey);
        assert_eq!(band(c), Band::Safe, "{default:?}: {c:#?}");
    }
    // The name of the class, but a default that names another class: that class's handler.
    let mut fx = machine();
    dangling_class(&mut fx);
    let key = handler_key(HKLM_CLASSES, "Directory", "ContextMenuHandlers", CLS_A);
    sz(&mut fx, &key, FOREIGN);
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
}

#[test]
fn handler_key_with_extra_value_offers_value_only() {
    // Another value next to the default.
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &star_menu(), CLS_A);
    fx.set_value(&star_menu(), "Flags", RegData::from_dword(1));
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &value_spot(&star_menu(), ""));
    assert_eq!(c.action, Action::DeleteValue);
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert!(!has_kind(c, EvidenceKind::ComKeyOwnership));
    assert_eq!(band(c), Band::Safe);
    // A subkey below it.
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &star_menu(), CLS_A);
    fx.add_key(&format!(r"{}\Sub", star_menu()));
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        get(&found, &value_spot(&star_menu(), "")).action,
        Action::DeleteValue
    );
    // Named by the class, its default only text, with another value: deleting the default would not
    // unregister it, and the key holds more than the registration. Nothing.
    let mut fx = machine();
    dangling_class(&mut fx);
    let key = handler_key(HKLM_CLASSES, "*", "ContextMenuHandlers", CLS_A);
    sz(&mut fx, &key, "App menu");
    fx.set_value(&key, "Flags", RegData::from_dword(1));
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
}

/// Hostile: after the harvest another product registers the app's class to its own DLL (in either
/// view). The handler is that product's now: nothing is offered.
#[test]
fn handler_clsid_reregistered_by_other_product_no_candidate() {
    let other_dll = format!(r"{OTHER_ROOT}\other.dll");
    let mut fx = machine();
    class(&mut fx, HKLM_CLASSES, CLS_A, "InprocServer32", &other_dll);
    sz(&mut fx, &star_menu(), CLS_A);
    sz(&mut fx, &approved(CV), "App menu");
    fx.set_value(&approved(CV), CLS_A, RegData::from_sz("App menu"));
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
    // The 64-bit class is the app's and gone; the 32-bit one is the other product's.
    let mut fx = machine();
    dangling_class(&mut fx);
    class(&mut fx, HKLM_CLASSES32, CLS_A, "InprocServer32", &other_dll);
    sz(&mut fx, &star_menu(), CLS_A);
    fx.set_value(&approved(CV), CLS_A, RegData::from_sz("App menu"));
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
}

#[test]
fn handler_clsid_still_present_likely() {
    let mut fx = machine();
    dangling_class(&mut fx);
    fx.add_dir(ROOT);
    fx.add_file(&app_file("a.dll"), 100);
    sz(&mut fx, &star_menu(), CLS_A);
    let found = app_world(fx).ready(&[]).shellex();
    let c = get(&found, &star_menu());
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::B), "{c:#?}");
    assert!(!has_kind(c, EvidenceKind::DanglingRef));
    assert!(
        !c.evidence.iter().any(|e| e.tier == Tier::A && e.weight > 0),
        "{c:#?}"
    );
    assert_eq!(band(c), Band::Likely);
}

/// The class key is gone in every view: the handler names nothing.
#[test]
fn handler_of_a_class_gone_everywhere_safe() {
    let mut fx = machine();
    sz(&mut fx, &star_menu(), CLS_A);
    let found = app_world(fx).ready(&[]).shellex();
    let c = get(&found, &star_menu());
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::A), "{c:#?}");
    assert!(has(c, EvidenceKind::ChainedRef, Tier::A), "{c:#?}");
    assert_eq!(band(c), Band::Safe);
}

/// Without a baseline of this Windows neither the handler key nor the class is proven not Windows'
/// own: listed, never Safe.
#[test]
fn handler_without_baseline_likely() {
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &star_menu(), CLS_A);
    let mut world = app_world(fx);
    world.baseline = None;
    let found = world.ready(&[]).shellex();
    let c = get(&found, &star_menu());
    assert_eq!(band(c), Band::Likely, "{c:#?}");
}

/// Hostile: a handler key Windows has, re-pointed by the app at its own class. Never taken, neither
/// the key nor its default value.
#[test]
fn windows_handler_repointed_never_taken() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let key = handler_key(HKLM_CLASSES, "*", "ContextMenuHandlers", "Sharing");
    sz(&mut fx, &key, CLS_A);
    let mut world = app_world(fx);
    world.baseline = Some(baseline(&[&key]));
    assert!(world.ready(&[]).shellex().is_empty());
    // With another value in it, where only its default value would be offered.
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &key, CLS_A);
    fx.set_value(&key, "Flags", RegData::from_dword(1));
    let mut world = app_world(fx);
    world.baseline = Some(baseline(&[&key]));
    assert!(world.ready(&[]).shellex().is_empty());
}

/// A handler the shell keys by interface id, below a file extension, and an icon handler below one of
/// the app's ProgIDs.
#[test]
fn iid_and_icon_handlers_of_types() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let thumb = format!(r"{HKLM_CLASSES}\.appdoc\shellex\{IID_THUMB}");
    let icon = format!(r"{HKLM_CLASSES}\App.Document\shellex\IconHandler");
    sz(&mut fx, &thumb, CLS_A);
    sz(&mut fx, &icon, CLS_A);
    // Not a place: a key below another key's shellex that is no handler.
    let other = format!(r"{HKLM_CLASSES}\SomeClass\shellex\ContextMenuHandlers\App");
    sz(&mut fx, &other, CLS_A);
    let mut world = app_world(fx);
    world.fp.anchors.progids = vec!["App.Document".into()];
    let found = world.ready(&[]).shellex();
    assert_eq!(found.len(), 2, "{found:#?}");
    for key in [&thumb, &icon] {
        assert_eq!(band(get(&found, key)), Band::Safe, "{key}");
    }
}

#[test]
fn icon_overlay_identifier() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let key = format!(r"{CV}\Explorer\ShellIconOverlayIdentifiers\   AppOverlay");
    sz(&mut fx, &key, CLS_A);
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &key);
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(band(c), Band::Safe);
}

#[test]
fn bho_key() {
    let mut fx = machine();
    dangling_class(&mut fx);
    let key = format!(r"{CV}\Explorer\Browser Helper Objects\{CLS_A}");
    sz(&mut fx, &key, "App helper");
    fx.set_value(&key, "NoExplorer", RegData::from_dword(1));
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &key);
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(band(c), Band::Safe);
    // Something else in it: not the registration alone, and its default names no class.
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &key, "App helper");
    fx.set_value(&key, "Other", RegData::from_dword(1));
    assert!(app_world(fx).ready(&[]).shellex().is_empty());
}

#[test]
fn structural_parent_never_offered() {
    let mut fx = machine();
    dangling_class(&mut fx);
    // The handler lists and `shellex` keys hold, as their own default, the app's class (a broken
    // installer wrote there); the handler itself is the app's.
    for object in ["*", "Directory", "Drive", "Folder"] {
        let shellex = format!(r"{HKLM_CLASSES}\{object}\shellex");
        sz(&mut fx, &shellex, CLS_A);
        sz(&mut fx, &format!(r"{shellex}\ContextMenuHandlers"), CLS_A);
        sz(
            &mut fx,
            &format!(r"{shellex}\ContextMenuHandlers\App"),
            CLS_A,
        );
    }
    sz(
        &mut fx,
        &format!(r"{CV}\Explorer\ShellIconOverlayIdentifiers"),
        CLS_A,
    );
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 4, "{found:#?}");
    for c in &found {
        assert!(
            spot(c).ends_with(r"\ContextMenuHandlers\App"),
            "{}",
            spot(c)
        );
        assert_eq!(c.action, Action::DeleteKey);
    }
}

#[test]
fn foreign_handler_untouched() {
    let mut fx = machine();
    dangling_class(&mut fx);
    class(
        &mut fx,
        HKLM_CLASSES,
        FOREIGN,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    );
    let key = handler_key(HKLM_CLASSES, "*", "ContextMenuHandlers", "Other");
    sz(&mut fx, &key, FOREIGN);
    sz(&mut fx, &star_menu(), CLS_A);
    let found = app_world(fx).ready(&[]).shellex();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(find(&found, &key).is_none());
}

/// Another installed app claims the class: COM-CLASS lists the class with a hard blocker, so the
/// class is not the app's to drop and no handler naming it is offered.
#[test]
fn class_claimed_by_other_app_not_offered() {
    let mut fx = machine();
    dangling_class(&mut fx);
    sz(&mut fx, &star_menu(), CLS_A);
    let mut world = app_world(fx);
    world.other_apps =
        purge_scan::framework::OtherApps::new(vec![purge_scan::framework::OtherApp {
            name: OTHER.into(),
            roots: vec![OTHER_ROOT.into()],
            anchors: vec![purge_model::AnchorRef {
                kind: purge_model::AnchorKind::Clsid,
                text: CLS_A.into(),
            }],
            ..Default::default()
        }]);
    let world = world.ready(&[]);
    let class = world.run(&purge_scan::com_class::ComClass);
    assert!(
        class
            .iter()
            .all(|c| c.blockers.iter().any(Blocker::is_hard)),
        "{class:#?}"
    );
    assert!(world.shellex().is_empty());
}
