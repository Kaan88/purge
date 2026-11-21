//! COM registrations and the two spellings of `HKLM\SOFTWARE\Classes` (M1a gate, r0-firefox-tb and
//! r0-vscode).
//!
//! Firefox and Thunderbird both ship `AccessibleMarshal.dll` and both register the same class,
//! `{1814CEEB-…}`. Whoever installs second rewrites `InProcServer32` to its own copy; the class key and
//! the `Interface\…\ProxyStubClsid32` values that name it are the first installer's. The harvest keeps
//! such a class out of the anchors (purge-harvest `anchors`, "modified, not owned"), and the scanners
//! then touch nothing of it.

use super::*;

const CLASS: &str = "{1814CEEB-49E2-407F-AF99-FA755A7D2607}";
const INTERFACES: [&str; 3] = [
    "{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}",
    "{1814CEEB-49E2-407F-AF99-FA755A7D2607}",
    "{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}",
];

fn server_key() -> String {
    format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLASS}\InProcServer32")
}

fn proxy_key(iid: &str) -> String {
    format!(r"HKLM\SOFTWARE\Classes\Interface\{iid}\ProxyStubClsid32")
}

/// What Firefox's uninstaller leaves of the class: the server value still names Firefox's DLL.
fn with_class(fixture: FixtureBuilder) -> FixtureBuilder {
    let mut fixture = fixture.sz(
        &server_key(),
        "",
        &format!(r"{FIREFOX}\AccessibleMarshal.dll"),
    );
    for iid in INTERFACES {
        fixture = fixture.sz(&proxy_key(iid), "", CLASS);
    }
    fixture
}

/// The snapshot rows the harvest writes for the class: the server value through the InstallRoot, and,
/// only when the class is an anchor, the interface values through the class id.
fn class_snapshot(fp: &mut purge_model::Fingerprint, owned: bool) {
    fp.ref_snapshot.push(snap(
        value(server_key(), ""),
        RefCarrier::Data,
        AnchorKind::Root,
        FIREFOX,
    ));
    if owned {
        fp.anchors.clsids = vec![CLASS.into()];
        for iid in INTERFACES {
            fp.ref_snapshot.push(snap(
                value(proxy_key(iid), ""),
                RefCarrier::Data,
                AnchorKind::Clsid,
                CLASS,
            ));
        }
    }
}

fn mentions_class(found: &[Candidate]) -> Vec<String> {
    found
        .iter()
        .map(|c| golden::target_text(&c.target))
        .filter(|t| {
            let t = t.to_ascii_uppercase();
            t.contains(CLASS) || t.contains(r"\INTERFACE\")
        })
        .collect()
}

/// Thunderbird installed first, Firefox second, Firefox removed. The class is not an anchor, so nothing
/// of it is offered by any scanner: not the interface values, and not the server value either, although
/// it points into Firefox's root and the snapshot lists it. Thunderbird repairs that value itself; a
/// deleted default value would leave its class without a server.
#[test]
fn a_class_the_app_only_modified_is_left_alone() {
    let mut fp = firefox();
    class_snapshot(&mut fp, false);
    let mut world = World::new(with_class(with_thunderbird(firefox_leftovers())), fp);
    world.other_apps = thunderbird();
    for scanner in all_scanners() {
        let found = world.scan(scanner);
        assert_eq!(mentions_class(&found), Vec::<String>::new());
    }
}

/// Firefox alone. The class is its own, so the dangling server value is offered with Tier A evidence.
/// The interface values are known only because their data is the class id: Tier B, so never Safe on
/// that (ENGINE_PLAN.md 1.4 lists the three ISimpleDOM interface keys as Likely).
#[test]
fn an_owned_class_makes_its_interface_values_likely_not_safe() {
    let mut fp = firefox();
    class_snapshot(&mut fp, true);
    let world = World::new(with_class(firefox_leftovers()), fp);
    let found = world.scan(&RefAny);

    let server = expect(&found, &value(server_key(), ""));
    assert!(tier_a_in_scope(server) && score(server) >= 8, "{server:?}");
    for iid in INTERFACES {
        let proxy = expect(&found, &value(proxy_key(iid), ""));
        assert_eq!(
            kinds(proxy),
            vec![EvidenceKind::InPreUninstallRefSnapshot],
            "{proxy:?}"
        );
        assert_eq!(proxy.evidence[0].tier, Tier::B);
        assert_eq!(proxy.evidence[0].detail.get("anchor_kind"), Some("id"));
        assert!(!tier_a_in_scope(proxy));
    }
}

/// The same for a ProgID (the `vscode` URL protocol of two VS Code installs): a value that the
/// snapshot knows through an id is Tier B, and Tier A only when the installer's own log names the
/// value.
#[test]
fn a_value_known_through_a_progid_needs_the_installers_record_to_be_tier_a() {
    let progid = format!("FirefoxHTML-{HASH}");
    let key_path = r"HKLM\SOFTWARE\Vendor\Handlers";
    let target = value(key_path, "html");
    let scan = |record: Option<purge_model::InnoRecord>| -> Candidate {
        let mut fp = firefox();
        fp.anchors.progids = vec![progid.clone()];
        fp.ref_snapshot.push(snap(
            target.clone(),
            RefCarrier::Data,
            AnchorKind::ProgId,
            &progid,
        ));
        fp.inno.extend(record);
        let world = World::new(firefox_leftovers().sz(key_path, "html", &progid), fp);
        expect(&world.scan(&RefAny), &target).clone()
    };
    let snapshot_tier = |c: &Candidate| {
        c.evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::InPreUninstallRefSnapshot)
            .expect("snapshot evidence")
            .tier
    };
    let alone = scan(None);
    assert_eq!(snapshot_tier(&alone), Tier::B);
    assert!(!tier_a_in_scope(&alone), "{alone:?}");
    // The log names the value, or deletes the whole key it created: Tier A.
    let by_value = scan(Some(inno(InnoRecordKind::RegDeleteValue, target.clone())));
    assert_eq!(snapshot_tier(&by_value), Tier::A);
    let by_key = scan(Some(inno(
        InnoRecordKind::RegDeleteEntireKey,
        key(key_path),
    )));
    assert_eq!(snapshot_tier(&by_key), Tier::A);
    // "Delete the key if it is empty" is what an installer says about a shared key it adds to: it
    // does not make the values in it the app's.
    let if_empty = scan(Some(inno(
        InnoRecordKind::RegDeleteKeyIfEmpty,
        key(key_path),
    )));
    assert_eq!(snapshot_tier(&if_empty), Tier::B);
    // A record of a value that was there before the install does not count either.
    let mut existed = inno(InnoRecordKind::RegDeleteValue, target.clone());
    existed.existed_before = true;
    assert_eq!(snapshot_tier(&scan(Some(existed))), Tier::B);

    // What the matcher cannot tell from a key path: a relative file path that begins with a root
    // word and has a folder named like the ProgID (`purge-index`, `matcher`, "The price"). The
    // snapshot knows the value through the id only, so it is listed and the policy never ticks it.
    let mut fp = firefox();
    fp.anchors.progids = vec![progid.clone()];
    let theirs = value(r"HKLM\SOFTWARE\Vendor\Recent", "Last");
    fp.ref_snapshot.push(snap(
        theirs.clone(),
        RefCarrier::Data,
        AnchorKind::ProgId,
        &progid,
    ));
    let world = World::new(
        firefox_leftovers().sz(
            r"HKLM\SOFTWARE\Vendor\Recent",
            "Last",
            &format!(r"Software\Tools\{progid}\Code.exe"),
        ),
        fp,
    );
    let found = world.scan(&RefAny);
    let relative = expect(&found, &theirs);
    assert!(!tier_a_in_scope(relative), "{relative:?}");
    let decision = purge_policy::band::decide(
        relative,
        &purge_policy::band::PolicyCtx {
            baseline_trust: purge_model::BaselineTrust::Exact,
            mode: purge_model::ScanMode::Post,
            verify_gone: purge_model::VerifyGone::new(true, true, true),
            target_scope: purge_policy::band::TargetScope::Machine,
        },
    );
    assert!(
        decision.band != purge_model::Band::Safe && !decision.preselected,
        "{decision:?}"
    );
}

/// `HKLM\SOFTWARE\WOW6432Node\Classes\.fx` is the key `HKLM\SOFTWARE\Classes\.fx` under a second
/// name (only CLSID, DirectShow, Interface, Media Type and MediaFoundation are separate per view). A
/// reader that follows the link sees every value twice; the plan lists it once, under the canonical
/// name.
#[test]
fn a_shared_classes_key_is_listed_once_under_its_canonical_name() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let command = format!(r#""{exe}" "%1""#);
    let canonical = r"HKLM\SOFTWARE\Classes\.fx\shell\open\command";
    let alias = r"HKLM\SOFTWARE\WOW6432Node\Classes\.fx\shell\open\command";
    let old_alias = r"HKLM\SOFTWARE\Classes\WOW6432Node\.fx\shell\open\command";
    let both = |lwt_alias: u64| {
        firefox_leftovers()
            .sz(canonical, "", &command)
            .key_lwt(canonical, 1_000_200_000_000)
            .sz(alias, "", &command)
            .key_lwt(alias, lwt_alias)
            .sz(old_alias, "", &command)
            .key_lwt(old_alias, lwt_alias)
    };
    let offered = |fixture: FixtureBuilder| -> Vec<String> {
        let world = World::new(fixture, firefox());
        world
            .scan(&RefAny)
            .iter()
            .map(|c| golden::target_text(&c.target))
            .filter(|t| t.contains(".fx"))
            .collect()
    };
    // The same key seen three times: one item.
    let once = offered(both(1_000_200_000_000));
    assert_eq!(once.len(), 1, "{once:?}");
    assert!(once[0].contains(canonical), "{once:?}");
    // Not the same last-write time: not shown to be one key, so nothing is folded.
    let apart = offered(both(1_000_300_000_000));
    assert_eq!(apart.len(), 3, "{apart:?}");

    // A redirected key is a different key in each view and is never folded.
    let clsid = r"HKLM\SOFTWARE\Classes\CLSID\{0A0A0A0A-0000-4000-8000-000000000001}\LocalServer32";
    let clsid32 = r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{0A0A0A0A-0000-4000-8000-000000000001}\LocalServer32";
    let mut fp = firefox();
    fp.anchors.clsids = vec!["{0A0A0A0A-0000-4000-8000-000000000001}".into()];
    let world = World::new(
        firefox_leftovers()
            .sz(clsid, "", &command)
            .key_lwt(clsid, 1_000_200_000_000)
            .sz(clsid32, "", &command)
            .key_lwt(clsid32, 1_000_200_000_000),
        fp,
    );
    let found = world.scan(&RefAny);
    assert!(find(&found, &value(clsid, "")).is_some());
    assert!(find(&found, &value(clsid32, "")).is_some());
}

/// Keys, not only values. The app's installer wrote `LocalServer32` into a class that is not its own;
/// the harvest recorded that subkey as fully attributed (all it held was the app's path), and the
/// vendor uninstaller then deleted the value. The empty subkey is still part of the other product's
/// class: it is not offered as an owned skeleton. The same subkey in a class the app owns is.
#[test]
fn an_emptied_subkey_of_a_class_that_is_not_the_apps_is_not_a_skeleton() {
    let server = format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLASS}\LocalServer32");
    let scan = |owned: bool| -> Vec<Candidate> {
        let mut fp = firefox();
        if owned {
            fp.anchors.clsids = vec![CLASS.into()];
        }
        fp.subtrees = vec![subtree(&server, &[("", "")], &[])];
        let fixture = firefox_leftovers()
            .sz(
                &format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLASS}"),
                "",
                "PSFactoryBuffer",
            )
            .key(&server)
            .ti_owned(&server, false);
        World::new(fixture, fp).scan(&RefAny)
    };
    assert_eq!(mentions_class(&scan(false)), Vec::<String>::new());
    let own = scan(true);
    let skeleton = expect(&own, &key(server.clone()));
    assert_eq!(kinds(skeleton), vec![EvidenceKind::ProvenOwnedSkeleton]);
}

/// Type libraries and AppIDs follow the same rule as classes: a path value under `TypeLib\{id}` or
/// `AppID\{id}` is offered only when the harvest took the registration for the app's own. One the app
/// merely re-pointed (older than the install, so not an anchor) is left alone, value and key.
#[test]
fn values_in_a_type_library_or_appid_that_is_not_the_apps_are_not_offered() {
    const TLB: &str = "{DDDDDDDD-2222-3333-4444-555555555555}";
    const APPID: &str = "{EEEEEEEE-2222-3333-4444-555555555555}";
    let win64 = format!(r"HKLM\SOFTWARE\Classes\TypeLib\{TLB}\1.0\0\win64");
    let helpdir = format!(r"HKLM\SOFTWARE\Classes\TypeLib\{TLB}\1.0\HELPDIR");
    let appid = format!(r"HKLM\SOFTWARE\Classes\AppID\{APPID}");
    let scan = |owned: bool| -> Vec<Candidate> {
        let mut fp = firefox();
        if owned {
            fp.anchors.typelibs = vec![TLB.to_lowercase()];
            fp.anchors.appids = vec![APPID.into()];
        }
        for (key_path, name) in [(&win64, ""), (&helpdir, ""), (&appid, "DllSurrogate")] {
            fp.ref_snapshot.push(snap(
                value(key_path.clone(), name),
                RefCarrier::Data,
                AnchorKind::Root,
                FIREFOX,
            ));
        }
        let fixture = firefox_leftovers()
            .sz(&win64, "", &format!(r"{FIREFOX}\firefox.tlb"))
            .sz(&helpdir, "", FIREFOX)
            .sz(&appid, "DllSurrogate", &format!(r"{FIREFOX}\surrogate.exe"));
        World::new(fixture, fp).scan(&RefAny)
    };
    let targets = |found: &[Candidate]| -> Vec<String> {
        found
            .iter()
            .map(|c| golden::target_text(&c.target))
            .filter(|t| t.contains(TLB) || t.contains(APPID))
            .collect()
    };
    assert_eq!(targets(&scan(false)), Vec::<String>::new());
    let own = scan(true);
    assert_eq!(targets(&own).len(), 3, "{}", golden::render(&own));
}
