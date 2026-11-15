//! Tests of the association scanners CLS-ASSOC, CLS-FILEEXTS and CLS-TOASTS and of the §5.7.1 handler
//! behind them, over fixtures shaped like a machine-wide VS Code after its uninstaller ran.
//!
//! Each scanner has a golden file under `tests/assoc/golden` (see [`golden`]); the assertions next to it
//! spell out the properties the design depends on.

mod golden;
mod vscode_run;
mod world;

use purge_guard::deny::{self, Exemptions};
use purge_index::queries;
use purge_model::{
    Action, AnchorKind, AnchorRef, Blocker, Candidate, EvidenceKind, Harm, Scope, Target, Tier,
    VendorBackup,
};
use purge_scan::cls_assoc::ClsAssoc;
use purge_scan::cls_fileexts::ClsFileExts;
use purge_scan::cls_toasts::{ClsToasts, split_toast_name};
use purge_scan::framework::{OtherApp, OtherApps, candidate_id};
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use world::{
    BUILD, EDITION, SID, UBR, World, baseline, classes, file_exts, fingerprint, journal, ref_snap,
    user_toasts,
};

const GROUP: &str = "File associations";

/// The candidates that belong to `ext` (every candidate says so in its evidence details).
fn of_ext<'a>(candidates: &'a [Candidate], ext: &str) -> Vec<&'a Candidate> {
    candidates
        .iter()
        .filter(|c| c.evidence.iter().any(|e| e.detail.get("ext") == Some(ext)))
        .collect()
}

fn key(path: String) -> Target {
    Target::RegKey { path }
}

fn value(path: String, name: &str) -> Target {
    Target::RegValue {
        path,
        name: name.into(),
    }
}

fn kinds(c: &Candidate) -> Vec<EvidenceKind> {
    c.evidence.iter().map(|e| e.kind).collect()
}

fn fact<'a>(c: &'a Candidate, name: &str) -> Option<&'a str> {
    c.evidence.iter().find_map(|e| e.detail.get(name))
}

/// Every piece of evidence of every candidate names the UI group.
fn assert_grouped(candidates: &[Candidate]) {
    for c in candidates {
        assert!(!c.evidence.is_empty(), "{:?}", c.target);
        for e in &c.evidence {
            assert_eq!(e.detail.get("group"), Some(GROUP), "{:?}", c.target);
        }
    }
}

/// Whether the policy itself (`purge_policy::band::decide`) lists the candidate Safe and ticked after
/// an uninstall that verified gone: the real rule, with its tiers, score, category, harm and
/// reversibility checks, not an approximation of it.
fn safe_eligible(c: &Candidate) -> bool {
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let hive = match &c.target {
        Target::RegKey { path } | Target::RegValue { path, .. } => path.as_str(),
        _ => "",
    };
    let per_user = hive
        .get(..4)
        .is_some_and(|root| root.eq_ignore_ascii_case(r"HKU\"));
    let decision = decide(
        c,
        &PolicyCtx {
            mode: purge_model::ScanMode::Post,
            verify_gone: purge_model::VerifyGone::new(true, true, true),
            target_scope: if per_user {
                TargetScope::PerUser
            } else {
                TargetScope::Machine
            },
        },
    );
    decision.band == purge_model::Band::Safe && decision.preselected
}

// ---------------------------------------------------------------------------------------------------------
// CLS-ASSOC: the VS Code shape
// ---------------------------------------------------------------------------------------------------------

const PROGIDS: &[&str] = &[
    "VSCode.vsnew",
    "VSCode.xaml",
    "VSCode.txt",
    "VSCode.md",
    "VSCodeSourceFile",
];

/// After the uninstall (Inno `uninsdeletevalue` without `…ifempty`):
///
/// - `.vsnew` is new to the machine: the key and its empty `OpenWithProgids` are left;
/// - `.xaml` is Windows' own, its `OpenWithProgids` was created by the app and is left empty;
/// - `.txt` and its `OpenWithProgids` are Windows' own; the app's value is still there;
/// - `.md` came with the app, but another app has registered there too; the app's value is still there.
fn vscode_world() -> World {
    let fixture = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .key(&classes(".vsnew"))
        .key(&classes(r".vsnew\OpenWithProgids"))
        .ti_owned(&classes(".vsnew"), false)
        .ti_owned(&classes(r".vsnew\OpenWithProgids"), false)
        .sz(&classes(".xaml"), "", "Windows.XamlDocument")
        .key(&classes(r".xaml\OpenWithProgids"))
        .sz(&classes(".txt"), "", "txtfile")
        .sz(&classes(".txt"), "Content Type", "text/plain")
        .sz(&classes(r".txt\OpenWithProgids"), "VSCode.txt", "")
        .key(&classes(".md"))
        .sz(&classes(r".md\OpenWithProgids"), "VSCode.md", "")
        .sz(&classes(r".md\OpenWithProgids"), "Typora.md", "")
        .build();

    let mut fp = fingerprint(PROGIDS);
    let mut xaml = journal(".xaml", &["VSCode.xaml"]);
    xaml.default = Some("Windows.XamlDocument".into());
    let mut txt = journal(".txt", &["VSCode.txt"]);
    txt.default = Some("txtfile".into());
    txt.other_values = vec!["Content Type".into()];
    let mut md = journal(".md", &["VSCode.md"]);
    md.openwith_others = vec!["Typora.md".into()];
    fp.ext_journal = vec![journal(".vsnew", &["VSCode.vsnew"]), xaml, txt, md];
    // The harvest's reference scan saw the `.txt` value; the `.md` value is known from the journal only.
    fp.ref_snapshot = vec![ref_snap(
        &classes(r".txt\OpenWithProgids"),
        "VSCode.txt",
        "VSCode.txt",
    )];

    let mut world = World::new(fixture, fp);
    world.baseline = Some(baseline(
        EDITION,
        &[
            &classes(".xaml"),
            &classes(".txt"),
            &classes(r".txt\OpenWithProgids"),
        ],
        &[],
    ));
    world
}

/// Rig run x1-vscode-userstate: the user made empty `.gemspec\OpenWithProgids` and
/// `.edn\OpenWithProgids` keys before the install; the journal saw nothing in them but the app's
/// value, and after the uninstall both keys of each pair were preselected as skeletons (through
/// REF-ANY first, and through this scanner once that was closed). The harvest names the keys that
/// are older than the install; none of them is a skeleton.
#[test]
fn an_extension_key_older_than_the_install_is_not_a_skeleton() {
    let proven = |out: &[Candidate], ext: &str| -> Vec<Target> {
        of_ext(out, ext)
            .into_iter()
            .filter(|c| kinds(c).contains(&EvidenceKind::ProvenOwnedSkeleton) || safe_eligible(c))
            .map(|c| c.target.clone())
            .collect()
    };
    let mut world = vscode_world();
    let out = world.scan(&ClsAssoc);
    assert_eq!(proven(&out, ".vsnew"), [key(classes(".vsnew"))]);
    assert_eq!(
        proven(&out, ".xaml"),
        [key(classes(r".xaml\OpenWithProgids"))]
    );

    // As the harvest records a planted pair: the extension key and, by its parent, the subkey.
    world.fp.older_keys = vec![
        classes(".vsnew"),
        classes(r".vsnew\OpenWithProgids"),
        classes(r".xaml\OpenWithProgids"),
    ];
    let out = world.scan(&ClsAssoc);
    assert_eq!(proven(&out, ".vsnew"), []);
    assert_eq!(proven(&out, ".xaml"), []);
    for c in &out {
        if let Target::RegKey { path } = &c.target {
            assert!(
                !path.contains(".vsnew") && !path.ends_with(r".xaml\OpenWithProgids"),
                "offered: {path}"
            );
        }
    }

    // The extension key alone is named (a fingerprint that lost the subkey's entry): the key is
    // still no skeleton, whatever is said about `OpenWithProgids`.
    world.fp.older_keys = vec![classes(".vsnew")];
    let out = world.scan(&ClsAssoc);
    assert!(
        !proven(&out, ".vsnew").contains(&key(classes(".vsnew"))),
        "{:?}",
        proven(&out, ".vsnew")
    );
}

#[test]
fn vscode_system_with_matching_baseline() {
    let world = vscode_world();
    let out = world.scan(&ClsAssoc);
    golden::check("cls_assoc_vscode_baseline", &out);
    assert_grouped(&out);

    // New to the machine: the `.ext` key is one Safe-eligible key candidate that takes OpenWithProgids.
    let vsnew = of_ext(&out, ".vsnew");
    assert_eq!(vsnew.len(), 1);
    let c = vsnew[0];
    assert_eq!(c.target, key(classes(".vsnew")));
    assert_eq!(
        (c.action, c.scanner.as_str()),
        (Action::DeleteKey, "CLS-ASSOC")
    );
    assert_eq!(kinds(c), [EvidenceKind::ProvenOwnedSkeleton]);
    let e = &c.evidence[0];
    assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Scope::Key));
    assert_eq!(e.detail.get("baseline"), Some("EnterpriseSEval-26100.1742"));
    assert_eq!(
        c.children,
        [candidate_id(&key(classes(r".vsnew\OpenWithProgids")))]
    );
    assert!(safe_eligible(c));

    // Windows' own extension whose OpenWithProgids the app created: that key only.
    let xaml = of_ext(&out, ".xaml");
    assert_eq!(xaml.len(), 1);
    assert_eq!(xaml[0].target, key(classes(r".xaml\OpenWithProgids")));
    assert_eq!(kinds(xaml[0]), [EvidenceKind::ProvenOwnedSkeleton]);
    assert!(xaml[0].children.is_empty());
    assert!(safe_eligible(xaml[0]));

    // Present in the baseline: only the value is offered.
    let txt = of_ext(&out, ".txt");
    assert_eq!(txt.len(), 1);
    assert_eq!(
        txt[0].target,
        value(classes(r".txt\OpenWithProgids"), "VSCode.txt")
    );
    assert_eq!(txt[0].action, Action::DeleteValue);
    assert_eq!(
        kinds(txt[0]),
        [
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::ChainedRef
        ]
    );
    assert!(txt[0].evidence[0].source.0.starts_with("refsnap:"));
    assert!(safe_eligible(txt[0]));

    // Another app has a value too: only ours is offered, and no key.
    let md = of_ext(&out, ".md");
    assert_eq!(md.len(), 1);
    assert_eq!(
        md[0].target,
        value(classes(r".md\OpenWithProgids"), "VSCode.md")
    );
    assert!(md[0].evidence[0].source.0.starts_with("extjournal:"));
    assert!(safe_eligible(md[0]));

    assert_eq!(out.len(), 4);
    assert!(out.iter().all(|c| c.blockers.is_empty()));
}

#[test]
fn vscode_system_without_baseline() {
    for mismatched in [false, true] {
        let mut world = vscode_world();
        // No baseline at all, or one of another edition: both mean "no matching baseline".
        world.baseline = mismatched.then(|| baseline("Professional", &[], &[]));
        let out = world.scan(&ClsAssoc);
        if !mismatched {
            golden::check("cls_assoc_vscode_no_baseline", &out);
        }
        assert_grouped(&out);

        // Nothing is proven.
        assert!(
            out.iter()
                .flat_map(|c| &c.evidence)
                .all(|e| e.kind != EvidenceKind::ProvenOwnedSkeleton)
        );
        // The skeleton keys go out under X-SYSTIDY with band-neutral evidence: Tier B, so never Safe.
        let keys: Vec<&Candidate> = out
            .iter()
            .filter(|c| matches!(c.target, Target::RegKey { .. }))
            .collect();
        let targets: Vec<&Target> = keys.iter().map(|c| &c.target).collect();
        assert_eq!(
            targets,
            [
                &key(classes(".vsnew")),
                &key(classes(r".xaml\OpenWithProgids"))
            ]
        );
        for c in keys {
            assert_eq!(c.scanner, "X-SYSTIDY");
            assert_eq!(kinds(c), [EvidenceKind::ChainedRef]);
            assert_eq!((c.evidence[0].tier, c.evidence[0].weight), (Tier::B, 5));
            assert_eq!(fact(c, "skeleton"), Some("no-baseline"));
            assert!(!safe_eligible(c));
        }
        // The values are offered as before.
        let values: Vec<&Candidate> = out
            .iter()
            .filter(|c| matches!(c.target, Target::RegValue { .. }))
            .collect();
        assert_eq!(values.len(), 2);
        assert!(
            values
                .iter()
                .all(|c| c.scanner == "CLS-ASSOC" && safe_eligible(c))
        );
    }
}

#[test]
fn skeleton_needs_an_empty_key_and_a_clean_journal() {
    // A value appeared after the harvest: OpenWithProgids is not empty, nothing key-level is offered.
    let mut world = vscode_world();
    world.fixture.set_value(
        &classes(r".vsnew\OpenWithProgids"),
        "Other.vsnew",
        RegData::from_sz(""),
    );
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());

    // The `.ext` key got a value of its own: only OpenWithProgids is still a skeleton.
    let mut world = vscode_world();
    world
        .fixture
        .set_value(&classes(".vsnew"), "", RegData::from_sz("somefile"));
    let out = world.scan(&ClsAssoc);
    let vsnew = of_ext(&out, ".vsnew");
    assert_eq!(vsnew.len(), 1);
    assert_eq!(vsnew[0].target, key(classes(r".vsnew\OpenWithProgids")));

    // A subkey the journal does not know: same.
    let mut world = vscode_world();
    world.fixture.add_key(&classes(r".vsnew\ShellNew"));
    let out = world.scan(&ClsAssoc);
    assert_eq!(
        of_ext(&out, ".vsnew")[0].target,
        key(classes(r".vsnew\OpenWithProgids"))
    );

    // The journal saw other content in the `.ext` key at harvest: the key was not the app's alone.
    let mut world = vscode_world();
    world.fp.ext_journal[0].other_subkeys = vec!["PersistentHandler".into()];
    let out = world.scan(&ClsAssoc);
    assert_eq!(
        of_ext(&out, ".vsnew")[0].target,
        key(classes(r".vsnew\OpenWithProgids"))
    );

    // The journal lists a value name that is not in P: nothing is proven about the keys.
    let mut world = vscode_world();
    world.fp.ext_journal[0].openwith_ours = vec!["Foreign.vsnew".into()];
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());

    // The key is gone altogether: nothing to offer.
    let mut world = vscode_world();
    world.fixture.remove_key(&classes(".vsnew"));
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());

    // An entry whose key is not `<Classes>\<.ext>` is ignored.
    let mut world = vscode_world();
    world.fp.ext_journal[0].key = r"HKLM\SOFTWARE\Vendor\.vsnew".into();
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());
}

#[test]
fn trusted_installer_keys_are_never_deleted() {
    // Owned by TrustedInstaller now.
    let mut now = vscode_world();
    now.fixture.set_ti_owned(&classes(".vsnew"), true);
    // Owned by TrustedInstaller at harvest; the source cannot tell any more.
    let mut then = vscode_world();
    then.fp.ext_journal[0].ti_owned = true;
    // The OpenWithProgids child is.
    let mut child = vscode_world();
    child
        .fixture
        .set_ti_owned(&classes(r".vsnew\OpenWithProgids"), true);

    for (name, world) in [("now", now), ("then", then), ("child", child)] {
        let out = world.scan(&ClsAssoc);
        if name == "now" {
            golden::check("cls_assoc_ti_owned", &out);
        }
        let vsnew = of_ext(&out, ".vsnew");
        assert_eq!(vsnew.len(), 1, "{name}");
        let c = vsnew[0];
        assert_eq!(c.target, key(classes(".vsnew")), "{name}");
        assert!(
            c.blockers.contains(&Blocker::TrustedInstallerOwned),
            "{name}"
        );
        assert!(c.has_hard_blocker(), "{name}");
        assert!(
            !kinds(c).contains(&EvidenceKind::ProvenOwnedSkeleton),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// CLS-ASSOC: the default of an extension
// ---------------------------------------------------------------------------------------------------------

/// `.foo`, `.bar`, `.baz` and `.qux` all still have the app's ProgID as their default.
///
/// - `.foo`: the vendor left a backup value;
/// - `.bar`: Windows ships a default for it, and the journal knows the previous default;
/// - `.baz`: Windows ships a default for it, but nothing recorded what it was;
/// - `.qux`: neither.
fn defaults_world() -> World {
    let progids = ["VSCode.foo", "VSCode.bar", "VSCode.baz", "VSCode.qux"];
    let mut builder = Fixture::builder().os(EDITION, BUILD, UBR).user_sid(SID);
    for ext in ["foo", "bar", "baz", "qux"] {
        builder = builder
            .sz(&classes(&format!(".{ext}")), "", &format!("VSCode.{ext}"))
            .key(&classes(&format!(r".{ext}\OpenWithProgids")));
    }
    let fixture = builder
        .sz(&classes(".foo"), "VSCode_backup", "foofile")
        .build();

    let mut fp = fingerprint(&progids);
    let entry = |ext: &str| {
        let mut j = journal(&format!(".{ext}"), &[&format!("VSCode.{ext}")]);
        j.default = Some(format!("VSCode.{ext}"));
        j
    };
    let mut backed = entry("foo");
    backed.vendor_backup = Some(VendorBackup {
        name: "VSCode_backup".into(),
        data: "foofile".into(),
    });
    backed.previous_default = Some("foofile".into());
    let mut bar = entry("bar");
    bar.previous_default = Some("barfile".into());
    fp.ext_journal = vec![backed, bar, entry("baz"), entry("qux")];
    fp.ref_snapshot = vec![ref_snap(&classes(".bar"), "", "VSCode.bar")];

    let hash = |s: &str| queries::data_hash(&RegData::from_sz(s)).expect("complete data");
    let mut world = World::new(fixture, fp);
    world.baseline = Some(baseline(
        EDITION,
        &[
            &classes(".bar"),
            &classes(r".bar\OpenWithProgids"),
            &classes(".baz"),
            &classes(r".baz\OpenWithProgids"),
        ],
        &[
            (&classes(".bar"), "", 1, hash("barfile")),
            (&classes(".baz"), "", 1, hash("bazfile")),
        ],
    ));
    world
}

#[test]
fn default_naming_a_removed_progid_is_restored_or_reported() {
    let world = defaults_world();
    let out = world.scan(&ClsAssoc);
    golden::check("cls_assoc_defaults", &out);
    assert_grouped(&out);

    let default_of = |ext: &str| -> &Candidate {
        let target = value(classes(ext), "");
        out.iter()
            .find(|c| c.target == target)
            .unwrap_or_else(|| panic!("no default candidate for {ext}"))
    };

    // With the vendor's backup.
    let backed = default_of(".foo");
    assert_eq!(
        (backed.action, backed.harm),
        (Action::DeleteValue, Harm::Medium)
    );
    assert_eq!(fact(backed, "action"), Some("restore"));
    assert_eq!(fact(backed, "restore_from"), Some("vendor_backup"));
    assert_eq!(fact(backed, "backup_value"), Some("VSCode_backup"));
    assert_eq!(fact(backed, "restore_to"), Some("foofile"));
    assert_eq!(kinds(backed), [EvidenceKind::ChainedRef]);
    assert_eq!(backed.evidence[0].scope, Scope::Value);

    // With the baseline value, whose data the journal's previous default confirms.
    let bar = default_of(".bar");
    assert_eq!((bar.action, bar.harm), (Action::DeleteValue, Harm::Medium));
    assert_eq!(fact(bar, "action"), Some("restore"));
    assert_eq!(fact(bar, "restore_from"), Some("baseline"));
    assert_eq!(fact(bar, "restore_to"), Some("barfile"));
    assert_eq!(fact(bar, "baseline"), Some("EnterpriseSEval-26100.1742"));
    // The value is in the baseline by name, and a restore is exactly what that calls for.
    assert!(bar.blockers.is_empty());
    // Even with snapshot evidence a restore is never Safe-eligible: its harm is Medium.
    assert!(kinds(bar).contains(&EvidenceKind::InPreUninstallRefSnapshot));
    assert!(!safe_eligible(bar));

    // With the baseline value, data unknown: the hash is all there is.
    let hashed = default_of(".baz");
    assert_eq!(fact(hashed, "restore_from"), Some("baseline"));
    assert_eq!(fact(hashed, "restore_to"), None);
    assert_eq!(fact(hashed, "restore_hash").map(str::len), Some(16));

    // With neither: report-only.
    let qux = default_of(".qux");
    assert_eq!(qux.action, Action::ReportOnly);
    assert_eq!(fact(qux, "action"), Some("report"));
    assert_eq!(
        fact(qux, "note"),
        Some(".qux has no default app; choose one in Settings")
    );
    assert!(!safe_eligible(qux));

    // An `.ext` key that still has its default is no skeleton; its OpenWithProgids is, where Windows
    // does not ship it.
    let keys: Vec<&Target> = out
        .iter()
        .filter(|c| matches!(c.target, Target::RegKey { .. }))
        .map(|c| &c.target)
        .collect();
    assert_eq!(
        keys,
        [
            &key(classes(r".foo\OpenWithProgids")),
            &key(classes(r".qux\OpenWithProgids"))
        ]
    );
}

#[test]
fn default_of_another_app_is_left_alone() {
    let mut world = defaults_world();
    world
        .fixture
        .set_value(&classes(".qux"), "", RegData::from_sz("Typora.qux"));
    let out = world.scan(&ClsAssoc);
    assert!(!out.iter().any(|c| c.target == value(classes(".qux"), "")));
}

#[test]
fn default_in_a_trusted_installer_key_is_blocked() {
    let mut world = defaults_world();
    world.fixture.set_ti_owned(&classes(".foo"), true);
    let out = world.scan(&ClsAssoc);
    let backed = out
        .iter()
        .find(|c| c.target == value(classes(".foo"), ""))
        .expect("the default is still listed");
    assert!(backed.blockers.contains(&Blocker::TrustedInstallerOwned));
}

// ---------------------------------------------------------------------------------------------------------
// CLS-ASSOC: exe-named keys and SystemFileAssociations
// ---------------------------------------------------------------------------------------------------------

fn exe_keys_world() -> World {
    let sfa = classes(r"SystemFileAssociations\.md");
    let fixture = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .sz(&classes(".md"), "", "mdfile")
        .key(&classes(r".md\OpenWithList\Code.exe"))
        .key(&classes(r".md\OpenWithList\notepad.exe"))
        .key(&format!(r"{sfa}\OpenWithList\code.exe"))
        .sz(
            &format!(r"{sfa}\shell\VSCodeOpen\command"),
            "",
            r#""C:\Program Files\Microsoft VS Code\Code.exe" "%1""#,
        )
        .sz(
            &format!(r"{sfa}\shell\ByName\command"),
            "",
            r#"Code.exe "%1""#,
        )
        .sz(
            &format!(r"{sfa}\shell\Other\command"),
            "",
            r#""C:\Program Files\Typora\Typora.exe" "%1""#,
        )
        .build();
    let mut fp = fingerprint(&["VSCode.md"]);
    let mut md = journal(".md", &["VSCode.md"]);
    md.default = Some("mdfile".into());
    md.subkey_count = 2;
    md.other_subkeys = vec!["OpenWithList".into()];
    fp.ext_journal = vec![md];
    World::new(fixture, fp)
}

#[test]
fn exe_named_keys_and_verbs_are_offered_unticked() {
    let world = exe_keys_world();
    let out = world.scan(&ClsAssoc);
    golden::check("cls_assoc_exe_keys", &out);
    assert_grouped(&out);

    let sfa = classes(r"SystemFileAssociations\.md");
    let targets: Vec<&Target> = out.iter().map(|c| &c.target).collect();
    assert_eq!(
        targets,
        [
            &key(classes(r".md\OpenWithList\Code.exe")),
            &key(format!(r"{sfa}\OpenWithList\code.exe")),
            &key(format!(r"{sfa}\shell\VSCodeOpen")),
        ]
    );
    for c in &out {
        assert_eq!(c.action, Action::DeleteKey);
        assert_eq!(kinds(c), [EvidenceKind::ChainedRef]);
        assert_eq!(c.evidence[0].scope, Scope::Key);
        // ChainedRef alone weighs 5: listed, never Safe.
        assert!(!safe_eligible(c));
    }
    // A bare exe name is a Tier B anchor; a full path into the root is Tier A.
    assert_eq!(out[0].evidence[0].tier, Tier::B);
    assert_eq!(out[2].evidence[0].tier, Tier::A);
}

#[test]
fn exe_name_of_another_app_is_not_ours() {
    let mut world = exe_keys_world();
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "VS Code Insiders".into(),
        anchors: vec![AnchorRef {
            kind: AnchorKind::Exe,
            text: "code.exe".into(),
        }],
        ..OtherApp::default()
    }]);
    let out = world.scan(&ClsAssoc);
    let sfa = classes(r"SystemFileAssociations\.md");
    let targets: Vec<&Target> = out.iter().map(|c| &c.target).collect();
    assert_eq!(targets, [&key(format!(r"{sfa}\shell\VSCodeOpen"))]);
}

#[test]
fn progid_claimed_by_another_app_blocks_its_values() {
    let mut world = vscode_world();
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "VS Code Insiders".into(),
        anchors: vec![AnchorRef {
            kind: AnchorKind::ProgId,
            text: "vscode.txt".into(),
        }],
        ..OtherApp::default()
    }]);
    let out = world.scan(&ClsAssoc);
    let txt = of_ext(&out, ".txt");
    assert_eq!(txt.len(), 1);
    assert_eq!(
        txt[0].blockers,
        [Blocker::ReferencedByOtherApp {
            app: "VS Code Insiders".into()
        }]
    );
}

// ---------------------------------------------------------------------------------------------------------
// CLS-FILEEXTS
// ---------------------------------------------------------------------------------------------------------

fn file_exts_world() -> World {
    let md = file_exts(".md");
    let txt = file_exts(".txt");
    let fixture = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .sz(&format!(r"{md}\OpenWithProgids"), "VSCode.md", "")
        .sz(&format!(r"{md}\OpenWithProgids"), "Typora.md", "")
        .sz(&format!(r"{md}\OpenWithList"), "a", "Code.exe")
        .sz(&format!(r"{md}\OpenWithList"), "b", "notepad.exe")
        .sz(&format!(r"{md}\OpenWithList"), "MRUList", "ba")
        .sz(&format!(r"{md}\UserChoice"), "ProgId", "VSCode.md")
        .sz(&format!(r"{md}\UserChoice"), "Hash", "abcdefgh")
        // `.txt`: the journal did not record the key; it is found through the user's SID.
        .sz(&format!(r"{txt}\OpenWithProgids"), "VSCode.txt", "")
        .sz(&format!(r"{txt}\UserChoice"), "ProgId", "txtfile")
        .build();
    let mut fp = fingerprint(&["VSCode.md", "VSCode.txt"]);
    let mut journal_md = journal(".md", &["VSCode.md"]);
    journal_md.file_exts_key = Some(md.clone());
    fp.ext_journal = vec![journal_md, journal(".txt", &["VSCode.txt"])];
    fp.ref_snapshot = vec![ref_snap(
        &format!(r"{md}\OpenWithProgids"),
        "VSCode.md",
        "VSCode.md",
    )];
    World::new(fixture, fp)
}

#[test]
fn file_exts_values_are_offered_at_value_level() {
    let world = file_exts_world();
    let out = world.scan(&ClsFileExts);
    golden::check("cls_fileexts", &out);
    assert_grouped(&out);
    assert!(out.iter().all(|c| c.scanner == "CLS-FILEEXTS"));
    // Never a key.
    assert!(
        out.iter()
            .all(|c| !matches!(c.target, Target::RegKey { .. }))
    );

    let md = file_exts(".md");
    let find = |target: Target| -> &Candidate {
        out.iter()
            .find(|c| c.target == target)
            .unwrap_or_else(|| panic!("missing {target:?}"))
    };

    // The harvested OpenWithProgids value.
    let progid = find(value(format!(r"{md}\OpenWithProgids"), "VSCode.md"));
    assert_eq!(
        kinds(progid),
        [
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::ChainedRef
        ]
    );
    assert!(safe_eligible(progid));
    // The other app's value is not listed.
    assert!(!out.iter().any(|c| matches!(
        &c.target, Target::RegValue { name, .. } if name == "Typora.md" || name == "b"
    )));

    // The OpenWithList entry naming our exe, and its letter in MRUList.
    let entry = find(value(format!(r"{md}\OpenWithList"), "a"));
    assert_eq!(entry.action, Action::DeleteValue);
    assert_eq!(entry.evidence[0].tier, Tier::B);
    assert!(!safe_eligible(entry));
    let mru = find(Target::RegMultiSzSegment {
        path: format!(r"{md}\OpenWithList"),
        name: "MRUList".into(),
        segment: "a".into(),
        index: Some(1),
    });
    assert_eq!(mru.action, Action::EditSegment);

    // UserChoice: report-only, and the deny-list refuses the target whatever the scanner says.
    let choice = find(value(format!(r"{md}\UserChoice"), "ProgId"));
    assert_eq!(choice.action, Action::ReportOnly);
    assert_eq!(fact(choice, "action"), Some("report"));
    assert!(matches!(
        deny::check(&choice.target, &world.guard, &Exemptions::default()),
        Some(Blocker::DenyListed { rule }) if rule == "reg.userchoice"
    ));

    // `.txt`: found without a journalled key; ChainedRef only, so offered but not Safe-eligible. Its
    // UserChoice names Windows' own ProgID and is not listed.
    let txt = of_ext(&out, ".txt");
    assert_eq!(txt.len(), 1);
    assert_eq!(
        txt[0].target,
        value(
            format!(r"{}\OpenWithProgids", file_exts(".txt")),
            "VSCode.txt"
        )
    );
    assert_eq!(kinds(txt[0]), [EvidenceKind::ChainedRef]);
    assert!(!safe_eligible(txt[0]));

    assert_eq!(out.len(), 5);
}

/// x2-npp-userfiles: the user registered a portable copy of the program (`Classes\Applications\<exe>`
/// with its own command) and picked it for an extension. The `OpenWithList` entry carries the bare exe
/// name of the removed install, and is the portable copy's.
#[test]
fn file_exts_entry_of_a_portable_copy_is_not_offered() {
    let md = file_exts(".md");
    let app_key = format!(r"HKU\{SID}_Classes\Applications\Code.exe");
    let world = |command: Option<&str>| {
        let mut b = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .sz(&format!(r"{md}\OpenWithList"), "a", "Code.exe")
            .sz(&format!(r"{md}\OpenWithList"), "MRUList", "a");
        if let Some(command) = command {
            b = b.sz(&app_key, "FriendlyAppName", "Code").sz(
                &format!(r"{app_key}\shell\open\command"),
                "",
                command,
            );
        }
        let mut fp = fingerprint(&["VSCode.md"]);
        let mut entry = journal(".md", &["VSCode.md"]);
        entry.file_exts_key = Some(md.clone());
        fp.ext_journal = vec![entry];
        World::new(b.build(), fp)
    };
    let listed = |command: Option<&str>| world(command).scan(&ClsFileExts).len();
    // No such key, or one that leads into the removed install: the entry and its letter are offered.
    assert_eq!(listed(None), 2);
    let own = format!(r#""{}\Code.exe" "%1""#, world::CODE_ROOT);
    assert_eq!(listed(Some(&own)), 2);
    // The key of the portable copy: nothing.
    assert_eq!(
        listed(Some(r#""C:\Users\tester\Tools\VSCode\Code.exe" "%1""#)),
        0
    );
}

/// The same with a key in each hive: the machine's key leading into the removed install does not
/// answer for the user's key of a portable copy, nor the other way round. Whichever hive is asked
/// first, a key that leads elsewhere means the bare name is not the app's alone.
#[test]
fn file_exts_entry_is_not_offered_when_either_hives_key_leads_elsewhere() {
    let md = file_exts(".md");
    let user_key = format!(r"HKU\{SID}_Classes\Applications\Code.exe");
    let machine_key = r"HKLM\SOFTWARE\Classes\Applications\Code.exe";
    let own = format!(r#""{}\Code.exe" "%1""#, world::CODE_ROOT);
    let portable = r#""C:\Users\tester\Tools\VSCode\Code.exe" "%1""#;
    let listed = |machine: Option<&str>, user: Option<&str>| {
        let mut b = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .sz(&format!(r"{md}\OpenWithList"), "a", "Code.exe")
            .sz(&format!(r"{md}\OpenWithList"), "MRUList", "a");
        if let Some(command) = machine {
            b = b.sz(&format!(r"{machine_key}\shell\open\command"), "", command);
        }
        if let Some(command) = user {
            b = b.sz(&format!(r"{user_key}\shell\open\command"), "", command);
        }
        let mut fp = fingerprint(&["VSCode.md"]);
        let mut entry = journal(".md", &["VSCode.md"]);
        entry.file_exts_key = Some(md.clone());
        fp.ext_journal = vec![entry];
        World::new(b.build(), fp).scan(&ClsFileExts).len()
    };
    assert_eq!(listed(Some(&own), None), 2);
    assert_eq!(listed(Some(&own), Some(&own)), 2);
    assert_eq!(listed(Some(&own), Some(portable)), 0);
    assert_eq!(listed(Some(portable), Some(&own)), 0);
    assert_eq!(listed(Some(portable), None), 0);

    // A key that cannot be read in full (a link below it) may lead anywhere.
    let unread = |machine: Option<&str>| {
        let mut b = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .sz(&format!(r"{md}\OpenWithList"), "a", "Code.exe")
            .sz(&format!(r"{md}\OpenWithList"), "MRUList", "a")
            .sz(&user_key, "FriendlyAppName", "Code")
            .link(&format!(r"{user_key}\shell"), r"HKLM\SOFTWARE\Elsewhere");
        if let Some(command) = machine {
            b = b.sz(&format!(r"{machine_key}\shell\open\command"), "", command);
        }
        let mut fp = fingerprint(&["VSCode.md"]);
        let mut entry = journal(".md", &["VSCode.md"]);
        entry.file_exts_key = Some(md.clone());
        fp.ext_journal = vec![entry];
        World::new(b.build(), fp).scan(&ClsFileExts).len()
    };
    assert_eq!(unread(None), 0);
    assert_eq!(unread(Some(&own)), 0);

    // Also when what was read of it leads into the app: the rest may lead anywhere.
    let b = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .sz(&format!(r"{md}\OpenWithList"), "a", "Code.exe")
        .sz(&format!(r"{md}\OpenWithList"), "MRUList", "a")
        .sz(&format!(r"{machine_key}\shell\open\command"), "", &own)
        .link(
            &format!(r"{machine_key}\shell\edit"),
            r"HKLM\SOFTWARE\Elsewhere",
        );
    let mut fp = fingerprint(&["VSCode.md"]);
    let mut entry = journal(".md", &["VSCode.md"]);
    entry.file_exts_key = Some(md.clone());
    fp.ext_journal = vec![entry];
    assert_eq!(World::new(b.build(), fp).scan(&ClsFileExts).len(), 0);
}

#[test]
fn file_exts_key_outside_file_exts_is_ignored() {
    let mut world = file_exts_world();
    world.fp.ext_journal[0].file_exts_key =
        Some(format!(r"HKU\{SID}\Software\Vendor\Settings\.md"));
    let out = world.scan(&ClsFileExts);
    assert!(of_ext(&out, ".md").is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// CLS-TOASTS
// ---------------------------------------------------------------------------------------------------------

fn toasts_world() -> World {
    let user = user_toasts();
    let machine = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";
    let fixture = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .dword(&user, "VSCode.md_.md", 0)
        .dword(&user, "VSCode.txt_.txt", 0)
        // Not ours, or not of the `<ProgID>_<.ext>` shape.
        .dword(&user, "Typora.md_.md", 0)
        .dword(&user, r"Applications\notepad.exe_.txt", 0)
        .dword(&user, "VSCode.md", 0)
        .dword(&user, "VSCode.md_", 0)
        .dword(&user, "VSCode.mdx_.md", 0)
        .dword(machine, "VSCode.md_.md", 0)
        .build();
    let mut fp = fingerprint(&["VSCode.md", "VSCode.txt", "VSCodeSourceFile"]);
    let mut md = journal(".md", &["VSCode.md"]);
    md.toast_values = vec!["VSCode.md_.md".into()];
    fp.ext_journal = vec![md];
    fp.ref_snapshot = vec![ref_snap(&user, "VSCode.txt_.txt", "VSCode.txt")];
    World::new(fixture, fp)
}

#[test]
fn toast_values_of_owned_progids_are_offered() {
    let world = toasts_world();
    let out = world.scan(&ClsToasts);
    golden::check("cls_toasts", &out);
    assert_grouped(&out);

    let user = user_toasts();
    let names: Vec<(&str, &str)> = out
        .iter()
        .map(|c| match &c.target {
            Target::RegValue { path, name } => (
                if *path == user { "user" } else { "machine" },
                name.as_str(),
            ),
            other => panic!("not a value: {other:?}"),
        })
        .collect();
    // A toast value whose ProgID is not in P is ignored, as is every malformed name.
    assert_eq!(
        names,
        [
            ("user", "VSCode.md_.md"),
            ("user", "VSCode.txt_.txt"),
            ("machine", "VSCode.md_.md"),
        ]
    );
    for c in &out {
        assert_eq!(
            (c.action, c.scanner.as_str()),
            (Action::DeleteValue, "CLS-TOASTS")
        );
        assert!(c.blockers.is_empty());
    }
    // Journal-listed, snapshot-listed: both Safe-eligible. The machine value is known from neither.
    assert!(out[0].evidence[0].source.0.starts_with("extjournal:"));
    assert!(out[1].evidence[0].source.0.starts_with("refsnap:"));
    assert!(safe_eligible(&out[0]) && safe_eligible(&out[1]));
    assert_eq!(kinds(&out[2]), [EvidenceKind::ChainedRef]);
    assert!(!safe_eligible(&out[2]));
    assert_eq!(fact(&out[0], "ext"), Some(".md"));
    assert_eq!(fact(&out[0], "progid"), Some("VSCode.md"));
}

#[test]
fn toast_names_split_at_the_last_underscore_dot() {
    assert_eq!(
        split_toast_name("VSCode.md_.md"),
        Some(("VSCode.md", ".md"))
    );
    assert_eq!(
        split_toast_name("My_App.doc_.doc"),
        Some(("My_App.doc", ".doc"))
    );
    assert_eq!(split_toast_name("A_.b_.c"), Some(("A_.b", ".c")));
    assert_eq!(split_toast_name("VSCode.md"), None);
    assert_eq!(split_toast_name("_.md"), None);
    assert_eq!(split_toast_name("VSCode.md_."), None);
    assert_eq!(split_toast_name(""), None);
}

#[test]
fn nothing_without_a_journal_or_progids() {
    // No journal: CLS-ASSOC and CLS-FILEEXTS have nothing to go by.
    let mut world = vscode_world();
    world.fp.ext_journal.clear();
    assert!(world.scan(&ClsAssoc).is_empty());
    assert!(world.scan(&ClsFileExts).is_empty());
    // No ProgIDs: no value is "named exactly in P".
    let mut world = toasts_world();
    world.fp.anchors.progids.clear();
    assert!(world.scan(&ClsToasts).is_empty());
    let mut world = vscode_world();
    world.fp.anchors.progids.clear();
    assert!(world.scan(&ClsAssoc).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// Review regressions
// ---------------------------------------------------------------------------------------------------------

/// A journal entry is only followed into one of the Classes roots the harvest journals. A key that
/// merely ends in `Classes` (or `_Classes`) elsewhere is not an extension key.
#[test]
fn journal_keys_outside_the_classes_roots_are_ignored() {
    for forged in [
        r"HKLM\SOFTWARE\Vendor\Classes\.vsnew",
        r"HKLM\SOFTWARE\Vendor_Classes\.vsnew",
        r"HKLM\SYSTEM\Classes\.vsnew",
        r"HKU\.DEFAULT_Classes\.vsnew",
        r"HKU\Vendor_Classes\.vsnew",
    ] {
        let fixture = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .key(forged)
            .sz(&format!(r"{forged}\OpenWithProgids"), "VSCode.vsnew", "")
            .build();
        let mut fp = fingerprint(PROGIDS);
        let mut entry = journal(".vsnew", &["VSCode.vsnew"]);
        entry.key = forged.into();
        fp.ext_journal = vec![entry];
        let world = World::new(fixture, fp);
        assert!(world.scan(&ClsAssoc).is_empty(), "{forged}");
    }

    // Both spellings of a user's Classes root are followed.
    for root in [
        format!(r"HKU\{SID}_Classes"),
        format!(r"HKU\{SID}\Software\Classes"),
    ] {
        let ext_key = format!(r"{root}\.vsnew");
        let fixture = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .sz(&format!(r"{ext_key}\OpenWithProgids"), "VSCode.vsnew", "")
            .build();
        let mut fp = fingerprint(PROGIDS);
        let mut entry = journal(".vsnew", &["VSCode.vsnew"]);
        entry.key = ext_key.clone();
        fp.ext_journal = vec![entry];
        let world = World::new(fixture, fp);
        let out = world.scan(&ClsAssoc);
        assert_eq!(out.len(), 1, "{root}");
        assert_eq!(
            out[0].target,
            value(format!(r"{ext_key}\OpenWithProgids"), "VSCode.vsnew")
        );
    }
}

/// A recorded `FileExts` key must be `HKU\<SID>\...\Explorer\FileExts\<.ext>`, not any key whose last
/// two segments look like it.
#[test]
fn file_exts_key_must_be_the_users_association_store() {
    for forged in [
        r"HKLM\SOFTWARE\Vendor\FileExts\.md".to_owned(),
        format!(r"HKU\{SID}\Software\Vendor\FileExts\.md"),
        r"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.md".to_owned(),
    ] {
        let fixture = Fixture::builder()
            .os(EDITION, BUILD, UBR)
            .user_sid(SID)
            .sz(&format!(r"{forged}\OpenWithProgids"), "VSCode.md", "")
            .sz(&format!(r"{forged}\OpenWithList"), "a", "Code.exe")
            .sz(&format!(r"{forged}\OpenWithList"), "MRUList", "a")
            .build();
        let mut fp = fingerprint(&["VSCode.md"]);
        let mut entry = journal(".md", &["VSCode.md"]);
        entry.file_exts_key = Some(forged.clone());
        fp.ext_journal = vec![entry];
        let world = World::new(fixture, fp);
        assert!(world.scan(&ClsFileExts).is_empty(), "{forged}");
    }
    // The real key, in another case, is read.
    let mut world = file_exts_world();
    world.fp.ext_journal[0].file_exts_key = Some(file_exts(".md").to_uppercase());
    assert!(!of_ext(&world.scan(&ClsFileExts), ".md").is_empty());
}

/// A ProgID that another installed app claims as well (two installs of one product) is not a removed
/// ProgID: neither the default that names it nor the skeleton of its extension is this app's to change.
#[test]
fn progid_claimed_by_another_app_blocks_defaults_and_skeletons() {
    let claim = |progid: &str| {
        OtherApps::new(vec![OtherApp {
            name: "VS Code (User)".into(),
            anchors: vec![AnchorRef {
                kind: AnchorKind::ProgId,
                text: progid.into(),
            }],
            ..OtherApp::default()
        }])
    };
    let blocked = [Blocker::ReferencedByOtherApp {
        app: "VS Code (User)".into(),
    }];

    let mut world = defaults_world();
    world.other_apps = claim("vscode.foo");
    let out = world.scan(&ClsAssoc);
    let default = out
        .iter()
        .find(|c| c.target == value(classes(".foo"), ""))
        .expect("the default is still listed");
    assert_eq!(default.blockers, blocked);
    // The unclaimed ones are untouched.
    let bar = out
        .iter()
        .find(|c| c.target == value(classes(".bar"), ""))
        .expect("the .bar default");
    assert!(bar.blockers.is_empty());

    let mut world = vscode_world();
    world.other_apps = claim("VSCODE.VSNEW");
    let out = world.scan(&ClsAssoc);
    let vsnew = of_ext(&out, ".vsnew");
    assert_eq!(vsnew.len(), 1);
    assert_eq!(vsnew[0].target, key(classes(".vsnew")));
    assert_eq!(vsnew[0].blockers, blocked);
    assert!(!safe_eligible(vsnew[0]));
}

/// The skeleton rules hold whatever the journal claims about the past: what counts is that the key is
/// empty **now** and that the source could read all of it.
#[test]
fn skeleton_fails_closed_on_keys_it_cannot_vouch_for() {
    // OpenWithProgids holds a subkey (no value): not empty, nothing key-level.
    let mut world = vscode_world();
    world
        .fixture
        .add_key(&classes(r".vsnew\OpenWithProgids\Sub"));
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());

    // The journal saw a default that is not the app's: the `.ext` key was somebody's, only
    // OpenWithProgids can be a skeleton.
    let mut world = vscode_world();
    world.fp.ext_journal[0].default = Some("somefile".into());
    let out = world.scan(&ClsAssoc);
    assert_eq!(
        of_ext(&out, ".vsnew")[0].target,
        key(classes(r".vsnew\OpenWithProgids"))
    );

    // A matching baseline that has the OpenWithProgids child but (oddly) not the `.ext` key: neither
    // key is offered.
    let mut world = vscode_world();
    world.baseline = Some(baseline(
        EDITION,
        &[&classes(r".vsnew\OpenWithProgids")],
        &[],
    ));
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());

    // A journal with more than one of the app's values and nothing else is still the app's alone, and
    // one foreign name among them spoils it.
    let mut world = vscode_world();
    world.fp.ext_journal[0].openwith_ours = vec!["VSCode.vsnew".into(), "VSCodeSourceFile".into()];
    assert_eq!(
        of_ext(&world.scan(&ClsAssoc), ".vsnew")[0].target,
        key(classes(".vsnew"))
    );
    world.fp.ext_journal[0].openwith_ours = vec!["VSCode.vsnew".into(), "Other.vsnew".into()];
    assert!(of_ext(&world.scan(&ClsAssoc), ".vsnew").is_empty());
}
