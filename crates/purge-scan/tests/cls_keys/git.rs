//! Git for Windows after its uninstall (ENGINE_PLAN.md §1.4, lessons L3/L4): the uninstaller removes
//! `sh_auto_file\shell\open\command` and its verbs under `LibraryFolder\background\shell`, and leaves the
//! empty parents behind. With the LTSC baseline both go as proven owned skeletons; without a baseline
//! neither key is offered.

use purge_model::{EvidenceKind, FileTime, Scope, SubtreeBaseline, SubtreeValue, Tier};
use purge_scan::cls_progid::ClsProgId;
use purge_scan::cls_verbs::ClsVerbs;
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::*;

const GIT_ROOT: &str = r"C:\Program Files\Git";
const SH_AUTO_FILE: &str = r"HKLM\SOFTWARE\Classes\sh_auto_file";
const LIBRARY_SHELL: &str = r"HKLM\SOFTWARE\Classes\LibraryFolder\background\shell";
const DIRECTORY_SHELL: &str = r"HKLM\SOFTWARE\Classes\Directory\shell";
const STAR_SHELL: &str = r"HKLM\SOFTWARE\Classes\*\shell";

fn subtree(key: &str, values: &[&str], subkeys: &[&str]) -> SubtreeBaseline {
    SubtreeBaseline {
        key: key.into(),
        values: values
            .iter()
            .map(|subkey| SubtreeValue {
                subkey: (*subkey).into(),
                name: String::new(),
                hash: "aa11".into(),
            })
            .collect(),
        subkeys: subkeys.iter().map(|s| (*s).into()).collect(),
        lwt: FileTime(133_900_000_000_000_000),
        ti_owned: false,
        fully_attributed: true,
    }
}

/// The registry after Git's uninstall on the LTSC VM, with Windows' own verbs around it.
fn after_uninstall() -> Fixture {
    Fixture::builder()
        .os(LTSC_EDITION, LTSC_BUILD, LTSC_UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        // Left behind, empty.
        .key(&format!(r"{SH_AUTO_FILE}\shell"))
        .ti_owned(SH_AUTO_FILE, false)
        .ti_owned(&format!(r"{SH_AUTO_FILE}\shell"), false)
        .key(LIBRARY_SHELL)
        .ti_owned(LIBRARY_SHELL, false)
        // Windows' own.
        .sz(
            &format!(r"{DIRECTORY_SHELL}\cmd\command"),
            "",
            r#"cmd.exe /s /k pushd "%V""#,
        )
        .key(STAR_SHELL)
        .build()
}

fn world() -> World {
    let mut fp = machine_fp("Git_is1", "Git", GIT_ROOT);
    fp.os.edition = LTSC_EDITION.into();
    fp.os.build = LTSC_BUILD;
    fp.os.ubr = LTSC_UBR;
    fp.subtrees = vec![
        subtree(
            SH_AUTO_FILE,
            &[r"shell\open\command"],
            &["shell", r"shell\open", r"shell\open\command"],
        ),
        subtree(
            LIBRARY_SHELL,
            &[r"git_shell\command", r"git_gui\command"],
            &[
                "git_shell",
                r"git_shell\command",
                "git_gui",
                r"git_gui\command",
            ],
        ),
    ];
    let mut world = World::new(after_uninstall(), fp);
    world.baseline = Some(ltsc_baseline());
    world
}

#[test]
fn skeletons_are_tier_a_key_scope_on_the_ltsc_baseline() {
    let world = world();
    // What the test rests on: clean LTSC has the shell objects but neither of Git's keys.
    let baseline = world.baseline.as_ref().unwrap();
    assert!(baseline.is_for(LTSC_EDITION, LTSC_BUILD, LTSC_UBR));
    assert!(baseline.has_key(r"HKLM\SOFTWARE\Classes\LibraryFolder\background"));
    assert!(baseline.has_key(DIRECTORY_SHELL));
    assert!(baseline.has_key(STAR_SHELL));
    assert!(!baseline.has_key(SH_AUTO_FILE));
    assert!(!baseline.has_key(LIBRARY_SHELL));

    let progids = world.run(&ClsProgId);
    assert_golden(
        render(&progids),
        &[r"key HKLM\SOFTWARE\Classes\sh_auto_file DeleteKey [ProvenOwnedSkeleton/A/Key]"],
    );
    let verbs = world.run(&ClsVerbs);
    assert_golden(
        render(&verbs),
        &[
            r"key HKLM\SOFTWARE\Classes\LibraryFolder\background\shell DeleteKey [ProvenOwnedSkeleton/A/Key]",
        ],
    );
    for (candidates, key) in [(&progids, SH_AUTO_FILE), (&verbs, LIBRARY_SHELL)] {
        let c = on_key(candidates, key).unwrap();
        let e = &c.evidence[0];
        assert_eq!(e.kind, EvidenceKind::ProvenOwnedSkeleton);
        assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Scope::Key));
        assert_eq!(e.detail.get("baseline"), Some("EnterpriseSEval-26100.1742"));
        assert!(c.blockers.is_empty(), "{key}: {:?}", c.blockers);
    }
}

#[test]
fn without_a_baseline_neither_key_is_offered() {
    let mut world = world();
    world.baseline = None;
    assert_golden(world.golden(&ClsProgId), &[]);
    assert_golden(world.golden(&ClsVerbs), &[]);
    // A baseline of another edition is no baseline for this Windows.
    world.baseline = Some(baseline_for("Professional", &[]));
    assert_golden(world.golden(&ClsProgId), &[]);
    assert_golden(world.golden(&ClsVerbs), &[]);
}

#[test]
fn a_skeleton_that_is_no_longer_empty_is_not_offered() {
    // Someone else's verb appeared under the shell key after the harvest.
    let mut world = world();
    world.fixture.set_value(
        &format!(r"{LIBRARY_SHELL}\other_tool\command"),
        "",
        RegData::from_sz(r#""C:\Tools\other.exe" "%V""#),
    );
    assert_golden(world.golden(&ClsVerbs), &[]);
    // A value in the auto-file key keeps it too.
    world
        .fixture
        .set_value(SH_AUTO_FILE, "", RegData::from_sz("Shell script"));
    assert_golden(world.golden(&ClsProgId), &[]);
}

#[test]
fn structural_shell_roots_are_never_offered() {
    // Even when Git's verbs are still there, only the verbs are offered, never `Directory\shell`,
    // `*\shell` or the shell objects.
    let mut world = world();
    for (shell, verb) in [(DIRECTORY_SHELL, "git_shell"), (STAR_SHELL, "git_gui")] {
        world.fixture.set_value(
            &format!(r"{shell}\{verb}\command"),
            "",
            RegData::from_sz(r#""C:\Program Files\Git\git-bash.exe" "--cd=%1""#),
        );
    }
    let verbs = world.run(&ClsVerbs);
    assert_golden(
        render(&verbs),
        &[
            r"key HKLM\SOFTWARE\Classes\*\shell\git_gui DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Classes\Directory\shell\git_shell DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Classes\LibraryFolder\background\shell DeleteKey [ProvenOwnedSkeleton/A/Key]",
        ],
    );
}
