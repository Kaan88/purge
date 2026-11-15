//! Tests for the live gate: a table per rule with both sides, hostile spellings, and a deterministic
//! property test over the spellings one location can have (ENGINE_PLAN.md §10.1).

use std::sync::LazyLock;

use serde_json::json;

use super::*;
use crate::canon::tests::{Rng, respell_path};

const SID: &str = GuardEnv::SAMPLE_SID;
const APP: &str = r"C:\Program Files\Vendor\App";
const FILE: &str = r"C:\Program Files\Vendor\App\bin\app.dll";
const SERIAL: u64 = 0x1122_3344_5566_7788;
const JUNCTION: u32 = 0xA000_0003;
const SYMLINK: u32 = 0xA000_000C;
const CLOUD_6: u32 = 0x9000_601A;

static LIST: LazyLock<DenyList> = LazyLock::new(|| DenyList::compile(&GuardEnv::sample()));

fn none() -> Exemptions {
    Exemptions::default()
}

fn long(path: &str) -> String {
    format!(r"\\?\{path}")
}

fn identity(n: u8) -> FileIdentity {
    FileIdentity {
        volume_serial: SERIAL,
        file_id: [n; 16],
    }
}

fn ntfs() -> VolumeFacts {
    VolumeFacts {
        drive_fixed: true,
        fs_name: "NTFS".into(),
    }
}

/// Facts of an ordinary file at `path`: everything known, nothing objectionable.
fn file_facts(path: &str) -> PathFacts {
    PathFacts {
        final_path: Some(long(path)),
        reparse_tag: Some(0),
        attributes: Some(0x20),
        identity: Some(identity(7)),
        n_links: Some(1),
        is_dir: Some(false),
        volume: Some(ntfs()),
        owner_is_ti: Some(false),
        explicit_ti_ace: Some(false),
        links_inside_plan: None,
        tree: None,
    }
}

/// Facts of an ordinary directory at `path` with a clean, complete walk below it.
fn dir_facts(path: &str) -> PathFacts {
    PathFacts {
        attributes: Some(FILE_ATTRIBUTE_DIRECTORY),
        is_dir: Some(true),
        tree: Some(TreeFacts {
            complete: true,
            ..TreeFacts::default()
        }),
        ..file_facts(path)
    }
}

fn check_with(
    lexical: &str,
    op: PathOp,
    binding: Binding<'_, PathStamp>,
    exemptions: Exemptions,
    facts: &PathFacts,
) -> Verdict {
    let check = PathCheck {
        lexical,
        op,
        binding,
        exemptions,
    };
    let verdict = check_path(&check, facts, &LIST);
    assert_softness(&verdict);
    verdict
}

fn quarantine(lexical: &str, facts: &PathFacts) -> Verdict {
    check_with(
        lexical,
        PathOp::QuarantineMove,
        Binding::Capture,
        none(),
        facts,
    )
}

/// Acceptance: `ChangedSinceScan` is the only soft refusal.
fn assert_softness(verdict: &Verdict) {
    if let Err(refusal) = verdict {
        assert_eq!(
            refusal.is_hard(),
            refusal.blocker != Blocker::ChangedSinceScan,
            "{refusal}"
        );
    }
}

fn refused(verdict: Verdict, blocker: Blocker, reason: &str) {
    match verdict {
        Ok(()) => panic!("let through; wanted {blocker:?} ({reason})"),
        Err(refusal) => assert_eq!(
            (refusal.blocker.clone(), refusal.reason),
            (blocker, reason),
            "{refusal}"
        ),
    }
}

fn deny_rule(verdict: Verdict) -> (String, &'static str) {
    match verdict {
        Err(Refusal {
            blocker: Blocker::DenyListed { rule },
            reason,
        }) => (rule, reason),
        other => panic!("wanted a deny rule, got {other:?}"),
    }
}

// ----- check_path ------------------------------------------------------------------------------------

#[test]
fn an_ordinary_file_and_directory_pass() {
    assert_eq!(quarantine(FILE, &file_facts(FILE)), Ok(()));
    assert_eq!(quarantine(APP, &dir_facts(APP)), Ok(()));
    let stamp = dir_facts(APP).stamp().unwrap();
    for op in [PathOp::QuarantineMove, PathOp::RemoveDirIfEmpty] {
        let verdict = check_with(APP, op, Binding::Recheck(&stamp), none(), &dir_facts(APP));
        assert_eq!(verdict, Ok(()), "{op:?}");
    }
    // Delete-if-empty needs no walk: `RemoveDirectory` itself refuses a directory with content.
    let mut no_walk = dir_facts(APP);
    no_walk.tree = None;
    let verdict = check_with(
        APP,
        PathOp::RemoveDirIfEmpty,
        Binding::Capture,
        none(),
        &no_walk,
    );
    assert_eq!(verdict, Ok(()));
}

#[test]
fn facts_that_know_nothing_are_refused() {
    refused(
        quarantine(FILE, &PathFacts::default()),
        Blocker::ReparseMismatch,
        reason::FINAL_UNKNOWN,
    );
    assert_eq!(PathFacts::default().stamp(), None);
}

/// Every fact, taken away alone, refuses with the rule that needs it.
#[test]
fn each_unknown_fact_refuses() {
    type Forget = fn(&mut PathFacts);
    let rows: &[(Forget, Blocker, &str)] = &[
        (
            |f| f.final_path = None,
            Blocker::ReparseMismatch,
            reason::FINAL_UNKNOWN,
        ),
        (
            |f| f.reparse_tag = None,
            Blocker::ReparseMismatch,
            reason::HANDLE_FACTS_UNKNOWN,
        ),
        (
            |f| f.attributes = None,
            Blocker::ReparseMismatch,
            reason::HANDLE_FACTS_UNKNOWN,
        ),
        (
            |f| f.is_dir = None,
            Blocker::ReparseMismatch,
            reason::HANDLE_FACTS_UNKNOWN,
        ),
        (
            |f| f.volume = None,
            Blocker::CannotBackUp,
            reason::VOLUME_UNKNOWN,
        ),
        (
            |f| f.owner_is_ti = None,
            Blocker::TrustedInstallerOwned,
            reason::TI_UNKNOWN,
        ),
        (
            |f| f.explicit_ti_ace = None,
            Blocker::TrustedInstallerOwned,
            reason::TI_UNKNOWN,
        ),
        (
            |f| f.n_links = None,
            Blocker::HardLinkOutsidePlan,
            reason::LINKS_UNKNOWN,
        ),
        (
            |f| f.tree = None,
            Blocker::HardLinkOutsidePlan,
            reason::TREE_UNKNOWN,
        ),
        (
            |f| f.identity = None,
            Blocker::ReparseMismatch,
            reason::IDENTITY_UNKNOWN,
        ),
    ];
    for (i, (forget, blocker, why)) in rows.iter().enumerate() {
        let mut facts = dir_facts(APP);
        forget(&mut facts);
        refused(quarantine(APP, &facts), blocker.clone(), why);
        // The same holds immediately before the act.
        let stamp = dir_facts(APP).stamp().unwrap();
        let verdict = check_with(
            APP,
            PathOp::QuarantineMove,
            Binding::Recheck(&stamp),
            none(),
            &facts,
        );
        assert!(verdict.is_err(), "row {i}");
    }
}

#[test]
fn spellings_of_the_same_item_pass() {
    let lexicals = [
        FILE.to_owned(),
        long(FILE),
        format!(r"\??\{FILE}"),
        FILE.replace('\\', "/"),
        FILE.to_ascii_lowercase(),
        FILE.to_ascii_uppercase(),
        r"c:\Program Files\\Vendor\App\bin\app.dll".to_owned(),
    ];
    let finals = [
        long(FILE),
        FILE.to_owned(),
        long(&FILE.to_ascii_uppercase()),
        long(&FILE.to_ascii_lowercase()),
        format!(r"\??\{FILE}"),
    ];
    for lexical in &lexicals {
        for final_path in &finals {
            let mut facts = file_facts(FILE);
            facts.final_path = Some(final_path.clone());
            assert_eq!(
                quarantine(lexical, &facts),
                Ok(()),
                "{lexical} / {final_path}"
            );
        }
    }
    // Case folding is that of the file system: non-ASCII letters fold, the Kelvin sign does not.
    let mut facts = file_facts(r"C:\Vendor\ÄPFEL\x");
    assert_eq!(quarantine(r"C:\Vendor\äpfel\x", &facts), Ok(()));
    facts.final_path = Some(long("C:\\Vendor\\\u{212A}odi\\x"));
    refused(
        quarantine(r"C:\Vendor\Kodi\x", &facts),
        Blocker::ReparseMismatch,
        reason::FINAL_DIFFERS,
    );
}

#[test]
fn a_lexical_path_that_does_not_canonicalise_is_refused() {
    let rows = [
        ("", "canon.empty"),
        (r"%ProgramFiles%\Vendor\App", "canon.env-token"),
        (r"%APPDATA%\App", "canon.no-profile"),
        (r"%TEMP%\App", "canon.env-token"),
        (r"Vendor\App", "canon.relative"),
        (r"C:\Vendor\..\Windows", "canon.dot-segment"),
        (r"C:\Vendor\App.", "canon.trailing-dot-or-space"),
        (r"C:\Vendor\App \x", "canon.trailing-dot-or-space"),
        (r"C:\Vendor\App\x.dll:stream", "canon.ads"),
        (r"C:\Vendor\App\x.dll::$DATA", "canon.ads"),
        (r"\\server\share\App", "canon.unc"),
        (r"\\?\UNC\server\share\App", "canon.unc"),
        (r"\\.\C:\Vendor\App", "canon.device-namespace"),
        (
            r"\\?\Volume{6f2e4b0a-0000-0000-0000-100000000000}\Vendor\App",
            "canon.device-namespace",
        ),
        (
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Vendor",
            "canon.globalroot",
        ),
        (r"C:\Vendor\NUL", "canon.device-name"),
        ("C:\\Vendor\\a\u{0}b", "canon.invalid-char"),
    ];
    for (lexical, rule) in rows {
        // The facts claim whatever the caller likes; the path itself is refused.
        let mut facts = file_facts(FILE);
        facts.final_path = Some(lexical.to_owned());
        let got = deny_rule(quarantine(lexical, &facts));
        assert_eq!(
            got,
            (rule.to_owned(), reason::LEXICAL_NOT_CANONICAL),
            "{lexical:?}"
        );
    }
}

#[test]
fn the_deny_list_runs_on_the_lexical_path() {
    for (lexical, rule) in [
        (r"C:\Windows\System32\x.dll", "fs.windir"),
        (r"C:\", "fs.drive-root"),
        (r"C:\Program Files", ""),
        (r"C:\Program Files\Purge\purge-engine.exe", "fs.purge"),
        (r"C:\ProgramData\Purge\Quarantine\s\1\app.dll", "fs.purge"),
        (r"C:\ProgramData\Purge\sessions\s\journal.jsonl", "fs.purge"),
        (r"D:\.purge-q\s\1\app.dll", "fs.purge"),
        (r"\\?\d:\.PURGE-Q\s\1\app.dll", "fs.purge"),
    ] {
        let (got, why) = deny_rule(quarantine(lexical, &file_facts(lexical)));
        assert_eq!(why, reason::DENY_LEXICAL, "{lexical}");
        if !rule.is_empty() {
            assert_eq!(got, rule, "{lexical}");
        }
    }
}

/// Acceptance: a clean lexical path whose final path is deny-listed reports the deny rule.
#[test]
fn a_clean_path_that_resolves_into_a_protected_place_reports_the_deny_rule() {
    for protected in [
        r"C:\Windows\System32\app.dll",
        r"C:\ProgramData\Purge\Quarantine\s\1\app.dll",
        r"C:\Users\tester\.ssh\id_ed25519",
        r"C:\Program Files",
        r"D:\.purge-q\s\1\x",
    ] {
        let direct = LIST
            .denying_rule(&path_target(protected), &none())
            .unwrap_or_else(|| panic!("{protected} should be denied"));
        let mut facts = file_facts(FILE);
        facts.final_path = Some(long(protected));
        let got = deny_rule(quarantine(FILE, &facts));
        assert_eq!(got, (direct, reason::DENY_FINAL), "{protected}");
    }
}

#[test]
fn a_final_path_elsewhere_is_a_reparse_mismatch() {
    let differs = [
        // A junction as the parent inside the install directory: the handle is somewhere else.
        r"\\?\D:\Elsewhere\bin\app.dll",
        r"\\?\C:\Program Files\Vendor\Other\bin\app.dll",
        r"\\?\C:\Program Files\Vendor\App\app.dll",
        r"\\?\C:\Program Files\Vendor\App\bin",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dll\x",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dl",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dll2",
        r"\\?\C:\Program Files\Vendor\App\bin2\app.dll",
        r"\\?\E:\Program Files\Vendor\App\bin\app.dll",
        // An 8.3 alias is another name, not another spelling.
        r"\\?\C:\PROGRA~1\Vendor\App\bin\app.dll",
    ];
    for final_path in differs {
        let mut facts = file_facts(FILE);
        facts.final_path = Some(final_path.to_owned());
        refused(
            quarantine(FILE, &facts),
            Blocker::ReparseMismatch,
            reason::FINAL_DIFFERS,
        );
    }
    let not_a_drive_path = [
        r"\\?\Volume{6f2e4b0a-0000-0000-0000-100000000000}\Program Files\Vendor\App\bin\app.dll",
        r"\\?\UNC\server\share\Vendor\App\bin\app.dll",
        r"\\server\share\Vendor\App\bin\app.dll",
        r"\\?\GLOBALROOT\Device\HarddiskVolume3\Program Files\Vendor\App\bin\app.dll",
        r"\Device\HarddiskVolume3\Program Files\Vendor\App\bin\app.dll",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dll.",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dll ",
        r"\\?\C:\Program Files\Vendor\App\bin\app.dll::$DATA",
        r"\\?\C:\Program Files\Vendor\App\bin\..\bin\app.dll",
        r"Program Files\Vendor\App\bin\app.dll",
        "",
    ];
    for final_path in not_a_drive_path {
        let mut facts = file_facts(FILE);
        facts.final_path = Some(final_path.to_owned());
        refused(
            quarantine(FILE, &facts),
            Blocker::ReparseMismatch,
            reason::FINAL_NOT_A_DRIVE_PATH,
        );
    }
}

#[test]
fn an_8_3_alias_never_passes() {
    let alias = r"C:\PROGRA~1\Vendor\App\bin\app.dll";
    // Unresolved, the deny-list refuses the lexical path outright.
    let got = deny_rule(quarantine(alias, &file_facts(FILE)));
    assert_eq!(
        got,
        (
            "canon.short-name-unresolved".to_owned(),
            reason::DENY_LEXICAL
        )
    );
    // A caller that claims the names are resolved still meets the final path.
    let resolved = Exemptions {
        long_names_resolved: true,
        ..none()
    };
    let verdict = check_with(
        alias,
        PathOp::QuarantineMove,
        Binding::Capture,
        resolved,
        &file_facts(FILE),
    );
    refused(verdict, Blocker::ReparseMismatch, reason::FINAL_DIFFERS);
    // A directory whose long name merely looks like a short one is the same item under both names.
    let odd = r"C:\Vendor\APP~1\x";
    let verdict = check_with(
        odd,
        PathOp::QuarantineMove,
        Binding::Capture,
        resolved,
        &file_facts(odd),
    );
    assert_eq!(verdict, Ok(()));
}

#[test]
fn a_reparse_point_as_the_item_is_refused() {
    let reparse = |tag: u32, attributes: u32, is_dir: bool| {
        let mut facts = if is_dir {
            dir_facts(APP)
        } else {
            file_facts(APP)
        };
        facts.reparse_tag = Some(tag);
        facts.attributes = Some(attributes);
        quarantine(APP, &facts)
    };
    let dir_link = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    for tag in [JUNCTION, SYMLINK, 0x8000_0017, 0x8000_001B, 0xFFFF_FFFF] {
        refused(
            reparse(tag, dir_link, true),
            Blocker::ReparseMismatch,
            reason::ITEM_IS_REPARSE_POINT,
        );
    }
    refused(
        reparse(SYMLINK, FILE_ATTRIBUTE_REPARSE_POINT | 0x20, false),
        Blocker::ReparseMismatch,
        reason::ITEM_IS_REPARSE_POINT,
    );
    // A tag without the attribute, the attribute without a tag, a directory bit that disagrees.
    let contradictions = [
        (JUNCTION, FILE_ATTRIBUTE_DIRECTORY, true),
        (0, dir_link, true),
        (0, 0x20, true),
        (0, FILE_ATTRIBUTE_DIRECTORY, false),
    ];
    for (tag, attributes, is_dir) in contradictions {
        refused(
            reparse(tag, attributes, is_dir),
            Blocker::ReparseMismatch,
            reason::HANDLE_FACTS_CONTRADICT,
        );
    }
}

#[test]
fn placeholders_and_cloud_tags_are_sync_root_items() {
    let cloud_tags = [
        0x9000_001A,
        0x9000_101A,
        CLOUD_6,
        0x9000_F01A,
        0x8000_0021,
        0x8000_0015,
        0xC000_0004,
        0x8000_0006,
        0x9000_001C,
        0xA000_0022,
    ];
    for tag in cloud_tags {
        assert!(is_cloud_reparse_tag(tag), "{tag:#x}");
        for attributes in [FILE_ATTRIBUTE_REPARSE_POINT | 0x20, 0x20] {
            let mut facts = file_facts(FILE);
            facts.reparse_tag = Some(tag);
            facts.attributes = Some(attributes);
            refused(
                quarantine(FILE, &facts),
                Blocker::SyncRoot,
                reason::CLOUD_TAG,
            );
        }
    }
    for tag in [0, JUNCTION, SYMLINK, 0x9000_001B, 0x8000_001A, 0x9001_001A] {
        assert!(!is_cloud_reparse_tag(tag), "{tag:#x}");
    }
    for bit in [
        FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_PINNED,
        FILE_ATTRIBUTE_UNPINNED,
    ] {
        let mut facts = file_facts(FILE);
        facts.attributes = Some(0x20 | bit);
        refused(
            quarantine(FILE, &facts),
            Blocker::SyncRoot,
            reason::PLACEHOLDER,
        );
    }
    // Hidden, system, read-only, archive, compressed, not indexed, sparse: ordinary.
    let mut facts = file_facts(FILE);
    facts.attributes = Some(0x1 | 0x2 | 0x4 | 0x20 | 0x200 | 0x800 | 0x2000);
    assert_eq!(quarantine(FILE, &facts), Ok(()));
    // Placeholders below a directory that is moved whole.
    let mut facts = dir_facts(APP);
    facts.tree.as_mut().unwrap().placeholders = 1;
    refused(
        quarantine(APP, &facts),
        Blocker::SyncRoot,
        reason::PLACEHOLDER_IN_TREE,
    );
}

#[test]
fn only_fixed_ntfs_and_refs_volumes_can_be_backed_up() {
    let on = |drive_fixed: bool, fs: &str| {
        let mut facts = file_facts(FILE);
        facts.volume = Some(VolumeFacts {
            drive_fixed,
            fs_name: fs.into(),
        });
        quarantine(FILE, &facts)
    };
    for fs in ["NTFS", "ntfs", "ReFS", "REFS"] {
        assert_eq!(on(true, fs), Ok(()), "{fs}");
        refused(
            on(false, fs),
            Blocker::CannotBackUp,
            reason::VOLUME_NOT_FIXED,
        );
    }
    for fs in ["FAT32", "exFAT", "FAT", "UDF", "CDFS", "", "NTFS ", "NTFS2"] {
        refused(on(true, fs), Blocker::CannotBackUp, reason::FILE_SYSTEM);
    }
}

#[test]
fn trusted_installer_items_are_refused() {
    let with = |owner: Option<bool>, ace: Option<bool>| {
        let mut facts = file_facts(FILE);
        facts.owner_is_ti = owner;
        facts.explicit_ti_ace = ace;
        quarantine(FILE, &facts)
    };
    let ti = Blocker::TrustedInstallerOwned;
    assert_eq!(with(Some(false), Some(false)), Ok(()));
    refused(with(Some(true), Some(false)), ti.clone(), reason::TI_OWNER);
    refused(with(Some(true), None), ti.clone(), reason::TI_OWNER);
    refused(with(Some(false), Some(true)), ti.clone(), reason::TI_ACE);
    refused(with(None, Some(true)), ti.clone(), reason::TI_ACE);
    refused(with(None, Some(false)), ti.clone(), reason::TI_UNKNOWN);
    refused(with(Some(false), None), ti.clone(), reason::TI_UNKNOWN);
    refused(with(None, None), ti, reason::TI_UNKNOWN);
}

#[test]
fn hard_links_must_all_lie_inside_the_plan() {
    let with = |n_links: Option<u32>, inside: Option<bool>| {
        let mut facts = file_facts(FILE);
        facts.n_links = n_links;
        facts.links_inside_plan = inside;
        quarantine(FILE, &facts)
    };
    let out = Blocker::HardLinkOutsidePlan;
    for inside in [None, Some(false), Some(true)] {
        assert_eq!(with(Some(1), inside), Ok(()), "one name: {inside:?}");
    }
    for n in [2, 3, 1024, u32::MAX] {
        assert_eq!(with(Some(n), Some(true)), Ok(()));
        refused(
            with(Some(n), Some(false)),
            out.clone(),
            reason::LINK_OUTSIDE_PLAN,
        );
        refused(with(Some(n), None), out.clone(), reason::LINKS_UNKNOWN);
    }
    refused(with(None, Some(true)), out.clone(), reason::LINKS_UNKNOWN);
    refused(
        with(Some(0), Some(true)),
        Blocker::ChangedSinceScan,
        reason::NO_LINKS,
    );

    // Below a directory that is moved whole.
    let mut facts = dir_facts(APP);
    facts.tree.as_mut().unwrap().hard_links_outside_plan = 1;
    refused(
        quarantine(APP, &facts),
        out.clone(),
        reason::LINK_OUTSIDE_PLAN_IN_TREE,
    );
    let mut facts = dir_facts(APP);
    facts.tree.as_mut().unwrap().complete = false;
    refused(quarantine(APP, &facts), out, reason::TREE_UNKNOWN);
}

#[test]
fn links_inside_plan_needs_every_name() {
    let roots = [APP, r"D:\Games\Vendor"];
    let inside = |names: &[&str], n: u32| links_inside_plan(names, n, &roots);
    assert!(inside(&[FILE, r"C:\Program Files\Vendor\App\copy.dll"], 2));
    assert!(inside(&[FILE, r"d:\games\VENDOR\x\copy.dll"], 2));
    assert!(inside(&[APP], 1), "a root itself is inside the plan");
    assert!(inside(&[&long(FILE), FILE], 2));
    // A name outside, a name that only shares a string prefix, a root's parent.
    assert!(!inside(&[FILE, r"C:\Users\tester\Desktop\app.dll"], 2));
    assert!(!inside(&[FILE, r"C:\Program Files\Vendor\App2\app.dll"], 2));
    assert!(!inside(&[FILE, r"C:\Program Files\Vendor"], 2));
    // Fewer or more names than the handle counts, no names, a name that does not canonicalise.
    assert!(!inside(&[FILE], 2));
    assert!(!inside(&[FILE, FILE, FILE], 2));
    assert!(!inside(&[], 0));
    assert!(!inside(&[FILE, r"\Program Files\Vendor\App\copy.dll"], 2));
    assert!(!inside(&[FILE, r"C:\Program Files\Vendor\App\..\x"], 2));
    // A root that does not canonicalise, and no roots at all.
    assert!(!links_inside_plan(&[FILE], 1, &[APP, r"Vendor\App"]));
    assert!(!links_inside_plan::<_, &str>(&[FILE], 1, &[]));
}

#[test]
fn the_identity_must_be_the_recorded_one() {
    let recorded = file_facts(FILE).stamp().unwrap();
    let recheck = |facts: &PathFacts| {
        check_with(
            FILE,
            PathOp::QuarantineMove,
            Binding::Recheck(&recorded),
            none(),
            facts,
        )
    };
    assert_eq!(recheck(&file_facts(FILE)), Ok(()));

    let mut other_file = file_facts(FILE);
    other_file.identity = Some(identity(8));
    let mut other_volume = file_facts(FILE);
    other_volume.identity.as_mut().unwrap().volume_serial = SERIAL + 1;
    // A directory was put where the file was, with the file's id (ids are per volume, not per kind).
    let mut other_kind = dir_facts(FILE);
    other_kind.identity = Some(identity(7));
    for facts in [&other_file, &other_volume, &other_kind] {
        let refusal = recheck(facts).unwrap_err();
        assert_eq!(
            (refusal.blocker.clone(), refusal.reason),
            (Blocker::ChangedSinceScan, reason::IDENTITY_CHANGED)
        );
        assert!(!refusal.is_hard(), "a changed item is skipped, not alarmed");
        // The validate pass has nothing to compare with and records what it sees.
        assert_eq!(quarantine(FILE, facts), Ok(()));
    }

    // An id that identifies nothing is no id.
    for bad in [[0u8; 16], [0xFF; 16]] {
        let mut facts = file_facts(FILE);
        facts.identity.as_mut().unwrap().file_id = bad;
        assert_eq!(facts.stamp(), None);
        refused(
            quarantine(FILE, &facts),
            Blocker::ReparseMismatch,
            reason::IDENTITY_UNKNOWN,
        );
        refused(
            recheck(&facts),
            Blocker::ReparseMismatch,
            reason::IDENTITY_UNKNOWN,
        );
    }
}

#[test]
fn remove_dir_if_empty_needs_a_directory() {
    let verdict = check_with(
        FILE,
        PathOp::RemoveDirIfEmpty,
        Binding::Capture,
        none(),
        &file_facts(FILE),
    );
    refused(verdict, Blocker::ChangedSinceScan, reason::NOT_A_DIRECTORY);
}

/// The hard rules are reported before the soft one: an item that is both swapped and protected is an
/// alarm, not a skip.
#[test]
fn hard_refusals_come_before_changed_since_scan() {
    let recorded = file_facts(FILE).stamp().unwrap();
    let mut facts = file_facts(FILE);
    facts.identity = Some(identity(9));
    facts.final_path = Some(long(r"C:\Windows\System32\app.dll"));
    let verdict = check_with(
        FILE,
        PathOp::QuarantineMove,
        Binding::Recheck(&recorded),
        none(),
        &facts,
    );
    assert!(verdict.unwrap_err().is_hard());
    let mut facts = file_facts(FILE);
    facts.identity = Some(identity(9));
    facts.n_links = Some(2);
    facts.links_inside_plan = Some(false);
    let verdict = check_with(
        FILE,
        PathOp::QuarantineMove,
        Binding::Recheck(&recorded),
        none(),
        &facts,
    );
    assert!(verdict.unwrap_err().is_hard());
}

#[test]
fn exemptions_reach_the_deny_list() {
    let entry = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Vendor\App.lnk";
    let (rule, why) = deny_rule(quarantine(entry, &file_facts(entry)));
    assert_eq!(why, reason::DENY_LEXICAL, "{rule}");
    let tier_a = Exemptions {
        tier_a_start_menu_entry: true,
        ..none()
    };
    let verdict = check_with(
        entry,
        PathOp::QuarantineMove,
        Binding::Capture,
        tier_a,
        &file_facts(entry),
    );
    assert_eq!(verdict, Ok(()));
}

#[test]
fn a_broken_deny_list_refuses_everything() {
    let broken = DenyList::compile(&GuardEnv::default());
    let check = PathCheck {
        lexical: FILE,
        op: PathOp::QuarantineMove,
        binding: Binding::Capture,
        exemptions: none(),
    };
    let got = deny_rule(check_path(&check, &file_facts(FILE), &broken));
    assert_eq!(got, ("guard.unavailable".to_owned(), reason::DENY_LEXICAL));
    let target = Target::RegKey {
        path: r"HKLM\SOFTWARE\Vendor\App".into(),
    };
    let check = KeyCheck {
        target: &target,
        op: KeyOp::DeleteKeyTree,
        binding: Binding::Capture,
        exemptions: none(),
    };
    let got = deny_rule(check_key(&check, &key_facts(&target), &broken));
    assert_eq!(got, ("guard.unavailable".to_owned(), reason::DENY_KEY));
}

const SEGMENTS: &[&str] = &[
    "App",
    "bin",
    "Program Data",
    "x64",
    "résumé",
    "ÄÖÜ",
    "100% done",
    ".config",
    "a.b.c",
    "data-1",
    "Größe",
    "名前",
    "v1.2.3",
    "plug ins",
];

const OTHER_SEGMENTS: &[&str] = &[
    "Other", "bin2", "Ap", "Appx", "App-", "APPLIC~1", "x", "résume",
];

fn random_clean_path(rng: &mut Rng) -> String {
    let mut path = String::from(*rng.pick(&[r"D:\Apps", r"C:\Vendor", r"E:\Tools\Portable"]));
    for _ in 0..1 + rng.below(4) {
        path.push('\\');
        path.push_str(rng.pick(SEGMENTS));
    }
    path
}

/// A path that differs from `canonical` in at least one segment: one replaced, removed, added, or the
/// drive changed. Never a protected place, so the verdict is about the difference alone.
fn mutate(rng: &mut Rng, canonical: &str) -> String {
    let mut segs: Vec<String> = canonical.split('\\').map(str::to_owned).collect();
    match rng.below(5) {
        0 => {
            let i = 1 + rng.below(segs.len() - 1);
            let mut other = *rng.pick(OTHER_SEGMENTS);
            if eq_ci(other, &segs[i]) {
                other = "Another";
            }
            segs[i] = other.to_owned();
        }
        1 if segs.len() > 3 => {
            segs.pop();
        }
        2 if segs.len() > 3 => {
            let i = 1 + rng.below(segs.len() - 1);
            segs.remove(i);
            // Removing one of two equal neighbours leaves the same path: make sure it differs.
            if prefix::is_same(&segs.join("\\"), canonical) {
                segs.push("x".into());
            }
        }
        3 => {
            let i = 1 + rng.below(segs.len());
            segs.insert(i, (*rng.pick(OTHER_SEGMENTS)).to_owned());
        }
        _ => segs[0] = if segs[0] == "F:" { "G:" } else { "F:" }.to_owned(),
    }
    segs.join("\\")
}

/// Acceptance: over every spelling of a location, the item passes when the final path is that location
/// and is a `ReparseMismatch` as soon as the final path differs in any segment.
#[test]
fn property_final_path_must_be_the_lexical_path() {
    let mut rng = Rng::new(0x51DE_CA11);
    for round in 0..4000 {
        let canonical = random_clean_path(&mut rng);
        let lexical = respell_path(&mut rng, &canonical);
        let mut facts = file_facts(&canonical);
        facts.final_path = Some(long(&rng.recase(&canonical)));
        assert_eq!(
            quarantine(&lexical, &facts),
            Ok(()),
            "round {round}: {lexical} / {:?}",
            facts.final_path
        );

        let elsewhere = mutate(&mut rng, &canonical);
        assert!(!prefix::is_same(&elsewhere, &canonical), "{elsewhere}");
        let final_path = if rng.coin() {
            long(&rng.recase(&elsewhere))
        } else {
            respell_path(&mut rng, &elsewhere)
        };
        facts.final_path = Some(final_path.clone());
        let stamp = facts.stamp().unwrap();
        let binding = if rng.coin() {
            Binding::Recheck(&stamp)
        } else {
            Binding::Capture
        };
        let verdict = check_with(&lexical, PathOp::QuarantineMove, binding, none(), &facts);
        refused(verdict, Blocker::ReparseMismatch, reason::FINAL_DIFFERS);
        // And the other way round. (The other path may hold a name shaped like a short one, which the
        // deny-list refuses on its own unless the caller has resolved it.)
        let mut facts = file_facts(&canonical);
        facts.final_path = Some(long(&canonical));
        let resolved = Exemptions {
            long_names_resolved: true,
            ..none()
        };
        let verdict = check_with(
            &final_path,
            PathOp::QuarantineMove,
            Binding::Capture,
            resolved,
            &facts,
        );
        refused(verdict, Blocker::ReparseMismatch, reason::FINAL_DIFFERS);
    }
}

// ----- registry --------------------------------------------------------------------------------------

fn hku(rest: &str) -> String {
    format!(r"HKU\{SID}\{rest}")
}

fn key(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

fn value(path: impl Into<String>, name: &str) -> Target {
    Target::RegValue {
        path: path.into(),
        name: name.into(),
    }
}

fn segment(path: impl Into<String>, name: &str, segment: &str) -> Target {
    Target::RegMultiSzSegment {
        path: path.into(),
        name: name.into(),
        segment: segment.into(),
        index: None,
    }
}

fn stamp(n: u8) -> ValueStamp {
    ValueStamp {
        ty: 1,
        len: 12,
        sha256: [n; 32],
    }
}

/// Facts of an ordinary key for `target`: every ancestor probed and plain, nothing objectionable, empty,
/// and holding the value.
fn key_facts(target: &Target) -> KeyFacts {
    let ancestors = key_probe(target, LIST.env())
        .map(|probe| probe.ancestors)
        .unwrap_or_default();
    KeyFacts {
        node: KeyNode::Plain,
        ancestors: ancestors
            .into_iter()
            .map(|path| KeyAncestor {
                path,
                node: KeyNode::Plain,
            })
            .collect(),
        owner_is_ti: Some(false),
        has_ti_ace: Some(false),
        subkeys: Some(0),
        values: Some(0),
        value: ValueState::Present(stamp(1)),
    }
}

fn key_with(
    target: &Target,
    op: KeyOp,
    binding: Binding<'_, ValueStamp>,
    exemptions: Exemptions,
    facts: &KeyFacts,
) -> Verdict {
    let check = KeyCheck {
        target,
        op,
        binding,
        exemptions,
    };
    let verdict = check_key(&check, facts, &LIST);
    assert_softness(&verdict);
    verdict
}

fn delete_tree(target: &Target, facts: &KeyFacts) -> Verdict {
    key_with(
        target,
        KeyOp::DeleteKeyTree,
        Binding::Capture,
        none(),
        facts,
    )
}

const APP_KEY: &str = r"HKLM\SOFTWARE\Vendor\App";

#[test]
fn key_probe_lists_the_chain_below_the_hive() {
    let probe = key_probe(&key(r"HKLM\Software\WOW6432Node\Vendor\App"), LIST.env()).unwrap();
    assert_eq!(probe.key_path, r"HKLM\SOFTWARE\WOW6432Node\Vendor\App");
    assert_eq!(
        probe.ancestors,
        [
            r"HKLM\SOFTWARE",
            r"HKLM\SOFTWARE\WOW6432Node",
            r"HKLM\SOFTWARE\WOW6432Node\Vendor"
        ]
    );
    assert_eq!(probe.key.path, r"SOFTWARE\Vendor\App");

    let probe = key_probe(&value(hku(r"Software\Vendor"), "x"), LIST.env()).unwrap();
    assert_eq!(probe.key_path, hku(r"Software\Vendor"));
    assert_eq!(probe.ancestors, [format!(r"HKU\{SID}"), hku("Software")]);

    let probe = key_probe(&key(r"HKLM\SOFTWARE"), LIST.env()).unwrap();
    assert!(probe.ancestors.is_empty());
}

/// The two aliases of §5.10 are resolved lexically, so the link they stand for is not on the chain.
#[test]
fn the_two_aliases_are_resolved_and_hkcr_is_rejected() {
    let source = r"Services\EventLog\Application\VendorApp";
    let aliased = key(format!(r"HKLM\SYSTEM\CurrentControlSet\{source}"));
    let probe = key_probe(&aliased, LIST.env()).unwrap();
    assert_eq!(
        probe.key_path,
        format!(r"HKLM\SYSTEM\ControlSet001\{source}")
    );
    assert!(
        probe
            .ancestors
            .iter()
            .all(|a| !a.contains("CurrentControlSet"))
    );
    assert_eq!(probe.ancestors[1], r"HKLM\SYSTEM\ControlSet001");
    assert_eq!(delete_tree(&aliased, &key_facts(&aliased)), Ok(()));
    let physical = key(format!(r"HKLM\SYSTEM\ControlSet001\{source}"));
    assert_eq!(delete_tree(&physical, &key_facts(&physical)), Ok(()));

    for spelled in [
        hku(r"Software\Classes\vendor.file"),
        format!(r"HKU\{SID}_Classes\vendor.file"),
        format!(r"HKEY_USERS\{}_classes\vendor.file", SID.to_lowercase()),
    ] {
        let target = key(spelled);
        let probe = key_probe(&target, LIST.env()).unwrap();
        assert_eq!(probe.key_path, format!(r"HKU\{SID}_Classes\vendor.file"));
        assert_eq!(probe.ancestors, [format!(r"HKU\{SID}_Classes")]);
        assert_eq!(delete_tree(&target, &key_facts(&target)), Ok(()));
    }

    // A caller that probed the alias instead of the canonical chain has not probed the chain.
    let mut facts = key_facts(&aliased);
    facts.ancestors[1].path = r"HKLM\SYSTEM\CurrentControlSet".into();
    refused(
        delete_tree(&aliased, &facts),
        Blocker::RegLink,
        reason::ANCESTORS_CONTRADICT,
    );

    for (rejected, rule) in [
        (r"HKCR\vendor.file", "canon.hkcr"),
        (r"HKEY_CLASSES_ROOT\CLSID\{x}", "canon.hkcr"),
        (r"HKCU\Software\Vendor\App", "canon.no-profile"),
        (r"HKCC\Software\Vendor", "canon.unknown-root"),
        (r"HKU\not-a-sid\Software\Vendor", "canon.bad-sid"),
        ("", "canon.empty"),
    ] {
        let target = key(rejected);
        let refusal = key_probe(&target, LIST.env()).unwrap_err();
        assert_eq!(refusal.reason, reason::KEY_NOT_CANONICAL);
        let mut facts = key_facts(&key(APP_KEY));
        facts.ancestors.clear();
        let got = deny_rule(delete_tree(&target, &facts));
        assert_eq!(
            got,
            (rule.to_owned(), reason::KEY_NOT_CANONICAL),
            "{rejected}"
        );
    }
    let no_set = GuardEnv {
        current_control_set: 0,
        ..GuardEnv::sample()
    };
    let refusal = key_probe(&aliased, &no_set).unwrap_err();
    assert_eq!(
        refusal.blocker,
        Blocker::DenyListed {
            rule: "canon.no-control-set".into()
        }
    );
}

#[test]
fn ordinary_registry_items_pass() {
    for path in [
        APP_KEY.to_owned(),
        r"HKLM\SOFTWARE\WOW6432Node\Vendor\App".to_owned(),
        r"hklm\software\vendor\app".to_owned(),
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\App".to_owned(),
        hku(r"Software\Vendor\App"),
    ] {
        let target = key(path.as_str());
        let facts = key_facts(&target);
        assert_eq!(delete_tree(&target, &facts), Ok(()), "{path}");
        let verdict = key_with(
            &target,
            KeyOp::DeleteKeyIfEmpty,
            Binding::Capture,
            none(),
            &facts,
        );
        assert_eq!(verdict, Ok(()), "{path}");
        let target = value(path.as_str(), "InstallDir");
        let verdict = key_with(
            &target,
            KeyOp::DeleteValue,
            Binding::Recheck(&stamp(1)),
            none(),
            &facts,
        );
        assert_eq!(verdict, Ok(()), "{path}");
    }
    // A value in a value container is the unit that is offered there.
    let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    let target = value(run, "VendorApp");
    let verdict = key_with(
        &target,
        KeyOp::DeleteValue,
        Binding::Capture,
        none(),
        &key_facts(&target),
    );
    assert_eq!(verdict, Ok(()));
}

#[test]
fn registry_facts_that_know_nothing_are_refused() {
    let target = key(APP_KEY);
    refused(
        delete_tree(&target, &KeyFacts::default()),
        Blocker::RegLink,
        reason::KEY_LINK_UNKNOWN,
    );
}

#[test]
fn the_operation_must_fit_the_target() {
    let k = key(APP_KEY);
    let v = value(APP_KEY, "x");
    let s = segment(APP_KEY, "Path", r"C:\Vendor");
    let changed = Target::RegValueChanged {
        path: APP_KEY.into(),
        name: "x".into(),
        before: String::new(),
        after: String::new(),
    };
    let file = path_target(FILE);
    let service = Target::Service {
        name: "VendorSvc".into(),
    };
    let fitting = [
        (KeyOp::DeleteKeyTree, &k),
        (KeyOp::DeleteKeyIfEmpty, &k),
        (KeyOp::DeleteValue, &v),
        (KeyOp::EditSegment, &s),
    ];
    for op in [
        KeyOp::DeleteKeyTree,
        KeyOp::DeleteKeyIfEmpty,
        KeyOp::DeleteValue,
        KeyOp::EditSegment,
    ] {
        for target in [&k, &v, &s, &changed, &file, &service] {
            let verdict = key_with(target, op, Binding::Capture, none(), &key_facts(&k));
            if fitting.contains(&(op, target)) {
                assert_eq!(verdict, Ok(()), "{op:?} {target:?}");
            } else {
                let got = deny_rule(verdict);
                assert_eq!(got.1, reason::OP_TARGET_MISMATCH, "{op:?} {target:?}");
            }
        }
    }
    assert_eq!(
        key_probe(&file, LIST.env()).unwrap_err().reason,
        reason::OP_TARGET_MISMATCH
    );
}

#[test]
fn the_deny_list_and_the_containers_run_on_registry_targets() {
    for (path, rule) in [
        (r"HKLM\SOFTWARE", ""),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "reg.run",
        ),
        (
            r"HKLM\SYSTEM\ControlSet001\Services\VendorSvc",
            "reg.hklm.system",
        ),
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager", ""),
        (r"HKU\S-1-5-18\Software\Vendor", "reg.hku.system-account"),
        (
            r"HKU\S-1-5-21-1-2-3-4444\Software\Vendor",
            "reg.hku.not-loaded",
        ),
    ] {
        let target = key(path);
        let (got, why) = deny_rule(delete_tree(&target, &key_facts(&target)));
        assert_eq!(why, reason::DENY_KEY, "{path}");
        if !rule.is_empty() {
            assert_eq!(got, rule, "{path}");
        }
    }
    // A value container that no deny rule names is still never deleted as a key.
    let toasts = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";
    let target = key(toasts);
    for op in [KeyOp::DeleteKeyTree, KeyOp::DeleteKeyIfEmpty] {
        let verdict = key_with(&target, op, Binding::Capture, none(), &key_facts(&target));
        refused(
            verdict,
            Blocker::StructuralContainer,
            reason::STRUCTURAL_CONTAINER,
        );
    }
    let target = value(toasts, "vendor.file_.foo");
    let verdict = key_with(
        &target,
        KeyOp::DeleteValue,
        Binding::Capture,
        none(),
        &key_facts(&target),
    );
    assert_eq!(verdict, Ok(()));

    // The Environment segment edit passes with its exemption and only with it.
    let environment = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    let target = segment(environment, "Path", r"C:\Program Files\Vendor\App\bin");
    let facts = key_facts(&target);
    let edit = |exemptions| {
        key_with(
            &target,
            KeyOp::EditSegment,
            Binding::Capture,
            exemptions,
            &facts,
        )
    };
    let (rule, why) = deny_rule(edit(none()));
    assert_eq!((rule.as_str(), why), ("reg.hklm.system", reason::DENY_KEY));
    let earned = Exemptions {
        environment_segment_edit: true,
        ..none()
    };
    assert_eq!(edit(earned), Ok(()));
}

#[test]
fn a_link_on_the_key_or_on_any_ancestor_is_refused() {
    let target = key(r"HKLM\SOFTWARE\WOW6432Node\Vendor\App");
    let clean = key_facts(&target);
    assert_eq!(clean.ancestors.len(), 3);

    let mut facts = clean.clone();
    facts.node = KeyNode::Link;
    refused(
        delete_tree(&target, &facts),
        Blocker::RegLink,
        reason::KEY_IS_LINK,
    );
    facts.node = KeyNode::Unknown;
    refused(
        delete_tree(&target, &facts),
        Blocker::RegLink,
        reason::KEY_LINK_UNKNOWN,
    );

    for i in 0..clean.ancestors.len() {
        for (node, why) in [
            (KeyNode::Link, reason::ANCESTOR_IS_LINK),
            (KeyNode::Unknown, reason::ANCESTOR_UNKNOWN),
            (KeyNode::Missing, reason::ANCESTORS_CONTRADICT),
        ] {
            let mut facts = clean.clone();
            facts.ancestors[i].node = node;
            refused(delete_tree(&target, &facts), Blocker::RegLink, why);
            // The same for every operation, also for a value in the key.
            let in_key = value(r"HKLM\SOFTWARE\WOW6432Node\Vendor\App", "x");
            let verdict = key_with(
                &in_key,
                KeyOp::DeleteValue,
                Binding::Capture,
                none(),
                &facts,
            );
            refused(verdict, Blocker::RegLink, why);
        }
        // An ancestor that was not probed.
        let mut facts = clean.clone();
        facts.ancestors.remove(i);
        refused(
            delete_tree(&target, &facts),
            Blocker::RegLink,
            reason::ANCESTOR_UNKNOWN,
        );
        // Two probes of one ancestor that disagree.
        let mut facts = clean.clone();
        let mut again = facts.ancestors[i].clone();
        again.node = KeyNode::Link;
        facts.ancestors.push(again);
        refused(
            delete_tree(&target, &facts),
            Blocker::RegLink,
            reason::ANCESTORS_CONTRADICT,
        );
    }
    // No ancestor facts at all.
    let mut facts = clean.clone();
    facts.ancestors.clear();
    refused(
        delete_tree(&target, &facts),
        Blocker::RegLink,
        reason::ANCESTOR_UNKNOWN,
    );
    // A fact about a key that is not an ancestor (the 64-bit sibling, the key itself, a child).
    for stray in [
        r"HKLM\SOFTWARE\Vendor",
        r"HKLM\SOFTWARE\WOW6432Node\Vendor\App",
        r"HKLM\SOFTWARE\WOW6432Node\Vendor\App\Sub",
        r"HKLM",
    ] {
        let mut facts = clean.clone();
        facts.ancestors.push(KeyAncestor {
            path: stray.into(),
            node: KeyNode::Plain,
        });
        refused(
            delete_tree(&target, &facts),
            Blocker::RegLink,
            reason::ANCESTORS_CONTRADICT,
        );
    }
    // Ancestor paths are compared as keys are: case-insensitively, in any order.
    let mut facts = clean.clone();
    facts.ancestors.reverse();
    for ancestor in &mut facts.ancestors {
        ancestor.path = ancestor.path.to_lowercase();
    }
    assert_eq!(delete_tree(&target, &facts), Ok(()));
    // A plain duplicate is harmless.
    let mut facts = clean.clone();
    facts.ancestors.push(clean.ancestors[0].clone());
    assert_eq!(delete_tree(&target, &facts), Ok(()));
}

#[test]
fn a_missing_key_is_not_acted_on() {
    let target = key(APP_KEY);
    let mut facts = key_facts(&target);
    facts.node = KeyNode::Missing;
    refused(
        delete_tree(&target, &facts),
        Blocker::ChangedSinceScan,
        reason::KEY_MISSING,
    );
}

#[test]
fn trusted_installer_keys_are_refused() {
    let target = key(APP_KEY);
    let with = |owner: Option<bool>, ace: Option<bool>| {
        let mut facts = key_facts(&target);
        facts.owner_is_ti = owner;
        facts.has_ti_ace = ace;
        delete_tree(&target, &facts)
    };
    let ti = Blocker::TrustedInstallerOwned;
    assert_eq!(with(Some(false), Some(false)), Ok(()));
    refused(with(Some(true), Some(false)), ti.clone(), reason::TI_OWNER);
    refused(with(Some(false), Some(true)), ti.clone(), reason::TI_ACE);
    refused(with(None, Some(false)), ti.clone(), reason::TI_UNKNOWN);
    refused(with(Some(false), None), ti, reason::TI_UNKNOWN);
}

#[test]
fn delete_if_empty_is_rechecked() {
    let target = key(r"HKLM\SOFTWARE\Vendor");
    let with = |subkeys: Option<u32>, values: Option<u32>, op: KeyOp| {
        let mut facts = key_facts(&target);
        facts.subkeys = subkeys;
        facts.values = values;
        key_with(&target, op, Binding::Capture, none(), &facts)
    };
    let empty = KeyOp::DeleteKeyIfEmpty;
    assert_eq!(with(Some(0), Some(0), empty), Ok(()));
    let changed = Blocker::ChangedSinceScan;
    for (subkeys, values) in [(1, 0), (0, 1), (3, 7), (u32::MAX, 0)] {
        refused(
            with(Some(subkeys), Some(values), empty),
            changed.clone(),
            reason::NOT_EMPTY,
        );
    }
    for (subkeys, values) in [(None, Some(0)), (Some(0), None), (None, None)] {
        refused(
            with(subkeys, values, empty),
            changed.clone(),
            reason::EMPTINESS_UNKNOWN,
        );
    }
    // A tree delete does not ask how much is below.
    assert_eq!(with(Some(9), None, KeyOp::DeleteKeyTree), Ok(()));
}

#[test]
fn a_value_must_be_the_recorded_one() {
    let recorded = stamp(1);
    for (target, op) in [
        (value(APP_KEY, "InstallDir"), KeyOp::DeleteValue),
        (segment(APP_KEY, "Paths", r"C:\Vendor"), KeyOp::EditSegment),
    ] {
        let with = |state: ValueState, binding: Binding<'_, ValueStamp>| {
            let mut facts = key_facts(&target);
            facts.value = state;
            key_with(&target, op, binding, none(), &facts)
        };
        let changed = Blocker::ChangedSinceScan;
        let recheck = Binding::Recheck(&recorded);
        assert_eq!(with(ValueState::Present(recorded), recheck), Ok(()));
        assert_eq!(
            with(ValueState::Present(stamp(2)), Binding::Capture),
            Ok(())
        );
        let other_type = ValueStamp { ty: 2, ..recorded };
        let other_len = ValueStamp {
            len: 13,
            ..recorded
        };
        for now in [stamp(2), other_type, other_len] {
            refused(
                with(ValueState::Present(now), recheck),
                changed.clone(),
                reason::VALUE_CHANGED,
            );
        }
        for binding in [Binding::Capture, recheck] {
            refused(
                with(ValueState::Unknown, binding),
                changed.clone(),
                reason::VALUE_UNKNOWN,
            );
            refused(
                with(ValueState::Absent, binding),
                changed.clone(),
                reason::VALUE_MISSING,
            );
        }
    }
    // A key action does not look at the value.
    let target = key(APP_KEY);
    let mut facts = key_facts(&target);
    facts.value = ValueState::Unknown;
    assert_eq!(delete_tree(&target, &facts), Ok(()));
}

// ----- protected descendants ---------------------------------------------------------------------------

fn candidate(id: &str, target: Target, action: Action) -> Candidate {
    let mut value = json!({
        "id": id, "target": {"type": "Path", "path": "C:\\x"},
        "action": "Quarantine",
        "owner": {"program_id": "HKLM|64|Vendor_is1", "display_name": "Vendor App"},
        "origin": "Scanner", "scanner": "FS-INSTALLDIR", "category": "Association",
        "harm": "Low", "reversibility": "Full",
        "size_bytes": null, "child_count": null,
        "decision": {"band": "Safe", "preselected": true, "score": 9, "explanation": ""}
    });
    value["target"] = serde_json::to_value(&target).unwrap();
    value["action"] = serde_json::to_value(action).unwrap();
    serde_json::from_value(value).unwrap()
}

fn banded(mut candidate: Candidate, band: Band) -> Candidate {
    candidate.decision.as_mut().unwrap().band = band;
    candidate.decision.as_mut().unwrap().preselected = false;
    candidate
}

fn blocked(mut candidate: Candidate, blocker: Blocker) -> Candidate {
    candidate.blockers.push(blocker);
    banded(candidate, Band::Blocked)
}

/// The M1a review requirement: a ticked whole-tree parent with a Blocked item below it is refused.
#[test]
fn a_whole_tree_removal_does_not_take_a_protected_item_with_it() {
    let parent = banded(
        candidate("dir", path_target(APP), Action::Quarantine),
        Band::Likely,
    );
    let below = |name: &str| path_target(&format!(r"{APP}\{name}"));
    let safe = candidate("safe", below(r"bin\app.dll"), Action::Quarantine);
    let likely = banded(
        candidate("likely", below("data"), Action::Quarantine),
        Band::Likely,
    );
    assert_eq!(
        check_protected_descendants(&parent, [&parent, &safe, &likely]),
        Ok(())
    );
    assert_eq!(check_protected_descendants(&parent, []), Ok(()));

    // Each blocker the collapse pass lets through (docs/DECISIONS.md), and one it does not.
    for blocker in [
        Blocker::SharedRefcount,
        Blocker::ExistedBeforeInstall,
        Blocker::WindowsBaseline,
        Blocker::MicrosoftSystemTarget,
        Blocker::TrustedInstallerOwned,
        Blocker::DenyListed {
            rule: "fs.windir".into(),
        },
        Blocker::SharedIid,
        Blocker::ReferencedByOtherApp {
            app: "Other".into(),
        },
    ] {
        let protected = blocked(
            candidate("kept", below(r"shared\common.dll"), Action::ReportOnly),
            blocker.clone(),
        );
        let verdict = check_protected_descendants(&parent, [&safe, &protected, &likely]);
        assert_softness(&verdict);
        refused(verdict, blocker.clone(), reason::PROTECTED_DESCENDANT);
        // Deep below, and in another spelling of the case.
        let mut deep = protected.clone();
        deep.target = path_target(&format!(r"{}\A\B\C\common.dll", APP.to_uppercase()));
        let verdict = check_protected_descendants(&parent, [&deep]);
        refused(verdict, blocker, reason::PROTECTED_DESCENDANT);
    }

    // A hard blocker counts whatever the band says; a Blocked band counts without one; an undecided
    // candidate was never cleared.
    let mut hard_but_safe = safe.clone();
    hard_but_safe.blockers.push(Blocker::WindowsBaseline);
    refused(
        check_protected_descendants(&parent, [&hard_but_safe]),
        Blocker::WindowsBaseline,
        reason::PROTECTED_DESCENDANT,
    );
    let band_only = banded(safe.clone(), Band::Blocked);
    let mut undecided = safe.clone();
    undecided.decision = None;
    for protected in [&band_only, &undecided] {
        let verdict = check_protected_descendants(&parent, [protected]);
        assert_softness(&verdict);
        let (rule, why) = deny_rule(verdict);
        assert_eq!((rule.as_str(), why), (reason::PROTECTED_DESCENDANT, why));
    }
    // A soft blocker below does not protect (the collapse pass has dealt with those).
    let mut soft = likely.clone();
    soft.blockers.push(Blocker::UserData);
    assert_eq!(check_protected_descendants(&parent, [&soft]), Ok(()));

    // Not below: a sibling that shares a string prefix, the parent's parent, the parent itself.
    let protect = |target: Target| {
        blocked(
            candidate("kept", target, Action::ReportOnly),
            Blocker::WindowsBaseline,
        )
    };
    let sibling = protect(path_target(r"C:\Program Files\Vendor\App2\x.dll"));
    let above = protect(path_target(r"C:\Program Files\Vendor"));
    let itself = protect(path_target(APP));
    let a_key = protect(key(APP_KEY));
    assert_eq!(
        check_protected_descendants(&parent, [&sibling, &above, &itself, &a_key]),
        Ok(())
    );
}

#[test]
fn protected_registry_items_below_a_key_delete() {
    let parent = banded(
        candidate("key", key(APP_KEY), Action::DeleteKey),
        Band::Likely,
    );
    let protect = |target: Target| {
        blocked(
            candidate("kept", target, Action::ReportOnly),
            Blocker::SharedRefcount,
        )
    };
    let refuses = [
        protect(key(r"HKLM\SOFTWARE\Vendor\App\Shared")),
        protect(key(r"hklm\software\vendor\app\a\b")),
        protect(value(r"HKLM\SOFTWARE\Vendor\App\Shared", "x")),
        // A value lies inside its own key.
        protect(value(APP_KEY, "SharedDll")),
        protect(segment(APP_KEY, "Paths", r"C:\x")),
    ];
    for protected in &refuses {
        refused(
            check_protected_descendants(&parent, [protected]),
            Blocker::SharedRefcount,
            reason::PROTECTED_DESCENDANT,
        );
    }
    let passes = [
        protect(key(r"HKLM\SOFTWARE\Vendor\App2")),
        protect(key(r"HKLM\SOFTWARE\Vendor")),
        protect(key(APP_KEY)),
        protect(value(r"HKLM\SOFTWARE\Vendor", "App")),
        protect(key(r"HKLM\SOFTWARE\WOW6432Node\Vendor\App\Shared")),
        protect(path_target(FILE)),
    ];
    assert_eq!(check_protected_descendants(&parent, &passes), Ok(()));
}

#[test]
fn actions_that_remove_no_tree_are_not_concerned() {
    let protected = [
        blocked(
            candidate(
                "kept",
                path_target(&format!(r"{APP}\keep.dll")),
                Action::ReportOnly,
            ),
            Blocker::WindowsBaseline,
        ),
        blocked(
            candidate("kept2", value(APP_KEY, "x"), Action::ReportOnly),
            Blocker::WindowsBaseline,
        ),
    ];
    let narrow = [
        candidate("a", path_target(APP), Action::RemoveDirIfEmpty),
        candidate("b", path_target(APP), Action::ReportOnly),
        candidate("c", value(APP_KEY, "x"), Action::DeleteValue),
        candidate("d", segment(APP_KEY, "x", "y"), Action::EditSegment),
        // A mismatched pair removes nothing as a tree either; the gates refuse it elsewhere.
        candidate("e", key(APP_KEY), Action::Quarantine),
        candidate("f", path_target(APP), Action::DeleteKey),
    ];
    for selected in &narrow {
        assert_eq!(
            check_protected_descendants(selected, &protected),
            Ok(()),
            "{:?}",
            selected.id
        );
    }
    for selected in [
        candidate("g", path_target(APP), Action::Quarantine),
        candidate("h", key(APP_KEY), Action::DeleteKey),
    ] {
        assert!(check_protected_descendants(&selected, &protected).is_err());
    }
}

// ----- the own store -----------------------------------------------------------------------------------

const SESSION: &str = r"C:\ProgramData\Purge\sessions\20261115T101500Z-9f3a";
const Q_C: &str = r"C:\ProgramData\Purge\Quarantine\20261115T101500Z-9f3a";
const Q_D: &str = r"D:\.purge-q\20261115T101500Z-9f3a";

fn scope() -> StoreScope {
    StoreScope {
        session_dir: SESSION.into(),
        quarantine_dirs: vec![Q_C.into(), Q_D.into()],
    }
}

#[test]
fn the_store_exemption_reaches_only_inside_the_session() {
    let scope = scope();
    for inside in [
        format!(r"{SESSION}\journal.jsonl"),
        format!(r"{SESSION}\reg\0007.regbackup.json"),
        format!(r"{Q_C}\0001\App"),
        format!(r"{Q_C}\0001\App\bin\app.dll"),
        format!(r"{Q_D}\0002\data"),
        format!(r"\\?\{}\0002\DATA", Q_D.to_lowercase()),
        Q_C.replace('\\', "/") + "/0001",
    ] {
        assert!(scope.authorises(&inside), "{inside}");
        // The deny-list itself keeps refusing all of it: the exemption is this function alone.
        assert!(
            LIST.denying_rule(&path_target(&inside), &none()).is_some(),
            "{inside}"
        );
    }
    for outside in [
        SESSION.to_owned(),
        Q_C.to_owned(),
        Q_D.to_owned(),
        r"C:\ProgramData\Purge".to_owned(),
        r"C:\ProgramData\Purge\sessions".to_owned(),
        r"C:\ProgramData\Purge\sessions\index.json".to_owned(),
        r"C:\ProgramData\Purge\sessions\20261114T090000Z-0001\journal.jsonl".to_owned(),
        r"C:\ProgramData\Purge\Quarantine\20261114T090000Z-0001\0001\App".to_owned(),
        format!(r"{Q_C}-old\0001\App"),
        format!(r"{Q_C}\..\20261114T090000Z-0001\0001\App"),
        format!(r"{Q_C}\0001\App."),
        format!(r"{Q_C}\0001\App:stream"),
        r"C:\Program Files\Purge\purge-engine.exe".to_owned(),
        r"D:\.purge-q".to_owned(),
        r"E:\.purge-q\20261115T101500Z-9f3a\0001\x".to_owned(),
        r"%ProgramData%\Purge\Quarantine\20261115T101500Z-9f3a\0001\App".to_owned(),
        r"\\server\share\x".to_owned(),
        FILE.to_owned(),
        String::new(),
    ] {
        assert!(!scope.authorises(&outside), "{outside}");
    }
    // A scope that names too much, or nothing usable, authorises nothing.
    for dir in [r"C:\", r"C:\ProgramData", r"D:\.purge-q", "", r"sessions\x"] {
        let wide = StoreScope {
            session_dir: dir.into(),
            quarantine_dirs: vec![dir.into()],
        };
        assert!(!wide.authorises(r"C:\ProgramData\Purge\x"), "{dir}");
        assert!(!wide.authorises(r"D:\.purge-q\s\1\x"), "{dir}");
        assert!(!wide.authorises(FILE), "{dir}");
    }
    assert!(!StoreScope::default().authorises(&format!(r"{Q_C}\0001\App")));
}

fn store_item(path: &str, op: StoreOp, facts: &PathFacts, recorded: Option<&PathStamp>) -> Verdict {
    let check = StoreCheck {
        path,
        op,
        binding: recorded.map_or(Binding::Capture, Binding::Recheck),
        volume_serial: SERIAL,
    };
    let verdict = check_store_item(&check, facts, &scope());
    assert_softness(&verdict);
    verdict
}

#[test]
fn store_items_are_checked_on_the_handle() {
    let item = format!(r"{Q_C}\0001\App");
    let facts = dir_facts(&item);
    let recorded = facts.stamp().unwrap();
    for op in [StoreOp::MoveBack, StoreOp::Descend, StoreOp::Remove] {
        assert_eq!(store_item(&item, op, &facts, Some(&recorded)), Ok(()));
    }
    // Inner entries have no recorded identity; a move back always needs one.
    assert_eq!(store_item(&item, StoreOp::Descend, &facts, None), Ok(()));
    assert_eq!(store_item(&item, StoreOp::Remove, &facts, None), Ok(()));
    let (_, why) = deny_rule(store_item(&item, StoreOp::MoveBack, &facts, None));
    assert_eq!(why, reason::STORE_NEEDS_IDENTITY);
    // The facts the plan gate needs beyond the handle's are not asked for here.
    let bare = PathFacts {
        volume: None,
        owner_is_ti: None,
        explicit_ti_ace: None,
        n_links: None,
        tree: None,
        ..facts.clone()
    };
    assert_eq!(
        store_item(&item, StoreOp::MoveBack, &bare, Some(&recorded)),
        Ok(())
    );

    // Outside the session: refused before any fact is looked at.
    for outside in [
        Q_C,
        r"C:\ProgramData\Purge\Quarantine\other\0001\App",
        r"C:\ProgramData\Purge\sessions\index.json",
        FILE,
        r"C:\Windows\System32\x.dll",
    ] {
        let got = deny_rule(store_item(
            outside,
            StoreOp::Remove,
            &dir_facts(outside),
            None,
        ));
        assert_eq!(got, ("fs.purge".to_owned(), reason::OUTSIDE_STORE));
    }

    // The handle is somewhere else (a junction planted on the way), or nowhere known.
    for (final_path, why) in [
        (Some(long(r"C:\Windows\System32")), reason::FINAL_DIFFERS),
        (
            Some(long(&format!(r"{Q_C}\0002\App"))),
            reason::FINAL_DIFFERS,
        ),
        (
            Some(r"\\?\Volume{6f2e4b0a-0000-0000-0000-100000000000}\x".to_owned()),
            reason::FINAL_NOT_A_DRIVE_PATH,
        ),
        (None, reason::FINAL_UNKNOWN),
    ] {
        let mut moved = facts.clone();
        moved.final_path = final_path;
        for op in [StoreOp::MoveBack, StoreOp::Descend, StoreOp::Remove] {
            refused(
                store_item(&item, op, &moved, Some(&recorded)),
                Blocker::ReparseMismatch,
                why,
            );
        }
    }

    // Unknown and contradictory handle facts.
    let mut unknown = facts.clone();
    unknown.reparse_tag = None;
    refused(
        store_item(&item, StoreOp::Remove, &unknown, None),
        Blocker::ReparseMismatch,
        reason::HANDLE_FACTS_UNKNOWN,
    );
    let mut contradictory = facts.clone();
    contradictory.reparse_tag = Some(JUNCTION);
    refused(
        store_item(&item, StoreOp::Remove, &contradictory, None),
        Blocker::ReparseMismatch,
        reason::HANDLE_FACTS_CONTRADICT,
    );

    // Identity: unknown, on another volume, changed.
    let mut no_id = facts.clone();
    no_id.identity = None;
    refused(
        store_item(&item, StoreOp::Remove, &no_id, None),
        Blocker::ReparseMismatch,
        reason::IDENTITY_UNKNOWN,
    );
    let mut other_volume = facts.clone();
    other_volume.identity.as_mut().unwrap().volume_serial = SERIAL ^ 1;
    refused(
        store_item(&item, StoreOp::Descend, &other_volume, None),
        Blocker::ReparseMismatch,
        reason::STORE_OTHER_VOLUME,
    );
    let mut swapped = facts.clone();
    swapped.identity = Some(identity(9));
    for op in [StoreOp::MoveBack, StoreOp::Descend, StoreOp::Remove] {
        refused(
            store_item(&item, op, &swapped, Some(&recorded)),
            Blocker::ChangedSinceScan,
            reason::IDENTITY_CHANGED,
        );
    }
}

/// Expiry never crosses a link: a link in the store is removed as the link, never listed or moved.
#[test]
fn a_link_in_the_store_is_only_ever_removed_as_itself() {
    let link = format!(r"{Q_C}\0001\App\planted");
    let mut facts = dir_facts(&link);
    facts.reparse_tag = Some(JUNCTION);
    facts.attributes = Some(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT);
    let recorded = facts.stamp().unwrap();
    assert_eq!(store_item(&link, StoreOp::Remove, &facts, None), Ok(()));
    for op in [StoreOp::Descend, StoreOp::MoveBack] {
        refused(
            store_item(&link, op, &facts, Some(&recorded)),
            Blocker::ReparseMismatch,
            reason::ITEM_IS_REPARSE_POINT,
        );
    }
    // Even for a removal the handle must be the link's own.
    facts.final_path = Some(long(r"C:\Users\tester\Documents"));
    refused(
        store_item(&link, StoreOp::Remove, &facts, None),
        Blocker::ReparseMismatch,
        reason::FINAL_DIFFERS,
    );
    // A file cannot be listed.
    let file = format!(r"{Q_C}\0001\App\app.dll");
    refused(
        store_item(&file, StoreOp::Descend, &file_facts(&file), None),
        Blocker::ChangedSinceScan,
        reason::NOT_A_DIRECTORY,
    );
}

fn destination_facts(parent: &str) -> DestinationFacts {
    DestinationFacts {
        parent_final_path: Some(long(parent)),
        parent_reparse_tag: Some(0),
        parent_is_dir: Some(true),
        parent_volume_serial: Some(SERIAL),
        occupied: Some(false),
    }
}

fn to_quarantine(source: &str, destination: &str, facts: &DestinationFacts) -> Verdict {
    let check = QuarantineCheck {
        source,
        source_volume_serial: Some(SERIAL),
        destination,
    };
    let verdict = check_quarantine_destination(&check, facts, &scope());
    assert_softness(&verdict);
    verdict
}

#[test]
fn a_quarantine_move_goes_into_the_session_on_the_same_volume() {
    let op_dir = format!(r"{Q_C}\0001");
    let destination = format!(r"{op_dir}\App");
    let facts = destination_facts(&op_dir);
    assert_eq!(to_quarantine(APP, &destination, &facts), Ok(()));
    let on_d = format!(r"{Q_D}\0002");
    assert_eq!(
        to_quarantine(
            r"D:\Games\Vendor",
            &format!(r"{on_d}\Vendor"),
            &destination_facts(&on_d)
        ),
        Ok(())
    );

    // Not `<quarantine dir of the session>\<op>\<leaf>`.
    for elsewhere in [
        Q_C.to_owned(),
        op_dir.clone(),
        format!(r"{SESSION}\0001\App"),
        r"C:\ProgramData\Purge\Quarantine\other-session\0001\App".to_owned(),
        r"C:\ProgramData\Purge\App".to_owned(),
        r"C:\Users\tester\AppData\Local\Temp\q\0001\App".to_owned(),
        r"C:\Windows\Temp\App".to_owned(),
        format!(r"{op_dir}\..\..\x\App"),
        format!(r"{op_dir}\App."),
        String::new(),
    ] {
        let parent = prefix::parent(&elsewhere).unwrap_or_default().to_owned();
        let (_, why) = deny_rule(to_quarantine(APP, &elsewhere, &destination_facts(&parent)));
        assert_eq!(why, reason::QUARANTINE_OUTSIDE_STORE, "{elsewhere}");
    }

    // The source is in the store, contains it, or does not canonicalise.
    for source in [
        format!(r"{Q_C}\0003\Other"),
        format!(r"{SESSION}\journal.jsonl"),
        r"C:\ProgramData".to_owned(),
        Q_D.to_owned(),
        r"Vendor\App".to_owned(),
    ] {
        let (_, why) = deny_rule(to_quarantine(&source, &destination, &facts));
        assert_eq!(why, reason::QUARANTINE_OVERLAP, "{source}");
    }

    // Another volume: by drive letter, by serial, or not known.
    let other = Blocker::CannotBackUp;
    refused(
        to_quarantine(r"D:\Games\Vendor", &destination, &facts),
        other.clone(),
        reason::QUARANTINE_OTHER_VOLUME,
    );
    for serial in [Some(SERIAL + 1), None] {
        let mut facts = facts.clone();
        facts.parent_volume_serial = serial;
        refused(
            to_quarantine(APP, &destination, &facts),
            other.clone(),
            reason::QUARANTINE_OTHER_VOLUME,
        );
    }
    let unknown_source = QuarantineCheck {
        source: APP,
        source_volume_serial: None,
        destination: &destination,
    };
    refused(
        check_quarantine_destination(&unknown_source, &facts, &scope()),
        other.clone(),
        reason::QUARANTINE_OTHER_VOLUME,
    );

    // The parent is not the plain directory the path names.
    type Spoil = fn(&mut DestinationFacts);
    let spoils: [Spoil; 7] = [
        |f| f.parent_final_path = None,
        |f| f.parent_final_path = Some(long(r"C:\Users\tester\Desktop")),
        |f| {
            f.parent_final_path = Some(r"\\?\Volume{6f2e4b0a-0000-0000-0000-100000000000}\x".into())
        },
        |f| f.parent_reparse_tag = Some(JUNCTION),
        |f| f.parent_reparse_tag = None,
        |f| f.parent_is_dir = Some(false),
        |f| f.parent_is_dir = None,
    ];
    for spoil in spoils {
        let mut facts = facts.clone();
        spoil(&mut facts);
        refused(
            to_quarantine(APP, &destination, &facts),
            Blocker::ReparseMismatch,
            reason::QUARANTINE_PARENT,
        );
    }

    // A move never overwrites.
    for occupied in [Some(true), None] {
        let mut facts = facts.clone();
        facts.occupied = occupied;
        refused(
            to_quarantine(APP, &destination, &facts),
            other.clone(),
            reason::QUARANTINE_OCCUPIED,
        );
    }
}

// ----- undo --------------------------------------------------------------------------------------------

fn undo_to(original: &str, facts: &DestinationFacts) -> Verdict {
    let check = UndoPathCheck {
        original,
        volume_serial: SERIAL,
        exemptions: none(),
    };
    let verdict = check_undo_path(&check, facts, &LIST);
    assert_softness(&verdict);
    verdict
}

#[test]
fn an_item_is_moved_back_only_to_its_plain_original_place() {
    let parent = r"C:\Program Files\Vendor";
    let facts = destination_facts(parent);
    assert_eq!(undo_to(APP, &facts), Ok(()));
    assert_eq!(undo_to(&long(APP), &facts), Ok(()));
    // An item directly in a drive root has the root as its parent.
    assert_eq!(undo_to(r"C:\Vendor", &destination_facts(r"C:\")), Ok(()));

    // The acceptance case: an undo destination under Purge's own directories, and other protected places.
    for (original, rule) in [
        (r"C:\ProgramData\Purge\Quarantine\s\0001\App", "fs.purge"),
        (r"C:\ProgramData\Purge\sessions\index.json", "fs.purge"),
        (r"C:\Program Files\Purge\purge-engine.exe", "fs.purge"),
        (r"D:\.purge-q\s\0001\App", "fs.purge"),
        (r"C:\Windows\System32\app.dll", "fs.windir"),
        (r"C:\", "fs.drive-root"),
    ] {
        let parent = parent_dir(original).unwrap_or_else(|| r"C:\".into());
        let got = deny_rule(undo_to(original, &destination_facts(&parent)));
        assert_eq!(got, (rule.to_owned(), reason::DENY_LEXICAL), "{original}");
    }
    for (original, rule) in [
        (r"C:\Vendor\..\Windows\x", "canon.dot-segment"),
        (r"%ProgramFiles%\Vendor\App", "canon.env-token"),
        (r"\\server\share\App", "canon.unc"),
        (r"C:\Vendor\App.", "canon.trailing-dot-or-space"),
    ] {
        let got = deny_rule(undo_to(original, &facts));
        assert_eq!(
            got,
            (rule.to_owned(), reason::LEXICAL_NOT_CANONICAL),
            "{original}"
        );
    }

    // The parent has become a reparse point, or resolves elsewhere, or is not known.
    type Spoil = fn(&mut DestinationFacts);
    let spoils: [Spoil; 8] = [
        |f| f.parent_reparse_tag = Some(JUNCTION),
        |f| f.parent_reparse_tag = Some(SYMLINK),
        |f| f.parent_reparse_tag = None,
        |f| f.parent_final_path = Some(long(r"C:\Windows\System32")),
        |f| f.parent_final_path = Some(long(r"C:\Program Files\Vendor\App")),
        |f| f.parent_final_path = None,
        |f| f.parent_is_dir = Some(false),
        |f| f.parent_is_dir = None,
    ];
    for spoil in spoils {
        let mut facts = facts.clone();
        spoil(&mut facts);
        refused(
            undo_to(APP, &facts),
            Blocker::ReparseMismatch,
            reason::UNDO_PARENT,
        );
    }

    for serial in [Some(SERIAL + 1), None] {
        let mut facts = facts.clone();
        facts.parent_volume_serial = serial;
        refused(
            undo_to(APP, &facts),
            Blocker::CannotBackUp,
            reason::UNDO_OTHER_VOLUME,
        );
    }
    // Something is there already: a conflict, skipped and reported.
    for occupied in [Some(true), None] {
        let mut facts = facts.clone();
        facts.occupied = occupied;
        refused(
            undo_to(APP, &facts),
            Blocker::ChangedSinceScan,
            reason::UNDO_OCCUPIED,
        );
    }
}

fn undo_key_facts(target: &Target, node: KeyNode) -> UndoKeyFacts {
    UndoKeyFacts {
        node,
        ancestors: key_facts(target).ancestors,
    }
}

fn undo_key(target: &Target, facts: &UndoKeyFacts) -> Verdict {
    let verdict = check_undo_key(target, facts, &LIST, &none());
    assert_softness(&verdict);
    verdict
}

#[test]
fn a_key_is_restored_only_below_plain_ancestors() {
    let target = key(r"HKLM\SOFTWARE\WOW6432Node\Vendor\App");
    for node in [KeyNode::Missing, KeyNode::Plain] {
        assert_eq!(undo_key(&target, &undo_key_facts(&target, node)), Ok(()));
    }
    let in_key = value(APP_KEY, "InstallDir");
    assert_eq!(
        undo_key(&in_key, &undo_key_facts(&in_key, KeyNode::Plain)),
        Ok(())
    );
    for (node, why) in [
        (KeyNode::Link, reason::KEY_IS_LINK),
        (KeyNode::Unknown, reason::KEY_LINK_UNKNOWN),
    ] {
        refused(
            undo_key(&target, &undo_key_facts(&target, node)),
            Blocker::RegLink,
            why,
        );
    }
    refused(
        undo_key(&target, &UndoKeyFacts::default()),
        Blocker::RegLink,
        reason::KEY_LINK_UNKNOWN,
    );

    let clean = undo_key_facts(&target, KeyNode::Missing);
    for i in 0..clean.ancestors.len() {
        for (node, why) in [
            (KeyNode::Link, reason::ANCESTOR_IS_LINK),
            (KeyNode::Unknown, reason::ANCESTOR_UNKNOWN),
        ] {
            let mut facts = clean.clone();
            facts.ancestors[i].node = node;
            refused(undo_key(&target, &facts), Blocker::RegLink, why);
        }
        let mut facts = clean.clone();
        facts.ancestors.remove(i);
        refused(
            undo_key(&target, &facts),
            Blocker::RegLink,
            reason::ANCESTOR_UNKNOWN,
        );
    }

    // The vendor key went with the app: it and everything below it is missing, and that is fine.
    let mut gone = clean.clone();
    gone.ancestors[2].node = KeyNode::Missing;
    assert_eq!(undo_key(&target, &gone), Ok(()));
    gone.ancestors[1].node = KeyNode::Missing;
    assert_eq!(undo_key(&target, &gone), Ok(()));
    // A key below a missing ancestor cannot exist.
    let mut hole = clean.clone();
    hole.ancestors[1].node = KeyNode::Missing;
    refused(
        undo_key(&target, &hole),
        Blocker::RegLink,
        reason::ANCESTORS_CONTRADICT,
    );
    let mut ghost = undo_key_facts(&target, KeyNode::Plain);
    ghost.ancestors[2].node = KeyNode::Missing;
    refused(
        undo_key(&target, &ghost),
        Blocker::RegLink,
        reason::ANCESTORS_CONTRADICT,
    );

    // G2 on the destination as it is now.
    for (denied, why) in [
        (
            key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            reason::DENY_KEY,
        ),
        (key(r"HKCR\vendor.file"), reason::KEY_NOT_CANONICAL),
        (
            key(r"HKU\S-1-5-21-1-2-3-4444\Software\Vendor"),
            reason::DENY_KEY,
        ),
    ] {
        let (_, got) = deny_rule(undo_key(
            &denied,
            &undo_key_facts(&denied, KeyNode::Missing),
        ));
        assert_eq!(got, why, "{denied:?}");
    }
    let toasts =
        key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts");
    refused(
        undo_key(&toasts, &undo_key_facts(&toasts, KeyNode::Missing)),
        Blocker::StructuralContainer,
        reason::STRUCTURAL_CONTAINER,
    );
    for not_restorable in [
        path_target(FILE),
        Target::RegValueChanged {
            path: APP_KEY.into(),
            name: "x".into(),
            before: String::new(),
            after: String::new(),
        },
    ] {
        let facts = undo_key_facts(&key(APP_KEY), KeyNode::Missing);
        let (_, why) = deny_rule(undo_key(&not_restorable, &facts));
        assert_eq!(why, reason::OP_TARGET_MISMATCH);
    }
    // The exemption the item had when it was removed is honoured on the way back.
    let environment = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    let edit = segment(environment, "Path", r"C:\Program Files\Vendor\App\bin");
    let facts = undo_key_facts(&edit, KeyNode::Plain);
    assert!(undo_key(&edit, &facts).is_err());
    let earned = Exemptions {
        environment_segment_edit: true,
        ..none()
    };
    assert_eq!(check_undo_key(&edit, &facts, &LIST, &earned), Ok(()));
}

// ----- boot-time moves ---------------------------------------------------------------------------------

fn chain_of(path: &str) -> Vec<AncestorWrite> {
    let mut chain = Vec::new();
    let mut at = Some(path.to_owned());
    while let Some(path) = at {
        at = parent_dir(&path);
        chain.push(AncestorWrite {
            path,
            admin_only: Some(true),
            reparse: Some(false),
        });
    }
    chain
}

#[test]
fn a_boot_move_needs_an_admin_only_chain() {
    let chain = chain_of(FILE);
    let paths: Vec<&str> = chain.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            FILE,
            r"C:\Program Files\Vendor\App\bin",
            APP,
            r"C:\Program Files\Vendor",
            r"C:\Program Files",
            r"C:\"
        ]
    );
    assert_eq!(admin_only_ancestors(FILE, &chain), BootMove::Allowed);
    assert_eq!(admin_only_ancestors(&long(FILE), &chain), BootMove::Allowed);
    let mut respelled = chain.clone();
    respelled.reverse();
    for fact in &mut respelled {
        fact.path = long(&fact.path.to_lowercase());
    }
    assert_eq!(admin_only_ancestors(FILE, &respelled), BootMove::Allowed);

    for i in 0..chain.len() {
        type Spoil = fn(&mut AncestorWrite);
        let spoils: [(Spoil, &str); 5] = [
            (|f| f.admin_only = Some(false), "live.boot.user-writable"),
            (|f| f.admin_only = None, "live.boot.fact-unknown"),
            (|f| f.reparse = Some(true), "live.boot.reparse-point"),
            (|f| f.reparse = None, "live.boot.fact-unknown"),
            (
                |f| {
                    f.admin_only = Some(false);
                    f.reparse = Some(true);
                },
                "live.boot.reparse-point",
            ),
        ];
        for (spoil, why) in spoils {
            let mut chain = chain.clone();
            spoil(&mut chain[i]);
            assert_eq!(
                admin_only_ancestors(FILE, &chain),
                BootMove::Hold(why),
                "component {i}"
            );
            // A good fact for the same component does not outvote a bad one.
            chain.push(chain_of(FILE)[i].clone());
            assert_eq!(admin_only_ancestors(FILE, &chain), BootMove::Hold(why));
        }
        // A component without a fact: the item itself and the drive root included.
        let mut chain = chain.clone();
        chain.remove(i);
        assert_eq!(
            admin_only_ancestors(FILE, &chain),
            BootMove::Hold("live.boot.chain-incomplete"),
            "component {i}"
        );
    }
    assert_eq!(
        admin_only_ancestors(FILE, &[]),
        BootMove::Hold("live.boot.chain-incomplete")
    );
    // Facts about another path do not count for this one.
    assert_eq!(
        admin_only_ancestors(
            FILE,
            &chain_of(r"C:\Program Files\Vendor\App\bin\other.dll")
        ),
        BootMove::Hold("live.boot.fact-off-chain")
    );
    let mut stray = chain.clone();
    stray.push(AncestorWrite {
        path: "C:".into(),
        admin_only: Some(true),
        reparse: Some(false),
    });
    assert_eq!(
        admin_only_ancestors(FILE, &stray),
        BootMove::Hold("live.boot.fact-off-chain")
    );
    for source in [r"bin\app.dll", r"C:\Vendor\..\x", r"\\server\share\x", ""] {
        assert_eq!(
            admin_only_ancestors(source, &chain),
            BootMove::Hold("live.boot.source-not-canonical"),
            "{source}"
        );
    }
}

// ----- the module as a whole ---------------------------------------------------------------------------

#[test]
fn a_refusal_reads_as_its_blocker_and_reason() {
    let refusal = quarantine(FILE, &PathFacts::default()).unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "ReparseMismatch (live.g1.final-unknown)"
    );
    assert_eq!(Blocker::from(refusal), Blocker::ReparseMismatch);
}

/// Acceptance: the module does no I/O and does not know `purge-win`.
#[test]
fn the_module_is_pure() {
    let source = include_str!("../live.rs");
    for forbidden in [
        "std::fs",
        "std::env",
        "std::process",
        "purge_win",
        "std::net",
    ] {
        assert!(!source.contains(forbidden), "live.rs mentions {forbidden}");
    }
}
