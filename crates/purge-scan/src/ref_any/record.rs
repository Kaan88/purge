//! Record-like `REG_MULTI_SZ` values for REF-ANY (see the module documentation of `ref_any`).
//!
//! A `REG_MULTI_SZ` value in which some entries refer to the app and others do not is either a list,
//! from which the app's entries can be taken out, or a record, whose entries are fields of one thing.
//! [`record_refs`] tells the two apart by shape and [`offer`] offers a record as the one unit it is.

use purge_guard::prefix;
use purge_index::matcher::RefMatcher;
use purge_model::{Action, Blocker, Candidate, Category, Evidence, Target};
use purge_source::types::{REG_MULTI_SZ, RegValue};

use super::ID;
use crate::framework::{AppIdentityView, ScanCtx};
use crate::reg_software::common::{self, Foreign, Segment, ValueRefs};

/// The longest file extension [`path_kind`] takes for one.
const EXTENSION_MAX: usize = 10;

/// Whether `entry` starts like a path: a drive path, a UNC path or a `%NAME%` reference.
fn looks_like_path(entry: &str) -> bool {
    let bytes = entry.as_bytes();
    entry.starts_with('%')
        || entry.starts_with(r"\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

/// What kind of thing the path `entry` names, for "all entries are of one kind": the folded extension
/// of its last component, or nothing for a name without one (a directory).
fn path_kind(entry: &str) -> String {
    let leaf = entry
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default();
    match leaf.rsplit_once('.') {
        Some((stem, ext))
            if !stem.is_empty()
                && !ext.is_empty()
                && ext.len() <= EXTENSION_MAX
                && ext.chars().all(char::is_alphanumeric) =>
        {
            prefix::fold(ext)
        }
        _ => String::new(),
    }
}

/// Whether the (non-empty, trimmed) entries of a `REG_MULTI_SZ` value form a list, i.e. each stands for
/// itself and one can be taken out: at least two entries, every one a path, all of one kind (see
/// [`path_kind`]). A value that mixes kinds (a shortcut, an executable, an argument string) is a
/// record. The test errs towards "record": a record is never edited by entry.
fn is_list(entries: &[&str]) -> bool {
    let mut kinds = entries.iter().map(|entry| {
        let entry = entry.trim_matches('"');
        looks_like_path(entry).then(|| path_kind(entry))
    });
    match kinds.next() {
        Some(Some(first)) => {
            entries.len() >= 2 && kinds.all(|kind| kind.as_deref() == Some(first.as_str()))
        }
        _ => false,
    }
}

/// The kind of one entry for "is this entry a peer of that one": whether it is a path, and the kind of
/// the thing it names ([`path_kind`]; for an entry that is no path, the extension of a bare file name).
fn entry_kind(entry: &str) -> (bool, String) {
    let entry = entry.trim_matches('"');
    (looks_like_path(entry), path_kind(entry))
}

/// A record-like `REG_MULTI_SZ` value of which some entries, not all, refer to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordRefs {
    /// The entries that refer to the app.
    entries: Vec<Segment>,
    /// The entries that do not, trimmed.
    others: Vec<String>,
}

impl RecordRefs {
    /// How many entries do not refer to the app.
    fn unmatched(&self) -> u32 {
        u32::try_from(self.others.len()).unwrap_or(u32::MAX)
    }

    /// Whether an entry that does not refer to the app is of the same kind as one that does (two
    /// directories, two `.exe` files, two bare words): the value then holds the app's entry next to
    /// its like, as a list does, whatever else is in it.
    fn has_peers(&self) -> bool {
        self.others.iter().any(|other| {
            let (is_path, kind) = entry_kind(other);
            self.entries.iter().any(|own| {
                let (own_is_path, own_kind) = entry_kind(&own.text);
                // A bare file name is the like of a path to a file of that extension.
                own_kind == kind && (own_is_path == is_path || !kind.is_empty())
            })
        })
    }
}

/// The file-system paths the entry `text` may name: the entry itself (its quoted head, when it starts
/// with a quote) and every head of it that ends in a file name before a space (a path followed by
/// arguments). Empty for an entry that is no path. `None` when the entry is a path that cannot be
/// resolved (a `%NAME%` the environment does not know).
fn named_paths(ctx: &ScanCtx<'_>, text: &str) -> Option<Vec<String>> {
    let expanded = common::expand_env(text.trim(), ctx.env);
    let (head, quoted) = match expanded.strip_prefix('"') {
        Some(rest) => (rest.split('"').next().unwrap_or_default(), true),
        None => (expanded.as_str(), false),
    };
    if !looks_like_path(head) {
        return Some(Vec::new());
    }
    if let Some(name) = head.strip_prefix('%') {
        // An unknown `%NAME%` before a separator is a path nobody here can test; `%1` is an argument.
        let unresolved = name
            .split_once('%')
            .is_some_and(|(name, rest)| !name.is_empty() && rest.starts_with(['\\', '/']));
        return (!unresolved).then(Vec::new);
    }
    let mut paths = vec![head.to_owned()];
    if !quoted {
        for (at, _) in head.match_indices(' ') {
            let cut = &head[..at];
            if !path_kind(cut).is_empty() {
                paths.push(cut.to_owned());
            }
        }
    }
    Some(paths)
}

/// Whether every entry of the record that does not refer to the app is dead or no path at all: each
/// path it may name ([`named_paths`]) is proven absent. An entry that names something that exists, or
/// whose existence cannot be told, is content of the value that is not the app's.
fn others_are_dead(ctx: &ScanCtx<'_>, record: &RecordRefs) -> bool {
    record.others.iter().all(|other| {
        named_paths(ctx, other)
            .is_some_and(|paths| paths.iter().all(|path| ctx.fs.exists(path).is_absent()))
    })
}

/// Tells whether `value` is a complete `REG_MULTI_SZ` value that refers to the app in some entries
/// only and is not a list: such a value is one unit. `None` for every other value (a string, a list,
/// a value that is the app's by its name or in all its entries), which `common::offer_value` handles.
pub(super) fn record_refs(refs: &RefMatcher, value: &RegValue) -> Option<RecordRefs> {
    if value.data.ty != REG_MULTI_SZ || !value.data.is_complete() {
        return None;
    }
    let Some(ValueRefs::Segments(segments)) = common::classify(refs, value) else {
        return None;
    };
    let all = value.data.multi_sz()?;
    let entries: Vec<&str> = all
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect();
    if is_list(&entries) {
        return None;
    }
    let others = all
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            !segments
                .iter()
                .any(|s| usize::try_from(s.index).is_ok_and(|i| i == *index))
        })
        .map(|(_, entry)| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect();
    Some(RecordRefs {
        entries: segments,
        others,
    })
}

/// Whether a baseline for exactly this Windows is loaded, so that "not in the baseline" is a fact.
fn has_matching_baseline(ctx: &ScanCtx<'_>) -> bool {
    // A: the machine as it is now decides; the fingerprint's record of it is the fallback.
    ctx.has_matching_exact_baseline()
}

/// What the pre-uninstall reference snapshot says about the entries of the record: the harvest
/// records a reference inside a `REG_MULTI_SZ` value under the entry that holds it, and "this value
/// referred to the app while it was installed" is a fact about the value whichever entry said so. Each
/// entry is put to [`CandidateBuilder::in_ref_snapshot`](crate::framework::CandidateBuilder), so the
/// rules of that evidence (an InstallRoot anchor, the anchor's trust) are the usual ones.
fn snapshot_evidence(
    ctx: &ScanCtx<'_>,
    key: &str,
    value: &RegValue,
    category: Category,
    record: &RecordRefs,
) -> Vec<Evidence> {
    let mut found: Vec<Evidence> = Vec::new();
    for entry in &record.entries {
        let mut probe = ctx.candidate(
            ID,
            Target::RegMultiSzSegment {
                path: key.to_owned(),
                name: value.name.clone(),
                segment: entry.text.clone(),
                index: None,
            },
            Action::EditSegment,
            category,
        );
        if probe.in_ref_snapshot() {
            for evidence in probe.build().evidence {
                if !found.contains(&evidence) {
                    found.push(evidence);
                }
            }
        }
    }
    found
}

/// Offers the record-like `value` of `key` whole, on the evidence of the entries that refer to the app.
///
/// A value that clean Windows has under this name is not offered: the app's record took the place of an
/// older one, so the value existed before the install and is not a leftover, and unlike a list there is
/// no part of it to take out. A slot of a user's numbered-slot store (`UFH\SHC`) counts as one without
/// an exact baseline of this Windows ([`ScanCtx::in_baseline`]), so below Exact no slot is offered. The
/// common blockers apply as to any value (an Inno record of it having existed before the install keeps
/// it).
///
/// The entries that do not refer to the app go with the value, so it is the app's alone only when they
/// are nothing of their own: `UnmatchedChildren` (offered, never preselected) unless
///
/// - a baseline for this Windows is loaded (without one nothing shows the value is newer than Windows),
/// - no such entry is of the kind of an entry that refers to the app ([`RecordRefs::has_peers`]: a list
///   that [`is_list`] did not take for one), and
/// - every such entry is dead or no path ([`others_are_dead`]).
// One parameter per thing the caller varies, as in `common::offer_value`.
#[allow(clippy::too_many_arguments)]
pub(super) fn offer(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    foreign: &Foreign,
    key: &str,
    value: &RegValue,
    category: Category,
    record: &RecordRefs,
    out: &mut Vec<Candidate>,
) {
    let target = Target::RegValue {
        path: key.to_owned(),
        name: value.name.clone(),
    };
    if ctx.in_baseline(&target) || ctx.in_unowned_com_class(key) {
        return;
    }
    let mut b = ctx.candidate(ID, target, Action::DeleteValue, category);
    // The whole value goes: nothing in its name or data may be another app's.
    let other = foreign.in_value(&app.refs, value);
    let matches: Vec<_> = record
        .entries
        .iter()
        .flat_map(|entry| entry.matches.iter().cloned())
        .collect();
    let snapshot = snapshot_evidence(ctx, key, value, category, record);
    if !common::add_value_evidence(ctx, &mut b, &matches, other) && snapshot.is_empty() {
        return;
    }
    if !has_matching_baseline(ctx) || record.has_peers() || !others_are_dead(ctx, record) {
        b.blocker(Blocker::UnmatchedChildren {
            n: record.unmatched(),
        });
    }
    // The entries' evidence stands for the whole value only when everything in the value is the
    // app's: it goes in before `build`, which applies that rule.
    b.evidence_also(snapshot);
    out.push(b.build());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::testkit::*;
    use crate::framework::{OtherApp, OtherApps, Scanner, candidate_id};
    use crate::ref_any::RefAny;
    use purge_guard::canon::GuardEnv;
    use purge_index::baseline::Baseline;
    use purge_index::baseline_view::BaselineView;
    use purge_model::{AnchorKind, AnchorRef, EvidenceKind, RefCarrier, RefSnapEntry, Scope, Tier};
    use purge_source::fixture::{Fixture, FixtureBuilder};

    const SID: &str = GuardEnv::SAMPLE_SID;
    const START_MENU: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";
    const OTHER_ROOT: &str = r"C:\Users\tester\AppData\Local\Programs\Download Manager";

    /// The shell's shortcut-usage key of the user: values `0`, `1`, … each hold one record
    /// `<shortcut>`, `<target>`, `[<arguments>]`.
    fn shc() -> String {
        format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\UFH\SHC")
    }

    fn lnk(name: &str) -> String {
        format!(r"{START_MENU}\Git\{name}.lnk")
    }

    fn exe(rel: &str) -> String {
        format!(r"{GIT_ROOT}\{rel}")
    }

    /// `C:\Program Files` exists on the recorded fixed NTFS volume; Git's directory is gone.
    fn machine() -> FixtureBuilder {
        Fixture::builder()
            .dir(r"C:\Program Files")
            .volume(r"C:\", Some(SERIAL), true, "NTFS")
            .os(EDITION, BUILD, UBR)
    }

    /// What the rig run `git` leaves in `UFH\SHC`: slot `0`, which held another program's record
    /// before the install, and the new slots `1` and `2`.
    fn git_slots() -> FixtureBuilder {
        machine()
            .multi_sz(
                &shc(),
                "0",
                &[&lnk("Git Bash"), &exe("git-bash.exe"), "--cd-to-home"],
            )
            .multi_sz(
                &shc(),
                "1",
                &[&lnk("Git CMD"), &exe("git-cmd.exe"), "--cd-to-home"],
            )
            .multi_sz(&shc(), "2", &[&lnk("Git GUI"), &exe(r"cmd\git-gui.exe")])
    }

    /// A baseline of the test Windows with `REG_MULTI_SZ` values `(key, name)`.
    fn baseline_with_values(values: &[(&str, &str)]) -> BaselineView {
        let mut text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
        for (key, name) in values {
            let key = key.replace('\\', "\\\\");
            text.push_str(&format!("K\t{key}\n"));
            text.push_str(&format!("V\t{key}\t{name}\t7\tf512a6c9a655adb5\n"));
        }
        BaselineView::exact(Baseline::from_bytes(text.as_bytes()).expect("the baseline parses"))
    }

    fn scan(world: &World) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        RefAny.scan(&world.ctx(), &app)
    }

    fn value(key: &str, name: &str) -> Target {
        Target::RegValue {
            path: key.into(),
            name: name.into(),
        }
    }

    fn find<'a>(found: &'a [Candidate], target: &Target) -> Option<&'a Candidate> {
        let id = candidate_id(target);
        found.iter().find(|c| c.id == id)
    }

    fn expect<'a>(found: &'a [Candidate], target: &Target) -> &'a Candidate {
        find(found, target).unwrap_or_else(|| panic!("no candidate for {target:?} in {found:#?}"))
    }

    fn has(c: &Candidate, kind: EvidenceKind) -> bool {
        c.evidence.iter().any(|e| e.kind == kind)
    }

    fn segments(found: &[Candidate]) -> usize {
        found
            .iter()
            .filter(|c| matches!(c.target, Target::RegMultiSzSegment { .. }))
            .count()
    }

    #[test]
    fn lists_are_paths_of_one_kind() {
        assert!(is_list(&[
            r"C:\Data",
            r"C:\Program Files\Git\cmd",
            r"D:\Media"
        ]));
        assert!(is_list(&[r"C:\a\one.dll", r#""C:\b\two.DLL""#]));
        assert!(is_list(&[
            r"%ProgramFiles%\Git\cmd",
            r"\\server\share\tools"
        ]));
        // A shortcut, its target and its arguments.
        assert!(!is_list(&[
            r"C:\x\Git Bash.lnk",
            r"C:\Program Files\Git\git-bash.exe",
            "--cd-to-home"
        ]));
        // Two paths of different kinds are still fields, not entries.
        assert!(!is_list(&[
            r"C:\x\Git GUI.lnk",
            r"C:\Program Files\Git\cmd\git-gui.exe"
        ]));
        assert!(!is_list(&[r"C:\Program Files\Git", r"C:\x\readme.txt"]));
        assert!(!is_list(&[r"C:\Program Files\Git", "Git"]));
        // One entry is no list to edit, and nothing is no list.
        assert!(!is_list(&[r"C:\Program Files\Git"]));
        assert!(!is_list(&[]));
    }

    /// Rig runs `git` and `npp`: a slot that clean Windows has is not offered, the new slots go whole,
    /// and no field is ever taken out of a record.
    #[test]
    fn a_record_is_offered_whole_unless_windows_has_the_value() {
        let mut world = World::new(git_slots().build());
        world.baseline = Some(baseline_with_values(&[(&shc(), "0")]));
        let found = scan(&world);
        assert_eq!(segments(&found), 0, "{found:#?}");
        assert_eq!(found.len(), 2, "{found:#?}");

        for name in ["1", "2"] {
            let c = expect(&found, &value(&shc(), name));
            assert_eq!(c.action, Action::DeleteValue);
            assert!(c.blockers.is_empty(), "{name}: {:?}", c.blockers);
            assert!(has(c, EvidenceKind::PointsIntoInstallRoot));
            assert!(has(c, EvidenceKind::DanglingRef));
        }
        assert!(find(&found, &value(&shc(), "0")).is_none());
    }

    /// The harvest records a reference in a `REG_MULTI_SZ` value under the entry that holds it. For a
    /// record that is evidence about the value. It is Tier B: the store is a ring of numbered slots
    /// that Windows manages and reuses (dirty-base runs f0d-git, f0d-npp, f0d-vlc: slot 15 held
    /// another product's record before the install), so the slot is never shown to be the app's and
    /// the value is listed, not preselected.
    #[test]
    fn a_record_carries_the_snapshot_evidence_of_its_entries() {
        let target_exe = exe("git-cmd.exe");
        let fixture = git_slots().dir(GIT_ROOT).file(&target_exe, 10);
        let mut world = World::new(fixture.build());
        world.fp.ref_snapshot = vec![RefSnapEntry {
            target: Target::RegMultiSzSegment {
                path: shc(),
                name: "1".into(),
                segment: target_exe.clone(),
                index: None,
            },
            carrier: RefCarrier::Segment,
            anchor: AnchorRef {
                kind: AnchorKind::Root,
                text: GIT_ROOT.into(),
            },
            parent_values: 3,
            parent_subkeys: 0,
            data_hash: None,
        }];
        let found = scan(&world);
        assert_eq!(segments(&found), 0, "{found:#?}");
        let recorded = expect(&found, &value(&shc(), "1"));
        assert!(!has(recorded, EvidenceKind::DanglingRef));
        let snap: Vec<_> = recorded
            .evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::InPreUninstallRefSnapshot)
            .collect();
        assert_eq!(snap.len(), 1, "{recorded:#?}");
        assert_eq!((snap[0].tier, snap[0].scope), (Tier::B, Scope::Value));
        assert!(has(recorded, EvidenceKind::PointsIntoInstallRoot));
        assert!(recorded.evidence.iter().all(|e| e.tier != Tier::A));
        // The slots the harvest did not record have the reference alone.
        let other = expect(&found, &value(&shc(), "2"));
        assert!(!has(other, EvidenceKind::InPreUninstallRefSnapshot));
    }

    /// Without a baseline for this Windows nothing shows the value is newer than the app: listed,
    /// with the unattributed fields counted, so never preselected.
    #[test]
    fn a_record_is_not_preselected_without_a_matching_baseline() {
        // The rig's slot records, in a key of another vendor rather than in Windows' slot store.
        let launcher = format!(r"HKU\{SID}\Software\Vendor\Launcher");
        let records = || {
            machine()
                .multi_sz(
                    &launcher,
                    "0",
                    &[&lnk("Git Bash"), &exe("git-bash.exe"), "--cd-to-home"],
                )
                .multi_sz(
                    &launcher,
                    "1",
                    &[&lnk("Git CMD"), &exe("git-cmd.exe"), "--cd-to-home"],
                )
                .multi_sz(&launcher, "2", &[&lnk("Git GUI"), &exe(r"cmd\git-gui.exe")])
        };
        // Every view below Exact takes the no-baseline path (presence-only, design L5).
        for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
            let mut none = World::new(records().build());
            none.baseline = purge_index::baseline_view::fixture::below_exact(below, &none.fp.os);
            // A baseline of another edition is not this Windows' baseline.
            let mut other = World::new(records().build());
            other.baseline = Some(baseline("Enterprise", &[]));
            for world in [&none, &other] {
                let found = scan(world);
                assert_eq!(segments(&found), 0, "{found:#?}");
                assert_eq!(found.len(), 3, "{found:#?}");
                for (name, n) in [("0", 2), ("1", 2), ("2", 1)] {
                    let c = expect(&found, &value(&launcher, name));
                    assert_eq!(c.blockers, vec![Blocker::UnmatchedChildren { n }], "{name}");
                    assert!(!c.blockers.iter().any(Blocker::is_hard));
                }
            }
        }
    }

    /// BL-GATE S1 (frozen runs `7zip`, `git`, `m1bcp-7zip` replayed with the local view): a slot of
    /// Windows' slot store is the app's leftover only when an exact baseline of this Windows shows the
    /// slot is newer than the profile's own. Below Exact, and with a baseline of another Windows, no
    /// slot is offered, whatever the view holds: the local baseline has no slot of any profile (the
    /// exact baselines hold slot `0` of the rig user, which the exact view withholds), a neighbour's
    /// slots are another machine's, and an empty view knows nothing. With the exact baseline the new
    /// slots are offered as before.
    #[test]
    fn a_slot_record_is_not_offered_without_a_matching_baseline() {
        use purge_index::baseline_view::fixture::{self, value_entry};
        let slots: Vec<String> = ["0", "1", "2"]
            .iter()
            .map(|name| value_entry(&shc(), name))
            .collect();
        let slots: Vec<&str> = slots.iter().map(String::as_str).collect();
        let mut views: Vec<(String, Option<BaselineView>)> = (0..fixture::BELOW_EXACT)
            .map(|below| {
                let world = World::new(git_slots().build());
                (
                    format!("below Exact {below}"),
                    fixture::below_exact(below, &world.fp.os),
                )
            })
            .collect();
        // Views that hold every slot, the slot store's key, or nothing of it: alike.
        views.push(("local, all slots".into(), Some(local_view(&slots))));
        views.push((
            "merged, the slots in the neighbour".into(),
            Some(merged_view(&[], &slots)),
        ));
        views.push((
            "merged, the key only".into(),
            Some(merged_view(&[], &[&shc()])),
        ));
        views.push(("none, all slots".into(), Some(none_view(&slots))));
        views.push((
            "another Windows' exact baseline".into(),
            Some(baseline("Enterprise", &[])),
        ));
        for (name, view) in views {
            let mut world = World::new(git_slots().build());
            world.baseline = view;
            let found = scan(&world);
            assert!(found.is_empty(), "{name}: {found:#?}");
        }
        // The exact baseline of this Windows: the slots it lacks are offered (L3).
        let mut exact = World::new(git_slots().build());
        exact.baseline = Some(baseline_with_values(&[(&shc(), "0")]));
        let found = scan(&exact);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(find(&found, &value(&shc(), "0")).is_none());
    }

    /// A record that names another installed app next to this one is not this app's alone.
    #[test]
    fn a_record_that_names_another_app_is_blocked() {
        let key = r"HKLM\SOFTWARE\Vendor\Launcher";
        let fixture = machine().dir(OTHER_ROOT).multi_sz(
            key,
            "Entry",
            &[
                &format!(r"{OTHER_ROOT}\Host.exe"),
                &exe("git-bash.exe"),
                "--open",
            ],
        );
        let mut world = World::new(fixture.build());
        world.other_apps = OtherApps::new(vec![OtherApp {
            name: "Download Manager".into(),
            roots: vec![OTHER_ROOT.into()],
            ..OtherApp::default()
        }]);
        let found = scan(&world);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].target, value(key, "Entry"));
        assert!(found[0].blockers.contains(&Blocker::ReferencedByOtherApp {
            app: "Download Manager".into()
        }));
    }

    /// Lists keep their entry edits, and a value that is the app's in every entry goes whole with no
    /// baseline needed: neither is a record.
    #[test]
    fn lists_and_values_that_are_all_the_apps_are_left_to_the_common_rule() {
        // Every view below Exact takes the no-baseline path (presence-only, design L5).
        for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
            let folders = r"HKLM\SOFTWARE\Vendor\Indexer";
            let own = r"HKLM\SOFTWARE\Vendor\Tools";
            let fixture = machine()
                .multi_sz(folders, "Folders", &[r"C:\Data", &exe("cmd"), r"D:\Media"])
                .multi_sz(own, "Git", &[&exe("git-bash.exe"), &exe(r"cmd\git.exe")]);
            let mut world = World::new(fixture.build());
            world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
            let found = scan(&world);
            assert_eq!(found.len(), 2, "{found:#?}");

            let entry = expect(
                &found,
                &Target::RegMultiSzSegment {
                    path: folders.into(),
                    name: "Folders".into(),
                    segment: exe("cmd"),
                    index: None,
                },
            );
            assert_eq!(entry.action, Action::EditSegment);
            assert!(find(&found, &value(folders, "Folders")).is_none());

            let whole = expect(&found, &value(own, "Git"));
            assert_eq!(whole.action, Action::DeleteValue);
            assert!(whole.blockers.is_empty(), "{:?}", whole.blockers);
        }
    }

    /// A list that is not all of one kind is no list to edit by entry, but its other entries are still
    /// the like of the app's: the value is listed whole, never preselected, even with every other
    /// entry dead.
    #[test]
    fn a_value_with_peers_of_the_apps_entry_is_not_preselected() {
        let key = r"HKLM\SOFTWARE\Vendor\Indexer";
        let fixture = machine()
            .dir(r"C:\Data")
            // Directories next to the app's directory, and a file.
            .multi_sz(
                key,
                "Folders",
                &[r"C:\Data", &exe("cmd"), r"C:\Data\notes.txt"],
            )
            // Programs next to the app's program, all gone, and a word.
            .multi_sz(
                key,
                "Allowed",
                &[r"C:\Gone\other.exe", &exe("git-bash.exe"), "always"],
            )
            // Bare program names next to the app's program.
            .multi_sz(key, "Names", &["calc.exe", &exe("git-bash.exe")]);
        let found = scan(&World::new(fixture.build()));
        assert_eq!(segments(&found), 0, "{found:#?}");
        assert_eq!(found.len(), 3, "{found:#?}");
        for (name, n) in [("Folders", 2), ("Allowed", 2), ("Names", 1)] {
            let c = expect(&found, &value(key, name));
            assert_eq!(c.blockers, vec![Blocker::UnmatchedChildren { n }], "{name}");
        }
    }

    /// A field of the record that names something that exists (or that cannot be told to be gone) is
    /// content that is not the app's: the value is not preselected. Dead fields and plain words are
    /// nothing of their own.
    #[test]
    fn a_record_with_a_live_field_is_not_preselected() {
        let key = r"HKLM\SOFTWARE\Vendor\Launcher";
        let fixture = machine()
            .dir(r"C:\Tools")
            .file(r"C:\Tools\Launch.lnk", 10)
            .file(r"C:\Tools\wrap.cmd", 10)
            .dir(r"C:\Locked")
            .denied(r"C:\Locked")
            .env("TOOLS", r"C:\Tools")
            .multi_sz(
                key,
                "Live",
                &[r"C:\Tools\Launch.lnk", &exe("git-bash.exe"), "--x"],
            )
            .multi_sz(
                key,
                "Quoted",
                &[r#""%TOOLS%\wrap.cmd" /c"#, &exe("git-bash.exe")],
            )
            .multi_sz(
                key,
                "Arguments",
                &[r"C:\Tools\wrap.cmd /c start", &exe("git-bash.exe")],
            )
            .multi_sz(key, "Unknown", &[r"C:\Locked\a.lnk", &exe("git-bash.exe")])
            .multi_sz(
                key,
                "Unresolved",
                &[r"%NOWHERE%\a.lnk", &exe("git-bash.exe")],
            )
            .multi_sz(
                key,
                "Dead",
                &[r"C:\Tools\Old.lnk", &exe("git-bash.exe"), "%1", "--x"],
            );
        let mut world = World::new(fixture.build());
        world.env.insert("TOOLS".into(), r"C:\Tools".into());
        let found = scan(&world);
        assert_eq!(segments(&found), 0, "{found:#?}");
        assert_eq!(found.len(), 6, "{found:#?}");
        for (name, n) in [
            ("Live", 2),
            ("Quoted", 1),
            ("Arguments", 1),
            ("Unknown", 1),
            ("Unresolved", 1),
        ] {
            let c = expect(&found, &value(key, name));
            assert_eq!(c.blockers, vec![Blocker::UnmatchedChildren { n }], "{name}");
        }
        let dead = expect(&found, &value(key, "Dead"));
        assert!(dead.blockers.is_empty(), "{:?}", dead.blockers);
    }

    /// Entries that only mention the app without evidence (no path into a root) offer nothing.
    #[test]
    fn a_record_without_evidence_is_not_offered() {
        let key = r"HKLM\SOFTWARE\Vendor\Launcher";
        let fixture = machine().multi_sz(
            key,
            "Entry",
            &[r"C:\Program Files\Git Extensions\x.lnk", "run", "--fast"],
        );
        let found = scan(&World::new(fixture.build()));
        assert!(found.is_empty(), "{found:#?}");
    }
}
