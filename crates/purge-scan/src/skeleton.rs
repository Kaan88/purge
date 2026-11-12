//! `ProvenOwnedSkeleton` (ENGINE_PLAN.md §5.3, lessons L3/L4): the empty key an uninstaller leaves behind
//! when its log names only the leaves.
//!
//! Git's uninstaller removes `sh_auto_file\shell\open\command` and the verbs it put under
//! `LibraryFolder\background\shell`, but not the parents it created for them. Such a parent holds no value
//! and no reference, so no value-level evidence can ever attribute it. It may still go when **all five**
//! of these hold ([`check`] names the one that fails):
//!
//! 1. **Attributed at harvest.** The fingerprint has a subtree baseline for the key in which every value
//!    and subkey was attributed to the app with Tier A (`SubtreeBaseline::fully_attributed`), or the key
//!    is an Inno key-create record that did not exist before the install, or the key is a `shell` key
//!    all of whose verbs were the app's at harvest (see "Verb parents" below).
//! 2. **Value-free now.** The key exists, is not a registry link and holds no value, not even a default.
//! 3. **Subkeys gone or themselves proven.** A subkey that is still there must be part of the attributed
//!    subtree (it was listed at harvest) or pass this whole check on its own record, and must itself be
//!    value-free, down to the leaves. A subkey that appeared after the harvest is nobody's.
//! 4. **Not in the baseline.** A baseline for exactly this (edition, build.ubr) is loaded, the key is in
//!    the scope that baselines capture, and neither the key nor any remaining subkey is in it. Without a
//!    matching baseline there is no evidence at all: the caller then works values-only (§5.7.1 step 3).
//! 5. **No TrustedInstaller owner or ACE**, at harvest or now. A harvest from a source that records
//!    owners looked at the top key of every subtree baseline (`SubtreeBaseline::ti_owned`) and, for a
//!    fully attributed one, at every key below it (a TrustedInstaller-owned or unreadable owner anywhere
//!    makes the subtree not fully attributed). A key whose owner the source cannot tell now is accepted
//!    only when both hold: it is the top key of its record or a listed subkey of a fully attributed
//!    subtree, **and** the source records no key owners at all (a rig snapshot, a plain fixture; the
//!    harvest warns that TrustedInstaller ownership was not checked). A source that does record owners
//!    (the live registry) and cannot tell for this one key does not prove it, exactly as at harvest.
//!
//! # Verb parents
//!
//! A verb key holds more than references: its default value is the menu text (`Open Git &GUI here`),
//! which points nowhere. Without an installer log the harvest therefore cannot mark a `shell` key that
//! holds such verbs as fully attributed, although CLS-VERBS (§5.6) takes exactly such a verb key as the
//! app's, with Tier A, when its `command` runs a file of the app. The same rule is applied to the
//! harvest's records here. A key named `shell` is attributed when the fingerprint has a subtree baseline
//! for it and, in that baseline:
//!
//! - the `shell` key itself held no value and had at least one verb;
//! - every verb (direct subkey) had a `command` subkey whose own subtree baseline is fully attributed
//!   and holds a default value, and the reference snapshot records that default value as a reference to
//!   a file of the exe set or into an InstallRoot;
//! - no other key of the subtree is called `command`;
//! - no Inno record says the key, a key above it or a key below it existed before the install (a verb
//!   the installer found in place means the `shell` key was in place too).
//!
//! Conditions 2 to 5 then apply as for any other key; a verb that is still there is not vouched for by
//! the harvest's owner check and so must be value-free and have an owner the source can tell.
//!
//! The result is Tier A, weight 8, **Key** scope evidence, the only kind that lifts the deny-list's
//! `shell` / `shellex` root rules (§5.10 "unless `ProvenOwnedSkeleton`").

use purge_index::baseline::Baseline;
use purge_model::{
    AnchorKind, Evidence, EvidenceKind, Facts, Scope, SourceTrust, SubtreeBaseline, Target,
};
use purge_source::types::SourceError;

use purge_guard::prefix;

use crate::framework::{ScanCtx, app_trust, inno_trust};

/// Why a key is not a proven owned skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NotProven {
    /// No baseline is loaded for this Windows.
    NoBaseline,
    /// The loaded baseline is for another (edition, build.ubr) than the machine's.
    BaselineMismatch,
    /// The key is outside what baselines capture, so "not in the baseline" would prove nothing.
    OutOfBaselineScope,
    /// The key, or the named subkey that is still there, is part of clean Windows.
    InBaseline(String),
    /// The harvest did not attribute the whole subtree to the app, and no installer record creates the
    /// key.
    NotAttributed,
    /// The key no longer exists: there is nothing to offer.
    Gone,
    /// The key, or the named subkey, still holds a value.
    HasValues(String),
    /// The named subkey is still there and is neither part of the attributed subtree nor proven itself.
    UnprovenSubkey(String),
    /// The key, or the named subkey, is TrustedInstaller-owned, or its owner could not be established.
    TrustedInstaller(String),
    /// The key, or the named subkey, is a registry link.
    Link(String),
    /// The key, or the named subkey, could not be read.
    Unreadable(String),
    /// The subtree is deeper or wider than the scan limits allow.
    TooLarge,
}

/// What attributes a key to the app.
enum Proof<'a> {
    /// A fully attributed subtree baseline of the fingerprint.
    Subtree(&'a SubtreeBaseline),
    /// A `shell` key whose verbs were all the app's at harvest (module documentation, "Verb parents").
    Verbs(&'a SubtreeBaseline),
    /// An Inno key-create record.
    Inno,
}

/// The `ProvenOwnedSkeleton` evidence for `key`, when all five conditions of the module documentation
/// hold.
pub fn proven_owned_skeleton(ctx: &ScanCtx<'_>, key: &str) -> Option<Evidence> {
    check(ctx, key).ok()
}

/// Like [`proven_owned_skeleton`], naming the first condition that fails.
pub fn check(ctx: &ScanCtx<'_>, key: &str) -> Result<Evidence, NotProven> {
    let baseline = ctx.baseline.ok_or(NotProven::NoBaseline)?;
    // The machine as it is now decides; the fingerprint's record of it is the fallback.
    let os = ctx.sys.os_info().unwrap_or_else(|_| ctx.fp.os.clone());
    if !baseline.is_for(&os.edition, os.build, os.ubr) {
        return Err(NotProven::BaselineMismatch);
    }
    let mut budget = ctx.limits.max_key_children;
    let proof = prove(ctx, baseline, key, 0, &mut budget)?;
    let (trust, source, via): (SourceTrust, String, &str) = match proof {
        Proof::Subtree(subtree) => (
            app_trust(ctx.fp),
            format!("subtree:{}", subtree.key),
            "subtree",
        ),
        Proof::Verbs(subtree) => (
            app_trust(ctx.fp),
            format!("subtree:{}", subtree.key),
            "shell-verbs",
        ),
        Proof::Inno => (inno_trust(ctx.fp), "inno:log".to_owned(), "inno-key-create"),
    };
    let detail = Facts::new()
        .with("key", key)
        .with("via", via)
        .with("baseline", os.baseline_name());
    Evidence::new(EvidenceKind::ProvenOwnedSkeleton, Scope::Key, trust, source)
        .map(|e| e.with_detail(detail))
        .ok_or(NotProven::NotAttributed)
}

/// The harvest record that attributes `key`, if any. A subtree baseline wins over an Inno record because
/// it also knows the subkeys; the verb-parent rule is tried last.
fn attribution<'a>(ctx: &ScanCtx<'a>, key: &str) -> Option<Proof<'a>> {
    let fp = ctx.fp;
    if let Some(subtree) = fp
        .subtrees
        .iter()
        .find(|s| s.fully_attributed && ctx.same_key(&s.key, key))
    {
        return Some(Proof::Subtree(subtree));
    }
    let inno = fp.inno.iter().any(|r| {
        r.key_create
            && !r.existed_before
            && matches!(&r.target, Target::RegKey { path } if ctx.same_key(path, key))
    });
    if inno {
        return Some(Proof::Inno);
    }
    verb_parent(ctx, key).map(Proof::Verbs)
}

/// The subtree baseline of `key` when `key` is a `shell` key whose verbs were all the app's at harvest
/// (module documentation, "Verb parents").
fn verb_parent<'a>(ctx: &ScanCtx<'a>, key: &str) -> Option<&'a SubtreeBaseline> {
    const SHELL: &str = "shell";
    const COMMAND: &str = "command";
    let fp = ctx.fp;
    if !prefix::leaf(key).is_some_and(|leaf| leaf.eq_ignore_ascii_case(SHELL)) {
        return None;
    }
    let subtree = fp.subtrees.iter().find(|s| ctx.same_key(&s.key, key))?;
    // A key the installer found in place is not the app's, whatever it held; and when it found a key
    // below this one in place, this one was in place too.
    let existed_before = fp.inno.iter().any(|r| {
        r.existed_before
            && matches!(&r.target, Target::RegKey { path } if matches!(
                ctx.key_relation(key, path),
                prefix::Relation::Same | prefix::Relation::Inside | prefix::Relation::Ancestor
            ))
    });
    if existed_before {
        return None;
    }
    let verbs: Vec<&str> = subtree
        .subkeys
        .iter()
        .map(String::as_str)
        .filter(|rel| prefix::segments(rel).count() == 1)
        .collect();
    if verbs.is_empty() {
        return None;
    }
    let app_verb = |verb: &str| {
        let command = format!("{key}{sep}{verb}{sep}{COMMAND}", sep = prefix::SEP);
        let recorded = fp.subtrees.iter().any(|s| {
            s.fully_attributed
                && !s.ti_owned
                && ctx.same_key(&s.key, &command)
                && s.values
                    .iter()
                    .any(|v| v.subkey.is_empty() && v.name.is_empty())
        });
        recorded
            && fp.ref_snapshot.iter().any(|entry| {
                matches!(&entry.target, Target::RegValue { path, name }
                    if name.is_empty() && ctx.same_key(path, &command))
                    && matches!(entry.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
                    && (ctx.inside_install_root(&entry.anchor.text).is_some()
                        || ctx.is_app_file(&entry.anchor.text))
            })
    };
    if !verbs.iter().all(|verb| app_verb(verb)) {
        return None;
    }
    let under_a_verb = |rel: &str| {
        prefix::segments(rel)
            .next()
            .is_some_and(|top| verbs.iter().any(|verb| prefix::eq_ci(verb, top)))
    };
    // Nothing on the `shell` key itself, nothing outside the verbs, and one `command` per verb.
    let values_ok = subtree.values.iter().all(|v| under_a_verb(&v.subkey));
    let subkeys_ok = subtree.subkeys.iter().all(|rel| {
        let segs: Vec<&str> = prefix::segments(rel).collect();
        let is_command = segs
            .last()
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(COMMAND));
        under_a_verb(rel) && (!is_command || segs.len() == 2)
    });
    (values_ok && subkeys_ok).then_some(subtree)
}

/// Conditions 1 to 5 for `key` as the top of its own proof.
fn prove<'a>(
    ctx: &ScanCtx<'a>,
    baseline: &Baseline,
    key: &str,
    depth: u32,
    budget: &mut usize,
) -> Result<Proof<'a>, NotProven> {
    if !Baseline::key_in_scope(key) {
        return Err(NotProven::OutOfBaselineScope);
    }
    if baseline.has_key(key) {
        return Err(NotProven::InBaseline(key.to_owned()));
    }
    let proof = attribution(ctx, key).ok_or(NotProven::NotAttributed)?;
    // `vouched`: the harvest checked the owner of every key of the subtree, not only of its top.
    let (subtree, vouched) = match &proof {
        Proof::Subtree(subtree) => (Some(*subtree), true),
        Proof::Verbs(subtree) => (Some(*subtree), false),
        Proof::Inno => (None, false),
    };
    if subtree.is_some_and(|s| s.ti_owned) {
        return Err(NotProven::TrustedInstaller(key.to_owned()));
    }
    let record = Record {
        subtree,
        vouched,
        owners_known: source_records_owners(ctx),
    };
    empty_now(ctx, baseline, key, record, "", depth, budget, true)?;
    Ok(proof)
}

/// What the harvest recorded about the key a proof starts at.
#[derive(Clone, Copy)]
struct Record<'a> {
    /// Its subtree baseline, when the proof rests on one.
    subtree: Option<&'a SubtreeBaseline>,
    /// The harvest checked the owner of every key of the subtree (it is fully attributed).
    vouched: bool,
    /// The source records key owners ([`source_records_owners`]).
    owners_known: bool,
}

/// Whether the source records key owners at all: `HKLM\SOFTWARE` exists on every Windows, so a source
/// that cannot tell its owner (a rig snapshot, a plain fixture) cannot tell any. The harvest uses the
/// same test. With such a source an unknown owner says nothing; with any other it means the security
/// descriptor of that one key could not be read, which is not what an app's own key looks like.
fn source_records_owners(ctx: &ScanCtx<'_>) -> bool {
    ctx.reg
        .key_info(r"HKLM\SOFTWARE")
        .is_ok_and(|info| info.ti_owned.is_some())
}

/// Conditions 2, 3 and 5 (and 4 for subkeys) for `key`, which is `rel` below the top of the subtree of
/// `record`.
#[allow(clippy::too_many_arguments)]
fn empty_now(
    ctx: &ScanCtx<'_>,
    baseline: &Baseline,
    key: &str,
    record: Record<'_>,
    rel: &str,
    depth: u32,
    budget: &mut usize,
    top: bool,
) -> Result<(), NotProven> {
    if depth > ctx.limits.max_depth {
        return Err(NotProven::TooLarge);
    }
    let unreadable = |error: SourceError| match error {
        SourceError::NotFound if top => NotProven::Gone,
        _ => NotProven::Unreadable(key.to_owned()),
    };
    let info = ctx.reg.key_info(key).map_err(unreadable)?;
    if info.is_link {
        return Err(NotProven::Link(key.to_owned()));
    }
    let subtree = record.subtree;
    // The owner: TrustedInstaller now is fatal. "Unknown now" is acceptable only when the source records
    // no owners at all and the harvest's record covers the key: the top key of every subtree baseline
    // and, for a fully attributed one, every key below it (below the top, this function is only reached
    // for listed subkeys). Anywhere else a key whose owner the source cannot tell is not proven.
    match info.ti_owned {
        Some(true) => return Err(NotProven::TrustedInstaller(key.to_owned())),
        Some(false) => {}
        None if !record.owners_known && subtree.is_some() && (top || record.vouched) => {}
        None => return Err(NotProven::TrustedInstaller(key.to_owned())),
    }
    let values = ctx.reg.values(key).map_err(unreadable)?;
    if !values.is_empty() {
        return Err(NotProven::HasValues(key.to_owned()));
    }
    let subkeys = ctx.reg.subkeys(key).map_err(unreadable)?;
    *budget = budget
        .checked_sub(subkeys.len() + 1)
        .ok_or(NotProven::TooLarge)?;
    for name in subkeys {
        let child = format!("{key}\\{name}");
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}\\{name}")
        };
        let listed = subtree.is_some_and(|s| {
            s.subkeys
                .iter()
                .any(|known| prefix::is_same(known, &child_rel))
        });
        if listed {
            if baseline.has_key(&child) {
                return Err(NotProven::InBaseline(child));
            }
            empty_now(
                ctx,
                baseline,
                &child,
                record,
                &child_rel,
                depth + 1,
                budget,
                false,
            )?;
        } else {
            // Not part of the attributed subtree: it must be proven on its own record.
            match prove(ctx, baseline, &child, depth + 1, budget) {
                Ok(_) => {}
                Err(NotProven::NotAttributed | NotProven::Gone) => {
                    return Err(NotProven::UnprovenSubkey(child));
                }
                Err(other) => return Err(other),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::testkit::*;
    use purge_model::{FileTime, InnoRecord, InnoRecordKind, ProgramId, SubtreeValue, Tier, View};
    use purge_source::fixture::Fixture;
    use purge_source::types::RegData;

    const SH_AUTO_FILE: &str = r"HKLM\SOFTWARE\Classes\sh_auto_file";
    const LIBRARY_SHELL: &str = r"HKLM\SOFTWARE\Classes\LibraryFolder\background\shell";

    /// The subtree baseline of `sh_auto_file` as harvested with Git installed: `shell\open\command` with
    /// a command into the root.
    fn sh_auto_file_subtree() -> SubtreeBaseline {
        SubtreeBaseline {
            key: SH_AUTO_FILE.into(),
            values: vec![SubtreeValue {
                subkey: r"shell\open\command".into(),
                name: String::new(),
                hash: "aa11".into(),
            }],
            subkeys: vec![
                "shell".into(),
                r"shell\open".into(),
                r"shell\open\command".into(),
            ],
            lwt: FileTime(133_900_000_000_000_000),
            ti_owned: false,
            fully_attributed: true,
        }
    }

    /// The subtree baseline of `LibraryFolder\background\shell`: Git's two verbs.
    fn library_shell_subtree() -> SubtreeBaseline {
        let verb = |name: &str| SubtreeValue {
            subkey: format!(r"{name}\command"),
            name: String::new(),
            hash: "bb22".into(),
        };
        SubtreeBaseline {
            key: LIBRARY_SHELL.into(),
            values: vec![verb("git_shell"), verb("git_gui")],
            subkeys: vec![
                "git_shell".into(),
                r"git_shell\command".into(),
                "git_gui".into(),
                r"git_gui\command".into(),
            ],
            lwt: FileTime(133_900_000_000_000_000),
            ti_owned: false,
            fully_attributed: true,
        }
    }

    /// After Git's uninstall: `sh_auto_file\shell` left empty (the log named only `open\command`), and
    /// `LibraryFolder\background\shell` left with no verb. `LibraryFolder\background` is Windows' own.
    fn after_uninstall() -> Fixture {
        Fixture::builder()
            .key(&format!(r"{SH_AUTO_FILE}\shell"))
            .ti_owned(SH_AUTO_FILE, false)
            .ti_owned(&format!(r"{SH_AUTO_FILE}\shell"), false)
            .key(LIBRARY_SHELL)
            .ti_owned(LIBRARY_SHELL, false)
            .os(EDITION, BUILD, UBR)
            .build()
    }

    fn world() -> World {
        let mut world = World::new(after_uninstall());
        world.fp.subtrees = vec![sh_auto_file_subtree(), library_shell_subtree()];
        world.baseline = Some(baseline(
            EDITION,
            &[
                r"HKLM\SOFTWARE\Classes\LibraryFolder",
                r"HKLM\SOFTWARE\Classes\LibraryFolder\background",
                r"HKLM\SOFTWARE\Classes\Directory\shell",
            ],
        ));
        world
    }

    #[test]
    fn git_shapes_are_proven() {
        let world = world();
        let ctx = world.ctx();
        for key in [SH_AUTO_FILE, LIBRARY_SHELL] {
            let e = check(&ctx, key).unwrap_or_else(|why| panic!("{key}: {why:?}"));
            assert_eq!(e.kind, EvidenceKind::ProvenOwnedSkeleton);
            assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Scope::Key));
            assert_eq!(e.trust, SourceTrust::AdminOnly);
            assert_eq!(e.source.0, format!("subtree:{key}"));
            assert_eq!(e.detail.get("baseline"), Some("Professional-26340.9882"));
            assert_eq!(proven_owned_skeleton(&ctx, key), Some(e));
        }
        // Spelling does not matter.
        assert!(proven_owned_skeleton(&ctx, r"hklm\software\classes\SH_AUTO_FILE").is_some());
        // The still-present subkey is proven as part of the subtree, not on its own.
        assert_eq!(
            check(&ctx, &format!(r"{SH_AUTO_FILE}\shell")),
            Err(NotProven::NotAttributed)
        );
    }

    /// Condition 1: a foreign value at harvest means the subtree was not fully attributed.
    #[test]
    fn foreign_value_at_harvest_is_not_proven() {
        for key in [SH_AUTO_FILE, LIBRARY_SHELL] {
            let mut world = world();
            for subtree in &mut world.fp.subtrees {
                // The harvest saw a value it could not attribute (e.g. another tool's verb).
                subtree.values.push(SubtreeValue {
                    subkey: "other_tool".into(),
                    name: "Icon".into(),
                    hash: "cc33".into(),
                });
                subtree.fully_attributed = false;
            }
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::NotAttributed),
                "{key}"
            );
        }
        // No record at all.
        let mut world = world();
        world.fp.subtrees.clear();
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::NotAttributed)
        );
    }

    /// Condition 2: a value in the key, even an empty default, keeps it.
    #[test]
    fn key_with_a_value_is_not_proven() {
        let mut world = world();
        world
            .fixture
            .set_value(SH_AUTO_FILE, "", RegData::from_sz(""));
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::HasValues(SH_AUTO_FILE.into()))
        );
        // A value deeper down counts as well.
        let mut world = self::world();
        let shell = format!(r"{SH_AUTO_FILE}\shell");
        world.fixture.set_value(&shell, "x", RegData::from_dword(1));
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::HasValues(shell))
        );
        // A key that is gone is not offered.
        let mut world = self::world();
        world.fixture.remove_key(LIBRARY_SHELL);
        assert_eq!(check(&world.ctx(), LIBRARY_SHELL), Err(NotProven::Gone));
    }

    /// Condition 3: a subkey that was not there at harvest is nobody's.
    #[test]
    fn unproven_subkey_is_not_proven() {
        let mut world = world();
        let newcomer = format!(r"{LIBRARY_SHELL}\other_tool");
        world.fixture.add_key(&newcomer);
        world.fixture.set_ti_owned(&newcomer, false);
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::UnprovenSubkey(newcomer.clone()))
        );
        // The same subkey with its own key-create record is proven, and so is the parent.
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::RegDeleteKeyIfEmpty,
            target: Target::RegKey {
                path: newcomer.clone(),
            },
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: true,
        }];
        assert!(check(&world.ctx(), LIBRARY_SHELL).is_ok());
        let own = check(&world.ctx(), &newcomer).unwrap();
        assert_eq!(own.source.0, "inno:log");
        assert_eq!(own.detail.get("via"), Some("inno-key-create"));
        // A key the log says existed before the install is not the installer's.
        world.fp.inno[0].existed_before = true;
        assert_eq!(
            check(&world.ctx(), &newcomer),
            Err(NotProven::NotAttributed)
        );
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::UnprovenSubkey(newcomer))
        );
    }

    /// Condition 4: a key of clean Windows is never a skeleton.
    #[test]
    fn key_in_the_baseline_is_not_proven() {
        for key in [SH_AUTO_FILE, LIBRARY_SHELL] {
            let mut world = world();
            world.baseline = Some(baseline(EDITION, &[key]));
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::InBaseline(key.into())),
                "{key}"
            );
            assert_eq!(proven_owned_skeleton(&world.ctx(), key), None);
        }
        // A remaining subkey that Windows ships blocks the parent too.
        let mut world = world();
        let shell = format!(r"{SH_AUTO_FILE}\shell");
        world.baseline = Some(baseline(EDITION, &[&shell]));
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::InBaseline(shell))
        );
        // Outside what baselines capture, absence proves nothing.
        let mut world = self::world();
        let outside = r"HKLM\SECURITY\Policy\Skeleton";
        world.fp.subtrees[0].key = outside.into();
        world.fixture.add_key(outside);
        assert_eq!(
            check(&world.ctx(), outside),
            Err(NotProven::OutOfBaselineScope)
        );
    }

    /// Condition 4: no baseline, or one of another build, gives no evidence.
    #[test]
    fn no_matching_baseline_is_not_proven() {
        for key in [SH_AUTO_FILE, LIBRARY_SHELL] {
            let mut world = world();
            world.baseline = None;
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::NoBaseline),
                "{key}"
            );
            assert_eq!(proven_owned_skeleton(&world.ctx(), key), None);
            // A baseline of another edition is not this Windows' baseline.
            world.baseline = Some(baseline("EnterpriseS", &[]));
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::BaselineMismatch),
                "{key}"
            );
        }
    }

    /// Condition 5: TrustedInstaller ownership, at harvest or now.
    #[test]
    fn trusted_installer_owned_is_not_proven() {
        for key in [SH_AUTO_FILE, LIBRARY_SHELL] {
            // Now.
            let mut world = world();
            world.fixture.set_ti_owned(key, true);
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::TrustedInstaller(key.into())),
                "{key}"
            );
            // At harvest.
            let mut world = self::world();
            for subtree in &mut world.fp.subtrees {
                subtree.ti_owned = true;
            }
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::TrustedInstaller(key.into())),
                "{key}"
            );
        }
        // A TrustedInstaller-owned subkey.
        let mut world = world();
        let shell = format!(r"{SH_AUTO_FILE}\shell");
        world.fixture.set_ti_owned(&shell, true);
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::TrustedInstaller(shell))
        );
    }

    #[test]
    fn links_and_unknown_owners_fail_closed() {
        let mut world = world();
        world
            .fixture
            .set_link(LIBRARY_SHELL, r"\Registry\Machine\SOFTWARE\Elsewhere");
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::Link(LIBRARY_SHELL.into()))
        );
        // An Inno-only key whose owner the source cannot tell.
        let mut world = self::world();
        let key = r"HKLM\SOFTWARE\Classes\GitBash.Created";
        world.fixture.add_key(key);
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::RegDeleteKeyIfEmpty,
            target: Target::RegKey { path: key.into() },
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: true,
        }];
        if world.ctx().reg.key_info(key).unwrap().ti_owned.is_none() {
            assert_eq!(
                check(&world.ctx(), key),
                Err(NotProven::TrustedInstaller(key.into()))
            );
        }
        world.fixture.set_ti_owned(key, false);
        assert!(check(&world.ctx(), key).is_ok());
    }

    /// A fully attributed subtree means the harvest checked the owner of every key in it, so a listed
    /// subkey whose owner the source cannot tell now rests on the harvest's record just as the top key
    /// does (the git replay: `sh_auto_file` with `shell\open` and `ShellEx` left empty, read from a
    /// snapshot that records no owners). A subkey the harvest did not list has no such record.
    #[test]
    fn unknown_owner_rests_on_the_harvest_only_for_listed_subkeys() {
        let open = format!(r"{SH_AUTO_FILE}\shell\open");
        let fixture = Fixture::builder()
            .key(&open)
            .os(EDITION, BUILD, UBR)
            .build();
        let mut world = World::new(fixture);
        world.fp.subtrees = vec![sh_auto_file_subtree()];
        let shell = format!(r"{SH_AUTO_FILE}\shell");
        for key in [SH_AUTO_FILE, shell.as_str(), open.as_str()] {
            assert_eq!(world.ctx().reg.key_info(key).unwrap().ti_owned, None);
        }
        let e = check(&world.ctx(), SH_AUTO_FILE).unwrap();
        assert_eq!(e.detail.get("via"), Some("subtree"));

        // A TrustedInstaller owner now is fatal wherever it is.
        world.fixture.set_ti_owned(&open, true);
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::TrustedInstaller(open.clone()))
        );
        world.fixture.set_ti_owned(&open, false);

        // The harvest said nothing about the owners below a subtree it could not attribute fully.
        world.fp.subtrees[0].fully_attributed = false;
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::NotAttributed)
        );
        world.fp.subtrees[0].fully_attributed = true;

        // A subkey that appeared after the harvest, created by an installer record: its owner must be
        // known now.
        let late = format!(r"{SH_AUTO_FILE}\late");
        world.fixture.add_key(&late);
        world.fp.inno = vec![InnoRecord {
            kind: InnoRecordKind::RegDeleteKeyIfEmpty,
            target: Target::RegKey { path: late.clone() },
            view: Some(View::K64),
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: true,
        }];
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::TrustedInstaller(late.clone()))
        );
        world.fixture.set_ti_owned(&late, false);
        assert!(check(&world.ctx(), SH_AUTO_FILE).is_ok());
    }

    /// A source that records owners (the live registry) and cannot tell for one key: that key's security
    /// descriptor could not be read, and neither it nor a key above it is proven, top key or not.
    #[test]
    fn unknown_owner_in_a_source_that_records_owners_is_not_proven() {
        let open = format!(r"{SH_AUTO_FILE}\shell\open");
        let shell = format!(r"{SH_AUTO_FILE}\shell");
        let fixture = Fixture::builder()
            .key(&open)
            .ti_owned(r"HKLM\SOFTWARE", true)
            .ti_owned(SH_AUTO_FILE, false)
            .ti_owned(&shell, false)
            .os(EDITION, BUILD, UBR)
            .build();
        let mut world = World::new(fixture);
        world.fp.subtrees = vec![sh_auto_file_subtree()];
        assert_eq!(
            check(&world.ctx(), SH_AUTO_FILE),
            Err(NotProven::TrustedInstaller(open.clone()))
        );
        world.fixture.set_ti_owned(&open, false);
        assert!(check(&world.ctx(), SH_AUTO_FILE).is_ok());

        // The top key itself.
        let fixture = Fixture::builder()
            .key(LIBRARY_SHELL)
            .ti_owned(r"HKLM\SOFTWARE", true)
            .os(EDITION, BUILD, UBR)
            .build();
        let mut world = World::new(fixture);
        world.fp.subtrees = vec![library_shell_subtree()];
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::TrustedInstaller(LIBRARY_SHELL.into()))
        );
        world.fixture.set_ti_owned(LIBRARY_SHELL, false);
        assert!(check(&world.ctx(), LIBRARY_SHELL).is_ok());
    }

    // ---- verb parents ----------------------------------------------------------------------------------

    const GIT_BASH: &str = r"C:\Program Files\Git\git-bash.exe";
    const GIT_GUI: &str = r"C:\Program Files\Git\cmd\git-gui.exe";

    /// What a harvest without an installer log records for one verb of `shell`: the verb key (menu
    /// text, `Icon`, `command`), which it cannot attribute fully because the menu text points nowhere,
    /// and the `command` key, which it can.
    fn verb_records(
        shell: &str,
        verb: &str,
        exe: &str,
    ) -> (Vec<SubtreeBaseline>, Vec<purge_model::RefSnapEntry>) {
        let value = |subkey: &str, name: &str, hash: &str| SubtreeValue {
            subkey: subkey.into(),
            name: name.into(),
            hash: hash.into(),
        };
        let subtree = |key: String, values, subkeys, fully_attributed| SubtreeBaseline {
            key,
            values,
            subkeys,
            lwt: FileTime(133_900_000_000_000_000),
            ti_owned: false,
            fully_attributed,
        };
        let verb_key = format!(r"{shell}\{verb}");
        let command = format!(r"{verb_key}\command");
        let reference = |path: &str, name: &str| purge_model::RefSnapEntry {
            target: Target::RegValue {
                path: path.into(),
                name: name.into(),
            },
            carrier: purge_model::RefCarrier::Data,
            anchor: purge_model::AnchorRef {
                kind: AnchorKind::Exe,
                text: exe.into(),
            },
            parent_values: 1,
            parent_subkeys: 0,
            data_hash: None,
        };
        (
            vec![
                subtree(
                    verb_key.clone(),
                    vec![
                        value("", "", "1:aa"),
                        value("", "Icon", "1:bb"),
                        value("command", "", "1:cc"),
                    ],
                    vec!["command".into()],
                    false,
                ),
                subtree(command.clone(), vec![value("", "", "1:cc")], vec![], true),
            ],
            vec![reference(&verb_key, "Icon"), reference(&command, "")],
        )
    }

    /// The `shell` record of a harvest without an installer log: both verbs with their menu texts.
    fn unattributed_shell(shell: &str) -> SubtreeBaseline {
        let mut values = Vec::new();
        let mut subkeys = Vec::new();
        for verb in ["git_gui", "git_shell"] {
            for (subkey, name) in [
                (verb.to_owned(), ""),
                (verb.to_owned(), "Icon"),
                (format!(r"{verb}\command"), ""),
            ] {
                values.push(SubtreeValue {
                    subkey,
                    name: name.into(),
                    hash: "1:dd".into(),
                });
            }
            subkeys.push(verb.to_owned());
            subkeys.push(format!(r"{verb}\command"));
        }
        SubtreeBaseline {
            key: shell.into(),
            values,
            subkeys,
            lwt: FileTime(133_900_000_000_000_000),
            ti_owned: false,
            fully_attributed: false,
        }
    }

    /// The git replay: no installer log, a snapshot source that records no owners, `shell` left empty
    /// under `LibraryFolder\background`, which is Windows' own.
    fn verb_world() -> World {
        let fixture = Fixture::builder()
            .key(LIBRARY_SHELL)
            .os(EDITION, BUILD, UBR)
            .build();
        let mut world = World::new(fixture);
        world.fp.subtrees = vec![unattributed_shell(LIBRARY_SHELL)];
        for (verb, exe) in [("git_gui", GIT_GUI), ("git_shell", GIT_BASH)] {
            let (subtrees, refs) = verb_records(LIBRARY_SHELL, verb, exe);
            world.fp.subtrees.extend(subtrees);
            world.fp.ref_snapshot.extend(refs);
        }
        world.baseline = Some(baseline(
            EDITION,
            &[
                r"HKLM\SOFTWARE\Classes\LibraryFolder",
                r"HKLM\SOFTWARE\Classes\LibraryFolder\Background",
            ],
        ));
        world
    }

    #[test]
    fn shell_key_whose_verbs_were_all_the_apps_is_proven() {
        let world = verb_world();
        let ctx = world.ctx();
        let e = check(&ctx, LIBRARY_SHELL).unwrap();
        assert_eq!(e.kind, EvidenceKind::ProvenOwnedSkeleton);
        assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Scope::Key));
        assert_eq!(e.source.0, format!("subtree:{LIBRARY_SHELL}"));
        assert_eq!(e.detail.get("via"), Some("shell-verbs"));
        // The spelling of the path does not matter (`Background` in the catalog, `background` on disk).
        assert!(
            check(
                &ctx,
                r"HKLM\SOFTWARE\Classes\LibraryFolder\Background\Shell"
            )
            .is_ok()
        );
        // The rule is about `shell` keys: a verb key is not a skeleton of its own.
        assert_eq!(
            check(&ctx, &format!(r"{LIBRARY_SHELL}\git_gui")),
            Err(NotProven::NotAttributed)
        );
    }

    #[test]
    fn shell_key_with_a_verb_that_was_not_the_apps_is_not_proven() {
        // Another tool's verb at harvest, whose command the snapshot does not know.
        let mut world = verb_world();
        world.fp.subtrees[0].subkeys.push("other_tool".into());
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );
        // ... even with a command, as long as it is not a reference to a file of the app.
        world.fp.subtrees[0]
            .subkeys
            .push(r"other_tool\command".into());
        let (subtrees, refs) = verb_records(
            LIBRARY_SHELL,
            "other_tool",
            r"C:\Program Files\Other\tool.exe",
        );
        world.fp.subtrees.extend(subtrees);
        world.fp.ref_snapshot.extend(refs);
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // A verb whose `command` key the harvest could not attribute.
        let mut world = verb_world();
        for subtree in &mut world.fp.subtrees {
            if subtree.key.ends_with(r"git_gui\command") {
                subtree.fully_attributed = false;
            }
        }
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // A verb whose command reference is not in the snapshot.
        let mut world = verb_world();
        world.fp.ref_snapshot.retain(|r| {
            !matches!(&r.target, Target::RegValue { path, .. } if path.ends_with(r"git_shell\command"))
        });
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // A command reference to something outside the app (a name in a foreign directory).
        let mut world = verb_world();
        for entry in &mut world.fp.ref_snapshot {
            entry.anchor.text = r"C:\Tools\git-bash.exe".into();
        }
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // A value on the `shell` key itself at harvest.
        let mut world = verb_world();
        world.fp.subtrees[0].values.push(SubtreeValue {
            subkey: String::new(),
            name: "MultiSelectModel".into(),
            hash: "1:ee".into(),
        });
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // A second `command` deeper in a verb.
        let mut world = verb_world();
        world.fp.subtrees[0]
            .subkeys
            .push(r"git_gui\shell\sub\command".into());
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );

        // No verbs at all: an empty `shell` key at harvest is nobody's.
        let mut world = verb_world();
        world.fp.subtrees[0].subkeys.clear();
        world.fp.subtrees[0].values.clear();
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NotAttributed)
        );
    }

    /// The rule names `shell` keys only, and the other four conditions still hold for them.
    #[test]
    fn verb_parent_rule_is_bounded() {
        // The same records under a key that is not called `shell`.
        let other = r"HKLM\SOFTWARE\Classes\LibraryFolder\background\menu";
        let mut world = verb_world();
        world.fixture.add_key(other);
        world.fp.subtrees = vec![unattributed_shell(other)];
        world.fp.ref_snapshot.clear();
        for (verb, exe) in [("git_gui", GIT_GUI), ("git_shell", GIT_BASH)] {
            let (subtrees, refs) = verb_records(other, verb, exe);
            world.fp.subtrees.extend(subtrees);
            world.fp.ref_snapshot.extend(refs);
        }
        assert_eq!(check(&world.ctx(), other), Err(NotProven::NotAttributed));

        // A `shell` key of clean Windows.
        let mut world = verb_world();
        world.baseline = Some(baseline(EDITION, &[LIBRARY_SHELL]));
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::InBaseline(LIBRARY_SHELL.into()))
        );
        // No matching baseline.
        world.baseline = None;
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::NoBaseline)
        );

        // The installer found the key, a key above it or one of its verbs in place.
        let old_verb = format!(r"{LIBRARY_SHELL}\git_gui");
        for existed in [
            LIBRARY_SHELL,
            r"HKLM\SOFTWARE\Classes\LibraryFolder\background",
            old_verb.as_str(),
        ] {
            let mut world = verb_world();
            world.fp.inno = vec![InnoRecord {
                kind: InnoRecordKind::RegDeleteKeyIfEmpty,
                target: Target::RegKey {
                    path: existed.into(),
                },
                view: Some(View::K64),
                user_hive: false,
                existed_before: true,
                shared: false,
                key_create: false,
            }];
            assert_eq!(
                check(&world.ctx(), LIBRARY_SHELL),
                Err(NotProven::NotAttributed),
                "{existed}"
            );
        }

        // TrustedInstaller, at harvest or now.
        let mut world = verb_world();
        world.fp.subtrees[0].ti_owned = true;
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::TrustedInstaller(LIBRARY_SHELL.into()))
        );
        let mut world = verb_world();
        world.fixture.set_ti_owned(LIBRARY_SHELL, true);
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::TrustedInstaller(LIBRARY_SHELL.into()))
        );

        // A verb that is still there: with a value it keeps the key; empty, its owner must be known,
        // because the harvest did not vouch for the owners below a subtree it could not attribute.
        let verb = format!(r"{LIBRARY_SHELL}\git_gui");
        let mut world = verb_world();
        world.fixture.add_key(&verb);
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::TrustedInstaller(verb.clone()))
        );
        world.fixture.set_ti_owned(&verb, false);
        assert!(check(&world.ctx(), LIBRARY_SHELL).is_ok());
        world
            .fixture
            .set_value(&verb, "", RegData::from_sz("Open Git &GUI here"));
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::HasValues(verb))
        );

        // A verb that appeared after the harvest is nobody's.
        let newcomer = format!(r"{LIBRARY_SHELL}\other_tool");
        let mut world = verb_world();
        world.fixture.add_key(&newcomer);
        world.fixture.set_ti_owned(&newcomer, false);
        assert_eq!(
            check(&world.ctx(), LIBRARY_SHELL),
            Err(NotProven::UnprovenSubkey(newcomer))
        );
    }

    /// Rule T input: a per-user registration yields UserWritable evidence, which policy will not accept
    /// as Tier A for a machine key.
    #[test]
    fn trust_follows_the_registration() {
        let mut world = world();
        world.fp.app.program_id = ProgramId::user(
            purge_guard::canon::GuardEnv::SAMPLE_SID,
            View::K64,
            "Git_is1",
        )
        .unwrap();
        let e = check(&world.ctx(), SH_AUTO_FILE).unwrap();
        assert_eq!(e.trust, SourceTrust::UserWritable);
    }

    #[test]
    fn limits_bound_the_walk() {
        let world = world();
        let mut ctx = world.ctx();
        ctx.limits.max_key_children = 1;
        assert_eq!(check(&ctx, SH_AUTO_FILE), Err(NotProven::TooLarge));
        ctx.limits = Default::default();
        ctx.limits.max_depth = 0;
        assert_eq!(check(&ctx, SH_AUTO_FILE), Err(NotProven::TooLarge));
    }
}
