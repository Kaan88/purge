//! Host tests of the Live sources: read only, except the junction test, which works inside a fresh
//! directory under `std::env::temp_dir()` and removes it again.
//!
//! The parity test runs the acceptance query set (Uninstall keys in both views, every loaded user's `Run`
//! key, a `Program Files` listing of depth 1, OS info) and prints what it saw; run it with
//! `cargo test -p purge-source live::tests::parity -- --nocapture`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use purge_win::reg::{Key, RegRoot, RegView};
use purge_win::{fs, msi, os, shelllink, sid};

use super::filesystem::{to_dir_entry, to_file_meta, to_volume_info};
use super::registry::to_reg_value;
use super::test_ffi;
use super::*;
use crate::filesystem::FileSystemSource;
use crate::registry::RegistrySource;
use crate::system::SystemSource;
use crate::types::{ExistsState, KnownFolder, SourceError};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

fn program_files() -> String {
    std::env::var("ProgramW6432")
        .or_else(|_| std::env::var("ProgramFiles"))
        .unwrap_or_else(|_| r"C:\Program Files".into())
}

fn me() -> String {
    sid::current_user_sid().expect("current user SID")
}

// -----------------------------------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------------------------------

#[test]
fn registry_agrees_with_direct_purge_win_calls() {
    let live = LiveRegistry::new();
    for (canon, view) in [
        (format!(r"HKLM\{UNINSTALL}"), RegView::K64),
        (
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
            RegView::K32,
        ),
    ] {
        let direct = Key::open(RegRoot::Hklm, UNINSTALL, view).unwrap();
        let names = direct.subkey_names().unwrap();
        assert_eq!(live.subkeys(&canon).unwrap(), names, "{canon}");
        let info = live.key_info(&canon).unwrap();
        let dinfo = direct.info().unwrap();
        assert_eq!(info.n_subkeys, dinfo.n_subkeys);
        assert_eq!(info.lwt.0, dinfo.last_write_time);
        assert!(!info.is_link);
        for name in names.iter().take(25) {
            let sub = direct.open_subkey(name).unwrap();
            let want: Vec<_> = sub
                .values()
                .unwrap()
                .into_iter()
                .map(to_reg_value)
                .collect();
            let key = format!(r"{canon}\{name}");
            assert_eq!(live.values(&key).unwrap(), want, "{key}");
            if let Some(v) = want.first() {
                assert_eq!(live.value(&key, &v.name).unwrap(), v.data, "{key}");
            }
        }
    }

    let run = format!(r"HKU\{}\{RUN}", me());
    let direct: Vec<_> = Key::open(RegRoot::Hku, &format!(r"{}\{RUN}", me()), RegView::K64)
        .and_then(|k| k.values())
        .map(|v| v.into_iter().map(to_reg_value).collect())
        .unwrap_or_default();
    assert_eq!(live.values(&run).unwrap_or_default(), direct);

    assert_eq!(
        live.loaded_user_sids().unwrap(),
        purge_win::reg::loaded_user_sids().unwrap()
    );
    let ccs = purge_win::reg::current_control_set().unwrap();
    assert_eq!(
        format!("ControlSet{:03}", live.current_control_set().unwrap()),
        ccs
    );
    assert_eq!(
        live.value(&format!(r"HKLM\{UNINSTALL}"), "no such value \u{1}x"),
        Err(SourceError::NotFound)
    );
    assert_eq!(
        live.key_info(r"HKLM\SOFTWARE\Purge test key that does not exist"),
        Err(SourceError::NotFound)
    );
    assert_eq!(
        live.key_exists(r"HKLM\SOFTWARE\Purge test key that does not exist"),
        ExistsState::Absent
    );
}

#[test]
fn links_are_reported_and_only_g1_links_resolved() {
    let live = LiveRegistry::new();
    let sid = me();

    // The user's Software\Classes is a link: reported, not followed.
    let info = live
        .key_info(&format!(r"HKU\{sid}\Software\Classes"))
        .unwrap();
    assert!(info.is_link, "{info:?}");
    assert!(
        info.link_target
            .as_deref()
            .is_some_and(|t| t.to_ascii_uppercase().ends_with("_CLASSES")),
        "{info:?}"
    );
    // Below it, the physical classes hive is read.
    assert_eq!(
        live.subkeys(&format!(r"HKU\{sid}\Software\Classes\CLSID")),
        live.subkeys(&format!(r"HKU\{sid}_Classes\CLSID"))
    );

    // CurrentControlSet goes to ControlSet00N.
    let ccs = purge_win::reg::current_control_set().unwrap();
    assert_eq!(
        live.subkeys(r"HKLM\SYSTEM\CurrentControlSet\Services")
            .unwrap(),
        live.subkeys(&format!(r"HKLM\SYSTEM\{ccs}\Services"))
            .unwrap()
    );

    // The 32-bit view of Classes resolves through the redirector, not through the
    // `SOFTWARE\WOW6432Node\Classes` link.
    let k32 = live
        .subkeys(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID")
        .unwrap();
    let physical = Key::open(
        RegRoot::Hklm,
        r"SOFTWARE\Classes\WOW6432Node\CLSID",
        RegView::K64,
    )
    .unwrap()
    .subkey_names()
    .unwrap();
    assert_eq!(k32, physical);
    // The bare node is the physical WOW6432Node key.
    assert_eq!(
        live.subkeys(r"HKLM\SOFTWARE\WOW6432Node").unwrap(),
        Key::open(RegRoot::Hklm, r"SOFTWARE\WOW6432Node", RegView::K64)
            .unwrap()
            .subkey_names()
            .unwrap()
    );

    // A path through any other link is refused, never followed.
    let shared = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileList";
    if live.key_info(shared).is_ok_and(|i| i.is_link) {
        assert_eq!(
            live.subkeys(&format!(r"{shared}\S-1-5-18")),
            Err(SourceError::ReparsePoint)
        );
        assert_eq!(
            live.key_exists(&format!(r"{shared}\S-1-5-18")),
            ExistsState::Unknown
        );
    }

    // Non-canonical roots are refused.
    assert!(matches!(
        live.key_info(r"HKCU\Software"),
        Err(SourceError::InvalidPath(_))
    ));
}

/// `.DEFAULT` and the service accounts have no classes hive: `Software\Classes` is an ordinary key and a
/// key below it is read where it is. That spelling is also the canonical one (`purge-model` renders it
/// unchanged, `purge-guard` leaves it alone), so the key a caller holds in place and the key a target
/// carries are read as one key. `HKU\<name>_Classes` names no hive.
#[test]
fn classes_of_a_hive_without_a_classes_hive_are_read_in_place() {
    let live = LiveRegistry::new();
    let mut read = 0;
    for sid in [".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"] {
        assert!(!purge_model::has_classes_hive(sid));
        let in_place = format!(r"HKU\{sid}\Software\Classes");
        // A service account's key may be closed to an unelevated run.
        let Ok(direct) = Key::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software\Classes"),
            RegView::K64,
        ) else {
            continue;
        };
        let info = live.key_info(&in_place).unwrap();
        assert!(!info.is_link, "{in_place}: {info:?}");
        let names = direct.subkey_names().unwrap();
        assert_eq!(live.subkeys(&in_place).unwrap(), names, "{in_place}");
        assert_eq!(
            live.key_exists(&format!(r"HKU\{sid}_Classes")),
            ExistsState::Absent,
            "{sid}"
        );
        for name in names.iter().take(8) {
            let key = format!(r"{in_place}\{name}");
            let (hive, view, path) = purge_model::TypedTarget::parse_key_path(&key).unwrap();
            let canonical =
                purge_model::TypedTarget::new(hive, view, path, purge_model::RegKind::Key)
                    .key_path();
            assert_eq!(canonical, key);
            let Ok(sub) = direct.open_subkey(name) else {
                continue;
            };
            let want = sub.info().unwrap();
            for spelling in [&key, &canonical] {
                let got = live.key_info(spelling).unwrap();
                assert_eq!(got.n_subkeys, want.n_subkeys, "{spelling}");
                assert_eq!(got.lwt.0, want.last_write_time, "{spelling}");
                assert_eq!(
                    live.key_exists(spelling),
                    ExistsState::Present,
                    "{spelling}"
                );
            }
            assert_eq!(
                live.key_exists(&format!(r"HKU\{sid}_Classes\{name}")),
                ExistsState::Absent,
                "{sid} {name}"
            );
            read += 1;
        }
    }
    println!("classes keys read in place: {read}");
}

/// `HKU\S-1-5-18` is not a hive: it is Windows' registry link to the `.DEFAULT` hive, and it is listed
/// among the loaded user hives. The link key itself is read; a path through it is refused, and the
/// same key is read in `.DEFAULT`. (`purge_index::ownership::user_hive_name` relies on exactly this
/// to read LocalSystem's dependency records where they are.)
#[test]
fn local_system_hive_is_the_link_to_the_default_hive() {
    let live = LiveRegistry::new();
    assert!(
        live.loaded_user_sids()
            .unwrap()
            .iter()
            .any(|sid| sid == "S-1-5-18")
    );
    let info = live.key_info(r"HKU\S-1-5-18").unwrap();
    assert!(info.is_link, "{info:?}");
    let target = info.link_target.unwrap();
    assert!(
        target.eq_ignore_ascii_case(r"\Registry\User\.Default"),
        "{target}"
    );
    assert_eq!(
        live.subkeys(r"HKU\S-1-5-18\Software"),
        Err(SourceError::ReparsePoint)
    );
    assert_eq!(
        live.subkeys(r"HKU\S-1-5-18\Software\Classes\Installer\Dependencies"),
        Err(SourceError::ReparsePoint)
    );
    assert!(!live.key_info(r"HKU\.DEFAULT").unwrap().is_link);
    assert!(!live.subkeys(r"HKU\.DEFAULT\Software").unwrap().is_empty());
}

/// `KeyInfo` without the field a walker leaves out.
fn walk_facts(info: &crate::types::KeyInfo) -> (u64, u32, u32, bool, Option<String>) {
    (
        info.lwt.0,
        info.n_values,
        info.n_subkeys,
        info.is_link,
        info.link_target.clone(),
    )
}

/// Enters `key` with the walker and reads it by path: both must agree.
fn agree(
    live: &LiveRegistry,
    walker: &mut dyn crate::registry::KeyWalker,
    key: &str,
) -> Vec<String> {
    let walked = walker.enter(key);
    let by_path = live.key_info(key);
    assert_eq!(
        walked.as_ref().map(walk_facts),
        by_path.as_ref().map(walk_facts),
        "{key}"
    );
    let Ok(info) = walked else {
        return Vec::new();
    };
    if info.is_link {
        return Vec::new();
    }
    assert_eq!(walker.values(), live.values(key), "{key}");
    let names = walker.subkeys();
    assert_eq!(names, live.subkeys(key), "{key}");
    names.unwrap_or_default()
}

/// The walker reads exactly what the path calls read, along depth-first walks and across jumps
/// between hives, views, the control set alias, links and missing keys.
#[test]
fn walker_reads_what_path_calls_read() {
    let live = LiveRegistry::new();
    let sid = me();
    let mut walker = live.walker();
    let roots = [
        r"HKLM\SOFTWARE\Classes\CLSID".to_string(),
        r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID".to_string(),
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts".to_string(),
        r"HKLM\SYSTEM\CurrentControlSet\Control\Nls".to_string(),
        format!(r"HKU\{sid}_Classes"),
        format!(r"HKU\{sid}\Software\Classes"),
        r"HKLM\SOFTWARE\WOW6432Node".to_string(),
    ];
    for root in &roots {
        let mut stack = vec![root.clone()];
        let mut entered = 0;
        while let Some(key) = stack.pop() {
            entered += 1;
            if entered > 600 {
                break;
            }
            let children = agree(&live, walker.as_mut(), &key);
            stack.extend(children.iter().rev().map(|c| format!(r"{key}\{c}")));
        }
    }
    // Jumps: a missing key below a deep one, its parent again, a path through a link, the root of a
    // hive, a non-canonical root, and back into a deep key of the other view.
    for key in [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Purge walker test that does not exist"
            .to_string(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion".to_string(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
        format!(r"HKU\{sid}\Software\Classes\CLSID"),
        format!(r"HKU\{sid}\Software\Classes"),
        format!(r"HKU\{sid}"),
        "HKU".to_string(),
        r"HKCU\Software".to_string(),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18"
            .to_string(),
    ] {
        agree(&live, walker.as_mut(), &key);
    }
}

/// Runs `reg.exe` with `args` and requires success.
fn reg_exe(args: &[&str]) {
    let out = Command::new("reg")
        .args(args)
        .output()
        .expect("run reg.exe");
    assert!(out.status.success(), "reg {args:?}: {out:?}");
}

/// A scratch key under the current user's `Software`, deleted on drop.
struct ScratchKey(String);

impl Drop for ScratchKey {
    fn drop(&mut self) {
        let _ = Command::new("reg").args(["delete", &self.0, "/f"]).output();
    }
}

/// A key the walker kept open as an ancestor is deleted and made again under the same name: the next
/// key below it reads as a fresh open reads it, never through the deleted key. (Writes and removes a
/// scratch key under `HKCU\Software`.)
#[test]
fn walker_reads_through_a_deleted_and_recreated_ancestor_as_a_fresh_open() {
    let name = format!("Purge walker test {}", std::process::id());
    let hkcu = format!(r"HKCU\Software\{name}");
    let _scratch = ScratchKey(hkcu.clone());
    reg_exe(&[
        "add",
        &format!(r"{hkcu}\A\B\C"),
        "/v",
        "x",
        "/d",
        "old",
        "/f",
    ]);
    let live = LiveRegistry::new();
    let base = format!(r"HKU\{}\Software\{name}", me());
    let mut walker = live.walker();
    agree(&live, walker.as_mut(), &format!(r"{base}\A\B\C"));

    reg_exe(&["delete", &format!(r"{hkcu}\A"), "/f"]);
    reg_exe(&[
        "add",
        &format!(r"{hkcu}\A\B\D"),
        "/v",
        "y",
        "/d",
        "new",
        "/f",
    ]);
    // `A` and `B` are kept from the walk to `C`, but they are other keys now.
    let names = agree(&live, walker.as_mut(), &format!(r"{base}\A\B\D"));
    assert!(names.is_empty());
    assert_eq!(
        walker.values().unwrap().first().map(|v| v.name.clone()),
        Some("y".to_string())
    );
    assert_eq!(
        walker.enter(&format!(r"{base}\A\B\C")),
        Err(SourceError::NotFound)
    );
    agree(&live, walker.as_mut(), &format!(r"{base}\A\B"));
    agree(&live, walker.as_mut(), &format!(r"{base}\A\B\D"));
}

/// A link key entered while it has no target yet (a link is made in two steps: the key, then its
/// `SymbolicLinkValue`) is asked again when the walker goes below it, also for a path the walker never
/// listed: refused as a path through a link, never read in the target (review S1, experiment E4b).
/// (Writes and removes `HKU\<SID>\Software\PurgeTest-<random>`.)
#[test]
fn walker_refuses_a_path_below_a_link_that_got_its_target_after_it_was_entered() {
    let mut scratch = test_ffi::Scratch::new(&me());
    scratch.create(r"T\Sub").set_sz("x", "in the target only");
    scratch.create(r"Plain\Sub").set_sz("y", "plain");
    let link = scratch.link("L");
    let live = LiveRegistry::new();
    let mut walker = live.walker();

    let info = walker.enter(&scratch.canon("L")).unwrap();
    assert_eq!((info.n_values, info.n_subkeys, info.is_link), (0, 0, false));
    link.set_link_target(&scratch.nt_path("T"));
    let below = scratch.canon(r"L\Sub");
    assert_eq!(walker.enter(&below), Err(SourceError::ReparsePoint));
    assert_eq!(live.key_info(&below), Err(SourceError::ReparsePoint));
    // Entered again, the link reports its target and nothing below it reads.
    let again = walker.enter(&scratch.canon("L")).unwrap();
    assert_eq!(
        again.link_target.as_deref(),
        Some(scratch.nt_path("T").as_str())
    );
    assert_eq!(walker.enter(&below), Err(SourceError::ReparsePoint));
    // An ordinary key with subkeys is passed as before, and the target reads by its own path.
    agree(&live, walker.as_mut(), &scratch.canon("Plain"));
    agree(&live, walker.as_mut(), &scratch.canon(r"Plain\Sub"));
    assert_eq!(walker.values().unwrap()[0].name, "y");
    agree(&live, walker.as_mut(), &scratch.canon(r"T\Sub"));
    assert_eq!(walker.values().unwrap()[0].name, "x");
}

/// A key deleted after the walker entered it reads as gone ([`SourceError::NotFound`]), as reading it by
/// path does, not as unreadable (review S2: `ERROR_KEY_DELETED` through the kept handle). Its values
/// were read when it was entered, while it was there: the walker hands those out once, and every
/// read made after the deletion says the key is gone. (Writes and removes
/// `HKU\<SID>\Software\PurgeTest-<random>`.)
#[test]
fn walker_reads_a_key_deleted_after_it_was_entered_as_not_found() {
    let scratch = test_ffi::Scratch::new(&me());
    scratch.create("Gone").set_sz("a", "b");
    scratch.create(r"Gone\Child");
    let live = LiveRegistry::new();
    let mut walker = live.walker();
    let key = scratch.canon("Gone");
    let info = walker.enter(&key).unwrap();
    assert_eq!((info.n_values, info.n_subkeys), (1, 1));
    scratch.delete(r"Gone\Child").unwrap();
    scratch.delete("Gone").unwrap();
    let entered = walker.values().unwrap();
    assert_eq!(entered.len(), 1);
    assert_eq!(entered[0].name, "a");
    assert_eq!(walker.values(), Err(SourceError::NotFound));
    assert_eq!(walker.subkeys(), Err(SourceError::NotFound));
    assert_eq!(live.values(&key), Err(SourceError::NotFound));
    assert_eq!(live.key_exists(&key), ExistsState::Absent);
}

// -----------------------------------------------------------------------------------------------------
// Filesystem
// -----------------------------------------------------------------------------------------------------

#[test]
fn filesystem_agrees_with_direct_purge_win_calls() {
    let live = LiveFileSystem::new();
    let pf = program_files();
    let want: Vec<_> = fs::list_dir(Path::new(&pf))
        .unwrap()
        .into_iter()
        .map(to_dir_entry)
        .collect();
    assert_eq!(live.list_dir(&pf).unwrap(), want);
    let meta = live.metadata(&pf).unwrap();
    assert!(meta.is_dir());
    let mut direct = to_file_meta(&fs::metadata(Path::new(&pf)).unwrap());
    // Access times may move between the two reads.
    direct.times.accessed = meta.times.accessed;
    assert_eq!(meta, direct);
    assert_eq!(live.exists(&pf), ExistsState::Present);
    let vol = live.volume_info(&pf).unwrap();
    assert_eq!(
        vol,
        to_volume_info(&fs::volume_info(Path::new(&pf)).unwrap())
    );

    let missing = format!(r"{pf}\Purge test folder that does not exist\x.exe");
    let want = if vol.proves_absence() {
        ExistsState::Absent
    } else {
        ExistsState::Unknown
    };
    assert_eq!(live.exists(&missing), want);
    assert_eq!(live.metadata(&missing), Err(SourceError::NotFound));
    assert_eq!(live.exists("relative\\path"), ExistsState::Unknown);

    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let notepad = format!(r"{windir}\System32\notepad.exe");
    if live.exists(&notepad).is_present() {
        let head = live.read_bytes(&notepad, 2).unwrap();
        assert_eq!(head, b"MZ");
        let v = live
            .version_info(&notepad)
            .unwrap()
            .expect("notepad has version info");
        assert!(v.company_name.is_some());
        // Catalog-signed: no embedded signer, and no panic.
        let _ = live.signer_cn(&notepad).unwrap();
        assert_eq!(live.read_bytes(&windir, 4), Err(SourceError::WrongKind));
        assert_eq!(live.list_dir(&notepad), Err(SourceError::WrongKind));
        assert!(
            live.long_path(&notepad)
                .unwrap()
                .eq_ignore_ascii_case(&notepad)
        );
    }
    assert_eq!(live.is_admin_only_writable(&windir), Ok(true));
    let temp = std::env::temp_dir();
    assert_eq!(
        live.is_admin_only_writable(&temp.to_string_lossy()),
        Ok(false)
    );
}

/// A scratch directory under the temp dir, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn junction_is_reported_and_not_traversed() {
    let base = std::env::temp_dir().join(format!("purge-p20-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("target")).unwrap();
    std::fs::write(base.join("target").join("inside.txt"), b"x").unwrap();
    let scratch = Scratch(base.clone());
    let junction = base.join("jn");
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(base.join("target"))
        .output()
        .expect("run mklink");
    assert!(status.status.success(), "mklink /J failed");

    let live = LiveFileSystem::new();
    let j = junction.to_string_lossy().into_owned();
    let meta = live.metadata(&j).unwrap();
    assert!(meta.is_reparse_point());
    assert_eq!(meta.reparse_tag, fs::IO_REPARSE_TAG_MOUNT_POINT);
    assert_eq!(live.list_dir(&j), Err(SourceError::ReparsePoint));
    let listed = live.list_dir(&base.to_string_lossy()).unwrap();
    let entry = listed.iter().find(|e| e.name == "jn").unwrap();
    assert_eq!(entry.meta.reparse_tag, fs::IO_REPARSE_TAG_MOUNT_POINT);
    assert_eq!(live.exists(&j), ExistsState::Present);
    // Behind a junction a missing name proves nothing.
    assert_eq!(
        live.exists(&format!(r"{j}\missing.txt")),
        ExistsState::Unknown
    );
    // Next to it, it does (when the temp dir is on a fixed NTFS/ReFS volume).
    let beside = base.join("missing.txt").to_string_lossy().into_owned();
    let proves = live
        .volume_info(&base.to_string_lossy())
        .is_ok_and(|v| v.proves_absence());
    assert_eq!(
        live.exists(&beside),
        if proves {
            ExistsState::Absent
        } else {
            ExistsState::Unknown
        }
    );
    // Removing the junction first leaves the target alone.
    std::fs::remove_dir(&junction).unwrap();
    assert!(base.join("target").join("inside.txt").exists());
    drop(scratch);
}

/// Up to `max` `.lnk` files under `dir`, two levels deep.
fn find_links(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let _ = fs::walk(dir, Some(2), |p, e| {
        if out.len() < max
            && !e.is_dir()
            && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
        {
            out.push(p.to_path_buf());
        }
        true
    });
    out
}

#[test]
fn shortcuts_read_on_worker_match_direct_reads() {
    let programs = purge_win::known_folders::known_folder(
        purge_win::known_folders::KnownFolder::CommonPrograms,
    )
    .unwrap();
    let links = find_links(&programs, 8);
    let live = LiveFileSystem::new();
    std::thread::scope(|s| {
        for chunk in links.chunks(2) {
            let live = &live;
            s.spawn(move || {
                for l in chunk {
                    let want = shelllink::read_shell_link(l).unwrap();
                    let got = live.read_shortcut(&l.to_string_lossy()).unwrap();
                    assert_eq!(got.raw_path, want.raw_path, "{}", l.display());
                    assert_eq!(got.args, want.arguments);
                    assert_eq!(got.workdir, want.working_directory);
                    assert_eq!(got.aumid, want.aumid);
                }
            });
        }
    });
    assert_eq!(
        live.read_shortcut(&programs.to_string_lossy()),
        Err(SourceError::WrongKind)
    );
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    assert!(live.read_shortcut(&format!(r"{windir}\win.ini")).is_err());
    assert_eq!(
        live.read_shortcut(r"C:\Purge test missing\x.lnk"),
        Err(SourceError::NotFound)
    );
}

// -----------------------------------------------------------------------------------------------------
// System
// -----------------------------------------------------------------------------------------------------

#[test]
fn system_facts_agree_with_direct_purge_win_calls() {
    let live = LiveSystem::new();
    let v = os::os_version().unwrap();
    let info = live.os_info().unwrap();
    assert_eq!(
        (info.edition.as_str(), info.build, info.ubr),
        (v.edition_id.as_str(), v.build, v.ubr)
    );
    assert_eq!(live.user_sid().unwrap(), me());
    assert_eq!(live.elevated(), sid::is_elevated().unwrap());

    let profiles = live.profiles().unwrap();
    let direct = sid::profiles().unwrap();
    assert_eq!(
        profiles.iter().map(|p| &p.sid).collect::<Vec<_>>(),
        direct.iter().map(|p| &p.sid).collect::<Vec<_>>()
    );
    for (p, d) in profiles.iter().zip(&direct) {
        assert!(
            p.path.eq_ignore_ascii_case(&d.path.to_string_lossy()),
            "{p:?}"
        );
    }

    let kf = live.known_folders().unwrap();
    for f in [
        KnownFolder::ProgramFiles,
        KnownFolder::LocalAppData,
        KnownFolder::CommonPrograms,
    ] {
        assert!(kf.contains_key(&f), "{f} missing");
    }

    // The registry-built environment matches the process environment for stable variables.
    let env = live.env().unwrap();
    for name in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramData",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ] {
        if let Ok(want) = std::env::var(name) {
            let got = env
                .get(&name.to_uppercase())
                .unwrap_or_else(|| panic!("{name} missing"));
            assert!(got.eq_ignore_ascii_case(&want), "{name}: {got} vs {want}");
        }
    }
    assert!(env.keys().all(|k| *k == k.to_uppercase()));
    assert!(
        env.get("PATH")
            .is_some_and(|p| p.to_ascii_lowercase().contains("system32")),
        "PATH"
    );

    let scope = if live.elevated() {
        msi::EnumScope::AllUsers
    } else {
        msi::EnumScope::CurrentUser
    };
    let products = live.msi_products().unwrap();
    let codes: BTreeSet<String> = products.iter().map(|p| p.code.clone()).collect();
    let direct: BTreeSet<String> = msi::enum_products(scope)
        .unwrap()
        .into_iter()
        .map(|r| r.product_code.to_ascii_uppercase())
        .collect();
    assert_eq!(codes, direct);
    if let Some(p) = products.first() {
        assert_eq!(live.msi_product_state_all(&p.code).unwrap().len(), 3);
    }
}

#[test]
fn processes_include_this_process_with_its_image_path() {
    let procs = LiveSystem::new().processes().unwrap();
    println!("{} processes", procs.len());
    let me = procs
        .iter()
        .find(|p| p.pid == std::process::id())
        .expect("own PID in the process list");
    let exe = std::env::current_exe().unwrap();
    assert!(
        exe.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case(&me.name)),
        "{me:?}"
    );
    assert_eq!(me.path.as_deref().map(Path::new), Some(exe.as_path()));
    assert!(me.ppid.is_some_and(|pp| pp != me.pid));
    // The direct snapshot sees the same process ids (a few may start or exit in between).
    let direct: BTreeSet<u32> = purge_win::process::snapshot_processes()
        .unwrap()
        .iter()
        .map(|e| e.pid)
        .collect();
    let shared = procs.iter().filter(|p| direct.contains(&p.pid)).count();
    assert!(
        shared * 10 >= procs.len() * 9,
        "{shared} of {}",
        procs.len()
    );
}

#[test]
fn packages_list_without_panicking() {
    let live = LiveSystem::new();
    match live.packages() {
        Ok(packages) => {
            println!("{} packages", packages.len());
            for p in packages.iter().filter(|p| p.is_sparse()) {
                println!("sparse: {} -> {:?}", p.full_name, p.external_location);
            }
            assert!(packages.iter().all(|p| !p.full_name.is_empty()));
            assert!(
                packages
                    .iter()
                    .all(|p| p.sparse == p.external_location.is_some())
            );
            if !live.elevated() {
                // A current-user listing is recorded for the engine account.
                assert!(packages.iter().all(|p| p.users == [me()]));
            }
        }
        // A service account without a user profile has no package repository to ask.
        Err(e) => println!("packages not available here: {e:?}"),
    }
}

#[test]
fn for_user_with_own_sid_matches_default() {
    let mine = LiveSystem::new();
    let explicit = LiveSystem::for_user(me().to_lowercase());
    assert_eq!(explicit.user_sid().unwrap(), me().to_ascii_uppercase());
    assert_eq!(explicit.env().unwrap(), mine.env().unwrap());
    assert_eq!(
        explicit.known_folders().unwrap(),
        mine.known_folders().unwrap()
    );
}

// -----------------------------------------------------------------------------------------------------
// Acceptance: the parity query set
// -----------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Tally {
    ok: usize,
    not_found: usize,
    denied: usize,
    other: usize,
}

impl Tally {
    fn add<T>(&mut self, r: &Result<T, SourceError>) {
        match r {
            Ok(_) => self.ok += 1,
            Err(SourceError::NotFound) => self.not_found += 1,
            Err(SourceError::AccessDenied) => self.denied += 1,
            Err(_) => self.other += 1,
        }
    }
}

#[test]
fn parity_query_set_runs_without_panics() {
    let live = Live::new();
    let mut tally = Tally::default();

    for root in [
        format!(r"HKLM\{UNINSTALL}"),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
    ] {
        let subkeys = live.registry.subkeys(&root).unwrap();
        let mut named = 0;
        for name in &subkeys {
            let key = format!(r"{root}\{name}");
            tally.add(&live.registry.key_info(&key));
            let values = live.registry.values(&key);
            tally.add(&values);
            if values
                .ok()
                .is_some_and(|v| v.iter().any(|v| v.name == "DisplayName"))
            {
                named += 1;
            }
        }
        println!(
            "{root}: {} entries, {named} with DisplayName",
            subkeys.len()
        );
    }

    for sid in live.registry.loaded_user_sids().unwrap() {
        let key = format!(r"HKU\{sid}\{RUN}");
        let r = live.registry.values(&key);
        tally.add(&r);
        match r {
            Ok(v) => println!("{key}: {} values", v.len()),
            Err(e) => println!("{key}: {e}"),
        }
    }

    // A key nobody but SYSTEM may read: counted, not fatal.
    let security = live.registry.subkeys(r"HKLM\SECURITY\Policy");
    tally.add(&security);
    println!(r"HKLM\SECURITY\Policy: {:?}", security.map(|s| s.len()));

    let pf = program_files();
    let entries = live.fs.list_dir(&pf).unwrap();
    for e in &entries {
        let p = format!(r"{pf}\{}", e.name);
        tally.add(&live.fs.metadata(&p));
        let _ = live.fs.exists(&p);
    }
    println!(
        "{pf}: {} entries, {} reparse points",
        entries.len(),
        entries.iter().filter(|e| e.meta.is_reparse_point()).count()
    );

    let os = live.system.os_info().unwrap();
    println!("os: {} ({})", os.baseline_name(), os.edition);
    println!("elevated: {}", live.system.elevated());
    println!("tally: {tally:?}");
    assert!(tally.ok > 0);
}
