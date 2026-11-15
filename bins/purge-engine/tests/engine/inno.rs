//! An Inno Setup app (Tidy Notes) end to end through the CLI.

use purge_engine::cli::Exit;
use purge_engine::cli::output::{read_json, sidecar_path};
use purge_model::{
    Band, Fingerprint, InventoryDoc, Plan, RootKind, RunDoc, RunOutcome, ScanMode, Target,
};
use purge_plan::emit::ScanDoc;
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::inno::*;
use crate::common::{FakeHost, Switch, arg, cli, golden, inno_log, machine, rig, scratch};

const APP_DIR: &str = r"C:\Program Files\Tidy Notes";
const KEY_NAME: &str = "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}_is1";

/// Adds the uninstall log the Tidy Notes installer wrote when it made its own folder.
fn with_log(f: &mut Fixture) {
    with_log_of(f, true);
}

/// Adds the uninstall log of the Tidy Notes installer. `created_dir`: the installer made the app
/// directory and logged that; without it the folder was there before the install.
fn with_log_of(f: &mut Fixture, created_dir: bool) {
    with_log_and(f, created_dir, &[]);
}

/// [`with_log_of`] with more records of the same install run.
fn with_log_and(f: &mut Fixture, created_dir: bool, more: &[crate::common::Rec<'_>]) {
    let made: &[&str] = if created_dir {
        &[APP_DIR]
    } else {
        // Some other directory: the record kind stays in the log, the app directory is not in it.
        &[r"C:\Program Files\Tidy Notes\bin"]
    };
    let mut records: Vec<crate::common::Rec<'_>> = vec![
        (START, 0, &["PC", "tester", APP_DIR, ""]),
        (DIR, 2, made),
        (FILE, 0, &[r"C:\Program Files\Tidy Notes\tidynotes.exe"]),
        (FILE, 0, &[r"C:\Program Files\Tidy Notes\bin\tidy-cli.exe"]),
        (FILE, 0, &[r"C:\Program Files\Tidy Notes\plugins\spell.dll"]),
        (DIR, DIR_TREE, &[r"C:\Program Files\Tidy Notes\plugins"]),
        (KEY, HKLM, &[r"Software\Acme Tools\Tidy Notes"]),
        (KEY_IF_EMPTY, HKLM, &[r"Software\Acme Tools"]),
        (KEY, HKLM, &[r"Software\Classes\TidyNotes.Document"]),
        (
            VALUE,
            HKLM,
            &[
                r"Software\Classes\.tidy\OpenWithProgids",
                "TidyNotes.Document",
            ],
        ),
        (
            KEY,
            HKLM,
            &[r"Software\Microsoft\Windows\CurrentVersion\App Paths\tidynotes.exe"],
        ),
        (
            VALUE,
            HKCU,
            &[
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "TidyNotes",
            ],
        ),
    ];
    records.extend_from_slice(more);
    records.push((END, 0, &[]));
    let log = inno_log(
        "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
        "Tidy Notes",
        ADMIN_64,
        &records,
    );
    f.add_file_with_content(r"C:\Program Files\Tidy Notes\unins000.dat", log);
}

/// The Tidy Notes machine.
pub fn tidy_notes() -> Switch {
    Switch::new(machine("inno", with_log))
}

fn item<'p>(plan: &'p Plan, target: &Target) -> Option<&'p purge_model::PlanItem> {
    plan.items.iter().find(|i| &i.target == target)
}

#[test]
fn inno_app_through_the_cli() {
    let machine = tidy_notes();
    let mut host = FakeHost::new(&machine, Some(0), true);
    let dir = scratch("inno-cli");
    let (fp_path, run_path, plan_path) = (
        dir.join("fp.json"),
        dir.join("run.json"),
        dir.join("plan-purge.json"),
    );

    // inventory --json
    let ran = cli(&machine, &mut host, &["inventory", "--json"]);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let inv: InventoryDoc = serde_json::from_str(&ran.out).unwrap();
    let entry = inv
        .entries
        .iter()
        .find(|e| e.program_id.key_name() == KEY_NAME)
        .expect("the Tidy Notes entry");
    let id = entry.program_id.to_string();
    assert_eq!(id, format!("HKLM|64|{KEY_NAME}"));

    // harvest
    let ran = cli(&machine, &mut host, &["harvest", &id, "-o", arg(&fp_path)]);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.is_empty());
    assert!(ran.err.contains("wrote the fingerprint"), "{}", ran.err);
    let fp: Fingerprint = read_json(&fp_path).unwrap();
    assert!(
        fp.roots
            .iter()
            .any(|r| r.path == APP_DIR && r.kind == RootKind::InstallRoot),
        "{:?}",
        fp.roots
    );
    assert!(fp.inno.len() >= 8, "{:?}", fp.inno);
    assert!(fp.window.t_start.is_none() && fp.verify_gone.is_none());

    // A post scan before the uninstall is a precondition error.
    let ran = cli(
        &machine,
        &mut host,
        &["scan", "--fp", arg(&fp_path), "-o", arg(&plan_path)],
    );
    assert_eq!(ran.exit, Exit::Usage, "{}", ran.err);
    assert!(ran.err.contains("--mode post needs"), "{}", ran.err);
    assert!(!plan_path.exists());

    // uninstall --quiet --fp
    let ran = cli(
        &machine,
        &mut host,
        &[
            "uninstall",
            KEY_NAME,
            "--quiet",
            "--fp",
            arg(&fp_path),
            "-o",
            arg(&run_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert_eq!(
        host.spawned,
        [r#""C:\Program Files\Tidy Notes\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"#]
    );
    let run: RunDoc = read_json(&run_path).unwrap();
    assert_eq!(run.outcome, RunOutcome::Success);
    assert!(run.verify_gone.is_passed(), "{:?}", run.verify_gone);
    let fp: Fingerprint = read_json(&fp_path).unwrap();
    assert_eq!(fp.window.t_start, Some(run.t_start));
    assert_eq!(fp.window.t_end, Some(run.t_end));
    assert_eq!(fp.verify_gone, Some(run.verify_gone));
    assert!(fp.co_removed.is_empty());

    // scan --mode post
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--mode",
            "post",
            "--app",
            "tidynotes",
            "-o",
            arg(&plan_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let text = std::fs::read_to_string(&plan_path).unwrap();
    assert!(!text.starts_with('\u{feff}'));
    golden("inno.plan.json", &text);
    let plan: Plan = serde_json::from_str(&text).unwrap();
    assert_eq!(
        (plan.app.as_str(), plan.mode),
        ("tidynotes", ScanMode::Post)
    );
    let rig: rig::Plan = serde_json::from_str(&text).expect("the rig reads the plan");
    assert_eq!(
        (rig.schema.as_str(), rig.tool.as_str()),
        ("purge.plan/0", "purge")
    );
    let sidecar: ScanDoc = read_json(&sidecar_path(&plan_path)).unwrap();
    assert!(dir.join("plan-purge.scan.json").exists());
    assert_eq!(sidecar.items.len(), plan.items.len());

    // What must and must not be offered.
    let root = item(
        &plan,
        &Target::Path {
            path: APP_DIR.into(),
        },
    )
    .expect("the install dir is offered");
    assert_eq!(root.band, Band::Safe, "{plan:#?}");
    // This run has no baseline of its Windows. A key record of the log says "delete this key on
    // uninstall", not "the installer made it", and nothing here shows the key is not older: the
    // logged vendor key (delete-if-empty) and the logged ProgID key are listed, not preselected.
    for logged in [
        r"HKLM\SOFTWARE\Acme Tools",
        r"HKLM\SOFTWARE\Classes\TidyNotes.Document",
    ] {
        let key = item(
            &plan,
            &Target::RegKey {
                path: logged.into(),
            },
        )
        .expect("the logged key is offered");
        assert_eq!(
            (key.band, key.preselected),
            (Band::Likely, false),
            "{logged}"
        );
    }
    // The app's own settings key is the app's by more than the record, and the values in the ProgID
    // key point at the app from the app's own registration: these stay preselected.
    let app_key = item(
        &plan,
        &Target::RegKey {
            path: r"HKLM\SOFTWARE\Acme Tools\Tidy Notes".into(),
        },
    )
    .expect("the app's settings key is offered");
    assert_eq!((app_key.band, app_key.preselected), (Band::Safe, true));
    let command = item(
        &plan,
        &Target::RegValue {
            path: r"HKLM\SOFTWARE\Classes\TidyNotes.Document\shell\open\command".into(),
            name: String::new(),
        },
    )
    .expect("the ProgID's command is offered");
    assert_eq!((command.band, command.preselected), (Band::Safe, true));
    for i in &plan.items {
        let text = format!("{:?}", i.target);
        assert!(!text.contains("todo.tidy"), "user data offered: {i:?}");
        if text.contains("Example Mail") || text.contains("ExampleMail") {
            assert!(
                !i.preselected && i.band != Band::Safe,
                "another app's item: {i:?}"
            );
        }
    }

    // plan show
    let ran = cli(&machine, &mut host, &["plan", "show", arg(&plan_path)]);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out
            .contains(&format!("hash {} (policy", sidecar.plan_hash)),
        "{}",
        ran.out
    );
    golden("inno.plan-show.txt", &ran.out);

    // The whole flow is deterministic: a second scan gives the same bytes.
    let again = dir.join("again.json");
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--app",
            "tidynotes",
            "-o",
            arg(&again),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert_eq!(std::fs::read_to_string(&again).unwrap(), text);
}

// ---------------------------------------------------------------------------------------------------------
// The VM campaign's ownership cases (x0-git-toolsdir, x0-git-userstate), on the Tidy Notes machine
// ---------------------------------------------------------------------------------------------------------

const DAY: u64 = 24 * 60 * 60 * 10_000_000;
const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
const RUN: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const APP_PATHS_RG: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\rg.exe";

fn created(f: &mut Fixture, path: &str, when: u64) {
    f.set_times(
        path,
        purge_source::types::FileTimes {
            created: Some(purge_model::FileTime(when)),
            modified: Some(purge_model::FileTime(when)),
            accessed: None,
        },
    );
}

/// What a user keeps in and around an app: an own tool and notes in the app's folder (older than
/// the install when `older`), an `App Paths` entry and a start entry for the own tool, and a
/// setting of another program that holds the path of the app's exe.
fn with_user_state(f: &mut Fixture, older: bool) {
    let install = crate::common::BASE - 30 * DAY;
    let theirs = if older {
        install - 300 * DAY
    } else {
        install + DAY
    };
    for file in [
        r"C:\Program Files\Tidy Notes\tidynotes.exe",
        r"C:\Program Files\Tidy Notes\bin\tidy-cli.exe",
        r"C:\Program Files\Tidy Notes\plugins\spell.dll",
    ] {
        created(f, file, install);
    }
    for (file, size) in [
        (r"C:\Program Files\Tidy Notes\rg.exe", 5_000),
        (r"C:\Program Files\Tidy Notes\backup.cmd", 100),
        (r"C:\Program Files\Tidy Notes\my notes\ideas.txt", 300),
    ] {
        f.add_file(file, size);
        created(f, file, theirs);
    }
    f.set_value(
        APP_PATHS_RG,
        "",
        RegData::from_sz(r"C:\Program Files\Tidy Notes\rg.exe"),
    );
    f.set_value(
        RUN,
        "Backup",
        RegData::from_sz(r#""C:\Program Files\Tidy Notes\backup.cmd" --nightly"#),
    );
    f.set_value(
        &format!(r"HKU\{SID}\Software\ContosoTools\Settings"),
        "NotesExecutable",
        RegData::from_sz(r"C:\Program Files\Tidy Notes\tidynotes.exe"),
    );
    f.set_value(
        &format!(r"HKU\{SID}\Environment"),
        "TIDY_EDITOR",
        RegData::from_sz(r"C:\Program Files\Tidy Notes\tidynotes.exe"),
    );
}

/// Harvest, uninstall and post scan; the fingerprint and the plan.
fn through_the_cli(machine: &Switch, name: &str) -> (Fingerprint, Plan) {
    through_the_cli_in(machine, name, purge_engine::pipeline::Settings::default())
}

/// [`through_the_cli`] with the engine's settings (a baseline directory).
fn through_the_cli_in(
    machine: &Switch,
    name: &str,
    settings: purge_engine::pipeline::Settings,
) -> (Fingerprint, Plan) {
    let cli = |machine: &Switch, host: &mut FakeHost, args: &[&str]| {
        crate::common::cli_in(machine, host, args, Default::default(), settings.clone())
    };
    let mut host = FakeHost::new(machine, Some(0), true);
    let dir = scratch(name);
    let (fp_path, run_path, plan_path) = (
        dir.join("fp.json"),
        dir.join("run.json"),
        dir.join("plan-purge.json"),
    );
    let ran = cli(
        machine,
        &mut host,
        &["harvest", KEY_NAME, "-o", arg(&fp_path)],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let ran = cli(
        machine,
        &mut host,
        &[
            "uninstall",
            KEY_NAME,
            "--quiet",
            "--fp",
            arg(&fp_path),
            "-o",
            arg(&run_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let ran = cli(
        machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--mode",
            "post",
            "--app",
            "tidynotes",
            "-o",
            arg(&plan_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    (read_json(&fp_path).unwrap(), read_json(&plan_path).unwrap())
}

fn mentions(i: &purge_model::PlanItem, what: &str) -> bool {
    format!("{:?}", i.target)
        .to_lowercase()
        .contains(&what.to_lowercase())
}

/// Nothing of the user's is preselected, and nothing of the user's alone is offered as a file.
fn assert_user_state_is_not_preselected(plan: &Plan) {
    for i in &plan.items {
        for theirs in [
            "rg.exe",
            "backup",
            "my notes",
            "ideas.txt",
            "ContosoTools",
            "TIDY_EDITOR",
        ] {
            assert!(
                !(mentions(i, theirs) && (i.preselected || i.band == Band::Safe)),
                "preselected: {i:?}"
            );
        }
        if let Target::Path { path } = &i.target {
            for theirs in ["rg.exe", "backup.cmd", "my notes"] {
                assert!(!path.contains(theirs), "the user's file is offered: {i:?}");
            }
        }
    }
    // The single-value variable is offered as the value, never as an entry of it.
    assert!(
        !plan.items.iter().any(|i| matches!(
            &i.target,
            Target::RegMultiSzSegment { name, .. } if name == "TIDY_EDITOR"
        )),
        "{plan:#?}"
    );
}

/// The user kept own files in the app's folder (x0-git-userstate): the folder was the app's, what
/// is left in it is not shown to be. It is listed unticked, with the file the log names next to it.
#[test]
fn inno_app_with_the_users_files_in_its_folder() {
    let machine = Switch::new(machine("inno", |f| {
        with_log(f);
        with_user_state(f, false);
    }));
    let (fp, plan) = through_the_cli(&machine, "inno-userstate");
    assert!(
        fp.roots
            .iter()
            .any(|r| r.path == APP_DIR && r.kind == RootKind::InstallRoot),
        "{:?}",
        fp.roots
    );
    let root = item(
        &plan,
        &Target::Path {
            path: APP_DIR.into(),
        },
    )
    .expect("the install dir is listed");
    assert_eq!((root.band, root.preselected), (Band::Likely, false));
    let named = item(
        &plan,
        &Target::Path {
            path: r"C:\Program Files\Tidy Notes\plugins".into(),
        },
    )
    .expect("the directory the log names (with the logged file in it) is offered on its own");
    assert_eq!((named.band, named.preselected), (Band::Safe, true));
    assert_user_state_is_not_preselected(&plan);
}

/// The app was installed into a folder that already held the user's tools (x0-git-toolsdir): the
/// log has no record of creating the folder and files in it are older than the install. The folder
/// is then no InstallRoot: it is never offered whole, and a reference to a file in it proves
/// nothing (`App Paths\rg.exe`, `Run|Backup`).
#[test]
fn inno_app_installed_into_a_folder_that_was_there_before() {
    let machine = Switch::new(machine("inno", |f| {
        with_log_of(f, false);
        with_user_state(f, true);
    }));
    let (fp, plan) = through_the_cli(&machine, "inno-shared-root");
    let root = fp.roots.iter().find(|r| r.path == APP_DIR).expect("root");
    assert_eq!(root.kind, RootKind::InferredRoot, "{:?}", fp.roots);
    assert!(
        fp.warnings.iter().any(|w| w.contains("shared folder")),
        "{:?}",
        fp.warnings
    );
    assert!(
        item(
            &plan,
            &Target::Path {
                path: APP_DIR.into()
            }
        )
        .is_none(),
        "the shared folder is offered whole: {plan:#?}"
    );
    // `App Paths\rg.exe` and `Run|Backup` may be listed (they point into the folder), never ticked.
    assert_user_state_is_not_preselected(&plan);
    // What the log names is still found and still the app's.
    let named = item(
        &plan,
        &Target::Path {
            path: r"C:\Program Files\Tidy Notes\plugins".into(),
        },
    )
    .expect("the directory the log names is offered");
    assert_eq!((named.band, named.preselected), (Band::Safe, true));
}

/// Rig run x1-vscode-userstate, end to end: 21 seconds before the install the user made an empty
/// `.gemx\OpenWithProgids`; the installer wrote its one value into it (and made `.tidx` with the
/// same value itself); the uninstaller took the values out. Both pairs of keys are empty now and
/// held nothing but the app's value at harvest. With a baseline of this Windows and the exact start
/// of the install (the creation time of the directory the installer made), the installer's pair is
/// the app's skeleton and the user's pair is not offered as one.
#[test]
fn inno_app_and_empty_extension_keys_made_before_the_install() {
    const SECOND: u64 = 10_000_000;
    const CLASSES: &str = r"HKLM\SOFTWARE\Classes";
    let install = crate::common::BASE - 30 * DAY;
    let (planted, written) = (install - 21 * SECOND, install + 31 * SECOND);
    let owp = |ext: &str| format!(r"{CLASSES}\{ext}\OpenWithProgids");
    let (mut before, mut after) = machine("inno", |f| {
        with_log(f);
        created(f, APP_DIR, install);
        for ext in [".gemx", ".tidx"] {
            f.set_value(&owp(ext), "TidyNotes.Document", RegData::from_sz(""));
            f.set_key_lwt(&owp(ext), purge_model::FileTime(written));
        }
        // The user's key keeps its time: the installer wrote into the subkey, not into it.
        f.set_key_lwt(&format!(r"{CLASSES}\.gemx"), purge_model::FileTime(planted));
        // The installer's: making `.tidx` moved its time and the time of the Classes key.
        f.set_key_lwt(&format!(r"{CLASSES}\.tidx"), purge_model::FileTime(written));
        f.set_key_lwt(CLASSES, purge_model::FileTime(written));
    });
    let _ = &mut before;
    for ext in [".gemx", ".tidx"] {
        assert!(after.remove_value(&owp(ext), "TidyNotes.Document"));
    }
    let machine = Switch::new((before, after));
    let (fp, plan) = through_the_cli_in(
        &machine,
        "inno-planted-ext",
        crate::common::shipped_baselines(),
    );
    assert!(
        fp.warnings.iter().all(|w| !w.starts_with("baseline:")),
        "{:?}",
        fp.warnings
    );
    // The harvest saw the times: the planted key and, by its parent, the subkey in it.
    for key in [format!(r"{CLASSES}\.gemx"), owp(".gemx")] {
        assert!(fp.older_keys.contains(&key), "{:?}", fp.older_keys);
    }
    assert!(
        fp.older_keys.iter().all(|k| !k.contains(".tidx")),
        "{:?}",
        fp.older_keys
    );
    let key = |path: String| Target::RegKey { path };
    // The installer's own pair: one Safe key that takes the subkey with it.
    let own = item(&plan, &key(format!(r"{CLASSES}\.tidx"))).expect("the app's skeleton");
    assert_eq!((own.band, own.preselected), (Band::Safe, true));
    // The user's pair: never Safe, never ticked, by any scanner.
    for target in [key(format!(r"{CLASSES}\.gemx")), key(owp(".gemx"))] {
        if let Some(i) = item(&plan, &target) {
            assert!(i.band != Band::Safe && !i.preselected, "{i:?}");
        }
    }
    for i in &plan.items {
        assert!(
            !(mentions(i, ".gemx") && (i.preselected || i.band == Band::Safe)),
            "{i:?}"
        );
    }
}

/// The installer added its `cmd` folder to the user's `Path` and logged the value. An entry edit
/// takes the whole text of one entry out, so an entry that holds more than the app's folder is
/// not the app's entry, however the rest got into it: through another variable that holds a
/// list, as a second quoted path, after a comma. The harvest and the scan must read an entry the
/// same way (`prefix::ListEntry::read`): what the one does not record the other does not offer,
/// and nothing of it reaches the plan, Safe or otherwise.
#[test]
fn inno_app_and_path_entries_that_hold_more_than_its_folder() {
    let env_key = format!(r"HKU\{SID}\Environment");
    let cmd = format!(r"{APP_DIR}\cmd");
    let tools = r"C:\Users\tester\tools";
    let planned = |name: &str, entry: &str, variable: Option<(&str, String)>| {
        let (before, after) = machine("inno", |f| {
            with_log_and(f, true, &[(VALUE, HKCU, &["Environment", "Path"])]);
            created(f, APP_DIR, crate::common::BASE - 30 * DAY);
            f.set_value(
                &env_key,
                "Path",
                RegData::from_expand_sz(&format!(r"C:\Users\tester\bin;{entry}")),
            );
            if let Some((variable, holds)) = &variable {
                f.set_value(&env_key, variable, RegData::from_sz(holds));
                f.system_mut()
                    .env
                    .insert(variable.to_uppercase(), holds.clone());
            }
        });
        let (fp, plan) = through_the_cli(&Switch::new((before, after)), name);
        let on_path = |target: &Target| {
            matches!(target, Target::RegMultiSzSegment { path, name, .. }
                if path == &env_key && name == "Path")
        };
        let recorded = fp
            .ref_snapshot
            .iter()
            .filter(|e| on_path(&e.target))
            .count();
        let offered: Vec<(Band, bool)> = plan
            .items
            .iter()
            .filter(|i| on_path(&i.target))
            .map(|i| (i.band, i.preselected))
            .collect();
        // Whatever else the plan holds, nothing on the user's environment is ticked.
        for i in &plan.items {
            assert!(
                !(mentions(i, "Environment") && (i.preselected || i.band == Band::Safe))
                    || offered == [(Band::Safe, true)],
                "{name}: {i:?}"
            );
        }
        (recorded, offered)
    };

    // The app's own entry, plainly written: recorded, offered, Safe.
    assert_eq!(
        planned("inno-path-own", &cmd, None),
        (1, vec![(Band::Safe, true)])
    );
    assert_eq!(
        planned("inno-path-own-quoted", &format!(r#""{cmd}\""#), None),
        (1, vec![(Band::Safe, true)])
    );

    // More than the app's folder in one entry: not recorded, not offered.
    let nothing = (0, Vec::new());
    assert_eq!(
        planned(
            "inno-path-indirect-list",
            "%MYDIRS%",
            Some(("MYDIRS", format!("{cmd};{tools}")))
        ),
        nothing
    );
    assert_eq!(
        planned(
            "inno-path-two-quoted",
            &format!(r#""{cmd}" "{tools}""#),
            None
        ),
        nothing
    );
    assert_eq!(
        planned("inno-path-comma", &format!("{cmd},{tools}"), None),
        nothing
    );
    assert_eq!(
        planned("inno-path-blank", &format!("{cmd} {tools}"), None),
        nothing
    );
    assert_eq!(
        planned(
            "inno-path-indirect-comma",
            "%MYDIRS%",
            Some(("MYDIRS", format!("{cmd},{tools}")))
        ),
        nothing
    );

    // One directory, but not provably the installer's entry: the user's reference to a variable
    // of their own, and a name with a comma in it. Recorded and listed, never ticked.
    assert_eq!(
        planned(
            "inno-path-reference",
            "%MYDIR%",
            Some(("MYDIR", cmd.clone()))
        ),
        (1, vec![(Band::Likely, false)])
    );
    assert_eq!(
        planned("inno-path-comma-name", &format!("{cmd},tools"), None),
        (1, vec![(Band::Likely, false)])
    );
}

/// Another product keeps a `;`-list of folders in its own key, the installer added the app's
/// `cmd` folder to it and logged the value. The record names the list, not its entries: an entry
/// that begins with the app's folder and holds more is not offered, a plain entry is listed, and
/// nothing on that value is Safe or ticked, by any scanner.
#[test]
fn inno_app_and_another_products_list_that_names_its_folder() {
    const TOOL: &str = r"HKLM\SOFTWARE\Other Vendor\Tool";
    let cmd = format!(r"{APP_DIR}\cmd");
    let tools = r"C:\Users\tester\tools";
    let planned = |name: &str, entry: &str, variable: Option<(&str, String)>| {
        let (before, after) = machine("inno", |f| {
            with_log_and(
                f,
                true,
                &[(VALUE, HKLM, &[r"Software\Other Vendor\Tool", "SearchPath"])],
            );
            created(f, APP_DIR, crate::common::BASE - 30 * DAY);
            f.set_value(
                TOOL,
                "SearchPath",
                RegData::from_sz(&format!(r"C:\Users\tester\bin;{entry}")),
            );
            if let Some((variable, holds)) = &variable {
                f.system_mut()
                    .env
                    .insert(variable.to_uppercase(), holds.clone());
            }
        });
        let (_, plan) = through_the_cli(&Switch::new((before, after)), name);
        for i in &plan.items {
            assert!(
                !(mentions(i, "SearchPath") && (i.preselected || i.band == Band::Safe)),
                "{name}: {i:?}"
            );
        }
        plan.items
            .iter()
            .filter(|i| matches!(&i.target, Target::RegMultiSzSegment { path, .. } if path == TOOL))
            .map(|i| (i.band, i.preselected))
            .collect::<Vec<_>>()
    };
    // A plain entry: the app's folder in somebody else's list. Listed, not ticked.
    assert_eq!(
        planned("inno-list-plain", &cmd, None),
        [(Band::Likely, false)]
    );
    for (name, entry, variable) in [
        (
            "inno-list-two-quoted",
            format!(r#""{cmd}" "{tools}""#),
            None,
        ),
        ("inno-list-comma", format!("{cmd},{tools}"), None),
        ("inno-list-blank", format!("{cmd} {tools}"), None),
        (
            "inno-list-indirect",
            "%MYDIRS%".to_owned(),
            Some(("MYDIRS", format!("{tools};{cmd}"))),
        ),
        (
            "inno-list-command-line",
            format!(r#""C:\Users\tester\my tool.exe" --with "{cmd}\x.exe""#),
            None,
        ),
    ] {
        assert_eq!(planned(name, &entry, variable), [], "{name}");
    }
}

/// The same files, but the log shows that the installer created the folder (a reinstall over
/// leftovers, a file restored from a backup): it stays the app's InstallRoot.
#[test]
fn inno_app_whose_installer_created_the_folder_keeps_its_root() {
    let machine = Switch::new(machine("inno", |f| {
        let log = inno_log(
            "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
            "Tidy Notes",
            ADMIN_64,
            &[
                (START, 0, &["PC", "tester", APP_DIR, ""]),
                (DIR, 2, &[APP_DIR]),
                (FILE, 0, &[r"C:\Program Files\Tidy Notes\tidynotes.exe"]),
                (FILE, 0, &[r"C:\Program Files\Tidy Notes\bin\tidy-cli.exe"]),
                (FILE, 0, &[r"C:\Program Files\Tidy Notes\plugins\spell.dll"]),
                (END, 0, &[]),
            ],
        );
        f.add_file_with_content(r"C:\Program Files\Tidy Notes\unins000.dat", log);
        with_user_state(f, true);
    }));
    let (fp, plan) = through_the_cli(&machine, "inno-created-root");
    let root = fp.roots.iter().find(|r| r.path == APP_DIR).expect("root");
    assert_eq!(root.kind, RootKind::InstallRoot, "{:?}", fp.roots);
    // Still never preselected with the user's files in it.
    let root = item(
        &plan,
        &Target::Path {
            path: APP_DIR.into(),
        },
    )
    .expect("the install dir is listed");
    assert_eq!((root.band, root.preselected), (Band::Likely, false));
}
