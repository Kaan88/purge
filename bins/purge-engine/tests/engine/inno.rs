//! An Inno Setup app (Tidy Notes) end to end through the CLI.

use purge_engine::cli::Exit;
use purge_engine::cli::output::{read_json, sidecar_path};
use purge_model::{
    Band, Fingerprint, InventoryDoc, Plan, RootKind, RunDoc, RunOutcome, ScanMode, Target,
};
use purge_plan::emit::ScanDoc;
use purge_source::fixture::Fixture;

use crate::common::inno::*;
use crate::common::{FakeHost, Switch, arg, cli, golden, inno_log, machine, rig, scratch};

const APP_DIR: &str = r"C:\Program Files\Tidy Notes";
const KEY_NAME: &str = "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}_is1";

/// Adds the uninstall log the Tidy Notes installer wrote.
fn with_log(f: &mut Fixture) {
    let log = inno_log(
        "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
        "Tidy Notes",
        ADMIN_64,
        &[
            (START, 0, &["PC", "tester", APP_DIR, ""]),
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
            (END, 0, &[]),
        ],
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
    // The logged vendor key (delete-if-empty) is emptied by the logged app key, which it absorbs.
    let vendor_key = item(
        &plan,
        &Target::RegKey {
            path: r"HKLM\SOFTWARE\Acme Tools".into(),
        },
    )
    .expect("the logged vendor key is offered");
    assert_eq!(
        (vendor_key.band, vendor_key.preselected),
        (Band::Safe, true)
    );
    assert!(
        sidecar.absorbed.iter().any(|c| c.target
            == Target::RegKey {
                path: r"HKLM\SOFTWARE\Acme Tools\Tidy Notes".into()
            }),
        "{:#?}",
        sidecar.absorbed
    );
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
