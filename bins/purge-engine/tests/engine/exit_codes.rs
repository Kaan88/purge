//! Exit codes of the CLI with a fake process host: failed, cancelled and timed-out uninstalls (4),
//! broken preconditions (2), write errors (3), and `scan --path`.

use std::time::Duration;

use purge_engine::cli::Exit;
use purge_engine::cli::output::read_json;
use purge_inventory::runner::RunOptions;
use purge_model::{Band, Fingerprint, Plan, RunDoc, RunOutcome, ScanMode};
use purge_source::fixture::Fixture;
use purge_source::types::VersionInfo;

use crate::common::{FakeHost, Switch, arg, cli, cli_with, machine, scratch};
use crate::inno::tidy_notes;

const TIDY: &str = "{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}_is1";

/// Harvests Tidy Notes into `<dir>/fp.json`.
fn harvested(machine: &Switch, host: &mut FakeHost, dir: &std::path::Path) -> std::path::PathBuf {
    let fp = dir.join("fp.json");
    let ran = cli(machine, host, &["harvest", TIDY, "-o", arg(&fp)]);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    fp
}

fn uninstall(
    machine: &Switch,
    host: &mut FakeHost,
    dir: &std::path::Path,
    run: RunOptions,
) -> Exit {
    let fp = dir.join("fp.json");
    let out = dir.join("run.json");
    let ran = cli_with(
        machine,
        host,
        &[
            "uninstall",
            TIDY,
            "--quiet",
            "--fp",
            arg(&fp),
            "-o",
            arg(&out),
        ],
        run,
    );
    if ran.exit == Exit::UninstallFailed {
        assert!(ran.err.contains("did not succeed"), "{}", ran.err);
    }
    ran.exit
}

#[test]
fn a_failed_uninstaller_exits_4_and_its_scan_has_no_safe_item() {
    let machine = tidy_notes();
    // The uninstaller exits with 1603 and removes nothing.
    let mut host = FakeHost::new(&machine, Some(1603), false);
    let dir = scratch("failed");
    let fp_path = harvested(&machine, &mut host, &dir);
    assert_eq!(
        uninstall(&machine, &mut host, &dir, RunOptions::default()),
        Exit::UninstallFailed
    );
    // run.json and the updated fingerprint are written anyway.
    let run: RunDoc = read_json(&dir.join("run.json")).unwrap();
    assert_eq!(
        (run.outcome, run.exit_code),
        (RunOutcome::Failed, Some(1603))
    );
    assert!(!run.verify_gone.is_passed());
    let fp: Fingerprint = read_json(&fp_path).unwrap();
    assert!(fp.window.t_end.is_some());
    assert_eq!(fp.verify_gone, Some(run.verify_gone));

    // A post scan of that run warns and offers nothing as Safe.
    let plan_path = dir.join("plan.json");
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--mode",
            "post",
            "-o",
            arg(&plan_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.err.contains("warning: scan: verify-gone failed"),
        "{}",
        ran.err
    );
    let plan: Plan = read_json(&plan_path).unwrap();
    assert_eq!(plan.mode, ScanMode::Post);
    assert!(!plan.items.is_empty());
    assert!(
        plan.items
            .iter()
            .all(|i| i.band != Band::Safe && !i.preselected),
        "{plan:#?}"
    );
}

#[test]
fn cancelled_and_timed_out_uninstalls_exit_4() {
    let machine = tidy_notes();
    let dir = scratch("cancelled");
    let mut host = FakeHost::new(&machine, Some(1602), false);
    harvested(&machine, &mut host, &dir);
    assert_eq!(
        uninstall(&machine, &mut host, &dir, RunOptions::default()),
        Exit::UninstallFailed
    );
    let run: RunDoc = read_json(&dir.join("run.json")).unwrap();
    assert_eq!(run.outcome, RunOutcome::Cancelled);

    // An uninstaller that never ends: the wait times out and nothing is killed.
    let machine = tidy_notes();
    let dir = scratch("timeout");
    let mut host = FakeHost::new(&machine, None, false);
    harvested(&machine, &mut host, &dir);
    let options = RunOptions {
        timeout: Duration::from_secs(60),
        ..RunOptions::default()
    };
    assert_eq!(
        uninstall(&machine, &mut host, &dir, options),
        Exit::UninstallFailed
    );
    let run: RunDoc = read_json(&dir.join("run.json")).unwrap();
    assert_eq!(run.outcome, RunOutcome::TimedOut);
    assert_eq!(host.spawned.len(), 1);
}

#[test]
fn preconditions_exit_2_and_write_errors_exit_3() {
    let machine = tidy_notes();
    let mut host = FakeHost::new(&machine, Some(0), true);
    let dir = scratch("preconditions");
    let fp_path = harvested(&machine, &mut host, &dir);

    // A fingerprint of another app.
    let ran = cli(
        &machine,
        &mut host,
        &["uninstall", "ExampleMail", "--quiet", "--fp", arg(&fp_path)],
    );
    assert_eq!(ran.exit, Exit::Usage, "{}", ran.err);
    assert!(ran.err.contains("the fingerprint is of"), "{}", ran.err);
    assert!(host.spawned.is_empty(), "nothing may be started");

    // An unknown program id, a fingerprint that is not one.
    let ran = cli(
        &machine,
        &mut host,
        &["harvest", "HKLM|64|Nope", "-o", arg(&fp_path)],
    );
    assert_eq!(ran.exit, Exit::Usage);
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{\"schema\": \"purge.fp/9\"}").unwrap();
    let ran = cli(
        &machine,
        &mut host,
        &["scan", "--fp", arg(&bad), "-o", arg(&dir.join("p.json"))],
    );
    assert_eq!(ran.exit, Exit::Usage, "{}", ran.err);

    // Post mode without an uninstall window.
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--mode",
            "post",
            "-o",
            arg(&dir.join("p.json")),
        ],
    );
    assert_eq!(ran.exit, Exit::Usage);

    // An output file in a directory that does not exist.
    let missing = dir.join("missing").join("fp.json");
    let ran = cli(&machine, &mut host, &["harvest", TIDY, "-o", arg(&missing)]);
    assert_eq!(ran.exit, Exit::Runtime, "{}", ran.err);
    assert!(
        ran.err.contains("cannot write the fingerprint"),
        "{}",
        ran.err
    );
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--fp",
            arg(&fp_path),
            "--mode",
            "forced",
            "-o",
            arg(&dir.join("missing").join("p.json")),
        ],
    );
    assert_eq!(ran.exit, Exit::Runtime, "{}", ran.err);
}

#[test]
fn scan_path_is_forced_and_refuses_other_apps_and_system_dirs() {
    let machine = Switch::new(machine("nsis", |f: &mut Fixture| {
        f.add_dir(r"C:\Tools\ProcView");
        f.add_file(r"C:\Tools\ProcView\procview.exe", 400_000);
        f.set_version_info(
            r"C:\Tools\ProcView\procview.exe",
            VersionInfo {
                company_name: Some("Example Sysutils".into()),
                product_name: Some("ProcView".into()),
                ..VersionInfo::default()
            },
        );
        f.add_file(r"C:\Tools\ProcView\procview.ini", 100);
    }));
    let mut host = FakeHost::new(&machine, Some(0), false);
    let dir = scratch("scan-path");
    let plan_path = dir.join("plan.json");
    let ran = cli(
        &machine,
        &mut host,
        &[
            "scan",
            "--path",
            r"C:\Tools\ProcView",
            "-o",
            arg(&plan_path),
        ],
    );
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.err.contains("minimal M1a implementation"),
        "{}",
        ran.err
    );
    let plan: Plan = read_json(&plan_path).unwrap();
    assert_eq!(
        (plan.app.as_str(), plan.mode),
        ("procview", ScanMode::Forced)
    );
    assert!(
        plan.items.iter().any(|i| matches!(&i.target,
            purge_model::Target::Path { path } if path == r"C:\Tools\ProcView")),
        "{plan:#?}"
    );
    assert!(
        plan.items
            .iter()
            .all(|i| i.band != Band::Safe && !i.preselected)
    );

    for refused in [
        r"C:\Program Files\Fennec Mail",
        r"C:\Program Files",
        r"C:\Windows",
        r"C:\Tools\Missing",
    ] {
        let ran = cli(
            &machine,
            &mut host,
            &["scan", "--path", refused, "-o", arg(&plan_path)],
        );
        assert_eq!(ran.exit, Exit::Usage, "{refused}: {}", ran.err);
    }
    assert!(host.spawned.is_empty());
}
