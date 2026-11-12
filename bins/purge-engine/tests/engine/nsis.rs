//! An NSIS app (Fennec Browser) whose uninstaller also removes a co-product (Fennec Maintenance
//! Service), while a sibling product of the same vendor (Fennec Mail) stays installed. Driven through the
//! pipeline functions.

use purge_engine::cli::output::json_text;
use purge_engine::pipeline::{self, Settings};
use purge_identity::kbdata::Kb;
use purge_inventory::runner::RunOptions;
use purge_model::{Band, Plan, RunOutcome, ScanMode, Target};

use crate::common::{FakeHost, Switch, golden, machine, rig};

const KEY_NAME: &str = "Fennec Browser 9.0 (x64 en-US)";

/// The Fennec machine.
pub fn fennec() -> Switch {
    Switch::new(machine("nsis", |_| {}))
}

fn mentions(target: &Target, needle: &str) -> bool {
    format!("{target:?}")
        .to_lowercase()
        .contains(&needle.to_lowercase())
}

#[test]
fn nsis_app_with_a_co_product_through_the_pipeline() {
    let machine = fennec();
    let sources = machine.sources();
    let settings = Settings::default();
    let mut lines: Vec<String> = Vec::new();
    let mut progress = |l: &str| lines.push(l.to_owned());

    // Harvest: the maintenance service is a co-product candidate, the mail client is not.
    let harvested =
        pipeline::harvest(sources, KEY_NAME, Kb::shipped(), &settings, &mut progress).unwrap();
    let names: Vec<&str> = harvested
        .report
        .co_candidates
        .iter()
        .map(|c| c.app.display_name.as_str())
        .collect();
    assert_eq!(names, ["Fennec Maintenance Service"]);
    let mut fp = harvested.report.fingerprint;

    // Uninstall: the co-product disappears with the app.
    let mut host = FakeHost::new(&machine, Some(0), true);
    let done = pipeline::uninstall(
        sources,
        &mut host,
        KEY_NAME,
        Some(&mut fp),
        &RunOptions::default(),
        &mut progress,
    )
    .unwrap();
    assert!(!done.failed());
    assert_eq!(done.report.doc.outcome, RunOutcome::Success);
    assert_eq!(
        host.spawned,
        [r#""C:\Program Files\Fennec Browser\uninstall\helper.exe" /S"#]
    );
    let co: Vec<&str> = fp
        .co_removed
        .iter()
        .map(|c| c.app.display_name.as_str())
        .collect();
    assert_eq!(co, ["Fennec Maintenance Service"]);
    assert!(fp.verify_gone.is_some_and(|v| v.is_passed()));

    // Scan.
    let scanned =
        pipeline::scan(sources, &fp, ScanMode::Post, None, &settings, &mut progress).unwrap();
    let plan: &Plan = &scanned.built.plan;
    assert_eq!(plan.app, "fennec browser 9.0 (x64 en-us)");
    assert_eq!(
        scanned.per_scanner.len(),
        purge_scan::catalog::SCANNER_IDS.len()
    );
    let text = json_text(plan);
    golden("nsis.plan.json", &text);
    serde_json::from_str::<rig::Plan>(&text).expect("the rig reads the plan");

    // The sibling product stays untouched: never Safe, never ticked.
    for i in &plan.items {
        if mentions(&i.target, "Fennec Mail") || mentions(&i.target, "fennecmail") {
            assert!(
                i.band != Band::Safe && !i.preselected,
                "the still-installed mail client: {i:?}"
            );
        }
    }
    // The browser's own leftovers are found.
    assert!(
        plan.items.iter().any(|i| i.target
            == Target::Path {
                path: r"C:\Program Files\Fennec Browser".into()
            }),
        "{plan:#?}"
    );
    // Progress went out, first line before any work.
    assert!(
        lines[0].starts_with("harvest: reading the inventory"),
        "{lines:?}"
    );

    // The same inputs give the same plan.
    let again = pipeline::scan(sources, &fp, ScanMode::Post, None, &settings, &mut |_| {}).unwrap();
    assert_eq!(again.built, scanned.built);
}

#[test]
fn external_and_forced_scans_check_verify_gone_afresh() {
    let machine = fennec();
    let settings = Settings::default();
    let fp = pipeline::harvest(
        machine.sources(),
        KEY_NAME,
        Kb::shipped(),
        &settings,
        &mut |_| {},
    )
    .unwrap()
    .report
    .fingerprint;
    // Still installed: verify-gone fails, nothing is Safe in either mode.
    for mode in [ScanMode::External, ScanMode::Forced] {
        let scanned = pipeline::scan(
            machine.sources(),
            &fp,
            mode,
            Some("fennec"),
            &settings,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(scanned.built.plan.mode, mode);
        assert!(
            scanned
                .built
                .plan
                .items
                .iter()
                .all(|i| i.band != Band::Safe && !i.preselected),
            "{mode:?}"
        );
        if mode == ScanMode::External {
            assert!(
                scanned
                    .warnings
                    .iter()
                    .any(|w| w.contains("verify-gone failed")),
                "{:?}",
                scanned.warnings
            );
        }
    }
}
