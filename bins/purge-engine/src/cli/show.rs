//! `plan show`: a plan as a text table grouped by band (ENGINE_PLAN.md §3.4, §5.8.6).
//!
//! The plan (`purge.plan/0`) gives the items; the sidecar `<plan>.scan.json` (`purge.scan/0`), when it is
//! next to the plan and agrees with it, adds each item's explanation, the number of items it absorbs, and
//! the plan hash. The hash shown is recomputed from the sidecar's candidates; a sidecar whose stored hash
//! or items differ from the plan is reported and not used.
//!
//! ```text
//! plan vendor-app: tool purge, mode post, 3 items (1 preselected)
//! hash 3f1c… (policy m1a.2)
//!
//! Safe (1)
//!   [x] RegKey HKLM\SOFTWARE\Vendor\App
//!       REG-SOFTWARE, Registration, absorbs 2
//!       <explanation line>
//! Likely (1)
//!   [ ] Path C:\ProgramData\Vendor
//!       FS-APPDATA, AppData
//! ```

use std::fmt::Write as _;

use purge_model::{Band, Candidate, Plan, PlanItem, Target};
use purge_plan::emit::ScanDoc;
use purge_plan::hash::plan_hash;

/// The bands in display order.
const BANDS: [Band; 4] = [Band::Safe, Band::Likely, Band::Weak, Band::Blocked];

/// One line for a target.
pub fn target_text(target: &Target) -> String {
    let name = |n: &str| {
        if n.is_empty() {
            "(default)".to_owned()
        } else {
            n.to_owned()
        }
    };
    match target {
        Target::Path { path } => format!("Path {path}"),
        Target::RegKey { path } => format!("RegKey {path}"),
        Target::RegValue { path, name: n } => format!("RegValue {path} : {}", name(n)),
        Target::RegValueChanged { path, name: n, .. } => {
            format!("RegValueChanged {path} : {}", name(n))
        }
        Target::RegMultiSzSegment {
            path,
            name: n,
            segment,
            ..
        } => format!("Segment {path} : {} : {segment}", name(n)),
        Target::Service { name } => format!("Service {name}"),
        Target::Task { path } => format!("Task {path}"),
        Target::FirewallRule { id } => format!("FirewallRule {id}"),
        Target::AppxPackage { full_name } => format!("AppxPackage {full_name}"),
    }
}

/// One line for a target, with the object's own name from the sidecar when it has one (M3-ENGINE-OUT).
/// A firewall rule's InstanceID is unique but unreadable; its `Name=` is what the user knows.
pub fn target_text_with_name(target: &Target, candidate: Option<&Candidate>) -> String {
    let text = target_text(target);
    if matches!(target, Target::FirewallRule { .. })
        && let Some(name) = candidate.and_then(|c| c.display_name.as_deref())
        && !name.is_empty()
    {
        return format!("{text} ({name})");
    }
    text
}

/// Checks that a sidecar belongs to `plan`: same app and mode, the same items in the same order, and a
/// stored hash equal to the one recomputed from its candidates.
///
/// # Errors
///
/// What does not agree.
pub fn check_sidecar(plan: &Plan, scan: &ScanDoc) -> Result<String, String> {
    if scan.app != plan.app || scan.mode != plan.mode {
        return Err(format!(
            "the sidecar is for app {:?} mode {:?}, the plan for app {:?} mode {:?}",
            scan.app, scan.mode, plan.app, plan.mode
        ));
    }
    let listed: Vec<&Candidate> = scan
        .items
        .iter()
        .filter(|c| !matches!(c.target, Target::RegValueChanged { .. }))
        .collect();
    if listed.len() != plan.items.len()
        || listed
            .iter()
            .zip(&plan.items)
            .any(|(c, item)| c.target != item.target)
    {
        return Err("the sidecar's items differ from the plan's".into());
    }
    let hash = plan_hash(&scan.items, &scan.policy_version, scan.mode);
    if hash != scan.plan_hash {
        return Err(format!(
            "the sidecar's stored hash {} differs from its recomputed hash {hash}",
            scan.plan_hash
        ));
    }
    Ok(hash)
}

/// The table for `plan`, with the facts of a matching sidecar (`sidecar` is `Ok` with the document, or
/// `Err` with why there is none).
pub fn render(plan: &Plan, sidecar: Result<&ScanDoc, String>) -> String {
    let mut out = String::new();
    let preselected = plan.items.iter().filter(|i| i.preselected).count();
    let _ = writeln!(
        out,
        "plan {}: tool {}, mode {}, {} item(s) ({} preselected)",
        plan.app,
        enum_text(&plan.tool),
        enum_text(&plan.mode),
        plan.items.len(),
        preselected
    );
    let scan = match sidecar.and_then(|scan| check_sidecar(plan, scan).map(|hash| (scan, hash))) {
        Ok((scan, hash)) => {
            let _ = writeln!(out, "hash {hash} (policy {})", scan.policy_version);
            Some(scan)
        }
        Err(why) => {
            let _ = writeln!(out, "hash unknown: {why}");
            None
        }
    };
    let candidates: Vec<&Candidate> = scan
        .map(|s| {
            s.items
                .iter()
                .filter(|c| !matches!(c.target, Target::RegValueChanged { .. }))
                .collect()
        })
        .unwrap_or_default();

    for band in BANDS {
        let rows: Vec<(usize, &PlanItem)> = plan
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.band == band)
            .collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{band:?} ({})", rows.len());
        for (index, item) in rows {
            let tick = if item.preselected { "[x]" } else { "[ ]" };
            let candidate = candidates.get(index).copied();
            let _ = writeln!(
                out,
                "  {tick} {}",
                target_text_with_name(&item.target, candidate)
            );
            let mut facts = format!("{}, {:?}", item.scanner, item.category);
            if let (Some(c), Some(scan)) = (candidate, scan) {
                let absorbed = scan
                    .absorbed
                    .iter()
                    .filter(|a| c.children.contains(&a.id))
                    .count();
                if absorbed > 0 {
                    let _ = write!(facts, ", absorbs {absorbed}");
                }
                let others: Vec<&str> = ScanDoc::scanners(c).into_iter().skip(1).collect();
                if !others.is_empty() {
                    let _ = write!(facts, ", also {}", others.join(" "));
                }
            }
            let _ = writeln!(out, "      {facts}");
            if let Some(decision) = candidate.and_then(|c| c.decision.as_ref()) {
                for line in decision
                    .explanation
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                {
                    let _ = writeln!(out, "      {}", line.trim_end());
                }
            }
        }
    }
    out
}

/// The serde name of a unit enum value (`post`, `purge`).
fn enum_text<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::{
        Action, AppRef, Category, Decision, Harm, Origin, PlanSchema, ProgramId, Reversibility,
        ScanMode, Tool, View,
    };
    use purge_plan::emit::ScanSchema;

    fn candidate(id: &str, target: Target, band: Band, explanation: &str) -> Candidate {
        Candidate {
            id: purge_model::CandidateId(id.into()),
            target,
            action: Action::Quarantine,
            owner: AppRef {
                program_id: ProgramId::machine(View::K64, "App").unwrap(),
                display_name: "App".into(),
            },
            origin: Origin::Scanner,
            scanner: "REG-SOFTWARE".into(),
            category: Category::Registration,
            evidence: Vec::new(),
            blockers: Vec::new(),
            harm: Harm::Low,
            reversibility: Reversibility::Full,
            children: Vec::new(),
            size_bytes: None,
            child_count: None,
            decision: Some(Decision {
                band,
                preselected: band == Band::Safe,
                score: 0,
                explanation: explanation.into(),
            }),
            item_fp: None,
            object_fp: None,
            display_name: None,
            owner_program: None,
        }
    }

    fn docs() -> (Plan, ScanDoc) {
        let mut key = candidate(
            "k",
            Target::RegKey {
                path: r"HKLM\SOFTWARE\Vendor\App".into(),
            },
            Band::Safe,
            "Removed with the app.\nSecond line.",
        );
        key.children.push(purge_model::CandidateId("v".into()));
        let value = candidate(
            "v",
            Target::RegValue {
                path: r"HKLM\SOFTWARE\Vendor\App".into(),
                name: String::new(),
            },
            Band::Safe,
            "",
        );
        let dir = candidate(
            "d",
            Target::Path {
                path: r"C:\ProgramData\Vendor".into(),
            },
            Band::Weak,
            "Name only.",
        );
        let items = vec![key, dir];
        let scan = ScanDoc {
            schema: ScanSchema,
            app: "app".into(),
            tool: Tool::Purge,
            mode: ScanMode::Post,
            policy_version: "test".into(),
            plan_hash: plan_hash(&items, "test", ScanMode::Post),
            items: items.clone(),
            absorbed: vec![value],
        };
        let plan = purge_plan::emit::to_plan0("app", ScanMode::Post, &items);
        assert_eq!(plan.schema, PlanSchema);
        (plan, scan)
    }

    #[test]
    fn table_groups_by_band_with_explanations_and_hash() {
        let (plan, scan) = docs();
        let text = render(&plan, Ok(&scan));
        let expected = format!(
            "plan app: tool purge, mode post, 2 item(s) (1 preselected)\n\
             hash {} (policy test)\n\
             \n\
             Safe (1)\n  \
             [x] RegKey HKLM\\SOFTWARE\\Vendor\\App\n      \
             REG-SOFTWARE, Registration, absorbs 1\n      \
             Removed with the app.\n      \
             Second line.\n\
             \n\
             Weak (1)\n  \
             [ ] Path C:\\ProgramData\\Vendor\n      \
             REG-SOFTWARE, Registration\n      \
             Name only.\n",
            scan.plan_hash
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn a_sidecar_that_disagrees_is_not_used() {
        let (plan, mut scan) = docs();
        scan.plan_hash = "0".repeat(64);
        let text = render(&plan, Ok(&scan));
        assert!(
            text.contains("hash unknown: the sidecar's stored hash"),
            "{text}"
        );
        assert!(!text.contains("Removed with the app."), "{text}");

        let (plan, mut scan) = docs();
        scan.items.pop();
        assert!(
            check_sidecar(&plan, &scan)
                .unwrap_err()
                .contains("items differ")
        );
        let (mut plan, scan) = docs();
        plan.app = "other".into();
        assert!(check_sidecar(&plan, &scan).is_err());

        let text = render(&plan, Err("no sidecar".into()));
        assert!(text.contains("hash unknown: no sidecar"), "{text}");
        assert!(text.contains("[x] RegKey"), "{text}");
    }

    #[test]
    fn every_target_kind_has_a_line() {
        let cases = [
            (
                Target::RegValue {
                    path: "K".into(),
                    name: "N".into(),
                },
                "RegValue K : N",
            ),
            (
                Target::RegMultiSzSegment {
                    path: "K".into(),
                    name: "Path".into(),
                    segment: r"C:\x".into(),
                    index: None,
                },
                r"Segment K : Path : C:\x",
            ),
            (Target::Service { name: "S".into() }, "Service S"),
            (Target::Task { path: r"\T".into() }, r"Task \T"),
            (Target::FirewallRule { id: "R".into() }, "FirewallRule R"),
            (
                Target::AppxPackage {
                    full_name: "P".into(),
                },
                "AppxPackage P",
            ),
            (
                Target::RegValueChanged {
                    path: "K".into(),
                    name: String::new(),
                    before: String::new(),
                    after: String::new(),
                },
                "RegValueChanged K : (default)",
            ),
        ];
        for (target, text) in cases {
            assert_eq!(target_text(&target), text);
        }
    }

    /// A firewall rule shows its readable `Name=` from the sidecar beside its unique id
    /// (M3-ENGINE-OUT); a sidecar without one keeps the old line.
    #[test]
    fn a_firewall_rule_shows_its_name_from_the_sidecar() {
        let mut rule = candidate(
            "f",
            Target::FirewallRule {
                id: "{0000BBBB-0000-0000-0000-000000000001}".into(),
            },
            Band::Likely,
            "The rule's program is gone.",
        );
        rule.display_name = Some("Tool".into());
        rule.owner_program = Some(r"C:\Program Files\Tool\tool.exe".into());
        let items = vec![rule.clone()];
        let scan = ScanDoc {
            schema: ScanSchema,
            app: "app".into(),
            tool: Tool::Purge,
            mode: ScanMode::Post,
            policy_version: "test".into(),
            plan_hash: plan_hash(&items, "test", ScanMode::Post),
            items: items.clone(),
            absorbed: Vec::new(),
        };
        let plan = purge_plan::emit::to_plan0("app", ScanMode::Post, &items);
        let text = render(&plan, Ok(&scan));
        assert!(
            text.contains("FirewallRule {0000BBBB-0000-0000-0000-000000000001} (Tool)"),
            "{text}"
        );

        // No name in the sidecar: the line is the target's own text.
        let mut unnamed = items[0].clone();
        unnamed.display_name = None;
        assert_eq!(
            target_text_with_name(&unnamed.target, Some(&unnamed)),
            "FirewallRule {0000BBBB-0000-0000-0000-000000000001}"
        );
        assert_eq!(
            target_text_with_name(&items[0].target, None),
            "FirewallRule {0000BBBB-0000-0000-0000-000000000001}"
        );
    }
}
