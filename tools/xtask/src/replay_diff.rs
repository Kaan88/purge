//! `replay-diff`: the M1a frozen runs replayed with the full M1b scanner set, compared with the m1a.6
//! plans (M1B_DESIGN.json, M1B-SCAN-INTEG "Offline replay").
//!
//! ```text
//! cargo xtask replay-diff [--runs <vm/runs>] [-o <diff.json>]
//! cargo xtask replay-diff --write-reference <dir with <id>.scan.json>
//! ```
//!
//! The reference is `vm/truth/m1a6-replay.json`: for each frozen run ([`DIFF_RUNS`]: the M0 runs and 7-Zip,
//! the one app M1b set out to change, review R4 S9) every item of the m1a.6
//! engine's replay (commit `622c64d`, `cargo xtask replay` over the same run), top-level and absorbed,
//! with its band, preselection, scanner and blocker names. `--write-reference` builds it from the scan
//! sidecars of such a replay.
//!
//! The diff replays each run with this build (as `replay` does, into a temporary directory), keys every
//! item by its target, and writes one row for each target whose band, preselection, absorption,
//! scanner or blockers differ, or that is on one side only, to `vm/truth/m1b-replay-diff.json`. Each row
//! carries a reason ([`reason`]):
//!
//! - a **promotion** (the band rose toward Safe, or the item became preselected; [`is_promotion`]) is
//!   explained by nothing above: it is `promotion_justified` when [`JUSTIFIED_PROMOTIONS`] names it with
//!   a written cause, else `unexplained` (review R4 S9: no reason may carry an item from Blocked to Safe);
//!
//! - `new_scanner`: the item is now listed under an M1b scanner (new, or merged into an M1b scanner's
//!   candidate);
//! - `msi_blocker_added`: it now carries an MSI blocker it did not carry (`OwnedByInstalledMsi`,
//!   `SharedRefcount`, `MsiProductStillRegistered`, `BurnDependentsRemain`, `MsiPackageUnreadable`);
//! - `msi_root_added`: a new item of an M1a scanner on or under a root the harvest read from MSI
//!   component paths;
//! - `policy_m1b`: it now carries an object blocker M1b added (`Driver`, `HasDependents`,
//!   `ObjectChangedSinceHarvest`, `ReversibilityPartial`, `ProgramUnresolved`).
//!
//! A row none of these explains is `unexplained`, and the command fails (after writing the file). The
//! file also counts the promotions and the new items offered Safe, so a reader sees them at once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use purge_guard::prefix;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::replay::{self, RUNS_DIR_VAR, ReplayOpts};

/// The frozen runs the diff replays: the M0 runs and 7-Zip (`vm/runs/7zip`, `vm/truth/m1a-frozen-7zip.json`).
pub const DIFF_RUNS: &[&str] = &["vscode", "git", "firefox", "npp", "7zip"];

/// Promotions with a written cause: (run, target JSON as the sidecar writes it, cause). A promotion not
/// listed here is unexplained. Empty: M1b justifies none.
pub const JUSTIFIED_PROMOTIONS: &[(&str, &str, &str)] = &[];

const USAGE: &str = "usage: cargo xtask replay-diff [--runs <vm/runs>] [-o <diff.json>] | \
                     --write-reference <dir with <id>.scan.json>";

/// The committed reference, relative to the workspace root.
pub const REFERENCE: &str = "vm/truth/m1a6-replay.json";
/// The committed diff, relative to the workspace root.
pub const DIFF: &str = "vm/truth/m1b-replay-diff.json";

/// The reasons a row may carry.
pub const REASONS: [&str; 5] = [
    "new_scanner",
    "msi_blocker_added",
    "msi_root_added",
    "policy_m1b",
    PROMOTION_JUSTIFIED,
];

/// The reason of a promotion [`JUSTIFIED_PROMOTIONS`] names.
pub const PROMOTION_JUSTIFIED: &str = "promotion_justified";

/// The reason of a row no allowed reason explains.
pub const UNEXPLAINED: &str = "unexplained";

/// The blockers of reason `msi_blocker_added`.
const MSI_BLOCKERS: [&str; 5] = [
    "OwnedByInstalledMsi",
    "SharedRefcount",
    "MsiProductStillRegistered",
    "BurnDependentsRemain",
    "MsiPackageUnreadable",
];

/// The blockers of reason `policy_m1b`.
const POLICY_M1B_BLOCKERS: [&str; 5] = [
    "Driver",
    "HasDependents",
    "ObjectChangedSinceHarvest",
    "ReversibilityPartial",
    "ProgramUnresolved",
];

/// The m1a.6 engine the reference comes from.
const REFERENCE_ENGINE: &str = "m1a.6 (622c64d), cargo xtask replay without overlay";

/// One item of a plan as the diff sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// The target, as the scan sidecar writes it.
    pub target: Value,
    /// The band.
    pub band: String,
    /// Whether it is preselected.
    pub preselected: bool,
    /// The scanner it is listed under.
    pub scanner: String,
    /// Whether a Safe parent absorbed it.
    #[serde(default)]
    pub absorbed: bool,
    /// Its blockers' names, sorted.
    #[serde(default)]
    pub blockers: Vec<String>,
    /// The evidence's `detail.root` values (not in the reference file).
    #[serde(default, skip_serializing)]
    pub evidence_roots: Vec<String>,
}

/// The reference file.
#[derive(Debug, Serialize, Deserialize)]
struct Reference {
    schema: String,
    engine: String,
    apps: BTreeMap<String, Vec<Item>>,
}

/// One row of the diff.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    /// The run.
    pub app: String,
    /// The target.
    pub target: Value,
    /// The m1a.6 item.
    pub before: Option<Item>,
    /// This build's item.
    pub after: Option<Item>,
    /// One of [`REASONS`], or [`UNEXPLAINED`].
    pub reason: &'static str,
}

/// The diff file.
#[derive(Debug, Serialize)]
struct DiffDoc<'a> {
    schema: &'static str,
    reference: &'a str,
    reasons: [&'static str; 5],
    apps: BTreeMap<String, (usize, usize)>,
    unexplained: usize,
    /// Rows whose band rose or that became preselected (justified or not).
    promotions: usize,
    /// Items on this side only that are offered Safe.
    new_safe: usize,
    rows: Vec<Row>,
}

/// The name of a blocker as the sidecar spells it (`"SharedRefcount"` or `{"HasDependents": {...}}`).
fn blocker_name(b: &Value) -> Option<String> {
    match b {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.keys().next().cloned(),
        _ => None,
    }
}

/// The items of a scan sidecar (`purge.scan/0`): top-level, then absorbed.
pub fn items_of_sidecar(doc: &Value) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for (list, absorbed) in [("items", false), ("absorbed", true)] {
        let Some(arr) = doc.get(list).and_then(Value::as_array) else {
            if list == "items" {
                bail!("the sidecar has no items");
            }
            continue;
        };
        for c in arr {
            let decision = c
                .get("decision")
                .ok_or_else(|| anyhow!("item without decision"))?;
            let mut blockers: Vec<String> = c
                .get("blockers")
                .and_then(Value::as_array)
                .map(|bs| bs.iter().filter_map(blocker_name).collect())
                .unwrap_or_default();
            blockers.sort();
            blockers.dedup();
            let evidence_roots = c
                .get("evidence")
                .and_then(Value::as_array)
                .map(|es| {
                    es.iter()
                        .filter_map(|e| e.pointer("/detail/root").and_then(Value::as_str))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            out.push(Item {
                target: c.get("target").cloned().unwrap_or(Value::Null),
                band: decision
                    .get("band")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                preselected: decision
                    .get("preselected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                scanner: c
                    .get("scanner")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                absorbed,
                blockers,
                evidence_roots,
            });
        }
    }
    Ok(out)
}

/// The key of a target: its JSON with every string folded (paths and names compare without case).
fn target_key(target: &Value) -> String {
    fn fold(v: &Value) -> Value {
        match v {
            Value::String(s) => Value::String(s.to_lowercase()),
            Value::Array(a) => Value::Array(a.iter().map(fold).collect()),
            Value::Object(m) => {
                Value::Object(m.iter().map(|(k, v)| (k.clone(), fold(v))).collect())
            }
            other => other.clone(),
        }
    }
    fold(target).to_string()
}

/// Items by target key; a target listed twice keeps its first (top-level) item.
fn by_target(items: &[Item]) -> BTreeMap<String, &Item> {
    let mut out = BTreeMap::new();
    for item in items {
        out.entry(target_key(&item.target)).or_insert(item);
    }
    out
}

/// Whether two items of the same target differ for the diff (blockers included, review R4 S9).
fn differs(a: &Item, b: &Item) -> bool {
    a.band != b.band
        || a.preselected != b.preselected
        || a.absorbed != b.absorbed
        || a.scanner != b.scanner
        || a.blockers != b.blockers
}

/// A band's rank: Blocked 0, Weak 1, Likely 2, Safe 3 (an unknown band ranks highest, so a change to it
/// counts as a promotion).
fn band_rank(band: &str) -> u8 {
    match band {
        "Blocked" => 0,
        "Weak" => 1,
        "Likely" => 2,
        "Safe" => 3,
        _ => 4,
    }
}

/// Whether the item went up toward Safe: a higher band, or newly preselected.
pub fn is_promotion(before: &Item, after: &Item) -> bool {
    band_rank(&after.band) > band_rank(&before.band) || (after.preselected && !before.preselected)
}

/// The M1b scanners: the catalog after the M1a nineteen.
fn m1b_scanners() -> &'static [&'static str] {
    &purge_scan::catalog::SCANNER_IDS[19..]
}

/// The path a target names (files and directories only).
fn target_path(target: &Value) -> Option<&str> {
    (target.get("type").and_then(Value::as_str) == Some("Path"))
        .then(|| target.get("path").and_then(Value::as_str))
        .flatten()
}

/// The reason of one differing row (see the module documentation); `None` when no allowed reason
/// explains it.
pub fn reason(
    before: Option<&Item>,
    after: Option<&Item>,
    msi_roots: &[String],
    m1b: &[&str],
) -> Option<&'static str> {
    let after = after?;
    // No reason explains a promotion: a new scanner, an added blocker or a new MSI root never makes an
    // item safer (review R4 S9). JUSTIFIED_PROMOTIONS is checked by the caller.
    if before.is_some_and(|b| is_promotion(b, after)) {
        return None;
    }
    let added = |names: &[&str]| {
        after
            .blockers
            .iter()
            .any(|b| names.contains(&b.as_str()) && before.is_none_or(|x| !x.blockers.contains(b)))
    };
    if m1b.contains(&after.scanner.as_str()) && before.is_none_or(|b| b.scanner != after.scanner) {
        return Some("new_scanner");
    }
    if before.is_some() && added(&MSI_BLOCKERS) {
        return Some("msi_blocker_added");
    }
    if before.is_none() {
        let under_msi_root = |p: &str| msi_roots.iter().any(|r| prefix::is_same_or_inside(p, r));
        if target_path(&after.target).is_some_and(under_msi_root)
            || after
                .evidence_roots
                .iter()
                .any(|r| msi_roots.iter().any(|m| prefix::is_same(r, m)))
        {
            return Some("msi_root_added");
        }
        if added(&MSI_BLOCKERS) {
            return Some("msi_blocker_added");
        }
    }
    if added(&POLICY_M1B_BLOCKERS) {
        return Some("policy_m1b");
    }
    None
}

/// The rows of one run.
pub fn diff_rows(app: &str, before: &[Item], after: &[Item], msi_roots: &[String]) -> Vec<Row> {
    let b = by_target(before);
    let a = by_target(after);
    let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
    let mut rows = Vec::new();
    for key in keys {
        let (x, y) = (b.get(key).copied(), a.get(key).copied());
        if let (Some(x), Some(y)) = (x, y)
            && !differs(x, y)
        {
            continue;
        }
        let target = y.or(x).map(|i| i.target.clone()).unwrap_or(Value::Null);
        let promoted = matches!((x, y), (Some(x), Some(y)) if is_promotion(x, y));
        let justified = promoted
            && JUSTIFIED_PROMOTIONS.iter().any(|(a, t, why)| {
                *a == app
                    && !why.trim().is_empty()
                    && target_key(&serde_json::from_str(t).unwrap_or(Value::Null)) == *key
            });
        let reason = if justified {
            PROMOTION_JUSTIFIED
        } else {
            reason(x, y, msi_roots, m1b_scanners()).unwrap_or(UNEXPLAINED)
        };
        rows.push(Row {
            app: app.to_owned(),
            target,
            before: x.cloned(),
            after: y.cloned(),
            reason,
        });
    }
    rows
}

/// Runs the command; `Ok(false)` when a row is unexplained.
pub fn run(root: &Path, args: &[String]) -> Result<bool> {
    let mut runs: Option<PathBuf> = None;
    let mut out = root.join(DIFF);
    let mut write_reference: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || {
            it.next()
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("{a} needs a value\n{USAGE}"))
        };
        match a.as_str() {
            "--runs" => runs = Some(value()?),
            "-o" => out = value()?,
            "--write-reference" => write_reference = Some(value()?),
            _ => bail!("unknown argument {a}\n{USAGE}"),
        }
    }
    if let Some(dir) = write_reference {
        return write_reference_file(root, &dir).map(|()| true);
    }

    let reference: Reference = serde_json::from_str(
        &std::fs::read_to_string(root.join(REFERENCE))
            .with_context(|| format!("reading {REFERENCE}"))?,
    )
    .with_context(|| format!("parsing {REFERENCE}"))?;
    let runs = runs
        .or_else(|| std::env::var_os(RUNS_DIR_VAR).map(PathBuf::from))
        .unwrap_or_else(|| root.join("vm").join("runs"));
    if !runs.is_dir() {
        bail!(
            "replay-diff: no runs directory {} (the frozen rig runs are git-ignored; pass --runs or set \
             {RUNS_DIR_VAR})",
            runs.display()
        );
    }
    let temp = std::env::temp_dir().join(format!("purge-replay-diff-{}", std::process::id()));
    let mut rows = Vec::new();
    let mut apps = BTreeMap::new();
    for id in DIFF_RUNS {
        let before = reference
            .apps
            .get(*id)
            .ok_or_else(|| anyhow!("{REFERENCE} has no run {id}"))?;
        let opts = ReplayOpts {
            run_dir: runs.join(id),
            app: (*id).to_owned(),
            out: temp.join(format!("{id}.json")),
            overlay: None,
            baselines: replay::default_baselines(root),
            fp: None,
            sidecar: true,
            live: false,
        };
        let replayed = replay::replay(&opts).with_context(|| format!("replaying {id}"))?;
        let sidecar = purge_engine::cli::output::sidecar_path(&opts.out);
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&sidecar)
                .with_context(|| format!("reading {}", sidecar.display()))?,
        )?;
        let after = items_of_sidecar(&doc)?;
        apps.insert((*id).to_owned(), (before.len(), after.len()));
        rows.extend(diff_rows(id, before, &after, &replayed.msi_roots));
    }
    let _ = std::fs::remove_dir_all(&temp);

    let unexplained = rows.iter().filter(|r| r.reason == UNEXPLAINED).count();
    let promotions = rows
        .iter()
        .filter(|r| matches!((&r.before, &r.after), (Some(b), Some(a)) if is_promotion(b, a)))
        .count();
    let new_safe = rows
        .iter()
        .filter(|r| r.before.is_none() && r.after.as_ref().is_some_and(|a| a.band == "Safe"))
        .count();
    let doc = DiffDoc {
        schema: "purge.replay-diff/2",
        reference: REFERENCE_ENGINE,
        reasons: REASONS,
        apps,
        unexplained,
        promotions,
        new_safe,
        rows,
    };
    let text = serde_json::to_string_pretty(&doc)? + "\n";
    std::fs::write(&out, text).with_context(|| format!("writing {}", out.display()))?;
    for row in &doc.rows {
        println!(
            "replay-diff: {}: {} {} -> {}: {}",
            row.app,
            row.target,
            row.before
                .as_ref()
                .map_or_else(|| "-".to_owned(), |i| format!("{}{}", i.band, star(i))),
            row.after.as_ref().map_or_else(
                || "-".to_owned(),
                |i| format!("{}{} {}", i.band, star(i), i.scanner)
            ),
            row.reason
        );
    }
    println!(
        "replay-diff: {} differing row(s), {unexplained} unexplained, {promotions} promotion(s), {new_safe} new Safe item(s) -> {}",
        doc.rows.len(),
        out.display()
    );
    Ok(unexplained == 0)
}

fn star(i: &Item) -> &'static str {
    if i.preselected { "*" } else { "" }
}

/// Writes [`REFERENCE`] from `<dir>/<id>.scan.json` of every run of [`DIFF_RUNS`].
fn write_reference_file(root: &Path, dir: &Path) -> Result<()> {
    let mut apps = BTreeMap::new();
    for id in DIFF_RUNS {
        let path = dir.join(format!("{id}.scan.json"));
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?,
        )?;
        apps.insert((*id).to_owned(), items_of_sidecar(&doc)?);
    }
    let reference = Reference {
        schema: "purge.replay-ref/1".into(),
        engine: REFERENCE_ENGINE.into(),
        apps,
    };
    let out = root.join(REFERENCE);
    std::fs::write(&out, serde_json::to_string_pretty(&reference)? + "\n")
        .with_context(|| format!("writing {}", out.display()))?;
    println!("replay-diff: wrote {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::M0_RUNS;
    use serde_json::json;

    fn item(target: Value, band: &str, scanner: &str, blockers: &[&str]) -> Item {
        Item {
            target,
            band: band.into(),
            preselected: band == "Safe",
            scanner: scanner.into(),
            absorbed: false,
            blockers: blockers.iter().map(|b| (*b).to_owned()).collect(),
            evidence_roots: Vec::new(),
        }
    }

    fn path(p: &str) -> Value {
        json!({"type": "Path", "path": p})
    }

    /// Each allowed reason is given only where it applies; every other change is unexplained. The
    /// committed diff has no row without an allowed reason.
    #[test]
    fn replay_diff_only_allowed_reasons() {
        let m1b = m1b_scanners();
        assert_eq!(m1b.len(), 14);
        assert!(m1b.contains(&"SYS-FIREWALL") && !m1b.contains(&"SYS-APPX"));
        let rule = json!({"type": "FirewallRule", "id": "{A}"});
        let msi_root = vec![r"C:\Program Files\7-Zip".to_owned()];

        // A new item of an M1b scanner; an M1a item now merged under one.
        let fw = item(rule.clone(), "Likely", "SYS-FIREWALL", &[]);
        assert_eq!(reason(None, Some(&fw), &[], m1b), Some("new_scanner"));
        let old = item(path(r"C:\x"), "Weak", "FS-APPDATA", &[]);
        let merged = item(path(r"C:\x"), "Weak", "FS-WER", &[]);
        assert_eq!(
            reason(Some(&old), Some(&merged), &[], m1b),
            Some("new_scanner")
        );

        // A promotion is explained by no reason (review R4 S9): a band that rose under an M1b scanner, a
        // Blocked item made Safe and preselected under one, an item newly preselected, a band that rose
        // while an MSI or M1b blocker was added.
        let raised = item(path(r"C:\x"), "Likely", "FS-WER", &[]);
        assert!(is_promotion(&old, &raised));
        assert_eq!(reason(Some(&old), Some(&raised), &[], m1b), None);
        let blocked_before = item(
            json!({"type": "FirewallRule", "id": "{B}"}),
            "Blocked",
            "REF-ANY",
            &["Driver"],
        );
        let safe_now = item(
            json!({"type": "FirewallRule", "id": "{B}"}),
            "Safe",
            "SYS-FIREWALL",
            &[],
        );
        assert_eq!(
            reason(Some(&blocked_before), Some(&safe_now), &[], m1b),
            None
        );
        let mut ticked = item(path(r"C:\z"), "Likely", "FS-APPDATA", &[]);
        ticked.preselected = false;
        let mut ticked_now = ticked.clone();
        ticked_now.preselected = true;
        ticked_now.scanner = "FS-WER".into();
        assert!(is_promotion(&ticked, &ticked_now));
        assert_eq!(reason(Some(&ticked), Some(&ticked_now), &[], m1b), None);
        let weak = item(path(r"C:\w"), "Weak", "FS-INSTALLDIR", &[]);
        let up_blocked = item(
            path(r"C:\w"),
            "Likely",
            "FS-INSTALLDIR",
            &["SharedRefcount", "Driver"],
        );
        assert_eq!(reason(Some(&weak), Some(&up_blocked), &[], m1b), None);
        let rows = diff_rows(
            "t",
            std::slice::from_ref(&blocked_before),
            std::slice::from_ref(&safe_now),
            &[],
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, UNEXPLAINED);
        // A demotion keeps its reason; a blocker change alone is a row.
        assert!(!is_promotion(&safe_now, &blocked_before));
        let more = item(
            path(r"C:\v"),
            "Blocked",
            "FS-INSTALLDIR",
            &["Driver", "SharedRefcount"],
        );
        let less = item(
            path(r"C:\v"),
            "Blocked",
            "FS-INSTALLDIR",
            &["SharedRefcount"],
        );
        let rows = diff_rows(
            "t",
            std::slice::from_ref(&less),
            std::slice::from_ref(&more),
            &[],
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, "policy_m1b");
        let rows = diff_rows(
            "t",
            std::slice::from_ref(&more),
            std::slice::from_ref(&less),
            &[],
        );
        assert_eq!(
            rows[0].reason, UNEXPLAINED,
            "a blocker dropped is not explained"
        );

        // A new MSI blocker on an M1a item.
        let safe = item(path(r"C:\y"), "Safe", "FS-INSTALLDIR", &[]);
        let blocked = item(
            path(r"C:\y"),
            "Blocked",
            "FS-INSTALLDIR",
            &["SharedRefcount"],
        );
        assert_eq!(
            reason(Some(&safe), Some(&blocked), &[], m1b),
            Some("msi_blocker_added")
        );
        // ... but not one it already had.
        let had = item(
            path(r"C:\y"),
            "Likely",
            "FS-INSTALLDIR",
            &["SharedRefcount"],
        );
        assert_eq!(reason(Some(&had), Some(&blocked), &[], m1b), None);

        // A new item of an M1a scanner under an MSI root; the same outside it is unexplained.
        let inside = item(
            path(r"C:\Program Files\7-Zip\Lang"),
            "Safe",
            "FS-INSTALLDIR",
            &[],
        );
        assert_eq!(
            reason(None, Some(&inside), &msi_root, m1b),
            Some("msi_root_added")
        );
        let outside = item(
            path(r"C:\Program Files\7-Zip2"),
            "Safe",
            "FS-INSTALLDIR",
            &[],
        );
        assert_eq!(reason(None, Some(&outside), &msi_root, m1b), None);
        let mut by_evidence = item(
            json!({"type": "RegValue", "path": "HKLM\\X", "name": "p"}),
            "Likely",
            "REF-ANY",
            &[],
        );
        by_evidence.evidence_roots = msi_root.clone();
        assert_eq!(
            reason(None, Some(&by_evidence), &msi_root, m1b),
            Some("msi_root_added")
        );

        // An M1b object blocker.
        let svc = item(
            json!({"type": "Service", "name": "S"}),
            "Blocked",
            "REF-ANY",
            &["HasDependents"],
        );
        let before = item(
            json!({"type": "Service", "name": "S"}),
            "Likely",
            "REF-ANY",
            &[],
        );
        assert_eq!(
            reason(Some(&before), Some(&svc), &[], m1b),
            Some("policy_m1b")
        );

        // Unexplained: a band that moved for no listed cause, a vanished item, a new M1a item.
        let moved = item(path(r"C:\y"), "Likely", "FS-INSTALLDIR", &[]);
        assert_eq!(reason(Some(&safe), Some(&moved), &[], m1b), None);
        assert_eq!(reason(Some(&safe), None, &[], m1b), None);
        assert_eq!(reason(None, Some(&safe), &[], m1b), None);

        // Rows: unchanged items give none; case of a path does not matter.
        let same_upper = item(path(r"C:\Y"), "Safe", "FS-INSTALLDIR", &[]);
        assert!(diff_rows("t", std::slice::from_ref(&safe), &[same_upper], &[]).is_empty());
        let rows = diff_rows("t", std::slice::from_ref(&safe), &[safe.clone(), fw], &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, "new_scanner");

        // The committed diff: every row has an allowed reason, and the count says so.
        let text = std::fs::read_to_string(crate::workspace_root().join(DIFF)).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["unexplained"], json!(0));
        for row in doc["rows"].as_array().unwrap() {
            let r = row["reason"].as_str().unwrap();
            assert!(REASONS.contains(&r), "{row}");
        }
        // Every run of the diff is in it, 7-Zip included.
        for id in DIFF_RUNS {
            assert!(
                doc["apps"].get(*id).is_some(),
                "{id} not in the committed diff"
            );
        }
        assert!(
            JUSTIFIED_PROMOTIONS
                .iter()
                .all(|(_, _, why)| !why.trim().is_empty())
        );
        // The committed reference parses and holds the runs: the M0 runs with items, 7-Zip (m1a.6
        // offered nothing for it).
        let reference: Reference = serde_json::from_str(
            &std::fs::read_to_string(crate::workspace_root().join(REFERENCE)).unwrap(),
        )
        .unwrap();
        for id in M0_RUNS {
            assert!(!reference.apps[*id].is_empty(), "{id}");
        }
        assert!(reference.apps.contains_key("7zip"));
        assert_eq!(DIFF_RUNS.len(), M0_RUNS.len() + 1);
    }
}
