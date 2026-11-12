//! Plan emission: the rig's plan document `purge.plan/0` (vm/RIG.md §7) and the extended scan document
//! `purge.scan/0` that `plan show` and debugging read.
//!
//! [`build`] is the whole of pipeline steps 6 and 7 for a dry run (ENGINE_PLAN.md §3.6): decide, collapse,
//! order, hash, emit. The parts are public for callers that need them one at a time.
//!
//! # `purge.plan/0`
//!
//! [`to_plan0`] writes one item per top-level candidate, Blocked and Weak ones included (the scorer treats
//! each band on its own terms). An absorbed child is not listed: its parent covers it. A candidate without
//! a decision is written as Blocked and unticked, and a `RegValueChanged` target (truth-only, never
//! offered) is left out. The default value of a key is the value name `""`. Registry paths are in the
//! guard's canonical form; the scorer canonicalises again on its side.
//!
//! # `purge.scan/0`
//!
//! [`ScanDoc`] carries everything the decision was made from: the full top-level candidates (evidence,
//! blockers, decision with its explanation, children ids), the absorbed candidates, the policy version and
//! the plan hash. A reader must not trust the stored decisions for anything but display: the candidates are
//! plain data, and only a fresh policy run over them is a verdict.

use std::borrow::Cow;

use purge_model::{Band, Candidate, Plan, PlanItem, PlanSchema, ScanMode, Target, Tool};
use purge_policy::band::POLICY_VERSION;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::collapse::{Collapsed, collapse};
use crate::decide::{DecideCtx, SCANNER_KEY, decide};
use crate::hash::plan_hash;
use crate::order;

/// The `schema` field of a scan document: always the literal string `purge.scan/0`. Reading any other
/// value fails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ScanSchema;

impl ScanSchema {
    /// The schema identifier this crate reads and writes.
    pub const ID: &'static str = "purge.scan/0";
}

impl Serialize for ScanSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::ID)
    }
}

impl<'de> Deserialize<'de> for ScanSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<str>::deserialize(deserializer)?;
        if s == Self::ID {
            Ok(ScanSchema)
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported scan schema {s:?}, expected {:?}",
                Self::ID
            )))
        }
    }
}

/// The extended scan document, `purge.scan/0`: the sidecar of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDoc {
    /// Always `purge.scan/0`.
    pub schema: ScanSchema,
    /// The app id, as in the plan.
    pub app: String,
    /// The cleaner that produced the scan: always `purge`.
    pub tool: Tool,
    /// The scan mode.
    pub mode: ScanMode,
    /// The version of the policy that decided the candidates.
    pub policy_version: String,
    /// The plan hash ([`crate::hash`]) of `items`.
    pub plan_hash: String,
    /// The top-level candidates in plan order: exactly the items of the plan, in full.
    pub items: Vec<Candidate>,
    /// The candidates absorbed by a Safe parent in `items`, in plan order.
    #[serde(default)]
    pub absorbed: Vec<Candidate>,
}

impl ScanDoc {
    /// The scanners that found `candidate`: the one it is listed under, then every other scanner whose
    /// evidence was merged into it.
    #[must_use]
    pub fn scanners(candidate: &Candidate) -> Vec<&str> {
        let mut all = vec![candidate.scanner.as_str()];
        for evidence in &candidate.evidence {
            match evidence.detail.get(SCANNER_KEY) {
                Some(scanner) if !all.contains(&scanner) => all.push(scanner),
                _ => {}
            }
        }
        all
    }
}

/// The plan and its sidecar, as [`build`] returns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The plan document for the rig and the executor.
    pub plan: Plan,
    /// The extended scan document.
    pub scan: ScanDoc,
}

/// The `purge.plan/0` document for the top-level, ordered candidates in `decided`.
#[must_use]
pub fn to_plan0(app_id: &str, mode: ScanMode, decided: &[Candidate]) -> Plan {
    let items = decided
        .iter()
        .filter(|c| !matches!(c.target, Target::RegValueChanged { .. }))
        .map(|c| {
            let (band, preselected) = c
                .decision
                .as_ref()
                .map_or((Band::Blocked, false), |d| (d.band, d.preselected));
            PlanItem {
                target: c.target.clone(),
                band,
                // Belt and braces: only a Safe item is ever written as ticked.
                preselected: preselected && band == Band::Safe,
                scanner: c.scanner.clone(),
                category: c.category,
            }
        })
        .collect();
    Plan {
        schema: PlanSchema,
        app: app_id.to_owned(),
        tool: Tool::Purge,
        mode,
        items,
    }
}

/// The `purge.scan/0` document for a collapsed, ordered scan. The plan hash is computed over
/// `collapsed.top` with the current policy version.
#[must_use]
pub fn to_scan0(app_id: &str, mode: ScanMode, collapsed: Collapsed) -> ScanDoc {
    ScanDoc {
        schema: ScanSchema,
        app: app_id.to_owned(),
        tool: Tool::Purge,
        mode,
        policy_version: POLICY_VERSION.to_owned(),
        plan_hash: plan_hash(&collapsed.top, POLICY_VERSION, mode),
        items: collapsed.top,
        absorbed: collapsed.absorbed,
    }
}

/// Decides, collapses, orders and emits the scanner candidates of one app (steps 6 and 7 of §3.6).
#[must_use]
pub fn build(app_id: &str, candidates: Vec<Candidate>, ctx: &DecideCtx<'_>) -> Built {
    let mut collapsed = collapse(decide(candidates, ctx), ctx);
    order::sort(&mut collapsed.top);
    order::sort(&mut collapsed.absorbed);
    let plan = to_plan0(app_id, ctx.mode, &collapsed.top);
    let scan = to_scan0(app_id, ctx.mode, collapsed);
    Built { plan, scan }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::testkit::*;
    use crate::empty_after::{Child, mark_pending};
    use purge_model::{Action, Blocker, Category, EvidenceKind, Facts, Scope};
    use serde_json::{Value, json};

    /// A copy of the reader in `vm/rigtool` (`score.rs`, `target.rs`): what the scorer accepts.
    mod rig {
        use serde::{Deserialize, Deserializer};

        fn null_str<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
            Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
        }

        #[derive(Deserialize, Debug, PartialEq, Eq)]
        #[serde(tag = "type")]
        pub enum Target {
            Path {
                path: String,
            },
            RegKey {
                path: String,
            },
            RegValue {
                path: String,
                #[serde(default, deserialize_with = "null_str")]
                name: String,
            },
            RegValueChanged {
                path: String,
                #[serde(default, deserialize_with = "null_str")]
                name: String,
                #[serde(default)]
                before: String,
                #[serde(default)]
                after: String,
            },
            RegMultiSzSegment {
                path: String,
                #[serde(default, deserialize_with = "null_str")]
                name: String,
                segment: String,
            },
            Service {
                name: String,
            },
            Task {
                path: String,
            },
            FirewallRule {
                #[serde(alias = "rule_id")]
                id: String,
            },
            AppxPackage {
                full_name: String,
            },
        }

        #[derive(Deserialize, Debug)]
        pub struct PlanItem {
            pub target: Target,
            #[serde(default)]
            pub band: String,
            #[serde(default)]
            pub preselected: bool,
            #[serde(default)]
            pub scanner: Option<String>,
            #[serde(default)]
            pub category: Option<String>,
        }

        #[derive(Deserialize, Debug, Default)]
        pub struct Plan {
            #[serde(default)]
            pub schema: String,
            #[serde(default)]
            pub app: String,
            #[serde(default)]
            pub tool: String,
            #[serde(default)]
            pub mode: String,
            #[serde(default)]
            pub items: Vec<PlanItem>,
        }
    }

    const VENDOR_KEY: &str = r"HKLM\SOFTWARE\Vendor";

    /// One candidate of each shape the M1a scanners produce.
    fn scan_output() -> Vec<Candidate> {
        let mut vendor = cand("vendor", key(VENDOR_KEY), "REG-SOFTWARE");
        vendor.action = Action::RemoveDirIfEmpty;
        vendor.evidence.push(
            ev(EvidenceKind::VendorContainer, Scope::Key, "vendor")
                .with_detail(mark_pending(Facts::new(), [Child::Container("App")])),
        );
        let mut segment = cand(
            "segment",
            Target::RegMultiSzSegment {
                path: r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment".into(),
                name: "Path".into(),
                segment: r"C:\Program Files\Vendor\App\bin".into(),
                index: None,
            },
            "REG-ENV",
        );
        segment.evidence.push(ev(
            EvidenceKind::InstallerManifest(purge_model::ManifestKind::Inno),
            Scope::Value,
            "inno",
        ));
        let mut weak = cand("weak", path(r"C:\ProgramData\Vendor"), "FS-APPDATA");
        weak.evidence
            .push(ev(EvidenceKind::NameTokenExact, Scope::Path, "name"));
        let mut package = cand(
            "pkg",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            "SYS-APPX",
        );
        package.category = Category::Package;
        package.blockers.push(Blocker::ReversibilityNone);
        package.evidence.push(ev(
            EvidenceKind::AppxExternalLocation,
            Scope::Package,
            "appx",
        ));
        let mut dup = cand(
            "dup",
            value(r"HKLM\Software\Vendor\App", "InstallDir"),
            "REG-SOFTWARE",
        );
        dup.evidence.push(ev(
            EvidenceKind::PointsIntoInstallRoot,
            Scope::Value,
            "live",
        ));
        vec![
            package,
            owned_path("root", r"C:\Program Files\Vendor\App"),
            weak,
            owned_path("exe", r"C:\Program Files\Vendor\App\app.exe"),
            vendor,
            owned_key("app-key", r"HKLM\SOFTWARE\Vendor\App"),
            owned_value("dir", r"HKLM\SOFTWARE\Vendor\App", "InstallDir"),
            dup,
            owned_value("default", &format!(r"HKU\{SID}\Software\Classes\.vnd"), ""),
            owned_key(
                "denied",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            segment,
        ]
    }

    fn built() -> Built {
        let deny = deny();
        build("vendor-app", scan_output(), &ctx(&deny))
    }

    fn row<'a>(plan: &'a Plan, target: &Target) -> &'a PlanItem {
        plan.items
            .iter()
            .find(|i| &i.target == target)
            .unwrap_or_else(|| panic!("no item for {target:?}"))
    }

    #[test]
    fn plan_lists_top_level_items_in_plan_order() {
        let Built { plan, scan } = built();
        assert_eq!(
            (plan.app.as_str(), plan.tool, plan.mode),
            ("vendor-app", Tool::Purge, ScanMode::Post)
        );
        let ids: Vec<&str> = scan.items.iter().map(|c| c.id.0.as_str()).collect();
        assert_eq!(
            ids,
            [
                "segment", "default", "denied", "app-key", "vendor", "root", "weak", "pkg"
            ]
        );
        let absorbed: Vec<&str> = scan.absorbed.iter().map(|c| c.id.0.as_str()).collect();
        assert_eq!(absorbed, ["dir", "exe"]);
        assert_eq!(plan.items.len(), scan.items.len());
        for (item, candidate) in plan.items.iter().zip(&scan.items) {
            let d = candidate.decision.as_ref().unwrap();
            assert_eq!(item.target, candidate.target);
            assert_eq!((item.band, item.preselected), (d.band, d.preselected));
            assert_eq!(item.scanner, candidate.scanner);
            assert_eq!(item.category, candidate.category);
        }

        let safe = |t: &Target| {
            let item = row(&plan, t);
            assert_eq!((item.band, item.preselected), (Band::Safe, true), "{t:?}");
        };
        safe(&key(r"HKLM\SOFTWARE\Vendor\App"));
        safe(&path(r"C:\Program Files\Vendor\App"));
        // The vendor key is emptied by the app key, so it goes too.
        safe(&key(VENDOR_KEY));
        // The default value is the value named "".
        safe(&value(&format!(r"HKU\{SID}_Classes\.vnd"), ""));

        // A denied target is listed as Blocked and never ticked.
        let denied = row(
            &plan,
            &key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        );
        assert_eq!((denied.band, denied.preselected), (Band::Blocked, false));
        let weak = row(&plan, &path(r"C:\ProgramData\Vendor"));
        assert_eq!((weak.band, weak.preselected), (Band::Weak, false));
        let pkg = plan.items.last().unwrap();
        assert_eq!(
            (pkg.band, pkg.preselected, pkg.category),
            (Band::Likely, false, Category::Package)
        );
        assert_eq!(plan.items.iter().filter(|i| i.preselected).count(), 5);
    }

    #[test]
    fn sidecar_keeps_evidence_blockers_explanations_and_the_hash() {
        let Built { plan: _, scan } = built();
        assert_eq!(scan.policy_version, POLICY_VERSION);
        assert_eq!(
            scan.plan_hash,
            plan_hash(&scan.items, POLICY_VERSION, ScanMode::Post)
        );
        let get = |id: &str| {
            scan.items
                .iter()
                .chain(&scan.absorbed)
                .find(|c| c.id.0 == id)
                .unwrap()
        };
        assert!(scan.items.iter().chain(&scan.absorbed).all(|c| {
            c.decision
                .as_ref()
                .is_some_and(|d| !d.explanation.is_empty())
        }));
        let denied = get("denied");
        assert!(matches!(denied.blockers[..], [Blocker::DenyListed { .. }]));
        let app_key = get("app-key");
        assert_eq!(app_key.children.len(), 1);
        assert_eq!(app_key.children[0].0, "dir");
        assert_eq!(get("root").children[0].0, "exe");
        assert!(
            get("vendor")
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::EmptyAfterPlan)
        );
        // The merged duplicate keeps its first scanner and names the other.
        let dir = get("dir");
        assert_eq!(dir.scanner, "REF-ANY");
        assert_eq!(ScanDoc::scanners(dir), ["REF-ANY", "REG-SOFTWARE"]);
        assert_eq!(ScanDoc::scanners(app_key), ["REG-SOFTWARE"]);

        // Round trip, and the schema id is checked on reading.
        let text = serde_json::to_string_pretty(&scan).unwrap();
        let back: ScanDoc = serde_json::from_str(&text).unwrap();
        assert_eq!(back, scan);
        let mut v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], json!("purge.scan/0"));
        assert_eq!(v["tool"], json!("purge"));
        v["schema"] = json!("purge.scan/1");
        assert!(serde_json::from_value::<ScanDoc>(v).is_err());
    }

    #[test]
    fn build_is_deterministic_and_the_hash_follows_the_plan() {
        let a = built();
        let b = built();
        assert_eq!(a, b);
        assert_eq!(a.scan.plan_hash, b.scan.plan_hash);

        let deny = deny();
        let ctx = ctx(&deny);
        // One item fewer.
        let mut fewer = scan_output();
        fewer.retain(|c| c.id.0 != "weak");
        assert_ne!(
            build("vendor-app", fewer, &ctx).scan.plan_hash,
            a.scan.plan_hash
        );
        // A band changes: the package loses its soft blocker's company but gains a hard one.
        let mut blocked = scan_output();
        blocked[0].blockers.push(Blocker::SharedRefcount);
        let other = build("vendor-app", blocked, &ctx);
        assert_eq!(other.plan.items.last().unwrap().band, Band::Blocked);
        assert_ne!(other.scan.plan_hash, a.scan.plan_hash);
        // The mode changes the bands and the hash.
        let forced = DecideCtx {
            mode: ScanMode::Forced,
            ..ctx
        };
        let f = build("vendor-app", scan_output(), &forced);
        assert_eq!(f.plan.mode, ScanMode::Forced);
        assert!(f.plan.items.iter().all(|i| !i.preselected));
        assert_ne!(f.scan.plan_hash, a.scan.plan_hash);
    }

    /// The emitted JSON reads with the rig's own structs, and reads back into the model.
    #[test]
    fn emitted_plan_parses_with_the_rig_reader() {
        let plan = built().plan;
        let text = serde_json::to_string(&plan).unwrap();
        let rig: rig::Plan = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (
                rig.schema.as_str(),
                rig.app.as_str(),
                rig.tool.as_str(),
                rig.mode.as_str()
            ),
            ("purge.plan/0", "vendor-app", "purge", "post")
        );
        assert_eq!(rig.items.len(), plan.items.len());
        for (theirs, ours) in rig.items.iter().zip(&plan.items) {
            assert!(["Safe", "Likely", "Weak", "Blocked"].contains(&theirs.band.as_str()));
            assert_eq!(theirs.band, format!("{:?}", ours.band));
            assert_eq!(theirs.preselected, ours.preselected);
            assert_eq!(theirs.scanner.as_deref(), Some(ours.scanner.as_str()));
            assert_eq!(
                theirs.category.as_deref(),
                Some(format!("{:?}", ours.category).as_str())
            );
        }
        assert_eq!(
            rig.items[0].target,
            rig::Target::RegMultiSzSegment {
                path: r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment".into(),
                name: "Path".into(),
                segment: r"C:\Program Files\Vendor\App\bin".into(),
            }
        );
        assert_eq!(
            rig.items[1].target,
            rig::Target::RegValue {
                path: format!(r"HKU\{SID}_Classes\.vnd"),
                name: String::new(),
            }
        );
        assert!(matches!(
            rig.items.last().unwrap().target,
            rig::Target::AppxPackage { .. }
        ));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["items"][1]["target"]["name"], json!(""));
        assert!(v["items"][0]["target"].get("index").is_none());
        // And back into the model.
        let back: Plan = serde_json::from_str(&text).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn undecided_and_truth_only_candidates() {
        let undecided = cand("u", key(r"HKLM\SOFTWARE\Vendor\App"), "REG-SOFTWARE");
        let changed = cand(
            "c",
            Target::RegValueChanged {
                path: r"HKLM\SOFTWARE\Vendor".into(),
                name: "Path".into(),
                before: "a".into(),
                after: "a;b".into(),
            },
            "REG-ENV",
        );
        // A decision that claims a tick without being Safe is not written as ticked.
        let mut odd = undecided.clone();
        odd.decision = Some(purge_model::Decision {
            band: Band::Likely,
            preselected: true,
            score: 5,
            explanation: String::new(),
        });
        let plan = to_plan0("app", ScanMode::External, &[undecided, changed, odd]);
        assert_eq!(plan.items.len(), 2);
        assert_eq!(
            (plan.items[0].band, plan.items[0].preselected),
            (Band::Blocked, false)
        );
        assert_eq!(
            (plan.items[1].band, plan.items[1].preselected),
            (Band::Likely, false)
        );
        assert_eq!(plan.mode, ScanMode::External);
        let empty = to_plan0("app", ScanMode::Post, &[]);
        assert_eq!(serde_json::to_value(&empty).unwrap()["items"], json!([]));
    }
}
