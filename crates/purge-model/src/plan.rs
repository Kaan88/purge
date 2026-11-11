//! The minimal plan document, `purge.plan/0` (vm/RIG.md §7).
//!
//! This is what a cleaner offers for one app: the dry-run output of `purge-engine scan`, and the format the
//! rig converts the old tools' results into before scoring.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Target;

/// The confidence band policy assigns to a candidate (ENGINE_PLAN.md §5.8.2).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Band {
    /// Proven to belong to the removed app; may be preselected.
    Safe,
    /// Probably the app's; shown, preselection depends on mode and category.
    Likely,
    /// Weak evidence only; listed, never preselected.
    Weak,
    /// A blocker or guard rule applies; shown for transparency, never actionable.
    Blocked,
}

/// Which cleaner produced a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    /// Purge's own engine.
    Purge,
    /// The earlier prototype (`draft_clone`), scored for comparison only.
    Clone,
    /// The commercial reference product, scored for comparison only.
    Ut,
    /// Bulk Crap Uninstaller, scored for comparison only.
    Bcu,
}

/// The situation a leftover scan runs in (ENGINE_PLAN.md §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Right after the vendor uninstaller ran under Purge, with a pre-uninstall harvest.
    Post,
    /// The app was uninstalled outside Purge; only a cached harvest, if any, is available.
    External,
    /// No uninstaller ran (forced removal of a broken or portable app).
    Forced,
}

/// What kind of thing a candidate is, for grouping and preselection (ENGINE_PLAN.md §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Category {
    /// Program files under an install root.
    AppFiles,
    /// Settings and state the app wrote for itself.
    AppData,
    /// Data the user made or would miss (profiles, saves, backups). Never preselected.
    UserData,
    /// Regenerable caches.
    Cache,
    /// Registration keys and values (uninstall entries, app keys, App Paths).
    Registration,
    /// File and protocol associations.
    Association,
    /// Shell extensions and COM registrations.
    ShellCom,
    /// Run entries, tasks and other autostart points.
    Startup,
    /// Services, drivers, firewall rules and other system integrations.
    System,
    /// Usage traces (MRU lists, MuiCache, prefetch).
    Privacy,
    /// Installer package caches and AppX packages.
    Package,
}

/// The `schema` field of a plan document: always the literal string `purge.plan/0`.
///
/// Deserialising any other value fails, so a plan of a different version is rejected up front.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PlanSchema;

impl PlanSchema {
    /// The schema identifier this crate reads and writes.
    pub const ID: &'static str = "purge.plan/0";
}

impl Serialize for PlanSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::ID)
    }
}

impl<'de> Deserialize<'de> for PlanSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<str>::deserialize(deserializer)?;
        if s == Self::ID {
            Ok(PlanSchema)
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported plan schema {s:?}, expected {:?}",
                Self::ID
            )))
        }
    }
}

impl JsonSchema for PlanSchema {
    fn schema_name() -> Cow<'static, str> {
        "PlanSchema".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "const": PlanSchema::ID })
    }
}

/// One offered item of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlanItem {
    /// What the item acts on.
    pub target: Target,
    /// Its confidence band.
    pub band: Band,
    /// Whether it is ticked by default.
    pub preselected: bool,
    /// Id of the scanner that found it, e.g. `REG-SOFTWARE` (ENGINE_PLAN.md §5.6).
    pub scanner: String,
    /// Its category.
    pub category: Category,
}

/// A plan document: what a cleaner offers to remove for one app (vm/RIG.md §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Plan {
    /// Always `purge.plan/0`.
    pub schema: PlanSchema,
    /// The app id (the rig's corpus id, e.g. `firefox`).
    pub app: String,
    /// The cleaner that produced the plan.
    pub tool: Tool,
    /// The scan mode.
    pub mode: ScanMode,
    /// The offered items.
    pub items: Vec<PlanItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// The example of vm/RIG.md §7, with each `a|b|c` placeholder resolved to one concrete value.
    const RIG_EXAMPLE: &str = r#"
{ "schema": "purge.plan/0", "app": "firefox", "tool": "purge", "mode": "post",
  "items": [ { "target": {"type":"RegKey","path":"HKLM\\SOFTWARE\\Mozilla"}, "band":"Safe",
               "preselected": true, "scanner": "REG-SOFTWARE", "category": "Registration" } ] }"#;

    fn round_trip<T>(v: &Value) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let typed: T = serde_json::from_value(v.clone()).expect("deserialise");
        assert_eq!(&serde_json::to_value(&typed).expect("serialise"), v);
        typed
    }

    #[test]
    fn rig_example_round_trips() {
        let v: Value = serde_json::from_str(RIG_EXAMPLE).unwrap();
        let plan: Plan = round_trip(&v);
        assert_eq!(plan.app, "firefox");
        assert_eq!(plan.tool, Tool::Purge);
        assert_eq!(plan.mode, ScanMode::Post);
        assert_eq!(
            plan.items,
            vec![PlanItem {
                target: Target::RegKey {
                    path: r"HKLM\SOFTWARE\Mozilla".into()
                },
                band: Band::Safe,
                preselected: true,
                scanner: "REG-SOFTWARE".into(),
                category: Category::Registration,
            }]
        );
    }

    #[test]
    fn every_placeholder_value_round_trips() {
        for tool in ["purge", "clone", "ut", "bcu"] {
            for mode in ["post", "external", "forced"] {
                for band in ["Safe", "Likely", "Weak", "Blocked"] {
                    let v = json!({
                        "schema": "purge.plan/0", "app": "a", "tool": tool, "mode": mode,
                        "items": [{ "target": {"type": "Path", "path": "C:\\X"}, "band": band,
                                    "preselected": false, "scanner": "FS-INSTALLDIR", "category": "AppFiles" }]
                    });
                    round_trip::<Plan>(&v);
                }
            }
        }
    }

    #[test]
    fn every_target_type_round_trips() {
        let targets = [
            json!({"type": "Path", "path": "C:\\Program Files\\Mozilla Firefox"}),
            json!({"type": "RegKey", "path": "HKLM\\SOFTWARE\\Mozilla"}),
            json!({"type": "RegValue", "path": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "App"}),
            json!({"type": "RegValue", "path": "HKLM\\SOFTWARE\\X", "name": ""}),
            json!({"type": "RegValueChanged", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "name": "Path", "before": "C:\\a", "after": "C:\\a;C:\\Tool\\bin"}),
            json!({"type": "RegMultiSzSegment", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "name": "Path", "segment": "C:\\Tool\\bin"}),
            json!({"type": "Service", "name": "MozillaMaintenance"}),
            json!({"type": "Task", "path": "\\Mozilla\\Firefox Default Browser Agent"}),
            json!({"type": "FirewallRule", "id": "{6A3F2C1E-0000-4000-8000-000000000001}"}),
            json!({"type": "AppxPackage", "full_name": "Vendor.App_1.0.0.0_x64__abcdefghijklm"}),
        ];
        for t in &targets {
            round_trip::<Target>(t);
        }
    }

    #[test]
    fn rejects_other_schema_and_unknown_target_type() {
        let mut v: Value = serde_json::from_str(RIG_EXAMPLE).unwrap();
        v["schema"] = json!("purge.plan/1");
        assert!(serde_json::from_value::<Plan>(v).is_err());
        assert!(
            serde_json::from_value::<Target>(json!({"type": "Shortcut", "path": "x"})).is_err()
        );
        assert!(
            serde_json::from_value::<Target>(json!({"type": "RegValue", "path": "x"})).is_err()
        );
    }

    #[test]
    fn null_value_name_reads_as_default_value() {
        for ty in ["RegValue", "RegValueChanged"] {
            let t: Target = serde_json::from_value(
                json!({"type": ty, "path": "HKLM\\SOFTWARE\\X", "name": null}),
            )
            .unwrap();
            let v = serde_json::to_value(&t).unwrap();
            assert_eq!(v["name"], json!(""), "{ty}");
        }
        let seg: Target = serde_json::from_value(
            json!({"type": "RegMultiSzSegment", "path": "HKLM\\X", "name": null, "segment": "s"}),
        )
        .unwrap();
        assert_eq!(
            seg,
            Target::RegMultiSzSegment {
                path: "HKLM\\X".into(),
                name: String::new(),
                segment: "s".into()
            }
        );
    }

    /// A `truth.json` item target as rigtool writes it (vm/RIG.md §5) reads into `Target`.
    #[test]
    fn reads_rig_truth_value_changed() {
        let t: Target = serde_json::from_value(json!({
            "type": "RegValueChanged", "path": "HKLM\\SOFTWARE\\Existing", "name": "Path",
            "before": "C:\\a", "after": "C:\\a;C:\\b"
        }))
        .unwrap();
        assert_eq!(
            t,
            Target::RegValueChanged {
                path: "HKLM\\SOFTWARE\\Existing".into(),
                name: "Path".into(),
                before: "C:\\a".into(),
                after: "C:\\a;C:\\b".into()
            }
        );
    }

    #[test]
    fn json_schema_is_generated() {
        let schema = serde_json::to_value(schemars::schema_for!(Plan)).unwrap();
        let text = schema.to_string();
        assert!(text.contains(r#""const":"purge.plan/0""#), "{text}");
        for t in [
            "RegMultiSzSegment",
            "FirewallRule",
            "AppxPackage",
            "Blocked",
            "forced",
            "bcu",
        ] {
            assert!(text.contains(t), "schema lacks {t}");
        }
    }
}
