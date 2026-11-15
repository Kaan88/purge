//! Targets (same names as `purge-model`) and their canonical strings (RIG.md §5, §7).

use crate::canon;
use serde::{Deserialize, Deserializer, Serialize};

fn null_str<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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

pub const SERVICES: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
pub const TASKS_DIR: &str = "C:\\Windows\\System32\\Tasks";
pub const TASKCACHE: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
pub const FW_RULES: &str =
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
pub const WINDOWSAPPS: &str = "C:\\Program Files\\WindowsApps";

impl Target {
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Path { .. } => "Path",
            Target::RegKey { .. } => "RegKey",
            Target::RegValue { .. } => "RegValue",
            Target::RegValueChanged { .. } => "RegValueChanged",
            Target::RegMultiSzSegment { .. } => "RegMultiSzSegment",
            Target::Service { .. } => "Service",
            Target::Task { .. } => "Task",
            Target::FirewallRule { .. } => "FirewallRule",
            Target::AppxPackage { .. } => "AppxPackage",
        }
    }

    /// Kind rank for stable sorting.
    pub fn rank(&self) -> u8 {
        match self {
            Target::Path { .. } => 0,
            Target::RegKey { .. } => 1,
            Target::RegValue { .. } => 2,
            Target::RegValueChanged { .. } => 3,
            Target::RegMultiSzSegment { .. } => 4,
            Target::Service { .. } => 5,
            Target::Task { .. } => 6,
            Target::FirewallRule { .. } => 7,
            Target::AppxPackage { .. } => 8,
        }
    }

    /// Path (for Path), key (for registry kinds), else the identifying string.
    pub fn path(&self) -> &str {
        match self {
            Target::Path { path }
            | Target::RegKey { path }
            | Target::RegValue { path, .. }
            | Target::RegValueChanged { path, .. }
            | Target::RegMultiSzSegment { path, .. }
            | Target::Task { path } => path,
            Target::Service { name } => name,
            Target::FirewallRule { id } => id,
            Target::AppxPackage { full_name } => full_name,
        }
    }

    pub fn value_name(&self) -> Option<&str> {
        match self {
            Target::RegValue { name, .. }
            | Target::RegValueChanged { name, .. }
            | Target::RegMultiSzSegment { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Canonical target string: `P:<path>`, `K:<key>`, `V:<key>|<name>`, `C:<key>|<name>`
    /// (plus `S:<key>|<name>|<segment>`, `SVC:`, `T:`, `FW:`, `A:` for the other kinds).
    pub fn canon_string(&self) -> String {
        match self {
            Target::Path { path } => format!("P:{path}"),
            Target::RegKey { path } => format!("K:{path}"),
            Target::RegValue { path, name } => format!("V:{path}|{name}"),
            Target::RegValueChanged { path, name, .. } => format!("C:{path}|{name}"),
            Target::RegMultiSzSegment { path, name, segment } => format!("S:{path}|{name}|{segment}"),
            Target::Service { name } => format!("SVC:{name}"),
            Target::Task { path } => format!("T:{path}"),
            Target::FirewallRule { id } => format!("FW:{id}"),
            Target::AppxPackage { full_name } => format!("A:{full_name}"),
        }
    }

    /// Same target with paths/keys canonicalised (`sid` maps HKCU).
    pub fn canonical(&self, sid: Option<&str>) -> Target {
        let r = |p: &str| canon::canon_reg(p, sid);
        let p = |x: &str| canon::canon_path(x);
        match self {
            Target::Path { path } => {
                // A plan may put a registry key in a Path by mistake; keep it as written but canonical.
                if canon::looks_like_reg(path) {
                    Target::RegKey { path: r(path) }
                } else {
                    Target::Path { path: p(path) }
                }
            }
            Target::RegKey { path } => Target::RegKey { path: r(path) },
            Target::RegValue { path, name } => Target::RegValue { path: r(path), name: name.clone() },
            Target::RegValueChanged { path, name, before, after } => Target::RegValueChanged {
                path: r(path),
                name: name.clone(),
                before: before.clone(),
                after: after.clone(),
            },
            Target::RegMultiSzSegment { path, name, segment } => {
                Target::RegMultiSzSegment { path: r(path), name: name.clone(), segment: segment.clone() }
            }
            Target::Service { name } => Target::Service { name: name.trim().to_string() },
            Target::Task { path } => {
                let t = path.trim().trim_start_matches('\\').trim_end_matches('\\').to_string();
                Target::Task { path: format!("\\{t}") }
            }
            Target::FirewallRule { id } => Target::FirewallRule { id: id.trim().to_string() },
            Target::AppxPackage { full_name } => Target::AppxPackage { full_name: full_name.trim().to_string() },
        }
    }

    /// Same target with `f` applied to its registry key (registry kinds only).
    pub fn map_reg(&self, f: impl Fn(&str) -> String) -> Target {
        match self {
            Target::RegKey { path } => Target::RegKey { path: f(path) },
            Target::RegValue { path, name } => Target::RegValue { path: f(path), name: name.clone() },
            Target::RegValueChanged { path, name, before, after } => Target::RegValueChanged {
                path: f(path),
                name: name.clone(),
                before: before.clone(),
                after: after.clone(),
            },
            Target::RegMultiSzSegment { path, name, segment } => {
                Target::RegMultiSzSegment { path: f(path), name: name.clone(), segment: segment.clone() }
            }
            other => other.clone(),
        }
    }

    /// The Path / RegKey / RegValue / RegMultiSzSegment targets a (canonical) target stands for.
    pub fn primitives(&self) -> Vec<Target> {
        match self {
            Target::Service { name } => vec![Target::RegKey { path: format!("{SERVICES}\\{name}") }],
            Target::Task { path } => {
                let rel = path.trim_start_matches('\\');
                vec![
                    Target::Path { path: format!("{TASKS_DIR}\\{rel}") },
                    Target::RegKey { path: format!("{TASKCACHE}\\Tree\\{rel}") },
                ]
            }
            Target::FirewallRule { id } => vec![Target::RegValue { path: FW_RULES.to_string(), name: id.clone() }],
            Target::AppxPackage { full_name } => vec![Target::Path { path: format!("{WINDOWSAPPS}\\{full_name}") }],
            other => vec![other.clone()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_shapes() {
        let t: Target = serde_json::from_str(r#"{"type":"RegKey","path":"HKLM\\SOFTWARE\\Mozilla"}"#).unwrap();
        assert_eq!(t, Target::RegKey { path: "HKLM\\SOFTWARE\\Mozilla".into() });
        let v: Target = serde_json::from_str(r#"{"type":"RegValue","path":"HKCU\\X","name":null}"#).unwrap();
        assert_eq!(v.value_name(), Some(""));
        let s = serde_json::to_string(&Target::Path { path: "C:\\x".into() }).unwrap();
        assert_eq!(s, r#"{"type":"Path","path":"C:\\x"}"#);
        let fw: Target = serde_json::from_str(r#"{"type":"FirewallRule","rule_id":"R1"}"#).unwrap();
        assert_eq!(fw.canon_string(), "FW:R1");
    }

    #[test]
    fn canonical_and_primitives() {
        let t = Target::RegKey { path: "HKEY_CURRENT_USER\\Software\\A\\".into() }.canonical(Some("S-1-5-21-9"));
        assert_eq!(t.canon_string(), "K:HKU\\S-1-5-21-9\\Software\\A");
        let task = Target::Task { path: "Mozilla\\Update".into() }.canonical(None);
        let p = task.primitives();
        assert_eq!(p[0].canon_string(), "P:C:\\Windows\\System32\\Tasks\\Mozilla\\Update");
        assert!(p[1].canon_string().ends_with("TaskCache\\Tree\\Mozilla\\Update"));
    }
}
