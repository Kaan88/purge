//! The engine API: newline-delimited JSON-RPC 2.0.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §3.3): request, response and notification framing, the method
//! table, and the capability sets `Read`, `Propose` and `Execute` that each transport (stdio, broker pipe,
//! CLI, MCP) is allowed to use. Holds no executor code, so `purge-mcp` can depend on it.
//!
//! Milestone: M3 with the UI and broker; agent `Propose` methods in M6 (§11.1). Present before M3:
//! the result of `engine.hello` ([`EngineHello`]), because the baseline view reports through it
//! (BASELINE_LOCAL_DESIGN.md, package BL-CACHE).

use purge_model::{BaselineTrust, BaselineViewRef};
use serde::{Deserialize, Serialize};

/// The method that reports what the engine is and what it can prove (ENGINE_PLAN.md §3.3).
pub const ENGINE_HELLO: &str = "engine.hello";

/// The result of [`ENGINE_HELLO`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHello {
    /// The engine's version.
    pub version: String,
    /// Whether the engine process is elevated.
    pub elevated: bool,
    /// The SID of the account the engine runs as.
    pub user_sid: String,
    /// The SID of the interactive shell's account, when it is another one.
    #[serde(default)]
    pub shell_sid: Option<String>,
    /// Windows `EditionID`.
    pub edition: String,
    /// Windows build number.
    pub build: u32,
    /// Windows update build revision.
    pub ubr: u32,
    /// The policy rule set (`purge_policy::POLICY_VERSION`).
    pub policy_version: String,
    /// What the engine knows about "Windows' own" on this machine.
    #[serde(flatten)]
    pub baseline: BaselineStatus,
}

/// The baseline fields of [`EngineHello`] (BASELINE_LOCAL_DESIGN.md §4.1, §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineStatus {
    /// A shipped baseline of exactly this Windows is in use: `baseline_trust` is `Exact`.
    pub baseline_available: bool,
    /// How far an absence answer of the view is trusted. Below `Exact` nothing is ever offered on
    /// absence; the view only blocks what Windows owns.
    pub baseline_trust: BaselineTrust,
    /// The view in use: its name, trust and the id of the local baseline it holds. `None` when no
    /// baseline directory is configured.
    #[serde(default)]
    pub baseline_view: Option<BaselineViewRef>,
    /// The local baseline's background build in this engine process.
    pub baseline_build: BaselineBuild,
}

/// The state of the local baseline's background build (BASELINE_LOCAL_DESIGN.md §5, W4): it starts
/// with the engine, never blocks a scan, and a scan made before it ended can be made again after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BaselineBuild {
    /// No build runs in this process: an exact shipped baseline, a complete cache, an engine that is
    /// not elevated, or no cache directory. `reason` says which.
    None {
        /// Why nothing is built.
        reason: String,
    },
    /// Deciding whether a build is needed.
    Checking,
    /// Building. A scan made now does not use what is still being built.
    Building {
        /// The sources being built (`S1`, `S2`, `S4`).
        parts: Vec<String>,
        /// A scan has asked for the view since the build started, so the build runs at normal
        /// priority and that scan is worth making again when the build is done.
        scan_waiting: bool,
    },
    /// Built in this process.
    Done {
        /// A scan ran before the build ended: making it again uses the new local baseline.
        rescan: bool,
    },
    /// The build did not produce a usable cache.
    Failed {
        /// Why.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_carries_the_baseline_trust_and_view() {
        let hello = EngineHello {
            version: "0.1.0".into(),
            elevated: true,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            shell_sid: None,
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
            policy_version: "bl.1".into(),
            baseline: BaselineStatus {
                baseline_available: false,
                baseline_trust: BaselineTrust::Merged,
                baseline_view: Some(BaselineViewRef {
                    name: "local-Professional-26100.9711+2".into(),
                    trust: BaselineTrust::Merged,
                    local_id: Some("0123456789abcdef".into()),
                }),
                baseline_build: BaselineBuild::Building {
                    parts: vec!["S1".into()],
                    scan_waiting: true,
                },
            },
        };
        let json = serde_json::to_value(&hello).unwrap();
        assert_eq!(json["baseline_available"], false);
        assert_eq!(json["baseline_trust"], "Merged");
        assert_eq!(
            json["baseline_view"]["name"],
            "local-Professional-26100.9711+2"
        );
        assert_eq!(json["baseline_view"]["local_id"], "0123456789abcdef");
        assert_eq!(json["baseline_build"]["state"], "building");
        assert_eq!(json["baseline_build"]["scan_waiting"], true);
        let back: EngineHello = serde_json::from_value(json).unwrap();
        assert_eq!(back, hello);
    }
}
