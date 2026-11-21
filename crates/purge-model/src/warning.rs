//! Typed warnings of a scan (M3-ENGINE-OUT, HANDOFF-m1b M3 notes).
//!
//! Before M3 a scan's warnings were plain strings: the client had to match words to tell "the engine
//! is not elevated" from "a scanner faulted" or "the baseline does not match this Windows". A
//! [`ScanWarning`] keeps the text shown and adds a stable [`WarningKind`]; the kind's
//! [`code`](WarningKind::code) is what a client switches on (the RPC `Warning.code` field). The text is
//! the same line the CLI prints, so nothing a user reads changes.
//!
//! The classification is done once, where the scan hands its warnings out
//! ([`ScanWarning::classify`]); the pipeline itself keeps building plain lines, as the harvest, the
//! baseline and the scanners do.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a scan warning is about. The serde spelling of each variant is its [`code`](Self::code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    /// The baseline view could not be read, or does not exist for this Windows.
    Baseline,
    /// The baseline view was injected by the caller (a replay or a test), not loaded by the engine.
    BaselineInjected,
    /// The fingerprint was harvested on another Windows than the one being scanned.
    BaselineMismatch,
    /// An Uninstall key, hive or source call could not be read; the inventory may be incomplete.
    Inventory,
    /// The engine is not elevated, so some keys and folders may be unreadable.
    Elevation,
    /// A scanner faulted; its candidates are missing from the scan.
    ScannerFault,
    /// The MSI ownership index is incomplete, so some Classes keys were kept from Safe.
    MsiOwnership,
    /// Two candidates shared an id; both were dropped.
    CandidateIdCollision,
    /// The deny-list could not be built; every target is Blocked.
    DenyList,
    /// The scan did not read everything it wanted to (budget cuts, unreadable keys or packages).
    ScanIncomplete,
    /// An uninstall or its verification reported a problem.
    Uninstall,
    /// Anything else the scan noticed.
    Other,
}

impl WarningKind {
    /// The stable machine code of the kind, as the RPC `Warning.code` carries it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::BaselineInjected => "baseline_injected",
            Self::BaselineMismatch => "baseline_mismatch",
            Self::Inventory => "inventory",
            Self::Elevation => "elevation",
            Self::ScannerFault => "scanner_fault",
            Self::MsiOwnership => "msi_ownership",
            Self::CandidateIdCollision => "candidate_id_collision",
            Self::DenyList => "deny_list",
            Self::ScanIncomplete => "scan_incomplete",
            Self::Uninstall => "uninstall",
            Self::Other => "other",
        }
    }

    /// The kind of the warning line `message` the pipeline built.
    #[must_use]
    pub fn of(message: &str) -> Self {
        let message = message.trim_start();
        if message.starts_with("baseline:") {
            if message.contains("injected by the caller") {
                Self::BaselineInjected
            } else {
                Self::Baseline
            }
        } else if message.starts_with("inventory:") {
            Self::Inventory
        } else if message.starts_with("uninstall:") {
            Self::Uninstall
        } else if message.contains("not elevated") {
            Self::Elevation
        } else if message.contains("scanner fault:") {
            Self::ScannerFault
        } else if message.contains("MsiPackageUnreadable") || message.contains("MSI rows of") {
            Self::MsiOwnership
        } else if message.contains("candidate(s) whose id") {
            Self::CandidateIdCollision
        } else if message.contains("deny-list could not be built") {
            Self::DenyList
        } else if message.contains("fingerprint was harvested on") {
            Self::BaselineMismatch
        } else if message.starts_with("scan:") || message.starts_with("scan --path:") {
            Self::ScanIncomplete
        } else {
            Self::Other
        }
    }
}

impl fmt::Display for WarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// One warning of a scan: its typed kind and the line shown to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanWarning {
    /// What the warning is about.
    pub kind: WarningKind,
    /// The text shown, exactly the line the engine's CLI prints.
    pub message: String,
}

impl ScanWarning {
    /// A warning of `kind` with `message`.
    #[must_use]
    pub fn new(kind: WarningKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The warning line `message`, with its kind taken from its prefix and wording
    /// ([`WarningKind::of`]).
    #[must_use]
    pub fn classify(message: impl Into<String>) -> Self {
        let message = message.into();
        let kind = WarningKind::of(&message);
        Self { kind, message }
    }

    /// The stable machine code of the warning, for a client that switches on the kind.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// The text shown.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_kind_serialises_as_its_code() {
        for kind in [
            WarningKind::Baseline,
            WarningKind::BaselineInjected,
            WarningKind::BaselineMismatch,
            WarningKind::Inventory,
            WarningKind::Elevation,
            WarningKind::ScannerFault,
            WarningKind::MsiOwnership,
            WarningKind::CandidateIdCollision,
            WarningKind::DenyList,
            WarningKind::ScanIncomplete,
            WarningKind::Uninstall,
            WarningKind::Other,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(kind.code()));
        }
    }

    #[test]
    fn warning_lines_are_classified_by_their_wording() {
        let cases = [
            (
                "baseline: no Professional-1.tsv.gz in C:\\b; the scan works values-only",
                WarningKind::Baseline,
            ),
            (
                "baseline: baseline view Local-1 injected by the caller: trust Merged",
                WarningKind::BaselineInjected,
            ),
            (
                "scan: the fingerprint was harvested on Professional 26100.1, this is Enterprise 26200.2",
                WarningKind::BaselineMismatch,
            ),
            (
                "inventory: HKLM\\SOFTWARE: cannot read subkeys: access denied",
                WarningKind::Inventory,
            ),
            (
                "scan: the engine is not elevated; keys and folders that need administrator rights may be \
                 unreadable, so the result may be incomplete",
                WarningKind::Elevation,
            ),
            (
                "scan: scanner fault: SYS-SERVICE: boom",
                WarningKind::ScannerFault,
            ),
            (
                "scan: 3 item(s) under a Classes key kept from Safe (MsiPackageUnreadable): the MSI rows of \
                 1 product(s) are unknown",
                WarningKind::MsiOwnership,
            ),
            (
                "scan: dropped 2 candidate(s) whose id c-0000000000000001 names more than one target",
                WarningKind::CandidateIdCollision,
            ),
            (
                "scan: the deny-list could not be built (bad rule); every target is Blocked",
                WarningKind::DenyList,
            ),
            (
                "scan: the environment could not be read (access denied)",
                WarningKind::ScanIncomplete,
            ),
            (
                "uninstall: the uninstaller exited with code 3",
                WarningKind::Uninstall,
            ),
            ("something new", WarningKind::Other),
        ];
        for (message, kind) in cases {
            let warning = ScanWarning::classify(message);
            assert_eq!(warning.kind, kind, "{message}");
            assert_eq!(warning.code(), kind.code());
            assert_eq!(warning.message(), message);
            assert_eq!(warning.to_string(), message);
        }
    }

    #[test]
    fn a_warning_round_trips() {
        let warning = ScanWarning::new(WarningKind::Elevation, "scan: the engine is not elevated");
        let v = json!({"kind": "elevation", "message": "scan: the engine is not elevated"});
        assert_eq!(serde_json::to_value(&warning).unwrap(), v);
        assert_eq!(serde_json::from_value::<ScanWarning>(v).unwrap(), warning);
    }
}
