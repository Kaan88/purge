//! Candidates: what a scanner proposes for removal, with the evidence for and the blockers against
//! (ENGINE_PLAN.md §5.2).
//!
//! A scanner emits a [`Candidate`] without a [`Decision`]. `purge-plan` runs the guard and `purge-policy`
//! over it and fills the decision in; the plan document (`purge.plan/0`) is then a projection of the
//! decided candidates. The M1a candidate has no inverse, item fingerprint or AI annotation yet: those
//! arrive with the executor (M2) and the agent surface (M6).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AppRef, Band, Blocker, CandidateId, Category, Evidence, Target};

/// How much the user loses if a removal turns out to be wrong (§5.8.5). Ordered from least to most.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Harm {
    /// Nothing: an empty key or directory.
    None,
    /// A cache, log, registration or privacy trace.
    Low,
    /// Configuration, or a `PATH` edit.
    Medium,
    /// User data: profiles, documents, saves, databases, unknown AppData folders.
    High,
    /// Drivers, filters, certificates.
    Critical,
}

/// Whether an action can be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Reversibility {
    /// Undo restores the exact previous state.
    Full,
    /// Undo restores most of it (e.g. a task whose stored password is lost).
    Partial,
    /// It cannot be undone (e.g. removing a package).
    None,
}

/// Who proposed a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Origin {
    /// One of the engine's scanners.
    Scanner,
    /// A knowledge-pack signature.
    Signature,
    /// A probe requested by an AI agent.
    ProbeAgent,
    /// The user added it by hand.
    ManualUser,
}

/// What executing a candidate would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Action {
    /// Move a file or directory to quarantine.
    Quarantine,
    /// Delete a registry key with its subtree (after a backup).
    DeleteKey,
    /// Delete one registry value.
    DeleteValue,
    /// Remove one segment from a list-like value, keeping the rest.
    EditSegment,
    /// Remove a directory or key only if it is empty when its turn comes.
    RemoveDirIfEmpty,
    /// Remove an AppX/MSIX package through the package API.
    RemovePackage,
    /// Do nothing; the item is shown for information.
    ReportOnly,
}

/// The policy's verdict on a candidate (§5.8).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Decision {
    /// The confidence band.
    pub band: Band,
    /// Whether the item is ticked by default.
    pub preselected: bool,
    /// The score S of §5.8.1.
    pub score: i32,
    /// The explanation, rendered from fixed templates (§5.8.6).
    pub explanation: String,
}

/// One proposed removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Candidate {
    /// Stable id within the scan (a hash of the target).
    pub id: CandidateId,
    /// What it acts on.
    pub target: Target,
    /// What executing it would do.
    pub action: Action,
    /// The app it is attributed to.
    pub owner: AppRef,
    /// Who proposed it.
    pub origin: Origin,
    /// Id of the scanner that found it, e.g. `REG-SOFTWARE` (§5.6).
    pub scanner: String,
    /// Its category.
    pub category: Category,
    /// The evidence that it belongs to the owner.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// The reasons against removing it.
    #[serde(default)]
    pub blockers: Vec<Blocker>,
    /// What is lost if the removal is wrong.
    pub harm: Harm,
    /// Whether the action can be undone.
    pub reversibility: Reversibility,
    /// Candidates nested inside this one (files of a directory, values of a key).
    #[serde(default)]
    pub children: Vec<CandidateId>,
    /// Size on disk, for paths, when measured.
    pub size_bytes: Option<u64>,
    /// Number of files or values inside, when counted.
    pub child_count: Option<u32>,
    /// The policy's verdict; `None` until `purge-plan` has decided.
    pub decision: Option<Decision>,
}

impl Candidate {
    /// Whether any blocker is hard, i.e. whether the candidate must end up Blocked.
    pub fn has_hard_blocker(&self) -> bool {
        self.blockers.iter().any(Blocker::is_hard)
    }

    /// Whether any blocker is soft.
    pub fn has_soft_blocker(&self) -> bool {
        self.blockers.iter().any(|b| !b.is_hard())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn sample() -> Value {
        json!({
            "id": "c-5f1d2a", "target": {"type": "RegKey", "path": "HKLM\\SOFTWARE\\Classes\\sh_auto_file"},
            "action": "DeleteKey",
            "owner": {"program_id": "HKLM|64|Git_is1", "display_name": "Git"},
            "origin": "Scanner", "scanner": "CLS-PROGID", "category": "Association",
            "evidence": [{
                "kind": "ProvenOwnedSkeleton", "tier": "A", "weight": 8, "scope": "Key",
                "trust": "AdminOnly", "source": "subtree", "detail": {"baseline": "Professional-26340.9882"}
            }],
            "blockers": [{"kind": "UnmatchedChildren", "n": 1}],
            "harm": "Low", "reversibility": "Full", "children": ["c-aa01"],
            "size_bytes": null, "child_count": 2,
            "decision": {"band": "Likely", "preselected": false, "score": 8, "explanation": "now empty"}
        })
    }

    #[test]
    fn candidate_round_trips() {
        let v = sample();
        let c: Candidate = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(c.action, Action::DeleteKey);
        assert_eq!(c.decision.as_ref().unwrap().band, Band::Likely);
        assert!(c.has_soft_blocker());
        assert!(!c.has_hard_blocker());
        assert_eq!(serde_json::to_value(&c).unwrap(), v);
    }

    #[test]
    fn undecided_candidate_reads_with_lists_omitted() {
        let mut v = sample();
        let o = v.as_object_mut().unwrap();
        for field in [
            "evidence",
            "blockers",
            "children",
            "size_bytes",
            "child_count",
            "decision",
        ] {
            o.remove(field);
        }
        let mut c: Candidate = serde_json::from_value(v).unwrap();
        assert!(c.evidence.is_empty() && c.blockers.is_empty() && c.children.is_empty());
        assert_eq!(
            (c.size_bytes, c.child_count, &c.decision),
            (None, None, &None)
        );
        c.blockers.push(Blocker::WindowsBaseline);
        assert!(c.has_hard_blocker());
    }

    #[test]
    fn every_enum_value_round_trips() {
        fn all<T: Serialize + for<'de> Deserialize<'de>>(names: &[&str]) {
            for name in names {
                let t: T = serde_json::from_value(json!(name)).unwrap();
                assert_eq!(serde_json::to_value(&t).unwrap(), json!(name));
            }
        }
        all::<Harm>(&["None", "Low", "Medium", "High", "Critical"]);
        all::<Reversibility>(&["Full", "Partial", "None"]);
        all::<Origin>(&["Scanner", "Signature", "ProbeAgent", "ManualUser"]);
        all::<Action>(&[
            "Quarantine",
            "DeleteKey",
            "DeleteValue",
            "EditSegment",
            "RemoveDirIfEmpty",
            "RemovePackage",
            "ReportOnly",
        ]);
        assert!(Harm::None < Harm::Low && Harm::Low < Harm::Medium);
        assert!(Harm::High < Harm::Critical);
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(Candidate)).unwrap();
        for name in [
            "RemoveDirIfEmpty",
            "ProbeAgent",
            "Critical",
            "Partial",
            "ProvenOwnedSkeleton",
            "ReferencedByOtherApp",
            "explanation",
            "ProgramId",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
