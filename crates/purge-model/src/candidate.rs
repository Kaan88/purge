//! Candidates: what a scanner proposes for removal, with the evidence for and the blockers against
//! (ENGINE_PLAN.md §5.2).
//!
//! A scanner emits a [`Candidate`] without a [`Decision`]. `purge-plan` runs the guard and `purge-policy`
//! over it and fills the decision in; the plan document (`purge.plan/0`) is then a projection of the
//! decided candidates. M2 adds the optional scan-time identity of a file or directory ([`ItemFp`]); the
//! inverse and the AI annotation arrive later (M1b, M6).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::exec::op::FileIdHex;
use crate::object::ObjectFp;
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
///
/// An item is a ([`Target`], `Action`) pair, and the target decides which API carries the action out.
/// [`Action::pairs_with`] checks a pair against this table, which is the whole convention:
///
/// | Target | Action | Meaning | Inverse (ENGINE_PLAN.md §7.8) |
/// |---|---|---|---|
/// | `Path` | `Quarantine` | Move the file or directory to quarantine | Move back |
/// | `Path` | `RemoveDirIfEmpty` | Remove the directory if it is empty when its turn comes | Re-create |
/// | `RegKey` | `DeleteKey` | Delete the key with its subtree | Restore the subtree |
/// | `RegKey` | `RemoveDirIfEmpty` | Delete the key if it is empty when its turn comes | Re-create |
/// | `RegValue` | `DeleteValue` | Delete the value | Restore it if absent |
/// | `RegMultiSzSegment` | `EditSegment` | Remove one entry of a list value | Re-insert at the index |
/// | `RegMultiSzSegment` named `MRUList` | `EditSegment` | **MRU-list edit**: remove one letter | Restore the letter and the order |
/// | `Service` | `DeleteKey` | **Service removal** (SCM stop, `DeleteService`) | `CreateServiceW` + config + SDDL |
/// | `Task` | `DeleteKey` | **Task removal** (`ITaskFolder::DeleteTask`) | `RegisterTask(XML)` |
/// | `FirewallRule` | `DeleteKey` | **Firewall rule removal** (by instance id) | Re-create the stored instance |
/// | `AppxPackage` | `RemovePackage` | Remove the package | None |
/// | any but `RegValueChanged` | `ReportOnly` | Nothing; shown only | — |
///
/// Why no new variants: service, task and firewall-rule removal is "delete the whole object after storing
/// its full definition" (§7.4), which is what `DeleteKey` already says for a key; the target variant names
/// the API, so `DeleteKey` on a `Service` can never be mistaken for a registry delete by code that
/// dispatches on the target. `RemovePackage` was not reused, because the policy reads it as irreversible
/// and never preselects it, while §5.11 preselects Tier A services and tasks. An MRU-list edit is an
/// in-place edit of a list value with an index-based inverse, which is what `EditSegment` already is; the
/// value name `MRUList` tells the executor to read the data as a string of one-letter entries
/// ([`Target::mru_list_letter`]). The letter's own value (`a`, `b`, …) is a separate `DeleteValue` item.
///
/// **Default-value change** (§5.7.1: an `.ext` default that names a removed ProgID is set back to the
/// vendor backup or baseline value; §7.8: undone only while the value still holds what Purge wrote) has no
/// executable pair: no target carries the data to write, and that data must be bound by the plan hash. It
/// needs a new target variant in a later package, together with the executor's op table. Until then a
/// scanner states such a change as (`RegValue`, `ReportOnly`).
///
/// Producers: none of the service, task, firewall-rule, MRU-list or default-value pairs is emitted by any
/// scanner yet (M1b). The service, task and firewall pairs resolve to their own ops
/// ([`ExecOp::DeleteService`](crate::exec::op::ExecOp::DeleteService) and its siblings) only together
/// with [`Candidate::object_fp`]; the executor runs them from M1B-X-INTEG on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Action {
    /// Move a file or directory to quarantine.
    Quarantine,
    /// Delete a registry key with its subtree (after a backup). On a `Service`, `Task` or `FirewallRule`
    /// target: remove that object whole through its own API, after storing its full definition (see the
    /// table above).
    DeleteKey,
    /// Delete one registry value.
    DeleteValue,
    /// Remove one segment from a list-like value, keeping the rest. On a value named `MRUList`: remove one
    /// letter from the MRU order (see the table above).
    EditSegment,
    /// Remove a directory or key only if it is empty when its turn comes.
    RemoveDirIfEmpty,
    /// Remove an AppX/MSIX package through the package API.
    RemovePackage,
    /// Do nothing; the item is shown for information.
    ReportOnly,
}

impl Action {
    /// Whether (`target`, `self`) is a pair of the convention table on [`Action`]. A segment of a value
    /// named `MRUList` pairs only when it is one letter ([`Target::mru_list_letter`]).
    /// `RegValueChanged` (rig truth only) pairs with nothing.
    ///
    /// This is the model's convention, not what can run today: the executor's op table and the policy's
    /// own fit check are narrower (they leave out the M1b pairs).
    pub fn pairs_with(self, target: &Target) -> bool {
        match (target, self) {
            (Target::RegValueChanged { .. }, _) => false,
            (_, Action::ReportOnly) => true,
            (Target::Path { .. }, Action::Quarantine | Action::RemoveDirIfEmpty) => true,
            (Target::RegKey { .. }, Action::DeleteKey | Action::RemoveDirIfEmpty) => true,
            (Target::RegValue { .. }, Action::DeleteValue) => true,
            (Target::RegMultiSzSegment { name, .. }, Action::EditSegment) => {
                !Target::is_mru_list_name(name) || target.mru_list_letter().is_some()
            }
            (
                Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. },
                Action::DeleteKey,
            ) => true,
            (Target::AppxPackage { .. }, Action::RemovePackage) => true,
            _ => false,
        }
    }
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

/// The identity a file or directory had when the scan read it (ENGINE_PLAN.md §5.10 G1: "`FileIdInfo` must
/// equal the scan"): the `FILE_ID_INFO` of a handle opened on the path itself, never through a reparse
/// point.
///
/// Serialised as `{"file_id": "<32 lower-case hex digits>", "volume_serial": <u64>}`, the same spelling
/// the executor's journal uses for the identity it reads itself, so the two compare field by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ItemFp {
    /// The 128-bit file id, in the byte order Windows returns.
    pub file_id: FileIdHex,
    /// The 64-bit serial of the volume the id was read on (`FILE_ID_INFO.VolumeSerialNumber`). A file id
    /// means nothing without it.
    pub volume_serial: u64,
}

impl ItemFp {
    /// Whether an identity read later (by the executor) is the one the scan saw.
    pub fn matches(&self, file_id: &FileIdHex, volume_serial: u64) -> bool {
        self.file_id == *file_id && self.volume_serial == volume_serial
    }
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
    /// For a [`Target::Path`] item: the identity of the file or directory as the scan read it, when the
    /// file-system source could read it. `None` for every other target, and for a path the scan could not
    /// open. Absent from the JSON when `None`, so documents written before the field existed read and
    /// write unchanged.
    ///
    /// **Not part of the plan hash** (`purge_plan::hash`, schema `purge.planhash/0`, decided for M2): every
    /// plan hash stays what it was with or without the field, and the M1a gate evidence stays valid. The
    /// consequence: `--confirm` does not bind this field, so a document edited after the scan can carry
    /// any value here. That can only make the executor refuse or skip the item (the identity it reads
    /// does not match) or fall back to its own start-of-run identity check (the field was removed). It
    /// cannot widen what is deleted: the target, action and selection stay bound by the hashes, and the
    /// executor acts only on the path it reads and checks itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_fp: Option<ItemFp>,
    /// For a [`Target::Service`], [`Target::Task`] or [`Target::FirewallRule`] item: the kind and identity
    /// digest of the object as the scan read it (C-OBJECT). A `DeleteKey` candidate for such a target must
    /// carry it, and the executor resolves such an item only when it does and its kind is the target's
    /// ([`resolve`](crate::exec::op::resolve)). `None` for every other target. Absent from the JSON when
    /// `None`, so documents written before the field existed read and write unchanged.
    ///
    /// **Not part of the plan hash** (`purge.planhash/0`), for the same reason as [`Candidate::item_fp`]:
    /// it can only make the executor refuse or skip an item, never act on another object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_fp: Option<ObjectFp>,
}

impl Candidate {
    /// Records the scan-time identity of a path item ([`Candidate::item_fp`]). Does nothing for any other
    /// target, which has no file identity.
    pub fn set_item_fp(&mut self, file_id: FileIdHex, volume_serial: u64) {
        if matches!(self.target, Target::Path { .. }) {
            self.item_fp = Some(ItemFp {
                file_id,
                volume_serial,
            });
        }
    }

    /// Whether any blocker is hard, i.e. whether the candidate must end up Blocked.
    pub fn has_hard_blocker(&self) -> bool {
        self.blockers.iter().any(Blocker::is_hard)
    }

    /// Whether any blocker is soft.
    pub fn has_soft_blocker(&self) -> bool {
        self.blockers.iter().any(|b| !b.is_hard())
    }

    /// Whether the candidate has evidence of an absence-dependent kind
    /// ([`Evidence::is_absence_dependent`]: only ever on a registry key target).
    pub fn has_absence_dependent_evidence(&self) -> bool {
        self.evidence
            .iter()
            .any(|e| e.is_absence_dependent(&self.target))
    }

    /// The seal check of the trust cap (BASELINE_LOCAL_DESIGN.md §4.4 layer 2): whether the candidate has
    /// absence-dependent evidence and does **not** carry [`Blocker::BaselineInferred`]. With a baseline
    /// view whose trust is below Exact such a candidate must not leave the scan: its scanner used
    /// inferred absence without the carrier. With an exact baseline (or none, where no absence is
    /// answered) the answer says nothing and must not be acted on.
    pub fn lacks_baseline_cap(&self) -> bool {
        self.has_absence_dependent_evidence() && !self.blockers.contains(&Blocker::BaselineInferred)
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
    fn item_fp_is_omitted_when_absent_and_round_trips_when_present() {
        // Absent: the document is byte for byte what it was before the field existed.
        let v = sample();
        let c: Candidate = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(c.item_fp, None);
        let text = serde_json::to_string(&c).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"id":"c-5f1d2a","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Classes\\sh_auto_file"},"#,
                r#""action":"DeleteKey","owner":{"program_id":"HKLM|64|Git_is1","display_name":"Git"},"#,
                r#""origin":"Scanner","scanner":"CLS-PROGID","category":"Association","evidence":[{"kind":"#,
                r#""ProvenOwnedSkeleton","tier":"A","weight":8,"scope":"Key","trust":"AdminOnly","source":"#,
                r#""subtree","detail":{"baseline":"Professional-26340.9882"}}],"blockers":[{"kind":"#,
                r#""UnmatchedChildren","n":1}],"harm":"Low","reversibility":"Full","children":["c-aa01"],"#,
                r#""size_bytes":null,"child_count":2,"decision":{"band":"Likely","preselected":false,"#,
                r#""score":8,"explanation":"now empty"}}"#
            )
        );

        // Present, on a path item.
        let mut v = sample();
        v["target"] = json!({"type": "Path", "path": "C:\\Program Files\\Vendor\\app.exe"});
        v["item_fp"] = json!({
            "file_id": "000102030405060708090a0b0c0d0e0f",
            "volume_serial": 18_446_744_073_709_551_615u64
        });
        let c: Candidate = serde_json::from_value(v.clone()).unwrap();
        let fp = c.item_fp.unwrap();
        let id = FileIdHex([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert!(fp.matches(&id, u64::MAX));
        assert!(!fp.matches(&id, 7));
        assert!(!fp.matches(&FileIdHex([0; 16]), u64::MAX));
        assert_eq!(serde_json::to_value(&c).unwrap(), v);

        // A file id in any other spelling is refused.
        v["item_fp"]["file_id"] = json!("000102030405060708090A0B0C0D0E0F");
        assert!(serde_json::from_value::<Candidate>(v).is_err());
    }

    #[test]
    fn object_fp_is_omitted_when_absent_and_round_trips_when_present() {
        // A plan item without the field reads, and writes nothing for it.
        let c: Candidate = serde_json::from_value(sample()).unwrap();
        assert_eq!(c.object_fp, None);
        assert!(!serde_json::to_string(&c).unwrap().contains("object_fp"));

        let sha = "971eccc7bd4d8e319d26b61e8ce5a2862f44e7653ed48e8d922dea80bb81575c";
        let mut v = sample();
        v["target"] = json!({"type": "Service", "name": "VendorSvc"});
        v["category"] = json!("System");
        v["object_fp"] = json!({"kind": "service", "sha256": sha});
        let c: Candidate = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(
            c.object_fp,
            Some(ObjectFp {
                kind: crate::ObjectKind::Service,
                sha256: sha.into()
            })
        );
        assert_eq!(serde_json::to_value(&c).unwrap(), v);
        // Its members are fixed.
        v["object_fp"]["extra"] = json!(1);
        assert!(serde_json::from_value::<Candidate>(v).is_err());
    }

    /// A scan document the M2 executor gate ran on (Firefox, `vm/` cleanpro run `cp2-m2-fidelity`):
    /// every item, with its `item_fp`, reads and writes back unchanged.
    #[test]
    fn m2_scan_document_items_round_trip() {
        let doc: Value =
            serde_json::from_str(include_str!("../testdata/m2-firefox.scan.json")).unwrap();
        assert_eq!(doc["schema"], json!("purge.scan/0"));
        let mut with_item_fp = 0;
        for list in ["items", "absorbed"] {
            for item in doc[list].as_array().unwrap() {
                let c: Candidate = serde_json::from_value(item.clone())
                    .unwrap_or_else(|e| panic!("{}: {e}", item["id"]));
                assert_eq!(c.object_fp, None);
                with_item_fp += usize::from(c.item_fp.is_some());
                assert_eq!(&serde_json::to_value(&c).unwrap(), item);
            }
        }
        assert!(
            with_item_fp > 0,
            "the fixture carries scan-time file identities"
        );
    }

    #[test]
    fn set_item_fp_records_an_identity_for_paths_only() {
        let mut key: Candidate = serde_json::from_value(sample()).unwrap();
        key.set_item_fp(FileIdHex([7; 16]), 9);
        assert_eq!(key.item_fp, None, "a key has no file identity");
        let mut path = key.clone();
        path.target = Target::Path {
            path: "C:\\x".into(),
        };
        path.set_item_fp(FileIdHex([7; 16]), 9);
        assert_eq!(
            path.item_fp,
            Some(ItemFp {
                file_id: FileIdHex([7; 16]),
                volume_serial: 9
            })
        );
    }

    #[test]
    fn convention_table_is_exact() {
        let seg = |name: &str, segment: &str| {
            Target::RegMultiSzSegment {
            path: "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.txt\\OpenWithList".into(),
            name: name.into(),
            segment: segment.into(),
            index: Some(1),
        }
        };
        let targets = [
            (
                "path",
                Target::Path {
                    path: "C:\\x".into(),
                },
            ),
            (
                "key",
                Target::RegKey {
                    path: "HKLM\\X".into(),
                },
            ),
            (
                "value",
                Target::RegValue {
                    path: "HKLM\\X".into(),
                    name: String::new(),
                },
            ),
            (
                "changed",
                Target::RegValueChanged {
                    path: "HKLM\\X".into(),
                    name: "Path".into(),
                    before: "a".into(),
                    after: "a;b".into(),
                },
            ),
            ("segment", seg("Path", "C:\\App")),
            ("mru", seg("MRUList", "b")),
            ("mru-bad", seg("mrulist", "bc")),
            ("service", Target::Service { name: "Svc".into() }),
            (
                "task",
                Target::Task {
                    path: "\\V\\T".into(),
                },
            ),
            ("firewall", Target::FirewallRule { id: "{1}".into() }),
            (
                "package",
                Target::AppxPackage {
                    full_name: "P_1.0.0.0_x64__abc".into(),
                },
            ),
        ];
        use Action::*;
        let actions = [
            Quarantine,
            DeleteKey,
            DeleteValue,
            EditSegment,
            RemoveDirIfEmpty,
            RemovePackage,
            ReportOnly,
        ];
        let expected: &[(&str, &[Action])] = &[
            ("path", &[Quarantine, RemoveDirIfEmpty, ReportOnly]),
            ("key", &[DeleteKey, RemoveDirIfEmpty, ReportOnly]),
            ("value", &[DeleteValue, ReportOnly]),
            ("changed", &[]),
            ("segment", &[EditSegment, ReportOnly]),
            ("mru", &[EditSegment, ReportOnly]),
            ("mru-bad", &[ReportOnly]),
            ("service", &[DeleteKey, ReportOnly]),
            ("task", &[DeleteKey, ReportOnly]),
            ("firewall", &[DeleteKey, ReportOnly]),
            ("package", &[RemovePackage, ReportOnly]),
        ];
        for ((label, target), (want_label, want)) in targets.iter().zip(expected) {
            assert_eq!(label, want_label);
            for action in actions {
                assert_eq!(
                    action.pairs_with(target),
                    want.contains(&action),
                    "{label} x {action:?}"
                );
            }
        }
    }

    #[test]
    fn mru_list_letter_reads_one_letter_of_an_mru_list_only() {
        let seg = |name: &str, segment: &str| Target::RegMultiSzSegment {
            path: "HKU\\S\\X\\OpenWithList".into(),
            name: name.into(),
            segment: segment.into(),
            index: None,
        };
        assert_eq!(seg("MRUList", "a").mru_list_letter(), Some('a'));
        assert_eq!(seg("mrulist", "z").mru_list_letter(), Some('z'));
        assert!(Target::is_mru_list_name("MRULIST"));
        for (name, segment) in [
            ("MRUList", ""),
            ("MRUList", "ab"),
            ("MRUList", "A"),
            ("MRUList", "1"),
            ("MRUList", "\u{e9}"),
            ("MRUListEx", "a"),
            ("Path", "a"),
        ] {
            assert_eq!(
                seg(name, segment).mru_list_letter(),
                None,
                "{name} {segment}"
            );
        }
        let value = Target::RegValue {
            path: "HKU\\S\\X\\OpenWithList".into(),
            name: "MRUList".into(),
        };
        assert_eq!(value.mru_list_letter(), None);
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
            "item_fp",
            "volume_serial",
            "object_fp",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
