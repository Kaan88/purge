//! The shared vocabulary of the Purge engine.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.2): the types every other crate, the UI (through generated
//! DTOs) and the VM rig agree on: `Target`, `Scope`, `AppRef`, `Evidence`, `Blocker`, `Candidate`,
//! `Plan`, `Journal`, `Inverse`. All of them are `serde`-serialisable and derive `schemars::JsonSchema`, so
//! the JSON Schema the C# client is generated from comes straight from this crate.
//!
//! Milestone: M0 landed the subset the rig already uses (vm/RIG.md §7): [`Target`], [`Band`] and the minimal
//! plan document [`Plan`] (`purge.plan/0`). M1a (§11.1) adds the §5.2 entities and three more documents:
//!
//! | Module | Types |
//! |---|---|
//! | `target` | [`Target`] (wire form, unchanged for the rig) and its typed registry view [`TypedTarget`] |
//! | `ids` | [`ProgramId`] (`<hive tag>\|<view>\|<key name>`), [`CandidateId`], [`SourceId`], [`FileTime`] |
//! | `scope`, `root` | [`Scope`], [`ScopeSet`]; [`Root`], [`RootKind`], [`RootSource`], [`SourceTrust`] |
//! | `evidence`, `blocker` | [`Evidence`], [`EvidenceKind`] with the §5.3 table, [`Tier`]; [`Blocker`] |
//! | `candidate`, `appref` | [`Candidate`], [`Decision`], [`Action`], [`Harm`], [`Reversibility`]; [`AppRef`] |
//! | `fingerprint` | [`Fingerprint`] (`purge.fp/0`): what the harvest knows about one app |
//! | `inventory` | [`InventoryDoc`] (`purge.inventory/0`): one [`InventoryEntry`] per Uninstall key |
//! | `run` | [`RunDoc`] (`purge.run/0`): the record of one uninstall run, with [`VerifyGone`] |
//! | `object`, `fingerprint_m1b` | M1b: [`ObjectFp`] and the identities it digests, firewall rule strings, the fold; [`MsiFacts`], [`BurnFacts`], [`SysObjects`] |
//!
//! Every document starts with a `schema` field holding its id; reading a document with any other id
//! fails. The journal and inverse types arrive with the executor (M2).

mod appref;
mod blocker;
mod candidate;
mod evidence;
pub mod exec;
mod fingerprint;
mod fingerprint_m1b;
mod ids;
mod inventory;
pub mod object;
mod plan;
mod root;
mod run;
mod scope;
mod target;

pub use appref::AppRef;
pub use blocker::Blocker;
pub use candidate::{Action, Candidate, Decision, Harm, ItemFp, Origin, Reversibility};
pub use evidence::{Evidence, EvidenceKind, Facts, ManifestKind, Tier};
pub use fingerprint::{
    AnchorKind, AnchorRef, Anchors, AppFileOutsideRoot, BaselineTrust, BaselineViewRef,
    CoRemovedProduct, ExeFile, ExtJournalEntry, Fingerprint, FingerprintSchema, HarvestedToken,
    IdentitySnapshot, InnoRecord, InnoRecordKind, OsInfo, RefCarrier, RefSnapEntry, RunEntry,
    SubtreeBaseline, SubtreeValue, TimeWindow, VendorBackup,
};
pub use fingerprint_m1b::{
    BurnFacts, BurnLinked, BurnPackage, MsiComponentFact, MsiFacts, MsiKeyPath, MsiRegRow,
    MsiServiceRow, ObjectWhy, SysFirewallRule, SysObjects, SysService, SysTask,
};
pub use ids::{CandidateId, FileTime, ProgramId, ProgramIdError, SourceId};
pub use inventory::{
    InstallScope, InstallTimeEvidence, InstallTimeSource, InstallerKind, InventoryDoc,
    InventoryEntry, InventorySchema, MsiContext, MsiInfo, MsiOnlyRow, RawFlags, WritableBy,
};
pub use object::{
    FIREWALL_RESTORE_EXACT, FIREWALL_UNPROVEN_SHAPES, FirewallIdentity, FirewallRuleFields,
    FirewallShape, FwParseError, ObjectFp, ObjectKind, ServiceIdentity, TaskAction, TaskIdentity,
    parse_firewall_rule,
};
pub use plan::{Band, Category, Plan, PlanItem, PlanSchema, ScanMode, Tool};
pub use root::{Root, RootKind, RootSource, SourceTrust};
pub use run::{ProcessSeen, RunDoc, RunOutcome, RunSchema, VerifyGone};
pub use scope::{Scope, ScopeSet};
pub use target::{Hive, RegKind, Target, TypedTarget, TypedTargetError, View, has_classes_hive};
